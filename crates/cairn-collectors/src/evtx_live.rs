//! Live EVTX collector: reads the on-disk log of every channel the Sigma engine
//! references, keeping events inside the `--since` window.
//!
//! Each channel's file is resolved, in order, from
//! 1. `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<channel>\File` (classic logs:
//!    Application, Security, System, ...),
//! 2. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<channel>\File`
//!    (where a relocated modern channel's path is stored; best knowledge, not verified
//!    on a host here),
//! 3. the default `%SystemRoot%\System32\winevt\Logs\<channel with / as %4>.evtx`,
//!
//! taking the first candidate that exists. `%SystemRoot%` / `%windir%` (and any other
//! `%VAR%`) in registry values are expanded. Read-only: registry values are read, log
//! files are opened for read only.
//!
//! Each file is streamed: the time filter runs on the record header before JSON
//! rendering (see [`crate::evtx::stream_evtx`]). Its sha256 is computed in a separate
//! streaming pass just before parsing; because a live log grows while it is read, the
//! manifest entry's `method` says the hash covers the bytes read at collection time.

use crate::asep::{Hive, KeyValues, RegData, RegRead};
use cairn_core::manifest::SourceEntry;
use cairn_core::record::Record;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// Classic event-log service configuration (one subkey per classic log).
pub(crate) const EVENTLOG_SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog";
/// Modern (crimson) channel configuration (one subkey per channel).
pub(crate) const WINEVT_CHANNELS_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels";

/// `SourceEntry.method` for a live log: read from the filesystem, sha256 over exactly
/// the bytes read at collection time (the file may have grown since).
pub const LIVE_EVTX_METHOD: &str = "fs:sha256_of_bytes_read_at_collection";

/// Map a Sigma channel name to its on-disk `.evtx` filename.
/// Windows EVTX filenames encode `/` as `%4`.
pub(crate) fn channel_to_filename(channel: &str) -> String {
    format!("{}.evtx", channel.replace('/', "%4"))
}

/// Map an on-disk `.evtx` filename back to a channel name (inverse of `channel_to_filename`).
/// Returns None if the file does not have a `.evtx` extension.
#[allow(dead_code)]
pub(crate) fn filename_to_channel(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".evtx")?;
    Some(stem.replace("%4", "/"))
}

/// True if `ts` is at or after `since`.
#[allow(dead_code)]
pub(crate) fn event_is_recent(ts: DateTime<Utc>, since: DateTime<Utc>) -> bool {
    ts >= since
}

/// The `File` string value of `HKLM\<key>`, if present and non-empty.
fn file_value(reg: &dyn RegRead, key: &str) -> Option<String> {
    let (values, _): KeyValues = reg.values(Hive::Hklm, key)?;
    values.into_iter().find_map(|(n, d)| match d {
        RegData::Str(s) if n.eq_ignore_ascii_case("File") && !s.trim().is_empty() => {
            Some(s.trim().to_string())
        }
        _ => None,
    })
}

/// Expand a registry log path: `%SystemRoot%` / `%windir%` always map to
/// `system_root`; other `%VAR%`s go through `lookup` (unknown ones stay literal).
pub(crate) fn expand_log_path(
    raw: &str,
    system_root: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> String {
    let root = system_root.trim_end_matches(['\\', '/']).to_string();
    let env = |v: &str| {
        if v.eq_ignore_ascii_case("SystemRoot") || v.eq_ignore_ascii_case("windir") {
            Some(root.clone())
        } else {
            lookup(v)
        }
    };
    crate::persist::expand_env_vars(raw.trim().trim_matches('"'), &env)
}

/// Candidate files for `channel`, in priority order, duplicates removed
/// (case-insensitive): EventLog service `File`, WINEVT channel `File`, default path.
pub(crate) fn channel_file_candidates(
    channel: &str,
    reg: &dyn RegRead,
    system_root: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let raw = [
        file_value(reg, &format!(r"{EVENTLOG_SERVICES_KEY}\{channel}")),
        file_value(reg, &format!(r"{WINEVT_CHANNELS_KEY}\{channel}")),
    ];
    for r in raw.into_iter().flatten() {
        let p = expand_log_path(&r, system_root, lookup);
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&p)) {
            out.push(p);
        }
    }
    let default = format!(
        r"{}\System32\winevt\Logs\{}",
        system_root.trim_end_matches(['\\', '/']),
        channel_to_filename(channel)
    );
    if !out.iter().any(|o| o.eq_ignore_ascii_case(&default)) {
        out.push(default);
    }
    out
}

/// First existing candidate for each channel: `(channel, path)`. A channel with no
/// existing file (e.g. Sysmon not installed) is left out.
pub(crate) fn resolve_channel_files(
    channels: &[String],
    reg: &dyn RegRead,
    system_root: &str,
    lookup: &impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for ch in channels {
        let found = channel_file_candidates(ch, reg, system_root, lookup)
            .into_iter()
            .find(|p| exists(p));
        match found {
            Some(p) => {
                // Two channel names resolving to one file are read once.
                if !out
                    .iter()
                    .any(|(_, q)| q.to_string_lossy().eq_ignore_ascii_case(&p))
                {
                    out.push((ch.clone(), PathBuf::from(p)));
                }
            }
            None => tracing::debug!(channel = %ch, "evtx_live: no log file found; skipping"),
        }
    }
    out
}

/// Stream every resolved file, keeping events at or after `since`; one SourceEntry
/// per file (with sha256 + byte count of the hash pass, or the error).
pub(crate) fn collect_files(
    files: &[(String, PathBuf)],
    since: DateTime<Utc>,
    source_entries: &mut Vec<SourceEntry>,
) -> Vec<Record> {
    let mut records = Vec::new();
    for (channel, path) in files {
        let mut errors = Vec::new();
        let (sha256, size) = match crate::evtx::sha256_file(path) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("sha256: {e}"));
                (
                    String::new(),
                    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                )
            }
        };
        match crate::evtx::stream_evtx(path, Some(since), |ev| records.push(Record::Event(ev))) {
            Ok(stats) => {
                tracing::info!(
                    channel = %channel,
                    events = stats.kept,
                    skipped_old = stats.skipped_old,
                    failed = stats.failed,
                    "evtx_live: parsed"
                );
            }
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "evtx_live: parse failed; skipping");
                errors.push(e.to_string());
            }
        }
        source_entries.push(SourceEntry {
            collector: String::new(),
            artifact: format!("evtx_live:{channel}"),
            path: path.display().to_string(),
            method: LIVE_EVTX_METHOD.into(),
            size,
            sha256,
            errors,
        });
    }
    records
}

/// A registry with nothing in it: the non-Windows stand-in (defaults only).
#[cfg(not(windows))]
struct NoReg;
#[cfg(not(windows))]
impl RegRead for NoReg {
    fn values(&self, _hive: Hive, _key: &str) -> Option<KeyValues> {
        None
    }
    fn subkeys(&self, _hive: Hive, _key: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Reads live logs for Sigma-referenced channels, filtering to events within the time window.
pub struct EvtxLiveCollector {
    channels: Vec<String>,
    since: DateTime<Utc>,
    sources: std::sync::Mutex<Vec<SourceEntry>>,
}

impl EvtxLiveCollector {
    pub fn new(channels: Vec<String>, since: DateTime<Utc>) -> Self {
        EvtxLiveCollector {
            channels,
            since,
            sources: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Collector for EvtxLiveCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::EVTX_LIVE
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        if self.channels.is_empty() {
            return Ok(vec![]);
        }
        let system_root = std::env::var("SystemRoot")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        let lookup = |v: &str| std::env::var(v).ok();
        #[cfg(windows)]
        let reg = crate::asep::WinReg;
        #[cfg(not(windows))]
        let reg = NoReg;
        let files = resolve_channel_files(&self.channels, &reg, &system_root, &lookup, |p| {
            Path::new(p).is_file()
        });
        let mut entries = Vec::new();
        let records = collect_files(&files, self.since, &mut entries);
        *self.sources.lock().unwrap_or_else(|e| e.into_inner()) = entries;
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::CollectCtx;
    use chrono::TimeZone;
    use std::collections::HashMap;

    /// HKLM-only fake: lowercased key -> File value.
    #[derive(Default)]
    struct FakeReg(HashMap<String, String>);
    impl FakeReg {
        fn file(mut self, key: &str, v: &str) -> Self {
            self.0.insert(key.to_ascii_lowercase(), v.to_string());
            self
        }
    }
    impl RegRead for FakeReg {
        fn values(&self, hive: Hive, key: &str) -> Option<KeyValues> {
            if hive != Hive::Hklm {
                return None;
            }
            self.0
                .get(&key.to_ascii_lowercase())
                .map(|v| (vec![("File".to_string(), RegData::Str(v.clone()))], None))
        }
        fn subkeys(&self, _hive: Hive, _key: &str) -> Vec<String> {
            Vec::new()
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn channel_to_filename_security() {
        assert_eq!(channel_to_filename("Security"), "Security.evtx");
    }

    #[test]
    fn channel_to_filename_powershell_operational() {
        assert_eq!(
            channel_to_filename("Microsoft-Windows-PowerShell/Operational"),
            "Microsoft-Windows-PowerShell%4Operational.evtx"
        );
    }

    #[test]
    fn filename_to_channel_roundtrip_and_non_evtx() {
        for ch in [
            "Security",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational",
        ] {
            assert_eq!(
                filename_to_channel(&channel_to_filename(ch)),
                Some(ch.to_string())
            );
        }
        assert_eq!(filename_to_channel("something.log"), None);
    }

    #[test]
    fn since_filter_boundaries() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        assert!(!event_is_recent(
            since - chrono::Duration::seconds(1),
            since
        ));
        assert!(event_is_recent(since, since));
        assert!(event_is_recent(since + chrono::Duration::seconds(1), since));
    }

    #[test]
    fn default_path_uses_system_root_not_hardcoded_c() {
        let c = channel_file_candidates(
            "Microsoft-Windows-Sysmon/Operational",
            &FakeReg::default(),
            r"D:\WINNT\",
            &no_env,
        );
        assert_eq!(
            c,
            vec![r"D:\WINNT\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"]
        );
    }

    #[test]
    fn registry_file_values_come_first_and_are_expanded() {
        let reg = FakeReg::default()
            .file(
                &format!(r"{EVENTLOG_SERVICES_KEY}\Security"),
                r"%SystemRoot%\System32\Winevt\Logs\Security.evtx",
            )
            .file(
                &format!(r"{WINEVT_CHANNELS_KEY}\Security"),
                r"E:\Logs\%LOGTAG%-Security.evtx",
            );
        let env = |v: &str| (v == "LOGTAG").then(|| "host1".to_string());
        let c = channel_file_candidates("Security", &reg, r"C:\Windows", &env);
        assert_eq!(
            c,
            vec![
                r"C:\Windows\System32\Winevt\Logs\Security.evtx".to_string(),
                r"E:\Logs\host1-Security.evtx".to_string(),
            ],
            "the EventLog value equals the default (case-insensitively) so it is not repeated"
        );
    }

    #[test]
    fn relocated_log_is_resolved_and_missing_channels_skipped() {
        let reg = FakeReg::default().file(
            &format!(r"{EVENTLOG_SERVICES_KEY}\System"),
            r"%windir%\..\Logs\Sys.evtx",
        );
        let channels = vec!["System".to_string(), "Security".to_string()];
        let exists = |p: &str| p == r"C:\Windows\..\Logs\Sys.evtx";
        let files = resolve_channel_files(&channels, &reg, r"C:\Windows", &no_env, exists);
        assert_eq!(
            files,
            vec![(
                "System".to_string(),
                PathBuf::from(r"C:\Windows\..\Logs\Sys.evtx")
            )]
        );
        // a registry path that does not exist falls back to the default
        let files = resolve_channel_files(&channels[..1], &reg, r"C:\Windows", &no_env, |p| {
            p.ends_with(r"winevt\Logs\System.evtx")
        });
        assert_eq!(
            files[0].1,
            PathBuf::from(r"C:\Windows\System32\winevt\Logs\System.evtx")
        );
    }

    #[test]
    fn no_channels_returns_empty_without_touching_fs() {
        let collector = EvtxLiveCollector::new(vec![], chrono::Utc::now());
        assert!(collector.collect(&make_ctx()).unwrap().is_empty());
        assert!(collector.sources().is_empty());
    }

    /// Off-Windows nothing resolves (no registry, no C:\Windows): Ok and empty.
    #[cfg(not(windows))]
    #[test]
    fn collect_off_windows_is_ok_empty() {
        let collector = EvtxLiveCollector::new(vec!["Security".into()], chrono::Utc::now());
        assert!(collector.collect(&make_ctx()).unwrap().is_empty());
    }

    /// An invalid file still yields a SourceEntry: the hash of the bytes read plus the
    /// parse error.
    #[test]
    fn invalid_file_gets_hash_and_error() {
        let dir = std::env::temp_dir().join(format!("cairn_evtx_live_bad_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("Security.evtx");
        std::fs::write(&p, b"abc").unwrap();
        let mut sources = Vec::new();
        let recs = collect_files(
            &[("Security".to_string(), p.clone())],
            chrono::Utc::now(),
            &mut sources,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(recs.is_empty());
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0].sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sources[0].size, 3);
        assert_eq!(sources[0].method, LIVE_EVTX_METHOD);
        assert!(!sources[0].errors.is_empty());
    }

    /// Real fixture end to end: resolved via a fake registry value, hashed, streamed.
    #[test]
    fn fixture_resolved_hashed_and_filtered() {
        let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/sysmon_compiledhtml.evtx");
        if !fx.exists() {
            eprintln!("skipping: fixture missing: {fx:?}");
            return;
        }
        let fx_s = fx.to_string_lossy().to_string();
        let ch = "Microsoft-Windows-Sysmon/Operational".to_string();
        let reg = FakeReg::default().file(&format!(r"{WINEVT_CHANNELS_KEY}\{ch}"), &fx_s);
        let files = resolve_channel_files(
            std::slice::from_ref(&ch),
            &reg,
            r"C:\Windows",
            &no_env,
            |p| Path::new(p).is_file(),
        );
        assert_eq!(files.len(), 1);
        let mut sources = Vec::new();
        let epoch = chrono::DateTime::UNIX_EPOCH;
        let recs = collect_files(&files, epoch, &mut sources);
        assert!(!recs.is_empty());
        let (want, len) = crate::evtx::sha256_file(&fx).unwrap();
        assert_eq!(sources[0].sha256, want);
        assert_eq!(sources[0].size, len);
        assert!(sources[0].errors.is_empty(), "{:?}", sources[0].errors);
        // a future window keeps nothing but still records the source
        let mut s2 = Vec::new();
        let none = collect_files(
            &files,
            chrono::Utc::now() + chrono::Duration::days(1),
            &mut s2,
        );
        assert!(none.is_empty());
        assert_eq!(s2.len(), 1);
    }

    fn make_ctx() -> CollectCtx<'static> {
        use cairn_core::Config;
        let cfg: &'static Config = Box::leak(Box::new(Config::default()));
        CollectCtx {
            config: cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        }
    }
}
