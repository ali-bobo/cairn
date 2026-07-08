//! Live EVTX collector: reads C:\Windows\System32\winevt\Logs\ filtered by
//! the Sigma engine's referenced channels and a time window.

use cairn_core::manifest::SourceEntry;
use cairn_core::record::Record;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const WINEVT_LOGS_DIR: &str = r"C:\Windows\System32\winevt\Logs";

/// Map a Sigma channel name to its on-disk `.evtx` filename.
/// Windows EVTX filenames encode `/` as `%4`.
pub(crate) fn channel_to_filename(channel: &str) -> String {
    format!("{}.evtx", channel.replace('/', "%4"))
}

/// Map an on-disk `.evtx` filename back to a channel name (inverse of `channel_to_filename`).
/// Returns None if the file does not have a `.evtx` extension.
pub(crate) fn filename_to_channel(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".evtx")?;
    Some(stem.replace("%4", "/"))
}

/// True if `ts` is at or after `since`.
pub(crate) fn event_is_recent(ts: DateTime<Utc>, since: DateTime<Utc>) -> bool {
    ts >= since
}

/// Internal: collect EventRecords from a given EVTX directory.
/// Extracted for testability (allows injecting a non-standard dir path).
pub(crate) fn collect_from_dir(
    dir: &Path,
    channels: &[String],
    since: DateTime<Utc>,
    source_entries: &mut Vec<SourceEntry>,
) -> Result<Vec<Record>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "evtx_live: cannot read winevt Logs dir; skipping");
            return Ok(vec![]);
        }
    };

    let wanted_filenames: HashSet<String> =
        channels.iter().map(|c| channel_to_filename(c)).collect();

    let mut records = Vec::new();

    for entry in rd {
        let path = match entry {
            Ok(e) => e.path(),
            Err(_) => continue,
        };
        let Some(fname) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !wanted_filenames.contains(fname) {
            continue;
        }
        let channel = filename_to_channel(fname).unwrap_or_else(|| fname.to_string());
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

        match crate::evtx::parse_evtx(&path) {
            Ok(evs) => {
                let before = records.len();
                for ev in evs {
                    if event_is_recent(ev.ts, since) {
                        records.push(Record::Event(ev));
                    }
                }
                let count = records.len() - before;
                tracing::info!(
                    channel = %channel,
                    events = count,
                    "evtx_live: parsed"
                );
                source_entries.push(SourceEntry {
                    artifact: format!("evtx_live:{channel}"),
                    path: path.display().to_string(),
                    method: "fs".into(),
                    size,
                    sha256: String::new(),
                    errors: vec![],
                });
            }
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "evtx_live: parse failed; skipping");
                source_entries.push(SourceEntry {
                    artifact: format!("evtx_live:{channel}"),
                    path: path.display().to_string(),
                    method: "fs".into(),
                    size,
                    sha256: String::new(),
                    errors: vec![e.to_string()],
                });
            }
        }
    }

    Ok(records)
}

/// Reads winevt Logs for Sigma-referenced channels, filtering to events within the time window.
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
        "evtx_live"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        if self.channels.is_empty() {
            return Ok(vec![]);
        }
        let mut entries = Vec::new();
        let result = collect_from_dir(
            &PathBuf::from(WINEVT_LOGS_DIR),
            &self.channels,
            self.since,
            &mut entries,
        );
        *self.sources.lock().unwrap() = entries;
        result
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
    fn channel_to_filename_sysmon() {
        assert_eq!(
            channel_to_filename("Microsoft-Windows-Sysmon/Operational"),
            "Microsoft-Windows-Sysmon%4Operational.evtx"
        );
    }

    #[test]
    fn filename_to_channel_security() {
        assert_eq!(
            filename_to_channel("Security.evtx"),
            Some("Security".to_string())
        );
    }

    #[test]
    fn filename_to_channel_powershell() {
        assert_eq!(
            filename_to_channel("Microsoft-Windows-PowerShell%4Operational.evtx"),
            Some("Microsoft-Windows-PowerShell/Operational".to_string())
        );
    }

    #[test]
    fn filename_to_channel_non_evtx_returns_none() {
        assert_eq!(filename_to_channel("something.log"), None);
    }

    #[test]
    fn since_filter_drops_old_event() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        let old_ts = chrono::Utc
            .with_ymd_and_hms(2026, 6, 26, 23, 59, 59)
            .unwrap();
        assert!(!event_is_recent(old_ts, since));
    }

    #[test]
    fn since_filter_keeps_recent_event() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        let new_ts = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 1).unwrap();
        assert!(event_is_recent(new_ts, since));
    }

    #[test]
    fn since_filter_keeps_exact_boundary() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        assert!(event_is_recent(since, since));
    }

    #[test]
    fn channel_filename_roundtrip() {
        let channels = &[
            "Security",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational",
        ];
        for ch in channels {
            assert_eq!(
                filename_to_channel(&channel_to_filename(ch)),
                Some(ch.to_string()),
                "roundtrip failed for channel: {ch}"
            );
        }
    }

    #[test]
    fn no_channels_returns_empty_without_touching_fs() {
        let collector = EvtxLiveCollector::new(vec![], chrono::Utc::now());
        let ctx = make_ctx();
        let result = collector.collect(&ctx).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn missing_dir_returns_ok_empty() {
        let result = collect_from_dir(
            &std::path::PathBuf::from(r"C:\nonexistent\path\winevt\Logs"),
            &["Security".to_string()],
            chrono::Utc::now(),
            &mut vec![],
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
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
