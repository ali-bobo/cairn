//! Export a live event-log channel to a `.evtx` file for re-parsing off-host
//! (`evidence/evtx/<channel>.evtx`), via the documented Windows Event Log API
//! `EvtExportLog` (wevtapi.dll) with `EvtExportLogChannelPath` and an XPath time window.
//!
//! Read-only on the host: `EvtExportLog` asks the Event Log service to copy matching
//! events into a NEW file at `target`. It never clears, modifies or truncates the source
//! channel (golden rules 3/4). The caller chooses `target` inside the operator's output
//! location, never a source path; this wrapper refuses an existing target (no
//! `EvtExportLogOverwrite`) so it can never be pointed at, or through, an existing file.
//!
//! The pure helpers ([`since_xpath`], [`channel_file_name`]) are platform-independent
//! and unit-tested everywhere; the FFI call is `cfg(windows)` only.
use cairn_core::{CairnError, Result};
use chrono::{DateTime, Utc};
use std::path::Path;

/// Collector-style name used in errors and manifest source entries.
pub const NAME: &str = "evtx_export";

fn err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: NAME.into(),
        reason,
    }
}

/// Structured XPath selecting events at or after `since` (UTC, millisecond precision),
/// the same window `--since` applies to the live EVTX collector.
pub fn since_xpath(since: DateTime<Utc>) -> String {
    format!(
        "*[System[TimeCreated[@SystemTime>='{}']]]",
        since.format("%Y-%m-%dT%H:%M:%S%.3fZ")
    )
}

/// File name for a channel's export, following Windows' own on-disk convention for
/// channel logs (`Microsoft-Windows-Sysmon/Operational` ->
/// `Microsoft-Windows-Sysmon%4Operational.evtx`). Any other character that is not
/// valid in a Windows file name becomes `_`, so the name is always a single, safe path
/// component.
pub fn channel_file_name(channel: &str) -> String {
    let mut out = String::with_capacity(channel.len() + 5);
    for c in channel.trim().chars() {
        match c {
            '/' => out.push_str("%4"),
            '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => out.push('_'),
            c if c.is_control() => out.push('_'),
            c => out.push(c),
        }
    }
    let base = out.trim_matches(['.', ' ']);
    let base = if base.is_empty() { "channel" } else { base };
    format!("{base}.evtx")
}

/// Refuse a target that already exists (file, dir or symlink): the export only ever
/// creates a fresh file.
fn check_target(target: &Path) -> Result<()> {
    if std::fs::symlink_metadata(target).is_ok() {
        return Err(err(format!(
            "export target already exists, refusing to overwrite: {}",
            target.display()
        )));
    }
    Ok(())
}

/// Export the events of live channel `channel` matching XPath `query` into a new file
/// at `target` (whose parent directory must exist). Errs (never panics) on any
/// failure: unknown channel, access denied (e.g. Security without admin), existing
/// target, or a non-Windows platform.
#[cfg(windows)]
pub fn export_channel(channel: &str, query: &str, target: &Path) -> Result<()> {
    use windows::core::HSTRING;
    use windows::Win32::System::EventLog::{
        EvtExportLog, EvtExportLogChannelPath, EvtExportLogTolerateQueryErrors,
    };
    check_target(target)?;
    let channel_w = HSTRING::from(channel);
    let query_w = HSTRING::from(query);
    let target_w = HSTRING::from(target.as_os_str());
    let flags = EvtExportLogChannelPath.0 | EvtExportLogTolerateQueryErrors.0;
    // SAFETY: EvtExportLog takes three NUL-terminated UTF-16 strings and an integer.
    // Each HSTRING above owns a NUL-terminated buffer that outlives the call (they are
    // locals dropped after it returns), and `&HSTRING` yields a PCWSTR borrowing that
    // buffer. `session = None` means the local computer (no remote session handle to
    // manage). The API writes only to the NEW file at `target` and returns a BOOL that
    // the binding converts to `Result`; no handle is returned, so nothing needs closing.
    unsafe { EvtExportLog(None, &channel_w, &query_w, &target_w, flags) }
        .map_err(|e| err(format!("EvtExportLog({channel}): {e}")))
}

/// Non-Windows: there is no live event log to export.
#[cfg(not(windows))]
pub fn export_channel(channel: &str, _query: &str, target: &Path) -> Result<()> {
    check_target(target)?;
    Err(err(format!(
        "EVTX export of {channel} is only supported on Windows"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn since_xpath_is_a_utc_millisecond_window() {
        let since = Utc.with_ymd_and_hms(2026, 9, 21, 8, 5, 3).unwrap();
        assert_eq!(
            since_xpath(since),
            "*[System[TimeCreated[@SystemTime>='2026-09-21T08:05:03.000Z']]]"
        );
    }

    #[test]
    fn channel_file_name_follows_windows_convention_and_is_one_component() {
        assert_eq!(channel_file_name("Security"), "Security.evtx");
        assert_eq!(
            channel_file_name("Microsoft-Windows-Sysmon/Operational"),
            "Microsoft-Windows-Sysmon%4Operational.evtx"
        );
        let odd = channel_file_name(r"..\evil:name|x");
        assert!(!odd.contains(['\\', '/', ':', '|']), "{odd}");
        assert_eq!(channel_file_name(" .. "), "channel.evtx");
    }

    #[test]
    fn existing_target_is_refused() {
        let dir = std::env::temp_dir().join("cairn_evtx_export_existing");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("Security.evtx");
        std::fs::write(&target, b"keep").unwrap();
        let e = export_channel("Security", "*", &target).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }
}
