//! Live EVTX collector: reads C:\Windows\System32\winevt\Logs\ filtered by
//! the Sigma engine's referenced channels and a time window.
#![allow(dead_code)]

use cairn_core::manifest::SourceEntry;
use chrono::{DateTime, Utc};

const WINEVT_LOGS_DIR: &str = r"C:\Windows\System32\winevt\Logs";

/// Map a Sigma channel name to its on-disk `.evtx` filename.
/// Windows EVTX filenames encode `/` as `%4`.
pub fn channel_to_filename(channel: &str) -> String {
    format!("{}.evtx", channel.replace('/', "%4"))
}

/// Map an on-disk `.evtx` filename back to a channel name (inverse of `channel_to_filename`).
/// Returns None if the file does not have a `.evtx` extension.
pub fn filename_to_channel(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".evtx")?;
    Some(stem.replace("%4", "/"))
}

/// True if `ts` is at or after `since`.
pub fn event_is_recent(ts: DateTime<Utc>, since: DateTime<Utc>) -> bool {
    ts >= since
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

// Collector impl will be added in Task 2.

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(filename_to_channel("Security.evtx"), Some("Security".to_string()));
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
        let old_ts = chrono::Utc.with_ymd_and_hms(2026, 6, 26, 23, 59, 59).unwrap();
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
}
