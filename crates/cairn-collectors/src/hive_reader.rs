//! HiveReader: raw-locate a locked hive, read its bytes (+ .LOG1/.LOG2) entirely in
//! memory, and parse it with notatin. Reusable primitive for hive-backed collectors
//! (shimcache now; amcache/userassist later). Mirrors usn.rs: same VolumeReader +
//! ntfs find_child navigation, same catch_unwind third-party-panic containment, same
//! read_value_capped memory ceiling. No temp files (notatin from_file takes a reader).

use chrono::{DateTime, Utc};
use cairn_core::{CairnError, Result};

/// A locked hive's on-volume location. Drive prefix is fixed C: (reads \\.\C:),
/// matching mft/usn — $MFT carries no drive-letter info.
#[allow(dead_code)]
pub(crate) struct HivePath {
    /// Volume-relative path components, last element is the hive filename.
    pub components: &'static [&'static str],
}

/// SYSTEM hive — the only path wired this segment.
#[allow(dead_code)]
pub(crate) const SYSTEM_HIVE: HivePath = HivePath {
    components: &["Windows", "System32", "config", "SYSTEM"],
};

/// 512 MiB hard ceiling on a single hive's in-memory size (NFR10). A boot sector or
/// attribute length lying about size cannot force a larger allocation than this.
#[allow(dead_code)]
pub(crate) const HIVE_HARD_CEILING: u64 = 512 * 1024 * 1024;

/// Outcome of attempting transaction-log replay. Recorded in the manifest.
#[allow(dead_code)]
pub(crate) enum LogStatus {
    /// At least one of .LOG1/.LOG2 was found and handed to notatin.
    Applied,
    /// Neither log file was present (clean shutdown or logs absent) — primary only.
    NotFound,
    /// A log existed but reading it failed; primary-only parse proceeded.
    Failed(String),
}

/// Result of open_hive.
#[allow(dead_code)]
pub(crate) struct OpenedHive {
    pub parser: notatin::parser::Parser,
    pub log_status: LogStatus,
    /// True if the primary hive read hit HIVE_HARD_CEILING (abstain signal).
    pub truncated: bool,
}

/// Build a Collector-variant CairnError (mirrors usn_err/mft_err).
#[allow(dead_code)]
fn hive_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "hive".into(),
        reason,
    }
}

/// Fetch a single value's raw bytes + the owning key's last-write time.
/// Returns Ok(None) when the key or value is absent (graceful — golden rule 8).
///
/// key_path uses notatin's path syntax WITHOUT the root prefix (key_path_has_root =
/// false), e.g. r"ControlSet001\Control\Session Manager\AppCompatCache".
///
/// AppCompatCache is always REG_BINARY, so only the binary case matters; non-binary
/// values return Ok(None).
#[allow(dead_code, clippy::type_complexity)]
pub(crate) fn get_value_bytes(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Result<Option<(Vec<u8>, Option<DateTime<Utc>>)>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(None),
    };
    let last_write = key.last_key_written_date_and_time();
    let value = match key.get_value(value_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    // Confirmed from notatin 1.0.1 source (cell_value.rs):
    //   CellValue::Binary(Vec<u8>) — NOT ValueBinary.
    // get_content() returns (CellValue, Option<Logs>); .0 gives the CellValue.
    let bytes = match value.get_content().0 {
        notatin::cell_value::CellValue::Binary(b) => b,
        _ => return Ok(None),
    };
    Ok(Some((bytes, Some(last_write))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_hive_path_is_config_system() {
        assert_eq!(
            SYSTEM_HIVE.components,
            &["Windows", "System32", "config", "SYSTEM"]
        );
    }

    #[test]
    fn hive_err_is_collector_variant() {
        let e = hive_err("boom".into());
        assert!(matches!(e, cairn_core::CairnError::Collector { .. }));
    }

    #[test]
    fn log_status_variants_construct() {
        let _ = LogStatus::Applied;
        let _ = LogStatus::NotFound;
        let _ = LogStatus::Failed("x".into());
    }
}
