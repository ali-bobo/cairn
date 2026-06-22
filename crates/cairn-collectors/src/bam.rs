//! BamCollector: parse the SYSTEM hive's Background Activity Moderator (bam)
//! UserSettings into per-SID Record::Execution with a real last-execution time.
//!
//! bam records the last background-activity time per program per user under
//! {ControlSet}\Services\bam\State\UserSettings\<SID>. Each value's NAME is the
//! executable's NT device path; its DATA begins with an 8-byte LE FILETIME. This is
//! reached via a raw \\.\C: hive read (the live registry denies the SYSTEM-only ACL).
//! On an absent key or unrecognised structure it ABSTAINS (records the reason) rather
//! than guess (NFR12).

use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use cairn_core::time::filetime_to_utc;

use crate::hive_reader::{list_subkeys, list_values, open_hive, LogStatus, SYSTEM_HIVE};

/// BamCollector: privilege-gated, read-only parse of the SYSTEM hive's bam UserSettings
/// into per-SID Record::Execution (source="bam", execution_confirmed=Some(true)).
/// Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
#[derive(Default)]
pub struct BamCollector {
    /// SYSTEM hive exceeded the memory ceiling (parse abstained). NFR10/NFR12.
    truncated: AtomicBool,
    /// The bam UserSettings key was absent/empty (build variance — abstained). NFR12.
    bam_key_absent: AtomicBool,
    /// A transaction log (.LOG1/.LOG2) existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
    /// At least one SID/value was skipped on a read error or impossible structure
    /// (non-binary / data<8). The rest still collected (golden rule 8); surfaced so the
    /// analyst knows the result is partial (NFR12).
    entry_read_errors: AtomicBool,
}

/// Read a REG_DWORD value (e.g. Select\Current) directly. Returns None if the key/value
/// is absent or not a DWORD. Kept local to bam to avoid widening hive_reader for one
/// caller (mirrors get_value_string's access pattern but for CellValue::U32).
fn read_dword(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Option<u32> {
    let key = parser.get_key(key_path, false).ok().flatten()?;
    let value = key.get_value(value_name)?;
    match value.get_content().0 {
        notatin::cell_value::CellValue::U32(n) => Some(n),
        _ => None,
    }
}

impl Collector for BamCollector {
    fn name(&self) -> &str {
        "bam"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors amcache/shimcache). The bam
        // UserSettings key is SYSTEM-ACL-protected and the SYSTEM hive is OS-locked, so
        // it is only reachable via a raw \\.\C: read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "bam".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let mut opened = open_hive(&mut reader, &SYSTEM_HIVE)?;

        if opened.truncated {
            self.truncated.store(true, Ordering::Relaxed);
            tracing::warn!("bam: SYSTEM hive exceeded ceiling; abstaining");
            return Ok(Vec::new());
        }
        if let LogStatus::Failed(reason) = &opened.log_status {
            self.log_replay_failed.store(true, Ordering::Relaxed);
            tracing::warn!(reason = %reason, "bam: log replay failed; primary-only");
        }

        // Resolve the active ControlSet from Select\Current; fall back to ControlSet001.
        let controlset = match read_dword(&mut opened.parser, "Select", "Current") {
            Some(n) => controlset_name(n),
            None => DEFAULT_CONTROLSET.to_string(),
        };
        let user_settings = format!("{controlset}\\Services\\bam\\State\\UserSettings");

        // Enumerate the per-SID subkeys.
        let sids = list_subkeys(&mut opened.parser, &user_settings)?;
        if sids.is_empty() {
            self.bam_key_absent.store(true, Ordering::Relaxed);
            tracing::warn!(key = %user_settings, "bam: UserSettings key absent/empty; abstaining");
            return Ok(Vec::new());
        }

        let mut records: Vec<Record> = Vec::new();
        for sid in sids {
            let sid_path = format!("{user_settings}\\{}", sid.name);
            let values = match list_values(&mut opened.parser, &sid_path) {
                Ok(v) => v,
                Err(e) => {
                    // A genuine read error on one SID skips that SID, not the whole run.
                    self.entry_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(sid = %sid.name, err = %e, "bam: SID value read error; skipping");
                    continue;
                }
            };
            for kv in values {
                match parse_bam_value(&kv.data) {
                    Some(last_run) => {
                        records.push(Record::Execution(ExecutionRecord {
                            source: "bam".into(),
                            path: kv.name, // NT device path, kept verbatim (NFR12)
                            first_run: None,
                            last_run: Some(last_run),
                            run_count: None,
                            sha1: None,
                            user_sid: Some(sid.name.clone()),
                            execution_confirmed: Some(true),
                        }));
                    }
                    None => {
                        // parse_bam_value returns None for data<8 OR a non-real time
                        // (ft==0 zero padding, or a pre-1970 FILETIME — filetime_to_utc
                        // rejects both). A non-real time is NOT an error (bam never has
                        // legitimate pre-1970 times), so it must NOT mark the result
                        // partial. Only a structurally-impossible value (data<8) is a
                        // partial signal. Distinguish: <8 bytes => entry_read_errors.
                        if kv.data.len() < 8 {
                            self.entry_read_errors.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        // Determinism (NFR4): enumeration order is physical; sort by (user_sid, path).
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => {
                x.user_sid.cmp(&y.user_sid).then(x.path.cmp(&y.path))
            }
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution emitted above
        });

        tracing::info!(bam_entries = records.len(), "bam scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.truncated.load(Ordering::Relaxed) {
            errors.push(
                "abstained: SYSTEM hive exceeded memory ceiling (NFR10); not parsed".to_string(),
            );
        }
        if self.bam_key_absent.load(Ordering::Relaxed) {
            errors
                .push("abstained: bam UserSettings key absent (build variance/NFR12)".to_string());
        }
        if self.log_replay_failed.load(Ordering::Relaxed) {
            errors.push(
                "log_replay_failed: transaction log present but unreadable; primary-only parse"
                    .to_string(),
            );
        }
        if self.entry_read_errors.load(Ordering::Relaxed) {
            errors.push("partial: one or more entries skipped (result incomplete)".to_string());
        }
        vec![SourceEntry {
            artifact: "bam".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

/// Parse the last-execution time from a bam value's data: the leading 8 bytes are a
/// little-endian FILETIME. Returns None if the data is shorter than 8 bytes or the
/// FILETIME is zero (legitimate "no time" padding). Never panics (bounds-checked).
fn parse_bam_value(data: &[u8]) -> Option<DateTime<Utc>> {
    let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
    let ft = u64::from_le_bytes(bytes);
    filetime_to_utc(ft)
}

/// Format a ControlSet key name from the `Select\Current` DWORD value, e.g.
/// 1 -> "ControlSet001". Zero-padded to 3 digits (the on-disk convention). Values >999
/// are not expected in practice (Windows uses 1-2, rarely 3) and produce wider output by
/// design — we do NOT clamp, since silently mapping a corrupt DWORD to a valid-looking
/// name would be harder to diagnose than honest wider output.
fn controlset_name(current: u32) -> String {
    format!("ControlSet{current:03}")
}

/// The ControlSet to use when `Select\Current` is unreadable/absent — the
/// overwhelmingly common active set. We proceed with this rather than abstain the whole
/// collect for a missing Select value (graceful degrade, golden rule 8).
const DEFAULT_CONTROLSET: &str = "ControlSet001";

#[cfg(test)]
mod tests {
    use super::*;

    use cairn_core::config::Config;

    /// FILETIME for 2021-01-01T00:00:00Z (verified: 132_539_328_000_000_000).
    const FT_2021: u64 = 132_539_328_000_000_000;

    #[test]
    fn parses_valid_8_byte_filetime() {
        let data = FT_2021.to_le_bytes().to_vec();
        let got = parse_bam_value(&data).expect("valid FILETIME must parse");
        assert_eq!(got, filetime_to_utc(FT_2021).unwrap());
    }

    #[test]
    fn trailing_padding_is_ignored() {
        // 8-byte FILETIME + 16 bytes of trailing padding must parse identically.
        let mut data = FT_2021.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 16]);
        let got = parse_bam_value(&data).expect("must parse despite padding");
        assert_eq!(got, filetime_to_utc(FT_2021).unwrap());
    }

    #[test]
    fn short_data_is_none_no_panic() {
        assert_eq!(parse_bam_value(&[]), None);
        assert_eq!(parse_bam_value(&[1, 2, 3]), None);
        assert_eq!(parse_bam_value(&[0u8; 7]), None); // one byte short
    }

    #[test]
    fn all_zero_filetime_is_none() {
        // Zero FILETIME is legitimate "no time" padding, not an error.
        assert_eq!(parse_bam_value(&[0u8; 8]), None);
        assert_eq!(parse_bam_value(&[0u8; 24]), None);
    }

    #[test]
    fn controlset_name_zero_pads_to_three_digits() {
        assert_eq!(controlset_name(0), "ControlSet000"); // honest output, not clamped
        assert_eq!(controlset_name(1), "ControlSet001");
        assert_eq!(controlset_name(2), "ControlSet002");
        assert_eq!(controlset_name(10), "ControlSet010");
        assert_eq!(controlset_name(123), "ControlSet123");
    }

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = BamCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_bam() {
        assert_eq!(BamCollector::default().name(), "bam");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = BamCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "bam");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_truncation_abstain() {
        let c = BamCollector::default();
        c.truncated.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("exceeded memory ceiling")));
    }

    #[test]
    fn sources_reports_bam_key_absent() {
        let c = BamCollector::default();
        c.bam_key_absent.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("UserSettings key absent")));
    }

    #[test]
    fn sources_reports_log_replay_failed() {
        let c = BamCollector::default();
        c.log_replay_failed.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("log_replay_failed")));
    }

    #[test]
    fn sources_reports_partial_on_entry_read_errors() {
        let c = BamCollector::default();
        c.entry_read_errors.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("partial")));
    }

    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors bam::tests::bam_e2e_real_system_hive -- --ignored --nocapture
    /// Proves the full chain: raw \\.\C: -> ntfs locate SYSTEM -> notatin parse
    /// (+ log replay) -> bam UserSettings -> Record::Execution.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn bam_e2e_real_system_hive() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        // Bind the collector so sources() reads the SAME instance whose flags collect()
        // set — a fresh BamCollector::default() would always report empty errors and make
        // the empty-result diagnostic inert.
        let collector = BamCollector::default();
        let recs = collector
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        eprintln!(
            "bam_e2e diagnostics: {} records; sources errors = {:?}",
            recs.len(),
            collector.sources()[0].errors
        );
        if recs.is_empty() {
            eprintln!(
                "NOTE: 0 bam records. If you are NOT running as Administrator with \
                 SeBackupPrivilege, that is the cause; re-run elevated. A genuinely empty \
                 bam (key_absent abstain) is also legitimate on some builds."
            );
        }
        // bam may be empty on some builds; that is legitimate (key_absent abstain).
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "bam");
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert_eq!(e.execution_confirmed, Some(true));
                let sid = e.user_sid.as_deref().unwrap_or("");
                assert!(
                    sid.starts_with("S-1-"),
                    "user_sid must be a SID, got {sid:?}"
                );
                assert!(e.last_run.is_some(), "bam must carry a last_run time");
                assert!(e.first_run.is_none(), "bam has no first_run");
                assert!(e.run_count.is_none(), "bam has no run_count");
                assert!(e.sha1.is_none(), "bam has no sha1");
            } else {
                panic!("bam must only emit Execution records");
            }
        }
    }
}
