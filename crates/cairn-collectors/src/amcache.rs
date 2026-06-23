//! AmcacheCollector: parse Amcache.hve InventoryApplicationFile entries into
//! Record::Execution (path + SHA1 + first-exec approximation).
//!
//! Amcache.hve is a structured registry hive (unlike shimcache's single blob). Each
//! file under InventoryApplicationFile is a subkey whose named values carry the path
//! (LowerCaseLongPath / Name) and a SHA1 (FileId). first_run is approximated by the
//! subkey's last-write time (the industry-accepted Amcache first-seen). On an absent
//! key or unrecognised structure it ABSTAINS (records the reason in the manifest)
//! rather than guess — misreading a forensic artifact is worse than abstaining (NFR12).
//! This segment parses InventoryApplicationFile only.

use std::sync::atomic::{AtomicBool, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use crate::hive_reader::{get_value_string, list_subkeys, open_hive, LogStatus, AMCACHE_HIVE};

/// Spec for the InventoryDriverBinary inventory key (driver binaries — BYOVD evidence).
const DRIVER_SPEC: InventorySpec = InventorySpec {
    key_path: "Root\\InventoryDriverBinary",
    source: "amcache_driver",
    sha1_value: "DriverId",
    path_values: &["DriverName"],
};

/// Spec for the InventoryApplicationFile inventory key.
const APP_FILE_SPEC: InventorySpec = InventorySpec {
    key_path: "Root\\InventoryApplicationFile",
    source: "amcache",
    sha1_value: "FileId",
    path_values: &["LowerCaseLongPath", "Name"],
};

/// AmcacheCollector: privilege-gated, read-only InventoryApplicationFile read from a
/// locked Amcache.hve. Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
/// Emits Record::Execution (source="amcache", execution_confirmed=Some(true)).
#[derive(Default)]
pub struct AmcacheCollector {
    /// Amcache.hve exceeded the memory ceiling (parse abstained). NFR10/NFR12.
    abstained_truncated: AtomicBool,
    /// The InventoryApplicationFile key was absent (build variance — abstained). NFR12.
    app_key_absent: AtomicBool,
    /// A transaction log (.LOG1/.LOG2) existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
    /// The InventoryDriverBinary key was absent (build variance — abstained). NFR12.
    driver_key_absent: AtomicBool,
    /// At least one subkey's value read failed mid-hive; that entry was skipped and the
    /// rest still collected (graceful degrade — golden rule 8). Surfaced so the analyst
    /// knows the result is partial rather than silently dropping evidence (NFR12).
    entry_read_errors: AtomicBool,
}

impl Collector for AmcacheCollector {
    fn name(&self) -> &str {
        "amcache"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors shimcache). Amcache.hve is
        // held open by the OS, so it is only reachable via a raw \\.\C: read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "amcache".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let mut opened = open_hive(&mut reader, &AMCACHE_HIVE())?;

        if opened.truncated {
            self.abstained_truncated.store(true, Ordering::Relaxed);
            tracing::warn!("amcache: Amcache.hve exceeded ceiling; abstaining");
            return Ok(Vec::new());
        }
        if let LogStatus::Failed(reason) = &opened.log_status {
            self.log_replay_failed.store(true, Ordering::Relaxed);
            tracing::warn!(reason = %reason, "amcache: log replay failed; primary-only");
        }

        let mut records = collect_inventory(
            &mut opened.parser,
            &APP_FILE_SPEC,
            &self.app_key_absent,
            &self.entry_read_errors,
        )?;

        // Driver binaries (BYOVD evidence). Independent per-key degrade: an absent
        // driver key does NOT suppress the app records already collected, and vice versa.
        let driver_records = collect_inventory(
            &mut opened.parser,
            &DRIVER_SPEC,
            &self.driver_key_absent,
            &self.entry_read_errors,
        )?;
        records.extend(driver_records);

        // Determinism (NFR4): subkey enumeration order is physical; sort by path.
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => x.path.cmp(&y.path),
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution is emitted above
        });

        tracing::info!(amcache_entries = records.len(), "amcache scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.abstained_truncated.load(Ordering::Relaxed) {
            errors.push(
                "abstained: Amcache.hve exceeded memory ceiling (NFR10); not parsed".to_string(),
            );
        }
        if self.app_key_absent.load(Ordering::Relaxed) {
            errors.push(
                "abstained: InventoryApplicationFile key absent (build variance/NFR12)".to_string(),
            );
        }
        if self.driver_key_absent.load(Ordering::Relaxed) {
            errors.push(
                "abstained: InventoryDriverBinary key absent (build variance/NFR12)".to_string(),
            );
        }
        if self.log_replay_failed.load(Ordering::Relaxed) {
            errors.push(
                "log_replay_failed: transaction log present but unreadable; primary-only parse"
                    .to_string(),
            );
        }
        if self.entry_read_errors.load(Ordering::Relaxed) {
            errors.push(
                "partial: one or more entries skipped on a value read error (result incomplete)"
                    .to_string(),
            );
        }
        vec![SourceEntry {
            artifact: "amcache".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

/// Parse the SHA1 out of an Amcache FileId value.
///
/// FileId format is the string "0000" + 40 lowercase hex (44 chars total). A
/// non-conforming value yields None (the entry is still emitted with sha1=None —
/// NFR12 honesty: never write a malformed value into a SHA1 field).
fn parse_sha1_from_fileid(field: &str) -> Option<String> {
    // Operate on chars, not bytes, so multibyte input can never panic on slicing.
    let chars: Vec<char> = field.chars().collect();
    if chars.len() != 44 {
        return None;
    }
    // First 4 chars must be the literal "0000" (ASCII digits; no case applies).
    if chars[0..4] != ['0', '0', '0', '0'] {
        return None;
    }
    let body: String = chars[4..].iter().collect();
    if !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(body.to_ascii_lowercase())
}

/// A pure-data description of one Amcache inventory key, so one helper can serve both
/// InventoryApplicationFile and InventoryDriverBinary (and future keys) — the only
/// difference between them is data, not logic.
struct InventorySpec {
    /// notatin key path (key_path_has_root = false).
    key_path: &'static str,
    /// ExecutionRecord.source tag for entries from this key.
    source: &'static str,
    /// REG_SZ value holding the "0000"+40hex SHA1.
    sha1_value: &'static str,
    /// Path candidates, tried in order; first non-empty wins, else the entry is dropped.
    path_values: &'static [&'static str],
}

/// Try value names in order, returning the first non-empty value, STOPPING as soon as
/// one is found (later names are never read). `read` returns `Ok(Some)` = value present,
/// `Ok(None)` = absent/non-string, `Err(())` = a genuine read error. Result:
/// - `Ok(Some(v))` — first non-empty value found,
/// - `Ok(None)`    — every consulted name was empty/absent (caller drops the entry),
/// - `Err(())`     — a read error on a CONSULTED name (caller skips the entry).
///
/// Pure given `read`: the early-stop logic is unit-testable with a fake `read`, and
/// because `read` is a `&mut` function parameter (not a closure captured inside another
/// closure) there is no borrow tangle with the caller's parser-borrowing `read`.
fn first_non_empty_read(
    names: &[&str],
    read: &mut impl FnMut(&str) -> std::result::Result<Option<String>, ()>,
) -> std::result::Result<Option<String>, ()> {
    for name in names {
        match read(name)? {
            Some(v) if !v.is_empty() => return Ok(Some(v)),
            _ => {} // empty/absent — try the next name
        }
    }
    Ok(None)
}

/// Enumerate one inventory key's subkeys into Record::Execution. Shared by both the
/// InventoryApplicationFile and InventoryDriverBinary specs.
///
/// Flags: `key_absent` is set when the key has no subkeys (build variance abstain);
/// `entry_err` is set when a per-subkey value read fails (that entry is skipped, the
/// rest continue — golden rule 8). The helper knows only "two flags", not which spec.
fn collect_inventory(
    parser: &mut notatin::parser::Parser,
    spec: &InventorySpec,
    key_absent: &std::sync::atomic::AtomicBool,
    entry_err: &std::sync::atomic::AtomicBool,
) -> Result<Vec<Record>> {
    let subkeys = list_subkeys(parser, spec.key_path)?;
    if subkeys.is_empty() {
        key_absent.store(true, Ordering::Relaxed);
        tracing::warn!(
            key = spec.key_path,
            "amcache: inventory key absent/empty; abstaining"
        );
        return Ok(Vec::new());
    }

    let mut records: Vec<Record> = Vec::new();
    'subkeys: for sk in subkeys {
        let key_path = format!("{}\\{}", spec.key_path, sk.name);
        // Read one value, degrading gracefully: a genuine mid-hive read Err on ONE
        // subkey returns Err(()) here so the caller can skip the entry (flag + continue),
        // never aborting the whole collect (golden rule 8). Ok(None) = absent/non-string.
        // The () error type (the detail is logged + flagged here) lets `read` slot
        // directly into first_non_empty_read without a nested closure.
        let mut read = |name: &str| -> std::result::Result<Option<String>, ()> {
            match get_value_string(parser, &key_path, name) {
                Ok(v) => Ok(v),
                Err(e) => {
                    entry_err.store(true, Ordering::Relaxed);
                    tracing::warn!(key = %sk.name, err = %e, "amcache: value read error; skipping entry");
                    Err(())
                }
            }
        };

        // Path: try path_values in order, STOPPING at the first non-empty value — a
        // later candidate is never read once an earlier one succeeds. This matches the
        // original nested-match semantics exactly (a non-empty LowerCaseLongPath means
        // Name is never touched, so a corrupt Name cannot drop an otherwise-good entry).
        // A read Err on a candidate we DO consult skips the entry (golden rule 8).
        let path = match first_non_empty_read(spec.path_values, &mut read) {
            Err(()) => continue 'subkeys, // read Err on a consulted candidate — skip
            Ok(Some(p)) => p,
            Ok(None) => continue 'subkeys, // all consulted empty/absent — no path, drop
        };

        let sha1 = match read(spec.sha1_value) {
            Err(()) => continue 'subkeys, // read Err — entry skipped
            Ok(opt) => opt.and_then(|id| parse_sha1_from_fileid(&id)),
        };

        records.push(Record::Execution(ExecutionRecord {
            source: spec.source.into(),
            path,
            first_run: Some(sk.last_write),
            last_run: None,
            run_count: None,
            sha1,
            user_sid: None,
            execution_confirmed: Some(true),
        }));
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cairn_core::config::Config;
    use std::sync::atomic::Ordering;

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = AmcacheCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_amcache() {
        assert_eq!(AmcacheCollector::default().name(), "amcache");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = AmcacheCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "amcache");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_truncation_abstain() {
        let c = AmcacheCollector::default();
        c.abstained_truncated.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0]
            .errors
            .iter()
            .any(|e| e.contains("exceeded memory ceiling")));
    }

    // ── first_non_empty_read unit tests (early-stop selector) ────────────────

    #[test]
    fn first_non_empty_read_stops_at_first_non_empty() {
        // The second name must NEVER be read once the first is non-empty.
        let mut reads: Vec<String> = Vec::new();
        let mut read = |name: &str| -> std::result::Result<Option<String>, ()> {
            reads.push(name.to_string());
            match name {
                "A" => Ok(Some(r"C:\a.sys".to_string())),
                _ => Ok(Some("should-not-be-read".to_string())),
            }
        };
        let got = first_non_empty_read(&["A", "B"], &mut read);
        assert_eq!(got, Ok(Some(r"C:\a.sys".to_string())));
        assert_eq!(reads, vec!["A"], "B must not be read once A is non-empty");
    }

    #[test]
    fn first_non_empty_read_skips_empty_then_takes_next() {
        let mut read = |name: &str| -> std::result::Result<Option<String>, ()> {
            match name {
                "A" => Ok(Some(String::new())), // empty → skip
                "B" => Ok(Some(r"C:\b.sys".to_string())),
                _ => Ok(None),
            }
        };
        assert_eq!(
            first_non_empty_read(&["A", "B"], &mut read),
            Ok(Some(r"C:\b.sys".to_string()))
        );
    }

    #[test]
    fn first_non_empty_read_all_empty_or_absent_is_ok_none() {
        let mut read = |name: &str| -> std::result::Result<Option<String>, ()> {
            match name {
                "A" => Ok(Some(String::new())),
                _ => Ok(None),
            }
        };
        assert_eq!(first_non_empty_read(&["A", "B"], &mut read), Ok(None));
    }

    #[test]
    fn first_non_empty_read_propagates_read_err() {
        // A read Err on a CONSULTED name short-circuits to Err(()).
        let mut read = |_name: &str| -> std::result::Result<Option<String>, ()> { Err(()) };
        assert_eq!(first_non_empty_read(&["A", "B"], &mut read), Err(()));
    }

    #[test]
    fn first_non_empty_read_empty_names_is_ok_none() {
        let mut read = |_name: &str| -> std::result::Result<Option<String>, ()> { Ok(None) };
        assert_eq!(first_non_empty_read(&[], &mut read), Ok(None));
    }

    #[test]
    fn sources_reports_driver_key_absent() {
        let c = AmcacheCollector::default();
        c.driver_key_absent.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0]
            .errors
            .iter()
            .any(|e| e.contains("InventoryDriverBinary key absent")));
    }

    #[test]
    fn sources_reports_app_key_absent() {
        let c = AmcacheCollector::default();
        c.app_key_absent.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0]
            .errors
            .iter()
            .any(|e| e.contains("InventoryApplicationFile key absent")));
    }

    #[test]
    fn sources_reports_log_replay_failed() {
        let c = AmcacheCollector::default();
        c.log_replay_failed.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0].errors.iter().any(|e| e.contains("log_replay_failed")));
    }

    #[test]
    fn sources_reports_partial_on_entry_read_errors() {
        let c = AmcacheCollector::default();
        c.entry_read_errors.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0].errors.iter().any(|e| e.contains("partial")));
    }

    // ── SHA1 parser unit tests ────────────────────────────────────────────────

    #[test]
    fn conforming_fileid_yields_lowercase_sha1() {
        let id = "0000aabbccddeeff00112233445566778899aabbccdd";
        assert_eq!(id.len() - 4, 40); // sanity on the fixture
        let full = format!("0000{}", &id[4..]);
        let got = parse_sha1_from_fileid(&full);
        assert_eq!(got.as_deref(), Some(&id[4..]));
    }

    #[test]
    fn uppercase_hex_is_normalised_to_lowercase() {
        let full = "0000AABBCCDDEEFF00112233445566778899AABBCCDD".to_string();
        // 4 + 40 = 44 chars; build exactly 44.
        assert_eq!(full.len(), 44);
        let got = parse_sha1_from_fileid(&full).unwrap();
        assert_eq!(got, got.to_ascii_lowercase());
        assert_eq!(got.len(), 40);
    }

    #[test]
    fn wrong_length_is_none() {
        assert_eq!(parse_sha1_from_fileid(""), None);
        assert_eq!(parse_sha1_from_fileid("0000"), None);
        assert_eq!(parse_sha1_from_fileid("0000abcd"), None); // too short
        let too_long = format!("0000{}", "a".repeat(41));
        assert_eq!(parse_sha1_from_fileid(&too_long), None);
    }

    #[test]
    fn wrong_prefix_is_none() {
        // 44 chars, valid hex, but prefix is not 0000.
        let full = format!("1234{}", "a".repeat(40));
        assert_eq!(full.len(), 44);
        assert_eq!(parse_sha1_from_fileid(&full), None);
    }

    #[test]
    fn non_hex_body_is_none() {
        // 44 chars, 0000 prefix, but body has a non-hex char ('g').
        let full = format!("0000{}", "g".repeat(40));
        assert_eq!(full.len(), 44);
        assert_eq!(parse_sha1_from_fileid(&full), None);
    }

    #[test]
    fn no_panic_on_multibyte_input() {
        // Multibyte chars: len() is byte length. A 44-BYTE string that is not 44
        // ASCII chars must not panic on slicing. "é" is 2 bytes.
        let s = "é".repeat(22); // 44 bytes, 22 chars
        let _ = parse_sha1_from_fileid(&s); // must not panic
    }

    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors amcache::tests::amcache_e2e_real_system_hive -- --ignored --nocapture
    /// Proves the full chain: raw \\.\C: -> ntfs locate Amcache.hve -> notatin parse
    /// (+ log replay) -> InventoryApplicationFile -> Record::Execution.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn amcache_e2e_real_system_hive() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        let recs = AmcacheCollector::default()
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        assert!(!recs.is_empty(), "expected at least one amcache entry");
        for r in &recs {
            if let Record::Execution(e) = r {
                assert!(
                    e.source == "amcache" || e.source == "amcache_driver",
                    "unexpected source: {}",
                    e.source
                );
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert_eq!(e.execution_confirmed, Some(true));
                // NFR12: amcache never fabricates an exec time into last_run.
                assert!(e.last_run.is_none(), "amcache must not claim a last_run");
                // first_run (subkey last-write) must be propagated end-to-end, not dropped.
                assert!(
                    e.first_run.is_some(),
                    "amcache must carry a first_seen time"
                );
                // SHA1, when present, is exactly 40 lowercase hex chars (strict parse).
                if let Some(h) = &e.sha1 {
                    assert_eq!(h.len(), 40, "sha1 must be 40 hex chars");
                    assert!(
                        h.chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                        "sha1 must be lowercase hex"
                    );
                }
            } else {
                panic!("amcache must only emit Execution records");
            }
        }
        let drivers = recs
            .iter()
            .filter(|r| matches!(r, Record::Execution(e) if e.source == "amcache_driver"))
            .count();
        eprintln!("amcache_e2e_real_system_hive: {} driver entries", drivers);
        eprintln!(
            "amcache_e2e_real_system_hive: parsed {} entries",
            recs.len()
        );
    }
}
