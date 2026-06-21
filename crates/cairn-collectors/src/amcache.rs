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
        let mut opened = open_hive(&mut reader, &AMCACHE_HIVE)?;

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

/// Return the first non-empty string from a slice of already-read candidates (in
/// order). All empty/absent → None (the caller drops the entry). Pure — the values are
/// read by the caller, so this is unit-testable without a hive and has no borrow tangle.
fn first_non_empty(candidates: &[Option<String>]) -> Option<String> {
    candidates.iter().flatten().find(|v| !v.is_empty()).cloned()
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
        // subkey returns Err here so the caller can skip the entry (flag + continue),
        // never aborting the whole collect (golden rule 8). Ok(None) = absent/non-string.
        let mut read = |name: &str| -> Result<Option<String>> {
            match get_value_string(parser, &key_path, name) {
                Ok(v) => Ok(v),
                Err(e) => {
                    entry_err.store(true, Ordering::Relaxed);
                    tracing::warn!(key = %sk.name, err = %e, "amcache: value read error; skipping entry");
                    Err(e)
                }
            }
        };

        // Read every path candidate first (any read Err skips the whole entry), THEN
        // pick the first non-empty via the pure selector. Reading into a Vec first
        // avoids nesting the parser-borrowing `read` closure inside another closure.
        let mut path_candidates: Vec<Option<String>> = Vec::with_capacity(spec.path_values.len());
        for name in spec.path_values {
            match read(name) {
                Ok(v) => path_candidates.push(v),
                Err(_) => continue 'subkeys, // read Err — entry skipped (flag already set)
            }
        }
        let path = match first_non_empty(&path_candidates) {
            Some(p) => p,
            None => continue 'subkeys, // no path = no evidence; local best-effort drop
        };

        let sha1 = match read(spec.sha1_value) {
            Err(_) => continue 'subkeys, // read Err — entry skipped
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
                assert_eq!(e.source, "amcache");
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
        eprintln!(
            "amcache_e2e_real_system_hive: parsed {} entries",
            recs.len()
        );
    }

    // ── first_non_empty unit tests ────────────────────────────────────────

    #[test]
    fn first_non_empty_returns_first_non_empty_in_order() {
        let candidates = vec![Some(String::new()), Some(r"C:\drivers\x.sys".to_string())];
        assert_eq!(
            first_non_empty(&candidates).as_deref(),
            Some(r"C:\drivers\x.sys")
        );
    }

    #[test]
    fn first_non_empty_all_empty_or_absent_is_none() {
        let candidates = vec![Some(String::new()), None];
        assert_eq!(first_non_empty(&candidates), None);
    }

    #[test]
    fn first_non_empty_single_value() {
        let candidates = vec![Some(r"C:\d.sys".to_string())];
        assert_eq!(first_non_empty(&candidates).as_deref(), Some(r"C:\d.sys"));
    }

    #[test]
    fn first_non_empty_empty_slice_is_none() {
        let candidates: Vec<Option<String>> = vec![];
        assert_eq!(first_non_empty(&candidates), None);
    }
}
