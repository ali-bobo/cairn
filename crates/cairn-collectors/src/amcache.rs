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

/// The InventoryApplicationFile key: one subkey per executable, holding LowerCaseLongPath
/// / Name (path) and FileId (SHA1). key_path_has_root = false (no root prefix).
const INVENTORY_APP_FILE_KEY: &str = "Root\\InventoryApplicationFile";

const VALUE_PATH: &str = "LowerCaseLongPath";
const VALUE_NAME: &str = "Name";
const VALUE_FILE_ID: &str = "FileId";

/// AmcacheCollector: privilege-gated, read-only InventoryApplicationFile read from a
/// locked Amcache.hve. Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
/// Emits Record::Execution (source="amcache", execution_confirmed=Some(true)).
#[derive(Default)]
pub struct AmcacheCollector {
    /// Amcache.hve exceeded the memory ceiling (parse abstained). NFR10/NFR12.
    abstained_truncated: AtomicBool,
    /// The InventoryApplicationFile key was absent (build variance — abstained). NFR12.
    key_absent: AtomicBool,
    /// A transaction log (.LOG1/.LOG2) existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
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

        let subkeys = list_subkeys(&mut opened.parser, INVENTORY_APP_FILE_KEY)?;
        if subkeys.is_empty() {
            self.key_absent.store(true, Ordering::Relaxed);
            tracing::warn!("amcache: InventoryApplicationFile absent/empty; abstaining");
            return Ok(Vec::new());
        }

        let mut records: Vec<Record> = Vec::new();
        for sk in subkeys {
            let key_path = format!("{INVENTORY_APP_FILE_KEY}\\{}", sk.name);
            // Path: LowerCaseLongPath, else Name, else drop (no path = no evidence).
            let path = match get_value_string(&mut opened.parser, &key_path, VALUE_PATH)? {
                Some(p) if !p.is_empty() => p,
                _ => match get_value_string(&mut opened.parser, &key_path, VALUE_NAME)? {
                    Some(n) if !n.is_empty() => n,
                    _ => continue, // local best-effort drop; no abstain flag
                },
            };
            let sha1 = get_value_string(&mut opened.parser, &key_path, VALUE_FILE_ID)?
                .and_then(|id| parse_sha1_from_fileid(&id));

            records.push(Record::Execution(ExecutionRecord {
                source: "amcache".into(),
                path,
                // Amcache InventoryApplicationFile has no real exec time; the subkey's
                // last-write is the industry first-seen approximation (NFR12: documented,
                // not a fabricated exec time).
                first_run: Some(sk.last_write),
                last_run: None,
                run_count: None,
                sha1,
                user_sid: None,
                // An InventoryApplicationFile entry means the OS registered the file as an
                // executable — stronger than shimcache "presence". Hence Some(true).
                execution_confirmed: Some(true),
            }));
        }

        // Determinism (NFR4): subkey enumeration order is physical; sort by path.
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => x.path.cmp(&y.path),
            _ => std::cmp::Ordering::Equal,
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
        if self.key_absent.load(Ordering::Relaxed) {
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
    fn sources_reports_key_absent_abstain() {
        let c = AmcacheCollector::default();
        c.key_absent.store(true, Ordering::Relaxed);
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
            } else {
                panic!("amcache must only emit Execution records");
            }
        }
        eprintln!(
            "amcache_e2e_real_system_hive: parsed {} entries",
            recs.len()
        );
    }
}
