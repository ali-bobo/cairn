//! UserAssistCollector: parse each user's NTUSER.DAT UserAssist into Record::Execution
//! with a real GUI launch count + last-execution time.
//!
//! UserAssist (Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\
//! Count) records Explorer-launched programs per user. Each value's NAME is the
//! executable path ROT13-encoded; its DATA is a 72-byte struct with run_count at
//! offset 4 and a last-run FILETIME at offset 60. Reached via a raw \\.\C: read of each
//! C:\Users\<name>\NTUSER.DAT (the live hive is locked). user_sid is resolved by
//! reverse-lookup against the SOFTWARE hive's ProfileList. On an absent key or
//! unrecognised structure it ABSTAINS (records the reason) rather than guess (NFR12).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::time::filetime_to_utc;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use crate::hive_reader::{
    get_value_string, list_dir_names, list_subkeys, list_values, open_hive, HivePath, LogStatus,
    SOFTWARE_HIVE,
};

/// Decode a ROT13-encoded ASCII string (UserAssist value names are ROT13). Pure: each
/// ASCII letter is rotated 13 places; every non-alphabetic byte (digits, braces, path
/// separators, dots) passes through unchanged. Never panics. Self-inverse.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            other => other,
        })
        .collect()
}

/// Parse the UserAssist 72-byte value struct. Returns:
/// - `Some((run_count, Some(last_run)))` — both fields present and last_run is a real time
/// - `Some((run_count, None))` — run_count present but FILETIME absent (data < 68 bytes)
///   or zero/pre-1970 (filetime_to_utc rejects those: a launch count with no usable time)
/// - `None` — data shorter than 8 bytes (run_count itself unreadable: not a real record)
///
/// Layout (verified on this Win11 host, classic Win7+ UserAssist):
///   offset 4  : u32 LE run_count
///   offset 60 : u64 LE FILETIME (last execution)
/// Never panics — all reads via slice::get (Option), never index slicing.
fn parse_userassist(data: &[u8]) -> Option<(u32, Option<DateTime<Utc>>)> {
    // run_count is the minimum to call this a record; < 8 bytes => not a record.
    let count_bytes: [u8; 4] = data.get(4..8)?.try_into().ok()?;
    let run_count = u32::from_le_bytes(count_bytes);

    // FILETIME is best-effort: absent field (data < 68) or a non-real time => None,
    // but the run_count still stands. filetime_to_utc rejects ft==0 and pre-1970.
    let last_run = data
        .get(60..68)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .and_then(filetime_to_utc);

    Some((run_count, last_run))
}

/// Normalize a ProfileImagePath (or a C:\Users\<name> path) to the map key: lowercased.
/// Pure — the lookup is case-insensitive because Windows paths are.
fn profile_map_key(path: &str) -> String {
    path.to_ascii_lowercase()
}

/// Build a { lowercased ProfileImagePath -> SID } map from a parsed SOFTWARE hive's
/// ProfileList. Used to resolve a user folder back to its SID. A read failure on the
/// ProfileList (or any individual entry) is non-fatal — this is ENRICHMENT, not core
/// data: callers fall back to user_sid = None and emit records anyway (no abstain flag).
/// Returns an empty map (not Err) if ProfileList is absent.
///
/// `parser` is &mut for notatin's lazy cursor (same as list_subkeys/get_value_string).
fn build_profilelist_map(parser: &mut notatin::parser::Parser) -> HashMap<String, String> {
    const PROFILE_LIST: &str = r"Microsoft\Windows NT\CurrentVersion\ProfileList";
    let mut map = HashMap::new();
    // list_subkeys returns Ok(vec![]) on absent key; an Err is a genuine read failure —
    // treat it as "no enrichment available" (return whatever we have, empty).
    let sids = match list_subkeys(parser, PROFILE_LIST) {
        Ok(s) => s,
        Err(_) => return map,
    };
    for sid in sids {
        let key_path = format!("{PROFILE_LIST}\\{}", sid.name);
        // ProfileImagePath is REG_EXPAND_SZ; get_value_string maps it to a String.
        if let Ok(Some(path)) = get_value_string(parser, &key_path, "ProfileImagePath") {
            if !path.is_empty() {
                map.insert(profile_map_key(&path), sid.name);
            }
        }
        // A missing/failed ProfileImagePath for one SID just omits that mapping.
    }
    map
}

/// UserAssistCollector: privilege-gated, read-only parse of every user's NTUSER.DAT
/// UserAssist into Record::Execution (source="userassist", execution_confirmed=
/// Some(true)). Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
#[derive(Default)]
pub struct UserAssistCollector {
    /// C:\Users enumeration failed — cannot find any user hive (abstained). NFR12.
    users_dir_unreadable: AtomicBool,
    /// No NTUSER had a UserAssist key (build variance — abstained). NFR12.
    no_userassist: AtomicBool,
    /// A user hive's transaction log existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
    /// A NTUSER that EXISTS failed to open/parse, or a value/struct was malformed; that
    /// item was skipped and the rest still collected (golden rule 8). Surfaced so the
    /// analyst knows the result is partial (NFR12). A simply-absent NTUSER is NOT this.
    entry_read_errors: AtomicBool,
}

/// The UserAssist parent key inside a NTUSER hive (key_path is hive-root-relative).
const USERASSIST_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

impl Collector for UserAssistCollector {
    fn name(&self) -> &str {
        "userassist"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors bam/amcache). NTUSER.DAT and
        // SOFTWARE are OS-locked, reachable only via a raw \\.\C: read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "userassist".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;

        // (1) Build the ProfileList reverse map (enrichment). A failure to open SOFTWARE
        // is non-fatal: we proceed with an empty map (user_sid = None for all).
        let profile_map = match open_hive(&mut reader, &SOFTWARE_HIVE()) {
            Ok(mut sw) if !sw.truncated => {
                if let LogStatus::Failed(reason) = &sw.log_status {
                    self.log_replay_failed.store(true, Ordering::Relaxed);
                    tracing::warn!(reason = %reason, "userassist: SOFTWARE log replay failed");
                }
                build_profilelist_map(&mut sw.parser)
            }
            _ => {
                tracing::warn!("userassist: SOFTWARE hive unavailable; user_sid will be None");
                HashMap::new()
            }
        };

        // (2) Enumerate C:\Users subdirectories.
        let users_dir = HivePath {
            components: vec!["Users".to_string()],
        };
        let user_dirs = match list_dir_names(&mut reader, &users_dir) {
            Ok(d) => d,
            Err(e) => {
                self.users_dir_unreadable.store(true, Ordering::Relaxed);
                tracing::warn!(err = %e, "userassist: C:\\Users enumeration failed; abstaining");
                return Ok(Vec::new());
            }
        };

        // (3) Per user: open NTUSER.DAT, walk UserAssist\<GUID>\Count.
        let mut records: Vec<Record> = Vec::new();
        let mut any_userassist_key = false;
        for user_dir in user_dirs {
            let hive_path = HivePath::user_ntuser(&user_dir);
            let mut opened = match open_hive(&mut reader, &hive_path) {
                Ok(o) => o,
                Err(e) => {
                    // Distinguish absent (system folders w/o NTUSER.DAT) from a genuine
                    // read failure. open_hive's "not found in directory" message means the
                    // file simply isn't there -> silent graceful skip (NOT a partial signal).
                    if e.to_string().contains("not found in directory") {
                        continue; // absent NTUSER.DAT — legitimate, skip silently
                    }
                    self.entry_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(user = %user_dir, err = %e, "userassist: NTUSER open failed; skipping");
                    continue;
                }
            };
            if opened.truncated {
                self.entry_read_errors.store(true, Ordering::Relaxed);
                tracing::warn!(user = %user_dir, "userassist: NTUSER exceeded ceiling; skipping");
                continue;
            }
            if let LogStatus::Failed(reason) = &opened.log_status {
                self.log_replay_failed.store(true, Ordering::Relaxed);
                tracing::warn!(user = %user_dir, reason = %reason, "userassist: NTUSER log replay failed");
            }

            // Resolve this user's SID via the ProfileList map (C:\Users\<name>).
            let user_path = format!(r"C:\Users\{user_dir}");
            let user_sid = profile_map.get(&profile_map_key(&user_path)).cloned();

            // The GUID subkeys under UserAssist.
            let guids = match list_subkeys(&mut opened.parser, USERASSIST_KEY) {
                Ok(g) => g,
                Err(e) => {
                    self.entry_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(user = %user_dir, err = %e, "userassist: GUID enum failed; skipping user");
                    continue;
                }
            };
            if guids.is_empty() {
                continue; // this NTUSER has no UserAssist key — skip (not an error)
            }
            any_userassist_key = true;

            for guid in guids {
                // Count is a constant child of each GUID; build the path directly.
                let count_path = format!("{USERASSIST_KEY}\\{}\\Count", guid.name);
                let values = match list_values(&mut opened.parser, &count_path) {
                    Ok(v) => v,
                    Err(e) => {
                        self.entry_read_errors.store(true, Ordering::Relaxed);
                        tracing::warn!(user = %user_dir, guid = %guid.name, err = %e, "userassist: Count value read failed; skipping");
                        continue;
                    }
                };
                for kv in values {
                    let path = rot13(&kv.name);
                    match parse_userassist(&kv.data) {
                        Some((run_count, last_run)) => {
                            records.push(Record::Execution(ExecutionRecord {
                                source: "userassist".into(),
                                path,
                                first_run: None,
                                last_run,
                                run_count: Some(run_count),
                                sha1: None,
                                user_sid: user_sid.clone(),
                                execution_confirmed: Some(true),
                            }));
                        }
                        None => {
                            // data < 8 bytes: structurally impossible UserAssist value.
                            self.entry_read_errors.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        if !any_userassist_key {
            self.no_userassist.store(true, Ordering::Relaxed);
            tracing::warn!("userassist: no UserAssist key found in any user hive; abstaining");
        }

        // Determinism (NFR4): enumeration order is physical; sort by (user_sid, path).
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => {
                x.user_sid.cmp(&y.user_sid).then(x.path.cmp(&y.path))
            }
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution emitted above
        });

        tracing::info!(userassist_entries = records.len(), "userassist scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.users_dir_unreadable.load(Ordering::Relaxed) {
            errors.push("abstained: C:\\Users enumeration failed (NFR12)".to_string());
        }
        if self.no_userassist.load(Ordering::Relaxed) {
            errors.push(
                "abstained: no UserAssist key in any user hive (build variance/NFR12)".to_string(),
            );
        }
        if self.log_replay_failed.load(Ordering::Relaxed) {
            errors.push(
                "log_replay_failed: a user hive's transaction log was unreadable; primary-only"
                    .to_string(),
            );
        }
        if self.entry_read_errors.load(Ordering::Relaxed) {
            errors.push(
                "partial: one or more user hives or entries skipped (result incomplete)"
                    .to_string(),
            );
        }
        vec![SourceEntry {
            artifact: "userassist".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cairn_core::config::Config;

    #[test]
    fn rot13_decodes_ueme_marker() {
        // The well-known UserAssist session marker, verified on-host.
        assert_eq!(rot13("HRZR_PGYFRFFVBA"), "UEME_CTLSESSION");
    }

    #[test]
    fn rot13_is_self_inverse() {
        let s = "UEME_RUNPATH:C:\\Windows\\notepad.exe";
        assert_eq!(rot13(&rot13(s)), s);
    }

    #[test]
    fn rot13_passes_non_alpha_through_unchanged() {
        // Digits, braces, backslash, colon, dot must be untouched (GUID + path chars).
        let s = "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\\1.2_3";
        // Only the letters rotate; the structure (digits/braces/sep) is preserved.
        let decoded = rot13(s);
        assert_eq!(decoded.len(), s.len());
        assert!(decoded.contains('{') && decoded.contains('}') && decoded.contains('\\'));
        assert!(decoded.contains("1.2_3")); // digits + dot + underscore unchanged
    }

    #[test]
    fn rot13_empty_string() {
        assert_eq!(rot13(""), "");
    }

    #[test]
    fn rot13_mixed_case_preserves_case() {
        assert_eq!(rot13("AbZz"), "NoMm");
    }

    /// FILETIME for 2021-01-01T00:00:00Z (same constant bam uses; verified value).
    const FT_2021: u64 = 132_539_328_000_000_000;

    /// Build a 72-byte UserAssist value: run_count @ 4, FILETIME @ 60, rest zero.
    fn make_ua(run_count: u32, filetime: u64) -> Vec<u8> {
        let mut v = vec![0u8; 72];
        v[4..8].copy_from_slice(&run_count.to_le_bytes());
        v[60..68].copy_from_slice(&filetime.to_le_bytes());
        v
    }

    #[test]
    fn parses_run_count_and_filetime() {
        let data = make_ua(4, FT_2021);
        let (count, last) = parse_userassist(&data).expect("valid 72-byte record parses");
        assert_eq!(count, 4);
        assert_eq!(last, cairn_core::time::filetime_to_utc(FT_2021));
    }

    #[test]
    fn zero_filetime_yields_count_with_no_last_run() {
        // run_count present but FILETIME==0 → Some((n, None)): a real count, no time.
        let data = make_ua(7, 0);
        let (count, last) = parse_userassist(&data).expect("count present even with ft==0");
        assert_eq!(count, 7);
        assert_eq!(last, None);
    }

    #[test]
    fn data_shorter_than_run_count_field_is_none() {
        // Can't even read run_count (needs >= 8 bytes) → None, no panic.
        assert_eq!(parse_userassist(&[]), None);
        assert_eq!(parse_userassist(&[0u8; 7]), None);
    }

    #[test]
    fn data_with_run_count_but_no_filetime_field_is_some_none() {
        // >= 8 bytes (run_count readable) but < 68 (no FILETIME): count present, last None.
        let mut data = vec![0u8; 8];
        data[4..8].copy_from_slice(&9u32.to_le_bytes());
        let (count, last) = parse_userassist(&data).expect("run_count readable at >=8 bytes");
        assert_eq!(count, 9);
        assert_eq!(last, None, "no FILETIME field present");
    }

    #[test]
    fn trailing_bytes_beyond_72_are_ignored() {
        let mut data = make_ua(3, FT_2021);
        data.extend_from_slice(&[0xAA; 16]);
        let (count, last) = parse_userassist(&data).expect("parses despite trailing bytes");
        assert_eq!(count, 3);
        assert_eq!(last, cairn_core::time::filetime_to_utc(FT_2021));
    }

    #[test]
    fn profile_map_key_lowercases() {
        assert_eq!(profile_map_key(r"C:\Users\Alice"), r"c:\users\alice");
        assert_eq!(profile_map_key(r"C:\Users\Bob"), r"c:\users\bob");
    }

    #[test]
    fn profile_map_key_idempotent_on_lowercase() {
        assert_eq!(profile_map_key(r"c:\users\alice"), r"c:\users\alice");
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
        let r = UserAssistCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_userassist() {
        assert_eq!(UserAssistCollector::default().name(), "userassist");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = UserAssistCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "userassist");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_users_dir_unreadable() {
        let c = UserAssistCollector::default();
        c.users_dir_unreadable.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("C:\\Users enumeration failed")));
    }

    #[test]
    fn sources_reports_no_userassist() {
        let c = UserAssistCollector::default();
        c.no_userassist.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("no UserAssist key")));
    }

    #[test]
    fn sources_reports_log_replay_failed() {
        let c = UserAssistCollector::default();
        c.log_replay_failed.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("log_replay_failed")));
    }

    #[test]
    fn sources_reports_partial_on_entry_read_errors() {
        let c = UserAssistCollector::default();
        c.entry_read_errors.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("partial")));
    }

    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors userassist::tests::userassist_e2e_real_hives -- --ignored --nocapture
    /// Proves the full chain: raw \\.\C: -> ntfs enumerate C:\Users -> per-user NTUSER
    /// open (+ log replay) -> UserAssist\<GUID>\Count -> rot13 + 72-byte parse ->
    /// Record::Execution, with SOFTWARE ProfileList SID reverse-lookup.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn userassist_e2e_real_hives() {
        use cairn_core::record::Record;
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        // Bind the collector so sources() reads the SAME instance collect() flagged
        // (a fresh default would always show empty errors and make the diagnostic inert).
        let collector = UserAssistCollector::default();
        let recs = collector
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        eprintln!(
            "userassist_e2e diagnostics: {} records; sources errors = {:?}",
            recs.len(),
            collector.sources()[0].errors
        );
        if recs.is_empty() {
            eprintln!(
                "NOTE: 0 userassist records. If you are NOT elevated (Administrator + \
                 SeBackupPrivilege), that is the cause; re-run elevated."
            );
        }
        assert!(
            !recs.is_empty(),
            "expected at least the current user's UserAssist entries"
        );
        let mut any_last_run = false;
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "userassist");
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert_eq!(e.execution_confirmed, Some(true));
                assert!(e.run_count.is_some(), "userassist carries a run_count");
                assert!(e.first_run.is_none(), "userassist has no first_run");
                assert!(e.sha1.is_none(), "userassist has no sha1");
                if e.last_run.is_some() {
                    any_last_run = true;
                }
                if let Some(sid) = &e.user_sid {
                    assert!(
                        sid.starts_with("S-1-"),
                        "user_sid must be a SID, got {sid:?}"
                    );
                }
            } else {
                panic!("userassist must only emit Execution records");
            }
        }
        assert!(
            any_last_run,
            "at least one userassist record should have a last_run time"
        );
    }
}
