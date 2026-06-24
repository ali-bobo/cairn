#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use srum_core::IdMapEntry;

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

/// Build an `app_id → name` lookup map from the SRUM ID-map table entries.
pub(crate) fn build_id_map(entries: Vec<IdMapEntry>) -> HashMap<i32, String> {
    entries.into_iter().map(|e| (e.id, e.name)).collect()
}

/// Resolve an `app_id` to a human-readable name, falling back to `"id:<n>"`.
pub(crate) fn resolve_app_name(app_id: i32, map: &HashMap<i32, String>) -> String {
    map.get(&app_id)
        .cloned()
        .unwrap_or_else(|| format!("id:{app_id}"))
}

/// Format network byte counts into a `Finding.reason`-compatible string.
/// Schema zero-change: net data lives entirely in the `reason` field.
/// Note: ExecutionRecord has no `reason` field; this helper is retained for
/// future Finding-layer enrichment.
#[allow(dead_code)]
pub(crate) fn net_reason(bytes_sent: u64, bytes_recv: u64) -> String {
    format!("bytes_sent={bytes_sent} bytes_recv={bytes_recv}")
}

/// Reads SRUDB.dat via raw volume → scratchpad NamedTempFile → srum-parser
/// → Record::Execution (source="srum_app" and "srum_net").
#[derive(Default)]
pub struct SrumCollector {
    truncated: AtomicBool,
    db_absent: AtomicBool,
    id_map_failed: AtomicBool,
    entry_read_errors: AtomicBool,
}

impl Collector for SrumCollector {
    fn name(&self) -> &str {
        "srum"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "srum".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;

        let tmp = match extract_srudb(&mut reader, &self.truncated) {
            Ok(t) => t,
            Err(e) => {
                if !self.truncated.load(Ordering::Relaxed) {
                    self.db_absent.store(true, Ordering::Relaxed);
                    tracing::warn!(reason = %e, "srum: SRUDB.dat extraction failed; abstaining");
                }
                return Ok(vec![]);
            }
        };

        let db_path = tmp.path();

        let id_map = match srum_parser::parse_id_map(db_path) {
            Ok(entries) => build_id_map(entries),
            Err(e) => {
                self.id_map_failed.store(true, Ordering::Relaxed);
                tracing::warn!(reason = %e, "srum: ID map parse failed; app names will be id:<n>");
                HashMap::new()
            }
        };

        let mut records: Vec<Record> = Vec::new();

        match srum_parser::parse_app_usage(db_path) {
            Ok(rows) => {
                for row in rows {
                    records.push(Record::Execution(ExecutionRecord {
                        source: "srum_app".into(),
                        path: resolve_app_name(row.app_id, &id_map),
                        first_run: None,
                        last_run: Some(row.timestamp),
                        run_count: None,
                        sha1: None,
                        user_sid: None,
                        execution_confirmed: Some(true),
                    }));
                }
            }
            Err(e) => {
                self.entry_read_errors.store(true, Ordering::Relaxed);
                tracing::warn!(reason = %e, "srum: app_usage parse error; partial result");
            }
        }

        match srum_parser::parse_network_usage(db_path) {
            Ok(rows) => {
                for row in rows {
                    records.push(Record::Execution(ExecutionRecord {
                        source: "srum_net".into(),
                        path: resolve_app_name(row.app_id, &id_map),
                        first_run: None,
                        last_run: Some(row.timestamp),
                        run_count: None,
                        sha1: None,
                        user_sid: None,
                        execution_confirmed: Some(true),
                    }));
                }
            }
            Err(e) => {
                self.entry_read_errors.store(true, Ordering::Relaxed);
                tracing::warn!(reason = %e, "srum: network_usage parse error; partial result");
            }
        }

        // tmp drops here → NamedTempFile deleted (RAII, golden rule 4)
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors: Vec<String> = Vec::new();
        if self.truncated.load(Ordering::Relaxed) {
            errors.push(
                "abstained: SRUDB.dat exceeded 512 MiB ceiling (NFR10); not parsed".into(),
            );
        }
        if self.db_absent.load(Ordering::Relaxed) {
            errors.push("abstained: SRUDB.dat not found (build variance/NFR12)".into());
        }
        if self.id_map_failed.load(Ordering::Relaxed) {
            errors.push("id_map_failed: app names fall back to id:<n>".into());
        }
        if self.entry_read_errors.load(Ordering::Relaxed) {
            errors.push(
                "entry_read_errors: one or more records skipped (partial result, NFR12)".into(),
            );
        }
        vec![SourceEntry {
            artifact: "srum".into(),
            path: r"C:\Windows\System32\sru\SRUDB.dat".into(),
            method: "raw_ntfs_copy".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

use std::io::Write as _;

use crate::hive_reader::{HivePath, HIVE_HARD_CEILING};

/// NTFS path components for SRUDB.dat (volume-relative, last element = filename).
pub(crate) const SRUDB_PATH: &[&str] = &["Windows", "System32", "sru", "SRUDB.dat"];

/// Read SRUDB.dat bytes from the raw volume into a NamedTempFile.
///
/// Returns a NamedTempFile. Caller must keep it alive for the duration of
/// parsing; it auto-deletes when dropped (RAII).
///
/// 512 MiB ceiling (NFR10): sets `truncated=true` and returns Err if exceeded.
pub(crate) fn extract_srudb(
    reader: &mut VolumeReader,
    truncated_flag: &AtomicBool,
) -> Result<tempfile::NamedTempFile> {
    use ntfs::Ntfs;

    let hive = HivePath {
        components: SRUDB_PATH.iter().map(|s| s.to_string()).collect(),
    };

    let mut ntfs = Ntfs::new(reader).map_err(|e| CairnError::Collector {
        collector: "srum".into(),
        reason: format!("Ntfs::new: {e}"),
    })?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| CairnError::Collector {
            collector: "srum".into(),
            reason: format!("read_upcase_table: {e}"),
        })?;
    let root = ntfs
        .root_directory(reader)
        .map_err(|e| CairnError::Collector {
            collector: "srum".into(),
            reason: format!("root_directory: {e}"),
        })?;

    let (file_name, dir_components) = hive
        .components
        .split_last()
        .ok_or_else(|| CairnError::Collector {
            collector: "srum".into(),
            reason: "empty path".into(),
        })?;

    let mut cur = root;
    for comp in dir_components {
        cur = crate::hive_reader::find_child_dir_pub(&ntfs, reader, &cur, comp.as_str())?;
    }

    let file =
        crate::hive_reader::find_child_file_pub(&ntfs, reader, &cur, file_name.as_str())?;
    let data_item = file
        .data(reader, "")
        .ok_or_else(|| CairnError::Collector {
            collector: "srum".into(),
            reason: "SRUDB.dat: no default data stream".into(),
        })?
        .map_err(|e| CairnError::Collector {
            collector: "srum".into(),
            reason: format!("SRUDB.dat data attr: {e}"),
        })?;
    let attr = data_item
        .to_attribute()
        .map_err(|e| CairnError::Collector {
            collector: "srum".into(),
            reason: format!("SRUDB.dat to_attribute: {e}"),
        })?;
    let value = attr.value(reader).map_err(|e| CairnError::Collector {
        collector: "srum".into(),
        reason: format!("SRUDB.dat value: {e}"),
    })?;

    use std::io::Read as _;
    let mut attached = value.attach(reader);
    let mut buf = Vec::new();
    let n = attached
        .by_ref()
        .take(HIVE_HARD_CEILING)
        .read_to_end(&mut buf)
        .map_err(|e| CairnError::Collector {
            collector: "srum".into(),
            reason: format!("SRUDB.dat read: {e}"),
        })?;

    if n as u64 == HIVE_HARD_CEILING {
        truncated_flag.store(true, Ordering::Relaxed);
        return Err(CairnError::Collector {
            collector: "srum".into(),
            reason: "SRUDB.dat exceeded 512 MiB ceiling (NFR10); abstained".into(),
        });
    }

    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| CairnError::Collector {
        collector: "srum".into(),
        reason: format!("tempfile::new: {e}"),
    })?;
    tmp.write_all(&buf)
        .map_err(|e| CairnError::Collector {
            collector: "srum".into(),
            reason: format!("tempfile write: {e}"),
        })?;
    tmp.flush().map_err(|e| CairnError::Collector {
        collector: "srum".into(),
        reason: format!("tempfile flush: {e}"),
    })?;

    Ok(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_name_is_srum() {
        use cairn_core::traits::Collector;
        let c = SrumCollector::default();
        assert_eq!(c.name(), "srum");
    }

    #[test]
    fn srudb_path_components_correct() {
        assert_eq!(SRUDB_PATH, &["Windows", "System32", "sru", "SRUDB.dat"]);
    }

    #[test]
    fn resolve_id_unknown_returns_id_string() {
        let map: std::collections::HashMap<i32, String> = std::collections::HashMap::new();
        assert_eq!(resolve_app_name(42, &map), "id:42");
    }

    #[test]
    fn resolve_id_known_returns_name() {
        let mut map = std::collections::HashMap::new();
        map.insert(3, "explorer.exe".to_string());
        assert_eq!(resolve_app_name(3, &map), "explorer.exe");
    }

    #[test]
    fn build_id_map_entries_indexed_by_id() {
        let entries = vec![
            srum_core::IdMapEntry { id: 1, name: "svchost.exe".to_string() },
            srum_core::IdMapEntry { id: 5, name: "explorer.exe".to_string() },
        ];
        let map = build_id_map(entries);
        assert_eq!(map.get(&1).map(|s| s.as_str()), Some("svchost.exe"));
        assert_eq!(map.get(&5).map(|s| s.as_str()), Some("explorer.exe"));
        assert!(!map.contains_key(&99));
    }

    #[test]
    fn net_reason_formats_bytes() {
        assert_eq!(net_reason(1024, 512), "bytes_sent=1024 bytes_recv=512");
    }
}
