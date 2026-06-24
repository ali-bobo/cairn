#![forbid(unsafe_code)]

use std::collections::HashMap;

use srum_core::IdMapEntry;

/// Build an `app_id → name` lookup map from the SRUM ID-map table entries.
#[allow(dead_code)] // wired in T4 (SrumCollector)
pub(crate) fn build_id_map(entries: Vec<IdMapEntry>) -> HashMap<i32, String> {
    entries.into_iter().map(|e| (e.id, e.name)).collect()
}

/// Resolve an `app_id` to a human-readable name, falling back to `"id:<n>"`.
#[allow(dead_code)] // wired in T4 (SrumCollector)
pub(crate) fn resolve_app_name(app_id: i32, map: &HashMap<i32, String>) -> String {
    map.get(&app_id)
        .cloned()
        .unwrap_or_else(|| format!("id:{app_id}"))
}

/// Format network byte counts into a `Finding.reason`-compatible string.
/// Schema zero-change: net data lives entirely in the `reason` field.
#[allow(dead_code)] // wired in T4 (SrumCollector)
pub(crate) fn net_reason(bytes_sent: u64, bytes_recv: u64) -> String {
    format!("bytes_sent={bytes_sent} bytes_recv={bytes_recv}")
}

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::{CairnError, Result};

use crate::hive_reader::{HivePath, HIVE_HARD_CEILING};

/// NTFS path components for SRUDB.dat (volume-relative, last element = filename).
pub(crate) const SRUDB_PATH: &[&str] = &["Windows", "System32", "sru", "SRUDB.dat"];

/// Read SRUDB.dat bytes from the raw volume into a NamedTempFile.
///
/// Returns a NamedTempFile. Caller must keep it alive for the duration of
/// parsing; it auto-deletes when dropped (RAII).
///
/// 512 MiB ceiling (NFR10): sets `truncated=true` and returns Err if exceeded.
#[allow(dead_code)] // wired in T4 (SrumCollector)
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
