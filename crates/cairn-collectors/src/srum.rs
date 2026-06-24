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

#[cfg(test)]
mod tests {
    use super::*;

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
