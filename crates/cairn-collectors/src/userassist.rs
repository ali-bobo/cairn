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

use chrono::{DateTime, Utc};

use crate::hive_reader::{get_value_string, list_subkeys};
use cairn_core::time::filetime_to_utc;

/// Decode a ROT13-encoded ASCII string (UserAssist value names are ROT13). Pure: each
/// ASCII letter is rotated 13 places; every non-alphabetic byte (digits, braces, path
/// separators, dots) passes through unchanged. Never panics. Self-inverse.
#[allow(dead_code)] // wired by UserAssistCollector in T6
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
#[allow(dead_code)] // wired by UserAssistCollector in T6
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
#[allow(dead_code)] // wired by UserAssistCollector in T6
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
#[allow(dead_code)] // wired by UserAssistCollector in T6
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
