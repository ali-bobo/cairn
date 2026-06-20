//! ShimCollector: parse the AppCompatCache (shimcache) value from a locked SYSTEM
//! hive into Record::Execution. The version-aware blob parser (parse_appcompatcache)
//! is a pure, never-panic function (bounds-checked readers, like parse_usn_record);
//! the collector is privilege-gated and read-only, using hive_reader to fetch bytes.

use chrono::{DateTime, Utc};

use cairn_core::time::filetime_to_utc;

/// AppCompatCache key/value location. ControlSet001, NOT CurrentControlSet — the
/// latter is a runtime symlink absent from an offline hive.
#[allow(dead_code)]
pub(crate) const SHIMCACHE_KEY: &str =
    r"ControlSet001\Control\Session Manager\AppCompatCache";

#[allow(dead_code)]
pub(crate) const SHIMCACHE_VALUE: &str = "AppCompatCache";

/// Win10+ header is 0x34 bytes; the 32-bit value at offset 0 equals 0x34.
const WIN10PLUS_HEADER_LEN: usize = 0x34;

/// Per-entry signature for Win8.1+/Win10/Win11 cache entries.
const ENTRY_SIG: &[u8; 4] = b"10ts";

/// One AppCompatCache entry (pure data).
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub(crate) struct ShimEntry {
    pub path: String,
    /// File last-modified time from the cache (NOT an execution time).
    pub last_modified: Option<DateTime<Utc>>,
    /// True only when the entry's data flag indicates execution (best-effort).
    pub executed: bool,
}

/// AppCompatCache format. Win10 and Win11 share one layout since Win10 1607, so they
/// collapse to Win10Plus; anything else abstains (NFR12).
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub(crate) enum ShimVersion {
    Win10Plus,
    Unknown(u32),
}

/// Bounds-checked little-endian readers (Option = out of bounds), like usn.rs.
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Version-aware AppCompatCache parser. NO I/O, never-panic. Unknown header → abstain.
#[allow(dead_code)]
pub(crate) fn parse_appcompatcache(buf: &[u8]) -> (ShimVersion, Vec<ShimEntry>) {
    let header = match rd_u32(buf, 0) {
        Some(h) => h,
        None => return (ShimVersion::Unknown(0), Vec::new()),
    };
    if header as usize != WIN10PLUS_HEADER_LEN {
        return (ShimVersion::Unknown(header), Vec::new());
    }

    let mut entries = Vec::new();
    let mut pos = WIN10PLUS_HEADER_LEN;

    // Walk entries until we run out of buffer or hit a malformed one (best-effort).
    // Loop termination: each successful iteration sets pos = data_end, where
    // data_end >= data_start >= path_end + 12 >= pos + 14 > pos. Strictly increasing.
    while pos + 14 <= buf.len() {
        // Signature check — bad sig means no more recognisable entries.
        if buf.get(pos..pos + 4) != Some(ENTRY_SIG.as_slice()) {
            break;
        }
        let path_len = match rd_u16(buf, pos + 12) {
            Some(l) => l as usize,
            None => break,
        };
        let path_start = pos + 14;
        let path_end = match path_start.checked_add(path_len) {
            Some(e) if e <= buf.len() => e,
            _ => break, // lying / truncated path length
        };
        let path_bytes = &buf[path_start..path_end];
        let path = utf16le_lossy(path_bytes);

        let ft_off = path_end;
        // rd_u64 returns Option<u64>; and_then(filetime_to_utc) gives Option<DateTime<Utc>>.
        // ft == 0 naturally maps to None via filetime_to_utc's own guard.
        let last_modified = rd_u64(buf, ft_off).and_then(filetime_to_utc);

        let data_len_off = ft_off + 8;
        let data_len = match rd_u32(buf, data_len_off) {
            Some(l) => l as usize,
            None => break,
        };
        let data_start = data_len_off + 4;
        let data_end = match data_start.checked_add(data_len) {
            Some(e) if e <= buf.len() => e,
            _ => break,
        };

        // Execution flag: data == 01 00 00 00 indicates execution (best-effort).
        let executed = buf.get(data_start..data_end) == Some(&[1, 0, 0, 0][..]);

        entries.push(ShimEntry {
            path,
            last_modified,
            executed,
        });
        pos = data_end;
    }

    (ShimVersion::Win10Plus, entries)
}

/// UTF-16LE → String, lossy (bad units → replacement char). Never panics.
fn utf16le_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG_10TS: &[u8; 4] = b"10ts";
    const WIN10_HEADER: u32 = 0x34;

    /// Build a minimal Win10+ AppCompatCache blob: a 0x34-byte header (signature
    /// 0x34 at offset 0) followed by `entries`. Each entry: "10ts", unknown(0),
    /// entry-data-size, path-len, path UTF-16LE, FILETIME, data-len, data.
    fn build_shim_win10plus(entries: &[(&str, u64, bool)]) -> Vec<u8> {
        let mut buf = vec![0u8; WIN10_HEADER as usize];
        buf[0..4].copy_from_slice(&WIN10_HEADER.to_le_bytes()); // header signature = 0x34
        for (path, filetime, executed) in entries {
            let path_utf16: Vec<u8> =
                path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let data: Vec<u8> = if *executed {
                vec![1, 0, 0, 0]
            } else {
                vec![0, 0, 0, 0]
            };
            // entry-data-size = everything after the size field: pathlen(2)+path+
            // filetime(8)+datalen(4)+data
            let entry_data_size =
                (2 + path_utf16.len() + 8 + 4 + data.len()) as u32;
            buf.extend_from_slice(SIG_10TS);
            buf.extend_from_slice(&0u32.to_le_bytes()); // unknown
            buf.extend_from_slice(&entry_data_size.to_le_bytes());
            buf.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
            buf.extend_from_slice(&path_utf16);
            buf.extend_from_slice(&filetime.to_le_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&data);
        }
        buf
    }

    // FILETIME for 2021-01-01T00:00:00Z.
    // Derived: (1_609_459_200 * 10_000_000) + (11_644_473_600 * 10_000_000)
    // = 132_539_328_000_000_000
    // NOTE: the plan draft used 132_539_904_000_000_000 which maps to 2021-01-01T16:00:00Z
    // (wrong). This constant has been verified correct via arithmetic cross-check.
    const FT_2021: u64 = 132_539_328_000_000_000;

    #[test]
    fn parse_win10_two_entries() {
        let blob = build_shim_win10plus(&[
            (r"C:\Windows\System32\evil.exe", FT_2021, true),
            (r"C:\temp\a.dll", FT_2021, false),
        ]);
        let (ver, entries) = parse_appcompatcache(&blob);
        assert_eq!(ver, ShimVersion::Win10Plus);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, r"C:\Windows\System32\evil.exe");
        assert_eq!(
            entries[0].last_modified.unwrap().to_rfc3339(),
            "2021-01-01T00:00:00+00:00"
        );
        assert!(entries[0].executed);
        assert!(!entries[1].executed);
    }

    #[test]
    fn parse_unknown_header_abstains() {
        let blob = vec![0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0];
        let (ver, entries) = parse_appcompatcache(&blob);
        assert!(matches!(ver, ShimVersion::Unknown(_)));
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_empty_buf_abstains_no_panic() {
        let (ver, entries) = parse_appcompatcache(&[]);
        assert!(matches!(ver, ShimVersion::Unknown(_)));
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_truncated_entry_best_effort_no_panic() {
        // Valid header + valid first entry + a second entry cut off mid-path.
        let mut blob = build_shim_win10plus(&[(r"C:\good.exe", FT_2021, false)]);
        blob.extend_from_slice(b"10ts");
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&999u32.to_le_bytes()); // lies: huge entry size
        blob.extend_from_slice(&200u16.to_le_bytes()); // path len 200 but no bytes follow
        let (ver, entries) = parse_appcompatcache(&blob);
        assert_eq!(ver, ShimVersion::Win10Plus);
        // First entry parsed; truncated second is dropped, no panic.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, r"C:\good.exe");
    }

    #[test]
    fn parse_path_length_lying_huge_no_overrun() {
        // path len field claims 0xFFFF but buffer ends — must not panic / over-read.
        let mut blob = vec![0u8; WIN10_HEADER as usize];
        blob[0..4].copy_from_slice(&WIN10_HEADER.to_le_bytes());
        blob.extend_from_slice(b"10ts");
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0xFFFFu16.to_le_bytes()); // huge path len
        let (_ver, entries) = parse_appcompatcache(&blob);
        assert!(entries.is_empty(), "lying path len must yield no entry, no panic");
    }
}
