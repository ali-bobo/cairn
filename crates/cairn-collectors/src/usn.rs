//! UsnCollector: read the $Extend\$UsnJrnl:$J change journal via the ntfs crate's
//! alternate-data-stream support and parse USN_RECORD_V2/V3 into Record::UsnEvent
//! (SRS FR12, S2 raw-NTFS second half).
//!
//! ## Design notes (see docs/superpowers/specs/2026-06-20-usn-journal-design.md)
//! - $J is reached as an ADS: root -> $Extend -> $UsnJrnl, then data(fs, "$J").
//!   `ntfs` named-stream lookup PANICS unless read_upcase_table() ran first; the
//!   whole parse also runs under catch_unwind (mirroring mft guard b).
//! - $J begins with a large SPARSE region. The ntfs crate fills sparse reads with
//!   zeroes (not errors), so RecordLength == 0 is the authoritative "no record"
//!   signal; the scanner advances past zero runs to the next 8-byte boundary.
//! - The parse logic is split into two PURE functions (no I/O) so it is fully
//!   unit-testable without a real volume: `parse_usn_record` (one record) and
//!   `scan_usn_stream` (a whole buffer, with sparse + cap handling).

#![allow(dead_code)] // Task 1 is the pure parser core; all functions are tested but unused in lib.rs until Task 4.

use cairn_core::record::UsnEventRecord;
use cairn_core::time::filetime_to_utc;
use cairn_core::{CairnError, Result};

/// USN_RECORD_V2 fixed header length in bytes (before the variable filename).
/// FileName begins at FileNameOffset (always >= this for a well-formed V2 record).
const V2_HEADER_LEN: usize = 60;
/// USN_RECORD_V3 fixed header length: V2 + 16 (two 128-bit file refs instead of u64).
const V3_HEADER_LEN: usize = 76;
/// Low 48 bits of a file reference number are the MFT record number; high 16 are the
/// sequence number. Mask to extract the record number (matches mft.rs convention).
const MFT_REF_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Outcome of parsing one record at the head of a byte slice.
#[derive(Debug, PartialEq)]
pub(crate) enum ParsedUsn {
    /// A V2/V3 record we understood. `record_length` is the full on-disk length (for advancing).
    Event {
        record_length: u32,
        rec: UsnEventRecord,
    },
    /// A record whose major version we do not support (e.g. V4). Skip it but advance.
    Skipped { record_length: u32 },
}

/// Construct a `CairnError::Collector` for the "usn" collector (mirrors mft_err).
#[inline]
fn usn_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "usn".into(),
        reason,
    }
}

/// Read a little-endian u16 at `off`, returning None if out of bounds.
/// Pure bounds-checked accessors keep the parser total (golden rule 8: never panic
/// on adversarial on-disk data).
#[inline]
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}
#[inline]
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}
#[inline]
fn rd_i64(buf: &[u8], off: usize) -> Option<i64> {
    buf.get(off..off + 8)?
        .try_into()
        .ok()
        .map(i64::from_le_bytes)
}

/// Decode the USN Reason bitmask into a deterministic, human-readable string.
/// Bits are emitted in a fixed order joined by '|'; an all-zero mask yields "".
fn reason_to_string(reason: u32) -> String {
    // (bit, label) in fixed order for determinism (NFR4).
    const BITS: &[(u32, &str)] = &[
        (0x0000_0001, "data_overwrite"),
        (0x0000_0002, "data_extend"),
        (0x0000_0004, "data_truncation"),
        (0x0000_0010, "named_data_overwrite"),
        (0x0000_0020, "named_data_extend"),
        (0x0000_0040, "named_data_truncation"),
        (0x0000_0100, "create"),
        (0x0000_0200, "delete"),
        (0x0000_0400, "ea_change"),
        (0x0000_0800, "security_change"),
        (0x0000_1000, "rename_old_name"),
        (0x0000_2000, "rename_new_name"),
        (0x0000_4000, "indexable_change"),
        (0x0000_8000, "basic_info_change"),
        (0x0001_0000, "hard_link_change"),
        (0x0002_0000, "compression_change"),
        (0x0004_0000, "encryption_change"),
        (0x0008_0000, "object_id_change"),
        (0x0010_0000, "reparse_point_change"),
        (0x0020_0000, "stream_change"),
        (0x0040_0000, "integrity_change"),
        (0x8000_0000, "close"),
    ];
    let parts: Vec<&str> = BITS
        .iter()
        .filter(|&(bit, _)| reason & bit != 0)
        .map(|(_, label)| *label)
        .collect();
    parts.join("|")
}

/// Parse one USN record at the start of `buf`. See ParsedUsn for the contract.
/// Total: every field access is bounds-checked; never panics on bad input.
pub(crate) fn parse_usn_record(buf: &[u8]) -> Result<Option<ParsedUsn>> {
    // RecordLength (and thus version) requires at least 6 bytes; fewer is a non-record
    // tail. Treat <4 bytes as "no record" so the scanner stops cleanly at buffer end.
    let record_length = match rd_u32(buf, 0) {
        Some(0) | None => return Ok(None), // zero or no room => sparse/padding/end
        Some(n) => n,
    };
    let major = rd_u16(buf, 4)
        .ok_or_else(|| usn_err("record claims length but has no version field".into()))?;

    // The full record must fit in the buffer the scanner handed us.
    let rec_len = record_length as usize;
    if rec_len > buf.len() {
        return Err(usn_err(format!(
            "RecordLength {rec_len} exceeds available buffer {}",
            buf.len()
        )));
    }

    // Version-specific fixed offsets.
    let (header_len, ts_off, reason_off, name_len_off, name_off_off) = match major {
        2 => (V2_HEADER_LEN, 32usize, 40usize, 56usize, 58usize),
        3 => (V3_HEADER_LEN, 48usize, 56usize, 72usize, 74usize),
        _ => return Ok(Some(ParsedUsn::Skipped { record_length })),
    };
    if rec_len < header_len {
        return Err(usn_err(format!(
            "RecordLength {rec_len} smaller than v{major} header {header_len}"
        )));
    }

    let file_ref = rd_u64(buf, 8).ok_or_else(|| usn_err("file ref out of bounds".into()))?;
    let mft_ref = file_ref & MFT_REF_MASK;
    let ts_raw = rd_i64(buf, ts_off).ok_or_else(|| usn_err("timestamp out of bounds".into()))?;
    let reason = rd_u32(buf, reason_off).ok_or_else(|| usn_err("reason out of bounds".into()))?;
    let name_len = rd_u16(buf, name_len_off)
        .ok_or_else(|| usn_err("name length out of bounds".into()))? as usize;
    let name_off = rd_u16(buf, name_off_off)
        .ok_or_else(|| usn_err("name offset out of bounds".into()))? as usize;

    // FileName must lie fully within this record.
    let name_end = name_off
        .checked_add(name_len)
        .ok_or_else(|| usn_err("name offset+length overflow".into()))?;
    if name_off < header_len || name_end > rec_len {
        return Err(usn_err(format!(
            "filename [{name_off}..{name_end}] outside record header..len [{header_len}..{rec_len}]"
        )));
    }
    let name_bytes = &buf[name_off..name_end];
    // UTF-16LE; best-effort (golden rule 8: keep the record even if the name is corrupt).
    let units: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let path = String::from_utf16_lossy(&units);

    // FILETIME 0 => unset; fall back to UNIX_EPOCH so the (non-optional) ts field is set
    // and the record is never dropped.
    let ts = filetime_to_utc(ts_raw as u64).unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH);

    Ok(Some(ParsedUsn::Event {
        record_length,
        rec: UsnEventRecord {
            ts,
            path,
            reason: reason_to_string(reason),
            mft_ref,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // USN reason bits we assert on (subset; full set decoded in reason_to_string).
    const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
    const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;

    /// Build a USN_RECORD_V2 with the given fields. `name` is encoded UTF-16LE.
    /// Layout: RecordLength(4) MajorVersion(2)=2 MinorVersion(2) FileRef(8) ParentRef(8)
    /// Usn(8) TimeStamp(8) Reason(4) SourceInfo(4) SecurityId(4) FileAttributes(4)
    /// FileNameLength(2) FileNameOffset(2)=60 FileName(var), padded to 8-byte align.
    fn build_usn_v2(file_ref: u64, reason: u32, timestamp: i64, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_off: u16 = V2_HEADER_LEN as u16;
        let unpadded = V2_HEADER_LEN + name_utf16.len();
        let record_len = unpadded.next_multiple_of(8);
        let mut b = vec![0u8; record_len];
        b[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes()); // MajorVersion
        b[6..8].copy_from_slice(&0u16.to_le_bytes()); // MinorVersion
        b[8..16].copy_from_slice(&file_ref.to_le_bytes());
        // ParentRef [16..24], Usn [24..32] left zero
        b[32..40].copy_from_slice(&timestamp.to_le_bytes()); // TimeStamp
        b[40..44].copy_from_slice(&reason.to_le_bytes()); // Reason
                                                          // SourceInfo/SecurityId/FileAttributes [44..56] zero
        b[56..58].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes()); // FileNameLength
        b[58..60].copy_from_slice(&name_off.to_le_bytes()); // FileNameOffset
        b[V2_HEADER_LEN..V2_HEADER_LEN + name_utf16.len()].copy_from_slice(&name_utf16);
        b
    }

    /// Build a USN_RECORD_V3 (128-bit file refs). FileNameOffset = 76.
    fn build_usn_v3(file_ref_low: u64, reason: u32, timestamp: i64, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_off: u16 = V3_HEADER_LEN as u16;
        let unpadded = V3_HEADER_LEN + name_utf16.len();
        let record_len = unpadded.next_multiple_of(8);
        let mut b = vec![0u8; record_len];
        b[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        b[4..6].copy_from_slice(&3u16.to_le_bytes()); // MajorVersion = 3
                                                      // FileRef 128-bit [8..24]: low 8 bytes carry file_ref_low
        b[8..16].copy_from_slice(&file_ref_low.to_le_bytes());
        // ParentRef 128-bit [24..40], Usn [40..48] zero
        b[48..56].copy_from_slice(&timestamp.to_le_bytes()); // TimeStamp
        b[56..60].copy_from_slice(&reason.to_le_bytes()); // Reason
                                                          // SourceInfo/SecurityId/FileAttributes [60..72] zero
        b[72..74].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes()); // FileNameLength
        b[74..76].copy_from_slice(&name_off.to_le_bytes()); // FileNameOffset
        b[V3_HEADER_LEN..V3_HEADER_LEN + name_utf16.len()].copy_from_slice(&name_utf16);
        b
    }

    #[test]
    fn parse_v2_create_event() {
        // file_ref with a sequence number in the high bits; mft_ref must mask it off.
        let file_ref = (7u64 << 48) | 0x1234;
        let ts = 130_018_833_000_000_000i64; // 2013-01-05T18:15:00Z
        let b = build_usn_v2(file_ref, USN_REASON_FILE_CREATE, ts, "evil.exe");
        let parsed = parse_usn_record(&b).unwrap().unwrap();
        match parsed {
            ParsedUsn::Event { record_length, rec } => {
                assert_eq!(record_length as usize, b.len());
                assert_eq!(rec.mft_ref, 0x1234, "mft_ref masks off the sequence number");
                assert_eq!(rec.path, "evil.exe");
                assert!(rec.reason.contains("create"));
                assert_eq!(rec.ts.to_rfc3339(), "2013-01-05T18:15:00+00:00");
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn parse_v3_event_128bit_ref() {
        let ts = 130_018_833_000_000_000i64;
        let b = build_usn_v3(0xABCD, USN_REASON_FILE_CREATE, ts, "a.txt");
        let parsed = parse_usn_record(&b).unwrap().unwrap();
        match parsed {
            ParsedUsn::Event { rec, .. } => {
                assert_eq!(rec.mft_ref, 0xABCD);
                assert_eq!(rec.path, "a.txt");
            }
            other => panic!("expected V3 Event, got {other:?}"),
        }
    }

    #[test]
    fn parse_zero_record_length_is_none() {
        // A run of zeroes (sparse / padding): RecordLength == 0 => Ok(None).
        let b = vec![0u8; 64];
        assert_eq!(parse_usn_record(&b).unwrap(), None);
    }

    #[test]
    fn parse_unknown_version_skips() {
        // MajorVersion 99 but a valid RecordLength: Ok(Some(Skipped{len})), no panic.
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&64u32.to_le_bytes());
        b[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            parse_usn_record(&b).unwrap(),
            Some(ParsedUsn::Skipped { record_length: 64 })
        );
    }

    #[test]
    fn parse_truncated_header_is_err() {
        // Buffer shorter than the V2 header but claims a long RecordLength: Err, no panic.
        let mut b = vec![0u8; 20];
        b[0..4].copy_from_slice(&60u32.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_usn_record(&b).is_err());
    }

    #[test]
    fn parse_filename_offset_out_of_bounds_is_err() {
        // Well-formed V2 header but FileNameOffset+Length exceeds RecordLength: Err.
        let mut b = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "x");
        // Corrupt FileNameLength to a huge value.
        b[56..58].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(parse_usn_record(&b).is_err());
    }

    #[test]
    fn parse_reason_bitmask_decodes() {
        let b = build_usn_v2(1, USN_REASON_FILE_CREATE | USN_REASON_DATA_EXTEND, 0, "x");
        let rec = match parse_usn_record(&b).unwrap().unwrap() {
            ParsedUsn::Event { rec, .. } => rec,
            other => panic!("expected Event, got {other:?}"),
        };
        assert!(rec.reason.contains("create"));
        assert!(rec.reason.contains("data_extend"));
    }

    #[test]
    fn parse_bad_utf16_filename_best_effort() {
        // 1 byte cannot form a UTF-16 code unit; chunks_exact(2) yields no chunks,
        // so path is "" — best-effort: the event is still kept, not dropped/panicked.
        let mut b = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "xy");
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // 1 byte of name (odd => lossy)
        let parsed = parse_usn_record(&b).unwrap();
        assert!(parsed.is_some(), "best-effort: still an Event, not dropped");
    }

    #[test]
    fn parse_zero_timestamp_falls_back_to_epoch() {
        // TimeStamp 0 (unset) must not drop the record; ts falls back to UNIX_EPOCH.
        let b = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "x");
        let rec = match parse_usn_record(&b).unwrap().unwrap() {
            ParsedUsn::Event { rec, .. } => rec,
            other => panic!("expected Event, got {other:?}"),
        };
        assert_eq!(rec.ts, chrono::DateTime::<chrono::Utc>::UNIX_EPOCH);
    }
}
