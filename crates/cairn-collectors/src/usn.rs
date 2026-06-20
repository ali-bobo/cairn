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

use std::sync::atomic::{AtomicU64, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{Record, UsnEventRecord};
use cairn_core::time::filetime_to_utc;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

/// USN_RECORD_V2 fixed header length in bytes (before the variable filename).
/// FileName begins at FileNameOffset (always >= this for a well-formed V2 record).
const V2_HEADER_LEN: usize = 60;
/// USN_RECORD_V3 fixed header length: V2 + 16 (two 128-bit file refs instead of u64).
const V3_HEADER_LEN: usize = 76;
/// USN records are 8-byte aligned; the scanner steps by this when skipping zero/sparse.
const USN_ALIGN: u64 = 8;
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

/// Scan a contiguous $J byte buffer into events, returning (events, truncated).
///
/// - Zero/sparse regions (RecordLength == 0) are skipped: the cursor advances to the
///   next USN_ALIGN (8-byte) boundary and continues. This is the correctness fallback
///   that handles both the sparse head and inter-record padding.
/// - Stops and returns `truncated = true` when `max_records` events have been collected.
/// - A corrupt record (parse Err) STOPS the scan, keeping already-parsed events, and is
///   NOT reported as a cap truncation.
///
/// Pure (no I/O); unit-tested against synthetic buffers.
pub(crate) fn scan_usn_stream(buf: &[u8], max_records: u64) -> (Vec<UsnEventRecord>, bool) {
    let mut events: Vec<UsnEventRecord> = Vec::new();
    let mut pos: usize = 0;
    let mut truncated = false;

    while pos < buf.len() {
        match parse_usn_record(&buf[pos..]) {
            Ok(Some(ParsedUsn::Event { record_length, rec })) => {
                if events.len() as u64 >= max_records {
                    truncated = true;
                    break;
                }
                events.push(rec);
                // record_length is validated <= remaining buffer by parse_usn_record,
                // and is nonzero for an Event; advance by it (rounded up to alignment
                // defensively in case a record's length is not 8-aligned).
                pos += advance_by(record_length as usize);
            }
            Ok(Some(ParsedUsn::Skipped { record_length })) => {
                pos += advance_by(record_length as usize);
            }
            Ok(None) => {
                // Sparse/padding: step to the next 8-byte boundary and keep scanning.
                pos = next_aligned(pos);
            }
            Err(_) => break, // corrupt record: keep what we have, stop here.
        }
    }

    (events, truncated)
}

/// Advance amount for a record, never zero (a zero-length non-sparse record would
/// otherwise loop forever); rounds up to the 8-byte USN alignment.
#[inline]
fn advance_by(record_length: usize) -> usize {
    // .max(alignment): defense in depth — guarantees a nonzero advance so the scan
    // loop always terminates, even if a future change let a zero-ish length reach here.
    next_aligned_usize(record_length.max(USN_ALIGN as usize))
}

/// Next 8-byte-aligned position at or after `pos` (usize variant).
#[inline]
fn next_aligned_usize(pos: usize) -> usize {
    let a = USN_ALIGN as usize;
    pos.next_multiple_of(a)
}

/// Next 8-byte-aligned position STRICTLY after `pos` when `pos` is already aligned,
/// else the next boundary. Used to step out of a zero region so we never re-read the
/// same zero word forever.
#[inline]
fn next_aligned(pos: usize) -> usize {
    let a = USN_ALIGN as usize;
    (pos / a + 1) * a
}

// ── UsnCollector (Task 4) ────────────────────────────────────────────────────

/// UsnCollector: privilege-gated, read-only $Extend\$UsnJrnl:$J parse.
///
/// Requires Administrator + SeBackupPrivilege (raw \\.\C: open). Emits
/// Record::UsnEvent for each parsed USN_RECORD_V2/V3, bounded by Config.max_usn_records.
#[derive(Default)]
pub struct UsnCollector {
    /// 0 = not truncated; >0 = the cap value the scan stopped at (mirrors MftCollector).
    truncated_cap: AtomicU64,
}

impl Collector for UsnCollector {
    fn name(&self) -> &str {
        "usn"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors mft).
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "usn".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let cap = ctx.config.max_usn_records;
        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let (events, truncated) = read_usn_journal(&mut reader, cap)?;
        self.truncated_cap
            .store(if truncated { cap } else { 0 }, Ordering::Relaxed);

        tracing::info!(
            usn_events = events.len(),
            record_cap = cap,
            truncated,
            "usn scan"
        );

        Ok(events.into_iter().map(Record::UsnEvent).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        let cap = self.truncated_cap.load(Ordering::Relaxed);
        if cap > 0 {
            errors.push(format!("truncated: max_usn_records reached (cap={cap})"));
        }
        vec![SourceEntry {
            artifact: "usn".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_usn".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

/// Open the $J change-journal stream via ntfs ADS and scan it into events.
/// Wrapped in catch_unwind (mirroring mft guard b): the ntfs crate panics on some
/// inputs (and named-stream lookup panics without read_upcase_table); contain any
/// third-party panic and convert to Err so it never escapes this collector.
fn read_usn_journal<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    max_records: u64,
) -> Result<(Vec<UsnEventRecord>, bool)> {
    use std::panic::{self, AssertUnwindSafe};
    // NOTE: AssertUnwindSafe is correct here because:
    // - `reader` is the only captured mutable reference.
    // - If the ntfs crate panics, `reader` may be in an undefined mid-parse state,
    //   but we NEVER use `reader` after a caught panic — we immediately return Err.
    // - We are NOT using catch_unwind to hide our own logic errors; only to contain
    //   a third-party panic (ntfs named-stream lookup panics without
    //   read_upcase_table; unforeseen ntfs regressions are also contained).
    let result = panic::catch_unwind(AssertUnwindSafe(|| read_usn_inner(reader, max_records)));
    match result {
        Ok(inner) => inner,
        Err(_) => Err(usn_err(
            "ntfs parser panicked (contained); treating $J as unreadable".into(),
        )),
    }
}

/// Inner $J read: navigate root -> $Extend -> $UsnJrnl, read the "$J" ADS, scan it.
/// Only called inside catch_unwind. read_upcase_table is called before any named
/// lookup (ntfs panics otherwise).
fn read_usn_inner<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    max_records: u64,
) -> Result<(Vec<UsnEventRecord>, bool)> {
    use ntfs::Ntfs;

    let mut ntfs = Ntfs::new(reader).map_err(|e| usn_err(format!("Ntfs::new failed: {e}")))?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| usn_err(format!("read_upcase_table failed: {e}")))?;

    let root = ntfs
        .root_directory(reader)
        .map_err(|e| usn_err(format!("root_directory failed: {e}")))?;
    let extend = find_child(&ntfs, reader, &root, "$Extend")?;
    let usnjrnl = find_child(&ntfs, reader, &extend, "$UsnJrnl")?;

    let data_item = usnjrnl
        .data(reader, "$J")
        .ok_or_else(|| usn_err("$J stream absent (USN journal disabled)".into()))?
        .map_err(|e| usn_err(format!("$J data attribute error: {e}")))?;
    let attr = data_item
        .to_attribute()
        .map_err(|e| usn_err(format!("$J to_attribute failed: {e}")))?;
    let value = attr
        .value(reader)
        .map_err(|e| usn_err(format!("$J value failed: {e}")))?;

    let buf = read_value_capped(value, reader, max_records)?;
    Ok(scan_usn_stream(&buf, max_records))
}

/// Look up a child file by name in a directory, returning its NtfsFile.
/// read_upcase_table MUST already have been called on `ntfs` (find() panics otherwise).
fn find_child<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    use ntfs::indexes::NtfsFileNameIndex;
    let index = dir
        .directory_index(reader)
        .map_err(|e| usn_err(format!("directory_index for {name} failed: {e}")))?;
    let mut finder = index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, ntfs, reader, name)
        .ok_or_else(|| usn_err(format!("{name} not found in directory")))?
        .map_err(|e| usn_err(format!("find {name} failed: {e}")))?;
    entry
        .to_file(ntfs, reader)
        .map_err(|e| usn_err(format!("to_file for {name} failed: {e}")))
}

/// Read up to a memory-bounded number of bytes from an ntfs attribute value into a Vec.
/// Ceiling derived from the record cap, clamped to a hard 512 MiB ceiling so a
/// lied-about value length cannot force a huge allocation (NFR10).
///
/// NOTE: $J begins with a large sparse region; the ntfs crate fills sparse
/// data-run reads with zeroes (not errors), so `read_to_end` may absorb up to
/// `ceiling` bytes of ntfs-supplied zeroes before any real record appears. The
/// scanner discards them via RecordLength==0, but the allocation is real. A future
/// improvement (spec §4.4 "performance path"): inspect data_runs() and seek past
/// leading sparse runs before buffering. Deferred — the record cap is the functional
/// bound; this ceiling is the hard memory backstop (NFR10).
fn read_value_capped<R: std::io::Read + std::io::Seek>(
    value: ntfs::attribute_value::NtfsAttributeValue<'_, '_>,
    reader: &mut R,
    max_records: u64,
) -> Result<Vec<u8>> {
    use std::io::Read as _;
    const HARD_CEILING: u64 = 512 * 1024 * 1024;
    // 1024 bytes/record: conservative upper bound (USN_RECORD_V2 min ~64 B; generous
    // for long UTF-16 filenames + 8-byte alignment). Keeps the functional ceiling
    // comfortably above any realistic burst of max_records records.
    let functional = max_records.saturating_mul(1024);
    let ceiling = functional.min(HARD_CEILING) as usize;

    let mut attached = value.attach(reader);
    let mut buf = Vec::new();
    attached
        .by_ref()
        .take(ceiling as u64)
        .read_to_end(&mut buf)
        .map_err(|e| usn_err(format!("reading $J value failed: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::config::Config;

    // ── UsnCollector unit tests (Task 4) ──────────────────────────────────────

    #[test]
    fn collect_without_privilege_returns_err_no_host_access() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = UsnCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_usn() {
        assert_eq!(UsnCollector::default().name(), "usn");
    }

    #[test]
    fn sources_reports_truncation_when_capped() {
        let c = UsnCollector::default();
        c.truncated_cap.store(42, Ordering::Relaxed);
        let s = c.sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.iter().any(|e| e.contains("cap=42")));
        assert!(s[0].errors.iter().any(|e| e.contains("max_usn_records")));
    }

    #[test]
    fn sources_clean_when_not_truncated() {
        let s = UsnCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "usn");
        assert_eq!(s[0].method, "raw_ntfs_usn");
    }

    // ── Pure parser tests (Tasks 1–3) ─────────────────────────────────────────

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

    #[test]
    fn scan_multiple_records_sequential() {
        let r1 = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "a.txt");
        let r2 = build_usn_v2(2, USN_REASON_FILE_CREATE, 0, "b.txt");
        let r3 = build_usn_v2(3, USN_REASON_FILE_CREATE, 0, "c.txt");
        let mut buf = Vec::new();
        buf.extend_from_slice(&r1);
        buf.extend_from_slice(&r2);
        buf.extend_from_slice(&r3);
        let (events, truncated) = scan_usn_stream(&buf, 100);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].path, "a.txt");
        assert_eq!(events[2].path, "c.txt");
        assert!(!truncated);
    }

    #[test]
    fn scan_skips_leading_sparse_zeros() {
        // 4 KiB of zeroes (a sparse-read gap), then one real record.
        let r1 = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "late.txt");
        let mut buf = vec![0u8; 4096];
        buf.extend_from_slice(&r1);
        let (events, _) = scan_usn_stream(&buf, 100);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, "late.txt");
    }

    #[test]
    fn scan_mixed_v2_v3() {
        let r1 = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "v2.txt");
        let r2 = build_usn_v3(2, USN_REASON_FILE_CREATE, 0, "v3.txt");
        let mut buf = Vec::new();
        buf.extend_from_slice(&r1);
        buf.extend_from_slice(&r2);
        let (events, _) = scan_usn_stream(&buf, 100);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].path, "v2.txt");
        assert_eq!(events[1].path, "v3.txt");
    }

    #[test]
    fn scan_respects_record_cap() {
        let mut buf = Vec::new();
        for i in 0..5 {
            buf.extend_from_slice(&build_usn_v2(i, USN_REASON_FILE_CREATE, 0, "x"));
        }
        let (events, truncated) = scan_usn_stream(&buf, 2);
        assert_eq!(events.len(), 2, "cap=2 bounds the output");
        assert!(truncated, "hitting the cap reports truncation");
    }

    #[test]
    fn scan_stops_on_corrupt_record() {
        // One valid record, then a record claiming a length that overruns the buffer.
        let r1 = build_usn_v2(1, USN_REASON_FILE_CREATE, 0, "good.txt");
        let mut bad = vec![0u8; 16];
        bad[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // absurd RecordLength
        bad[4..6].copy_from_slice(&2u16.to_le_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(&r1);
        buf.extend_from_slice(&bad);
        let (events, truncated) = scan_usn_stream(&buf, 100);
        assert_eq!(events.len(), 1, "the good record is kept");
        assert!(!truncated, "stopping on corruption is not a cap truncation");
    }

    /// ELEVATED, manual-only. Run from an Administrator shell with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors usn::tests::elevated_e2e_real_j -- --ignored --nocapture
    /// Opens the real \\.\C:, parses $Extend\$UsnJrnl:$J, and asserts at least one event
    /// with a non-empty reason was decoded. CI never runs this (no privilege, no real disk).
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn elevated_e2e_real_j() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        let records = UsnCollector::default()
            .collect(&ctx)
            .expect("elevated $J collect should succeed on a live admin host");
        let usn_events: Vec<_> = records
            .iter()
            .filter_map(|r| match r {
                Record::UsnEvent(e) => Some(e),
                _ => None,
            })
            .collect();
        assert!(
            !usn_events.is_empty(),
            "a live C: volume with an active journal should yield USN events"
        );
        assert!(
            usn_events.iter().any(|e| !e.reason.is_empty()),
            "at least one event should carry a decoded reason"
        );
        eprintln!(
            "elevated_e2e_real_j: decoded {} USN events",
            usn_events.len()
        );
    }
}
