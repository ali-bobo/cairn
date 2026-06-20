# $J / USN Journal Collector + mft Truncation Harvest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only `$J`/USN journal collector (USN_RECORD_V2/V3 → `Record::UsnEvent`) wired into the live run, and harvest mft+usn record-cap truncations into the manifest.

**Architecture:** A new `cairn-collectors::usn` module mirrors `MftCollector`: a privilege-gated `UsnCollector` consumes the existing safe `VolumeReader`, uses the existing `ntfs` crate's alternate-data-stream support to reach `$Extend\$UsnJrnl:$J`, and hand-parses USN records with two pure, fully-unit-tested functions (`parse_usn_record`, `scan_usn_stream`). A pure `collect_truncations` helper turns collector `sources()` truncation notes into manifest `Truncation` entries. Zero new dependencies; all new code is `#![forbid(unsafe_code)]`.

**Tech Stack:** Rust, `ntfs` 0.4.0 (already a dep), `cairn-core` contracts, `rayon`, `clap`, `thiserror`/`anyhow`, `chrono`.

**Spec:** `docs/superpowers/specs/2026-06-20-usn-journal-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `crates/cairn-collectors/src/usn.rs` (CREATE) | `parse_usn_record` (pure), `scan_usn_stream` (pure), `UsnCollector` (ntfs ADS → records), all their tests |
| `crates/cairn-collectors/src/lib.rs` (MODIFY) | `pub mod usn;` |
| `crates/cairn-core/src/config.rs` (MODIFY) | `Config.max_usn_records: u64` (default 1_000_000) + test |
| `crates/cairn-cli/src/main.rs` (MODIFY) | `--max-usn-records` flag; AVAILABLE += `"usn"`; construct `UsnCollector`; `collect_truncations` + wire into `governance.truncations` |

## Conventions every task must follow (read first)

- Errors in libs: `cairn_core::CairnError` via the existing pattern. In `usn.rs` add a local helper `fn usn_err(reason: String) -> CairnError { CairnError::Collector { collector: "usn".into(), reason } }` (mirrors `mft_err` in `mft.rs`).
- `#![forbid(unsafe_code)]` stays at the top of `cairn-collectors` (it is already there). Do NOT add unsafe.
- Acceptance gate per task (run from the repo root `cairn/`):
  - `cargo fmt`
  - `cargo clippy --workspace --all-targets --locked -- -D warnings`  ← `--all-targets` is MANDATORY (it lints test code; omitting it is how a past CI break slipped through)
  - `cargo test --workspace`  ← `--workspace`, NOT `-p` (a required-field addition can break another crate's test code without `-p` ever noticing)
- Determinism (NFR4): emit records in `$J` byte order (the journal is already chronological); do not sort inside the collector.
- Commit after each task with the footer:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

---

## Task 1: USN record binary layout constants + `parse_usn_record` (pure)

**Files:**
- Create: `crates/cairn-collectors/src/usn.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`

This task builds the pure parser with NO I/O and NO ntfs/VolumeReader usage. It is the correctness core and must be exhaustively tested against synthetic bytes.

- [ ] **Step 1: Register the module**

In `crates/cairn-collectors/src/lib.rs`, add alongside the other `pub mod` lines (e.g. after `pub mod mft;`):

```rust
pub mod usn;
```

- [ ] **Step 2: Write the module skeleton with layout constants and types**

Create `crates/cairn-collectors/src/usn.rs` with the header doc, imports, constants, and the `ParsedUsn` enum. (Implementation of `parse_usn_record` comes in Step 4 after the tests.)

```rust
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
    Event { record_length: u32, rec: UsnEventRecord },
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
```

- [ ] **Step 3: Write the failing tests for `parse_usn_record`**

Add a `#[cfg(test)]` module at the bottom of `usn.rs`. Include a `build_usn_v2` / `build_usn_v3` byte-builder helper and the parse tests.

```rust
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
        // An odd FileNameLength (1 byte) is not valid UTF-16; from_utf16_lossy must
        // produce a best-effort string (replacement char) without erroring/panicking.
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
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p cairn-collectors usn::tests`
Expected: FAIL — `parse_usn_record` / `reason_to_string` not defined.

- [ ] **Step 5: Implement `parse_usn_record` + `reason_to_string`**

Add to `usn.rs` (above the test module):

```rust
/// Read a little-endian u16/u32/i64 at `off`, returning None if out of bounds.
/// Pure bounds-checked accessors keep the parser total (golden rule 8: never panic
/// on adversarial on-disk data).
#[inline]
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)?.try_into().ok().map(u16::from_le_bytes)
}
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)?.try_into().ok().map(u32::from_le_bytes)
}
#[inline]
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)?.try_into().ok().map(u64::from_le_bytes)
}
#[inline]
fn rd_i64(buf: &[u8], off: usize) -> Option<i64> {
    buf.get(off..off + 8)?.try_into().ok().map(i64::from_le_bytes)
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
        (0x8000_0000, "close"),
    ];
    let parts: Vec<&str> = BITS
        .iter()
        .filter(|(bit, _)| reason & bit != 0)
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
    let ts = filetime_to_utc(ts_raw as u64)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH);

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
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p cairn-collectors usn::tests`
Expected: PASS (all parse_* tests).

- [ ] **Step 7: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/usn.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(collectors): pure USN_RECORD_V2/V3 parser (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `scan_usn_stream` (pure sparse + cap scanner)

**Files:**
- Modify: `crates/cairn-collectors/src/usn.rs`

Builds the buffer-level scanner that drives `parse_usn_record` across a `$J` byte
buffer, handling sparse zero regions and the record cap. Still pure (no I/O).

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in `usn.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p cairn-collectors usn::tests::scan`
Expected: FAIL — `scan_usn_stream` not defined.

- [ ] **Step 3: Implement `scan_usn_stream`**

Add to `usn.rs` (above the test module):

```rust
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

    // Re-check the cap boundary: if we filled exactly to the cap AND there were more
    // bytes that could hold another record, mark truncated. The break above handles the
    // common case; this covers exact-fill. (Simplest: the break path already set it.)
    if events.len() as u64 >= max_records && pos < buf.len() {
        truncated = true;
    }

    (events, truncated)
}

/// Advance amount for a record, never zero (a zero-length non-sparse record would
/// otherwise loop forever); rounds up to the 8-byte USN alignment.
#[inline]
fn advance_by(record_length: usize) -> usize {
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
```

NOTE: `next_aligned` always moves forward by at least one alignment unit (guaranteeing
termination of the sparse-skip loop). `advance_by` rounds the record length up to the
alignment and never returns 0.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p cairn-collectors usn::tests::scan`
Expected: PASS (all scan_* tests).

- [ ] **Step 5: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/usn.rs
git commit -m "feat(collectors): pure $J stream scanner with sparse + record cap (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `max_usn_records` config field

**Files:**
- Modify: `crates/cairn-core/src/config.rs` (struct ~line 93, `Default` impl ~line 138)

Adds the record cap to `Config`, mirroring `max_mft_records`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `config.rs` (near `max_mft_records_defaults_to_one_million`):

```rust
    #[test]
    fn max_usn_records_defaults_to_one_million() {
        let cfg = Config::default();
        assert_eq!(cfg.max_usn_records, 1_000_000);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p cairn-core max_usn_records`
Expected: FAIL — no field `max_usn_records` on `Config`.

- [ ] **Step 3: Add the field and default**

In the `Config` struct, after the `max_mft_records: u64,` field (and its doc comment), add:

```rust
    /// Hard cap on USN ($J) records the usn collector emits (NFR10). Default 1,000,000.
    /// Hitting it records a truncation note in the manifest and stops the scan, so a
    /// huge journal on a long-uptime server cannot exhaust memory. Mirrors max_mft_records.
    pub max_usn_records: u64,
```

In `Config::default()`, after `max_mft_records: 1_000_000,`, add:

```rust
            max_usn_records: 1_000_000,
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p cairn-core max_usn_records`
Expected: PASS.

- [ ] **Step 5: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-core/src/config.rs
git commit -m "feat(core): Config.max_usn_records cap, default 1M (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `UsnCollector` — wire the pure scanner to the `$J` ADS

**Files:**
- Modify: `crates/cairn-collectors/src/usn.rs`

Adds the `Collector` impl: privilege gate, volume open, ntfs navigation to
`$Extend\$UsnJrnl:$J`, streaming read into `scan_usn_stream`, truncation surfacing.
This is the integration task — use a standard (not cheap) model.

- [ ] **Step 1: Write the failing privilege/identity tests**

Add to the test module in `usn.rs`:

```rust
    use cairn_core::config::Config;

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p cairn-collectors usn::tests`
Expected: FAIL — `UsnCollector` not defined.

- [ ] **Step 3: Implement `UsnCollector`**

Add to `usn.rs` (above the test module). The `$J`-reading helper is split out so the
privilege/navigation flow is readable; it runs under `catch_unwind` like mft guard b.

```rust
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
    use ntfs::indexes::NtfsFileNameIndex;
    use ntfs::Ntfs;

    let mut ntfs = Ntfs::new(reader).map_err(|e| usn_err(format!("Ntfs::new failed: {e}")))?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| usn_err(format!("read_upcase_table failed: {e}")))?;

    // root -> $Extend
    let root = ntfs
        .root_directory(reader)
        .map_err(|e| usn_err(format!("root_directory failed: {e}")))?;
    let extend = find_child(&ntfs, reader, &root, "$Extend")?;
    // $Extend -> $UsnJrnl
    let usnjrnl = find_child(&ntfs, reader, &extend, "$UsnJrnl")?;

    // $UsnJrnl:$J data stream (the journal payload). data() returns None if absent.
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

    // Read the $J value into a bounded buffer, then scan. The value's data length is the
    // logical (incl. sparse) size; we cap the bytes we buffer so an enormous journal does
    // not exhaust memory (NFR10) — the record cap further bounds emitted events.
    let buf = read_value_capped(value, reader, max_records)?;
    Ok(scan_usn_stream(&buf, max_records))
}

/// Look up a child file by name in a directory, returning its NtfsFile.
/// `read_upcase_table` MUST already have been called on `ntfs` (find() panics otherwise);
/// the caller guarantees this.
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

/// Read up to a memory-bounded number of bytes from an ntfs attribute value into a Vec,
/// so the pure scanner can run over it. The byte ceiling is derived from the record cap
/// (a generous upper bound: max_records * a typical max record size), clamped to a hard
/// ceiling so a lied-about value length cannot force a huge allocation (NFR10).
fn read_value_capped<R: std::io::Read + std::io::Seek>(
    value: ntfs::attribute_value::NtfsAttributeValue<'_, '_>,
    reader: &mut R,
    max_records: u64,
) -> Result<Vec<u8>> {
    use std::io::Read as _;
    // Hard ceiling: 512 MiB. A USN record is typically < 1 KiB; max_records * 1 KiB is a
    // generous functional bound, then we clamp to the hard ceiling regardless.
    const HARD_CEILING: u64 = 512 * 1024 * 1024;
    let functional = max_records.saturating_mul(1024);
    let ceiling = functional.min(HARD_CEILING) as usize;

    let mut attached = value.attach(reader);
    let mut buf = Vec::new();
    // Read in capped chunks; stop at the ceiling (Read::take bounds total bytes).
    attached
        .by_ref()
        .take(ceiling as u64)
        .read_to_end(&mut buf)
        .map_err(|e| usn_err(format!("reading $J value failed: {e}")))?;
    Ok(buf)
}
```

IMPLEMENTER NOTE (one inferred API spot — verify against `ntfs` 0.4.0 during this task):
the exact way to get a `Read+Seek` from the `$J` value is assumed to be
`attr.value(reader)?` → `NtfsAttributeValue`, then `value.attach(reader)` →
`NtfsAttributeValueAttached` (which is `Read`). The crate's own docs/examples for
`NtfsAttributeValue` / `NtfsAttributeValueAttached` are authoritative; if `attach`
or `value` differ, adjust these two lines (the surrounding logic is unaffected).
Confirm `index.finder()` and `entry.to_file(ntfs, reader)` likewise. Do NOT change
the pure functions or the public collector surface to accommodate API drift.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p cairn-collectors usn::tests`
Expected: PASS (privilege/name/sources tests; the parse/scan tests still pass).

- [ ] **Step 5: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/usn.rs
git commit -m "feat(collectors): UsnCollector reads \$Extend\\\$UsnJrnl:\$J via ntfs ADS (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `collect_truncations` harvest + manifest wiring (the mft closeout)

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (~line 638-642, the `governance_report` construction)

Replaces the hardcoded empty `truncations` with a pure function that extracts cap
notes from collector `sources()`, covering both mft and usn.

- [ ] **Step 1: Write the failing test**

In `crates/cairn-cli/src/main.rs`, find the `#[cfg(test)] mod tests` block. Add:

```rust
    #[test]
    fn collect_truncations_extracts_mft_and_usn() {
        use cairn_core::manifest::SourceEntry;
        let sources = vec![
            SourceEntry {
                artifact: "mft".into(),
                path: r"\\.\C:".into(),
                method: "raw_ntfs".into(),
                size: 0,
                sha256: String::new(),
                errors: vec!["truncated: max_mft_records reached (cap=1000000)".into()],
            },
            SourceEntry {
                artifact: "usn".into(),
                path: r"\\.\C:".into(),
                method: "raw_ntfs_usn".into(),
                size: 0,
                sha256: String::new(),
                errors: vec!["truncated: max_usn_records reached (cap=42)".into()],
            },
        ];
        let t = collect_truncations(&sources);
        assert_eq!(t.len(), 2);
        assert!(t.iter().any(|x| x.collector == "mft" && x.cap == 1_000_000));
        assert!(t.iter().any(|x| x.collector == "usn" && x.cap == 42));
    }

    #[test]
    fn collect_truncations_empty_when_no_caps() {
        use cairn_core::manifest::SourceEntry;
        let sources = vec![SourceEntry {
            artifact: "mft".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }];
        assert!(collect_truncations(&sources).is_empty());
    }

    #[test]
    fn collect_truncations_ignores_unrelated_errors() {
        use cairn_core::manifest::SourceEntry;
        let sources = vec![SourceEntry {
            artifact: "proc".into(),
            path: "live".into(),
            method: "toolhelp".into(),
            size: 0,
            sha256: String::new(),
            errors: vec!["some unrelated warning".into()],
        }];
        assert!(collect_truncations(&sources).is_empty());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p cairn-cli collect_truncations`
Expected: FAIL — `collect_truncations` not defined.

- [ ] **Step 3: Implement `collect_truncations`**

Add a free function in `main.rs` (near the other helpers, outside `fn main`):

```rust
/// Harvest record-cap truncation notes from collector provenance into manifest
/// Truncation entries. Collectors surface a cap via a `sources()` error string of the
/// form "truncated: max_<X>_records reached (cap=N)"; this parses the cap and attributes
/// it to the SourceEntry's artifact name. The authoritative source is the collector's own
/// sources() — no separate truncation channel is invented (governance design).
fn collect_truncations(
    sources: &[cairn_core::manifest::SourceEntry],
) -> Vec<cairn_core::manifest::Truncation> {
    let mut out = Vec::new();
    for entry in sources {
        for err in &entry.errors {
            // Match "...(cap=NNN)" and extract the integer.
            if let Some(rest) = err.strip_prefix("truncated: ") {
                if let Some(cap) = parse_cap(rest) {
                    out.push(cairn_core::manifest::Truncation {
                        collector: entry.artifact.clone(),
                        cap,
                        reason: err.clone(),
                    });
                }
            }
        }
    }
    out
}

/// Extract N from a string containing "(cap=N)". Returns None if absent or unparsable.
fn parse_cap(s: &str) -> Option<u64> {
    let start = s.find("(cap=")? + "(cap=".len();
    let tail = &s[start..];
    let end = tail.find(')')?;
    tail[..end].parse::<u64>().ok()
}
```

- [ ] **Step 4: Wire it into the governance report**

Replace the hardcoded `truncations: Vec::new()` in the `governance_report`
construction. Because `collect_truncations` reads `outcome.sources`, the
`governance_report` must be built AFTER `run_live` returns. Move the
`GovernanceReport` construction to just before the `Manifest { ... }` literal (it is
currently built before `run_live`). Concretely:

1. Before `run_live`, keep computing `effective_threads` and `low_priority_applied`
   (those do not depend on the outcome).
2. Delete the early `let governance_report = GovernanceReport { ... truncations: Vec::new() };`.
3. After `let mut outcome = run_live(...);` and after findings are stamped/sorted,
   build:

```rust
            let governance_report = cairn_core::manifest::GovernanceReport {
                effective_threads,
                low_priority_applied,
                truncations: collect_truncations(&outcome.sources),
            };
```

4. The `Manifest { ... governance: governance_report }` line is unchanged (the value
   is now the post-outcome one).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p cairn-cli collect_truncations`
Expected: PASS.

- [ ] **Step 6: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): harvest mft+usn record-cap truncations into manifest (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: CLI wiring — `--max-usn-records`, AVAILABLE, RAW_NTFS gating, collector construction

**Files:**
- Modify: `crates/cairn-core/src/selection.rs` (RAW_NTFS, line 34)
- Modify: `crates/cairn-cli/src/main.rs` (RunArgs ~line 113; AVAILABLE line 586 & 845; collector construction ~line 658; cfg construction ~line 600)

Adds the flag, marks usn as raw-NTFS (so `--profile minimal` skips it), and puts
`UsnCollector` into the live run.

**CRITICAL — without this, the `minimal skips usn` test fails:** `--profile minimal`
gates out raw-NTFS collectors via `const RAW_NTFS: &[&str]` in
`crates/cairn-core/src/selection.rs` (currently `&["mft"]`). `usn` is also a raw-NTFS
admin read, so it MUST be added there. Edit line 34:

```rust
const RAW_NTFS: &[&str] = &["mft", "usn"];
```

The existing selection.rs tests (`minimal_excludes_raw_ntfs_collectors`,
`standard_and_verbose_include_raw_ntfs`, `only_mft_under_minimal_still_excluded`) use
fixtures `available = vec!["proc", "net", "persist", "mft"]` — they do NOT contain
`"usn"`, so adding `"usn"` to `RAW_NTFS` does NOT break them; leave those tests
unchanged. Optionally add ONE focused test proving usn is gated:

```rust
    #[test]
    fn minimal_excludes_usn() {
        let available = vec!["proc", "net", "persist", "mft", "usn"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]); // no mft, no usn
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"usn".to_string())); // standard keeps usn (Vec<String>)
    }
```

Run `cargo test -p cairn-core` after this edit to confirm selection tests pass.

- [ ] **Step 1: Write the failing flag tests**

In `main.rs` tests, near `max_mft_records_flag_defaults_to_one_million` (~line 1032).
NOTE the real parse pattern in this file: `RunArgs::parse_from(["cairn", "--target",
"live", "--output", "out", ...])` with `use clap::Parser;` — `--target` and
`--output` are REQUIRED, so they must be present in every parse_from call.

```rust
    #[test]
    fn max_usn_records_flag_defaults_to_one_million() {
        use clap::Parser;
        let args = RunArgs::parse_from(["cairn", "--target", "live", "--output", "out"]);
        assert_eq!(args.max_usn_records, 1_000_000);
    }

    #[test]
    fn max_usn_records_flag_parses_override() {
        use clap::Parser;
        let args = RunArgs::parse_from([
            "cairn",
            "--target",
            "live",
            "--output",
            "out",
            "--max-usn-records",
            "42",
        ]);
        assert_eq!(args.max_usn_records, 42);
    }
```

ALSO update the existing `selected_collector_names_follow_selection` test (~line 843),
which pins AVAILABLE membership AND asserts the exact selected vector. Adding `"usn"`
to AVAILABLE breaks the exact-vector assertion at line 856 unless updated. The test
uses the helper `built_collector_names(&sel.selected)` (it returns `Vec<String>`).
Make these three edits inside that test:

1. Line 845 — add `"usn"` to AVAILABLE:
```rust
        const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft", "usn"];
```
2. Line 856 — extend the exact-order expected vector:
```rust
        assert_eq!(built, vec!["proc", "net", "persist", "mft", "usn"]);
```
3. After the existing `assert!(built.contains(&"mft"...))` lines, add usn assertions:
```rust
        // raw-NTFS collectors: standard includes both, minimal skips both.
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"usn".to_string()), "standard includes usn");
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"usn".to_string()), "minimal skips usn");
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p cairn-cli max_usn_records_flag`
Expected: FAIL — no field `max_usn_records` on `RunArgs`.

- [ ] **Step 3: Add the CLI flag**

In `RunArgs`, after the `max_mft_records` field (~line 116), add:

```rust
    /// Hard cap on USN ($J) records the usn collector emits (NFR10). Default 1,000,000.
    /// Keep in sync with `cairn_core::config::Config::default().max_usn_records`.
    #[arg(long, default_value_t = 1_000_000)]
    max_usn_records: u64,
```

(Match the exact `#[arg(...)]` attribute style used by the adjacent `max_mft_records`
field — copy its attribute and change the name/doc.)

- [ ] **Step 4: Wire the cap into Config and add usn to AVAILABLE + construction**

a) In the live `Config { ... }` construction (~line 600), add the field:

```rust
            let mut cfg = Config {
                max_mft_records: args.max_mft_records,
                max_usn_records: args.max_usn_records,
                profile,
                ..Config::default()
            };
```

b) Update the runtime AVAILABLE (~line 586):

```rust
            const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft", "usn"];
```

c) After the `mft` collector construction block (~line 658-660), add:

```rust
            if selection.selected.iter().any(|m| m == "usn") {
                collectors.push(Box::new(cairn_collectors::usn::UsnCollector::default()));
            }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p cairn-cli`
Expected: PASS (flag tests + updated AVAILABLE tests).

- [ ] **Step 6: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): --max-usn-records and wire UsnCollector into live run (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: `#[ignore]` elevated e2e for $J

**Files:**
- Modify: `crates/cairn-collectors/src/usn.rs`

A manually-run, admin-only sanity check that the real `$J` parses end to end. CI does
not run it (`#[ignore]`).

- [ ] **Step 1: Add the ignored e2e test**

Add to the `#[cfg(test)] mod tests` in `usn.rs`:

```rust
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
        eprintln!("elevated_e2e_real_j: decoded {} USN events", usn_events.len());
    }
```

- [ ] **Step 2: Verify it is collected but skipped**

Run: `cargo test -p cairn-collectors usn::tests::elevated_e2e_real_j`
Expected: the test is listed and reported as `ignored` (0 run, 1 ignored). It must
NOT run or fail in the normal suite.

- [ ] **Step 3: Acceptance gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/usn.rs
git commit -m "test(collectors): #[ignore] elevated e2e for real \$J parse (usn)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final review (after all tasks)

Dispatch a whole-feature code review covering: golden-rule compliance (no evasion,
read-only, dry-run, UTC, graceful degrade), never-panic on adversarial bytes,
manifest honesty (truncations actually reflect collector state), determinism
(byte-order emission, fixed reason-bit order), schema compatibility (no
`UsnEventRecord`/`Manifest` shape change), `#![forbid(unsafe_code)]` intact in
cairn-collectors, zero new dependencies (`Cargo.lock` unchanged). Then use
superpowers:finishing-a-development-branch.
