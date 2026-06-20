# $J / USN Journal Collector + mft Truncation Harvest — Design

**Date:** 2026-06-20
**Owning stage:** S2 (raw-NTFS second half, FR12)
**Branch:** `feature/usn-journal`

---

## 1. Scope

This sub-segment completes the raw-NTFS timeline by adding the `$J`/USN journal
collector and closing the one remaining `$MFT` gap (truncation visibility in the
manifest). It is deliberately scoped to **two products**:

1. **`UsnCollector`** — a new collector that reads the `$Extend\$UsnJrnl:$J`
   change-journal stream via the existing `ntfs` crate's alternate-data-stream
   support, parses USN_RECORD_V2/V3 into `Record::UsnEvent`, and is wired into the
   live AVAILABLE set.
2. **mft/usn truncation harvest** — replace the hardcoded empty
   `governance.truncations` (`cairn-cli/src/main.rs:641`) with a pure function that
   extracts truncation notes from collector `sources()` into the manifest, covering
   both `mft` and the new `usn`.

**Out of scope (next sub-segment):** the offline locked-hive collector
(`hive_collector`, FR12) and the hive-dependent offline collectors
(amcache/shimcache). The locked-hive path needs a different architecture
(raw-read hive bytes → off-target temp copy → `notatin` parse with transaction-log
replay) and a new dependency; it gets its own spec.

### 1.1 What already exists (verified 2026-06-20)

- `cairn-collectors-win::volume::VolumeReader` — raw read-only `\\.\C:`, sector
  aligned, `Read + Seek`, fully tested.
- `cairn-collectors::mft::MftCollector` — `$MFT` MACB + path map + two-layer DoS
  guard + record-cap truncation + privilege gate; **already in the live AVAILABLE
  set and selected** (`main.rs:586`, `:658`).
- `cairn-core::record::UsnEventRecord` — schema type already defined (`ts`, `path`,
  `reason`, `mft_ref`); no collector yet.
- `cairn-core::time::filetime_to_utc(u64) -> Option<DateTime<Utc>>` — the FILETIME
  helper; its doc-comment already predicts "$J later uses FILETIME too".
- Governance (NFR9/NFR10): capped rayon pool, live priority, `Config.governance`,
  `manifest::GovernanceReport { effective_threads, low_priority_applied,
  truncations: Vec<Truncation> }`, `manifest::Truncation { collector, cap, reason }`.

## 2. Crate / dependency decisions (verified 2026-06-20)

- **$J via the existing `ntfs` crate (zero new dependency).** `ntfs` 0.4 does NOT
  support journaling as a feature, but it DOES expose alternate data streams of any
  size via `NtfsFile::data(fs, "$J")`. `$UsnJrnl:$J` is an ADS, so we reach its raw
  bytes through that path and hand-parse the USN records ourselves.
- **`usn-journal-rs` REJECTED.** It works via live `DeviceIoControl`
  (`FSCTL_QUERY_USN_JOURNAL`), a live-host API that conflicts with the raw
  `\\.\C:` approach and cannot read `$J` offline/raw.
- **Hand-rolled raw-`$Extend` parse REJECTED (YAGNI/over-engineering).** Reusing
  `ntfs`'s ADS support keeps the collector symmetric with `MftCollector` and avoids
  re-implementing data-run / sparse handling.

### 2.1 Two verified `ntfs`-crate facts that shape the design

- **`data(fs, "<named stream>")` panics unless `read_upcase_table()` was called
  first.** We call `ntfs.read_upcase_table(fs)` before any named-stream lookup. The
  whole parse also runs under `catch_unwind` (mirroring mft guard b), so even an
  unforeseen panic is contained and converted to `Err`.
- **Sparse data runs read as zeroes, not errors.** `ntfs`'s non-resident reader
  fills the buffer with `0` for sparse runs and reports the length read (it does NOT
  return an error or a short read). `$J` typically begins with a large sparse
  region; reading it yields zeroes. Our parser treats `RecordLength == 0` as "no
  record here" and advances, so sparse gaps are handled correctly by the same code
  that handles inter-record padding. `data_runs()` sparse info (a run's
  `data_position().value().is_none()`) MAY be used as a fast-forward optimization,
  but `RecordLength == 0` is the authoritative correctness signal.

## 3. Architecture

### 3.1 New / modified units

| Unit | Action | Responsibility |
|------|--------|----------------|
| `crates/cairn-collectors/src/usn.rs` | **Create** | `UsnCollector` + pure `parse_usn_record` + pure `scan_usn_stream` |
| `crates/cairn-collectors/src/lib.rs` | Modify | `pub mod usn;` |
| `crates/cairn-core/src/config.rs` | Modify | add `max_usn_records: u64` (default 1_000_000, mirrors mft) |
| `crates/cairn-cli/src/main.rs` | Modify | (a) AVAILABLE += `"usn"`, construct `UsnCollector`; (b) `--max-usn-records` flag; (c) replace `truncations: Vec::new()` with `collect_truncations(&outcome.sources)` |

All new code lives in `cairn-collectors`, which is `#![forbid(unsafe_code)]`. The
only unsafe in the whole feature remains the pre-existing
`cairn-collectors-win::volume`. The collector consumes `VolumeReader` exactly as
`MftCollector` does.

### 3.2 Golden-rule posture

- #1 no evasion — none; benign raw read.
- #3 collectors don't modify the host — `$J` is read-only; never written.
- #4 footprint / `--dry-run` writes nothing — streaming, record-capped; `$J` not
  modified (USN-journal preservation, FR17).
- #7 UTC RFC3339 — `TimeStamp` FILETIME → `filetime_to_utc`.
- #8 graceful degrade — every failure path (no privilege, no `$UsnJrnl`/`$J`, parse
  panic, corrupt record) skips the collector or stops the stream with a recorded
  reason; the run continues.

## 4. Component detail

### 4.1 USN_RECORD binary layout (Microsoft USN_RECORD_V2 / V3)

Both versions share the first four fixed fields; they differ in file-reference
width and therefore all subsequent offsets.

| Field | Size | Notes |
|-------|------|-------|
| `RecordLength` | u32 | total record length incl. padding; `0` ⇒ no record |
| `MajorVersion` | u16 | 2 or 3 |
| `MinorVersion` | u16 | |
| `FileReferenceNumber` | 8 (V2) / 16 (V3) | low 48 bits = MFT record number |
| `ParentFileReferenceNumber` | 8 (V2) / 16 (V3) | |
| `Usn` | u64 | |
| `TimeStamp` | i64 | FILETIME |
| `Reason` | u32 | bitmask |
| `SourceInfo` | u32 | |
| `SecurityId` | u32 | |
| `FileAttributes` | u32 | |
| `FileNameLength` | u16 | bytes |
| `FileNameOffset` | u16 | from start of record |
| `FileName` | `FileNameLength` | UTF-16LE at `FileNameOffset` |

V2 fixed header = 60 bytes; V3 = 76 bytes (two 128-bit refs add 16). `mft_ref` =
`FileReferenceNumber & 0x0000_FFFF_FFFF_FFFF` (low 48 bits; high 16 are the
sequence number).

### 4.2 Pure parse function (no I/O — the correctness core)

```rust
/// Parse one USN record at the start of `buf`.
/// - RecordLength == 0       -> Ok(None)            (sparse / padding / end; caller advances)
/// - unknown major version   -> Ok(Some(Skipped))   (graceful skip; caller advances RecordLength)
/// - V2/V3 but field out of bounds -> Err           (caller records and stops THIS stream)
/// Never panics: every field read is bounds-checked against buf.len() first.
fn parse_usn_record(buf: &[u8]) -> Result<Option<ParsedUsn>>;

enum ParsedUsn {
    Event   { record_length: u32, rec: UsnEventRecord },
    Skipped { record_length: u32 },
}
```

- `reason` (u32 bitmask) decodes to a human-readable, deterministic string
  (e.g. `create`, `delete`, `rename_new`, `rename_old`, `data_overwrite`,
  `data_extend`, `data_truncation`, `close`, ...; multiple bits joined with `|`).
- `ts` = `filetime_to_utc(TimeStamp as u64)`; an unset/zero TimeStamp yields `None`
  for the option but the record is still emitted (the event happened). Because
  `UsnEventRecord.ts` is a non-optional `DateTime<Utc>`, a zero/unconvertible
  TimeStamp falls back to `DateTime::<Utc>::UNIX_EPOCH` and the record is still
  emitted; determinism and never-drop are preserved. (No schema change.)
- `path` = the bare UTF-16LE filename via `String::from_utf16_lossy` (best-effort:
  a corrupt name yields replacement chars, never an error — a triage tool keeps the
  record). Full-path reconstruction is intentionally NOT done here (see §4.4).

### 4.3 `UsnCollector` (mirrors `MftCollector`)

```rust
#[derive(Default)]
pub struct UsnCollector {
    truncated_cap: AtomicU64,   // 0 = not truncated; >0 = cap value (identical to mft)
}

impl Collector for UsnCollector {
    fn name(&self) -> &str { "usn" }
    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> { /* see flow */ }
    fn sources(&self) -> Vec<SourceEntry> {
        // artifact "usn", path \\.\C:, method "raw_ntfs_usn";
        // errors carries "truncated: max_usn_records reached (cap=N)" when capped.
    }
}
```

`collect`:
1. Privilege gate: `if !(ctx.admin && ctx.se_backup) { return Err(Privilege) }` —
   BEFORE any volume open (mirrors mft).
2. `VolumeReader::open(r"\\.\C:")?`.
3. Inside `catch_unwind(AssertUnwindSafe(...))`:
   - `Ntfs::new(reader)` → `ntfs.read_upcase_table(reader)`.
   - Navigate root → `$Extend` → `$UsnJrnl` via `directory_index()` lookups; a
     missing `$UsnJrnl` ⇒ `Err("$UsnJrnl absent; USN journal disabled")`.
   - `file.data(reader, "$J")` ⇒ missing ⇒ `Err("$J stream absent")`.
   - Stream the `$J` value, feeding `scan_usn_stream`-equivalent logic bounded by
     `max_usn_records`.
4. On cap hit, `truncated_cap.store(cap, Relaxed)`; return `Vec<Record::UsnEvent>`.

### 4.4 Pure stream scanner (sparse + cap, testable without a volume)

```rust
/// Scan a contiguous $J byte buffer, returning (events, truncated).
/// - leading/embedded zero regions (sparse) are skipped via RecordLength == 0
/// - stops at max_records (truncated = true) or end of buffer
/// - a corrupt record (parse Err) stops the scan, keeping already-parsed events
fn scan_usn_stream(buf: &[u8], max_records: u64) -> (Vec<UsnEventRecord>, bool);
```

The collector reads the `$J` value in bounded chunks and applies this logic; the
function is extracted so the sparse/cap/corruption behavior is unit-testable
against synthetic bytes (no `\\.\C:` needed).

**Two complementary advance mechanisms (they are not in tension):**

- *Performance path (collector, real `$J`):* before streaming, the collector reads
  `$J`'s `data_runs()` and seeks past leading sparse runs (`data_position().value()
  .is_none()`) so it does not stream megabytes of zeroes. This is an optimization
  over a real, possibly-multi-GB journal whose head is one large sparse run.
- *Correctness fallback (pure scanner, any buffer):* within the bytes it does
  examine, the scanner treats `RecordLength == 0` as "no record" and advances to
  the next 8-byte boundary (USN records are 8-byte aligned). This guarantees
  correctness even for embedded zero padding the data-run skip did not cover, and is
  the behavior exercised by the synthetic-byte tests (which have no data-run
  metadata). The two layers compose: data-run skip handles the bulk sparse head
  cheaply; the 8-byte fallback guarantees we never misread a record boundary.

### 4.5 Path handling (collector independence)

`UsnEventRecord` carries the bare filename (`path`) plus `mft_ref`. The collector
does NOT reach into the mft path index — that would either re-read `$MFT` (doubling
peak RAM, violating NFR10) or require sharing state across collectors (breaking the
Collector seam, golden rule 3). Cross-referencing a USN event to its full path is a
post-hoc join on `mft_ref` against `Record::FileMeta`, left to the consumer.

## 5. Data flow

### 5.1 Live run (usn parallel with mft, independent state)

```
orchestrator (rayon, capped pool)
   ├─ proc / net / persist
   ├─ MftCollector.collect()  → Vec<Record::FileMeta>   (independent)
   └─ UsnCollector.collect()  → Vec<Record::UsnEvent>   (independent)
        privilege gate ─ no → Err::Privilege → skip, reason in manifest, run continues
        VolumeReader::open ─ fail → Err → skip
        catch_unwind { Ntfs::new → read_upcase_table → $Extend\$UsnJrnl → data("$J")
                       → bounded streaming parse }
        → Vec<Record::UsnEvent> + sources(){ errors:[truncation note?] }
```

### 5.2 Truncation harvest (the mft-closeout product)

```
run_live → outcome.sources : Vec<SourceEntry>
   │  collect_truncations(&outcome.sources) -> Vec<manifest::Truncation>
   │     for each SourceEntry, for each error string matching
   │       "truncated: max_<X>_records reached (cap=N)",
   │       emit Truncation{ collector: entry.artifact, cap: N, reason: <the string> }
   ▼
governance_report.truncations = collect_truncations(&outcome.sources)
   (replaces the hardcoded Vec::new() at main.rs:641)
```

One function harvests BOTH mft and usn truncations. The authoritative source is the
collector's own `sources()` output; no new field is invented. `cap` is parsed from
the existing note format already emitted by mft (`truncated: max_mft_records reached
(cap=N)`) and usn (`truncated: max_usn_records reached (cap=N)`).

## 6. Error handling (golden-rule mapping)

| Situation | Handling | Rule |
|-----------|----------|------|
| no admin / no SeBackup | `Err::Privilege` before volume open → skip | #8 |
| `$UsnJrnl` or `$J` absent (journal disabled) | `Err::Collector` → skip, no panic | #8 |
| `ntfs` parse panic (unforeseen) | `catch_unwind` → `Err` → skip | #8 |
| single record out-of-bounds / corrupt length | `parse_usn_record` Err → stop THIS stream, keep parsed events | #8 |
| unknown USN major version | `Ok(Skipped)`, advance RecordLength, continue | degrade |
| huge `$J` (long-uptime server) | `max_usn_records` cap → stop + truncation note | #4 / NFR10 |
| any write | read-only; `--dry-run` writes nothing; `$J` unmodified | #3 #4 |
| timestamps | FILETIME → UTC RFC3339 via existing helper | #7 |

**Residual risk (accepted):** a `FileNameOffset`/`Length` pointing inside the
record but at corrupt UTF-16 yields replacement chars via `from_utf16_lossy` rather
than an error. This is intentional best-effort — a triage tool keeps a record with a
`�`-bearing filename rather than dropping it.

## 7. Testing strategy

### 7.1 `parse_usn_record` pure unit tests (synthetic bytes)

`parse_v2_create_event`, `parse_v3_event_128bit_ref`,
`parse_zero_record_length_is_none`, `parse_unknown_version_skips`,
`parse_truncated_header_is_err`, `parse_filename_offset_out_of_bounds_is_err`,
`parse_reason_bitmask_decodes`, `parse_bad_utf16_filename_best_effort`,
`parse_filetime_to_utc`. A `build_usn_v2(...)` / `build_usn_v3(...)` helper composes
records field-by-field.

### 7.2 `scan_usn_stream` pure unit tests

`scan_skips_leading_sparse_zeros`, `scan_multiple_records_sequential`,
`scan_mixed_v2_v3`, `scan_respects_record_cap`, `scan_stops_on_corrupt_record`.

### 7.3 Collector-layer unit tests

`collect_without_privilege_returns_err` (no volume opened — mirrors mft),
`sources_reports_truncation_when_capped`, `name_is_usn`.

### 7.4 `collect_truncations` pure unit tests

`collect_truncations_extracts_mft_and_usn`, `collect_truncations_empty_when_no_caps`,
`collect_truncations_ignores_unrelated_errors`.

### 7.5 `#[ignore]` elevated e2e

`#[ignore]`-gated, documented to require an admin shell (CI does not run it): open
real `\\.\C:`, parse the real `$J`, assert at least a few events with valid
`ts`/`reason`/filename. Same pattern as the mft elevated e2e.

### 7.6 CI consistency gate (per task)

`cargo fmt --check`; `cargo clippy --workspace --all-targets --locked -- -D
warnings` (`--all-targets` is mandatory — the governance lesson); `cargo test
--workspace` (NOT `-p`, to catch cross-crate test breakage); `cargo audit`
unchanged; `Cargo.lock` unchanged (zero new deps).

## 8. Definition of done

- `UsnCollector` in the live AVAILABLE set, selected under standard/verbose,
  excluded under `--profile minimal` (mirrors mft's raw-NTFS gating).
- `--max-usn-records` flag (default 1_000_000) wired into `Config`.
- `governance.truncations` populated from `collect_truncations`, covering mft + usn.
- All §7 tests pass; fmt clean; clippy `--all-targets` clean; `cargo test
  --workspace` green; `Cargo.lock` unchanged; `#![forbid(unsafe_code)]` intact in
  `cairn-collectors`.

## 9. YAGNI / explicitly deferred

- Offline locked-hive collector + amcache/shimcache (next sub-segment; needs
  `notatin` + temp-file architecture).
- USN_RECORD_V4 (range-tracking) — rare, low triage value; unknown versions skip
  gracefully so a V4 stream degrades cleanly rather than erroring.
- Full-path reconstruction for USN events (post-hoc join on `mft_ref`).
- VSS / `--since` time filtering of `$J` (the journal is already time-ordered;
  consumers can filter on `ts`).
