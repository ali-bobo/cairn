# Hive-Reader Primitive + Shimcache Collector — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read a locked SYSTEM hive via raw `\\.\C:` (notatin, in-memory, with `.LOG1`/`.LOG2` replay), parse AppCompatCache (shimcache), and emit `Record::Execution`.

**Architecture:** Two new files in `cairn-collectors` (`#![forbid(unsafe_code)]` preserved): `hive_reader.rs` (reusable primitive — raw-locate + read hive bytes + notatin Parser + safe value-fetch) and `shimcache.rs` (pure version-aware AppCompatCache parser + `ShimCollector`). All in-memory via `Cursor<Vec<u8>>`; zero temp files; zero new `unsafe` (reuses existing `VolumeReader`).

**Tech Stack:** Rust, `notatin` 1.0.1 (Apache-2.0, `default-features = false`), existing `ntfs` 0.4, existing `cairn_collectors_win::volume::VolumeReader`.

**Design doc:** `docs/superpowers/specs/2026-06-20-hive-reader-shimcache-design.md`

**Reference files to read before starting (existing patterns to mirror exactly):**
- `crates/cairn-collectors/src/usn.rs` — the canonical raw-NTFS collector: privilege gate, `catch_unwind` guard with the full AssertUnwindSafe NOTE, `find_child` ntfs nav, `read_value_capped`, `sources()` with truncation flag, `#[ignore]` e2e. **This plan mirrors usn.rs throughout.**
- `crates/cairn-collectors/src/mft.rs` — boot-sector length guard (a) + `catch_unwind` guard (b) precedent.
- `crates/cairn-core/src/record.rs:114-126` — `ExecutionRecord` fields.
- `crates/cairn-core/src/selection.rs:34` — `RAW_NTFS` const.
- `crates/cairn-cli/src/main.rs:277,623,676-693,882-916` — `built_collector_names`, `AVAILABLE`, collector construction, `selected_collector_names_follow_selection`.

**Two facts the implementer MUST verify against the installed source (NOT guessed — same discipline used for ntfs in usn.rs):**
1. **notatin value→raw-bytes:** `Parser::get_key(path, has_root) -> Result<Option<CellKeyNode>>`, `CellKeyNode::get_value(name) -> Option<CellKeyValue>`, `CellKeyNode::last_key_written_date_and_time() -> DateTime<Utc>` are confirmed from docs.rs. The exact way to pull the **raw binary bytes** out of a `CellKeyValue` (the `get_content()` return / `CellValue::ValueBinary` variant) must be confirmed against the installed `notatin` source in Task 2.
2. **AppCompatCache magic & header size:** authoritative layout below (from nullsec.us deep-dive + winreg-kb): 52-byte file header, cache entries begin at offset **0x34**, per-entry signature `"10ts"` (bytes `31 30 74 73`). The implementer confirms the 0x34 header offset and `"10ts"` magic against Eric Zimmerman's AppCompatCacheParser source if available; otherwise the values below are authoritative.

---

## Task 1: Add notatin dependency, wire the empty modules

**Files:**
- Modify: `Cargo.toml` (workspace root — `[workspace.dependencies]`)
- Modify: `crates/cairn-collectors/Cargo.toml`
- Create: `crates/cairn-collectors/src/hive_reader.rs`
- Create: `crates/cairn-collectors/src/shimcache.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`

- [ ] **Step 1: Add notatin to workspace dependencies**

In the workspace root `Cargo.toml`, under `[workspace.dependencies]`, add (keep the section's existing alphabetical-ish ordering near other parser crates like `ntfs`):

```toml
# Offline Windows registry hive parser (Apache-2.0, 100% safe Rust). default-features
# = false drops binary-only deps (clap/xlsxwriter/walkdir). Used by hive_reader for
# locked-hive parse + .LOG1/.LOG2 replay. Last upstream release 2023-08 (mature, stale);
# cargo audit gates advisories.
notatin = { version = "1.0.1", default-features = false }
```

- [ ] **Step 2: Reference notatin from cairn-collectors**

In `crates/cairn-collectors/Cargo.toml`, under `[dependencies]`, add:

```toml
notatin = { workspace = true }
```

- [ ] **Step 3: Create the two module files as empty stubs**

Create `crates/cairn-collectors/src/hive_reader.rs` with exactly:

```rust
//! HiveReader: raw-locate a locked hive, read its bytes (+ .LOG1/.LOG2) entirely in
//! memory, and parse it with notatin. Reusable primitive for hive-backed collectors
//! (shimcache now; amcache/userassist later). Mirrors usn.rs: same VolumeReader +
//! ntfs find_child navigation, same catch_unwind third-party-panic containment, same
//! read_value_capped memory ceiling. No temp files (notatin from_file takes a reader).
```

Create `crates/cairn-collectors/src/shimcache.rs` with exactly:

```rust
//! ShimCollector: parse the AppCompatCache (shimcache) value from a locked SYSTEM
//! hive into Record::Execution. The version-aware blob parser (parse_appcompatcache)
//! is a pure, never-panic function (bounds-checked readers, like parse_usn_record);
//! the collector is privilege-gated and read-only, using hive_reader to fetch bytes.
```

- [ ] **Step 4: Declare the modules in lib.rs**

In `crates/cairn-collectors/src/lib.rs`, add alongside the existing `pub mod usn;` (keep alphabetical with siblings):

```rust
pub mod hive_reader;
pub mod shimcache;
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --workspace`
Expected: PASS (notatin resolves; empty modules compile). If notatin pulls an unexpected transitive advisory, run `cargo audit` and report before proceeding.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/cairn-collectors/Cargo.toml crates/cairn-collectors/src/hive_reader.rs crates/cairn-collectors/src/shimcache.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(hive): add notatin dep, stub hive_reader + shimcache modules

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: hive_reader — types, error helper, get_value_bytes (pure-ish, no volume)

This task builds the notatin-facing half (no raw volume yet): the `HivePath`/`OpenedHive`/`LogStatus` types, the `hive_err` helper, and `get_value_bytes` which takes an already-built `notatin::parser::Parser`. `get_value_bytes` is testable against an in-memory hive built with notatin's own `from_file` over a tiny real hive fixture is NOT feasible (no fixture); instead its correctness is covered by the e2e in Task 7. This task's unit tests cover the **types and error helper** only; `get_value_bytes` is compiled + exercised by e2e.

**Files:**
- Modify: `crates/cairn-collectors/src/hive_reader.rs`

- [ ] **Step 1: Write failing tests for types + helper**

Append to `hive_reader.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_hive_path_is_config_system() {
        assert_eq!(
            SYSTEM_HIVE.components,
            &["Windows", "System32", "config", "SYSTEM"]
        );
    }

    #[test]
    fn hive_err_is_collector_variant() {
        let e = hive_err("boom".into());
        assert!(matches!(e, cairn_core::CairnError::Collector { .. }));
    }

    #[test]
    fn log_status_variants_construct() {
        let _ = LogStatus::Applied;
        let _ = LogStatus::NotFound;
        let _ = LogStatus::Failed("x".into());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p cairn-collectors hive_reader`
Expected: FAIL (types/consts/`hive_err` not defined).

- [ ] **Step 3: Implement types, consts, helper, get_value_bytes**

At the top of `hive_reader.rs` (after the module doc), add:

```rust
use std::io::{Read, Seek};

use chrono::{DateTime, Utc};
use cairn_core::{CairnError, Result};

/// A locked hive's on-volume location. Drive prefix is fixed C: (reads \\.\C:),
/// matching mft/usn — $MFT carries no drive-letter info.
pub(crate) struct HivePath {
    /// Volume-relative path components, last element is the hive filename.
    pub components: &'static [&'static str],
}

/// SYSTEM hive — the only path wired this segment.
pub(crate) const SYSTEM_HIVE: HivePath = HivePath {
    components: &["Windows", "System32", "config", "SYSTEM"],
};

/// 512 MiB hard ceiling on a single hive's in-memory size (NFR10). A boot sector or
/// attribute length lying about size cannot force a larger allocation than this.
pub(crate) const HIVE_HARD_CEILING: u64 = 512 * 1024 * 1024;

/// Outcome of attempting transaction-log replay. Recorded in the manifest.
pub(crate) enum LogStatus {
    /// At least one of .LOG1/.LOG2 was found and handed to notatin.
    Applied,
    /// Neither log file was present (clean shutdown or logs absent) — primary only.
    NotFound,
    /// A log existed but reading it failed; primary-only parse proceeded.
    Failed(String),
}

/// Result of open_hive.
pub(crate) struct OpenedHive {
    pub parser: notatin::parser::Parser,
    pub log_status: LogStatus,
    /// True if the primary hive read hit HIVE_HARD_CEILING (abstain signal).
    pub truncated: bool,
}

/// Build a Collector-variant CairnError (mirrors usn_err/mft_err).
fn hive_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "hive".into(),
        reason,
    }
}

/// Fetch a single value's raw bytes + the owning key's last-write time.
/// Returns Ok(None) when the key or value is absent (graceful — golden rule 8).
///
/// key_path uses notatin's path syntax WITHOUT the root prefix (key_path_has_root =
/// false), e.g. r"ControlSet001\Control\Session Manager\AppCompatCache".
///
/// IMPLEMENTER: confirm the CellKeyValue -> raw bytes extraction against the installed
/// notatin source. From docs.rs: CellKeyValue::get_content() returns (CellValue, _);
/// the binary case is CellValue::ValueBinary(Vec<u8>). Match that variant; for any
/// non-binary value return its bytes best-effort or Ok(None) (AppCompatCache is always
/// REG_BINARY, so the binary path is the only one that matters here).
pub(crate) fn get_value_bytes(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Result<Option<(Vec<u8>, Option<DateTime<Utc>>)>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(None),
    };
    let last_write = key.last_key_written_date_and_time();
    let value = match key.get_value(value_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    // IMPLEMENTER: confirm exact content accessor + binary variant name here.
    let bytes = match value.get_content().0 {
        notatin::cell_value::CellValue::ValueBinary(b) => b,
        _ => return Ok(None),
    };
    Ok(Some((bytes, Some(last_write))))
}
```

> NOTE: `get_value_bytes` takes `&mut Parser` because notatin's `get_key` is `&mut self`. The tests in Step 1 don't call it (no fixture); it's compiled here and exercised in Task 7 e2e.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors hive_reader`
Expected: PASS (3 tests). If `value.get_content()` / `CellValue::ValueBinary` don't match the installed notatin API, fix per the real source and report what changed.

- [ ] **Step 5: Clippy + commit**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`
Expected: clean.

```bash
git add crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(hive): hive_reader types, hive_err, get_value_bytes

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: hive_reader — open_hive (raw volume → notatin Parser, catch_unwind guarded)

Adds the raw-volume half: navigate to the hive file, read primary + logs into memory, build the notatin Parser. Wrapped in `catch_unwind` exactly like `usn.rs::read_usn_journal`. The only CI-testable branch is the short-reader error path (mirrors mft guard); the success path is e2e (Task 7).

**Files:**
- Modify: `crates/cairn-collectors/src/hive_reader.rs`

- [ ] **Step 1: Write the failing test (short-reader error branch)**

Add to the `tests` mod in `hive_reader.rs`:

```rust
    use std::io::Cursor;

    #[test]
    fn open_hive_short_reader_is_err_not_panic() {
        // A reader far shorter than a boot sector: ntfs cannot parse a volume.
        // Must return Err (contained), never panic (golden rule 8).
        let mut reader = Cursor::new(vec![0u8; 16]);
        let r = open_hive(&mut reader, &SYSTEM_HIVE);
        assert!(r.is_err(), "short reader must yield Err, got Ok");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p cairn-collectors hive_reader::tests::open_hive_short_reader`
Expected: FAIL (`open_hive` not defined).

- [ ] **Step 3: Implement open_hive + helpers**

Add to `hive_reader.rs` (before the tests mod). This mirrors `usn.rs` navigation (`find_child`) and memory-capped read (`read_value_capped`), and the `catch_unwind` guard with the SAME AssertUnwindSafe NOTE wording usn.rs uses:

```rust
/// Locate, read (in memory), and notatin-parse a hive from a raw volume reader.
///
/// Wrapped in catch_unwind (mirroring usn.rs read_usn_journal / mft.rs guard b): the
/// ntfs crate panics on some inputs (named-stream lookup panics without
/// read_upcase_table; short sources panic in Ntfs::new) and notatin is third-party
/// too. Contain any panic and convert to Err so it never escapes this collector.
pub(crate) fn open_hive<R: Read + Seek>(reader: &mut R, hive: &HivePath) -> Result<OpenedHive> {
    use std::panic::{self, AssertUnwindSafe};
    // AssertUnwindSafe is correct here because:
    // - `reader` is the only captured mutable reference.
    // - If ntfs/notatin panic, `reader` may be in an undefined mid-parse state, but we
    //   NEVER use `reader` after a caught panic — we immediately return Err.
    // - We are NOT using catch_unwind to hide our own logic errors; only to contain a
    //   third-party panic (ntfs short-source / named-lookup; notatin regressions).
    let result = panic::catch_unwind(AssertUnwindSafe(|| open_hive_inner(reader, hive)));
    match result {
        Ok(inner) => inner,
        Err(_) => Err(hive_err(
            "ntfs/notatin panicked (contained); treating hive as unreadable".into(),
        )),
    }
}

/// Inner open: navigate to the hive file, read primary + .LOG1/.LOG2 into memory,
/// build the notatin Parser. Only called inside catch_unwind.
fn open_hive_inner<R: Read + Seek>(reader: &mut R, hive: &HivePath) -> Result<OpenedHive> {
    use ntfs::Ntfs;

    let mut ntfs = Ntfs::new(reader).map_err(|e| hive_err(format!("Ntfs::new failed: {e}")))?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| hive_err(format!("read_upcase_table failed: {e}")))?;
    let root = ntfs
        .root_directory(reader)
        .map_err(|e| hive_err(format!("root_directory failed: {e}")))?;

    // Walk components: dirs are intermediate, last is the hive file.
    let (dir_components, file_name) = hive
        .components
        .split_last()
        .map(|(last, init)| (init, *last))
        .ok_or_else(|| hive_err("empty HivePath".into()))?;

    let mut cur = root;
    for comp in dir_components {
        cur = find_child(&ntfs, reader, &cur, comp)?;
    }
    // Read primary hive (default unnamed data stream).
    let (primary, truncated) = read_named_default_stream(&ntfs, reader, &cur, file_name)?;

    // Read .LOG1/.LOG2 best-effort (graceful: absent -> NotFound).
    let log1 = read_named_default_stream(&ntfs, reader, &cur, &format!("{file_name}.LOG1"));
    let log2 = read_named_default_stream(&ntfs, reader, &cur, &format!("{file_name}.LOG2"));

    let log_status = build_parser_log_status(&log1, &log2);
    let parser = build_parser(primary, log1.ok().map(|(b, _)| b), log2.ok().map(|(b, _)| b))?;

    Ok(OpenedHive {
        parser,
        log_status,
        truncated,
    })
}

/// Read a named child file's DEFAULT (unnamed) data stream into a memory-capped Vec.
/// Returns (bytes, truncated). truncated == true if HIVE_HARD_CEILING was hit.
fn read_named_default_stream<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<(Vec<u8>, bool)> {
    use std::io::Read as _;
    let file = find_child(ntfs, reader, dir, name)?;
    let data_item = file
        .data(reader, "")
        .ok_or_else(|| hive_err(format!("{name}: no default data stream")))?
        .map_err(|e| hive_err(format!("{name} data attribute error: {e}")))?;
    let attr = data_item
        .to_attribute()
        .map_err(|e| hive_err(format!("{name} to_attribute failed: {e}")))?;
    let value = attr
        .value(reader)
        .map_err(|e| hive_err(format!("{name} value failed: {e}")))?;
    let mut attached = value.attach(reader);
    let mut buf = Vec::new();
    let n = attached
        .by_ref()
        .take(HIVE_HARD_CEILING)
        .read_to_end(&mut buf)
        .map_err(|e| hive_err(format!("reading {name} failed: {e}")))?;
    let truncated = n as u64 == HIVE_HARD_CEILING;
    Ok((buf, truncated))
}

/// Look up a child file by name in a directory (mirrors usn.rs find_child).
/// read_upcase_table MUST already have been called on `ntfs`.
fn find_child<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    use ntfs::indexes::NtfsFileNameIndex;
    let index = dir
        .directory_index(reader)
        .map_err(|e| hive_err(format!("directory_index for {name} failed: {e}")))?;
    let mut finder = index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, ntfs, reader, name)
        .ok_or_else(|| hive_err(format!("{name} not found in directory")))?
        .map_err(|e| hive_err(format!("find {name} failed: {e}")))?;
    entry
        .to_file(ntfs, reader)
        .map_err(|e| hive_err(format!("to_file for {name} failed: {e}")))
}

/// Derive LogStatus from the two log read results.
fn build_parser_log_status(
    log1: &Result<(Vec<u8>, bool)>,
    log2: &Result<(Vec<u8>, bool)>,
) -> LogStatus {
    match (log1.is_ok(), log2.is_ok()) {
        (false, false) => LogStatus::NotFound,
        _ => LogStatus::Applied,
    }
}

/// Build a notatin Parser from in-memory primary + optional log bytes via from_file.
/// IMPLEMENTER: confirm ParserBuilder::from_file / with_transaction_log / build chain
/// against the installed notatin source (docs.rs: from_file<R: ReadSeek>,
/// with_transaction_log<T: ReadSeek>, recover_deleted(bool), build()).
fn build_parser(
    primary: Vec<u8>,
    log1: Option<Vec<u8>>,
    log2: Option<Vec<u8>>,
) -> Result<notatin::parser::Parser> {
    use notatin::parser_builder::ParserBuilder;
    use std::io::Cursor;

    let mut builder = ParserBuilder::from_file(Cursor::new(primary));
    builder.recover_deleted(false);
    if let Some(b) = log1 {
        builder.with_transaction_log(Cursor::new(b));
    }
    if let Some(b) = log2 {
        builder.with_transaction_log(Cursor::new(b));
    }
    builder
        .build()
        .map_err(|e| hive_err(format!("notatin build failed: {e}")))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors hive_reader`
Expected: PASS (4 tests incl. `open_hive_short_reader_is_err_not_panic`). If the ntfs short-reader path panics in a way catch_unwind doesn't catch on this platform, report — but usn/mft prove it is caught.

- [ ] **Step 5: Clippy + commit**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`

```bash
git add crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(hive): open_hive raw-volume locate + notatin build, catch_unwind guarded

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: shimcache — parse_appcompatcache pure parser (the correctness core)

The version-aware AppCompatCache blob parser. Pure, no I/O, never-panic — this is where shimcache correctness lives (CI cannot read a real hive). Bounds-checked readers in the style of `parse_usn_record`.

**Authoritative Win10+ layout** (header 0x34 bytes; entries from offset 0x34; per-entry):

| within-entry offset | size | field |
|---|---|---|
| 0 | 4 | signature `"10ts"` = `31 30 74 73` |
| 4 | 4 | unknown |
| 8 | 4 | entry data size (bytes that FOLLOW this field) |
| 12 | 2 | path length (bytes, UTF-16LE) |
| 14 | path_len | path (UTF-16LE) |
| 14+path_len | 8 | last-modified FILETIME (u64 LE) |
| 14+path_len+8 | 4 | data length |
| ... | data_len | data (last 4 bytes == 01 00 00 00 → executed) |

**Files:**
- Modify: `crates/cairn-collectors/src/shimcache.rs`

- [ ] **Step 1: Write failing tests with a synthetic builder**

Append to `shimcache.rs`:

```rust
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

    // FILETIME for 2021-01-01T00:00:00Z = 132_539_904_000_000_000.
    const FT_2021: u64 = 132_539_904_000_000_000;

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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p cairn-collectors shimcache`
Expected: FAIL (`parse_appcompatcache`, `ShimVersion`, `ShimEntry` not defined).

- [ ] **Step 3: Implement the pure parser**

Add to `shimcache.rs` (after the module doc, before tests):

```rust
use chrono::{DateTime, Utc};
use cairn_core::time::filetime_to_utc;

/// AppCompatCache key/value location. ControlSet001, NOT CurrentControlSet — the
/// latter is a runtime symlink absent from an offline hive.
pub(crate) const SHIMCACHE_KEY: &str =
    r"ControlSet001\Control\Session Manager\AppCompatCache";
pub(crate) const SHIMCACHE_VALUE: &str = "AppCompatCache";

/// Win10+ header is 0x34 bytes; the 32-bit value at offset 0 equals 0x34.
const WIN10PLUS_HEADER_LEN: usize = 0x34;
/// Per-entry signature for Win8.1+/Win10/Win11 cache entries.
const ENTRY_SIG: &[u8; 4] = b"10ts";

/// One AppCompatCache entry (pure data).
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
    while pos + 14 <= buf.len() {
        // signature check
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
        let last_modified = rd_u64(buf, ft_off)
            .and_then(|ft| filetime_to_utc(ft).ok());

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
```

> IMPLEMENTER: `filetime_to_utc` is `cairn_core::time::filetime_to_utc` (used by usn/mft). Confirm its signature (`fn filetime_to_utc(ft: u64) -> Result<DateTime<Utc>, _>`). If a FILETIME of 0 should map to None rather than the FILETIME epoch, the `.ok()` already drops parse errors; verify 0 is handled sanely.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors shimcache`
Expected: PASS (5 tests).

- [ ] **Step 5: Clippy + commit**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`

```bash
git add crates/cairn-collectors/src/shimcache.rs
git commit -m "feat(shimcache): version-aware AppCompatCache pure parser (Win10+)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: shimcache — ShimCollector (privilege gate, wire primitive → Record::Execution)

The Collector: privilege-gated, opens the volume, reads SYSTEM hive via hive_reader, parses AppCompatCache, emits `Record::Execution`. Mirrors `UsnCollector` (gate before open, AtomicU64 abstain flag, `sources()`).

**Files:**
- Modify: `crates/cairn-collectors/src/shimcache.rs`

- [ ] **Step 1: Write failing tests (no-I/O collector surface)**

Add to the `tests` mod in `shimcache.rs`:

```rust
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::CairnError;
    use cairn_core::config::Config;
    use std::sync::atomic::Ordering;

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = ShimCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_shimcache() {
        assert_eq!(ShimCollector::default().name(), "shimcache");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = ShimCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "shimcache");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_abstain() {
        let c = ShimCollector::default();
        c.abstained.store(1, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0].errors.iter().any(|e| e.contains("abstain")));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p cairn-collectors shimcache`
Expected: FAIL (`ShimCollector` not defined).

- [ ] **Step 3: Implement ShimCollector**

Add to `shimcache.rs` (after the parser, before tests). Note the imports at the top of the file must gain the collector deps:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use crate::hive_reader::{get_value_bytes, open_hive, LogStatus, SYSTEM_HIVE};
```

```rust
/// ShimCollector: privilege-gated, read-only AppCompatCache read from SYSTEM hive.
/// Requires Administrator + SeBackupPrivilege (raw \\.\C: open). Emits
/// Record::Execution (source="shimcache", execution_confirmed reflects the data flag).
#[derive(Default)]
pub struct ShimCollector {
    /// 0 = clean; 1 = abstained (unknown version / truncated hive / parse gave nothing
    /// usable) — surfaced via sources() so the manifest is honest (NFR12).
    abstained: AtomicU64,
}

impl Collector for ShimCollector {
    fn name(&self) -> &str {
        "shimcache"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors usn/mft).
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "shimcache".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let mut opened = open_hive(&mut reader, &SYSTEM_HIVE)?;

        if opened.truncated {
            // Hive exceeded the memory ceiling — abstain rather than parse a partial.
            self.abstained.store(1, Ordering::Relaxed);
            tracing::warn!("shimcache: SYSTEM hive exceeded ceiling; abstaining");
            return Ok(Vec::new());
        }
        if let LogStatus::Failed(reason) = &opened.log_status {
            tracing::warn!(reason = %reason, "shimcache: log replay failed; primary-only");
        }

        let bytes = match get_value_bytes(&mut opened.parser, SHIMCACHE_KEY, SHIMCACHE_VALUE)? {
            Some((b, _last_write)) => b,
            None => {
                tracing::info!("shimcache: AppCompatCache value absent");
                return Ok(Vec::new());
            }
        };

        let (version, entries) = parse_appcompatcache(&bytes);
        if let ShimVersion::Unknown(magic) = version {
            self.abstained.store(1, Ordering::Relaxed);
            tracing::warn!(magic = format!("{magic:#x}"), "shimcache: unknown format; abstaining");
            return Ok(Vec::new());
        }

        let mut records: Vec<Record> = entries
            .into_iter()
            .map(|e| {
                Record::Execution(ExecutionRecord {
                    source: "shimcache".into(),
                    path: e.path,
                    // shimcache last_modified is a FILE mtime, NOT an exec time, so it
                    // must NOT go in first_run/last_run (NFR12 honesty). ExecutionRecord
                    // has no "file mtime" field, so e.last_modified is intentionally
                    // dropped at the Record layer this segment. KNOWN LIMITATION: the
                    // mtime is real evidence; surfacing it belongs to the downstream
                    // Finding/analyzer layer (timeline ts is projected from Finding, not
                    // Record — see cairn-report timeline_row) or a future schema field.
                    // Lying it into last_run would be worse than omitting it.
                    first_run: None,
                    last_run: None,
                    run_count: None,
                    sha1: None,
                    user_sid: None,
                    execution_confirmed: Some(e.executed),
                })
            })
            .collect();
        // Determinism (NFR4): sort by path (entries carry no record_id).
        records.sort_by(|a, b| record_sort_key(a).cmp(record_sort_key(b)));

        tracing::info!(shim_entries = records.len(), "shimcache scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.abstained.load(Ordering::Relaxed) > 0 {
            errors.push("abstained: unknown format or hive exceeded ceiling".to_string());
        }
        vec![SourceEntry {
            artifact: "shimcache".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

/// Stable sort key: the Execution path (shimcache records have no native ts/id).
fn record_sort_key(r: &Record) -> &str {
    match r {
        Record::Execution(e) => &e.path,
        _ => "",
    }
}
```

> IMPLEMENTER: confirm `CollectCtx`, `Collector::sources()`, `SourceEntry` field names against the installed `cairn_core` (they match usn.rs exactly as of cd6e9d4). If `ExecutionRecord` gained/lost a field, align the struct literal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors`
Expected: PASS (all hive_reader + shimcache tests).

- [ ] **Step 5: Clippy + commit**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`

```bash
git add crates/cairn-collectors/src/shimcache.rs
git commit -m "feat(shimcache): ShimCollector wires hive_reader -> Record::Execution

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Wire shimcache into selection + CLI

Register "shimcache" as a raw-NTFS collector so `--profile minimal` skips it, and construct it in the live run.

**Files:**
- Modify: `crates/cairn-core/src/selection.rs:34` (and add a test)
- Modify: `crates/cairn-cli/src/main.rs` (AVAILABLE, construction, built_collector_names, test)

- [ ] **Step 1: Write the failing selection test**

In `crates/cairn-core/src/selection.rs`, in the `tests` mod (after `minimal_excludes_usn`), add:

```rust
    #[test]
    fn minimal_excludes_shimcache() {
        let available = vec!["proc", "net", "persist", "mft", "usn", "shimcache"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]); // no raw-NTFS
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p cairn-core minimal_excludes_shimcache`
Expected: FAIL (shimcache still selected because it's not in RAW_NTFS).

- [ ] **Step 3: Add shimcache to RAW_NTFS**

In `crates/cairn-core/src/selection.rs:34`, change:

```rust
const RAW_NTFS: &[&str] = &["mft", "usn"];
```
to:
```rust
const RAW_NTFS: &[&str] = &["mft", "usn", "shimcache"];
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p cairn-core`
Expected: PASS.

- [ ] **Step 5: Update CLI AVAILABLE + construction + test helper**

In `crates/cairn-cli/src/main.rs`:

(a) `built_collector_names` helper array (around line 278):
```rust
    ["proc", "net", "persist", "mft", "usn", "shimcache"]
```

(b) `AVAILABLE` const in the run block (around line 623):
```rust
            const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft", "usn", "shimcache"];
```

(c) construction block (after the `usn` block, around line 692):
```rust
            if selection.selected.iter().any(|m| m == "shimcache") {
                collectors.push(Box::new(
                    cairn_collectors::shimcache::ShimCollector::default(),
                ));
            }
```

(d) `AVAILABLE` const in `selected_collector_names_follow_selection` test (around line 884):
```rust
        const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft", "usn", "shimcache"];
```

(e) the exact-vector assertion in that test (around line 895):
```rust
        assert_eq!(built, vec!["proc", "net", "persist", "mft", "usn", "shimcache"]);
```

(f) add shimcache assertions at the end of that test (after the usn block, line ~915):
```rust
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"shimcache".to_string()), "standard includes shimcache");
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"shimcache".to_string()), "minimal skips shimcache");
```

- [ ] **Step 6: Run the whole workspace test suite**

Run: `cargo test --workspace`
Expected: PASS (catches any cross-crate breakage, e.g. report test helpers — the governance lesson).

- [ ] **Step 7: Clippy (all-targets) + commit**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

```bash
git add crates/cairn-core/src/selection.rs crates/cairn-cli/src/main.rs
git commit -m "feat(shimcache): wire into selection (RAW_NTFS) + CLI live run

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Elevated end-to-end test (#[ignore], manual on real host)

A smoke test proving the whole chain works against the real local SYSTEM hive. `#[ignore]` so CI never runs it (needs admin+SeBackup); run manually with `cargo test -- --ignored`.

**Files:**
- Modify: `crates/cairn-collectors/src/shimcache.rs` (test mod)

- [ ] **Step 1: Add the ignored e2e test**

Add to the `tests` mod in `shimcache.rs`:

```rust
    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors -- --ignored shimcache_e2e
    /// Proves the full chain: raw \\.\C: -> ntfs locate SYSTEM -> notatin parse
    /// (+ log replay) -> AppCompatCache -> Record::Execution. Mirrors usn elevated_e2e.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn shimcache_e2e_real_system_hive() {
        let cfg = cairn_core::config::Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        let recs = ShimCollector::default()
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        assert!(!recs.is_empty(), "expected at least one shimcache entry");
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "shimcache");
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert!(e.last_run.is_none(), "shimcache must not claim a last_run");
            } else {
                panic!("shimcache must only emit Execution records");
            }
        }
    }
```

- [ ] **Step 2: Verify it compiles and is ignored by default**

Run: `cargo test -p cairn-collectors`
Expected: PASS; output shows `shimcache_e2e_real_system_hive ... ignored`.

- [ ] **Step 3: Final workspace gate**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all clean. (`cargo fmt` then re-add if it reformats.)

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-collectors/src/shimcache.rs
git commit -m "test(shimcache): #[ignore] elevated e2e against real SYSTEM hive

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Definition of done (whole segment)

- `cargo check --workspace` / `cargo test --workspace` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo fmt --check` all clean.
- `#![forbid(unsafe_code)]` still present in `cairn-collectors` (zero new unsafe).
- `Cargo.lock` committed; only notatin + its (default-features-off) transitive deps added; `cargo audit` clean.
- No schema change (ExecutionRecord reused).
- Golden rules intact: read-only raw access, no temp files, no host writes, `--dry-run` unaffected, graceful degrade on every failure, never-panic (catch_unwind + bounds-checked parser), UTC RFC3339, determinism (sorted output).
- The two implementer-verification points (notatin CellValue→bytes, AppCompatCache magic/0x34) confirmed against installed source during Tasks 2–4.
