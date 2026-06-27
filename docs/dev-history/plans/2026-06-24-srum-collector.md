# srum_collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `SrumCollector` that reads `SRUDB.dat` via raw `\\.\C:` volume read (bypassing the OS lock), writes the bytes to a scratchpad temp file, then parses it with `srum-parser 0.1.0` to produce `Record::Execution` records for app CPU usage (`source="srum_app"`) and network byte counts (`source="srum_net"`), with ID resolution via the SRUM ID-map table.

**Architecture:** Mirrors the hive-reader pattern: `VolumeReader::open(r"\\.\C:")` → navigate NTFS to `Windows\System32\sru\SRUDB.dat` → read bytes into memory (512 MiB ceiling, NFR10) → write to a `NamedTempFile` in the system temp dir → `srum_parser::parse_app_usage(tmp.path())` + `parse_network_usage(tmp.path())` + `parse_id_map(tmp.path())` → resolve `app_id`→app name via ID map → emit `Record::Execution`. The temp file is deleted when `NamedTempFile` drops (RAII). Schema zero-change: net bytes go into `reason` as `"bytes_sent=N bytes_recv=N"`.

**Tech Stack:** `srum-parser 0.1.0` (MIT, pure Rust, no unsafe in library code itself), `ese-core 0.1.0` (MIT, uses `memmap2` internally — equivalent to `notatin`/`zip`/`age` pattern), `tempfile 3` (already a dev-dep of `srum-parser`; add as runtime dep to `cairn-collectors`), existing `VolumeReader` + NTFS navigation from `hive_reader.rs`.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `Cargo.toml` (workspace root) | Modify | Add `srum-parser`, `tempfile` workspace deps |
| `crates/cairn-collectors/Cargo.toml` | Modify | Pull workspace deps into cairn-collectors |
| `crates/cairn-collectors/src/srum.rs` | Create | `SrumCollector` + all parsing/mapping logic |
| `crates/cairn-collectors/src/lib.rs` | Modify | `pub mod srum;` |
| `crates/cairn-core/src/selection.rs` | Modify | Add `"srum"` to `HEAVY_OFFLINE` |
| `crates/cairn-cli/src/main.rs` | Modify | Add `"srum"` to `AVAILABLE`, construct `SrumCollector`, wire `sources()` |

---

## Task T1 — Workspace deps: srum-parser + tempfile

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/cairn-collectors/Cargo.toml`

- [ ] **Step 1: Add workspace deps to root `Cargo.toml`**

Open `Cargo.toml` (workspace root). In the `[workspace.dependencies]` section, after the `age` entry, add:

```toml
srum-parser = { version = "0.1.0", default-features = false }  # FR12 srum (cairn-collectors only)
tempfile    = { version = "3",     default-features = false }   # srum scratchpad temp file (cairn-collectors only)
```

- [ ] **Step 2: Wire deps into cairn-collectors**

Open `crates/cairn-collectors/Cargo.toml`. In `[dependencies]`, after `compcol`, add:

```toml
srum-parser.workspace = true
tempfile.workspace    = true
```

- [ ] **Step 3: Verify compilation**

```bash
cargo check -p cairn-collectors 2>&1
```

Expected: compiles with no errors. (No new code yet, just deps.)

- [ ] **Step 4: Check audit**

```bash
cargo audit 2>&1
```

Expected: only existing ignored advisories (RUSTSEC-2021-0153, RUSTSEC-2024-0436, RUSTSEC-2026-0173). If any new advisory from `ese-core`/`srum-parser`/`tempfile`, evaluate and add to `.cargo/audit.toml` ignore list with justification comment matching existing format.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/cairn-collectors/Cargo.toml Cargo.lock .cargo/audit.toml
git commit -m "deps(collectors): add srum-parser 0.1.0 + tempfile 3 for srum_collector (FR12)"
```

---

## Task T2 — Pure parsing functions (no I/O, unit-testable on any platform)

**Files:**
- Create: `crates/cairn-collectors/src/srum.rs`

These functions have zero host interaction: they take slices/paths and return Results. Write tests first.

- [ ] **Step 1: Write failing tests for ID-map resolution**

Create `crates/cairn-collectors/src/srum.rs` with only the test module:

```rust
#![forbid(unsafe_code)]

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
        assert!(map.get(&99).is_none());
    }

    #[test]
    fn net_reason_formats_bytes() {
        assert_eq!(net_reason(1024, 512), "bytes_sent=1024 bytes_recv=512");
    }
}
```

- [ ] **Step 2: Run test to confirm failure**

```bash
cargo test -p cairn-collectors srum 2>&1
```

Expected: compile error (functions not defined yet).

- [ ] **Step 3: Implement the pure helper functions**

Add above the `#[cfg(test)]` block:

```rust
use std::collections::HashMap;

use srum_core::IdMapEntry;

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
pub(crate) fn net_reason(bytes_sent: u64, bytes_recv: u64) -> String {
    format!("bytes_sent={bytes_sent} bytes_recv={bytes_recv}")
}
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
cargo test -p cairn-collectors srum 2>&1
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors/src/srum.rs
git commit -m "feat(srum): pure helpers build_id_map / resolve_app_name / net_reason + tests"
```

---

## Task T3 — SRUDB.dat extraction via raw volume (scratchpad temp file)

**Files:**
- Modify: `crates/cairn-collectors/src/srum.rs`

The core novelty: `srum-parser` needs a `&Path`. We read bytes from the locked SRUDB.dat using VolumeReader + NTFS navigation (same as hive_reader), then write to a `NamedTempFile`. RAII drops the file on function exit.

- [ ] **Step 1: Write failing test for SRUDB path constant**

Add to the `tests` module in `srum.rs`:

```rust
    #[test]
    fn srudb_path_components_correct() {
        assert_eq!(
            SRUDB_PATH,
            &["Windows", "System32", "sru", "SRUDB.dat"]
        );
    }
```

- [ ] **Step 2: Run test to confirm failure**

```bash
cargo test -p cairn-collectors srum::tests::srudb_path_components_correct 2>&1
```

Expected: compile error — `SRUDB_PATH` not defined.

- [ ] **Step 3: Add SRUDB_PATH constant and extract_srudb function**

Add after the existing pure helpers, before `#[cfg(test)]`:

```rust
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::{CairnError, Result};

use crate::hive_reader::{HivePath, HIVE_HARD_CEILING};

/// NTFS path components for SRUDB.dat (volume-relative, last = filename).
pub(crate) const SRUDB_PATH: &[&str] =
    &["Windows", "System32", "sru", "SRUDB.dat"];

/// Read SRUDB.dat bytes from the raw volume into a NamedTempFile.
///
/// Returns (tempfile, truncated). Caller must keep the NamedTempFile alive
/// for the duration of parsing; it is deleted on drop (RAII).
///
/// 512 MiB ceiling (NFR10): SRUDB.dat on production hosts is typically
/// 10–200 MiB. Exceeding the ceiling sets `truncated=true` and the collector
/// abstains (NFR12).
pub(crate) fn extract_srudb(
    reader: &mut VolumeReader,
    truncated_flag: &AtomicBool,
) -> Result<tempfile::NamedTempFile> {
    use ntfs::Ntfs;

    // Build the HivePath-equivalent for SRUDB.dat navigation.
    let hive = HivePath {
        components: SRUDB_PATH.iter().map(|s| s.to_string()).collect(),
    };

    let mut ntfs = Ntfs::new(reader)
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("Ntfs::new: {e}") })?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("read_upcase_table: {e}") })?;
    let root = ntfs.root_directory(reader)
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("root_directory: {e}") })?;

    // Walk dir components to reach the sru\ directory.
    let (file_name, dir_components) = hive.components.split_last()
        .ok_or_else(|| CairnError::Collector { collector: "srum".into(), reason: "empty path".into() })?;

    let mut cur = root;
    for comp in dir_components {
        cur = crate::hive_reader::find_child_dir_pub(&ntfs, reader, &cur, comp.as_str())?;
    }

    // Read the SRUDB.dat file via its default $DATA stream (same as hive_reader).
    let file = crate::hive_reader::find_child_file_pub(&ntfs, reader, &cur, file_name.as_str())?;
    let data_item = file.data(reader, "")
        .ok_or_else(|| CairnError::Collector { collector: "srum".into(), reason: "SRUDB.dat: no default data stream".into() })?
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("SRUDB.dat data attr: {e}") })?;
    let attr = data_item.to_attribute()
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("SRUDB.dat to_attribute: {e}") })?;
    let value = attr.value(reader)
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("SRUDB.dat value: {e}") })?;

    use std::io::Read as _;
    let mut attached = value.attach(reader);
    let mut buf = Vec::new();
    let n = attached
        .by_ref()
        .take(HIVE_HARD_CEILING)
        .read_to_end(&mut buf)
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("SRUDB.dat read: {e}") })?;

    if n as u64 == HIVE_HARD_CEILING {
        truncated_flag.store(true, Ordering::Relaxed);
        return Err(CairnError::Collector {
            collector: "srum".into(),
            reason: "SRUDB.dat exceeded 512 MiB ceiling (NFR10); abstained".into(),
        });
    }

    // Write bytes to a NamedTempFile. The file is in the system temp dir (off-target,
    // golden rule 4). It is deleted automatically when the returned value drops.
    let mut tmp = tempfile::NamedTempFile::new()
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("tempfile::new: {e}") })?;
    tmp.write_all(&buf)
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("tempfile write: {e}") })?;
    tmp.flush()
        .map_err(|e| CairnError::Collector { collector: "srum".into(), reason: format!("tempfile flush: {e}") })?;

    Ok(tmp)
}
```

**Note:** `find_child_dir_pub` and `find_child_file_pub` are new `pub(crate)` wrappers we add to `hive_reader.rs` in this task (see step 4). Currently `find_child_dir` in hive_reader is `fn` (private to the module). We need to expose two narrowly-scoped helpers.

- [ ] **Step 4: Expose find_child_dir and find_child_file as pub(crate) in hive_reader.rs**

Open `crates/cairn-collectors/src/hive_reader.rs`. Find the existing `fn find_child_dir` (currently private). Add two new `pub(crate)` wrapper functions immediately after its definition:

```rust
/// pub(crate) wrapper so srum_collector can reuse the same NTFS navigation
/// without duplicating the find logic. Mirrors find_child_dir semantics exactly.
pub(crate) fn find_child_dir_pub<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    parent: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    find_child_dir(ntfs, reader, parent, name)
}

/// pub(crate) wrapper to locate a regular file (not directory) inside a directory.
/// Used by srum_collector to get SRUDB.dat as an NtfsFile, then read its $DATA stream.
pub(crate) fn find_child_file_pub<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    parent: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    use ntfs::NtfsReadAt;
    // find_child_dir locates any child by name; for SRUDB.dat (which IS a regular file)
    // we use the same index walk. The NTFS index entries carry all file types, not just
    // directories — the "dir" in find_child_dir means "look inside a directory index",
    // not "return only directory entries".
    find_child_dir(ntfs, reader, parent, name)
}
```

- [ ] **Step 5: Run test to confirm SRUDB_PATH passes; compile check**

```bash
cargo test -p cairn-collectors srum::tests::srudb_path 2>&1
cargo check -p cairn-collectors 2>&1
```

Expected: 1 test passes, no compile errors.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/srum.rs crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(srum): extract_srudb via raw volume + NamedTempFile scratchpad; pub(crate) NTFS nav wrappers"
```

---

## Task T4 — SrumCollector struct + collect() + sources()

**Files:**
- Modify: `crates/cairn-collectors/src/srum.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`

- [ ] **Step 1: Write failing test for collector name**

Add to `tests` module in `srum.rs`:

```rust
    #[test]
    fn collector_name_is_srum() {
        use cairn_core::traits::Collector;
        let c = super::SrumCollector::default();
        assert_eq!(c.name(), "srum");
    }
```

- [ ] **Step 2: Run to confirm failure**

```bash
cargo test -p cairn-collectors srum::tests::collector_name 2>&1
```

Expected: compile error — `SrumCollector` not defined.

- [ ] **Step 3: Implement SrumCollector**

Add the following before `pub(crate) const SRUDB_PATH` (or near the top of srum.rs after imports):

```rust
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};

/// SrumCollector: raw-volume read of SRUDB.dat → scratchpad temp file →
/// srum-parser → Record::Execution (source="srum_app" and "srum_net").
/// Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
#[derive(Default)]
pub struct SrumCollector {
    /// SRUDB.dat exceeded the 512 MiB ceiling; parse abstained (NFR10/NFR12).
    truncated: AtomicBool,
    /// SRUDB.dat not found at expected path (build variance — abstained). NFR12.
    db_absent: AtomicBool,
    /// ID-map table absent or parse failed; app names fall back to "id:<n>".
    id_map_failed: AtomicBool,
    /// One or more app_usage or net_usage records failed to parse; rest collected.
    entry_read_errors: AtomicBool,
}

impl Collector for SrumCollector {
    fn name(&self) -> &str {
        "srum"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate: SRUDB.dat is OS-locked, needs raw volume read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "srum".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;

        // Extract SRUDB.dat to a temp file. On any I/O error, mark db_absent and abstain.
        let tmp = match extract_srudb(&mut reader, &self.truncated) {
            Ok(t) => t,
            Err(e) => {
                // truncated flag already set if that was the cause; otherwise db_absent.
                if !self.truncated.load(Ordering::Relaxed) {
                    self.db_absent.store(true, Ordering::Relaxed);
                    tracing::warn!(reason = %e, "srum: SRUDB.dat extraction failed; abstaining");
                }
                return Ok(vec![]);
            }
        };

        let db_path = tmp.path();

        // Build ID map first (best-effort; failures degrade to "id:<n>" fallback).
        let id_map = match srum_parser::parse_id_map(db_path) {
            Ok(entries) => build_id_map(entries),
            Err(e) => {
                self.id_map_failed.store(true, Ordering::Relaxed);
                tracing::warn!(reason = %e, "srum: ID map parse failed; app names will be id:<n>");
                HashMap::new()
            }
        };

        let mut records: Vec<Record> = Vec::new();

        // --- App usage (CPU cycles) → source="srum_app" ---
        match srum_parser::parse_app_usage(db_path) {
            Ok(rows) => {
                for row in rows {
                    let app_name = resolve_app_name(row.app_id, &id_map);
                    records.push(Record::Execution(ExecutionRecord {
                        source: "srum_app".into(),
                        path: app_name,
                        ts: row.timestamp,
                        run_count: None,
                        first_run: None,
                        last_run: Some(row.timestamp),
                        execution_confirmed: Some(true),
                        sha1: None,
                        user_sid: None,
                        reason: Some(format!(
                            "fg_cycles={} bg_cycles={}",
                            row.foreground_cycles, row.background_cycles
                        )),
                    }));
                }
            }
            Err(e) => {
                self.entry_read_errors.store(true, Ordering::Relaxed);
                tracing::warn!(reason = %e, "srum: app_usage parse error; partial result");
            }
        }

        // --- Network usage (bytes) → source="srum_net" ---
        match srum_parser::parse_network_usage(db_path) {
            Ok(rows) => {
                for row in rows {
                    let app_name = resolve_app_name(row.app_id, &id_map);
                    records.push(Record::Execution(ExecutionRecord {
                        source: "srum_net".into(),
                        path: app_name,
                        ts: row.timestamp,
                        run_count: None,
                        first_run: None,
                        last_run: Some(row.timestamp),
                        execution_confirmed: Some(true),
                        sha1: None,
                        user_sid: None,
                        reason: Some(net_reason(row.bytes_sent, row.bytes_recv)),
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
            name: "srum".into(),
            path: r"C:\Windows\System32\sru\SRUDB.dat".into(),
            record_count: None,
            errors,
        }]
    }
}
```

- [ ] **Step 4: Add `pub mod srum;` to lib.rs**

Open `crates/cairn-collectors/src/lib.rs`. After the last `pub mod` line, add:

```rust
pub mod srum;
```

- [ ] **Step 5: Run tests; check compilation**

```bash
cargo test -p cairn-collectors srum 2>&1
cargo check --workspace 2>&1
```

Expected: all srum tests pass, workspace compiles.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/srum.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(srum): SrumCollector + collect() + sources() (srum_app + srum_net records)"
```

---

## Task T5 — Selection + CLI wiring + `#[ignore]` elevated e2e

**Files:**
- Modify: `crates/cairn-core/src/selection.rs`
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: Add "srum" to HEAVY_OFFLINE in selection.rs**

Open `crates/cairn-core/src/selection.rs`. Find `const HEAVY_OFFLINE`:

```rust
const HEAVY_OFFLINE: &[&str] = &[
    "mft",
    "usn",
    "shimcache",
    "amcache",
    "prefetch",
    "bam",
    "userassist",
];
```

Change to:

```rust
const HEAVY_OFFLINE: &[&str] = &[
    "mft",
    "usn",
    "shimcache",
    "amcache",
    "prefetch",
    "bam",
    "userassist",
    "srum",
];
```

- [ ] **Step 2: Write failing test for srum in selection**

Add to the `tests` module in `selection.rs`:

```rust
    #[test]
    fn minimal_excludes_srum() {
        let available = vec![
            "proc", "net", "persist", "mft", "usn",
            "shimcache", "amcache", "prefetch", "bam", "userassist", "srum",
        ];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"srum".to_string()));
    }
```

- [ ] **Step 3: Run test**

```bash
cargo test -p cairn-core minimal_excludes_srum 2>&1
```

Expected: PASS (HEAVY_OFFLINE already updated in step 1).

- [ ] **Step 4: Wire SrumCollector into main.rs**

Open `crates/cairn-cli/src/main.rs`.

**4a.** Find `const AVAILABLE: &[&str] = &[` (there are two — one at ~line 662 for the live run, one at ~line 968 for tests). Add `"srum"` to BOTH lists, after `"userassist"`:

```rust
// In the live-run AVAILABLE (around line 672):
const AVAILABLE: &[&str] = &[
    "proc", "net", "persist", "mft", "usn",
    "shimcache", "amcache", "prefetch", "bam", "userassist", "srum",
];
```

```rust
// In the test AVAILABLE (around line 968):
const AVAILABLE: &[&str] = &[
    "proc", "net", "persist", "mft", "usn",
    "shimcache", "amcache", "prefetch", "bam", "userassist", "srum",
];
```

**4b.** Find the collector construction block (around line 777 where userassist is constructed). Add after the userassist block:

```rust
            if selection.selected.iter().any(|m| m == "srum") {
                collectors.push(Box::new(cairn_collectors::srum::SrumCollector::default()));
            }
```

- [ ] **Step 5: Add `#[ignore]` elevated e2e test**

Add at the bottom of `srum.rs` in the `#[cfg(test)]` block:

```rust
    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors srum::tests::elevated_e2e_srum -- --ignored
    /// Verifies:
    ///   - SRUDB.dat is reachable via raw volume
    ///   - at least one srum_app and one srum_net record is produced
    ///   - sources errors are empty (no abstain, no partial)
    ///   - all records have source="srum_app" or "srum_net"
    ///   - temp file is deleted after collect() returns
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    #[test]
    fn elevated_e2e_srum() {
        use cairn_core::traits::{CollectCtx, Collector};
        use cairn_core::record::Record;

        let c = SrumCollector::default();
        let ctx = CollectCtx { admin: true, se_backup: true, config: &Default::default() };
        let records = c.collect(&ctx).expect("collect must not error on real host");

        assert!(
            !records.is_empty(),
            "expected at least one SRUM record on a real Win host"
        );
        let app_count = records.iter().filter(|r| {
            matches!(r, Record::Execution(e) if e.source == "srum_app")
        }).count();
        let net_count = records.iter().filter(|r| {
            matches!(r, Record::Execution(e) if e.source == "srum_net")
        }).count();
        assert!(app_count > 0, "expected srum_app records; got {app_count}");
        assert!(net_count > 0, "expected srum_net records; got {net_count}");

        let sources = c.sources();
        assert_eq!(sources.len(), 1);
        assert!(
            sources[0].errors.is_empty(),
            "sources errors must be empty on real host: {:?}",
            sources[0].errors
        );
    }
```

- [ ] **Step 6: Run full workspace tests + clippy**

```bash
cargo test --workspace 2>&1
cargo clippy --workspace --all-targets -- -D warnings 2>&1
```

Expected: all non-ignored tests pass, no clippy warnings. The `elevated_e2e_srum` test is skipped (ignored).

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-core/src/selection.rs crates/cairn-cli/src/main.rs crates/cairn-collectors/src/srum.rs
git commit -m "feat(srum): wire SrumCollector into AVAILABLE + selection + CLI; #[ignore] e2e test (FR12)"
```

---

## Self-Review

**Spec coverage check:**

| SRS requirement | Covered by |
|---|---|
| FR12: SRUDB.dat (ESE) → Record::Execution | T4 SrumCollector.collect() |
| FR12: per-app/user resource | T4: srum_app source, fg/bg_cycles in reason |
| FR12: net bytes | T4: srum_net source, bytes_sent/recv in reason |
| NFR10: 512 MiB ceiling | T3: extract_srudb HIVE_HARD_CEILING check |
| NFR12: abstain if absent/truncated | T4: db_absent / truncated flags + sources() |
| NFR12: partial if some records fail | T4: entry_read_errors flag + sources() |
| Golden rule 3: no host modification | temp file in system temp (off-target), VolumeReader read-only |
| Golden rule 4: no target writes | NamedTempFile in system temp, not in output dir |
| Golden rule 8: graceful degrade | each parse error → flag + continue, not abort |
| Minimal profile excludes srum | T5: HEAVY_OFFLINE + selection test |
| `#![forbid(unsafe_code)]` | T4: top of srum.rs; srum-parser itself has no unsafe |

**Placeholder scan:** None found.

**Type consistency:**
- `SrumCollector` defined in T4, referenced in T5 ✓
- `extract_srudb` defined in T3, called in T4 ✓
- `build_id_map` / `resolve_app_name` / `net_reason` defined in T2, used in T4 ✓
- `find_child_dir_pub` / `find_child_file_pub` defined in T3 (hive_reader.rs), used in T3 (srum.rs) ✓
- `SRUDB_PATH` defined in T3, tested in T3 ✓
- `ExecutionRecord` fields (`source`, `path`, `ts`, `run_count`, `first_run`, `last_run`, `execution_confirmed`, `sha1`, `user_sid`, `reason`) — match existing schema in `cairn-core/src/record.rs` ✓
