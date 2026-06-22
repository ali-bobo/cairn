# BAM Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse the SYSTEM hive's Background Activity Moderator (bam) UserSettings into per-SID `Record::Execution` with a real last-execution time, reusing the hive_reader foundation plus one new `list_values` primitive.

**Architecture:** A new `list_values` primitive on hive_reader (enumerate ALL values of a key, returning `KeyValue{name,data}`) using notatin's verified `value_iter()`. A `BamCollector` in `cairn-collectors` that, gated on admin+SeBackup, raw-reads the SYSTEM hive via the existing `open_hive`, resolves the active ControlSet from `Select\Current`, enumerates `{ControlSet}\Services\bam\State\UserSettings\<SID>`, and maps each value (NT exe path + leading 8-byte FILETIME) to a `Record::Execution`. Four AtomicBool flags surface abstain/partial states. Wired into selection (HEAVY_OFFLINE) and the CLI like amcache/prefetch.

**Tech Stack:** Rust, notatin 1.0.1 (hive parse), `cairn-collectors-win::VolumeReader` (raw `\\.\C:`), chrono. `#![forbid(unsafe_code)]` kept in cairn-collectors. Zero new dependency, zero schema change.

**Authoritative spec:** `docs/superpowers/specs/2026-06-22-bam-collector-design.md`

**Build/test env:** `CARGO_TARGET_DIR` is set OUT of the OneDrive tree (machine config). Run all cargo commands from the repo root `cairn/`. Local clippy MUST use `--all-targets` (matches CI).

---

## File Structure

- `crates/cairn-collectors/src/hive_reader.rs` (MODIFY) — add `KeyValue` type + `list_values` primitive. Mirrors the existing `SubKey`/`list_subkeys` pair.
- `crates/cairn-collectors/src/bam.rs` (CREATE) — the `BamCollector` + pure helpers `parse_bam_value` and `resolve_controlset`.
- `crates/cairn-collectors/src/lib.rs` (MODIFY) — `pub mod bam;`.
- `crates/cairn-core/src/selection.rs` (MODIFY) — add `"bam"` to `HEAVY_OFFLINE` + one `minimal_excludes_bam` test.
- `crates/cairn-cli/src/main.rs` (MODIFY) — add `"bam"` to the two `AVAILABLE` arrays + `built_collector_names` list (+ doc/count), a selection-gated push block, and a wiring test assertion.

---

## Task 1: hive_reader `list_values` primitive + `KeyValue` type

**Files:**
- Modify: `crates/cairn-collectors/src/hive_reader.rs`

**Context for the engineer:** hive_reader already has `SubKey{name,last_write}` + `list_subkeys` (enumerate child KEYS) and `get_value_bytes`/`get_value_string` (read ONE named value). bam needs to enumerate ALL VALUES of a key (each value = one executable). The notatin API is verified from source: `CellKeyNode::value_iter()` yields `CellKeyValue` (owned, no lifetime); `CellKeyValue` has public `value_name: String` and `get_content() -> (CellValue, _)` — take `.0`, match `CellValue::Binary(b)`. Non-binary values are skipped. notatin guards its own value vector against a lying `number_of_key_values > 1<<20`, so no manual pre-alloc cap is needed (unlike list_subkeys, which uses index-based access). `get_key` is `&mut` (notatin's lazy cursor).

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `hive_reader.rs`:

```rust
    #[test]
    fn keyvalue_holds_name_and_data() {
        let kv = KeyValue {
            name: r"\Device\HarddiskVolume3\Windows\notepad.exe".into(),
            data: vec![1u8, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(kv.name, r"\Device\HarddiskVolume3\Windows\notepad.exe");
        assert_eq!(kv.data.len(), 8);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-collectors hive_reader::tests::keyvalue_holds_name_and_data`
Expected: FAIL — `cannot find type KeyValue in this scope` (compile error).

- [ ] **Step 3: Add the `KeyValue` type**

Insert after the `SubKey` definition (after its closing `}`, around line 57):

```rust
/// One enumerated value: its name and raw REG_BINARY bytes. hive_reader's OWN pure type
/// (mirrors SubKey) — it deliberately does NOT expose notatin's CellKeyValue, so a
/// notatin upgrade cannot break consumers. Non-binary values are not represented here
/// (list_values skips them).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeyValue {
    pub name: String,
    pub data: Vec<u8>,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p cairn-collectors hive_reader::tests::keyvalue_holds_name_and_data`
Expected: PASS.

- [ ] **Step 5: Add the `list_values` primitive**

Insert after `list_subkeys` (after its closing `}` and the `SUBKEY_PREALLOC_CAP` const, before `get_value_string`, around line 390):

```rust
/// Enumerate ALL values of `key_path`, returning each value's name and raw REG_BINARY
/// bytes. Non-binary values (REG_SZ etc.) are skipped — bam/userassist values are all
/// REG_BINARY. Absent key => Ok(vec![]) (graceful — golden rule 8).
///
/// Order is the hive's physical value order, NOT sorted — the CALLER sorts for
/// determinism. `parser` is &mut because notatin traverses lazily (mutates state per
/// lookup). notatin guards its own value vector against a lying number_of_key_values
/// (> 1<<20 OOM guard, cell_key_node.rs), so no manual pre-alloc cap is needed here.
pub(crate) fn list_values(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
) -> Result<Vec<KeyValue>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for value in key.value_iter() {
        // get_content().0 is the CellValue; only REG_BINARY is kept (bam data is binary).
        if let notatin::cell_value::CellValue::Binary(data) = value.get_content().0 {
            out.push(KeyValue {
                name: value.value_name.clone(),
                data,
            });
        }
    }
    Ok(out)
}
```

- [ ] **Step 6: Verify compile + no clippy warnings**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`
Expected: clean (no warnings).

Note: `list_values` will show as `dead_code` until Task 4 consumes it. If clippy flags
that, add `#[allow(dead_code)]` ON `list_values` and `KeyValue` for this task ONLY, with
a `// removed in Task 4 (bam consumes it)` comment. Task 4 MUST remove both allows.

- [ ] **Step 7: Run the full crate test suite**

Run: `cargo test -p cairn-collectors`
Expected: all pass (existing tests + the new `keyvalue_holds_name_and_data`).

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(hive_reader): add list_values primitive + KeyValue type

Enumerate ALL REG_BINARY values of a key (verified notatin value_iter
API), returning hive_reader's own KeyValue{name,data} type. Mirrors the
SubKey/list_subkeys pair. Consumed by bam (next).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: pure `parse_bam_value` (leading-8-byte FILETIME)

**Files:**
- Create: `crates/cairn-collectors/src/bam.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`

**Context for the engineer:** A bam value's data is `[8-byte LE FILETIME][trailing padding/sequence]`. The forensic value is only the leading FILETIME (last-execution time). `cairn_core::time::filetime_to_utc(ft: u64) -> Option<DateTime<Utc>>` already returns None for ft==0, so a zero FILETIME (legitimate "no time" padding) naturally maps to None. We must never panic on a short buffer: use `data.get(0..8)` (Option), not slice indexing. The project convention for a known FILETIME test value is `FT_2021 = 132_539_328_000_000_000` (2021-01-01T00:00:00Z).

- [ ] **Step 1: Register the module**

In `crates/cairn-collectors/src/lib.rs`, add `pub mod bam;` in alphabetical position (before `pub mod hive_reader;`, after `pub mod amcache;`):

```rust
pub mod bam;
```

- [ ] **Step 2: Write the failing tests**

Create `crates/cairn-collectors/src/bam.rs` with ONLY the parse helper + its tests for now:

```rust
//! BamCollector: parse the SYSTEM hive's Background Activity Moderator (bam)
//! UserSettings into per-SID Record::Execution with a real last-execution time.
//!
//! bam records the last background-activity time per program per user under
//! {ControlSet}\Services\bam\State\UserSettings\<SID>. Each value's NAME is the
//! executable's NT device path; its DATA begins with an 8-byte LE FILETIME. This is
//! reached via a raw \\.\C: hive read (the live registry denies the SYSTEM-only ACL).
//! On an absent key or unrecognised structure it ABSTAINS (records the reason) rather
//! than guess (NFR12).

use chrono::{DateTime, Utc};

use cairn_core::time::filetime_to_utc;

/// Parse the last-execution time from a bam value's data: the leading 8 bytes are a
/// little-endian FILETIME. Returns None if the data is shorter than 8 bytes or the
/// FILETIME is zero (legitimate "no time" padding). Never panics (bounds-checked).
fn parse_bam_value(data: &[u8]) -> Option<DateTime<Utc>> {
    let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
    let ft = u64::from_le_bytes(bytes);
    filetime_to_utc(ft)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FILETIME for 2021-01-01T00:00:00Z (verified: 132_539_328_000_000_000).
    const FT_2021: u64 = 132_539_328_000_000_000;

    #[test]
    fn parses_valid_8_byte_filetime() {
        let data = FT_2021.to_le_bytes().to_vec();
        let got = parse_bam_value(&data).expect("valid FILETIME must parse");
        assert_eq!(got, filetime_to_utc(FT_2021).unwrap());
    }

    #[test]
    fn trailing_padding_is_ignored() {
        // 8-byte FILETIME + 16 bytes of trailing padding must parse identically.
        let mut data = FT_2021.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 16]);
        let got = parse_bam_value(&data).expect("must parse despite padding");
        assert_eq!(got, filetime_to_utc(FT_2021).unwrap());
    }

    #[test]
    fn short_data_is_none_no_panic() {
        assert_eq!(parse_bam_value(&[]), None);
        assert_eq!(parse_bam_value(&[1, 2, 3]), None);
        assert_eq!(parse_bam_value(&[0u8; 7]), None); // one byte short
    }

    #[test]
    fn all_zero_filetime_is_none() {
        // Zero FILETIME is legitimate "no time" padding, not an error.
        assert_eq!(parse_bam_value(&[0u8; 8]), None);
        assert_eq!(parse_bam_value(&[0u8; 24]), None);
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors bam::tests`
Expected: 4 tests PASS. (They pass immediately because `parse_bam_value` is written in
the same step — this is acceptable for a pure, fully-specified helper; the tests still
prove the never-panic and zero-handling contracts.)

- [ ] **Step 4: Verify no clippy warnings**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`
Expected: clean. Note: `parse_bam_value` will be `dead_code` until Task 4. If flagged,
add `#[allow(dead_code)]` on `parse_bam_value` for this task ONLY with a
`// removed in Task 4` comment; Task 4 removes it.

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors/src/bam.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(bam): pure parse_bam_value (leading-8-byte FILETIME)

Never-panic (data.get(0..8)); zero FILETIME -> None (legit padding, not
an error); trailing padding ignored. Registers the bam module.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `resolve_controlset` helper

**Files:**
- Modify: `crates/cairn-collectors/src/bam.rs`

**Context for the engineer:** In a raw hive there is no `CurrentControlSet` (that's a live-registry symlink). The active ControlSet is found by reading the `Select` key's `Current` value (a REG_DWORD, e.g. 1) and formatting `ControlSet{NNN:03}` → `ControlSet001`. We read it with the existing `hive_reader::get_value_bytes` (REG_DWORD comes back as 4 LE bytes via the Binary path? — NO: REG_DWORD is NOT CellValue::Binary). So resolution splits into a PURE formatting function (unit-tested here) and the actual read (done in Task 4 using a notatin DWORD read). This task implements ONLY the pure `controlset_name(current: u32) -> String`; Task 4 reads the DWORD and calls it, falling back to ControlSet001 if the read fails.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `bam.rs`:

```rust
    #[test]
    fn controlset_name_zero_pads_to_three_digits() {
        assert_eq!(controlset_name(1), "ControlSet001");
        assert_eq!(controlset_name(2), "ControlSet002");
        assert_eq!(controlset_name(10), "ControlSet010");
        assert_eq!(controlset_name(123), "ControlSet123");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-collectors bam::tests::controlset_name_zero_pads_to_three_digits`
Expected: FAIL — `cannot find function controlset_name in this scope`.

- [ ] **Step 3: Implement `controlset_name`**

Add to `bam.rs` (after `parse_bam_value`, before the tests module):

```rust
/// Format a ControlSet key name from the `Select\Current` DWORD value, e.g.
/// 1 -> "ControlSet001". Zero-padded to 3 digits (the on-disk convention).
fn controlset_name(current: u32) -> String {
    format!("ControlSet{current:03}")
}

/// The ControlSet to use when `Select\Current` is unreadable/absent — the
/// overwhelmingly common active set. We proceed with this rather than abstain the whole
/// collect for a missing Select value (graceful degrade, golden rule 8).
const DEFAULT_CONTROLSET: &str = "ControlSet001";
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p cairn-collectors bam::tests::controlset_name_zero_pads_to_three_digits`
Expected: PASS.

- [ ] **Step 5: Verify no clippy warnings**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings`
Expected: clean. (`controlset_name`/`DEFAULT_CONTROLSET` may be `dead_code` until Task 4;
apply the same temporary `#[allow(dead_code)]` + `// removed in Task 4` pattern if flagged.)

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/bam.rs
git commit -m "feat(bam): controlset_name formatter (Select\\Current -> ControlSetNNN)

Pure 3-digit zero-pad formatter + DEFAULT_CONTROLSET fallback. The DWORD
read + fallback wiring lands in Task 4.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `BamCollector`

**Files:**
- Modify: `crates/cairn-collectors/src/bam.rs`

**Context for the engineer:** This is the integration task. Study `crates/cairn-collectors/src/amcache.rs` closely — `BamCollector` mirrors its shape exactly (privilege gate → `VolumeReader::open(r"\\.\C:")` → `open_hive(SYSTEM_HIVE)` → truncated/log_status checks → enumerate → map → sort → `sources()` with four flags). Differences: bam uses `SYSTEM_HIVE` (not AMCACHE_HIVE), resolves the ControlSet first, enumerates `list_subkeys` (SIDs) then `list_values` per SID (not amcache's inventory keys), and maps via `parse_bam_value` (not SHA1). `CollectCtx` has fields `config, admin, se_backup, se_debug`. `filetime_to_utc` and the verified hive_reader primitives are already imported in Task 2/3.

**Reading the active ControlSet (a REG_DWORD):** hive_reader has no DWORD accessor. `Select\Current` is a REG_DWORD; `get_value_bytes` only returns `CellValue::Binary`, and REG_DWORD is `CellValue::U32(u32)` in notatin (VERIFIED from `cell_value.rs:30` — the variant is exactly `U32(u32)`), so `get_value_bytes` returns `Ok(None)` for it. To avoid widening hive_reader's surface for one caller, implement the DWORD read inline in bam.rs using notatin (mirrors get_value_string's body):

```rust
/// Read a REG_DWORD value (e.g. Select\Current) directly. Returns None if the key/value
/// is absent or not a DWORD. Mirrors hive_reader::get_value_string's access pattern but
/// for CellValue::U32 — kept local to bam to avoid widening hive_reader for one caller.
fn read_dword(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Option<u32> {
    let key = parser.get_key(key_path, false).ok().flatten()?;
    let value = key.get_value(value_name)?;
    match value.get_content().0 {
        notatin::cell_value::CellValue::U32(n) => Some(n),
        _ => None,
    }
}
```

The `CellValue::U32(u32)` variant is VERIFIED from notatin 1.0.1 `cell_value.rs:30` — no
further source-check needed. `get_value` returns `Option<CellKeyValue>` (no Result), so
`get_key(...).ok().flatten()?` then `key.get_value(name)?` is the correct access chain.

- [ ] **Step 1: Add imports + the BamCollector struct + the four-flag scaffold**

At the top of `bam.rs`, extend the imports:

```rust
use std::sync::atomic::{AtomicBool, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use crate::hive_reader::{list_subkeys, list_values, open_hive, LogStatus, SYSTEM_HIVE};
```

Add the struct (after the imports, before `parse_bam_value`):

```rust
/// BamCollector: privilege-gated, read-only parse of the SYSTEM hive's bam UserSettings
/// into per-SID Record::Execution (source="bam", execution_confirmed=Some(true)).
/// Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
#[derive(Default)]
pub struct BamCollector {
    /// SYSTEM hive exceeded the memory ceiling (parse abstained). NFR10/NFR12.
    truncated: AtomicBool,
    /// The bam UserSettings key was absent/empty (build variance — abstained). NFR12.
    bam_key_absent: AtomicBool,
    /// A transaction log (.LOG1/.LOG2) existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
    /// At least one SID/value was skipped on a read error or impossible structure
    /// (non-binary / data<8). The rest still collected (golden rule 8); surfaced so the
    /// analyst knows the result is partial (NFR12).
    entry_read_errors: AtomicBool,
}
```

- [ ] **Step 2: Write the collector-surface failing tests**

Add to the `tests` module in `bam.rs`:

```rust
    use cairn_core::config::Config;

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = BamCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_bam() {
        assert_eq!(BamCollector::default().name(), "bam");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = BamCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "bam");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_truncation_abstain() {
        let c = BamCollector::default();
        c.truncated.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("exceeded memory ceiling")));
    }

    #[test]
    fn sources_reports_bam_key_absent() {
        let c = BamCollector::default();
        c.bam_key_absent.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("UserSettings key absent")));
    }

    #[test]
    fn sources_reports_log_replay_failed() {
        let c = BamCollector::default();
        c.log_replay_failed.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("log_replay_failed")));
    }

    #[test]
    fn sources_reports_partial_on_entry_read_errors() {
        let c = BamCollector::default();
        c.entry_read_errors.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("partial")));
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p cairn-collectors bam::tests`
Expected: FAIL — `collect`/`name`/`sources` not found (`Collector` not impl'd yet).

- [ ] **Step 4: Implement `read_dword` + the `Collector` impl**

Add `read_dword` (the helper shown in the Context above; VERIFY the `CellValue::U32`
variant name from source first). Then add the `Collector` impl after the struct:

```rust
impl Collector for BamCollector {
    fn name(&self) -> &str {
        "bam"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors amcache/shimcache). The bam
        // UserSettings key is SYSTEM-ACL-protected and the SYSTEM hive is OS-locked, so
        // it is only reachable via a raw \\.\C: read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "bam".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let mut opened = open_hive(&mut reader, &SYSTEM_HIVE)?;

        if opened.truncated {
            self.truncated.store(true, Ordering::Relaxed);
            tracing::warn!("bam: SYSTEM hive exceeded ceiling; abstaining");
            return Ok(Vec::new());
        }
        if let LogStatus::Failed(reason) = &opened.log_status {
            self.log_replay_failed.store(true, Ordering::Relaxed);
            tracing::warn!(reason = %reason, "bam: log replay failed; primary-only");
        }

        // Resolve the active ControlSet from Select\Current; fall back to ControlSet001.
        let controlset = match read_dword(&mut opened.parser, "Select", "Current") {
            Some(n) => controlset_name(n),
            None => DEFAULT_CONTROLSET.to_string(),
        };
        let user_settings = format!("{controlset}\\Services\\bam\\State\\UserSettings");

        // Enumerate the per-SID subkeys.
        let sids = list_subkeys(&mut opened.parser, &user_settings)?;
        if sids.is_empty() {
            self.bam_key_absent.store(true, Ordering::Relaxed);
            tracing::warn!(key = %user_settings, "bam: UserSettings key absent/empty; abstaining");
            return Ok(Vec::new());
        }

        let mut records: Vec<Record> = Vec::new();
        for sid in sids {
            let sid_path = format!("{user_settings}\\{}", sid.name);
            let values = match list_values(&mut opened.parser, &sid_path) {
                Ok(v) => v,
                Err(e) => {
                    // A genuine read error on one SID skips that SID, not the whole run.
                    self.entry_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(sid = %sid.name, err = %e, "bam: SID value read error; skipping");
                    continue;
                }
            };
            for kv in values {
                match parse_bam_value(&kv.data) {
                    Some(last_run) => {
                        records.push(Record::Execution(ExecutionRecord {
                            source: "bam".into(),
                            path: kv.name, // NT device path, kept verbatim (NFR12)
                            first_run: None,
                            last_run: Some(last_run),
                            run_count: None,
                            sha1: None,
                            user_sid: Some(sid.name.clone()),
                            execution_confirmed: Some(true),
                        }));
                    }
                    None => {
                        // data<8 or zero FILETIME. Zero FILETIME is legitimate padding,
                        // NOT an error — only a structurally-impossible value (data<8) is
                        // a partial signal. Distinguish: <8 bytes => entry_read_errors.
                        if kv.data.len() < 8 {
                            self.entry_read_errors.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        // Determinism (NFR4): enumeration order is physical; sort by (user_sid, path).
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => {
                x.user_sid.cmp(&y.user_sid).then(x.path.cmp(&y.path))
            }
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution emitted above
        });

        tracing::info!(bam_entries = records.len(), "bam scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.truncated.load(Ordering::Relaxed) {
            errors.push(
                "abstained: SYSTEM hive exceeded memory ceiling (NFR10); not parsed".to_string(),
            );
        }
        if self.bam_key_absent.load(Ordering::Relaxed) {
            errors.push(
                "abstained: bam UserSettings key absent (build variance/NFR12)".to_string(),
            );
        }
        if self.log_replay_failed.load(Ordering::Relaxed) {
            errors.push(
                "log_replay_failed: transaction log present but unreadable; primary-only parse"
                    .to_string(),
            );
        }
        if self.entry_read_errors.load(Ordering::Relaxed) {
            errors.push(
                "partial: one or more entries skipped (result incomplete)".to_string(),
            );
        }
        vec![SourceEntry {
            artifact: "bam".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}
```

- [ ] **Step 5: Remove all temporary `#[allow(dead_code)]`**

Remove every `#[allow(dead_code)]` added in Tasks 1–3 (`KeyValue`, `list_values`,
`parse_bam_value`, `controlset_name`, `DEFAULT_CONTROLSET`) — they are all consumed now.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors bam::tests`
Expected: all bam tests PASS (the 7 surface/parse tests + earlier helpers).

- [ ] **Step 7: Verify compile + clippy on the whole workspace**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean. Then `cargo fmt`.

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-collectors/src/bam.rs
git commit -m "feat(bam): BamCollector (SYSTEM hive bam UserSettings -> Execution)

admin+SeBackup gate -> raw \\.\C: -> open_hive(SYSTEM) -> resolve
ControlSet from Select\\Current -> enumerate UserSettings\\<SID> values ->
parse_bam_value -> Record::Execution (source=bam, last_run, user_sid).
Four flags (truncated/key_absent/log_replay_failed/entry_read_errors);
per-SID + per-value graceful degrade. NT path kept verbatim (NFR12).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: selection / CLI wiring + elevated e2e

**Files:**
- Modify: `crates/cairn-core/src/selection.rs`
- Modify: `crates/cairn-cli/src/main.rs`
- Modify: `crates/cairn-collectors/src/bam.rs` (e2e test)

**Context for the engineer:** bam is a heavy offline collector (reads the whole SYSTEM hive), so it joins `HEAVY_OFFLINE` (minimal-excluded). Wiring mirrors amcache/prefetch exactly. There are TWO `AVAILABLE` arrays in main.rs (the runtime one ~line 632 and the test one ~line 917) and the `built_collector_names` list (~line 278) — all must gain `"bam"` in canonical order (after `"prefetch"`).

- [ ] **Step 1: Add bam to HEAVY_OFFLINE + a minimal-exclusion test**

In `crates/cairn-core/src/selection.rs`, change line 36:

```rust
const HEAVY_OFFLINE: &[&str] = &["mft", "usn", "shimcache", "amcache", "prefetch", "bam"];
```

Add a test in the `tests` module (after `minimal_excludes_prefetch`):

```rust
    #[test]
    fn minimal_excludes_bam() {
        let available = vec![
            "proc", "net", "persist", "mft", "usn", "shimcache", "amcache", "prefetch", "bam",
        ];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"bam".to_string()));
    }
```

- [ ] **Step 2: Run the selection test**

Run: `cargo test -p cairn-core selection::tests::minimal_excludes_bam`
Expected: PASS.

- [ ] **Step 3: Add bam to both AVAILABLE arrays + built_collector_names**

In `crates/cairn-cli/src/main.rs`:
- Runtime `AVAILABLE` (~line 632): add `"bam",` after `"prefetch",`.
- Test `AVAILABLE` (~line 917): add `"bam",` after `"prefetch",`.
- `built_collector_names` list (~line 278): add `"bam",` after `"prefetch",`.
- Update the doc comment at line 274–275: change "eight" to "nine" and append `/bam` to
  the collector list string.

- [ ] **Step 4: Add the selection-gated push block**

In `main.rs`, after the prefetch push block (~line 726):

```rust
            if selection.selected.iter().any(|m| m == "bam") {
                collectors.push(Box::new(
                    cairn_collectors::bam::BamCollector::default(),
                ));
            }
```

- [ ] **Step 5: Add a wiring assertion to the existing test**

In `main.rs`, in the wiring test that asserts prefetch (the `standard includes prefetch /
minimal skips prefetch` block ~line 996–1006), append:

```rust
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"bam".to_string()), "standard includes bam");
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"bam".to_string()), "minimal skips bam");
```

Also, if the "all eight in canonical order" assertion (~line 935–948) lists the eight
names explicitly, add `"bam"` after `"prefetch"` there and update its comment to "nine".

- [ ] **Step 6: Add the `#[ignore]` elevated e2e**

In `crates/cairn-collectors/src/bam.rs` tests module:

```rust
    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors bam::tests::bam_e2e_real_system_hive -- --ignored --nocapture
    /// Proves the full chain: raw \\.\C: -> ntfs locate SYSTEM hive -> notatin parse ->
    /// resolve ControlSet -> bam UserSettings\<SID> -> Record::Execution.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn bam_e2e_real_system_hive() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        let recs = BamCollector::default()
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        eprintln!("bam_e2e_real_system_hive: parsed {} entries", recs.len());
        assert!(!recs.is_empty(), "an active host always has bam entries");
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "bam");
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert_eq!(e.execution_confirmed, Some(true));
                assert!(e.last_run.is_some(), "bam carries a last-execution time");
                // NFR12: bam never fabricates these fields.
                assert!(e.first_run.is_none(), "bam must not claim a first_run");
                assert!(e.run_count.is_none(), "bam has no run count");
                assert!(e.sha1.is_none(), "bam has no sha1");
                let sid = e.user_sid.as_deref().unwrap_or("");
                assert!(sid.starts_with("S-1-"), "user_sid must be a SID, got {sid:?}");
            } else {
                panic!("bam must only emit Execution records");
            }
        }
    }
```

- [ ] **Step 7: Full workspace build + test + clippy**

Run: `cargo test --workspace`
Expected: all pass (e2e is `#[ignore]`d, won't run).
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.
Run: `cargo fmt`

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-core/src/selection.rs crates/cairn-cli/src/main.rs crates/cairn-collectors/src/bam.rs
git commit -m "feat(bam): wire BamCollector into selection + CLI; add elevated e2e

bam joins HEAVY_OFFLINE (minimal-excluded) and both AVAILABLE arrays +
built_collector_names. Selection-gated push block constructs it. Ignored
elevated e2e proves the full raw->hive->Execution chain on a real host.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## After all tasks

Dispatch a final whole-implementation code review, then run the elevated e2e on the real
host (admin + SeBackup) to confirm real bam entries parse:

```
cargo test -p cairn-collectors bam::tests::bam_e2e_real_system_hive -- --ignored --nocapture
```

Then use superpowers:finishing-a-development-branch (push + PR + CI green + merge).

**Accepted residual (document, do not fix here):** the bam value `path` is the NT device
path (`\Device\HarddiskVolumeN\...`), not a DOS path — verbatim by design (NFR12); DOS
translation is deferred (YAGNI). The `read_dword` REG_DWORD accessor is local to bam; if
a second consumer needs it later, promote it to hive_reader then.
```
