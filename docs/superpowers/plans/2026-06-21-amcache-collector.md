# Amcache Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse `Amcache.hve` InventoryApplicationFile entries (path + strict SHA1 + key last-write as first-exec) into `Record::Execution`, reusing the `hive_reader` primitive.

**Architecture:** Extend `hive_reader.rs` with two reusable primitives (`list_subkeys`, `get_value_string`) returning hive_reader's own pure types (no notatin leak). A new `amcache.rs` consumer maps InventoryApplicationFile subkeys to `Record::Execution`. Wire into selection (`RAW_NTFS`) and the CLI run arm, mirroring the shimcache segment exactly.

**Tech Stack:** Rust, notatin 1.0.1 (offline hive parser), the existing `VolumeReader` (raw `\\.\C:`), `cairn-collectors` (`#![forbid(unsafe_code)]`).

**Authoritative spec:** `docs/superpowers/specs/2026-06-21-amcache-collector-design.md`

---

## Context for the implementer (read before Task 1)

The hive/shimcache segment (PR #20) already built the foundation. You are EXTENDING it.
Study these existing files first — your work mirrors them:

- `crates/cairn-collectors/src/hive_reader.rs` — has `open_hive`, `get_value_bytes`
  (REG_BINARY), `HivePath`, `SYSTEM_HIVE`, `LogStatus`, `OpenedHive`, `hive_err`,
  `HIVE_HARD_CEILING`. You ADD `AMCACHE_HIVE`, `SubKey`, `list_subkeys`,
  `get_value_string` here.
- `crates/cairn-collectors/src/shimcache.rs` — the consumer TEMPLATE. `amcache.rs`
  copies its structure: privilege gate, `VolumeReader::open`, `open_hive`, truncated /
  `LogStatus::Failed` handling, three `AtomicBool` flags, `sources()` surfacing,
  determinism sort, `#[ignore]` elevated e2e.
- `crates/cairn-core/src/record.rs` — `ExecutionRecord` (ALL fields already exist;
  schema is UNCHANGED by this work).
- `crates/cairn-core/src/time.rs` — `filetime_to_utc` (you do NOT need it here;
  notatin's `last_key_written_date_and_time()` already returns `DateTime<Utc>`).
- `crates/cairn-core/src/selection.rs` — `RAW_NTFS` const.
- `crates/cairn-cli/src/main.rs` — AVAILABLE arrays, `built_collector_names`, the
  selection-gated push blocks.

### notatin 1.0.1 API facts (verified from installed source — do NOT re-guess)

- `Parser::get_key(&mut self, key_path: &str, key_path_has_root: bool) -> Result<Option<CellKeyNode>, Error>`.
  Use `key_path_has_root = false`. Lazy cursor: takes `&mut self`, mutates on lookup.
- `CellKeyNode.key_name: String` — PUBLIC field (the subkey's name).
- `CellKeyNode.detail.number_of_sub_keys() -> u32` — child count (accessor on the detail enum).
- `CellKeyNode::get_sub_key_by_index(&mut self, parser: &mut Parser, index: usize) -> Option<Self>`
  — `&mut self` on the PARENT node; out-of-range index returns `None` (never panics).
- `CellKeyNode::last_key_written_date_and_time(&self) -> DateTime<Utc>` (chrono, UTC).
- `CellKeyNode::get_value(&self, name: &str) -> Option<CellKeyValue>`.
- `CellKeyValue::get_content() -> (CellValue, Option<Logs>)`; `.0` is the `CellValue`.
- `CellValue::String(String)` is the REG_SZ variant (also `Binary(Vec<u8>)`, `U32`, `U64`, …).

### Performance residual (documented; do NOT prematurely optimize)

`get_sub_key_by_index` re-parses the subkey-offset list on EVERY call (it calls
`parse_sub_key_list` internally), so `for i in 0..n` is O(n²) in offset-list parses.
For typical InventoryApplicationFile counts (~1k–5k) this is acceptable on a
one-shot single-host run. If the elevated e2e (Task 6) shows this takes more than a
few seconds, the optimization is `ParserIterator::new(&parser).with_filter(filter)`
with a `FilterBuilder::new().add_key_path("InventoryApplicationFile")` scope (O(n)
single pass) — but that API needs its own verification pass; keep the simple,
fully-verified `get_sub_key_by_index` path for this segment.

### Standing constraints (every task)

- `#![forbid(unsafe_code)]` stays in `cairn-collectors`. Zero new unsafe.
- Never panic in collector code (golden rule 8). Bounds-checked, `Option`-returning.
- Determinism: sort emitted records by path (NFR4).
- Schema UNCHANGED — do not touch `record.rs`.
- Commit footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Run `cargo test --workspace` (NOT `-p`) and `cargo clippy --workspace --all-targets -- -D warnings`
  before each commit — the CI runs both; local must match.
- `cargo fmt` before each commit.

---

## Task 1: Strict SHA1-from-FileId pure parser

**Files:**
- Create: `crates/cairn-collectors/src/amcache.rs`
- Modify: `crates/cairn-collectors/src/lib.rs` (add `pub mod amcache;`)

This task creates `amcache.rs` containing ONLY the pure SHA1 parser + its tests, so
it compiles and tests in isolation before any I/O code exists.

- [ ] **Step 1: Register the module**

In `crates/cairn-collectors/src/lib.rs`, add `pub mod amcache;` in alphabetical
position (before `pub mod hive_reader;`). Check the existing module list to place it
correctly.

- [ ] **Step 2: Write the failing tests**

Create `crates/cairn-collectors/src/amcache.rs` with:

```rust
//! AmcacheCollector: parse Amcache.hve InventoryApplicationFile entries into
//! Record::Execution (path + SHA1 + first-exec approximation).
//!
//! Amcache.hve is a structured registry hive (unlike shimcache's single blob). Each
//! file under InventoryApplicationFile is a subkey whose named values carry the path
//! (LowerCaseLongPath / Name) and a SHA1 (FileId). first_run is approximated by the
//! subkey's last-write time (the industry-accepted Amcache first-seen). On an absent
//! key or unrecognised structure it ABSTAINS (records the reason in the manifest)
//! rather than guess — misreading a forensic artifact is worse than abstaining (NFR12).
//! This segment parses InventoryApplicationFile only.

/// Parse the SHA1 out of an Amcache FileId value.
///
/// FileId format is the string "0000" + 40 lowercase hex (44 chars total). A
/// non-conforming value yields None (the entry is still emitted with sha1=None —
/// NFR12 honesty: never write a malformed value into a SHA1 field).
fn parse_sha1_from_fileid(field: &str) -> Option<String> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conforming_fileid_yields_lowercase_sha1() {
        let id = "0000aabbccddeeff00112233445566778899aabb";
        assert_eq!(id.len() - 4, 40); // sanity on the fixture
        let full = format!("0000{}", &id[4..]);
        let got = parse_sha1_from_fileid(&full);
        assert_eq!(got.as_deref(), Some(&id[4..]));
    }

    #[test]
    fn uppercase_hex_is_normalised_to_lowercase() {
        let full = "0000AABBCCDDEEFF00112233445566778899AABBCC".to_string();
        // 4 + 40 = 44 chars; build exactly 44.
        assert_eq!(full.len(), 44);
        let got = parse_sha1_from_fileid(&full).unwrap();
        assert_eq!(got, got.to_ascii_lowercase());
        assert_eq!(got.len(), 40);
    }

    #[test]
    fn wrong_length_is_none() {
        assert_eq!(parse_sha1_from_fileid(""), None);
        assert_eq!(parse_sha1_from_fileid("0000"), None);
        assert_eq!(parse_sha1_from_fileid("0000abcd"), None); // too short
        let too_long = format!("0000{}", "a".repeat(41));
        assert_eq!(parse_sha1_from_fileid(&too_long), None);
    }

    #[test]
    fn wrong_prefix_is_none() {
        // 44 chars, valid hex, but prefix is not 0000.
        let full = format!("1234{}", "a".repeat(40));
        assert_eq!(full.len(), 44);
        assert_eq!(parse_sha1_from_fileid(&full), None);
    }

    #[test]
    fn non_hex_body_is_none() {
        // 44 chars, 0000 prefix, but body has a non-hex char ('g').
        let full = format!("0000{}", "g".repeat(40));
        assert_eq!(full.len(), 44);
        assert_eq!(parse_sha1_from_fileid(&full), None);
    }

    #[test]
    fn no_panic_on_multibyte_input() {
        // Multibyte chars: len() is byte length. A 44-BYTE string that is not 44
        // ASCII chars must not panic on slicing. "é" is 2 bytes.
        let s = "é".repeat(22); // 44 bytes, 22 chars
        let _ = parse_sha1_from_fileid(&s); // must not panic
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p cairn-collectors amcache::tests`
Expected: FAIL (panics on `unimplemented!()` / compile error on the body).

- [ ] **Step 4: Implement `parse_sha1_from_fileid`**

Replace the `unimplemented!()` body with:

```rust
fn parse_sha1_from_fileid(field: &str) -> Option<String> {
    // Operate on chars, not bytes, so multibyte input can never panic on slicing.
    let chars: Vec<char> = field.chars().collect();
    if chars.len() != 44 {
        return None;
    }
    // First 4 chars must be the literal "0000" (ASCII digits; no case applies).
    if chars[0..4] != ['0', '0', '0', '0'] {
        return None;
    }
    let body: String = chars[4..].iter().collect();
    if !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(body.to_ascii_lowercase())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors amcache::tests`
Expected: PASS (6 tests).

- [ ] **Step 6: Lint + format + commit**

```bash
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add crates/cairn-collectors/src/amcache.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(amcache): strict SHA1-from-FileId pure parser

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: hive_reader primitives — list_subkeys + get_value_string

**Files:**
- Modify: `crates/cairn-collectors/src/hive_reader.rs`

Add the two reusable primitives + the `AMCACHE_HIVE` path + `SubKey` type. These are
the ntfs/notatin navigation layer; like `open_hive`/`get_value_bytes` they are
verified by the elevated e2e (Task 6), not unit-tested against a real hive. The
unit test here only proves the AMCACHE_HIVE path const joins correctly and that
`hive_err` wraps reasons (no live hive needed).

- [ ] **Step 1: Write the failing tests**

In `crates/cairn-collectors/src/hive_reader.rs`, add to the existing `#[cfg(test)]
mod tests` block:

```rust
    #[test]
    fn amcache_hive_path_joins_to_appcompat_programs() {
        let joined = AMCACHE_HIVE.components.join("\\");
        assert_eq!(joined, r"Windows\AppCompat\Programs\Amcache.hve");
    }

    #[test]
    fn subkey_holds_name_and_time() {
        // SubKey is hive_reader's OWN pure type (no notatin leak). Smoke-construct it.
        let t = chrono::Utc::now();
        let sk = SubKey {
            name: "0006...".into(),
            last_write: t,
        };
        assert_eq!(sk.name, "0006...");
        assert_eq!(sk.last_write, t);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-collectors hive_reader::tests`
Expected: FAIL (compile error — `AMCACHE_HIVE` and `SubKey` not defined).

- [ ] **Step 3: Add AMCACHE_HIVE const**

After the `SYSTEM_HIVE` const in `hive_reader.rs`, add:

```rust
/// Amcache.hve — programs/files inventory (FR12 amcache_collector).
pub(crate) const AMCACHE_HIVE: HivePath = HivePath {
    components: &["Windows", "AppCompat", "Programs", "Amcache.hve"],
};
```

- [ ] **Step 4: Add the SubKey type**

Near `OpenedHive` in `hive_reader.rs`, add:

```rust
/// One enumerated subkey: its name and last-write time. hive_reader's OWN pure type —
/// it deliberately does NOT expose notatin's CellKeyNode, so a notatin upgrade cannot
/// break consumers (same encapsulation as get_value_bytes returning (Vec<u8>, DateTime)).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SubKey {
    pub name: String,
    pub last_write: DateTime<Utc>,
}
```

- [ ] **Step 5: Add list_subkeys**

After `get_value_bytes` in `hive_reader.rs`, add:

```rust
/// Enumerate the direct child keys of `key_path`, returning each child's name and
/// last-write time. Absent key => Ok(vec![]) (graceful — golden rule 8).
///
/// Index-based enumeration (get_sub_key_by_index over 0..number_of_sub_keys). Order
/// is the hive's physical order, NOT sorted — the CALLER sorts for determinism.
/// `parser` is &mut because notatin traverses lazily (mutates state per lookup).
pub(crate) fn list_subkeys(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
) -> Result<Vec<SubKey>> {
    let mut parent = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let n = parent.detail.number_of_sub_keys() as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // get_sub_key_by_index returns None for an out-of-range / unreadable child;
        // skip it (best-effort, never panic).
        if let Some(child) = parent.get_sub_key_by_index(parser, i) {
            out.push(SubKey {
                name: child.key_name.clone(),
                last_write: child.last_key_written_date_and_time(),
            });
        }
    }
    Ok(out)
}
```

- [ ] **Step 6: Add get_value_string**

After `list_subkeys`, add:

```rust
/// Fetch a single REG_SZ value as a String. Returns Ok(None) when the key or value is
/// absent, or when the value is not a string type (graceful — golden rule 8).
///
/// Companion to get_value_bytes (which handles REG_BINARY). `parser` is &mut for the
/// same lazy-cursor reason.
pub(crate) fn get_value_string(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Result<Option<String>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(None),
    };
    let value = match key.get_value(value_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    match value.get_content().0 {
        notatin::cell_value::CellValue::String(s) => Ok(Some(s)),
        _ => Ok(None),
    }
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors hive_reader::tests`
Expected: PASS (existing tests + the 2 new ones). If clippy warns `dead_code` on the
new primitives (no consumer yet until Task 3), that is expected — Task 3 wires the
consumer in the SAME branch, so do NOT add `#[allow(dead_code)]`; instead verify the
whole branch compiles clean after Task 3. For THIS task's commit, a temporary
`#[allow(dead_code)]` on `list_subkeys`/`get_value_string`/`SubKey`/`AMCACHE_HIVE` is
acceptable and MUST be removed in Task 3.

- [ ] **Step 8: Lint + format + commit**

```bash
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(hive_reader): list_subkeys + get_value_string + AMCACHE_HIVE

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: AmcacheCollector — InventoryApplicationFile → Record::Execution

**Files:**
- Modify: `crates/cairn-collectors/src/amcache.rs`
- Modify: `crates/cairn-collectors/src/hive_reader.rs` (remove any temporary `#[allow(dead_code)]` from Task 2)

Build the collector that ties everything together. Mirror `shimcache.rs` closely.

- [ ] **Step 1: Add imports + consts + the AmcacheCollector struct**

At the top of `crates/cairn-collectors/src/amcache.rs` (after the module doc comment),
add:

```rust
use std::sync::atomic::{AtomicBool, Ordering};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use crate::hive_reader::{
    get_value_string, list_subkeys, open_hive, LogStatus, AMCACHE_HIVE,
};

/// The InventoryApplicationFile key: one subkey per executable, holding LowerCaseLongPath
/// / Name (path) and FileId (SHA1). key_path_has_root = false (no root prefix).
const INVENTORY_APP_FILE_KEY: &str = "Root\\InventoryApplicationFile";

const VALUE_PATH: &str = "LowerCaseLongPath";
const VALUE_NAME: &str = "Name";
const VALUE_FILE_ID: &str = "FileId";

/// AmcacheCollector: privilege-gated, read-only InventoryApplicationFile read from a
/// locked Amcache.hve. Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
/// Emits Record::Execution (source="amcache", execution_confirmed=Some(true)).
#[derive(Default)]
pub struct AmcacheCollector {
    /// Amcache.hve exceeded the memory ceiling (parse abstained). NFR10/NFR12.
    abstained_truncated: AtomicBool,
    /// The InventoryApplicationFile key was absent (build variance — abstained). NFR12.
    key_absent: AtomicBool,
    /// A transaction log (.LOG1/.LOG2) existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
}
```

NOTE on `INVENTORY_APP_FILE_KEY`: Amcache.hve's executable inventory lives under
`Root\InventoryApplicationFile`. notatin's `get_key(path, false)` expects the path
WITHOUT the hive-root prefix; in Amcache the first on-hive key IS named `Root`, so the
path is `Root\InventoryApplicationFile`. The elevated e2e (Task 6) confirms this; if a
real hive shows the entries are reachable as just `InventoryApplicationFile`, the e2e
will fail loudly and the const is the single place to fix.

- [ ] **Step 2: Write the collector surface tests (no I/O)**

Add a `#[cfg(test)]` section to `amcache.rs` (alongside the existing SHA1 tests).
Append these tests INTO the existing `mod tests` block:

```rust
    use cairn_core::config::Config;
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::CairnError;
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
        let r = AmcacheCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_amcache() {
        assert_eq!(AmcacheCollector::default().name(), "amcache");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = AmcacheCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "amcache");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_truncation_abstain() {
        let c = AmcacheCollector::default();
        c.abstained_truncated.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0].errors.iter().any(|e| e.contains("exceeded memory ceiling")));
    }

    #[test]
    fn sources_reports_key_absent_abstain() {
        let c = AmcacheCollector::default();
        c.key_absent.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0].errors.iter().any(|e| e.contains("InventoryApplicationFile key absent")));
    }

    #[test]
    fn sources_reports_log_replay_failed() {
        let c = AmcacheCollector::default();
        c.log_replay_failed.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0].errors.iter().any(|e| e.contains("log_replay_failed")));
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p cairn-collectors amcache::tests`
Expected: FAIL (compile error — `Collector` not impl'd for `AmcacheCollector`,
`name`/`collect`/`sources` missing).

- [ ] **Step 4: Implement the Collector impl**

Add to `amcache.rs` (after the struct, before `#[cfg(test)]`):

```rust
impl Collector for AmcacheCollector {
    fn name(&self) -> &str {
        "amcache"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors shimcache). Amcache.hve is
        // held open by the OS, so it is only reachable via a raw \\.\C: read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "amcache".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let mut opened = open_hive(&mut reader, &AMCACHE_HIVE)?;

        if opened.truncated {
            self.abstained_truncated.store(true, Ordering::Relaxed);
            tracing::warn!("amcache: Amcache.hve exceeded ceiling; abstaining");
            return Ok(Vec::new());
        }
        if let LogStatus::Failed(reason) = &opened.log_status {
            self.log_replay_failed.store(true, Ordering::Relaxed);
            tracing::warn!(reason = %reason, "amcache: log replay failed; primary-only");
        }

        let subkeys = list_subkeys(&mut opened.parser, INVENTORY_APP_FILE_KEY)?;
        if subkeys.is_empty() {
            // Distinguish "key absent" from "key present but empty" is not possible from
            // list_subkeys alone (both yield empty). Probe the key directly: if get_key
            // returns None the key is absent (build variance, NFR12). We treat an empty
            // result as key-absent for the manifest signal — a populated host always has
            // entries here, so empty in practice means the key/structure is unsupported.
            self.key_absent.store(true, Ordering::Relaxed);
            tracing::warn!("amcache: InventoryApplicationFile absent/empty; abstaining");
            return Ok(Vec::new());
        }

        let mut records: Vec<Record> = Vec::new();
        for sk in subkeys {
            let key_path = format!("{INVENTORY_APP_FILE_KEY}\\{}", sk.name);
            // Path: LowerCaseLongPath, else Name, else drop (no path = no evidence).
            let path = match get_value_string(&mut opened.parser, &key_path, VALUE_PATH)? {
                Some(p) if !p.is_empty() => p,
                _ => match get_value_string(&mut opened.parser, &key_path, VALUE_NAME)? {
                    Some(n) if !n.is_empty() => n,
                    _ => continue, // local best-effort drop; no abstain flag
                },
            };
            let sha1 = get_value_string(&mut opened.parser, &key_path, VALUE_FILE_ID)?
                .and_then(|id| parse_sha1_from_fileid(&id));

            records.push(Record::Execution(ExecutionRecord {
                source: "amcache".into(),
                path,
                // Amcache InventoryApplicationFile has no real exec time; the subkey's
                // last-write is the industry first-seen approximation (NFR12: documented,
                // not a fabricated exec time).
                first_run: Some(sk.last_write),
                last_run: None,
                run_count: None,
                sha1,
                user_sid: None,
                // An InventoryApplicationFile entry means the OS registered the file as an
                // executable — stronger than shimcache "presence". Hence Some(true).
                execution_confirmed: Some(true),
            }));
        }

        // Determinism (NFR4): subkey enumeration order is physical; sort by path.
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => x.path.cmp(&y.path),
            _ => std::cmp::Ordering::Equal,
        });

        tracing::info!(amcache_entries = records.len(), "amcache scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.abstained_truncated.load(Ordering::Relaxed) {
            errors.push(
                "abstained: Amcache.hve exceeded memory ceiling (NFR10); not parsed".to_string(),
            );
        }
        if self.key_absent.load(Ordering::Relaxed) {
            errors.push(
                "abstained: InventoryApplicationFile key absent (build variance/NFR12)".to_string(),
            );
        }
        if self.log_replay_failed.load(Ordering::Relaxed) {
            errors.push(
                "log_replay_failed: transaction log present but unreadable; primary-only parse"
                    .to_string(),
            );
        }
        vec![SourceEntry {
            artifact: "amcache".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}
```

- [ ] **Step 5: Remove the temporary dead_code allows from Task 2**

In `hive_reader.rs`, remove any `#[allow(dead_code)]` you added in Task 2 to
`list_subkeys`/`get_value_string`/`SubKey`/`AMCACHE_HIVE`. They are now consumed by
`amcache.rs`, so the warnings are gone.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors amcache::tests`
Expected: PASS (6 SHA1 tests + 6 surface tests).

- [ ] **Step 7: Lint + format + commit**

```bash
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add crates/cairn-collectors/src/amcache.rs crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(amcache): AmcacheCollector InventoryApplicationFile -> Record::Execution

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Selection wiring — add amcache to RAW_NTFS

**Files:**
- Modify: `crates/cairn-core/src/selection.rs`

- [ ] **Step 1: Write the failing test**

In `crates/cairn-core/src/selection.rs`, add to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn minimal_excludes_amcache() {
        let available = vec!["proc", "net", "persist", "mft", "usn", "shimcache", "amcache"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]); // no raw-NTFS
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"amcache".to_string())); // standard keeps amcache
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-core selection::tests::minimal_excludes_amcache`
Expected: FAIL (`amcache` is in selected because it's not yet in RAW_NTFS, so the
assertion `out.selected == ["proc","net","persist"]` fails — amcache leaks into minimal).

- [ ] **Step 3: Add amcache to RAW_NTFS**

In `crates/cairn-core/src/selection.rs`, change:

```rust
const RAW_NTFS: &[&str] = &["mft", "usn", "shimcache"];
```

to:

```rust
const RAW_NTFS: &[&str] = &["mft", "usn", "shimcache", "amcache"];
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p cairn-core selection::tests`
Expected: PASS (all selection tests including the new one).

- [ ] **Step 5: Lint + format + commit**

```bash
cargo fmt
cargo clippy -p cairn-core --all-targets -- -D warnings
git add crates/cairn-core/src/selection.rs
git commit -m "feat(selection): amcache is raw-NTFS (excluded by --profile minimal)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: CLI wiring — register AmcacheCollector in the run arm

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

Three edit sites, all mirroring shimcache. Search the file for `"shimcache"` to find
each one.

- [ ] **Step 1: Write/extend the failing test**

In `crates/cairn-cli/src/main.rs` tests, find the test that asserts
`built_collector_names` for a standard no-only run (around the
`vec!["proc", "net", "persist", "mft", "usn", "shimcache"]` assertion) and the
`standard includes shimcache` / `minimal skips shimcache` block. Add amcache assertions.
Locate the test block (search `standard includes shimcache`) and add after it:

```rust
        // raw-NTFS collectors: standard includes amcache, minimal skips it.
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            built.contains(&"amcache".to_string()),
            "standard includes amcache"
        );
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"amcache".to_string()),
            "minimal skips amcache"
        );
```

Also update the standard-selects-all assertion (search
`vec!["proc", "net", "persist", "mft", "usn", "shimcache"]`) to include amcache:

```rust
            vec!["proc", "net", "persist", "mft", "usn", "shimcache", "amcache"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-cli`
Expected: FAIL — amcache is not in AVAILABLE / not in built_collector_names yet, so the
new assertions and the updated vec assertion fail.

- [ ] **Step 3: Add amcache to both AVAILABLE arrays**

There are TWO `AVAILABLE` arrays (the run block ~line 623 and the test ~line 889) plus
the helper-list near line 278. Add `"amcache"` as the LAST element to each:

Run-block AVAILABLE (search `const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft", "usn", "shimcache"];`
in the run arm):
```rust
            const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft", "usn", "shimcache", "amcache"];
```

Test AVAILABLE (the same literal in the test module): change identically to include `"amcache"`.

- [ ] **Step 4: Add amcache to built_collector_names + fix its doc**

Near line 277, update the helper array and the doc comment. Change:

```rust
/// MUST stay in sync with the six `if ... push(...)` blocks in `main` that
/// construct proc/net/persist/mft/usn/shimcache collectors (search: "S2-L: construct only").
#[cfg(test)]
fn built_collector_names(selected: &[String]) -> Vec<String> {
    ["proc", "net", "persist", "mft", "usn", "shimcache"]
```

to:

```rust
/// MUST stay in sync with the seven `if ... push(...)` blocks in `main` that
/// construct proc/net/persist/mft/usn/shimcache/amcache collectors (search: "S2-L: construct only").
#[cfg(test)]
fn built_collector_names(selected: &[String]) -> Vec<String> {
    ["proc", "net", "persist", "mft", "usn", "shimcache", "amcache"]
```

- [ ] **Step 5: Add the selection-gated push block**

In the run arm, after the `shimcache` push block (search
`cairn_collectors::shimcache::ShimCollector::default()` — the block ends at line ~698),
add:

```rust
            if selection.selected.iter().any(|m| m == "amcache") {
                collectors.push(Box::new(
                    cairn_collectors::amcache::AmcacheCollector::default(),
                ));
            }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p cairn-cli`
Expected: PASS (all CLI tests including the amcache selection assertions).

- [ ] **Step 7: Full-workspace check + lint + format + commit**

```bash
cargo test --workspace
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): register AmcacheCollector in the live run arm

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Elevated end-to-end test (ignored by default)

**Files:**
- Modify: `crates/cairn-collectors/src/amcache.rs`

Add a manual elevated e2e proving the full chain on a real host. Mirrors
`shimcache_e2e_real_system_hive`.

- [ ] **Step 1: Add the ignored e2e test**

In `amcache.rs` `mod tests`, add:

```rust
    use cairn_core::record::Record;

    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors amcache::tests::amcache_e2e_real_hive -- --ignored --nocapture
    /// Proves the full chain: raw \\.\C: -> ntfs locate Amcache.hve -> notatin parse
    /// (+ log replay) -> InventoryApplicationFile subkeys -> Record::Execution.
    /// Mirrors shimcache_e2e_real_system_hive. Also surfaces the INVENTORY_APP_FILE_KEY
    /// path correctness: if the const is wrong, this fails with an empty/abstain result.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn amcache_e2e_real_hive() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        let recs = AmcacheCollector::default()
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        assert!(!recs.is_empty(), "expected at least one amcache entry");
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "amcache");
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert!(e.last_run.is_none(), "amcache must not claim a last_run");
                assert_eq!(
                    e.execution_confirmed,
                    Some(true),
                    "amcache entries are OS-registered executables"
                );
                // SHA1, when present, is exactly 40 lowercase hex chars.
                if let Some(h) = &e.sha1 {
                    assert_eq!(h.len(), 40, "sha1 must be 40 hex chars");
                    assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
                }
            } else {
                panic!("amcache must only emit Execution records");
            }
        }
        eprintln!("amcache_e2e_real_hive: parsed {} entries", recs.len());
    }
```

- [ ] **Step 2: Verify it compiles and is correctly ignored**

Run: `cargo test -p cairn-collectors amcache`
Expected: PASS for the non-ignored tests; the e2e shows as `ignored`. Confirm the
output lists `amcache_e2e_real_hive ... ignored`.

- [ ] **Step 3: Full-workspace gate + commit**

```bash
cargo test --workspace
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
git add crates/cairn-collectors/src/amcache.rs
git commit -m "test(amcache): ignored elevated e2e for the full real-hive chain

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final acceptance (after all tasks)

- `cargo test --workspace` green (expect prior count + ~13 new amcache tests; the
  amcache e2e + the usn/shimcache e2e remain `ignored`).
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `Cargo.lock` UNCHANGED (zero new dependencies — notatin already present).
- Schema UNCHANGED (`record.rs` untouched).
- `#![forbid(unsafe_code)]` intact in `cairn-collectors` (zero new unsafe).
- `--profile minimal` excludes amcache; standard/verbose include it.

## Known residuals (documented, not defects)

1. **O(n²) enumeration + per-entry full-path re-traversal** — two stacked costs:
   (a) `get_sub_key_by_index` re-parses the offset list on every call; (b) each entry
   then calls `get_value_string` 3× (LowerCaseLongPath/Name/FileId), and each of those
   does a fresh `get_key(full_subkey_path, false)` traverse from root. So per entry =
   1 index lookup + up to 3 full-path traversals. Acceptable for ~1k–5k entries on a
   one-shot single-host run (seconds, not minutes). If the elevated e2e (Task 6) shows
   this is too slow, the upgrade is `ParserIterator::new(&parser).with_filter(filter)`
   with a `FilterBuilder::new().add_key_path("Root\\InventoryApplicationFile")` scope:
   one O(n) pass yielding each child `CellKeyNode` with its values already in hand (no
   re-traversal). That API needs its own verification pass; keep the simple, fully
   -verified path for THIS segment and measure first.
2. **key-absent vs empty conflation** — list_subkeys returning empty is treated as
   key-absent for the manifest signal. A populated host always has entries, so empty in
   practice means the structure is unsupported (NFR12 build variance). The manifest says
   "absent" which is the honest, actionable signal for the analyst.
3. **notatin panic on the enumeration path is not wrapped in catch_unwind** — identical
   to shimcache's get_value_bytes call site (also outside open_hive's umbrella). Risk is
   lower than blob parsing (get_sub_key_by_index returns Option, strict 0..n bound).
