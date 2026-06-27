# Amcache InventoryDriverBinary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `AmcacheCollector` to also emit `Record::Execution` (source="amcache_driver") for `Amcache.hve` InventoryDriverBinary entries (driver path + SHA1), via a spec-driven helper shared with the existing InventoryApplicationFile path.

**Architecture:** Refactor the hard-coded-InventoryApplicationFile `collect` into a `collect_inventory(parser, spec, key_absent_flag, entry_err_flag)` helper driven by a pure-data `InventorySpec`. Call it twice (APP_FILE_SPEC, DRIVER_SPEC) against one `open_hive`. Path selection is a pure `extract_path` function. No new file, no new dependency, no selection/CLI wiring change, schema unchanged.

**Tech Stack:** Rust, notatin 1.0.1, existing `VolumeReader` + `hive_reader` primitives, `cairn-collectors` (`#![forbid(unsafe_code)]`).

**Authoritative spec:** `docs/superpowers/specs/2026-06-21-amcache-driver-design.md`

---

## Context for the implementer (read before Task 1)

This EXTENDS the just-merged amcache collector (PR #21). You are refactoring then
extending `crates/cairn-collectors/src/amcache.rs`. Study it first — particularly:
- The current `collect` (lines ~52–141): privilege gate → open_hive → truncated/log
  handling → `list_subkeys(INVENTORY_APP_FILE_KEY)` → empty-check sets `key_absent`
  and early-returns → per-subkey graceful `read` closure → path fallback → SHA1 →
  `Record::Execution` push → sort by path.
- The current consts: `INVENTORY_APP_FILE_KEY`, `VALUE_PATH`, `VALUE_NAME`,
  `VALUE_FILE_ID`. These get REPLACED by `InventorySpec` consts.
- The current struct flags: `abstained_truncated`, `key_absent`, `log_replay_failed`,
  `entry_read_errors`. `key_absent` gets SPLIT into `app_key_absent` + `driver_key_absent`.
- `parse_sha1_from_fileid` (pure, reused unchanged for DriverId).
- `sources()` (lines ~143–175): surfaces each flag. Gets a second key-absent message.
- The `#[ignore]` elevated e2e at the end.

### Reused primitives (no change needed)
- `hive_reader::list_subkeys(parser, key_path) -> Result<Vec<SubKey>>` (has the
  SUBKEY_PREALLOC_CAP DoS guard).
- `hive_reader::get_value_string(parser, key_path, value_name) -> Result<Option<String>>`.
- `hive_reader::open_hive`, `LogStatus`, `AMCACHE_HIVE`.

### Amcache format confidence (honest)
`DriverId` = "0000"+40hex SHA1 is high-confidence (same as FileId; reuse
`parse_sha1_from_fileid`). `Root\InventoryDriverBinary` (key) and `DriverName` (path
value) are MEDIUM-confidence Amcache format facts, isolated in `DRIVER_SPEC` (single
fix-point); the elevated e2e is the final verification.

### Standing constraints (every task)
- `#![forbid(unsafe_code)]` in cairn-collectors. Zero new unsafe.
- Never panic in non-test code (golden rule 8).
- Schema UNCHANGED — do not touch record.rs.
- Determinism: sort by path (NFR4).
- Commit footer EXACTLY: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Before each commit: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` (NOT `-p`). Local clippy MUST use `--all-targets` (matches CI).

---

## Task 1: InventorySpec + extract_path pure function

**Files:**
- Modify: `crates/cairn-collectors/src/amcache.rs`

Add the data type + the pure path-selection function with tests. Do NOT wire them into
`collect` yet (Task 2 does the refactor). They will be unused after this task — add a
TEMPORARY `#[allow(dead_code)]` to `InventorySpec` and `first_non_empty`, removed in Task 2.

NOTE on the design: the path-selection function is `first_non_empty(&[Option<String>])`,
NOT a closure-taking `extract_path`. Reason: in Task 2 the value read borrows `&mut parser`
inside a `read` closure; wrapping that closure inside ANOTHER closure passed to an
`extract_path(values, closure)` would double-borrow `parser` (and the read-Err flag) and
fail the borrow checker. Instead `collect_inventory` reads the candidate values into a
small `Vec<Option<String>>` first (handling read-Err there), then calls this pure
selector. Pure data in, pure answer out — trivially testable, no borrow tangle.

- [ ] **Step 1: Write the failing tests**

In `amcache.rs` `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn first_non_empty_returns_first_non_empty_in_order() {
        let candidates = vec![Some(String::new()), Some(r"C:\drivers\x.sys".to_string())];
        assert_eq!(first_non_empty(&candidates).as_deref(), Some(r"C:\drivers\x.sys"));
    }

    #[test]
    fn first_non_empty_all_empty_or_absent_is_none() {
        let candidates = vec![Some(String::new()), None];
        assert_eq!(first_non_empty(&candidates), None);
    }

    #[test]
    fn first_non_empty_single_value() {
        let candidates = vec![Some(r"C:\d.sys".to_string())];
        assert_eq!(first_non_empty(&candidates).as_deref(), Some(r"C:\d.sys"));
    }

    #[test]
    fn first_non_empty_empty_slice_is_none() {
        let candidates: Vec<Option<String>> = vec![];
        assert_eq!(first_non_empty(&candidates), None);
    }
```

- [ ] **Step 2: Run, confirm FAIL**

Run: `cargo test -p cairn-collectors amcache::tests::first_non_empty`
Expected: FAIL (compile error — `first_non_empty` not defined).

- [ ] **Step 3: Add the InventorySpec type + first_non_empty**

After the existing `parse_sha1_from_fileid` fn (or near the top consts) in `amcache.rs`,
add:

```rust
/// A pure-data description of one Amcache inventory key, so one helper can serve both
/// InventoryApplicationFile and InventoryDriverBinary (and future keys) — the only
/// difference between them is data, not logic.
#[allow(dead_code)] // wired in Task 2
struct InventorySpec {
    /// notatin key path (key_path_has_root = false).
    key_path: &'static str,
    /// ExecutionRecord.source tag for entries from this key.
    source: &'static str,
    /// REG_SZ value holding the "0000"+40hex SHA1.
    sha1_value: &'static str,
    /// Path candidates, tried in order; first non-empty wins, else the entry is dropped.
    path_values: &'static [&'static str],
}

/// Return the first non-empty string from a slice of already-read candidates (in
/// order). All empty/absent → None (the caller drops the entry). Pure — the values are
/// read by the caller, so this is unit-testable without a hive and has no borrow tangle.
#[allow(dead_code)] // wired in Task 2
fn first_non_empty(candidates: &[Option<String>]) -> Option<String> {
    candidates
        .iter()
        .flatten()
        .find(|v| !v.is_empty())
        .cloned()
}
```

- [ ] **Step 4: Run, confirm PASS**

Run: `cargo test -p cairn-collectors amcache::tests::first_non_empty`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint + format + commit**

```bash
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add crates/cairn-collectors/src/amcache.rs
git commit -m "feat(amcache): InventorySpec + pure extract_path helper

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Refactor collect to spec-driven helper (app behavior unchanged)

**Files:**
- Modify: `crates/cairn-collectors/src/amcache.rs`

Refactor the existing `collect` to call a new `collect_inventory` helper with
`APP_FILE_SPEC`. Behavior for the app path MUST be identical — the existing tests are
the zero-regression proof. This task does NOT add the driver key yet.

- [ ] **Step 1: Replace the four value consts with APP_FILE_SPEC**

Remove `INVENTORY_APP_FILE_KEY`, `VALUE_PATH`, `VALUE_NAME`, `VALUE_FILE_ID`. Add:

```rust
const APP_FILE_SPEC: InventorySpec = InventorySpec {
    key_path: "Root\\InventoryApplicationFile",
    source: "amcache",
    sha1_value: "FileId",
    path_values: &["LowerCaseLongPath", "Name"],
};
```

- [ ] **Step 2: Add the collect_inventory helper**

Add this free function (after `extract_path`):

```rust
/// Enumerate one inventory key's subkeys into Record::Execution. Shared by both the
/// InventoryApplicationFile and InventoryDriverBinary specs.
///
/// Flags: `key_absent` is set (by the caller-supplied &AtomicBool) when the key has no
/// subkeys (build variance abstain); `entry_err` is set when a per-subkey value read
/// fails (that entry is skipped, the rest continue — golden rule 8). The helper knows
/// only "two flags", not which spec they belong to.
fn collect_inventory(
    parser: &mut notatin::parser::Parser,
    spec: &InventorySpec,
    key_absent: &std::sync::atomic::AtomicBool,
    entry_err: &std::sync::atomic::AtomicBool,
) -> Result<Vec<Record>> {
    let subkeys = list_subkeys(parser, spec.key_path)?;
    if subkeys.is_empty() {
        key_absent.store(true, Ordering::Relaxed);
        tracing::warn!(key = spec.key_path, "amcache: inventory key absent/empty; abstaining");
        return Ok(Vec::new());
    }

    let mut records: Vec<Record> = Vec::new();
    'subkeys: for sk in subkeys {
        let key_path = format!("{}\\{}", spec.key_path, sk.name);
        // Read one value, degrading gracefully: a genuine mid-hive read Err on ONE
        // subkey returns Err here so the caller can skip the entry (flag + continue),
        // never aborting the whole collect (golden rule 8). Ok(None) = absent/non-string.
        let mut read = |name: &str| -> Result<Option<String>> {
            match get_value_string(parser, &key_path, name) {
                Ok(v) => Ok(v),
                Err(e) => {
                    entry_err.store(true, Ordering::Relaxed);
                    tracing::warn!(key = %sk.name, err = %e, "amcache: value read error; skipping entry");
                    Err(e)
                }
            }
        };

        // Read every path candidate first (any read Err skips the whole entry), THEN
        // pick the first non-empty via the pure selector. Reading into a Vec first
        // avoids nesting the parser-borrowing `read` closure inside another closure.
        let mut path_candidates: Vec<Option<String>> = Vec::with_capacity(spec.path_values.len());
        for name in spec.path_values {
            match read(name) {
                Ok(v) => path_candidates.push(v),
                Err(_) => continue 'subkeys, // read Err — entry skipped (flag already set)
            }
        }
        let path = match first_non_empty(&path_candidates) {
            Some(p) => p,
            None => continue 'subkeys, // no path = no evidence; local best-effort drop
        };

        let sha1 = match read(spec.sha1_value) {
            Err(_) => continue 'subkeys, // read Err — entry skipped
            Ok(opt) => opt.and_then(|id| parse_sha1_from_fileid(&id)),
        };

        records.push(Record::Execution(ExecutionRecord {
            source: spec.source.into(),
            path,
            first_run: Some(sk.last_write),
            last_run: None,
            run_count: None,
            sha1,
            user_sid: None,
            execution_confirmed: Some(true),
        }));
    }
    Ok(records)
}
```

NOTE on the read flow: `read` now returns `Result<Option<String>>` — `Err` means a
genuine hive read failure (skip the entry, golden rule 8), `Ok(None)` means the value
is absent/non-string (normal). The path candidates are read into a `Vec` first, then
`first_non_empty` (the pure selector) picks the winner. This keeps the pure selector
testable AND avoids the borrow tangle of nesting the `read` closure (which borrows
`&mut parser`) inside another closure. Preserves PR #21's per-subkey error contract.

- [ ] **Step 3: Rewrite collect body to call the helper**

Replace the body from `let subkeys = list_subkeys(...)` through the sort (the part
AFTER the truncated/log_status handling) with:

```rust
        // Set by collect_inventory when InventoryApplicationFile has no subkeys.
        let mut records = collect_inventory(
            &mut opened.parser,
            &APP_FILE_SPEC,
            &self.app_key_absent,
            &self.entry_read_errors,
        )?;

        // Determinism (NFR4): subkey enumeration order is physical; sort by path.
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => x.path.cmp(&y.path),
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution is emitted above
        });

        tracing::info!(amcache_entries = records.len(), "amcache scan");
        Ok(records)
```

(The privilege gate, `VolumeReader::open`, `open_hive`, truncated check, and
`LogStatus::Failed` check stay exactly as they are above this block.)

- [ ] **Step 4: Rename the struct flag `key_absent` → `app_key_absent`**

In the struct definition change `key_absent: AtomicBool,` to:
```rust
    /// The InventoryApplicationFile key was absent (build variance — abstained). NFR12.
    app_key_absent: AtomicBool,
```

- [ ] **Step 5: Update sources() for the renamed flag**

In `sources()`, change the `self.key_absent` block to `self.app_key_absent` (message
text unchanged — still "InventoryApplicationFile key absent ...").

- [ ] **Step 6: Update the existing surface test name + field**

Rename test `sources_reports_key_absent_abstain` → `sources_reports_app_key_absent`
and change `c.key_absent.store(...)` to `c.app_key_absent.store(...)`. Assertion text
unchanged ("InventoryApplicationFile key absent").

- [ ] **Step 7: Remove the Task-1 dead_code allows**

`InventorySpec` and `first_non_empty` are now used by `collect_inventory`. Remove both
`#[allow(dead_code)]`. `cargo clippy --all-targets -D warnings` must stay clean.

- [ ] **Step 8: Run the FULL existing suite — zero regression proof**

Run: `cargo test -p cairn-collectors amcache`
Expected: ALL existing amcache tests still pass (the refactor changed structure, not
app behavior). This is the acceptance gate for Task 2.

- [ ] **Step 9: Workspace gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/amcache.rs
git commit -m "refactor(amcache): spec-driven collect_inventory helper (app behavior unchanged)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Add DRIVER_SPEC + second helper call + driver_key_absent flag

**Files:**
- Modify: `crates/cairn-collectors/src/amcache.rs`

Now add the driver key. The helper already exists; this task adds the spec, the second
call, the second key-absent flag, and the driver surface test.

- [ ] **Step 1: Add the driver_key_absent flag to the struct**

After `app_key_absent`, add:
```rust
    /// The InventoryDriverBinary key was absent (build variance — abstained). NFR12.
    driver_key_absent: AtomicBool,
```

- [ ] **Step 2: Add the driver surface test (failing)**

In `mod tests`, add:
```rust
    #[test]
    fn sources_reports_driver_key_absent() {
        let c = AmcacheCollector::default();
        c.driver_key_absent.store(true, Ordering::Relaxed);
        let s = c.sources();
        assert!(s[0]
            .errors
            .iter()
            .any(|e| e.contains("InventoryDriverBinary key absent")));
    }
```

- [ ] **Step 3: Run, confirm FAIL**

Run: `cargo test -p cairn-collectors amcache::tests::sources_reports_driver_key_absent`
Expected: FAIL (the message isn't emitted yet).

- [ ] **Step 4: Add DRIVER_SPEC const**

After `APP_FILE_SPEC`, add:
```rust
const DRIVER_SPEC: InventorySpec = InventorySpec {
    key_path: "Root\\InventoryDriverBinary",
    source: "amcache_driver",
    sha1_value: "DriverId",
    path_values: &["DriverName"],
};
```

- [ ] **Step 5: Add the second helper call in collect**

In `collect`, after the `APP_FILE_SPEC` call (which assigns `records`) and BEFORE the
sort, append the driver records:
```rust
        // Driver binaries (BYOVD evidence). Independent per-key degrade: an absent
        // driver key does NOT suppress the app records already collected, and vice versa.
        let driver_records = collect_inventory(
            &mut opened.parser,
            &DRIVER_SPEC,
            &self.driver_key_absent,
            &self.entry_read_errors,
        )?;
        records.extend(driver_records);
```

(The sort now orders the combined app+driver set by path.)

- [ ] **Step 6: Add the driver_key_absent message to sources()**

After the `app_key_absent` block in `sources()`, add:
```rust
        if self.driver_key_absent.load(Ordering::Relaxed) {
            errors.push(
                "abstained: InventoryDriverBinary key absent (build variance/NFR12)".to_string(),
            );
        }
```

- [ ] **Step 7: Run, confirm PASS**

Run: `cargo test -p cairn-collectors amcache`
Expected: all pass (existing + the new driver surface test).

- [ ] **Step 8: Workspace gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/amcache.rs
git commit -m "feat(amcache): parse InventoryDriverBinary (source=amcache_driver, BYOVD)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Extend the elevated e2e to cover driver records

**Files:**
- Modify: `crates/cairn-collectors/src/amcache.rs`

- [ ] **Step 1: Extend the ignored e2e**

In the existing `#[ignore]` e2e test (`amcache_e2e_real_system_hive`), the per-record
loop currently asserts the contract for every record. Make the source assertion accept
both sources and verify the driver-specific contract. Replace the `assert_eq!(e.source, "amcache")`
line with:
```rust
                assert!(
                    e.source == "amcache" || e.source == "amcache_driver",
                    "unexpected source: {}",
                    e.source
                );
```
The remaining per-record assertions (non-empty path, last_run None, sha1 40-lowercase-hex
when present, execution_confirmed Some(true), first_run Some) already apply to both
sources and need no change. Add, after the loop, an informational driver count:
```rust
        let drivers = recs
            .iter()
            .filter(|r| matches!(r, Record::Execution(e) if e.source == "amcache_driver"))
            .count();
        eprintln!("amcache_e2e_real_system_hive: {} driver entries", drivers);
```
Do NOT hard-require `drivers > 0` (a freshly-imaged VM may have few); the per-record
loop already validates any that exist.

- [ ] **Step 2: Verify it compiles + is ignored**

Run: `cargo test -p cairn-collectors amcache`
Expected: non-ignored tests pass; `amcache_e2e_real_system_hive ... ignored`.

- [ ] **Step 3: Final workspace gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/amcache.rs
git commit -m "test(amcache): extend elevated e2e to cover amcache_driver records

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final acceptance (after all tasks)

- `cargo test --workspace` green (existing count + ~5 new: 4 first_non_empty + 1 driver
  surface; the e2e stays ignored).
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `Cargo.lock` UNCHANGED (zero new deps). Schema UNCHANGED (record.rs untouched).
- `#![forbid(unsafe_code)]` intact (zero new unsafe).
- NO selection.rs / main.rs change (amcache already wired; driver is the same
  collector emitting a second source).
- App-section behavior unchanged (zero regression — existing tests green after Task 2).

## Known residuals (documented, not defects)

1. **Driver key/value name confidence** — `Root\InventoryDriverBinary` + `DriverName`
   are medium-confidence Amcache format facts, isolated in `DRIVER_SPEC`. The elevated
   e2e is the final field verification; a wrong const is a one-line fix.
2. **Inherited from PR #21** — O(n²) enumeration + per-entry full-path re-traversal;
   key-absent vs empty conflation (now per-key); notatin panic on the enumeration path
   outside catch_unwind. All documented in the predecessor; unchanged here.
3. **No signature field** — driver signed/signer not captured (schema unchanged);
   BYOVD detection delegated to downstream SHA1 ↔ LOLDrivers matching.
