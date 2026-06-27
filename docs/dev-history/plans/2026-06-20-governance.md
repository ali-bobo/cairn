# Governance (NFR9/NFR10) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install resource guard-rails (thread cap, below-normal priority on live, profile→light-mode linkage, manifest-visible mft truncation) so the heavier raw-NTFS collectors can later run on a live host without taking it down.

**Architecture:** A `Governance` sub-struct on `Config` holds the two pure knobs (`max_threads`, `low_priority`); a pure `resolve_max_threads` picks the effective count; `normalize_for_profile` links `minimal`→`resolve_mft_paths=false`. A new `priority` module in `cairn-collectors-win` (the only unsafe) lowers the process's own CPU/IO priority best-effort. `MftCollector` gains an `AtomicBool` truncation flag surfaced via the existing `SourceEntry.errors` and a new `GovernanceReport`/`Truncation` manifest block. The cli `run` path wires `--max-threads`/`--full-speed`, calls `build_global` once, lowers priority for live, and assembles the report.

**Tech Stack:** Rust, `rayon` (already a dep), `windows` 0.62.2 (already a dep, collectors-win only), `serde`, `thiserror`. No new dependencies.

Design reference: `docs/superpowers/specs/2026-06-20-governance-design.md`.

Build/test (run from repo root `cairn/`):
- `cargo test -p <crate> --locked` for a single crate's acceptance.
- `cargo test --workspace --locked` for the full gate.
- `cargo clippy --workspace --locked -- -D warnings` and `cargo fmt --check` at the end.
- Cargo target dir is set in `.cargo/config.toml` (out of OneDrive); do NOT change it.

---

## File Structure

- `crates/cairn-core/src/config.rs` — add `Governance`, `resolve_max_threads`, `Config.governance`, `Config::normalize_for_profile`. (T1)
- `crates/cairn-core/src/manifest.rs` — add `GovernanceReport`, `Truncation`, `Manifest.governance`. (T2)
- `crates/cairn-core/src/lib.rs` — re-export `Governance` and `resolve_max_threads` if other crates need them (check existing re-export style). (T1)
- `crates/cairn-collectors-win/src/priority.rs` — NEW: `lower_priority()` Windows impl + non-Windows stub. (T3)
- `crates/cairn-collectors-win/src/lib.rs` — add `pub mod priority;`. (T3)
- `crates/cairn-collectors/src/mft.rs` — `parse_mft_records`/`parse_mft_inner` return `(u64, bool, Vec<..>)`; `MftCollector` gains `AtomicBool`; `sources()` appends a truncation error. (T4)
- `crates/cairn-cli/src/main.rs` — `--max-threads`/`--full-speed` args, `build_global`, priority call, `GovernanceReport` assembly into the manifest. (T5)

---

## Task 1: Governance data model (cairn-core, pure)

**Files:**
- Modify: `crates/cairn-core/src/config.rs`
- Modify: `crates/cairn-core/src/lib.rs` (re-export, mirror existing pattern)

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block at the bottom of `config.rs`:

```rust
#[test]
fn governance_defaults_are_uncapped_and_normal_priority() {
    let cfg = Config::default();
    assert_eq!(cfg.governance.max_threads, None);
    assert!(!cfg.governance.low_priority);
}

#[test]
fn resolve_max_threads_none_uses_min_cores_ceiling() {
    // None → min(available, 8). available=4 → 4; available=32 → 8 (ceiling).
    assert_eq!(resolve_max_threads(None, 4), 4);
    assert_eq!(resolve_max_threads(None, 32), 8);
    assert_eq!(resolve_max_threads(None, 8), 8);
}

#[test]
fn resolve_max_threads_zero_is_treated_as_default() {
    // Some(0) is meaningless; fall back to the None default.
    assert_eq!(resolve_max_threads(Some(0), 16), 8);
}

#[test]
fn resolve_max_threads_explicit_never_exceeds_available() {
    assert_eq!(resolve_max_threads(Some(2), 16), 2);
    assert_eq!(resolve_max_threads(Some(1000), 16), 16); // clamped to cores
    assert_eq!(resolve_max_threads(Some(4), 4), 4);
}

#[test]
fn resolve_max_threads_never_returns_zero() {
    // available could be reported as 0 in pathological cases; result must be >= 1.
    assert!(resolve_max_threads(None, 0) >= 1);
    assert!(resolve_max_threads(Some(0), 0) >= 1);
}

#[test]
fn normalize_for_profile_minimal_disables_path_resolution() {
    let mut cfg = Config::default();
    cfg.profile = Profile::Minimal;
    assert!(cfg.resolve_mft_paths, "default starts true");
    cfg.normalize_for_profile();
    assert!(!cfg.resolve_mft_paths, "minimal must force false");
    // idempotent
    cfg.normalize_for_profile();
    assert!(!cfg.resolve_mft_paths);
}

#[test]
fn normalize_for_profile_standard_and_verbose_leave_path_resolution() {
    for p in [Profile::Standard, Profile::Verbose] {
        let mut cfg = Config::default();
        cfg.profile = p;
        cfg.resolve_mft_paths = true;
        cfg.normalize_for_profile();
        assert!(cfg.resolve_mft_paths, "{p:?} must not disable resolution");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-core --locked config::`
Expected: FAIL — `Governance` / `resolve_max_threads` / `governance` field / `normalize_for_profile` not defined.

- [ ] **Step 3: Implement the data model**

In `config.rs`, add the `Governance` struct (place it after the `Profile` impl, before `OutputKind`):

```rust
/// Resource-governance knobs (NFR9). Grouped so the resource posture is one object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Governance {
    /// rayon global pool ceiling. None = default min(cores, MAX_THREADS_CEILING)
    /// (NFR9: not all cores). Some(n>0) = explicit `--max-threads N` (clamped to
    /// real cores by `resolve_max_threads`). Some(0) is treated as None.
    pub max_threads: Option<usize>,
    /// Lower this process's CPU + IO priority. Default true for a live target,
    /// false for offline analysis. `--full-speed` forces false for any target.
    pub low_priority: bool,
}

impl Default for Governance {
    fn default() -> Self {
        // Default serves the offline/evtx path: uncapped (resolver picks the
        // ceiling) and normal priority. The live run path flips low_priority true.
        Governance {
            max_threads: None,
            low_priority: false,
        }
    }
}

/// NFR9 "sane ceiling, not all cores": the default rayon pool size is capped here
/// even on a many-core box, leaving headroom for the production workload.
pub const MAX_THREADS_CEILING: usize = 8;

/// Effective rayon thread count. Pure; no global state, so it is unit-testable.
/// - None / Some(0) → min(available, MAX_THREADS_CEILING)
/// - Some(n>0)      → min(n, available)  (never exceed real cores)
/// Always returns >= 1 (a 0 `available` is clamped up so rayon gets a valid count).
pub fn resolve_max_threads(requested: Option<usize>, available: usize) -> usize {
    let avail = available.max(1);
    match requested {
        None | Some(0) => avail.min(MAX_THREADS_CEILING),
        Some(n) => n.min(avail),
    }
}
```

Add the field to `Config` (after `resolve_mft_paths`):

```rust
    /// Resource governance (NFR9): thread cap + priority posture.
    pub governance: Governance,
```

Add to `Config::default()` (after `resolve_mft_paths: true,`):

```rust
            governance: Governance::default(),
```

Add the normalization method to the `impl Config` block (after `with_rules_plain`):

```rust
    /// Apply profile-implied light-mode overrides. Call once after CLI parsing,
    /// before the run. Currently: `minimal` disables full-path reconstruction
    /// (path map is the first enhancement dropped in light mode). Idempotent.
    pub fn normalize_for_profile(&mut self) {
        if self.profile == Profile::Minimal {
            self.resolve_mft_paths = false;
        }
    }
```

Ensure the test module can see `resolve_max_threads` — it is in the same module via
`use super::*;` (already present at the top of `mod tests`), so no extra import.

- [ ] **Step 4: Re-export from lib.rs**

Open `crates/cairn-core/src/lib.rs`, find the existing `pub use crate::config::{...}` (or `pub use config::...`) line, and add `Governance` and `resolve_max_threads` to it, matching the existing style. If `Config`/`Profile` are already re-exported there, append the two new names to the same `use`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-core --locked config::`
Expected: PASS — all seven new tests plus the existing config tests.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-core/src/config.rs crates/cairn-core/src/lib.rs
git commit -m "feat(core): Governance config + resolve_max_threads + normalize_for_profile (governance)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: GovernanceReport in the manifest (cairn-core, pure serde)

**Files:**
- Modify: `crates/cairn-core/src/manifest.rs`

- [ ] **Step 1: Write the failing tests**

Add to `manifest.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn governance_report_round_trips_and_old_json_defaults() {
    use super::{GovernanceReport, Truncation};
    let r = GovernanceReport {
        effective_threads: 8,
        low_priority_applied: true,
        truncations: vec![Truncation {
            collector: "mft".into(),
            cap: 1_000_000,
            reason: "max_mft_records reached".into(),
        }],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: GovernanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.effective_threads, 8);
    assert!(back.low_priority_applied);
    assert_eq!(back.truncations.len(), 1);
    assert_eq!(back.truncations[0].collector, "mft");

    // A GovernanceReport with no truncations omits/defaults the vec.
    let empty: GovernanceReport = serde_json::from_str("{}").unwrap();
    assert_eq!(empty.effective_threads, 0);
    assert!(!empty.low_priority_applied);
    assert!(empty.truncations.is_empty());
}

#[test]
fn manifest_without_governance_field_deserializes() {
    // Pre-governance manifest JSON lacks the `governance` field → defaults.
    let m = sample_manifest();
    let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
    v.as_object_mut().unwrap().remove("governance");
    let back: Manifest = serde_json::from_value(v).unwrap();
    assert_eq!(back.governance.effective_threads, 0);
    assert!(back.governance.truncations.is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-core --locked manifest::`
Expected: FAIL — `GovernanceReport` / `Truncation` / `Manifest.governance` not defined.

- [ ] **Step 3: Implement the manifest types**

In `manifest.rs`, add after the `Counts` struct:

```rust
/// Resource-governance report (NFR9/NFR10): what the run throttled or truncated.
/// Additive; `#[serde(default)]` on the `Manifest` field keeps pre-governance
/// manifests parseable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceReport {
    /// Effective rayon thread count used this run.
    pub effective_threads: usize,
    /// True if the process priority was successfully lowered (live + not --full-speed).
    pub low_priority_applied: bool,
    /// One entry per collector that hit a record cap / circuit breaker.
    #[serde(default)]
    pub truncations: Vec<Truncation>,
}

/// A single circuit-breaker / cap hit, recorded for transparency (NFR10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Truncation {
    pub collector: String, // e.g. "mft"
    pub cap: u64,          // the cap that fired
    pub reason: String,    // e.g. "max_mft_records reached"
}
```

Add the field to `Manifest` (after `integrity_note`):

```rust
    /// Resource-governance report (NFR9/NFR10). Additive; defaults on old JSON.
    #[serde(default)]
    pub governance: GovernanceReport,
```

Update `sample_manifest()` in the test module to construct the new field (add after
`integrity_note: ...,`):

```rust
            governance: GovernanceReport::default(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p cairn-core --locked manifest::`
Expected: PASS — the two new tests plus existing manifest tests (incl. round-trip).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-core/src/manifest.rs
git commit -m "feat(core): GovernanceReport + Truncation manifest block (governance)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Priority wrapper (cairn-collectors-win, the only unsafe)

**Files:**
- Create: `crates/cairn-collectors-win/src/priority.rs`
- Modify: `crates/cairn-collectors-win/src/lib.rs`

- [ ] **Step 1: Write the failing test (non-Windows behaviour + symbol existence)**

Create `crates/cairn-collectors-win/src/priority.rs` with ONLY the test first to
drive the API into existence:

```rust
//! Lower this process's own CPU + IO priority so Cairn yields to production
//! workloads on a live host. Best-effort and benign (golden rules 1 & 8).

use cairn_core::Result;

// (impl added in Step 3)

#[cfg(test)]
mod tests {
    use super::lower_priority;

    #[test]
    fn lower_priority_succeeds_or_degrades_without_panic() {
        // On every platform the call must return without panicking. On non-Windows
        // it is a no-op Ok; on Windows it lowers the calling process's priority and
        // returns Ok on success. We assert it does not panic and yields a Result.
        let r = lower_priority();
        // We do not assert Ok unconditionally on Windows CI (a sandbox could deny
        // it); the contract is "never panic, return a Result". A non-Windows build
        // MUST be Ok.
        #[cfg(not(windows))]
        assert!(r.is_ok(), "non-Windows lower_priority must be a no-op Ok");
        #[cfg(windows)]
        let _ = r; // Windows: success not guaranteed in all sandboxes; no panic is the contract.
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

First add `pub mod priority;` to `crates/cairn-collectors-win/src/lib.rs` (after
`pub mod net;` or in the existing alphabetical-ish list).

Run: `cargo test -p cairn-collectors-win --locked priority::`
Expected: FAIL to compile — `lower_priority` not defined.

- [ ] **Step 3: Implement the wrapper**

Replace the `// (impl added in Step 3)` line with the platform impls.

Non-Windows stub:

```rust
#[cfg(not(windows))]
pub fn lower_priority() -> Result<()> {
    // No live host to yield to on an analyst's non-Windows box. No-op success.
    Ok(())
}
```

Windows impl:

```rust
#[cfg(windows)]
pub fn lower_priority() -> Result<()> {
    use cairn_core::CairnError;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS,
        PROCESS_MODE_BACKGROUND_BEGIN,
    };

    // SAFETY: GetCurrentProcess returns a pseudo-handle that must NOT be closed.
    // SetPriorityClass only reads the handle and returns a BOOL we check; nothing
    // is dereferenced or freed. Lowering our OWN priority needs no privilege and
    // touches no other process or host artifact (golden rule 3).
    let h = unsafe { GetCurrentProcess() };

    // Lower CPU priority.
    unsafe { SetPriorityClass(h, BELOW_NORMAL_PRIORITY_CLASS) }.map_err(|e| {
        CairnError::Collector {
            collector: "priority".into(),
            reason: format!("SetPriorityClass(BELOW_NORMAL): {e}"),
        }
    })?;

    // Enter background IO mode (also lowers IO priority for this process).
    unsafe { SetPriorityClass(h, PROCESS_MODE_BACKGROUND_BEGIN) }.map_err(|e| {
        CairnError::Collector {
            collector: "priority".into(),
            reason: format!("SetPriorityClass(BACKGROUND_BEGIN): {e}"),
        }
    })?;

    Ok(())
}
```

NOTE TO IMPLEMENTER: `windows` 0.62 may path these symbols slightly differently
(e.g. the constants may be associated consts of `PROCESS_CREATION_FLAGS`, or
`SetPriorityClass` may take a `PROCESS_CREATION_FLAGS` arg rather than a bare
constant). If `cargo check` errors on a symbol path or arg type, fix the import /
wrap the constant accordingly — the SAFETY contract and the two-call structure
(lower CPU, then background IO) are the invariant, not the exact symbol spelling.
Confirm the final symbols compile before moving on; do NOT guess and leave it red.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p cairn-collectors-win --locked priority::`
Expected: PASS. On a Linux CI runner this exercises the stub; the Windows CI job
exercises the real call.

- [ ] **Step 5: Verify the unsafe boundary holds**

Run: `cargo clippy -p cairn-collectors-win --locked -- -D warnings`
Expected: no warnings. Confirm every `unsafe` block in `priority.rs` carries a
`// SAFETY:` comment (clippy `undocumented_unsafe_blocks` is not on by default, so
this is a manual check — the reviewer will verify).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors-win/src/priority.rs crates/cairn-collectors-win/src/lib.rs
git commit -m "feat(collectors-win): below-normal priority wrapper, best-effort (governance)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: mft truncation flag (cairn-collectors)

**Files:**
- Modify: `crates/cairn-collectors/src/mft.rs`

Context: `parse_mft_records` (the public, `catch_unwind`-guarded entry) calls
`parse_mft_inner`. Both currently return `Result<(u64, Vec<FileMetaRecord>)>`.
`parse_mft_inner` computes `ceiling = capacity.min(max_records)` and has two return
points: the `scan_bare` fallback (`!resolve_paths`) and the two-phase path. We add a
`truncated: bool` (= `capacity > max_records`) as the middle tuple element at BOTH
return points, thread it through the `catch_unwind` wrapper, and store it on the
collector for `sources()` to surface.

- [ ] **Step 1: Write the failing tests**

The module's tests do NOT use a single reader helper; they feed synthetic bytes via
`std::io::Cursor`. Most synthetic inputs make `Ntfs::new` fail (short/garbage), so
they never reach the `capacity` computation where `truncated` is decided. The ONE
fixture that DOES parse successfully is `write_boot_sector` (defined at ~line 514):
it writes a valid NTFS boot sector declaring a huge volume, so `Ntfs::new` succeeds,
`capacity` is large, and the scan returns `Ok((capacity, .., records))` with empty
`records` (the garbage MFT body is skipped per-record). The existing test
`record_cap_truncates_without_panic` (~line 526) already uses it. Mirror that fixture.

Add to `mft.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn truncated_true_when_capacity_exceeds_cap() {
    // Huge declared volume → huge capacity; a tiny cap bounds the scan → truncated.
    const BUF: usize = 1024 * 1024;
    let mut buf = vec![0u8; BUF];
    write_boot_sector(&mut buf, (BUF as u64 / 512).saturating_sub(1), 4);
    let mut cur = std::io::Cursor::new(buf);
    let (capacity, truncated, _records) =
        parse_mft_records(&mut cur, 8, false).expect("valid boot sector parses");
    assert!(capacity > 8, "synthetic volume capacity must exceed the cap");
    assert!(truncated, "cap=8 below capacity must report truncation");
}

#[test]
fn truncated_false_when_cap_above_capacity() {
    const BUF: usize = 1024 * 1024;
    let mut buf = vec![0u8; BUF];
    write_boot_sector(&mut buf, (BUF as u64 / 512).saturating_sub(1), 4);
    let mut cur = std::io::Cursor::new(buf);
    let (capacity, truncated, _records) =
        parse_mft_records(&mut cur, u64::MAX, false).expect("valid boot sector parses");
    assert!(!truncated, "cap above capacity ({capacity}) must not report truncation");
}
```

IMPLEMENTER: also update EVERY existing `parse_mft_records(...)` call site in this
module (both tests AND the `MftCollector::collect` body at ~line 145) to destructure
the new 3-tuple. The existing call sites and their lines (verify by grep, they may
shift): tests at ~427, ~437, ~480, ~536, ~544, ~657, ~659 — most ignore the result
or only check `is_err()`, so they need `let (_a, _t, _b) = ...` only where they bind
the tuple. The `is_err()`-only sites need no change. The explicit type annotation at
~544 (`Result<(u64, Vec<FileMetaRecord>)>`) MUST become `Result<(u64, bool, Vec<FileMetaRecord>)>`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-collectors --locked mft::`
Expected: FAIL to compile — `parse_mft_records` returns a 2-tuple, tests expect 3.

- [ ] **Step 3: Thread `truncated` through the return types**

Change `parse_mft_inner`'s signature and both return points:

```rust
fn parse_mft_inner<R: Read + Seek>(
    src: &mut R,
    max_records: u64,
    resolve_paths: bool,
) -> Result<(u64, bool, Vec<FileMetaRecord>)> {
    let ntfs = Ntfs::new(src).map_err(|e| mft_err(format!("Ntfs::new failed: {e}")))?;
    let file_record_size = ntfs.file_record_size() as u64;
    let capacity = ntfs.size().checked_div(file_record_size).unwrap_or(0);
    let ceiling = capacity.min(max_records);
    let truncated = capacity > max_records;

    if !resolve_paths {
        return Ok((capacity, truncated, scan_bare(src, &ntfs, ceiling)));
    }

    // ... phase 1 + phase 2 unchanged ...

    Ok((capacity, truncated, out))
}
```

Change `parse_mft_records`'s signature and the `catch_unwind` handling so the
3-tuple is threaded through (find the existing `catch_unwind` block; it currently
returns `Result<(u64, Vec<FileMetaRecord>)>`):

```rust
pub(crate) fn parse_mft_records<R: Read + Seek>(
    src: &mut R,
    max_records: u64,
    resolve_paths: bool,
) -> Result<(u64, bool, Vec<FileMetaRecord>)> {
    // ... existing 512-byte guard (a) unchanged ...
    // ... existing catch_unwind around parse_mft_inner, now carrying the 3-tuple ...
}
```

(The `catch_unwind` closure already returns whatever `parse_mft_inner` returns; only
the outer type annotation changes. Keep both DoS guards intact.)

- [ ] **Step 4: Add the AtomicBool to MftCollector and surface it in sources()**

Change the struct:

```rust
use std::sync::atomic::{AtomicBool, Ordering};

/// ... existing doc ...
#[derive(Default)]
pub struct MftCollector {
    /// Set by `collect` when the scan stopped at the record cap rather than the
    /// volume's true record count. Read by `sources()`. AtomicBool (not Cell)
    /// because `Collector: Send + Sync`.
    truncated: AtomicBool,
}
```

In `collect`, destructure the new tuple and store the flag (replace the existing
`let (capacity, records) = parse_mft_records(...)?;` line and the tracing call):

```rust
        let (capacity, truncated, records) = parse_mft_records(&mut reader, cap, resolve_paths)?;
        self.truncated.store(truncated, Ordering::Relaxed);

        tracing::info!(
            mft_capacity_estimate = capacity,
            records_emitted = records.len(),
            record_cap = cap,
            truncated,
            "mft scan"
        );
```

In `sources()`, append a structured error when truncated (replace the `errors: vec![]`):

```rust
    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.truncated.load(Ordering::Relaxed) {
            errors.push("truncated: max_mft_records reached".to_string());
        }
        vec![SourceEntry {
            artifact: "mft".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-collectors --locked mft::`
Expected: PASS — new truncation tests + all existing mft tests (now destructuring 3-tuples).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/mft.rs
git commit -m "feat(collectors): mft surfaces record-cap truncation (governance NFR10)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: CLI wiring (cairn-cli)

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

Context: `RunArgs` is the clap struct for the `run` subcommand. The live run path
already calls `select_modules(profile, only, AVAILABLE)` and builds a `RunInfo`/
manifest (around lines 580–670). We add two args, resolve+build the rayon pool once,
lower priority for live, and attach a `GovernanceReport` to the manifest.

- [ ] **Step 1: Write the failing test**

Add to `main.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn governance_report_assembles_threads_and_priority() {
    use cairn_core::{resolve_max_threads, manifest::GovernanceReport};
    // Pure assembly logic mirrored: effective_threads from resolver, priority flag
    // from (is_live && !full_speed). This guards the wiring contract without
    // touching the global pool.
    let effective = resolve_max_threads(Some(3), 16);
    let report = GovernanceReport {
        effective_threads: effective,
        low_priority_applied: true,
        truncations: vec![],
    };
    assert_eq!(report.effective_threads, 3);
    assert!(report.low_priority_applied);
}
```

(This is a thin guard; the real wiring is exercised by the e2e. The point is to pin
that the cli depends on `resolve_max_threads` + `GovernanceReport` and they compose.)

- [ ] **Step 2: Run test to verify it fails (or compiles trivially)**

Run: `cargo test -p cairn-cli --locked governance_report_assembles`
Expected: PASS only after the `use` paths resolve; if `GovernanceReport` is not yet
re-exported under `cairn_core::manifest`, this fails to compile → fix the path.

- [ ] **Step 3: Add the CLI args**

In the `RunArgs` struct add (match the existing `#[arg(long)]` style):

```rust
    /// Cap the rayon worker pool (NFR9). Default: min(cores, 8). 0 = use default.
    #[arg(long)]
    max_threads: Option<usize>,
    /// Do NOT lower process priority on a live run (opt out of below-normal).
    #[arg(long, default_value_t = false)]
    full_speed: bool,
```

- [ ] **Step 4: Wire governance into the run path**

In the live `run` handler, AFTER the `Config` is built and BEFORE collectors run,
add (use the actual local variable names present — `cfg`, the live/target boolean,
`args`):

```rust
    // ── Resource governance (NFR9/NFR10) ──────────────────────────────────────
    let is_live = matches!(cfg.target, cairn_core::Target::Live);
    cfg.governance.max_threads = args.max_threads;
    cfg.governance.low_priority = is_live && !args.full_speed;
    cfg.normalize_for_profile();

    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let effective_threads = cairn_core::resolve_max_threads(cfg.governance.max_threads, available);
    // build_global is a process one-shot; a second call (e.g. in tests) errors — ignore it.
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(effective_threads)
        .build_global();

    let low_priority_applied = if cfg.governance.low_priority {
        match cairn_collectors_win::priority::lower_priority() {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "failed to lower process priority; continuing at normal priority");
                false
            }
        }
    } else {
        false
    };

    let mut governance_report = cairn_core::manifest::GovernanceReport {
        effective_threads,
        low_priority_applied,
        truncations: Vec::new(),
    };
```

IMPLEMENTER: `cfg` must be `mut` for the assignments above; if the existing binding
is `let cfg`, change it to `let mut cfg`. If `cairn_collectors_win` is not yet a
dependency of `cairn-cli`, add it to `crates/cairn-cli/Cargo.toml`
(`cairn-collectors-win = { path = "../cairn-collectors-win" }`) — check whether it is
already there first (it likely is, for proc/net).

- [ ] **Step 5: Attach the report to the manifest**

Find where the `Manifest` is constructed in the run path (the struct literal with
`run: RunInfo { ... }`). Add the new field to that literal:

```rust
        governance: governance_report,
```

If a `Truncation` from mft should be recorded, that happens only once mft is in the
live AVAILABLE set (next segment); for now `truncations` stays empty here. Leave a
one-line comment at the `governance_report` construction:

```rust
    // truncations populated when raw-NTFS collectors (mft) join the live AVAILABLE
    // set (next segment); thread/priority fields are live now.
```

(Make `governance_report` `mut` only if you wire truncation now; otherwise drop the
`mut`.)

- [ ] **Step 6: Run the full crate test + build**

Run: `cargo test -p cairn-cli --locked`
Expected: PASS.
Run: `cargo build -p cairn-cli --locked`
Expected: builds clean.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-cli/src/main.rs crates/cairn-cli/Cargo.toml
git commit -m "feat(cli): --max-threads/--full-speed, capped rayon pool, live priority + report (governance)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final acceptance gate (after all tasks)

- [ ] `cargo fmt --check` — clean (run `cargo fmt` if not).
- [ ] `cargo clippy --workspace --locked -- -D warnings` — zero warnings.
- [ ] `cargo test --workspace --locked` — all green (report the count).
- [ ] `cargo build --workspace --locked` — clean.
- [ ] `git diff main -- Cargo.lock` — confirm Cargo.lock unchanged (no new deps).
- [ ] Confirm `#![forbid(unsafe_code)]` still present in cairn-core, cairn-collectors,
      cairn-heur, cairn-report; the only new `unsafe` is in
      `cairn-collectors-win/src/priority.rs`, each block with a `// SAFETY:` comment.
- [ ] Manifest schema change is additive only (`#[serde(default)]` on `governance`);
      old manifest JSON still deserializes (T2 test proves it).

## Self-review notes (author)

- Spec coverage: §3 data model→T1; §4 priority→T3; §5 resolve_mft_paths→T1
  (`normalize_for_profile`); §6 truncation→T2 (types) + T4 (mft flag) + T5 (report);
  §7 CLI→T5; §8 tests distributed across T1–T5. All spec sections mapped.
- Type consistency: `resolve_max_threads(Option<usize>, usize) -> usize`,
  `parse_mft_records -> (u64, bool, Vec<FileMetaRecord>)`,
  `GovernanceReport { effective_threads: usize, low_priority_applied: bool, truncations: Vec<Truncation> }`
  used identically in every referencing task.
- Placeholder honesty: T4 uses the REAL in-module fixture `write_boot_sector` (the
  one input that parses to a valid NTFS volume), not an invented helper — verified
  against mft.rs. The only remaining "fill in the local name" notes are in T5 (`cfg`/
  `args` binding names in the run handler), flagged explicitly because they depend on
  code the plan author did not transcribe verbatim. No silent TODOs.
- T4 reader caveat: synthetic Cursor inputs that fail `Ntfs::new` never reach the
  `truncated` computation; only `write_boot_sector`-backed buffers do. The truncation
  tests therefore MUST use that fixture (the plan's T4 Step 1 does).
