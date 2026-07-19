# LiveExecHeuristic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new independent `Analyzer` (`heur_live_exec`) that flags live processes
with no execution-artifact history across prefetch/amcache/shimcache, and live
processes whose earliest execution-artifact record is both recent (≤30 days) and
unsigned.

**Architecture:** New file `crates/cairn-heur/src/live_exec.rs`, structured like
`parentchild.rs`/`netconn.rs` (module constants → pure scoring function → zero-field
`Analyzer` struct → unit tests). Reuses the existing three-source
(prefetch/amcache/shimcache) cross-index lookup logic currently private to
`persist.rs`, promoted to `score.rs` so both modules can call it without duplication.
`depends_on()` returns `&[]` — fully independent of other analyzers.

**Tech Stack:** Rust, existing `cairn-core`/`cairn-heur` crates, `chrono` for
date math, existing `Score`/`join_key`/`severity_for` primitives from `score.rs`.

Spec: `docs/dev-history/specs/2026-07-19-live-exec-heuristic-design.md`

---

## Task 1: Promote `CrossIndex` from `persist.rs` to `score.rs`

`persist.rs`'s `CrossIndex`/`build_cross_index` (lines 258-332) is currently a
private struct scoped to that file. `live_exec.rs` needs the exact same
three-source execution-artifact lookup. Move it to `score.rs` (public) and have
`persist.rs` import it from there — no behavior change, pure relocation.

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`
- Modify: `crates/cairn-heur/src/persist.rs:250-332` (remove `CrossIndex`/`build_cross_index`, import from `score`)
- Test: existing tests in both files (must still pass unchanged)

- [ ] **Step 1: Copy `CrossIndex`/`build_cross_index` into `score.rs`, made public**

Append to `crates/cairn-heur/src/score.rs`, right after the `escalate` function
(before the `#[cfg(test)]` module):

```rust
/// Index execution + process records for corroboration lookups. Two-layer index:
/// exact (JoinKey equality — Path==Path or Name==Name with identical string) built
/// for **all** records; degraded (basename-only) built **only** from records whose
/// source itself lacks path information (`JoinKey::Name`, e.g. prefetch filenames,
/// srum's `id:<n>` fallback) — records with a full path (`JoinKey::Path`) are never
/// inserted into the degraded index. On lookup, exact is tried first regardless of
/// the query's own key kind; degraded is only consulted on an exact miss. Because
/// the degraded index only ever holds path-less records, two records that both carry
/// full paths (but disagree on directory) can never collide there.
pub struct CrossIndex<'a> {
    exec_exact: std::collections::HashMap<JoinKey, Vec<&'a cairn_core::record::ExecutionRecord>>,
    exec_degraded: std::collections::HashMap<String, Vec<&'a cairn_core::record::ExecutionRecord>>,
    proc_exact: std::collections::HashMap<JoinKey, Vec<&'a cairn_core::record::ProcessRecord>>,
    proc_degraded: std::collections::HashMap<String, Vec<&'a cairn_core::record::ProcessRecord>>,
}

impl<'a> CrossIndex<'a> {
    /// Look up execution-artifact corroboration: exact key first, falling back to
    /// the degraded (filename-only) index on a miss. Returns (hits, was_degraded).
    pub fn lookup_exec(
        &self,
        key: &JoinKey,
    ) -> (Vec<&'a cairn_core::record::ExecutionRecord>, bool) {
        if let Some(hits) = self.exec_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        match self.exec_degraded.get(&key.degraded_key()) {
            Some(hits) if !hits.is_empty() => (hits.clone(), true),
            _ => (Vec::new(), false),
        }
    }

    /// Same as `lookup_exec`, on the process side.
    pub fn lookup_proc(&self, key: &JoinKey) -> (Vec<&'a cairn_core::record::ProcessRecord>, bool) {
        if let Some(hits) = self.proc_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        match self.proc_degraded.get(&key.degraded_key()) {
            Some(hits) if !hits.is_empty() => (hits.clone(), true),
            _ => (Vec::new(), false),
        }
    }
}

/// Build a `CrossIndex` over every `Record::Execution`/`Record::Process` entry in
/// `records`.
pub fn build_cross_index(records: &[cairn_core::record::Record]) -> CrossIndex<'_> {
    use cairn_core::record::Record;
    let mut exec_exact: std::collections::HashMap<JoinKey, Vec<&cairn_core::record::ExecutionRecord>> =
        std::collections::HashMap::new();
    let mut exec_degraded: std::collections::HashMap<String, Vec<&cairn_core::record::ExecutionRecord>> =
        std::collections::HashMap::new();
    let mut proc_exact: std::collections::HashMap<JoinKey, Vec<&cairn_core::record::ProcessRecord>> =
        std::collections::HashMap::new();
    let mut proc_degraded: std::collections::HashMap<String, Vec<&cairn_core::record::ProcessRecord>> =
        std::collections::HashMap::new();
    for r in records {
        match r {
            Record::Execution(e) => {
                let k = join_key(&e.path);
                if !k.degraded_key().is_empty() {
                    if let JoinKey::Name(n) = &k {
                        exec_degraded.entry(n.clone()).or_default().push(e);
                    }
                    exec_exact.entry(k).or_default().push(e);
                }
            }
            Record::Process(p) => {
                let k = join_key(&p.image);
                if !k.degraded_key().is_empty() {
                    if let JoinKey::Name(n) = &k {
                        proc_degraded.entry(n.clone()).or_default().push(p);
                    }
                    proc_exact.entry(k).or_default().push(p);
                }
            }
            _ => {}
        }
    }
    CrossIndex {
        exec_exact,
        exec_degraded,
        proc_exact,
        proc_degraded,
    }
}
```

Also move the `cross_index_full_paths_with_same_basename_never_collide_via_degraded`
test from `persist.rs`'s `#[cfg(test)] mod tests` into `score.rs`'s test module
(copy the test body verbatim from `persist.rs:1180-1243`, updating only the import
path — it references `build_cross_index`, `join_key`, and `Record::Execution`,
all of which are now local to `score.rs`).

- [ ] **Step 2: Remove the old `CrossIndex`/`build_cross_index` from `persist.rs` and import from `score`**

In `crates/cairn-heur/src/persist.rs`:
1. Delete lines 250-332 (the `CrossIndex` struct, its `impl`, and
   `build_cross_index`) and their doc comment.
2. Delete the now-duplicated `cross_index_full_paths_with_same_basename_never_collide_via_degraded`
   test (lines 1180-1243) from `persist.rs`'s test module (it now lives in `score.rs`).
3. Update the `use crate::score::{...}` import at the top of `persist.rs`:

```rust
use crate::score::{build_cross_index, escalate, join_key, CrossIndex, JoinKey};
```

4. `persist.rs`'s `analyze()` calls `build_cross_index(records)` and
   `idx.lookup_exec(...)`/`idx.lookup_proc(...)` — these calls are unchanged since
   the function/method signatures are identical; only the import path changed.

- [ ] **Step 3: Run the scoped test suite to verify the move is behavior-preserving**

Run: `cargo test -p cairn-heur`
Expected: All existing tests pass, including
`cross_index_full_paths_with_same_basename_never_collide_via_degraded` (now in
`score.rs`) and all `persist.rs` tests (`analyzer_emits_finding_for_malicious_only`,
`execution_corroboration_escalates_and_adds_evidence`, etc. — unchanged behavior).

- [ ] **Step 4: Run workspace check to confirm no other crate referenced the old private path**

Run: `cargo check --workspace`
Expected: Clean compile. (`CrossIndex`/`build_cross_index` were `persist.rs`-private
before this change, so no external crate could have referenced them; this is a
sanity check, not expected to surface anything.)

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/score.rs crates/cairn-heur/src/persist.rs
git commit -m "refactor(heur): promote CrossIndex from persist.rs to score.rs

Pure relocation, no behavior change — live_exec.rs (next commit) needs the
same three-source execution-artifact lookup persist.rs already built."
```

---

## Task 2: `LiveExecHeuristic` — signal A (execution artifact completely absent)

Write the failing test first (TDD), then the minimal scoring logic.

**Files:**
- Create: `crates/cairn-heur/src/live_exec.rs`
- Modify: `crates/cairn-heur/src/lib.rs` (add `pub mod live_exec;` + re-export)

- [ ] **Step 1: Scaffold the file and register the module**

Add to `crates/cairn-heur/src/lib.rs` (alphabetical among the existing `pub mod`
lines, after `logon_bruteforce` and before `netconn`):

```rust
pub mod live_exec;
```

And in the `pub use` block (alphabetical, after `logon_bruteforce::LogonBruteforceHeuristic`):

```rust
pub use live_exec::LiveExecHeuristic;
```

Create `crates/cairn-heur/src/live_exec.rs` with the module skeleton:

```rust
//! heur_live_exec (docs/REMAINING-WORK.md segment 5): a live process with no
//! execution-artifact history across prefetch/amcache/shimcache (signal A), or a
//! live process whose earliest execution-artifact record is both recent (≤30 days)
//! and unsigned (signal B). Independent of every other analyzer — depends_on()
//! returns &[].
use crate::score::{build_cross_index, join_key, severity_for, Score};
use cairn_core::finding::EntityProcess;
use cairn_core::record::{ExecutionRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use chrono::{Duration, Utc};

/// Signal B's recency window: an execution artifact whose earliest first_run is
/// within this many days of "now" counts as "recently first seen". Fixed module
/// constant (no Config entry) — mirrors persist.rs::RECENT_DAYS; nobody has asked
/// to tune this yet (YAGNI).
const RECENT_DAYS: i64 = 30;

/// Weight for signal A (no execution artifact in any of prefetch/amcache/shimcache).
/// Chosen to land in the High band (50..=69) on its own — see score.rs::severity_for.
const SIGNAL_A_WEIGHT: u32 = 55;

/// Weight for signal B (recent first-seen + unsigned). Same High-band target as
/// signal A; the two signals are mutually exclusive (see score_process doc comment)
/// so there is no double-counting to guard against.
const SIGNAL_B_WEIGHT: u32 = 55;
```

- [ ] **Step 2: Write the failing test for signal A**

Append to `crates/cairn-heur/src/live_exec.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn proc(image: &str, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 100,
            ppid: 4,
            image: image.into(),
            cmdline: String::new(),
            signed,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        }
    }

    fn exec_rec(source: &str, path: &str, first_run: Option<chrono::DateTime<Utc>>) -> ExecutionRecord {
        ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: None,
        }
    }

    /// Signal A: a live process with zero matches across prefetch/amcache/shimcache
    /// scores SIGNAL_A_WEIGHT (High band).
    #[test]
    fn signal_a_fires_when_no_execution_artifact_exists() {
        let p = proc(r"C:\Users\a\AppData\Local\Temp\ghost.exe", None);
        let records = vec![Record::Process(p.clone())];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, Utc::now());
        assert_eq!(s.weight, SIGNAL_A_WEIGHT);
        assert!(s.reasons.iter().any(|r| r.contains("prefetch")
            && r.contains("amcache")
            && r.contains("shimcache")));
    }

    /// Signal A must NOT fire when any one of the three sources has a match, even
    /// if that record carries no first_run (shimcache's normal case).
    #[test]
    fn signal_a_does_not_fire_when_shimcache_alone_has_a_match() {
        let p = proc(r"C:\Windows\System32\notepad.exe", None);
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec(
                "shimcache",
                r"C:\Windows\System32\notepad.exe",
                None,
            )),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, Utc::now());
        assert_eq!(s.weight, 0, "any source match suppresses signal A");
    }
}
```

- [ ] **Step 3: Run the test to verify it fails to compile (score_process doesn't exist yet)**

Run: `cargo test -p cairn-heur live_exec:: -- --nocapture`
Expected: Compile error — `cannot find function `score_process` in this scope`.

- [ ] **Step 4: Implement `score_process` to satisfy signal A**

Insert before the `#[cfg(test)]` block in `live_exec.rs`:

```rust
/// Score one live process against the three-source execution-artifact index.
/// Signal A (no artifact anywhere) and signal B (recent + unsigned) are mutually
/// exclusive by construction: A requires zero matches across all three sources; B
/// requires at least one match. See the spec's "Signal互斥" section.
fn score_process(p: &ProcessRecord, idx: &crate::score::CrossIndex<'_>, now: chrono::DateTime<Utc>) -> Score {
    let mut s = Score::default();
    let key = join_key(&p.image);
    let (hits, _degraded) = idx.lookup_exec(&key);

    if hits.is_empty() {
        s.add(
            SIGNAL_A_WEIGHT,
            format!(
                "process {} is running but has no execution-artifact record in \
                 prefetch, amcache, or shimcache — does not by itself prove the \
                 binary never ran (each source has known coverage limits: prefetch \
                 retains only the ~1024 most recent entries and is disabled by \
                 default on Windows Server; amcache/shimcache have their own \
                 retention limits and clearing cycles)",
                p.image
            ),
            &[],
        );
        return s;
    }

    // Signal B: earliest first_run across all matched sources, if any carry one.
    let earliest = hits.iter().filter_map(|e| e.first_run).min();
    if let Some(first_run) = earliest {
        let age = now.signed_duration_since(first_run);
        let recent = age >= Duration::zero() && age <= Duration::days(RECENT_DAYS);
        if recent && p.signed == Some(false) {
            let amcache_involved = hits
                .iter()
                .any(|e| e.source == "amcache" && e.first_run == Some(first_run));
            let mut reason = format!(
                "process {} is unsigned and its earliest execution-artifact record \
                 ({}) is only {} day(s) old",
                p.image,
                first_run.format("%Y-%m-%dT%H:%M:%SZ"),
                age.num_days()
            );
            if amcache_involved {
                reason.push_str(
                    "; note: amcache's first_run is a registry LastWrite \
                     approximation, not a precise execution timestamp",
                );
            }
            s.add(SIGNAL_B_WEIGHT, reason, &[]);
        }
    }
    s
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p cairn-heur live_exec:: -- --nocapture`
Expected: Both tests pass —
`signal_a_fires_when_no_execution_artifact_exists` and
`signal_a_does_not_fire_when_shimcache_alone_has_a_match`.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-heur/src/live_exec.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): add signal A (no execution artifact) to live_exec scoring"
```

---

## Task 3: Signal B — recent first-seen + unsigned, plus abstain/exclusion tests

Task 2's `score_process` already implements signal B inline. This task adds the
remaining test coverage the spec calls for (abstain on `signed=None`, no-fire past
30 days, no-fire when signed, multi-source earliest-wins) to lock the behavior in
before wiring up the `Analyzer` impl.

**Files:**
- Modify: `crates/cairn-heur/src/live_exec.rs` (tests only)

- [ ] **Step 1: Write the failing (well — these will pass immediately since Task 2 already implemented the logic; write them to lock in the contract) tests**

Append to the `mod tests` block in `live_exec.rs`:

```rust
    /// Signal B must NOT fire when signed is None — abstain, don't guess. A
    /// collection failure (no WinVerifyTrust result) is not the same as a
    /// confirmed-unsigned binary.
    #[test]
    fn signal_b_abstains_when_signed_is_none() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\new.exe", None);
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec("prefetch", "NEW.EXE", Some(now - Duration::days(5)))),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, now);
        assert_eq!(s.weight, 0, "signed=None must abstain, not trigger signal B");
    }

    /// Signal B must NOT fire when the binary is explicitly signed.
    #[test]
    fn signal_b_does_not_fire_when_signed_true() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\new.exe", Some(true));
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec("prefetch", "NEW.EXE", Some(now - Duration::days(5)))),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, now);
        assert_eq!(s.weight, 0);
    }

    /// Signal B must NOT fire when the earliest first_run is older than RECENT_DAYS.
    #[test]
    fn signal_b_does_not_fire_when_first_run_too_old() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\old.exe", Some(false));
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec(
                "prefetch",
                "OLD.EXE",
                Some(now - Duration::days(RECENT_DAYS + 1)),
            )),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, now);
        assert_eq!(s.weight, 0);
    }

    /// Signal B fires when the earliest first_run is within the window and the
    /// process is confirmed unsigned.
    #[test]
    fn signal_b_fires_when_recent_and_unsigned() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\new.exe", Some(false));
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec("prefetch", "NEW.EXE", Some(now - Duration::days(5)))),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, now);
        assert_eq!(s.weight, SIGNAL_B_WEIGHT);
    }

    /// Multi-source: prefetch has a recent first_run (5 days), amcache has an older
    /// one (40 days) for the same binary. The earliest (40 days, amcache) must win
    /// the comparison, pushing the age past RECENT_DAYS and suppressing signal B —
    /// proving "take the earliest across all matched sources" rather than "any
    /// source within the window fires".
    #[test]
    fn signal_b_uses_earliest_first_run_across_sources_not_any_source() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\new.exe", Some(false));
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec("prefetch", "NEW.EXE", Some(now - Duration::days(5)))),
            Record::Execution(exec_rec(
                "amcache",
                r"C:\Users\a\AppData\Local\Temp\new.exe",
                Some(now - Duration::days(40)),
            )),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, now);
        assert_eq!(
            s.weight, 0,
            "earliest first_run (40 days, amcache) must suppress signal B"
        );
    }

    /// The amcache-approximation caveat is included in the reason text only when
    /// amcache supplied the winning (earliest) first_run.
    #[test]
    fn signal_b_reason_notes_amcache_approximation_when_amcache_wins() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\new.exe", Some(false));
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec(
                "amcache",
                r"C:\Users\a\AppData\Local\Temp\new.exe",
                Some(now - Duration::days(3)),
            )),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, now);
        assert_eq!(s.weight, SIGNAL_B_WEIGHT);
        assert!(s.reasons[0].contains("registry LastWrite approximation"));
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p cairn-heur live_exec:: -- --nocapture`
Expected: All 6 new tests pass alongside the 2 from Task 2 (8 total in the module).
No implementation changes should be needed — Task 2's `score_process` already
covers this contract; this step exists to catch any mismatch between the spec's
intent and what got implemented.

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-heur/src/live_exec.rs
git commit -m "test(heur): lock in live_exec signal B contract (abstain/age/multi-source)"
```

---

## Task 4: Wire up the `Analyzer` impl and `Finding` construction

**Files:**
- Modify: `crates/cairn-heur/src/live_exec.rs`

- [ ] **Step 1: Write the failing analyzer-level tests**

Append to the `mod tests` block in `live_exec.rs`:

```rust
    #[test]
    fn depends_on_returns_empty() {
        assert!(LiveExecHeuristic.depends_on().is_empty());
    }

    #[test]
    fn analyzer_emits_finding_for_signal_a() {
        let p = proc(r"C:\Users\a\AppData\Local\Temp\ghost.exe", None);
        let findings = LiveExecHeuristic
            .analyze(&[Record::Process(p)], &[])
            .expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert_eq!(f.artifact, "process");
        assert!(f.entity.process.is_some());
        assert_eq!(f.entity.process.as_ref().unwrap().pid, 100);
    }

    #[test]
    fn analyzer_emits_finding_for_signal_b_with_matched_artifact() {
        let now = Utc::now();
        let p = proc(r"C:\Users\a\AppData\Local\Temp\new.exe", Some(false));
        let records = vec![
            Record::Process(p),
            Record::Execution(exec_rec("prefetch", "NEW.EXE", Some(now - Duration::days(5)))),
        ];
        let findings = LiveExecHeuristic.analyze(&records, &[]).expect("analyze");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].artifact, "prefetch");
    }

    #[test]
    fn analyzer_emits_nothing_for_a_quiet_signed_process_with_history() {
        let now = Utc::now();
        let p = proc(r"C:\Windows\System32\notepad.exe", Some(true));
        let records = vec![
            Record::Process(p),
            Record::Execution(exec_rec(
                "amcache",
                r"C:\Windows\System32\notepad.exe",
                Some(now - Duration::days(400)),
            )),
        ];
        let findings = LiveExecHeuristic.analyze(&records, &[]).expect("analyze");
        assert!(findings.is_empty());
    }

    #[test]
    fn severity_is_high_for_signal_a() {
        let p = proc(r"C:\Users\a\AppData\Local\Temp\ghost.exe", None);
        let findings = LiveExecHeuristic
            .analyze(&[Record::Process(p)], &[])
            .expect("analyze");
        assert_eq!(findings[0].severity, cairn_core::Severity::High);
    }
```

- [ ] **Step 2: Run to verify compile failure (LiveExecHeuristic doesn't exist yet)**

Run: `cargo test -p cairn-heur live_exec:: -- --nocapture`
Expected: Compile error — `cannot find type `LiveExecHeuristic` in this scope`.

- [ ] **Step 3: Implement the `Analyzer`**

Insert before the `#[cfg(test)]` block in `live_exec.rs` (after `score_process`):

```rust
/// Analyzer: flags live processes with no execution-artifact history, or with a
/// recently-first-seen unsigned one. Independent — depends_on() is empty.
pub struct LiveExecHeuristic;

impl Analyzer for LiveExecHeuristic {
    fn name(&self) -> &str {
        "heur_live_exec"
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let idx = build_cross_index(records);
        let mut out = Vec::new();
        for r in records {
            let Record::Process(p) = r else { continue };
            let score = score_process(p, &idx, now);
            if score.weight == 0 {
                continue;
            }
            let Some(severity) = severity_for(score.weight) else {
                continue;
            };

            let key = join_key(&p.image);
            let (hits, _degraded) = idx.lookup_exec(&key);
            let short = p.image.rsplit(['\\', '/']).next().unwrap_or(&p.image);
            let is_signal_a = hits.is_empty();

            let mut f = Finding::new(
                severity,
                if is_signal_a {
                    format!("正在執行但無執行文物紀錄: {short}")
                } else {
                    format!("正在執行的未簽章程式最近才首見: {short}")
                },
                FindingSource::Heuristic,
            );
            f.reason = Some(score.reasons.join("; "));
            f.mitre = if is_signal_a {
                // No ATT&CK technique cleanly maps to "no execution-artifact record
                // exists" on its own — that absence could mean living-off-the-land
                // execution never touched these artifact types, deliberate log/
                // artifact clearing, or simply a coverage gap (prefetch disabled,
                // retention rollover). Tagging a specific technique here would
                // overclaim what signal A actually establishes. Leave mitre empty
                // rather than guess; the honest `reason` text carries the nuance
                // instead (golden rule 6).
                vec![]
            } else {
                vec!["T1036".to_string()]
            };
            f.artifact = if is_signal_a {
                "process".to_string()
            } else {
                // At least one source matched (signal B requires it) — use the
                // source that supplied the winning (earliest) first_run.
                let earliest = hits.iter().filter_map(|e| e.first_run).min();
                hits.iter()
                    .find(|e| e.first_run == earliest)
                    .map(|e| e.source.clone())
                    .unwrap_or_else(|| "process".to_string())
            };
            f.details = format!("pid={} image={}", p.pid, p.image);
            f.entity = Entity {
                process: Some(EntityProcess {
                    pid: p.pid,
                    ppid: p.ppid,
                    image: p.image.clone(),
                    cmdline: p.cmdline.clone(),
                    signed: p.signed,
                    integrity: p.integrity.clone(),
                }),
                ..Entity::default()
            };
            f.ts = p.start_time.unwrap_or(now);
            out.push(f);
        }
        Ok(out)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p cairn-heur live_exec:: -- --nocapture`
Expected: All tests in the `live_exec` module pass (8 from Tasks 2-3, plus the 5
new analyzer-level tests = 13 total).

- [ ] **Step 5: Run the full crate test suite to check for regressions**

Run: `cargo test -p cairn-heur`
Expected: All tests pass, including the unaffected `persist.rs`/`netconn.rs`/etc.
suites and the relocated `CrossIndex` test in `score.rs` from Task 1.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-heur/src/live_exec.rs
git commit -m "feat(heur): wire LiveExecHeuristic as an independent Analyzer

Emits Finding for signal A (no execution artifact across prefetch/amcache/
shimcache) and signal B (recent first-seen + unsigned artifact). Weight-based
scoring via the existing Score/severity_for machinery; depends_on() is empty."
```

---

## Task 5: Wire into the CLI live-run analyzer chain + workspace-level integration test

**Files:**
- Modify: `crates/cairn-cli/src/main.rs:885-902` (production wiring)
- Modify: `crates/cairn-cli/src/main.rs:1285-1306` (`live_analyzers_include_all_heuristics` test's analyzer list)
- Test: new integration test in `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: Add `LiveExecHeuristic` to the production analyzer chain**

In `crates/cairn-cli/src/main.rs`, modify the `analyzers` vec at line 885-902 —
add `Box::new(cairn_heur::LiveExecHeuristic)` after the `TemporalWindowCorrelator`
line (it has no dependency ordering requirement since `depends_on()` is empty, so
position among the independent analyzers doesn't matter; grouping it next to
`TemporalWindowCorrelator` keeps the two most recently added independent
process-focused analyzers together):

```rust
            let mut analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
                Box::new(cairn_heur::PersistHeuristic),
                Box::new(cairn_heur::TemporalWindowCorrelator),
                Box::new(cairn_heur::LiveExecHeuristic),
                // S2-N′: threshold from Config (fixed default 24h; no CLI flag).
                Box::new(cairn_heur::TimestompHeuristic::new(
                    chrono::Duration::hours(cfg.timestomp_threshold_hours),
                )),
```

(Only the one new line is added; everything else in that block is unchanged.)

- [ ] **Step 2: Update the `live_analyzers_include_all_heuristics` test's analyzer list to match**

In `crates/cairn-cli/src/main.rs` around line 1290, add the same line to the
test's mirrored `analyzers` vec so it doesn't drift from production wiring:

```rust
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(cairn_heur::ParentChildHeuristic),
            Box::new(cairn_heur::NetConnHeuristic),
            Box::new(cairn_heur::PersistHeuristic),
            Box::new(cairn_heur::TemporalWindowCorrelator),
            Box::new(cairn_heur::LiveExecHeuristic),
            Box::new(cairn_heur::TimestompHeuristic::new(threshold)),
```

Then add an assertion alongside the existing `heur_timestomp`/`heur_account`
assertions further down in that same test (near line 1308-1314):

```rust
        assert!(
            analyzers.iter().any(|a| a.name() == "heur_live_exec"),
            "heur_live_exec must be in analyzer set"
        );
```

- [ ] **Step 3: Run this test to verify it passes**

Run: `cargo test -p cairn-cli live_analyzers_include_all_heuristics -- --nocapture`
Expected: PASS.

- [ ] **Step 4: Write a synthetic end-to-end integration test through `run_live`**

Append a new test to `crates/cairn-cli/src/main.rs`'s test module, following the
exact pattern of `temporal_window_correlator_fires_in_live_outcome` (found around
line 1770 — a `FixedRecordsCollector` feeding synthetic records through the real
`run_live` pipeline):

```rust
    /// Integration: LiveExecHeuristic fires in run_live's live outcome for a
    /// process with zero execution-artifact matches (signal A), proving the
    /// analyzer is correctly wired end-to-end through the CLI's collector/analyzer
    /// plumbing, not just unit-testable in isolation.
    #[test]
    fn live_exec_heuristic_fires_in_live_outcome() {
        use cairn_core::manifest::Privileges;
        use cairn_core::orchestrator::run_live;
        use cairn_core::record::{ProcessRecord, Record};

        struct FixedRecordsCollector(Vec<Record>);
        impl cairn_core::traits::Collector for FixedRecordsCollector {
            fn name(&self) -> &str {
                "fake_live_exec_records"
            }
            fn collect(
                &self,
                _ctx: &cairn_core::traits::CollectCtx<'_>,
            ) -> cairn_core::Result<Vec<Record>> {
                Ok(self.0.clone())
            }
        }

        let ghost = ProcessRecord {
            pid: 9001,
            ppid: 1,
            image: r"C:\Users\victim\AppData\Local\Temp\ghost.exe".to_string(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        };

        let cfg = cairn_core::Config::default();
        let privs = Privileges {
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let collectors: Vec<Box<dyn cairn_core::traits::Collector>> =
            vec![Box::new(FixedRecordsCollector(vec![Record::Process(ghost)]))];
        let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> =
            vec![Box::new(cairn_heur::LiveExecHeuristic)];

        let outcome = run_live(&cfg, privs, "TEST".into(), &collectors, &analyzers);

        let finding = outcome
            .findings
            .iter()
            .find(|f| f.artifact == "process" && f.entity.process.is_some());
        assert!(
            finding.is_some(),
            "live_exec finding must be present when a process has no execution \
             artifact anywhere; got findings: {:?}",
            outcome.findings
        );
        assert_eq!(
            finding.unwrap().entity.process.as_ref().unwrap().pid,
            9001
        );
    }
```

- [ ] **Step 5: Run the new integration test**

Run: `cargo test -p cairn-cli live_exec_heuristic_fires_in_live_outcome -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Run the full workspace test/clippy/fmt gate (cross-crate boundary — this task touches cairn-cli wiring)**

Run:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
Expected: `fmt --check` clean; `clippy` zero warnings; all tests pass (0 failed).
Per CLAUDE.md's test-scope discipline, this is the one point in this plan where a
full-workspace run is warranted — `main.rs` wiring is a cross-crate boundary.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire LiveExecHeuristic into the live analyzer chain"
```

---

## Task 6: Update `docs/REMAINING-WORK.md`

Record completion and the backlog-description correction discovered during
brainstorming (prefetch basename normalization was not actually needed).

**Files:**
- Modify: `docs/REMAINING-WORK.md`

- [ ] **Step 1: Add a completion entry**

In `docs/REMAINING-WORK.md`, change the 段 5 heading from:

```
### 段 5 — LiveExecHeuristic（原待辦 D）
```

to:

```
### 段 5 — LiveExecHeuristic（原待辦 D）✅ 完成並已 merge（<實作日期>，PR #<PR號>，main `<commit>`）
```

and append a short completion paragraph below the existing description (in the
same style as the 段3/段4 completion write-ups), noting: (1) the backlog's
original "prefetch basename normalization" concern did not apply — collector-side
`ExecutionRecord.path` for prefetch never carries the `.pf` hash suffix; (2)
`CrossIndex`/`build_cross_index` was promoted from `persist.rs` to `score.rs` for
reuse; (3) `depends_on()` is empty — the analyzer is fully independent. Fill in the
actual date/PR number/commit SHA at merge time (not available until this plan is
executed and merged — do not guess a placeholder value now).

- [ ] **Step 2: Update the 建議執行順序 block**

Move the `段 5 / 6（heuristic 深化...)← 下一步` line to reflect segment 5's
completion, following the exact style of how prior completed segments were
appended to that ordered list (see the block starting `段 0（CI 熱修）✅ 完成...`).

- [ ] **Step 3: Commit**

```bash
git add docs/REMAINING-WORK.md
git commit -m "docs(backlog): register segment 5 completion (LiveExecHeuristic)"
```

(This commit should happen as part of `finishing-a-development-branch`, alongside
or immediately before the PR is opened — not before the PR number/commit SHA are
known. If executing this plan strictly task-by-task before a PR exists, leave a
placeholder marker in the text like `<PR號待補>` and correct it in a follow-up
commit once the PR merges, matching how other segments in this file handle the
same chicken-and-egg problem.)

---

## Final gate

Before calling this done, per CLAUDE.md's "Definition of done for a task" and the
finishing-a-development-branch skill: `cargo check --workspace`,
`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
and `cargo fmt --check` must all be clean (this is the authoritative full-workspace
gate for the whole branch — see Task 5 Step 6 for the same commands run earlier;
re-run once more here if any commits landed after that point). No golden-rule
violation. No schema change (Finding/Record/EntityProcess are all unchanged by
this plan — only a new Analyzer and Finding *instances*, not new fields).
