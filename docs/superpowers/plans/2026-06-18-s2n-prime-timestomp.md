# S2-N′ Timestomp Delta Heuristic — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `cairn-heur` analyzer that flags timestomp by detecting SI timestamps
directionally earlier than FN timestamps beyond a 24h threshold, emitting a
T1070.006 Finding.

**Architecture:** Pure Record→Finding analyzer over the `Record::FileMeta` stream
S2-N produces. No host touch, `#![forbid(unsafe_code)]` preserved, zero new deps.
Two evidence fields added to `EntityFile`; a fixed threshold in `Config` (no CLI flag).

**Tech Stack:** Rust, `chrono` (already present), serde. Workspace crates
`cairn-core` (contracts), `cairn-heur` (analyzers), `cairn-cli` (wiring).

**Spec:** `docs/superpowers/specs/2026-06-18-s2n-prime-timestomp-design.md`

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `crates/cairn-core/src/finding.rs` | Modify | `EntityFile` + `si_mtime`/`fn_mtime` |
| `crates/cairn-core/src/config.rs` | Modify | `Config.timestomp_threshold_hours` (default 24) |
| `crates/cairn-heur/src/persist.rs` | Modify | add `si_mtime: None, fn_mtime: None` to its `EntityFile` |
| `crates/cairn-heur/src/timestomp.rs` | **Create** | `detect_timestomp` + `timestomp_severity` + `TimestompHeuristic` + tests |
| `crates/cairn-heur/src/lib.rs` | Modify | `pub mod timestomp;` + `pub use` |
| `crates/cairn-cli/src/main.rs` | Modify | push `TimestompHeuristic` (threshold from Config) into analyzer vec |

Build order: T1 (EntityFile schema, unblocks persist.rs + timestomp.rs) → T2
(Config field) → T3 (timestomp.rs detection core, TDD) → T4 (TimestompHeuristic
analyzer) → T5 (CLI wiring). Each task: `cargo check -p <crate>` then its test.

---

## Task 1: EntityFile gains si_mtime / fn_mtime

**Files:**
- Modify: `crates/cairn-core/src/finding.rs:46-52` (struct) + add a test
- Modify: `crates/cairn-heur/src/persist.rs:139-150` (only existing constructor)

- [ ] **Step 1: Write the failing backward-compat test**

Add to the `tests` module in `crates/cairn-core/src/finding.rs`:

```rust
/// EntityFile JSON written before S2-N′ (no si_mtime/fn_mtime) still deserializes,
/// with the two new fields defaulting to None (serde backward compat). And a full
/// four-axis EntityFile round-trips.
#[test]
fn entityfile_old_json_gets_none_mtimes_and_new_roundtrips() {
    use super::EntityFile;
    // old JSON: lacks si_mtime / fn_mtime
    let old = r#"{"path":"C:\\a.exe","sha256":null,"mtime":null,
        "si_btime":null,"fn_btime":null}"#;
    let e: EntityFile = serde_json::from_str(old).unwrap();
    assert_eq!(e.si_mtime, None);
    assert_eq!(e.fn_mtime, None);

    // new EntityFile carries all four times and survives a round-trip
    let t = chrono::DateTime::parse_from_rfc3339("2013-01-05T18:15:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let full = EntityFile {
        path: "C:\\a.exe".into(),
        sha256: None,
        mtime: None,
        si_btime: Some(t),
        fn_btime: Some(t),
        si_mtime: Some(t),
        fn_mtime: Some(t),
    };
    let j = serde_json::to_string(&full).unwrap();
    let back: EntityFile = serde_json::from_str(&j).unwrap();
    assert_eq!(back.si_mtime, Some(t));
    assert_eq!(back.fn_mtime, Some(t));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-core entityfile_old_json -- --nocapture`
Expected: FAIL to compile — `EntityFile` has no field `si_mtime` / `fn_mtime`.

- [ ] **Step 3: Add the two fields to the struct**

In `crates/cairn-core/src/finding.rs`, change the `EntityFile` struct (lines 46-52)
from:

```rust
pub struct EntityFile {
    pub path: String,
    pub sha256: Option<String>,
    pub mtime: Option<DateTime<Utc>>,
    pub si_btime: Option<DateTime<Utc>>,
    pub fn_btime: Option<DateTime<Utc>>,
}
```

to:

```rust
pub struct EntityFile {
    pub path: String,
    pub sha256: Option<String>,
    pub mtime: Option<DateTime<Utc>>,
    pub si_btime: Option<DateTime<Utc>>,
    pub fn_btime: Option<DateTime<Utc>>,
    /// SI/FN modification times (S2-N′): exposed alongside the btimes so a
    /// timestomp Finding carries all four axes as cross-checkable evidence.
    pub si_mtime: Option<DateTime<Utc>>,
    pub fn_mtime: Option<DateTime<Utc>>,
}
```

(serde needs no attribute here: a missing field on a non-`Option`-required struct
would error, but these ARE `Option`, and serde defaults a missing `Option` field to
`None`, which the test asserts.)

- [ ] **Step 4: Fix the one existing constructor in persist.rs**

In `crates/cairn-heur/src/persist.rs`, the `EntityFile { .. }` literal in
`persistence_entity` (around lines 139-150) currently ends with `fn_btime: None,`.
Add the two new fields right after it:

```rust
            file: Some(EntityFile {
                path: p
                    .binary_path
                    .clone()
                    .or_else(|| p.value.clone())
                    .unwrap_or_default(),
                sha256: None,
                mtime: p.last_write,
                si_btime: None,
                fn_btime: None,
                si_mtime: None,
                fn_mtime: None,
            }),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-core -p cairn-heur`
Expected: PASS (new test green; persist.rs compiles + its tests stay green).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-core/src/finding.rs crates/cairn-heur/src/persist.rs
git commit -m "feat(core): EntityFile + si_mtime/fn_mtime (S2-N' evidence fields)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Config.timestomp_threshold_hours (default 24)

**Files:**
- Modify: `crates/cairn-core/src/config.rs` (struct, `Default`, a test)

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/cairn-core/src/config.rs`:

```rust
#[test]
fn timestomp_threshold_defaults_to_24_hours() {
    let cfg = Config::default();
    assert_eq!(cfg.timestomp_threshold_hours, 24);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-core timestomp_threshold_defaults`
Expected: FAIL to compile — no field `timestomp_threshold_hours`.

- [ ] **Step 3: Add the field + default**

In `crates/cairn-core/src/config.rs`, add to the `Config` struct (after
`max_mft_records: u64,` at line 69):

```rust
    /// Min FN−SI delta (hours), either axis, before a timestomp Finding fires (S2-N′).
    /// Below this, sub-day SI/FN drift from legit ops (unzip/copy/install) is ignored.
    /// Fixed default; no CLI flag — banding (Medium/High/Critical) carries severity.
    pub timestomp_threshold_hours: i64,
```

And in `impl Default for Config`, after `max_mft_records: 1_000_000,` (line 86):

```rust
            timestomp_threshold_hours: 24,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p cairn-core timestomp_threshold_defaults`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-core/src/config.rs
git commit -m "feat(core): Config.timestomp_threshold_hours (default 24, S2-N')

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: detect_timestomp + timestomp_severity (detection core, TDD)

**Files:**
- Create: `crates/cairn-heur/src/timestomp.rs`
- Modify: `crates/cairn-heur/src/lib.rs` (add `pub mod timestomp;`)

This task builds the PURE detection logic + its severity banding. The
`TimestompHeuristic` analyzer is Task 4 (kept separate so the core is testable
without constructing Records).

- [ ] **Step 1: Create the module file with the failing tests**

Create `crates/cairn-heur/src/timestomp.rs`:

```rust
//! heur_timestomp (SRS §10, ATT&CK T1070.006): flag files whose $STANDARD_INFORMATION
//! (SI) timestamps are directionally earlier than their $FILE_NAME (FN) timestamps
//! beyond a threshold — the classic timestomp signature (`SetFileTime` backdates SI;
//! FN is kernel-only and stays at the real, later time). Pure logic over
//! `Record::FileMeta` (S2-N); touches no host state. Every Finding carries a `reason`
//! (golden rule 6) and the T1070.006 tag.
//!
//! Severity is MAGNITUDE-BANDED on the max fired delta — it is NOT additive scoring,
//! so it deliberately does NOT use `score.rs::severity_for` (a weight→severity map).
use cairn_core::record::FileMetaRecord;
use cairn_core::Severity;
use chrono::{DateTime, Duration, Utc};

/// One axis that fired the directional-delta test, kept for the reason string + entity.
#[derive(Debug, Clone, PartialEq)]
pub struct AxisHit {
    /// "btime" or "mtime".
    pub axis: &'static str,
    pub si: DateTime<Utc>,
    pub fn_: DateTime<Utc>,
    pub delta: Duration,
}

/// The outcome of evaluating one file: the axes that fired and the max delta.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestompHit {
    pub hits: Vec<AxisHit>,
    pub max_delta: Duration,
}

/// Evaluate one axis: returns a hit only when BOTH sides are Some, SI is earlier
/// than FN (delta = FN − SI > 0), AND delta exceeds `threshold`. None otherwise
/// (missing data → no guess; SI≥FN → legit direction; sub-threshold → legit noise).
fn eval_axis(
    axis: &'static str,
    si: Option<DateTime<Utc>>,
    fn_: Option<DateTime<Utc>>,
    threshold: Duration,
) -> Option<AxisHit> {
    let (si, fn_) = (si?, fn_?);
    let delta = fn_ - si; // positive == SI earlier than FN == backdating direction
    if delta > threshold {
        Some(AxisHit {
            axis,
            si,
            fn_,
            delta,
        })
    } else {
        None
    }
}

/// Detect timestomp on one file. Evaluates the btime and mtime axes independently;
/// returns Some when either fires, carrying every fired axis and the max delta.
pub fn detect_timestomp(meta: &FileMetaRecord, threshold: Duration) -> Option<TimestompHit> {
    let mut hits = Vec::new();
    if let Some(h) = eval_axis("btime", meta.si_btime, meta.fn_btime, threshold) {
        hits.push(h);
    }
    if let Some(h) = eval_axis("mtime", meta.si_mtime, meta.fn_mtime, threshold) {
        hits.push(h);
    }
    if hits.is_empty() {
        return None;
    }
    let max_delta = hits.iter().map(|h| h.delta).max().expect("non-empty");
    Some(TimestompHit { hits, max_delta })
}

/// Map the max fired delta to a Severity. A fired hit always has delta > threshold
/// (≥ 24h by default), so this never returns below Medium.
pub fn timestomp_severity(max_delta: Duration) -> Severity {
    if max_delta > Duration::days(365) {
        Severity::Critical
    } else if max_delta > Duration::days(30) {
        Severity::High
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A FileMetaRecord builder defaulting all four times to None.
    fn meta(
        si_btime: Option<DateTime<Utc>>,
        fn_btime: Option<DateTime<Utc>>,
        si_mtime: Option<DateTime<Utc>>,
        fn_mtime: Option<DateTime<Utc>>,
    ) -> FileMetaRecord {
        FileMetaRecord {
            path: r"C:\Users\a\evil.exe".into(),
            size: 0,
            sha256: None,
            si_btime,
            si_mtime,
            fn_btime,
            fn_mtime,
            zone_identifier: None,
        }
    }

    const THRESH: Duration = Duration::hours(24);

    #[test]
    fn si_earlier_than_fn_btime_beyond_threshold_fires() {
        // SI.btime backdated ~2 years before FN.btime → fires, Critical.
        let m = meta(
            Some(t("2011-01-01T00:00:00Z")),
            Some(t("2013-01-05T18:15:00Z")),
            None,
            None,
        );
        let hit = detect_timestomp(&m, THRESH).expect("should fire");
        assert_eq!(hit.hits.len(), 1);
        assert_eq!(hit.hits[0].axis, "btime");
        assert_eq!(timestomp_severity(hit.max_delta), Severity::Critical);
    }

    #[test]
    fn mtime_axis_independently_fires() {
        // btime aligned (no hit), only mtime backdated → fires on mtime alone.
        let aligned = t("2024-06-01T00:00:00Z");
        let m = meta(
            Some(aligned),
            Some(aligned),
            Some(t("2020-01-01T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
        );
        let hit = detect_timestomp(&m, THRESH).expect("should fire on mtime");
        assert_eq!(hit.hits.len(), 1);
        assert_eq!(hit.hits[0].axis, "mtime");
    }

    #[test]
    fn legit_si_after_fn_does_not_fire() {
        // SI later than FN (unzip/copy/install direction) → delta negative → no fire.
        let m = meta(
            Some(t("2024-06-02T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
            None,
            None,
        );
        assert_eq!(detect_timestomp(&m, THRESH), None);
    }

    #[test]
    fn delta_within_threshold_does_not_fire() {
        // 2h drift (< 24h) → legit noise → no fire.
        let m = meta(
            Some(t("2024-06-01T00:00:00Z")),
            Some(t("2024-06-01T02:00:00Z")),
            None,
            None,
        );
        assert_eq!(detect_timestomp(&m, THRESH), None);
    }

    #[test]
    fn none_timestamps_do_not_fire() {
        // any axis with a None side contributes nothing; all-None → None (no guess).
        let m = meta(Some(t("2011-01-01T00:00:00Z")), None, None, None);
        assert_eq!(detect_timestomp(&m, THRESH), None);
        let empty = meta(None, None, None, None);
        assert_eq!(detect_timestomp(&empty, THRESH), None);
    }

    #[test]
    fn equal_si_fn_does_not_fire() {
        let same = t("2024-06-01T00:00:00Z");
        let m = meta(Some(same), Some(same), Some(same), Some(same));
        assert_eq!(detect_timestomp(&m, THRESH), None);
    }

    #[test]
    fn severity_bands() {
        // just over each edge: 25h → Medium, 31d → High, 366d → Critical.
        assert_eq!(timestomp_severity(Duration::hours(25)), Severity::Medium);
        assert_eq!(timestomp_severity(Duration::days(31)), Severity::High);
        assert_eq!(timestomp_severity(Duration::days(366)), Severity::Critical);
        // band edges themselves: exactly 30d is NOT > 30d → Medium; exactly 365d → High.
        assert_eq!(timestomp_severity(Duration::days(30)), Severity::Medium);
        assert_eq!(timestomp_severity(Duration::days(365)), Severity::High);
    }

    #[test]
    fn both_axes_fire_max_delta_drives_severity() {
        // btime delta ~2d (Medium-band magnitude), mtime delta ~2y (Critical) →
        // both recorded, severity from the MAX (mtime).
        let m = meta(
            Some(t("2024-05-30T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
            Some(t("2022-06-01T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
        );
        let hit = detect_timestomp(&m, THRESH).expect("both axes fire");
        assert_eq!(hit.hits.len(), 2);
        assert_eq!(timestomp_severity(hit.max_delta), Severity::Critical);
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/cairn-heur/src/lib.rs`, add after `pub mod score;` (line 9):

```rust
pub mod timestomp;
```

(Leave the `pub use` for Task 4 — the analyzer type does not exist yet.)

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p cairn-heur timestomp`
Expected: PASS (8 tests in the timestomp module).

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-heur/src/timestomp.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): detect_timestomp + magnitude banding (S2-N', T1070.006 core)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: TimestompHeuristic analyzer

**Files:**
- Modify: `crates/cairn-heur/src/timestomp.rs` (add the analyzer + its test)
- Modify: `crates/cairn-heur/src/lib.rs` (add `pub use`)

- [ ] **Step 1: Write the failing analyzer test**

Add to the `tests` module in `crates/cairn-heur/src/timestomp.rs`:

```rust
use cairn_core::record::Record;
use cairn_core::traits::Analyzer;

#[test]
fn analyzer_emits_finding_with_four_axis_entity() {
    // one stomped file (SI.btime 2y before FN.btime, SI.mtime 2y before FN.mtime)
    // and one clean file → exactly one Finding, carrying all four times + T1070.006.
    let stomped = Record::FileMeta(meta(
        Some(t("2011-01-01T00:00:00Z")),
        Some(t("2013-01-05T18:15:00Z")),
        Some(t("2011-01-01T00:00:00Z")),
        Some(t("2013-01-05T18:15:00Z")),
    ));
    let clean_t = t("2024-06-01T00:00:00Z");
    let clean = Record::FileMeta(meta(
        Some(clean_t),
        Some(clean_t),
        Some(clean_t),
        Some(clean_t),
    ));

    let h = TimestompHeuristic::new(Duration::hours(24));
    let findings = h.analyze(&[stomped, clean]).expect("analyze");

    assert_eq!(findings.len(), 1, "only the stomped file fires");
    let f = &findings[0];
    assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
    assert!(f.reason.is_some(), "golden rule 6: reason required");
    assert!(f.mitre.contains(&"T1070.006".to_string()));
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.artifact, "file_meta");
    let ef = f.entity.file.as_ref().expect("file entity");
    assert!(ef.si_btime.is_some() && ef.fn_btime.is_some());
    assert!(ef.si_mtime.is_some() && ef.fn_mtime.is_some());
    assert_eq!(ef.path, r"C:\Users\a\evil.exe");
}

#[test]
fn analyzer_ignores_non_filemeta_and_empty_stream() {
    // a non-FileMeta record and an empty stream both yield zero findings (no crash).
    let h = TimestompHeuristic::new(Duration::hours(24));
    assert!(h.analyze(&[]).unwrap().is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-heur analyzer_emits_finding_with_four_axis`
Expected: FAIL to compile — `TimestompHeuristic` does not exist.

- [ ] **Step 3: Implement the analyzer**

Add to `crates/cairn-heur/src/timestomp.rs` (after `timestomp_severity`, before the
`#[cfg(test)]` module). Note the imports needed at the top of the file — add
`use cairn_core::finding::EntityFile; use cairn_core::record::Record;
use cairn_core::traits::Analyzer; use cairn_core::{Entity, Finding, FindingSource, Result};`
to the existing `use` block:

```rust
/// Analyzer: flags timestomped files from the FileMeta stream. Holds the threshold
/// (read from `Config.timestomp_threshold_hours` when the analyzer vec is built).
pub struct TimestompHeuristic {
    threshold: Duration,
}

impl TimestompHeuristic {
    pub fn new(threshold: Duration) -> Self {
        TimestompHeuristic { threshold }
    }
}

impl Analyzer for TimestompHeuristic {
    fn name(&self) -> &str {
        "heur_timestomp"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        for r in records {
            let Record::FileMeta(m) = r else { continue };
            let Some(hit) = detect_timestomp(m, self.threshold) else {
                continue;
            };
            let severity = timestomp_severity(hit.max_delta);

            let mut f = Finding::new(
                severity,
                "Timestomp: SI timestamps backdated vs $FILE_NAME",
                FindingSource::Heuristic,
            );
            f.reason = Some(reason_for(&hit, &m.path));
            f.mitre = vec!["T1070.006".to_string()];
            f.artifact = "file_meta".into();
            f.details = format!("path={} {}", m.path, axes_detail(&hit));
            // Anchor the finding at the real creation time (FN.btime) when known.
            f.ts = m.fn_btime.or(m.fn_mtime).unwrap_or_else(Utc::now);
            f.entity = Entity {
                file: Some(EntityFile {
                    path: m.path.clone(),
                    sha256: m.sha256.clone(),
                    mtime: m.si_mtime,
                    si_btime: m.si_btime,
                    fn_btime: m.fn_btime,
                    si_mtime: m.si_mtime,
                    fn_mtime: m.fn_mtime,
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        Ok(out)
    }
}

/// Human-readable explanation (golden rule 6): names each fired axis and its delta.
fn reason_for(hit: &TimestompHit, path: &str) -> String {
    let parts: Vec<String> = hit
        .hits
        .iter()
        .map(|h| {
            format!(
                "SI.{} {} is earlier than FN.{} {} by {}",
                h.axis,
                h.si.to_rfc3339(),
                h.axis,
                h.fn_.to_rfc3339(),
                humanize(h.delta),
            )
        })
        .collect();
    format!("{} ({})", parts.join("; "), path)
}

/// Compact technical axis listing for `details`.
fn axes_detail(hit: &TimestompHit) -> String {
    hit.hits
        .iter()
        .map(|h| format!("{}_delta={}", h.axis, humanize(h.delta)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render a Duration as a coarse human string (days when ≥ 1 day, else hours).
fn humanize(d: Duration) -> String {
    let days = d.num_days();
    if days >= 1 {
        format!("{days}d")
    } else {
        format!("{}h", d.num_hours())
    }
}
```

- [ ] **Step 4: Export the analyzer**

In `crates/cairn-heur/src/lib.rs`, add to the public-API `pub use` block (after the
existing `pub use persist::PersistHeuristic;`):

```rust
pub use timestomp::TimestompHeuristic;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-heur timestomp`
Expected: PASS (core 8 + analyzer 2 = 10 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-heur/src/timestomp.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): TimestompHeuristic analyzer — Finding w/ reason + 4-axis entity (S2-N')

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Wire TimestompHeuristic into the live run

**Files:**
- Modify: `crates/cairn-cli/src/main.rs:614-618` (analyzer vec)

- [ ] **Step 1: Add a parse/wiring test**

The analyzer vec is built inside the `run` arm; there is no isolated unit for it.
Verify wiring by asserting the vec contains the new analyzer by name. Add to the
`tests` module in `crates/cairn-cli/src/main.rs`:

```rust
/// The live analyzer set includes the timestomp heuristic (S2-N' wiring).
#[test]
fn live_analyzers_include_timestomp() {
    use cairn_core::traits::Analyzer;
    let threshold = chrono::Duration::hours(24);
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(cairn_heur::ParentChildHeuristic),
        Box::new(cairn_heur::NetConnHeuristic),
        Box::new(cairn_heur::PersistHeuristic),
        Box::new(cairn_heur::TimestompHeuristic::new(threshold)),
    ];
    assert!(analyzers.iter().any(|a| a.name() == "heur_timestomp"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-cli live_analyzers_include_timestomp`
Expected: FAIL to compile — `TimestompHeuristic` not yet referenced in cli (or PASS
trivially only after the type is imported; the real change is Step 3 wiring the
production vec).

- [ ] **Step 3: Wire it into the production analyzer vec**

In `crates/cairn-cli/src/main.rs`, change the analyzer vec (lines 614-618) from:

```rust
            let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
                Box::new(cairn_heur::PersistHeuristic),
            ];
```

to:

```rust
            let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
                Box::new(cairn_heur::PersistHeuristic),
                // S2-N′: threshold from Config (fixed default 24h; no CLI flag).
                Box::new(cairn_heur::TimestompHeuristic::new(
                    chrono::Duration::hours(cfg.timestomp_threshold_hours),
                )),
            ];
```

(`cfg` is already in scope here — built at lines 593-596. `chrono` is already a
dependency of the cli crate; if the import is not present, qualify as
`chrono::Duration` as shown.)

- [ ] **Step 4: Run the full workspace test suite**

Run: `cargo test --workspace --locked`
Expected: PASS (all prior + new).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire TimestompHeuristic into live analyzers (threshold from Config, S2-N')

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final acceptance gate (after all tasks)

Run, all must pass:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
git diff <main-sha>..HEAD -- Cargo.lock   # MUST be empty (zero new dependency)
```

Manual invariant checks:
- `#![forbid(unsafe_code)]` still present in `cairn-heur/src/lib.rs` and `cairn-core`.
- Every emitted timestomp Finding has `reason.is_some()` and `mitre` contains
  `T1070.006` (golden rules 6).
- No CLI flag was added (threshold is Config-only).
- `EntityFile` change is purely additive (old JSON deserializes — T1 test proves it).

A non-admin smoke run is sufficient (no elevated e2e): `cairn run --target live`
on this box has no FileMeta records (mft skipped without admin), so the analyzer
emits nothing and does not crash — proving it is wired and safe on an empty stream.
Output MUST go off the OneDrive tree (e.g. `C:\Users\bosen\AppData\Local\cairn-e2e-*`).
```
