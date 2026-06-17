# S2-N′ — Timestomp Delta Heuristic (design)

> **Status:** design, approved 2026-06-18.
> **Predecessor:** S2-N ($MFT MACB + SI/FN dual-axis collection, merged main 7e1decf).
> S2-N read the *material* (SI/FN btime+mtime into `Record::FileMeta`); S2-N′ turns
> that material into a *judgement* — a `cairn-heur` analyzer that flags timestomp.
> **Authoritative spec:** `cairn-SRS.md` §10 (heuristics). **ATT&CK:** T1070.006
> (Indicator Removal: Timestomp).

## 1. Scope & intent

A new `cairn-heur` analyzer, `TimestompHeuristic`, consumes the `Record::FileMeta`
stream produced by the S2-N mft collector and emits a `Finding` when a file's
`$STANDARD_INFORMATION` (SI) timestamps are **directionally earlier than** its
`$FILE_NAME` (FN) timestamps **beyond a threshold** — the canonical timestomp
signature (`SetFileTime` backdates SI to make a file look old; FN is kernel-only
and stays at the real, later time).

This is a **pure Record→Finding analyzer**. It touches no host state, keeps
`cairn-heur`'s `#![forbid(unsafe_code)]`, and adds **zero new dependencies** (uses
the existing `chrono`). Because it never touches the host, the whole feature is
verifiable on the dev box — there is **no "left to the operator" elevated-e2e gap**
(the key contrast with S2-N).

### In scope
- A `detect_timestomp` pure function over one `FileMetaRecord`.
- The `TimestompHeuristic` `Analyzer`, wired into the CLI analyzer vec.
- Two new evidence fields on `EntityFile` (`si_mtime`, `fn_mtime`).
- A `Config.timestomp_threshold_hours` (default 24), no CLI flag.

### Out of scope (explicitly)
- No CLI flag for the threshold (banding carries severity; the threshold is a
  fixed Config default — decided in brainstorm).
- No system-path (`C:\Windows\`) whitelist / band-down — avoids the "attacker
  hides in the Windows folder" blind spot (fail-loud). Path goes into `details`
  for analyst judgement instead.
- No `SI.btime > SI.mtime` (created-after-modified) contradiction signal — that is
  a multi-signal weighting extension, beyond the approved "directional + threshold"
  contract. Flagged as future work.
- No $J ($UsnJrnl) cross-correlation (that is S2-O).

## 2. Detection logic

`detect_timestomp(meta: &FileMetaRecord, threshold: Duration) -> Option<TimestompHit>`,
pure, unit-testable. `threshold` is injected (tests pass `Duration::hours(24)` or
custom; the analyzer reads it from `Config`).

For each of the **two axes** (btime, mtime), independently:

```
gate (avoid "guess on missing data"):
    the axis is evaluated ONLY when BOTH SI.<axis> and FN.<axis> are Some.
    A None on either side → that axis does not contribute (no fire).

directional + threshold test:
    delta = FN.<axis> - SI.<axis>     // positive == SI earlier than FN == backdating direction
    if delta > threshold:
        record this axis as a hit: (axis_name, si_time, fn_time, delta)
    if delta <= 0  (SI later than/equal to FN — the legit direction) → no hit
    if 0 < delta <= threshold        (sub-day legit noise)          → no hit
```

If **neither** axis hits → `None` (no finding). If **either** axis hits →
`Some(TimestompHit)` carrying every fired axis's `(si, fn, delta)` plus the
**maximum delta across fired axes** (used for banding).

**Why `FN − SI > 0` (direction matters):** classic timestomp pushes SI into the
*past* (file looks old) while FN stays at the real, later time → `FN − SI` is a
large positive. Legitimate metadata-restoring operations (unzip, copy, installer)
typically land SI at or *after* FN → `FN − SI` ≤ 0 or tiny → filtered by direction
+ the 24h threshold. `SI == FN` (delta 0) and any axis with a `None` value never
fire.

### Severity banding (by the max fired delta)

This heuristic is **magnitude-banded, not weight-accumulated** — unlike
`persist.rs`, it does not sum independent signals, so it does **not** reuse
`score.rs::severity_for` (which maps an additive weight). It uses a dedicated map:

| max fired delta | Severity | rationale |
|---|---|---|
| `> 24h` and `≤ 30 days` | **Medium** | beyond legit noise but bounded — could be TZ / batch-op residue |
| `> 30 days` and `≤ 365 days` | **High** | clearly deliberate, month-scale rollback |
| `> 365 days` | **Critical** | textbook backdating (payload made to look "old enough to be unsuspicious") |

The `> 24h` lower edge equals `threshold`, so a hit (delta `> threshold`) always
lands at least Medium. There is no "Low" band: a directional super-threshold delta
is never merely informational.

`Score` (from `score.rs`) is still used to collect the human-readable `reason`
strings and the (single, deduped) `T1070.006` mitre tag — but severity comes from
`timestomp_severity(max_delta)`, not from `Score.weight`.

## 3. Schema changes (additive, backward-compatible)

serde fills a missing `Option` field with `None`, so adding optional fields is
backward-compatible with old JSON (regression-tested).

### 3.1 `EntityFile` (`crates/cairn-core/src/finding.rs`)

Add two fields aligned with the existing `si_btime`/`fn_btime`:

```rust
pub struct EntityFile {
    pub path: String,
    pub sha256: Option<String>,
    pub mtime: Option<DateTime<Utc>>,
    pub si_btime: Option<DateTime<Utc>>,
    pub fn_btime: Option<DateTime<Utc>>,
    pub si_mtime: Option<DateTime<Utc>>,   // NEW (S2-N′)
    pub fn_mtime: Option<DateTime<Utc>>,   // NEW (S2-N′)
}
```

Every existing `EntityFile { .. }` constructor must add `si_mtime`/`fn_mtime`
(`None` where not applicable) — the compiler enumerates them; the plan lists each.
Known sites: `persist.rs` (`persistence_entity`). The plan greps for the rest.

### 3.2 `Config` (`crates/cairn-core/src/config.rs`)

```rust
/// Min FN−SI delta (hours) on either axis before a timestomp Finding fires (S2-N′).
/// Below this, sub-day SI/FN drift from legit ops (unzip/copy/install) is ignored.
pub timestomp_threshold_hours: i64,   // default 24
```

Default `24` in `Config::default()`. No CLI flag (brainstorm decision).

## 4. File structure

| File | Action | Responsibility |
|---|---|---|
| `crates/cairn-core/src/finding.rs` | Modify | `EntityFile` + `si_mtime`/`fn_mtime` |
| `crates/cairn-core/src/config.rs` | Modify | `Config.timestomp_threshold_hours` (default 24) |
| `crates/cairn-heur/src/timestomp.rs` | **Create** | `detect_timestomp` + `timestomp_severity` + `TimestompHeuristic` + tests |
| `crates/cairn-heur/src/lib.rs` | Modify | `pub mod timestomp;` + `pub use timestomp::TimestompHeuristic;` |
| `crates/cairn-heur/src/persist.rs` | Modify | add `si_mtime: None, fn_mtime: None` to its `EntityFile` |
| `crates/cairn-cli/src/main.rs` | Modify | push `TimestompHeuristic` into analyzer vec; thread `timestomp_threshold_hours` into `Config` (default already 24, so no new CLI arg) |

The analyzer holds the threshold (read from `Config` at construction, or takes
`Config` at `analyze` time consistent with how the other analyzers get `now`).
Decision in the plan: `TimestompHeuristic` carries a `threshold: Duration` field
set from `Config.timestomp_threshold_hours` when the vec is built in main.rs — this
keeps `Analyzer::analyze(&self, &[Record])` signature unchanged.

## 5. Determinism

Findings are emitted in `records` iteration order; the orchestrator already sorts
the final timeline by `(ts, record_id)` (CLAUDE.md). `Finding.ts` for a timestomp
hit = the file's `fn_btime` (the real creation time — the most defensible anchor),
falling back to `si_mtime`/`fn_mtime`/`Utc::now()` if absent. No `HashMap`
iteration in output paths.

## 6. Testing strategy (TDD)

Unit tests in `timestomp.rs`, one per signal + boundaries + analyzer end-to-end:

- `si_earlier_than_fn_btime_beyond_threshold_fires` — SI.btime 2 years before
  FN.btime → `Some`, max_delta ~2y, severity Critical, mitre `T1070.006`.
- `mtime_axis_independently_fires` — btime axis aligned, only mtime axis super-
  threshold → fires (independent-axis coverage).
- `legit_si_after_fn_does_not_fire` — SI later than FN (unzip/copy direction) →
  `None` (directional regression).
- `delta_within_threshold_does_not_fire` — 2h drift (< 24h) → `None` (legit-noise
  regression).
- `none_timestamps_do_not_fire` — any axis with a `None` side → no contribution;
  all-None → `None` (no guessing).
- `equal_si_fn_does_not_fire` — delta 0 → `None`.
- `severity_bands` — 25h → Medium, 31 days → High, 366 days → Critical (boundary
  values just over each edge).
- `analyzer_emits_finding_with_four_axis_entity` — `TimestompHeuristic.analyze`
  on one stomped + one clean record emits exactly one `Finding` with: `reason`
  set (golden rule 6), `entity.file` carrying all four times (si/fn × b/m),
  `mitre` contains `T1070.006`, `source == Heuristic`, `artifact == "file_meta"`.
- `old_json_entityfile_deserializes_with_none_mtimes` — JSON without the two new
  fields round-trips with `si_mtime == None`, `fn_mtime == None` (backward compat).

## 7. Acceptance gate

- `cargo test --workspace --locked` — all green (243 current + new).
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — 0 warnings.
- `cargo fmt --check` — clean.
- `cargo audit --deny warnings` — clean.
- **`Cargo.lock` unchanged vs main** (zero new dependency).
- `#![forbid(unsafe_code)]` preserved in `cairn-heur` and `cairn-core`.
- Every emitted `Finding` carries `reason` (golden rule 6) and `T1070.006`.
- **No elevated e2e required** — pure analyzer; full verification on the dev box.
  A non-admin smoke run (`cairn run --target live`) confirms the analyzer is wired
  and emits nothing when no FileMeta records exist (mft skipped on non-admin),
  i.e. it does not crash the run and does not false-fire on an empty stream.

## 8. Threat-model note (think-like-an-attacker)

- **Input:** `FileMetaRecord` times originate from raw NTFS read (S2-N), already a
  trusted-internal Record by the time the analyzer sees it — no external string is
  concatenated, no untrusted parse here.
- **Evasion the attacker WANTS:** an attacker who also rewrites `$FILE_NAME` times
  (kernel-level, e.g. via a driver) defeats the SI/FN delta — acknowledged
  limitation. S2-N′ catches the overwhelmingly common user-space `SetFileTime`
  timestomp; FN-rewrite is a much higher bar and is the documented residual risk.
- **False-negative by design:** sub-threshold backdating (< 24h) is intentionally
  missed to keep false positives near zero. A SOC analyst wanting hour-level drift
  can lower `timestomp_threshold_hours` (Config), but the default protects trust.
- **No host effect:** the analyzer reads Records only; it cannot modify artifacts
  or the host (golden rule 3).
