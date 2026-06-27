# Governance (NFR9/NFR10 resource governance) — Design

> Status: APPROVED (brainstorm 2026-06-20). Owning stage: S2 (raw-NTFS) safety
> pre-requisite per SRS §19.1. This sub-segment installs the resource guard-rails
> that must exist BEFORE the heavier raw-NTFS full-parse collectors are wired into
> the live run path.

## 1. Why this, why now

SRS §12 risk: "a multi-GB $MFT/$J parse can spike a live server to 100% CPU/RAM …
the triage tool must not become the incident." SRS §19.1 makes resource governance
the owning concern of the raw-NTFS stage. The raw volume-read primitive
(`cairn-collectors-win::volume::VolumeReader`) and the `MftCollector` already exist
and are tested, but the live run path has **no thread cap, no priority yielding, no
profile-driven skip of heavy collectors, and no manifest-visible truncation record**.
This sub-segment installs those guard-rails. It is deliberately the step BEFORE
exercising `MftCollector` on a real volume in the live path.

Principle: **install the guard-rails, then open the gate.**

## 2. Scope (what changed during brainstorm)

Investigation of `main` (fc562e6) showed parts of the originally-envisioned design
already exist. The final scope is narrower than the first sketch:

| Concern | Pre-existing on main | This segment does |
| --- | --- | --- |
| Profile→collector gating | **`cairn_core::select_modules` EXISTS & tested**; `RAW_NTFS = &["mft"]`; `minimal` already excludes mft; wired CLI→manifest `selected_modules` | nothing to the selection logic itself |
| `resolve_mft_paths` toggle | exists (`Config`, default true) | **profile `minimal` forces it false** (the one missing linkage) |
| Raw volume read primitive | `VolumeReader` EXISTS & tested | nothing |
| Thread cap / rayon pool | only `rayon` dep declared; **no `build_global`** | **add `--max-threads`, default `min(cores, 8)`, call `build_global` once in `main`** |
| Below-normal priority | **does not exist** | **new `priority` module in collectors-win; live target lowers priority by default; `--full-speed` opts out** |
| Circuit-breaker truncation record | mft cap exists but hit is **only logged via `tracing`**, not in the manifest | **surface mft truncation in the manifest** |
| OS-level RSS hard kill (job object) | — | **OUT OF SCOPE** (chosen lightweight path; avoids a second unsafe FFI surface and the kill-vs-graceful-degrade tension) |

Zero new dependencies (`rayon`, `windows` already in use). `unsafe` is confined to
the new `priority` module inside `cairn-collectors-win` (the single allow-unsafe crate).

## 3. Data model (cairn-core)

New sub-struct on `Config`, grouping the two pure resource knobs:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Governance {
    /// rayon global pool ceiling. None = default min(cores, MAX_THREADS_CEILING)
    /// (NFR9: not all cores). Some(n) = explicit `--max-threads N`. n is clamped
    /// to >= 1 by the resolver (a 0 from the CLI is treated as "use default").
    pub max_threads: Option<usize>,
    /// Lower this process's CPU + IO priority (below-normal + background IO).
    /// Default true for a live target, false for offline analysis. `--full-speed`
    /// forces false for any target.
    pub low_priority: bool,
}
```

- `Config` gains `pub governance: Governance`.
- `Config::default()` → `Governance { max_threads: None, low_priority: false }`
  (Default serves the evtx/offline path; the live path flips `low_priority` true
  when it builds the live Config).
- `Profile` stays a top-level `Config` field (it also governs output verbosity, so
  it is not purely a governance knob — keeping it where it is avoids over-coupling).

A pure resolver function determines the effective thread count (testable without
touching the global pool):

```rust
/// Effective rayon thread count from the requested cap. Pure; no global state.
/// - None      → min(available_parallelism, MAX_THREADS_CEILING)
/// - Some(0)   → treated as None (a 0 cap is meaningless; use the default)
/// - Some(n>0) → min(n, available_parallelism)  // never exceed real cores
pub fn resolve_max_threads(requested: Option<usize>, available: usize) -> usize;
```

`MAX_THREADS_CEILING` const = 8 (NFR9 "sane ceiling, not all cores").
`available` is passed in by the caller (from `std::thread::available_parallelism`)
so the function is deterministic and unit-testable.

## 4. Priority wrapper (cairn-collectors-win — the only unsafe in this segment)

New file `crates/cairn-collectors-win/src/priority.rs`, mirroring `volume.rs`:
Windows impl + non-Windows stub + a single safe wrapper.

```rust
/// Lower this process to below-normal CPU + background-IO priority so Cairn
/// yields to production workloads on a live host. Best-effort: returns Err if the
/// WinAPI call fails; the caller records that in the manifest and continues at
/// normal priority (golden rule 8). A forensic tool that yields CPU is benign,
/// not evasion (golden rule 1).
pub fn lower_priority() -> Result<()>;
```

Windows implementation:
- `SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS)` — lower CPU.
- `SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN)` — also
  lowers IO priority for the duration of the process (Win32 background mode).
- Symbols live in `windows::Win32::System::Threading` (`GetCurrentProcess` is
  already imported from there in `privilege.rs`). On `windows` 0.62 the priority
  constants are values of `PROCESS_CREATION_FLAGS`. The implementer MUST confirm
  the exact symbol paths with `cargo check` and adjust imports if 0.62 differs;
  the SAFETY contract below is unaffected by the symbol path.
- SAFETY: `GetCurrentProcess()` returns a pseudo-handle that must NOT be closed;
  `SetPriorityClass` only reads the handle and returns a BOOL — we check the
  return value and never dereference anything. No handle is leaked or freed.

Non-Windows stub: `lower_priority()` returns `Ok(())` (no-op). Offline analysis on
an analyst's non-Windows box has no live host to yield to.

Attacker-view check: this call only changes the calling process's own scheduling
priority. It needs no extra privilege (a process may always lower its own
priority), touches no other process, opens no network connection. Its sole effect
is that Cairn runs slower. No residual risk.

## 5. Profile → resolve_mft_paths linkage (cairn-core)

The selection mechanism (`select_modules`) already skips `mft` under `minimal`.
The one missing linkage: `minimal` should also force `resolve_mft_paths = false`
(path map is the first enhancement to drop in light mode — already documented in
the `Config.resolve_mft_paths` doc comment). Implement as a normalization step:

```rust
impl Config {
    /// Apply profile-implied light-mode overrides. Called once after CLI parsing,
    /// before the run. Currently: `minimal` disables full-path reconstruction.
    /// Idempotent.
    pub fn normalize_for_profile(&mut self) {
        if self.profile == Profile::Minimal {
            self.resolve_mft_paths = false;
        }
    }
}
```

(`standard`/`verbose` leave `resolve_mft_paths` at its configured value.)

## 6. Circuit-breaker truncation in the manifest (cairn-core + collectors + cli)

Today, when the mft scan stops at `min(capacity, max_records)` it only emits a
`tracing::info!`. NFR10 wants the circuit-breaker event to be a manifest-visible
fact, not just a log line. Minimal, additive change:

New manifest field (additive — serde `#[serde(default)]` for backward compat with
pre-governance manifests, matching the existing `SourceEntry.errors` pattern):

```rust
// in Manifest
/// Resource-governance notes: collectors that hit a cap / circuit-breaker, the
/// effective thread count, and whether priority was lowered. Transparency for
/// NFR9/NFR10 (the run is honest about what it throttled or truncated).
#[serde(default)]
pub governance: GovernanceReport,

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceReport {
    /// Effective rayon thread count used this run.
    pub effective_threads: usize,
    /// Whether process priority was lowered (and, if attempted-but-failed, noted).
    pub low_priority_applied: bool,
    /// One entry per collector that hit a record cap / circuit breaker.
    #[serde(default)]
    pub truncations: Vec<Truncation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Truncation {
    pub collector: String,   // e.g. "mft"
    pub cap: u64,            // the cap that fired
    pub reason: String,      // e.g. "max_mft_records reached"
}
```

### 6.1 How mft surfaces truncation — the exact mechanism (no trait change)

Constraints discovered by reading `cairn_core::traits`:
- `Collector::collect` returns `Result<Vec<Record>>` — no place for a side fact.
- `Collector::sources()` returns `Vec<SourceEntry>` and `SourceEntry` ALREADY has
  an additive `errors: Vec<String>` field that the run path ALREADY writes into the
  manifest's `sources`. But `sources()` is logically stateless (static provenance).
- `Collector` requires `Send + Sync`, so any interior mutability must be `Sync`.
- Changing the `Collector` trait or `CollectCtx` would ripple across every existing
  collector — explicitly avoided (no unrelated refactor).

**Chosen mechanism (minimal, no trait/ctx churn): an interior-mutable flag on
`MftCollector`.**

```rust
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct MftCollector {
    /// Set by `collect` when the scan stopped at the record cap rather than at the
    /// volume's true record count. Read by `sources()` and by the run path.
    /// AtomicBool (not Cell) because `Collector: Send + Sync`.
    truncated: AtomicBool,
}
```

- `parse_mft_records` changes its return tuple to
  `(capacity: u64, truncated: bool, Vec<FileMetaRecord>)`, where
  `truncated = capacity > max_records` (the cap, not the volume, bounded the scan).
  (`scan_bare` and the resolve path both return the same `truncated` value computed
  once from `capacity` vs `max_records`.)
- `MftCollector::collect` stores it: `self.truncated.store(truncated, Ordering::Relaxed);`
  and keeps its existing `tracing::info!`.
- `MftCollector::sources()` appends a structured error string to the mft
  `SourceEntry.errors` when `self.truncated.load(Relaxed)` is true, e.g.
  `"truncated: max_mft_records reached (cap=<N>)"`. This makes the cap hit visible
  in the manifest's `sources` block via the EXISTING additive field — zero schema
  churn there.

### 6.2 Populating `GovernanceReport.truncations`

The run path (cli `run`) builds the manifest. After running the mft collector (when
it is in scope) it reads `mft_collector.truncated` and, if true, pushes a
`Truncation { collector: "mft", cap, reason: "max_mft_records reached" }` into
`GovernanceReport.truncations`. The `GovernanceReport` is assembled in the cli run
path alongside `effective_threads` and `low_priority_applied` (§7), then attached
to the `Manifest`.

This means the cap hit is recorded in BOTH places, intentionally: `sources[].errors`
(per-artifact provenance, already part of chain-of-custody) and
`governance.truncations` (the consolidated NFR10 circuit-breaker view). They derive
from the same single `truncated` boolean, so they cannot disagree.

Note: until `MftCollector` joins the live AVAILABLE set (the NEXT segment), the run
path has no mft instance to read. The `GovernanceReport.truncations` plumbing in the
cli is therefore written but only exercised end-to-end once mft is live; the
`parse_mft_records` `truncated` flag itself is unit-tested now (§8).

## 7. CLI wiring (cairn-cli)

`RunArgs` gains:
- `--max-threads <N>` (`Option<usize>`, default None → resolver picks min(cores,8)).
- `--full-speed` (`bool` flag, default false): forces `low_priority = false`.

In the live `run` path, after parsing args and building Config:
1. `cfg.governance.max_threads = args.max_threads;`
2. `cfg.governance.low_priority = is_live && !args.full_speed;`
3. `cfg.normalize_for_profile();`
4. Resolve threads: `let n = resolve_max_threads(cfg.governance.max_threads, available);`
5. Build the global rayon pool ONCE:
   `rayon::ThreadPoolBuilder::new().num_threads(n).build_global()` — ignore the
   `Err` if already initialized (idempotent across the process; only the first
   wins). Record `n` in `GovernanceReport.effective_threads`.
6. If `cfg.governance.low_priority`, call `cairn_collectors_win::priority::lower_priority()`;
   set `GovernanceReport.low_priority_applied` to the Ok/Err outcome (Err → false,
   and a note; never abort — golden rule 8).

`build_global` is a process-global one-shot; it is therefore NOT called from unit
tests (would poison other tests' pools). Only `resolve_max_threads` (pure) is unit
tested; the actual `build_global` call is exercised only by the binary at runtime
and by the e2e.

## 8. Testing strategy

Pure unit tests (run on every platform, in CI's Linux job):
- `resolve_max_threads`: None→min(cores,8) capped; Some(0)→default; Some(2)→2;
  Some(1000)→clamped to available; Some(n) never exceeds `available`.
- `Config::default().governance` = `{ max_threads: None, low_priority: false }`.
- `normalize_for_profile`: minimal forces `resolve_mft_paths=false`; standard/
  verbose leave it; idempotent (calling twice == once).
- `GovernanceReport` / `Truncation` serde round-trip; old manifest JSON without the
  `governance` field deserializes (default).
- mft `truncated` flag: capacity > cap → true; capacity <= cap → false (extend the
  existing mft tests with the new tuple element).

priority wrapper:
- non-Windows: `lower_priority()` returns `Ok(())`.
- Windows (CI Windows job): `lower_priority()` returns `Ok(())` on a normal process.
  We assert the call succeeds and does not panic; we do NOT read the priority back
  (reading-back makes the test brittle and proves nothing the call's Ok doesn't).

e2e (Windows, writes to `C:\Users\bosen\AppData\Local`, never the OneDrive tree):
- a `--profile minimal` run produces a manifest whose `governance.effective_threads`
  is set, `low_priority_applied` reflects the live/full-speed choice, and (when mft
  is in scope and caps) a `truncations` entry exists. Since mft is not yet in the
  live AVAILABLE set, the e2e asserts the governance block is present and populated
  for the thread/priority fields; the mft-truncation assertion is exercised by the
  unit test on `parse_mft_records` until mft joins the live path.

## 9. Crate touch map

| Concern | Crate | unsafe? |
| --- | --- | --- |
| `Governance`, `resolve_max_threads`, `normalize_for_profile` | cairn-core | no |
| `GovernanceReport`, `Truncation` (manifest) | cairn-core | no |
| `priority::lower_priority` | cairn-collectors-win | **yes (isolated)** |
| mft `truncated` flag | cairn-collectors | no |
| `--max-threads`/`--full-speed`, `build_global`, priority call, report assembly | cairn-cli | no |

## 10. Golden-rule / threat-model check

- GR1 (no evasion): lowering own priority is benign and visible; recorded in the
  manifest. Not evasion.
- GR3 (collectors don't modify host): priority change is to Cairn's own process,
  not the host's artifacts. No host state changed.
- GR4 (output off-target, dry-run writes nothing): governance adds no output side
  effects; `--dry-run` still writes nothing.
- GR8 (graceful degrade): priority failure, thread-pool-already-init, and cap hits
  are all recorded-and-continue, never abort.
- NFR3 (unsafe only in collectors-win): the single new unsafe is in
  `priority.rs` inside collectors-win.

## 11. Out of scope (explicit YAGNI)

- OS-level RSS hard kill / Windows job object memory limit (deferred; the
  lightweight record-truncation path is chosen).
- Per-analyzer memory accounting beyond the existing per-collector record caps.
- `--full-speed` granularity (per-resource opt-out); a single boolean is enough.
- Wiring `MftCollector` into the live AVAILABLE set — that is the NEXT segment
  (real-volume mft), which this segment exists to make safe.
