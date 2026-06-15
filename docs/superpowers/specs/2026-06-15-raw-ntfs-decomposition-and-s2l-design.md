# raw-NTFS decomposition + S2-L (profile/only wiring) — Design

> Sub-segment of Stage 2 (the second half: SRS §16 "raw-NTFS + offline hives").
> Authoritative spec: `cairn-SRS.md` (§4 mft/usn/hive collectors, FR12, §8 NFR9-12, §19.1).
> Predecessors: S2-A..K (live collectors, heuristics, signed mainline, scheduled tasks, hashing).
> **This document does two things:** (A) records how raw-NTFS is decomposed into a SEQUENCE of
> sub-segments (so each is small and shippable), and (B) specifies the FIRST one, S2-L. Only
> S2-L is implemented now; S2-M..P each get their own brainstorm → spec → plan later.

---

## Part A — raw-NTFS decomposition (the plan for the whole second half)

### Why decompose

raw-NTFS is the single biggest and hardest remaining piece. Doing it as one sub-segment would
combine, in one change: unsafe `\\.\C:` raw volume reads, an NTFS structure parser, admin+SeBackup
privilege (breaking the non-admin e2e pattern used everywhere so far), resource governance
(NFR9-12, so it doesn't take a production host down), AND multiple artifact collectors ($MFT, $J,
offline hives). That is too much risk in one step. It splits cleanly along de-risking lines.

### Feasibility findings (verified during this brainstorm, 2026-06-14/15)

- **NTFS parsing has mature Rust crates** — `ntfs` 0.4.0 (Colin Finck, trait-based Read+Seek,
  no RustSec advisory), plus `ntfs-reader` 0.4.5 ("Read MFT and USN journal"), `ntfs-forensic`
  0.7.0 ("timestomping, ADS, deleted records, MFT"), `ntfs-core` 0.8.0. So we do NOT hand-roll
  NTFS format parsing; the from-scratch reverse-engineering risk is off the table. Crate SELECTION
  (maintenance, unsafe surface, whether it self-opens the volume, forensic-field completeness) is
  a decision for S2-M, not now.
- **unsafe collapses to the volume-read primitive.** The `ntfs` crate reads from a `Read+Seek`
  source we supply; the only unsafe we must write is "raw-read `\\.\C:` and present it as
  Read+Seek" — a small module in `cairn-collectors-win` (the single allow(unsafe) crate).
- **Privilege:** raw volume read needs Administrator + SeBackupPrivilege. Every prior e2e ran
  non-admin; S2-M+ e2e MUST run elevated, and must graceful-degrade (skip + manifest note) when
  not elevated — golden rule 8.
- **Resource governance ordering:** SRS §19.1 defines `--profile minimal` as "SKIP raw-NTFS",
  so the profile switch must exist BEFORE raw-NTFS lands (something has to be able to skip it).
  Hence S2-L (profile/only wiring) comes first.

### The sequence (each its own future sub-segment)

| # | Sub-segment | What | unsafe? | admin? | depends on |
|---|---|---|---|---|---|
| **S2-L** | **profile/only wiring (THIS doc, Part B)** | wire the declared-but-ignored `--profile`/`--only` to actual collector selection; `minimal` skips raw-NTFS (when it exists) | no | no | — |
| S2-M | raw volume read primitive + NTFS crate pick | unsafe `\\.\C:` Read+Seek in cairn-collectors-win + select the NTFS crate + smallest proof ($MFT record count) | yes | yes | S2-L |
| S2-N | $MFT collector | MACB times + SI/FN timestomp delta → FileMetaRecord | (reuses M) | yes | S2-M |
| S2-O | $J / USN collector | create/delete/rename history → UsnEvent | (reuses M) | yes | S2-M |
| S2-P | offline locked hive collector | read locked SYSTEM/SOFTWARE/NTUSER hives → RegValue | (reuses M) | yes | S2-M |
| later | Amcache / Shimcache / Prefetch / SRUM | execution-evidence collectors built on hive/file reads | (reuses) | yes | S2-P |
| later | thread cap / rayon pool / IO priority (NFR9 rest) | added WHEN raw-NTFS actually parallelizes heavy parsing (no parallelism today, so a cap would gate nothing) | small | — | S2-N..P |

**Note on thread/IO governance:** SRS §19.1 lists `--max-threads`, rayon pool cap, and IO
priority. Verified during this brainstorm: collectors currently run SERIALLY (rayon is a declared
dep but unused; `orchestrator::run_live` is a `for c in collectors` loop). A thread cap today
would govern nothing. So that governance is deferred to the sub-segment where raw-NTFS actually
uses rayon to parallelize $MFT/$J parsing — added with the workload it protects, not before.

### Smallest first slice = S2-L

S2-L is the smallest slice that delivers value and de-risks the rest: it is pure-safe, non-admin,
touches no NTFS, and installs the `--profile`/`--only` selection that (a) fixes today's misleading
flags and (b) is the prerequisite "skip raw-NTFS" switch S2-M+ depend on.

---

## Part B — S2-L specification (profile/only wiring)

### Purpose

`cairn run` declares `--profile <minimal|standard|verbose>` and `--only <csv>` and `Config` has a
`Profile` enum — but the `run` arm IGNORES both: the collector list is a hardcoded `vec![proc,
net, persist]`, and neither `args.profile` nor `args.only` is parsed into the run. `--only evtx`
does not actually restrict anything; `--profile minimal` does nothing. S2-L wires both to real
collector selection, fixing the misleading flags and installing the profile switch that raw-NTFS
(S2-M+) will hang off.

### Scope

**In scope:**
- Parse `--profile` (string) into the existing `Profile` enum; thread it into the run.
- Parse `--only <csv>` into a module allow-list.
- A pure `select_collectors(profile, only, available) -> Vec<name>` decision function: given the
  profile, the optional only-list, and the set of available collector names, return which to run.
  Linux-CI-testable (pure; no host).
- The `run` arm builds its collector list from that decision instead of the hardcoded vec.
- A `Profile::from_str` (or TryFrom) so an invalid `--profile` value is a clean error, not a
  silent fallback.
- Manifest/run.log record the active profile + selected modules (transparency, FR6).

**Explicitly OUT of scope (deferred, with rationale):**
- **Thread cap / rayon pool / IO priority (NFR9 rest).** No parallelism exists today; deferred to
  the raw-NTFS parsing sub-segment that introduces it (Part A note).
- **Analyzer memory bounds (NFR10).** Needs an accumulating analyzer (correlation) to matter; none
  exists. Deferred.
- **raw-NTFS itself** and any `minimal`-skips-raw-NTFS behavior beyond the selection wiring — the
  raw-NTFS collectors don't exist yet, so `minimal` simply selects the live set; the skip becomes
  real automatically when S2-M+ register raw-NTFS collectors as `standard`/`verbose`-only.
- **evtx in the run arm.** `cairn run` is live-only today (`cairn evtx` is the separate EVTX path);
  the only-list covers the live collectors that exist (process, net, persist). Unknown names in
  `--only` are reported, not silently dropped (the misleading-flag lesson).

### Profile → module mapping

The `Profile` enum (`Minimal`, `Standard`, `Verbose`) maps to module sets. With only live
collectors existing today:
- **minimal** = live state + persistence (process, net, persist) — the light triage set. (Per
  SRS §19.1 minimal also = EVTX, but `cairn run` is live-only; EVTX is `cairn evtx`. minimal here
  is the live light set.)
- **standard** = minimal + (future offline artifacts). Today == minimal's collectors.
- **verbose** = everything (today == standard).

Because the three live collectors are light, all three profiles currently select the same live set
— the DIFFERENCE becomes meaningful when S2-M+ register raw-NTFS/offline collectors tagged
`standard`/`verbose`-only, which `minimal` then skips. S2-L builds the selection MECHANISM; the
profiles diverge as heavier collectors are added. This is the correct order: switch first, heavy
collectors gated by it later.

`--only <csv>` intersects with the profile selection: a module runs iff it is in the profile's set
AND (only is None OR the module is in only). An only-name not matching any available collector is
logged as a warning (not silently ignored).

### Architecture

```
cairn-core/src/config.rs
  Profile::from_str (or TryFrom<&str>) -> Result<Profile>  (minimal|standard|verbose; else Err)
  (Config already has `profile: Profile`)

cairn-core (or cli) — pure decision:
  select_collectors(profile: Profile, only: Option<&[String]>, available: &[&str]) -> Vec<String>
    1. base = modules for `profile` (minimal/standard/verbose → name set)
    2. if `only` is Some, keep only names in both base and only; warn on only-names not in `available`
    3. return the kept names, intersected with `available`
    PURE: no host, no I/O. Unit-tested on Linux.

cli `run` arm:
  parse args.profile -> Profile (clean error on bad value)
  parse args.only -> Option<Vec<String>>
  let selected = select_collectors(profile, only.as_deref(), &["process","net","persist"]);
  build collectors vec by including each only if its name ∈ selected
  (analyzers: keep all — they fan-in over whatever records exist; or gate later)
  run.log + manifest: record active profile + selected module names
```

**Layering:** all pure (selection is a string-set decision; no host, no unsafe). `cairn-cli` and
`cairn-core` stay `#![forbid(unsafe_code)]`. No new dependency.

### Error handling / graceful degrade

- Invalid `--profile` value → clean CLI error (exit non-zero), not a silent Standard fallback.
- `--only` name that matches no available collector → warning in run.log, the run continues with
  the valid intersection (don't abort; don't silently pretend it matched).
- Empty selection (e.g. `--only nonexistent`) → run produces no records but does not panic; the
  manifest records zero selected modules honestly.
- Determinism (NFR4): selection order is deterministic (fixed module order).

### Security note (golden rules)

- Pure orchestration logic; no host modification, no unsafe, no evasion. `--profile minimal` is a
  footprint-reduction lever (golden rule 4 spirit). The profile/selected-modules are logged
  (transparency).

### Testing

- **Profile::from_str (pure):** "minimal"/"standard"/"verbose" (case-insensitive) → variants;
  "bogus" → Err.
- **select_collectors (pure):**
  - profile=standard, only=None, available=[process,net,persist] → all three.
  - profile=minimal, only=None → the minimal live set (today: all three).
  - only=Some([persist]) → just persist.
  - only=Some([persist, bogus]) → just persist (bogus warned, not included).
  - only=Some([bogus]) → empty (no panic).
  - a name in only but not in available → excluded; a name in available but not in profile base →
    excluded.
- **run-arm wiring (smoke):** `--only persist` runs only the persist collector (the others are not
  constructed/run); `--profile minimal` selects the live set; an invalid `--profile` exits non-zero.
- **e2e (manual, Windows, non-admin):** `cairn run --target live --only persist` → records contain
  ONLY persistence (today it also would have, but now provably via selection, not by accident);
  `cairn run --target live --profile minimal` runs the live set; `cairn run --profile bogus` errors;
  `cairn verify` passes; the manifest/run.log show the active profile + selected modules.

### Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new dep).
- `unsafe` in no crate except `cairn-collectors-win`; cli/core stay `#![forbid(unsafe_code)]`.
- A real live run honors `--only` (provably restricts collectors) and `--profile` (selects the
  set; invalid value errors); manifest/run.log record the choice; `cairn verify` passes; earlier
  stages unchanged.
- No golden-rule violation; no scope creep (no thread cap, no raw-NTFS, no memory bounds).

### Non-goals / future hooks (S2-L)

- Thread cap / rayon pool / IO priority → the raw-NTFS parsing sub-segment (Part A).
- `minimal` actually skipping a heavy collector → automatic once S2-M+ tag raw-NTFS collectors
  `standard`/`verbose`-only.
- Per-analyzer gating by profile → if/when an analyzer becomes expensive.
