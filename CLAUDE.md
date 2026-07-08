# CLAUDE.md — Cairn project guide for Claude Code

> **Status: S1–S4 complete; post-S4 hardening merged (gate redesign, IR panels,
> BYOVD, dependency-audit fix). Current backlog: `docs/REMAINING-WORK.md`.**

This file is the operating contract for Claude Code working in this repo. Read it
fully before writing code. Authoritative spec: `cairn-SRS.md`.
Backlog + per-segment known risks: `docs/REMAINING-WORK.md`.
Decision context: `cairn-decision-summary.md`.

Before diving into any individual spec/plan under `docs/dev-history/`, check
`docs/dev-history/INDEX.md` first — it records merge status per topic so you
don't have to open a spec just to find out it's already shipped.

## What this is
A single signed Rust binary: agentless, **user-space only**, on-host Windows
live-forensics triage. It parses live state + EVTX + offline NTFS artifacts,
runs Sigma rules + heuristics, and emits a small severity/ATT&CK-tagged, hashed
timeline. Model = Hayabusa(engine)+Chainsaw(artifact hunt)+KAPE(collect/process
split)+Velociraptor offline-collector(packaging), fused in one process.

## GOLDEN RULES (non-negotiable — see docs/threat-model.md §13 of SRS)
1. **No evasion, ever.** FORBIDDEN, auto-reject in review: process injection;
   direct/indirect syscalls to bypass hooks; AMSI/ETW patch or bypass; in-memory
   execution of downloaded code; packing/obfuscation/entropy-reduction; anti-debug
   /anti-VM; artifact erasure or log tampering; masquerade/system-impersonation
   naming. The EDR SHOULD see this tool and recognize it as benign.
2. **Release profile stays normal.** Do NOT add `strip=true`, `panic="abort"`,
   UPX, or any "make the binary small/low-entropy" trick. Those are malware tells.
3. **Collectors never modify the host. Analyzers never touch the host.** Keep the
   Collector/Analyzer seam (cairn-core::traits) clean.
4. **Output defaults off-target; `--dry-run` writes nothing.** Minimize footprint
   (USN journal preservation). Never modify source artifacts.
5. **DRL 1.1: every Sigma Finding MUST carry `rule_author`.** Surface it in output.
6. **Heuristics MUST set `Finding.reason`** (explainability). No opaque scores.
7. **All timestamps UTC RFC3339.** Record host TZ + clock skew in the manifest.
8. **Graceful degrade:** missing privilege -> skip module, record reason in
   manifest, continue. Never abort the whole run for one collector.

## Workspace map
- `crates/cairn-core`  — typed contracts: Record, Finding (+ EvidenceItem), Manifest, traits, Config, orchestrator. Depend-on-only crate; no host or external-forensic deps.
- `crates/cairn-collectors` — artifact->Record collectors (evtx live; proc/net/persist pure logic; offline raw-NTFS/hive/prefetch/srum parsers). `#![forbid(unsafe_code)]`.
- `crates/cairn-collectors-win` — Windows unsafe FFI ONLY (proc/net/host/privilege/logon; raw `\\.\C:` VolumeReader). The single `#![allow(unsafe_code)]` crate; `cfg(windows)`, empty shell elsewhere.
- `crates/cairn-sigma` — SigmaMatcher trait + sigma-rust engine + LogsourceMap + XOR rule codec.
- `crates/cairn-heur`  — heuristic analyzers (parentchild/persist gate/netconn/account/timestomp/byovd) + trust.rs path-trust knowledge + known-vulnerable-drivers list.
- `crates/cairn-report`— timeline(csv)/findings(jsonl)/observations(jsonl)/manifest/report.html, sha256, output sinks (Dir/Zip/Age/DryRun), bodyfile, client_text (zh-TW).
- `crates/cairn-updater` — `cairn update-rules`: SSRF-gated SigmaHQ fetch + DRL 1.1 + XOR encode + PROVENANCE. `#![forbid(unsafe_code)]`.
- `crates/cairn-cli`   — `cairn` binary, clap CLI (SRS §6). Subcommands: run / evtx / update-rules / verify.
- `crates/cairn-launcher` — interactive CLI launcher for end users; double-click entry point that wraps cairn.exe.
- `rules/`             — bundled Sigma (DRL 1.1) + config maps. XOR-encoded on disk (avoid AV FP on .yml; encode RULES, never the tool). Subset list: `rules/ruleset.toml`.
- `docs/`              — REMAINING-WORK (backlog), threat-model, SOC-runbook, dev-history (INDEX.md first).
- `tests/`             — EVTX-ATTACK-SAMPLES fixtures + Sigma match-parity tests.

## Build / test commands
```
cargo check --workspace
cargo build --workspace
cargo test  --workspace                                  # elevated e2e are #[ignore]
cargo clippy --workspace --all-targets -- -D warnings    # --all-targets: must match CI
cargo fmt --check                                        # must pass — CI gates on it
```
Set `CARGO_TARGET_DIR` outside OneDrive first (see Local dev environment notes).

## How to proceed (do NOT free-build)
S1–S4 and post-S4 hardening are complete. For any new work: pick the segment from
`docs/REMAINING-WORK.md`, then brainstorm → writing-plans → subagent-driven-development
→ finishing-a-development-branch. Merge via GitHub PR only (CI green first) — never
local `git merge` pushed straight to main. Each task needs its `cargo check` +
scoped `cargo test` gate before moving on.

## Coding conventions
- `#![forbid(unsafe_code)]` everywhere EXCEPT collector modules that must do raw
  `\\.\C:` volume reads / WinAPI — isolate that unsafe behind a small reviewed
  module with a safe wrapper; document the invariant.
- Errors: `cairn_core::CairnError` + `Result`; use `thiserror` in libs, `anyhow`
  only in the cli bin.
- Serialize with serde; keep schema strings from `cairn_core::schema`.
- Determinism: sort output by (ts, record_id). Reproducible builds in CI.
- Prefer streaming iteration over loading whole artifacts (EVTX, MFT).
- Parallelism via `rayon`; collectors are independent, analyzers fan-in.

## Skills to lean on (Claude Code)
There is no project-specific "skill" to install — for Claude Code the equivalent
is THIS file. Use the available engineering workflow skills where they fit:
- architecture / system-design : when adding a new collector or the orchestrator.
- testing-strategy : when building the EVTX-ATTACK-SAMPLES parity harness (T8).
- code-review : before each task's acceptance gate, esp. the unsafe raw-NTFS module.
- debug : EVTX/Sigma match mismatches.
Do not invent new skills; do not add SKILL.md files (that format is for claude.ai
/Cowork, not Claude Code).

## Test scope discipline (avoid 4x redundant full-workspace runs)
Full `cargo test --workspace` + `cargo clippy --workspace --all-targets` is expensive
and gets re-run redundantly across a single dev loop (subagent → controller →
finishing-a-branch → post-merge). Split responsibility:
- **Task-implementer subagents**: run `cargo test -p <crate>` scoped to the crate(s)
  they touched. Do not run full workspace unless the task itself changes a trait
  signature, schema, or public API surface consumed by other crates.
- **Controller (this session)**: only run full-workspace check/test/clippy when
  crossing a cross-crate boundary (trait shape in cairn-core, schema in
  cairn-report, main.rs wiring, or multi-crate integration). Otherwise trust the
  scoped subagent runs.
- **finishing-a-development-branch**: this is the one authoritative full-workspace
  gate for the whole branch before merge.
- **Post-merge**: do not re-run the full suite again; the pre-merge gate already
  covered HEAD.

## SeBackupPrivilege constraint (real-machine e2e limitation)
A normal Administrator token does NOT include `SeBackupPrivilege` by default (it
must be explicitly enabled, which most interactive admin sessions don't do). The
7 collectors that depend on raw-NTFS / raw-hive reads for real-machine e2e
verification — amcache, mft, usn, shimcache, bam, userassist, srum — will
silently produce zero records under a normal admin session, not because of a
bug but because of this privilege gap. When validating this class of feature:
- Do not treat an empty real-machine e2e run as a regression signal by itself —
  first check whether the run actually had the privilege.
- Prefer synthetic integration tests that exercise the pipeline without needing
  the real privilege, following the existing pattern of tests like
  `byovd_driver_list_override_pipeline_end_to_end` and
  `sigma_analyzer_findings_appear_in_live_outcome` (fake collector data fed
  through the real `run_live` + analyzer + report path).
- Real-machine e2e with the privilege genuinely enabled remains the final
  acceptance bar for these 7 collectors, but is not the day-to-day dev loop
  verification method.

## Legitimacy work (must exist before first real client use, any stage)
Authenticode-sign + timestamp releases; ship README intent statement (done);
embed version/manifest resources; publish hashes; open-source; produce the SOC
pre-allowlist runbook (docs/SOC-runbook-template.md); submit binary to MS WDSI.

## Local dev environment notes
- Build artifacts are kept OUT of the OneDrive-synced tree. `.cargo/config.toml` is
  committed — it contains the CRT static link rustflags. The `target-dir` line was
  intentionally removed; set `CARGO_TARGET_DIR` env var if you need a custom build
  artifact path (e.g. `$env:CARGO_TARGET_DIR = "C:\Users\<you>\AppData\Local\cairn-target"`).
  This avoids OneDrive syncing/locking `target/`.
- On Windows with real-time AV (e.g. PC-cillin), cargo build-probe executables
  (serde/anyhow/thiserror build scripts) can trip a scan and surface `os error 5` on
  cleanup. Exclude the target dir from AV scanning; if a `cargo clean` rebuild ever
  re-locks a probe, just re-run the build (probes are cached afterward).
- Toolchain is pinned via `rust-toolchain.toml`; `Cargo.lock` is committed (NFR7).
- `build.rs` stamps the git commit into `CAIRN_BUILD_SHA` (shown by `cairn --version`,
  recorded as manifest `tool.build_sha`).

## Definition of done for a task
Compiles (`cargo check`), passes its acceptance test, no clippy warnings, no
golden-rule violation, manifest/Finding schemas unchanged unless the task says so.
