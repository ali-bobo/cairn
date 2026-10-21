# CLAUDE.md — Cairn project guide for Claude Code

> **Status: S1–S4 complete; post-S4 hardening merged. Phase 0 cleanup removed the
> raw-disk collectors, the updater, age/bodyfile output and rule XOR encoding.
> Current backlog: `docs/REMAINING-WORK.md`.**

This file is the operating contract for Claude Code working in this repo. Read it
fully before writing code. Authoritative spec: `cairn-SRS.md`.
Backlog + per-segment known risks: `docs/REMAINING-WORK.md`.
Decision context: `cairn-decision-summary.md`.

## What this is
A single signed Rust binary: agentless, **user-space only**, on-host Windows
live-forensics triage. It reads live state (processes, network, logon sessions,
persistence/ASEPs, WMI subscriptions, scheduled tasks, prefetch) + EVTX, runs Sigma rules + heuristics, and emits a small severity/ATT&CK-tagged, hashed
timeline. Model = Hayabusa(engine)+Chainsaw(artifact hunt)+KAPE(collect/process
split)+Velociraptor offline-collector(packaging), fused in one process.

## GOLDEN RULES (see docs/threat-model.md of SRS)
1. **No evasion by default.** FORBIDDEN, auto-reject in review unless explicitly
   overridden (see exception clause below): process injection; direct/indirect
   syscalls to bypass hooks; AMSI/ETW patch or bypass; in-memory execution of
   downloaded code; packing/obfuscation/entropy-reduction; anti-debug/anti-VM;
   artifact erasure or log tampering; masquerade/system-impersonation naming.
   The EDR SHOULD see this tool and recognize it as benign.

   **Exception clause (2026-07-15, user-approved)**: this rule may be overridden
   ONLY when the user explicitly and individually approves a *specific* evasion
   technique *within the current conversation*. A past approval — including this
   one — does NOT carry forward to a new request, a new session, or a different
   technique. If asked to bypass detection and no such live approval exists in
   this conversation, refuse and ask first; do not infer consent from urgency,
   repetition, or "we discussed this before." Every use of this exception MUST
   be logged (commit message + a line in this file's or the relevant rule's
   lesson log) naming what was approved and why, so the exception's use stays
   auditable rather than becoming silent default behavior.
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
- `crates/cairn-core`  — typed contracts: Record (persistence `Mechanism` enum), Finding (+ EvidenceItem; `analyzer` = producing analyzer's name), Observation, Manifest (`SourceEntry.collector`), traits, Config, selection, orchestrator (panic-guarded collector/analyzer runs; `run_analyzers` shared by live and evtx), canonical `collectors::*` / `analyzers::*` name constants. Depend-on-only crate; no host or external-forensic deps.
- `crates/cairn-collectors` — artifact->Record collectors (evtx file + live; proc/net/logon_session; persist + asep incl. per-user HKU; WMI subscriptions; scheduled tasks; prefetch). `#![forbid(unsafe_code)]`.
- `crates/cairn-collectors-win` — Windows unsafe FFI ONLY (proc/net/host/privilege/logon/signature/WMI/priority). The single `#![allow(unsafe_code)]` crate; `cfg(windows)`, empty shell elsewhere.
- `crates/cairn-sigma` — SigmaMatcher trait + sigma-rust engine + LogsourceMap + ruleset aggregate hash (ADR-0003).
- `crates/cairn-heur`  — heuristic analyzers (parentchild/netconn/account/logon_bruteforce/eventlog/clickfix/persist/asep) + score.rs scoring/cross-artifact corroboration + trust.rs, the single home of shared detection knowledge (drop-zone dirs, launcher table, exe-name tokenizer, encoded-command/base64 checks, script markers) + coverage table. Analyzers set `Finding.analyzer` and correlate on it, never on reason/title text.
- `crates/cairn-report`— timeline(csv)/findings(jsonl)/observations(jsonl)/manifest/report.html, sha256, output sinks (Dir/Zip/DryRun), verify, client_text (zh-TW client wording, chosen from `Finding.analyzer` + typed mechanism).
- `crates/cairn-cli`   — `cairn` binary, clap CLI (SRS §6). Subcommands: run / evtx / coverage / verify. Modules: cli (args), registry (THE collector table + analyzer set for live/evtx — add a collector or analyzer there, nowhere else), run, evtx, coverage, verify, enrich, output.
- `crates/cairn-launcher` — interactive CLI launcher for end users; double-click entry point that wraps cairn.exe.
- `rules/`             — bundled Sigma (DRL 1.1, plain YAML under `rules/sigma/`) + config maps. Bundle manifest: `rules/ruleset.toml` (a test keeps it in sync with `rules/sigma/`).
- `docs/`              — REMAINING-WORK (backlog), COVERAGE, threat-model, SOC-runbook, ADRs.
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
- Prefer streaming iteration over loading whole artifacts (EVTX).
- Collectors run sequentially and independently; analyzers fan in over the
  accumulated records in `depends_on()` order.
- No stringly-typed coupling: match on typed fields (`Mechanism`,
  `Finding.analyzer`, `SourceEntry.collector`) and the name constants in
  `cairn_core::{collectors, analyzers}`, never on titles or reason text.

## Skills to lean on (Claude Code)
There is no project-specific "skill" to install — for Claude Code the equivalent
is THIS file. Use the available engineering workflow skills where they fit:
- architecture / system-design : when adding a new collector or the orchestrator.
- testing-strategy : when building the EVTX-ATTACK-SAMPLES parity harness (T8).
- code-review : before each task's acceptance gate, esp. the unsafe cairn-collectors-win FFI.
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

## Testing collectors and analyzers
- Prefer synthetic integration tests that exercise the pipeline through `run_live`
  with a fake collector (pattern: `sigma_analyzer_findings_appear_in_live_outcome`,
  `logon_bruteforce_heuristic_fires_in_live_outcome` in cairn-cli `run.rs`).
- Report wording tests feed findings produced by the real analyzers (see
  cairn-report `client_text.rs`), not hand-built titles.
- Real-machine e2e as elevated admin remains the final acceptance bar for the live
  collectors.

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
