# CLAUDE.md — Cairn project guide for Claude Code

This file is the operating contract for Claude Code working in this repo. Read it
fully before writing code. Authoritative spec: `cairn-SRS.md`. Build order:
`docs/stage1-plan.md`. Decision context: `cairn-decision-summary.md`.

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
- `crates/cairn-core`  — typed contracts: Record, Finding, Manifest, traits, Config, orchestrator. Depend-on-only crate; no host or external-forensic deps.
- `crates/cairn-collectors` — artifact->Record collectors (evtx; S2+ proc/net pure logic). `#![forbid(unsafe_code)]`.
- `crates/cairn-collectors-win` — Windows unsafe FFI ONLY (proc/net/host/privilege; later raw-NTFS). The single `#![allow(unsafe_code)]` crate; `cfg(windows)`, empty shell elsewhere (S2-A).
- `crates/cairn-sigma` — SigmaMatcher trait + chosen engine + LogsourceMap (de-abstraction).
- `crates/cairn-report`— timeline(csv)/findings(jsonl)/manifest, sha256, output sinks.
- `crates/cairn-cli`   — `cairn` binary, clap CLI (SRS §6).
- `rules/`             — bundled Sigma (DRL 1.1) + config maps. May be XOR-encoded on disk (avoid AV FP on .yml; encode RULES, never the tool).
- `docs/`              — stage1-plan, threat-model, SOC-runbook, sigma benchmark plan.
- `tests/`             — EVTX-ATTACK-SAMPLES fixtures + Sigma match-parity tests.

## Build / test commands
```
cargo check --workspace          # FIRST: skeleton not yet compiled; expect to fix dep versions
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace -- -D warnings
cargo fmt
```
The dependency versions in Cargo.toml are 2025-plausible starting points, NOT
verified. Resolve them in task T0 before anything else.

## How to proceed (do NOT free-build)
Work task-by-task through `docs/stage1-plan.md`. After EACH task: `cargo check`,
then `cargo test` for that task's acceptance check. Do not start a later task
until the current one's acceptance gate passes. Stage 1 (EVTX+Sigma+timeline+
manifest) must stand alone as a useful, shippable tool before any S2 work.

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
