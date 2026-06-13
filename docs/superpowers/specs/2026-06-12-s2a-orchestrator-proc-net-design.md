# S2-A design: orchestrator + proc/net live collectors

- **Date:** 2026-06-12 (UTC)
- **Status:** Approved (design); pending implementation plan
- **Authority:** `cairn-SRS.md` §3, §4, §6, §11, §12; `CLAUDE.md` golden rules; ADRs.
- **Scope tier:** first deliverable sub-segment of SRS Stage 2.

## 1. Why this sub-segment exists

SRS Stage 2 (§16) bundles ~12 modules across two risk tiers: live collectors
(proc/net/persist), three heuristics, the raw-NTFS `\\.\C:` unsafe boundary, and five
offline-artifact collectors, all tied together by an orchestrator that S1 left as a
`TODO S2+` stub. Building that as one change would be huge and unreviewable.

**S2-A is the smallest useful slice:** a minimal orchestrator plus the two collectors
that need only *safe* WinAPI calls — process enumeration and network tables. It carries
**no `unsafe` raw-NTFS**, so it is the lowest-risk way to stand up the live-triage
skeleton. When it lands, `cairn run --target live` produces a process + connection list
with a verifiable manifest.

Deferred to later sub-segments: persistence collector, the three heuristics, raw-NTFS
($MFT/$J/locked hives), offline-artifact collectors, analyzer fan-in, additional output
sinks. This spec does **not** design those.

## 2. Decisions locked in brainstorming

1. **Sub-segment = orchestrator + proc + net only.** No unsafe, no persistence, no
   heuristics.
2. **windows-rs (native WinAPI)**, not sysinfo. sysinfo cannot supply the forensic
   fields triage needs (signer, integrity level, full cmdline, correct conn→PID).
3. **New crate `cairn-collectors-win`** isolates *all* Windows `unsafe` FFI. It is the
   only crate with `#![allow(unsafe_code)]`. Same isolation pattern the future raw-NTFS
   work will reuse. (Resolves SRS open decision direction; the raw-NTFS default D3 is
   still out of scope here.)
4. **Layered testing:** error-prone logic (raw→Record mapping, process-tree assembly,
   conn→PID association, field normalization) is extracted into pure functions tested
   with TDD; the thin FFI layer gets one smoke test each. No mocking of WinAPI.
5. **Minimal orchestrator:** privilege probe → sequence a static list of `Collector`s →
   graceful degrade → existing reporter. No analyzer fan-in, no plugin registry (YAGNI).

## 3. Architecture

New crate; two crates modified; **zero** breakage to the S1 EVTX path.

```
crates/
  cairn-collectors-win/   NEW. All Windows unsafe FFI lives here, and only here.
                          #![allow(unsafe_code)] is in this crate alone.
                          Compiles under cfg(windows); an empty/Err shell elsewhere
                          so the workspace still builds on non-Windows CI.
  cairn-collectors/       Keeps #![forbid(unsafe_code)]. evtx.rs untouched. Adds
                          proc.rs / net.rs holding the PURE logic (raw -> Record),
                          which call cairn-collectors-win for the raw data.
  cairn-core/             Adds orchestrator.rs (pure sequencing). Record/traits/
                          CairnError already exist — no contract changes.
  cairn-cli/              Cmd::Run wires --target live to the orchestrator (was stub).
```

**Why a crate, not a module, for the FFI:** the crate boundary is Rust's hardest
isolation unit. `#![allow(unsafe_code)]` then scopes to exactly one crate, so a reviewer
knows *all* unsafe lives there, and the future raw-NTFS layer reuses the same boundary
(its own crate or a sibling). Module-level `allow` cannot give that "audit at a glance"
property (NFR3, CLAUDE.md coding conventions).

### Data flow (reuses the existing Collector/Analyzer/OutputSink seams)

```
cairn run --target live --output <dir>
  -> Orchestrator (cairn-core):
       1. probe privileges (admin/se_backup/se_debug)   [via cairn-collectors-win]
       2. build CollectCtx
       3. for each registered Collector in [Proc, Net]:   (volatility order: proc->net)
            Ok(records) -> accumulate; record sources()
            Err(Privilege|Collector) -> log WARN, record in manifest.sources[].errors,
                                        CONTINUE (FR13 / golden rule 8)
       4. build manifest (privileges, sources, host, counts)
  -> Reporter (existing DirSink): findings.jsonl (empty this segment), manifest.json,
       run.log. timeline.csv has only its header (no findings yet).
```

No new types and no contract changes: `ProcessRecord`, `NetConnRecord`, `Collector`,
`CollectCtx`, `CairnError::{Collector,Privilege}`, `SourceEntry.errors`, `Privileges`
all already exist (S1 pre-provisioned them).

## 4. Component design

### 4.1 cairn-collectors-win (thin, unsafe, smoke-tested)

Only job: call WinAPI, return plain Rust structs. **No business logic.** Every WinAPI
return value is checked; on failure it returns `Result`, never panics. Each `unsafe`
call sits behind a safe wrapper; handles use an RAII guard so they are always closed —
the guard's invariant is documented at its definition (CLAUDE.md requirement).

```
mod privilege:
  fn probe() -> Privileges            // OpenProcessToken + GetTokenInformation
mod proc:
  // pid/ppid/image come from the snapshot (always present). The per-process fields are
  // Option — best-effort: a process we can't open (ACL/privilege) leaves them None
  // rather than failing enumeration (graceful; never panic).
  struct RawProc { pid, ppid, image, cmdline: Option<String>,
                   integrity_raw: Option<u32>, signed: Option<bool>,
                   user: Option<String>, start_time: Option<...> }
  fn enumerate() -> Result<Vec<RawProc>>
      // CreateToolhelp32Snapshot (pid/ppid/image — the reliable core), then per process:
      // OpenProcess + QueryFullProcessImageNameW (full path), PEB read for cmdline, token
      // query for integrity. Any per-process read that fails -> that field stays None;
      // enumeration still returns the row. signer: best-effort Some(bool) or None (§6).
      // enumerate() only Errs if the SNAPSHOT itself fails (whole-OS read impossible).
mod net:
  struct RawTcpRow { laddr, lport, raddr, rport, state_raw, pid }
  struct RawUdpRow { laddr, lport, pid }
  fn tcp_table() -> Result<Vec<RawTcpRow>>   // GetExtendedTcpTable (TCP_TABLE_OWNER_PID)
  fn udp_table() -> Result<Vec<RawUdpRow>>   // GetExtendedUdpTable (UDP_TABLE_OWNER_PID)
mod host:
  fn hostname() -> Result<String>            // GetComputerNameExW
```

The `Raw*` structs are the unsafe boundary's *exit*: plain, `Debug`+`Clone`, no unsafe.
These are the standard WinAPI patterns Sysinternals/Velociraptor/KAPE use — domain
convention, not any one project's code; implemented originally against Cairn's types
(clean Apache-2.0).

**Non-Windows build:** every `fn` returns `Err(Collector{..})` ("not supported on this
platform") or an empty vec, so `cargo check/test` is green on the ubuntu CI runner. The
real behavior is exercised on the windows CI job.

### 4.2 cairn-collectors::proc / ::net (pure logic, TDD)

Takes the `Raw*` vectors and does everything that can be wrong — all TDD-able because
given a `Vec<RawProc>` input you can assert the exact output:

```
proc.rs:
  fn build_process_records(raw: &[RawProc]) -> Vec<Record>
      // RawProc -> Record::Process(ProcessRecord). Note the existing ProcessRecord has
      // cmdline: String (not Option), so a None RawProc.cmdline maps to "" via
      // unwrap_or_default(); image is always present. integrity_raw (u32) normalizes to
      // the ProcessRecord.integrity string ("low"/"medium"/"high"/"system"). Pure; tested.
  struct ProcCollector;  impl Collector:
      name()="proc"; collect(ctx)= win::proc::enumerate().map(|r| build_process_records(&r))
      sources()= [SourceEntry{ artifact:"process", path:"live:process", method:"api",
                               size:0, sha256:"", errors:[] }]
net.rs:
  fn build_netconn_records(tcp: &[RawTcpRow], udp: &[RawUdpRow]) -> Vec<Record>
      // -> Record::NetConn(NetConnRecord): proto/laddr/lport/raddr/rport/state/pid;
      // normalize IP/port byte order, TCP state enum -> string. Pure; tested.
  struct NetCollector;  impl Collector:
      name()="net"; collect(ctx)= build_netconn_records(&tcp_table()?, &udp_table()?)
      sources()= [SourceEntry{ artifact:"netconn", path:"live:net", method:"api", ... }]
```

A collector returns `Err(Privilege)` when it lacks a required right, so the orchestrator
degrades gracefully. (proc/net are largely user-readable; admin only enriches *other*
users' processes — missing admin reduces coverage, recorded as a non-fatal note, not an
error.)

### 4.3 cairn-core::orchestrator (pure sequencing, TDD with fake collectors)

```
// Pure core: privileges + collector list are PARAMETERS (dependency injection), so the
// orchestrator's logic is testable without touching WinAPI.
fn run_live(cfg, privileges, hostname, collectors: &[Box<dyn Collector>]) -> RunOutcome
  // RunOutcome { records: Vec<Record>, sources: Vec<SourceEntry>, privileges, hostname }
  1. (privileges, hostname provided by caller — real probe in the bin, fakes in tests)
  2. let ctx = CollectCtx { config: cfg, admin, se_backup, se_debug }
  3. for c in collectors:                // bin passes [ProcCollector, NetCollector]
       match c.collect(&ctx) {
         Ok(recs)  => records.extend(recs); sources.extend(c.sources()),
         Err(e)    => { warn!(collector=c.name(), %e); push a SourceEntry with
                        errors=[e.to_string()]; }   // continue — never abort the run
       }
  4. return RunOutcome
```

**Testability:** the sequencing/accumulation/degrade logic is tested with **fake
collectors** — `struct FakeCollector { result: Result<Vec<Record>> } impl Collector` —
returning canned `Ok`/`Err`. This is a legitimate test double for the orchestrator's own
logic (not WinAPI mocking, which was rejected). Asserts: all-ok accumulates everything;
one collector erroring still runs the others and records the error; ordering is
proc-before-net. The privilege probe (real token query) gets a smoke test in the win
crate. To keep `run_live` pure/testable, the probe result and collector list are passed
in (dependency injection) rather than hard-called inside.

### 4.4 CLI wiring (cairn-cli)

`Cmd::Run` currently logs `TODO S2+`. Wire the `--target live` case:
- build `Config` from `RunArgs`, resolve off-target output dir (golden rule 4),
- init tracing -> run.log (reuse the S1 mechanism),
- call the real `win::privilege::probe()` + `win::host::hostname()`, build the live
  collector list `[ProcCollector, NetCollector]`, and pass all three into `run_live`,
- build the manifest from `RunOutcome`, write via `DirSink`.
- `--target <dir>` (offline artifact orchestration) returns an explicit "not yet
  implemented (raw-NTFS sub-segment)" message — honest, not a fake success.
- `cairn evtx` is untouched.

## 5. Manifest / run.log / host

- `manifest.privileges` <- probe result.
- `manifest.sources[]` <- each collector's `sources()`; live enumeration has no bytes to
  hash, so `sha256=""` and `method="api"` (SHA-256 is for file-backed sources; a live
  table is not a byte stream — this is correct, not a gap). Degrade reasons go in
  `errors[]`.
- `manifest.host.hostname` <- `win::host::hostname()` (live runs have no EVTX `computer`
  field to borrow). os_build/timezone/skew best-effort or left as S1 does.
- `manifest.counts.records` <- total Record count.
- run.log records: probe outcome, each collector ran/skipped + reason, totals.

## 6. Error handling & explicit scope limits

- **Reuse `CairnError`** — no new variants. Privilege → `Privilege{what,need}`; WinAPI
  failure → `Collector{collector,reason}`.
- **Win layer never panics** — every WinAPI return checked, failure -> `Result`
  (consistent with the S1 panic-free output path).
- **Graceful degrade is mandatory** (FR13 / golden rule 8): any single collector failure
  logs + records + continues; it never aborts the run. This is an S2 acceptance-gate
  requirement ("runs admin & degrades non-admin").
- **YAGNI — signer depth:** S2-A only attempts to obtain a signed *status*
  (`signed: Some(bool)`, else `None`). Full Authenticode certificate-chain verification
  is a large task that only the heuristics sub-segment (SRS §10) actually needs; it is
  **out of scope here**. The spec states this explicitly to prevent scope creep.
- **No host modification** (golden rule 3): proc/net only *read* OS state. No writes, no
  process manipulation, no injection.

## 7. Boundary with S1 (zero breakage)

- `cairn evtx` subcommand and its data path are untouched.
- `cairn run --target live` is a new, separate path that never goes through evtx.
- Shared, already-existing pieces reused as-is: `Record`, `Collector`, the reporter
  (`DirSink`), `manifest`. S2-A adds *implementors*, changes no contract.

## 8. Required edits to existing specs (anti-drift)

The gap analysis against SRS/CLAUDE.md found five items. ①–④ are spec edits made
*with* this design so the authoritative docs do not drift from what we build; ⑤ is a
scope line this spec states.

| # | Edit | Where |
|---|---|---|
| ① | Add `cairn-collectors-win` (unsafe-FFI isolation crate) to the repo layout | SRS §15 |
| ② | `proc_collector` crate column: drop `sysinfo`, keep only `windows-rs` | SRS §4 |
| ③ | Add `cairn-collectors-win` to the workspace map | CLAUDE.md |
| ④ | Define live-run `host.hostname` source = `GetComputerNameExW` (win crate) | SRS §5.3 note |
| ⑤ | State the signer-depth scope limit (status-only here; full verify later) | this spec §6 |

**Confirmed sound (no change needed):** every `Record` variant, the `Collector`/
`Analyzer`/`CollectCtx` traits, `CairnError::{Collector,Privilege}`, `SourceEntry.errors`,
and `Privileges` were pre-provisioned by S1 — S2-A needs no contract or error-type
changes.

## 9. Dependencies (pinned per global policy)

- `windows` crate (windows-rs), pinned to an exact resolved version, added to
  `cairn-collectors-win` only, under `[target.'cfg(windows)'.dependencies]` with the
  minimal feature set (Win32_System_Threading/ProcessStatus/Diagnostics_ToolHelp,
  Win32_NetworkManagement_IpHelper, Win32_Security, Win32_System_SystemInformation).
- No sysinfo. No new runtime network deps (NFR6).
- `cargo audit` must stay clean (global dependency-security policy); resolve or document
  any advisory before the gate.

## 10. Acceptance gates (per task + sub-segment)

Per task (the S1 discipline): `cargo check` + that task's test, then
`fmt`/`clippy -D warnings`/`test`/`audit` all green before the next task. Plus the
anti-drift check: no golden-rule violation, no deviation from SRS §3/§4 data flow, no
invention beyond spec (YAGNI).

Sub-segment exit (maps to SRS §16 S2 gate, partial):
- `cairn run --target live --output <dir>` on this Windows host produces a manifest with
  real privileges, a non-empty process list including this process's PID, a network list,
  and a clean run.log — verified end to end, not just unit tests.
- Runs as admin and **degrades** (no abort) when not admin.
- Zero target writes; output off-target (golden rule 4).
- `cairn verify` passes on the produced manifest.
- Workspace builds green on BOTH ubuntu (non-Windows shell path) and windows CI jobs.

> Periodic alignment (user requirement): at each task and at sub-segment exit, re-check
> the project against SRS + CLAUDE.md for feasibility and drift — run the gates, confirm
> no golden-rule/SRS deviation, update the progress memory. Alignment is built into the
> task acceptance criteria, not a separate afterthought.

## 11. Out of scope (explicit)

persistence collector; heur_parentchild/persist/netconn; raw-NTFS ($MFT/$J/locked
hives); offline-artifact collectors (amcache/shimcache/prefetch/srum/userassist/bam);
analyzer fan-in in the orchestrator; zip/encrypted output sinks; `--target <dir>` offline
orchestration; full Authenticode verification. Each is its own later sub-segment with its
own spec.
