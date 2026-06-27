# S2-B: parent/child + netconn heuristics — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-13.
> Authoritative spec: `cairn-SRS.md` (§10 heuristics, §7 FR10/FR11, §5.1 Finding).
> Predecessor: S2-A (`docs/superpowers/specs/2026-06-12-s2a-orchestrator-proc-net-design.md`)
> which delivered live proc/net collection. This adds the first *analysis* — the tool
> stops merely listing host state and starts flagging suspicious items.

## Purpose

Today `cairn run --target live` emits a faithful snapshot (process tree + network
table) but `findings.jsonl` is always empty: the tool collects, it does not judge.
This sub-segment adds two heuristic analyzers that scan the already-collected
`ProcessRecord`/`NetConnRecord` stream and emit explainable `Finding`s for items
matching known-suspicious patterns. After this, a live run produces a short
severity/ATT&CK-tagged list of "these few are worth looking at, and here is why" —
the core triage value of the whole project.

## Scope

**In scope (FR10, FR11, SRS §10):**
- `heur_parentchild`: anomalous parent→child, encoded PowerShell, suspicious exec
  path, unsigned + integrity weighting, a small built-in LOLBAS-flavored watchlist.
- `heur_netconn`: bare public-IP remote, rare remote port, owning-proc-in-temp,
  unsigned owning proc, suspicious high-port listener.
- Wire an analyzer fan-in stage into the orchestrator (after collectors), with the
  same graceful-degrade discipline (FR13): an analyzer that errors is logged and
  skipped, never aborts the run.
- CLI `run --target live` writes the real findings into timeline.csv + findings.jsonl
  and reflects them in `manifest.counts.findings_by_sev`.

**Explicitly OUT of scope (deferred, with rationale):**
- `heur_persist` (SRS §10 persistence ranking) — needs a persistence collector that
  produces `PersistenceRecord`; no such collector exists yet. Deferred to the
  persistence sub-segment.
- External LOLBAS dataset ingest (SRS §9) — introduces a rule-supply-chain concern
  (download/pin/encode/version) like the Sigma ruleset. This sub-segment uses a small
  built-in watchlist instead; full LOLBAS is its own later sub-segment. The
  parentchild design keeps the watchlist behind a single named table so adding LOLBAS
  later does not change the architecture.
- DNS reverse lookup for netconn (no runtime network per NFR6 except update-rules;
  also S2-A collected no DNS). The "bare public IP" signal is approximated by
  "public IP + uncommon port" rather than a true no-DNS check.
- Aggregation/correlation across records (e.g. process-tree depth chains). Each
  analyzer judges one record (plus its parent/owner lookup), not multi-hop chains.

## Architecture

A new crate `cairn-heur` (`#![forbid(unsafe_code)]`, pure logic, depends only on
`cairn-core`) holds both analyzers and a shared scoring module.

```
crates/cairn-heur/
  Cargo.toml          # dep: cairn-core only
  src/lib.rs          # re-exports both analyzers
  src/score.rs        # shared: path classification, weight->Severity mapping, signal log
  src/parentchild.rs  # ParentChildHeuristic impl Analyzer  (FR10)
  src/netconn.rs      # NetConnHeuristic impl Analyzer       (FR11)
```

**Dependency direction:** `cairn-heur → cairn-core` (one-way, no cycle).
`cairn-cli` gains a dep on `cairn-heur`.

**Each analyzer is a self-contained unit:** input `&[Record]`, output
`Vec<Finding>`, touches no host state and no sibling state (the `Analyzer` trait
contract, already defined in `cairn-core::traits`). `score.rs` factors out the
common "classify path → accumulate weighted signals → map to Severity → build the
reason string" so both analyzers speak one explainable scoring language.

### Orchestrator change (cairn-core)

`run_live` currently runs collectors and returns records; there is no analyzer
stage (the CLI writes an empty `&[]` for findings). Add:

- `RunOutcome` gains `pub findings: Vec<Finding>`.
- `run_live` gains a parameter `analyzers: &[Box<dyn Analyzer>]`. After collectors
  finish, each analyzer is run over the accumulated `&[Record]`; results are
  concatenated into `findings`. An analyzer returning `Err` is logged
  (`tracing::warn!`) and skipped — graceful degrade, mirroring the collector path.
  (Analyzer failures are operational, not provenance, so they are NOT added to
  `sources[]`; they are logged to run.log only. `sources[]` stays
  collector/artifact provenance.)

### CLI change (cairn-cli)

In the `run --target live` arm: build `vec![ParentChildHeuristic, NetConnHeuristic]`
as `Box<dyn Analyzer>`, pass to `run_live`, then write `outcome.findings` (instead
of `&[]`) to `write_timeline_csv` + `write_findings_jsonl`, and compute
`counts.findings_by_sev` from them via the existing `Summary::from_findings`.

## Rules

Every weight, port set, suspicious-path pattern, and watchlist entry is a **named
constant table** in source (in `score.rs` or the top of each analyzer), centralized
so it can later be loaded from a config file without changing the matching logic
(CLAUDE.md: settings must not be hard-wired into logic).

### Severity mapping (shared, score.rs)

Weighted signal sum → severity. A triage tool prefers over- to under-reporting:

| Score sum | Severity |
|---|---|
| `>= 70` | critical |
| `50–69` | high |
| `30–49` | medium |
| `15–29` | low |
| `< 15` | no finding emitted (noise floor) |

### heur_parentchild (FR10)

For each `ProcessRecord`, resolve its parent via `ppid` (None if not present), then
accumulate signals:

| Signal | Condition | Weight | ATT&CK |
|---|---|---|---|
| Office→shell | parent in {winword,excel,powerpnt,outlook}.exe AND child in {cmd,powershell,pwsh,wscript,cscript,mshta}.exe | +50 | T1059 |
| Encoded PowerShell | cmdline contains (case-insensitive) one of `-enc`, `-encodedcommand`, `-e ` (the `-e ` form only when the process image is a PowerShell binary, to avoid matching unrelated `-e` flags) followed within the cmdline by a base64-looking token — defined as a run of >= 16 chars from `[A-Za-z0-9+/=]` | +40 | T1059.001 |
| Suspicious exec path | image path under `\Temp\`, `\AppData\`, `\ProgramData\`, `\Downloads\`, `\Public\` (case-insensitive) | +25 | T1036 |
| Unsigned | `signed == Some(false)` | +20 | — |
| High-integrity + unsigned | `integrity` in {high, system} AND unsigned | +15 | T1068 |
| script→shell | parent in {wscript,cscript,mshta}.exe AND child in {cmd,powershell,pwsh}.exe | +30 | T1059 |
| LOLBAS-flavored | child image in built-in watchlist {rundll32,regsvr32,mshta,certutil,bitsadmin,cscript,wscript}.exe AND cmdline matches a suspicious pattern (`http`, `scrobj`, base64-looking, `/i:`) | +30 | T1218 |

Mitre tags accumulate from all matched signals (deduplicated). `reason` lists the
matched signals in plain English including the actual parent/child image names.

### heur_netconn (FR11)

For each `NetConnRecord`, resolve the owning process via `pid` (None if not present
or no matching record), then accumulate signals:

| Signal | Condition | Weight |
|---|---|---|
| Bare public IP | `raddr` parses as a public IPv4 (NOT RFC1918 / loopback / link-local / `0.0.0.0`) | +25 |
| Rare remote port | `rport` is Some and NOT in COMMON_PORTS {80,443,53,22,3389,445,135,139,21,25,587,993,143,110} | +20 |
| Owner in suspicious dir | owning process image under Temp/AppData/ProgramData (same path table as parentchild) | +30 |
| Owner unsigned | owning process `signed == Some(false)` | +20 |
| Suspicious listener | `state == "listen"` AND `lport > 1024` AND owning process unsigned | +25 |

`reason` lists matched signals plus raddr/rport and the owning image. Loopback /
private destinations on common ports score 0 → no finding (the common case stays
quiet).

## Finding construction (both analyzers)

- `source = FindingSource::Heuristic`, `reason = Some(...)` ALWAYS (golden rule 6).
- `severity` from the mapping above; `title` a short label; `details` the technical
  English summary; `details_client` left None (zh-TW client text is FR18 / S3).
- `mitre` from matched signals.
- `entity.process` populated for parentchild (and for netconn's owner when resolved);
  `entity.netconn` populated for netconn.
- `host` = filled by the CLI from `outcome.hostname` after analysis (analyzers do not
  know the hostname; the CLI stamps it onto each finding, matching how the evtx path
  stamps host from the parsed Computer field).
- `ts` / `detected_at`: `detected_at = now`. `ts` (observation time) = the process
  `start_time` when available, else `now` (a live snapshot has no better event time).
- `rule_id` / `rule_author` = None (heuristics are not Sigma; DRL 1.1 author
  requirement applies only to `source == Sigma`).
- `event_id` = None (not event-derived).

## Error handling

- Analyzers are total: no panics. Missing parent/owner → that lookup is None and
  only self-signals score. Unparseable IP → the bare-public-IP signal simply does
  not fire (no error).
- Orchestrator: an analyzer returning `Err` is logged and skipped (graceful degrade);
  other analyzers and the run continue.
- Determinism (NFR4): findings are sorted before output by (ts, then a stable
  tiebreak key = `(title, entity pid for process / lport for netconn)`), since
  heuristic findings have no EVTX record_id. The analyzers must NOT sort by the
  random `Finding.id` (uuid) — that would make ordering non-reproducible. Sorting
  is applied by the CLI before writing, consistent with the existing reporter's
  (ts, record_id) ordering for the evtx path.

## Testing

Pure logic → full TDD, no host or network needed:

- **score.rs**: path classification (each suspicious dir matches; a normal
  `C:\Windows\System32` path does not); weight→severity boundaries (69→high,
  70→critical, 14→none, 15→low).
- **parentchild**: Office→encoded-PowerShell case fires high+ with T1059.001 and a
  reason naming both images; a benign `explorer.exe → notepad.exe` (signed, normal
  path) produces no finding; unsigned-from-temp fires; missing parent still scores
  self-signals without panic.
- **netconn**: unsigned proc in temp connecting to a public IP on a rare port fires
  with a reason listing the signals; a signed browser to 443 on a public IP scores
  below the floor (rare-port signal absent) → no finding; loopback/private dest
  produces nothing; missing owner still evaluates connection-only signals.
- **orchestrator**: a fake analyzer's findings land in `RunOutcome.findings`; a fake
  analyzer returning `Err` is skipped and the run still returns the other's findings
  (graceful degrade).
- **e2e (manual, Windows)**: `cairn run --target live` over this host produces a
  non-empty-or-justified findings set, `findings.jsonl` has heuristic findings with
  `reason`, `manifest.counts.findings_by_sev` matches, and `cairn verify` still
  passes (exit 0). `cairn evtx` (S1) unchanged.

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` all green; `cargo audit` clean.
- `unsafe` appears in NO crate except `cairn-collectors-win` (cairn-heur is
  `#![forbid(unsafe_code)]`).
- Real live run emits explainable heuristic findings; verify passes; S1 evtx path
  and S2-A live collection unchanged.
- No golden-rule violation; no deviation from SRS §3/§4/§5.1/§10; no scope creep
  beyond the two analyzers (YAGNI: no persist heuristic, no external LOLBAS, no
  correlation).

## Non-goals / future hooks

- LOLBAS dataset, persistence heuristic, DNS enrichment, cross-record correlation,
  and config-file-driven rule tables are all explicit later work. The named-constant
  rule tables are the seam where a config loader plugs in without touching logic.
