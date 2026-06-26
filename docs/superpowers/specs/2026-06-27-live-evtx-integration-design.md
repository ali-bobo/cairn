# Live EVTX Integration — Design Spec

> **Status:** Approved for implementation.
> **Date:** 2026-06-27

## Problem

`cairn run` (live mode) runs heuristic analyzers over collected artifacts but never
reads Windows event logs or runs Sigma rules. Sigma only fires in `cairn evtx`
(offline subcommand). As a result:

- Live triage misses all event-log–based detections (LOLBin, scheduled task creation,
  logon anomalies, C2 service installs, DCSync, NTLM brute, etc.).
- `sigma_ruleset_ver` in the live-run manifest is always an empty string.
- An analyst running `cairn run` gets heuristics only; they must separately run
  `cairn evtx` against the same machine's logs — defeating the point of a single binary.

## Goal

Wire the existing Sigma engine into `cairn run --target live` so that:

1. `C:\Windows\System32\winevt\Logs\` is read for the channels referenced by the
   loaded rules.
2. Events from the last 24 hours (default; overridable with `--since`) pass through
   `Engine::match_event`.
3. Resulting Findings appear in the same `findings.jsonl` + `timeline.csv` as the
   heuristic findings — one unified report.
4. `sigma_ruleset_ver` in the live manifest is populated.

## Architecture Decision: Method A

New `EvtxLiveCollector` (Collector) + `SigmaAnalyzer` (Analyzer), each in its own
file, wired into the existing `run_live` pipeline. The orchestrator (`run_live`) is
**unchanged**. The Collector/Analyzer trait signatures are **unchanged**.

```
collectors:  [...existing...]  EvtxLiveCollector
                    ↓                 ↓
               run_live → records: Vec<Record>   (includes Record::Event)
                    ↓
analyzers:  [...existing heuristics...]  SigmaAnalyzer
                    ↓
               RunOutcome.findings
```

This is the cleanest extension: EVTX is just another collector, Sigma is just another
analyzer. No changes to `orchestrator.rs`, `traits.rs`, or any existing struct.

## New Files

| File | Responsibility |
|------|---------------|
| `crates/cairn-collectors/src/evtx_live.rs` | `EvtxLiveCollector` — reads winevt Logs, filters by channel + time window |
| `crates/cairn-heur/src/sigma.rs` | `SigmaAnalyzer` — runs `Engine::match_event` over `Record::Event` |

## Modified Files

| File | Change |
|------|--------|
| `crates/cairn-collectors/src/lib.rs` | `pub mod evtx_live;` |
| `crates/cairn-heur/src/lib.rs` | `pub mod sigma; pub use sigma::SigmaAnalyzer;` |
| `crates/cairn-cli/src/main.rs` | Wire both into `Cmd::Run`; add `--rules`, `--rules-plain`, `--since` to `RunArgs`; set `cfg.since` default; fill `sigma_ruleset_ver` |

## EvtxLiveCollector

**Location:** `crates/cairn-collectors/src/evtx_live.rs`

### Construction

```rust
pub struct EvtxLiveCollector {
    /// Channels to read (from Engine::referenced_channels()).
    channels: Vec<String>,
    /// Only include events at or after this time.
    since: DateTime<Utc>,
}

impl EvtxLiveCollector {
    pub fn new(channels: Vec<String>, since: DateTime<Utc>) -> Self { ... }
}
```

Built in `main.rs` after the `Engine` is loaded:
```rust
let collector = EvtxLiveCollector::new(engine.referenced_channels().to_vec(), since);
```

If `cfg.rules_dir` is `None`, `EvtxLiveCollector` is **not constructed** (no rules →
no point scanning EVTX). This mirrors the existing `cairn evtx` behaviour where
`--rules` is optional.

### Channel → Filename Mapping

Windows EVTX filenames encode the channel name with `/` → `%4`:

```
Security                                     → Security.evtx
System                                       → System.evtx
Microsoft-Windows-PowerShell/Operational     → Microsoft-Windows-PowerShell%4Operational.evtx
Microsoft-Windows-Sysmon/Operational         → Microsoft-Windows-Sysmon%4Operational.evtx
```

Rule: replace every `/` in the channel name with `%4` and append `.evtx`.

The EVTX directory is the Windows constant:
`C:\Windows\System32\winevt\Logs\`

Defined as a `const &str`; no registry lookup (this path has not changed since Vista).

### collect() Implementation

```
1. if self.channels is empty → return Ok(vec![])   // no rules loaded
2. list *.evtx in WINEVT_LOGS_DIR
3. for each candidate filename:
       if channel_from_filename(name) is in self.channels:
           parse_evtx(path) → Vec<EventRecord>
           filter: ev.ts >= self.since
           wrap each as Record::Event(ev)
           push to SourceEntry (artifact="evtx_live:<channel>", path, size)
4. return Ok(all_records)
```

All failures are per-file graceful degrade (match `parse_evtx` Err → push error to
SourceEntry, continue). The EVTX directory being absent or unreadable logs a warning
and returns `Ok(vec![])` — never `Err` (golden rule 8).

### sources() Implementation

One `SourceEntry` per successfully opened .evtx file:
- `artifact`: `evtx_live:<channel_name>`
- `path`: absolute path to the .evtx file
- `method`: `"fs"`
- `size`: `std::fs::metadata(path).len()`
- `sha256`: `""` (not hashed; consistent with other collectors)
- `errors`: per-file parse errors, if any

### No unsafe code

`std::fs::read_dir` + `std::fs::File::open` — fully safe. Inherits `cairn-collectors`
`#![forbid(unsafe_code)]`.

## SigmaAnalyzer

**Location:** `crates/cairn-heur/src/sigma.rs`

### Construction

```rust
pub struct SigmaAnalyzer {
    engine: cairn_sigma::engine::Engine,
}

impl SigmaAnalyzer {
    pub fn new(engine: cairn_sigma::engine::Engine) -> Self { ... }
    /// The ruleset version string for the manifest (from Engine::ruleset_ver()).
    pub fn ruleset_ver(&self) -> &str { self.engine.ruleset_ver() }
}
```

`Engine::ruleset_ver()` is a new one-liner on `Engine` that returns the version string
embedded at load time (currently unused in live mode). If not available, returns `""`.

### analyze() Implementation

```rust
fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for record in records {
        if let Record::Event(ev) = record {
            match self.engine.match_event(ev) {
                Ok(mut fs) => findings.append(&mut fs),
                Err(e) => tracing::warn!(error = %e, "sigma match error"),
            }
        }
    }
    Ok(findings)
}
```

Errors from `match_event` are logged and skipped (never abort). Non-Event records are
silently ignored. `f.host` is left as-is: `main.rs` stamps hostname onto all findings
after `run_live` returns (existing code at line 807-808).

### Dependency

`cairn-heur` must add `cairn-sigma` to its `Cargo.toml` dependencies. This is the only
new dependency edge. No circular deps (cairn-heur → cairn-sigma → cairn-core ✓).

## Config + CLI Changes

### New `RunArgs` fields

```
--rules <PATH>          Path to Sigma rules directory (XOR-encoded .yml)
--rules-plain           Load rules as plain un-encoded .yml (SOC audit bypass)
--since <DATETIME>      Only analyze events after this time (ISO8601 UTC).
                        Default: 24 hours ago. Example: 2026-06-27T00:00:00Z
```

### cfg.since default in Cmd::Run

```rust
cfg.since = Some(
    args.since
        .as_deref()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(|| Utc::now() - Duration::hours(24))
);
```

A bad `--since` value → CLI error (not silent fallback).

### AVAILABLE + selection

Add `"evtx_live"` to the `AVAILABLE` array. Include in `standard` and `verbose`
profiles. Exclude from `minimal` (consistent with heavy collectors like `mft`/`usn`).

The collector is only instantiated if `cfg.rules_dir.is_some()`. If `--rules` is not
given, `"evtx_live"` stays in the selection list but produces zero records and one
SourceEntry noting "no rules dir — skipped".

### sigma_ruleset_ver in manifest

```rust
let sigma_ruleset_ver = sigma_analyzer
    .as_ref()
    .map(|a| a.ruleset_ver().to_string())
    .unwrap_or_default();
// ... then used in ToolInfo { sigma_ruleset_ver, ... }
```

## Engine::ruleset_ver()

New method on `Engine` in `cairn-sigma/src/engine.rs`:

```rust
pub fn ruleset_ver(&self) -> &str {
    &self.ruleset_ver
}
```

`Engine` gains a `ruleset_ver: String` field, populated by `load()` from the
`PROVENANCE` file in the rules directory (already written by `cairn update-rules`).
If the file is absent, defaults to `""`.

## Graceful Degrade Summary

| Failure | Behaviour |
|---------|-----------|
| `--rules` not given | `EvtxLiveCollector` not constructed; `SigmaAnalyzer` not constructed; `sigma_ruleset_ver = ""`  |
| Rules dir unreadable | `Engine::load` logs warn; no `SigmaAnalyzer` added to vec; run continues |
| `winevt/Logs/` absent | `EvtxLiveCollector::collect` returns `Ok(vec![])` + warn; SourceEntry records the path |
| Single .evtx unreadable | Per-file error in SourceEntry; other files continue |
| `match_event` error | Log warn + skip; no Finding emitted for that event |

## Tests

### `crates/cairn-collectors/src/evtx_live.rs`

1. `channel_to_filename_security` — `"Security"` → `"Security.evtx"`
2. `channel_to_filename_powershell_operational` — `"Microsoft-Windows-PowerShell/Operational"` → `"Microsoft-Windows-PowerShell%4Operational.evtx"`
3. `filename_to_channel_roundtrip` — channel → filename → channel is identity
4. `since_filter_drops_old_events` — EventRecord with ts before `since` is excluded
5. `since_filter_keeps_recent_events` — EventRecord with ts after `since` is kept
6. `no_channels_returns_empty` — empty `channels` → `Ok(vec![])` without touching filesystem
7. `missing_dir_returns_ok_empty` — non-existent EVTX dir → `Ok(vec![])`, no panic

### `crates/cairn-heur/src/sigma.rs`

1. `sigma_analyzer_ignores_non_event_records` — `Record::Process` etc. produce no findings
2. `sigma_analyzer_empty_records_returns_empty` — no records → no findings
3. `sigma_analyzer_match_fires_finding` — craft `EventRecord` that hits a loaded rule → Finding emitted with correct severity + rule_author
4. `sigma_analyzer_no_match_returns_empty` — EventRecord that hits no rule → empty vec

## No Schema Changes

`Record::Event` already exists. `Finding` struct is unchanged. `SourceEntry` fields
are unchanged (artifact naming convention extended, not changed). Manifest `ToolInfo`
field `sigma_ruleset_ver` already exists (was just always `""` in live mode).
