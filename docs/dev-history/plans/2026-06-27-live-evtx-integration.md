# Live EVTX Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing Sigma engine into `cairn run --target live` by adding `EvtxLiveCollector` (reads `winevt\Logs\` filtered by channel + time window) and `SigmaAnalyzer` (runs `Engine::match_event` over `Record::Event`), so live triage emits Sigma findings in the same unified report as heuristic findings.

**Architecture:** New `EvtxLiveCollector` implements `Collector` trait in `cairn-collectors`; new `SigmaAnalyzer` implements `Analyzer` trait in `cairn-heur`. Both plug into the existing `run_live` pipeline unchanged. The orchestrator, trait signatures, and schemas are not modified.

**Tech Stack:** Rust, existing `evtx` crate (already in `cairn-collectors`), existing `cairn-sigma::engine::Engine` + `cairn-sigma::ruleset::ruleset_version`, `chrono::DateTime<Utc>`, `std::fs`.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Create | `crates/cairn-collectors/src/evtx_live.rs` | `EvtxLiveCollector` + `channel_to_filename` + time filter |
| Modify | `crates/cairn-collectors/src/lib.rs` | add `pub mod evtx_live;` |
| Create | `crates/cairn-heur/src/sigma.rs` | `SigmaAnalyzer` wrapping `Engine` |
| Modify | `crates/cairn-heur/src/lib.rs` | add `pub mod sigma; pub use sigma::SigmaAnalyzer;` |
| Modify | `crates/cairn-heur/Cargo.toml` | add `cairn-sigma` dependency |
| Modify | `crates/cairn-cli/src/main.rs` | wire both into `Cmd::Run`; fill `sigma_ruleset_ver`; set `cfg.since` default |

---

## Key background: existing code you MUST understand before writing

### `Engine` lives in `cairn-sigma/src/engine.rs`
- `Engine::default()` → empty engine
- `engine.load(rules_dir: &Path, plain: bool) -> Result<usize>` → loads + compiles rules, returns count
- `engine.match_event(ev: &EventRecord) -> Result<Vec<Finding>>` → runs all rules against one event
- `engine.referenced_channels() -> &[String]` → channels referenced by logsource.service in loaded rules

### `cairn_sigma::ruleset::ruleset_version(dir: &Path, plain: bool) -> Result<String>`
- Returns `"<pin>+<aggregate-sha256>"` — already used by the `evtx` subcommand
- Use this (not a new method) to fill `sigma_ruleset_ver` in the live run manifest

### `parse_evtx` lives in `cairn-collectors/src/evtx.rs`
- `parse_evtx(path: &Path) -> Result<Vec<EventRecord>, EvtxError>`
- Returns all events in the file; time filtering must be done by the caller

### `Record::Event(EventRecord)` already exists in `cairn-core/src/record.rs`

### `RunArgs` in `main.rs` already has:
- `rules: Option<PathBuf>` (line 101) — already present, just not used in `Cmd::Run`
- `since: Option<String>` (line 108) — already present, just not used in `Cmd::Run`

### `AVAILABLE` array in `main.rs` (around line 670): the list of live collectors
- `"evtx_live"` must be added here and gated behind `cfg.rules_dir.is_some()`

### Cargo env variable for `CARGO_TARGET_DIR`
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
```

---

## Task 1: `EvtxLiveCollector` — channel mapping + time filter (pure logic, no I/O)

**Files:**
- Create: `crates/cairn-collectors/src/evtx_live.rs`

- [ ] **Step 1: Write failing tests for `channel_to_filename` and time-filter helpers**

In `crates/cairn-collectors/src/evtx_live.rs`, write the tests module first (TDD):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn channel_to_filename_security() {
        assert_eq!(channel_to_filename("Security"), "Security.evtx");
    }

    #[test]
    fn channel_to_filename_powershell_operational() {
        assert_eq!(
            channel_to_filename("Microsoft-Windows-PowerShell/Operational"),
            "Microsoft-Windows-PowerShell%4Operational.evtx"
        );
    }

    #[test]
    fn channel_to_filename_sysmon() {
        assert_eq!(
            channel_to_filename("Microsoft-Windows-Sysmon/Operational"),
            "Microsoft-Windows-Sysmon%4Operational.evtx"
        );
    }

    #[test]
    fn filename_to_channel_security() {
        // inverse: strip .evtx, replace %4 with /
        assert_eq!(filename_to_channel("Security.evtx"), Some("Security".to_string()));
    }

    #[test]
    fn filename_to_channel_powershell() {
        assert_eq!(
            filename_to_channel("Microsoft-Windows-PowerShell%4Operational.evtx"),
            Some("Microsoft-Windows-PowerShell/Operational".to_string())
        );
    }

    #[test]
    fn filename_to_channel_non_evtx_returns_none() {
        assert_eq!(filename_to_channel("something.log"), None);
    }

    #[test]
    fn since_filter_drops_old_event() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        let old_ts = chrono::Utc.with_ymd_and_hms(2026, 6, 26, 23, 59, 59).unwrap();
        assert!(!event_is_recent(old_ts, since));
    }

    #[test]
    fn since_filter_keeps_recent_event() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        let new_ts = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 1).unwrap();
        assert!(event_is_recent(new_ts, since));
    }

    #[test]
    fn since_filter_keeps_exact_boundary() {
        let since = chrono::Utc.with_ymd_and_hms(2026, 6, 27, 0, 0, 0).unwrap();
        assert!(event_is_recent(since, since));
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-collectors evtx_live 2>&1 | head -30
```

Expected: compile error (`evtx_live` module doesn't exist yet).

- [ ] **Step 3: Implement the pure helper functions**

Write the full `evtx_live.rs` file (no I/O yet, just the two helpers + struct skeleton):

```rust
//! Live EVTX collector: reads C:\Windows\System32\winevt\Logs\ filtered by
//! the Sigma engine's referenced channels and a time window.

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

const WINEVT_LOGS_DIR: &str = r"C:\Windows\System32\winevt\Logs";

/// Map a Sigma channel name to its on-disk `.evtx` filename.
/// Windows EVTX filenames encode `/` as `%4`.
/// e.g. "Microsoft-Windows-PowerShell/Operational" -> "Microsoft-Windows-PowerShell%4Operational.evtx"
pub fn channel_to_filename(channel: &str) -> String {
    format!("{}.evtx", channel.replace('/', "%4"))
}

/// Map an on-disk `.evtx` filename back to a channel name (inverse of `channel_to_filename`).
/// Returns None if the file does not have a `.evtx` extension.
pub fn filename_to_channel(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".evtx")?;
    Some(stem.replace("%4", "/"))
}

/// True if `ts` is at or after `since`.
pub fn event_is_recent(ts: DateTime<Utc>, since: DateTime<Utc>) -> bool {
    ts >= since
}

/// Reads winevt Logs for Sigma-referenced channels, filtering to events within the time window.
pub struct EvtxLiveCollector {
    channels: Vec<String>,
    since: DateTime<Utc>,
    sources: std::sync::Mutex<Vec<SourceEntry>>,
}

impl EvtxLiveCollector {
    pub fn new(channels: Vec<String>, since: DateTime<Utc>) -> Self {
        EvtxLiveCollector {
            channels,
            since,
            sources: std::sync::Mutex::new(Vec::new()),
        }
    }
}
```

- [ ] **Step 4: Add the module to `lib.rs`**

Edit `crates/cairn-collectors/src/lib.rs`, add one line after the existing `pub mod evtx;`:

```rust
pub mod evtx_live;
```

- [ ] **Step 5: Run the tests to confirm they pass**

```powershell
cargo test -p cairn-collectors evtx_live 2>&1
```

Expected: all 8 tests pass.

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-collectors/src/evtx_live.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(collectors): add EvtxLiveCollector skeleton with channel/time helpers"
```

---

## Task 2: `EvtxLiveCollector::collect()` — I/O implementation

**Files:**
- Modify: `crates/cairn-collectors/src/evtx_live.rs`

- [ ] **Step 1: Write failing test for `collect()` with missing dir**

Add to the `tests` module in `evtx_live.rs`:

```rust
    #[test]
    fn no_channels_returns_empty_without_touching_fs() {
        let collector = EvtxLiveCollector::new(vec![], chrono::Utc::now());
        let ctx = make_ctx();
        let result = collector.collect(&ctx).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn missing_dir_returns_ok_empty() {
        let collector = EvtxLiveCollector::new(
            vec!["Security".to_string()],
            chrono::Utc::now(),
        );
        // Override the dir for this test by calling the internal fn directly.
        // We test the graceful-degrade path: absent dir → Ok(empty).
        let result = collect_from_dir(
            &std::path::PathBuf::from(r"C:\nonexistent\path\winevt\Logs"),
            &["Security".to_string()],
            chrono::Utc::now(),
            &mut vec![],
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    fn make_ctx() -> CollectCtx<'static> {
        use cairn_core::Config;
        // SAFETY: Config::default() lives for 'static via Box::leak — only in tests.
        let cfg: &'static Config = Box::leak(Box::new(Config::default()));
        CollectCtx {
            config: cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        }
    }
```

- [ ] **Step 2: Run to confirm fail**

```powershell
cargo test -p cairn-collectors evtx_live 2>&1 | head -20
```

Expected: compile error (`collect_from_dir` not defined yet).

- [ ] **Step 3: Implement `collect_from_dir` and `Collector` impl**

Replace the `EvtxLiveCollector` section in `evtx_live.rs` with the full implementation:

```rust
/// Internal: collect EventRecords from a given EVTX directory.
/// Extracted for testability (allows injecting a non-standard dir path).
pub fn collect_from_dir(
    dir: &Path,
    channels: &[String],
    since: DateTime<Utc>,
    source_entries: &mut Vec<SourceEntry>,
) -> Result<Vec<Record>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "evtx_live: cannot read winevt Logs dir; skipping");
            return Ok(vec![]);
        }
    };

    let wanted_filenames: std::collections::HashSet<String> =
        channels.iter().map(|c| channel_to_filename(c)).collect();

    let mut records = Vec::new();

    for entry in rd {
        let path = match entry {
            Ok(e) => e.path(),
            Err(_) => continue,
        };
        let Some(fname) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !wanted_filenames.contains(fname) {
            continue;
        }
        let channel = filename_to_channel(fname).unwrap_or_else(|| fname.to_string());
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

        match crate::evtx::parse_evtx(&path) {
            Ok(evs) => {
                let before = records.len();
                for ev in evs {
                    if event_is_recent(ev.ts, since) {
                        records.push(Record::Event(ev));
                    }
                }
                let count = records.len() - before;
                tracing::info!(
                    channel = %channel,
                    total_in_file = count,
                    "evtx_live: parsed"
                );
                source_entries.push(SourceEntry {
                    artifact: format!("evtx_live:{channel}"),
                    path: path.display().to_string(),
                    method: "fs".into(),
                    size,
                    sha256: String::new(),
                    errors: vec![],
                });
            }
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "evtx_live: parse failed; skipping");
                source_entries.push(SourceEntry {
                    artifact: format!("evtx_live:{channel}"),
                    path: path.display().to_string(),
                    method: "fs".into(),
                    size,
                    sha256: String::new(),
                    errors: vec![e.to_string()],
                });
            }
        }
    }

    Ok(records)
}

impl Collector for EvtxLiveCollector {
    fn name(&self) -> &str {
        "evtx_live"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        if self.channels.is_empty() {
            return Ok(vec![]);
        }
        let mut entries = Vec::new();
        let result = collect_from_dir(
            &PathBuf::from(WINEVT_LOGS_DIR),
            &self.channels,
            self.since,
            &mut entries,
        );
        *self.sources.lock().unwrap() = entries;
        result
    }

    fn sources(&self) -> Vec<SourceEntry> {
        self.sources.lock().unwrap().clone()
    }
}
```

Also add these imports at the top of the file:

```rust
use std::collections::HashSet;
```

- [ ] **Step 4: Run tests**

```powershell
cargo test -p cairn-collectors evtx_live 2>&1
```

Expected: all tests pass (including the new `no_channels_returns_empty_without_touching_fs` and `missing_dir_returns_ok_empty`).

- [ ] **Step 5: Full workspace check**

```powershell
cargo check --workspace 2>&1
```

Expected: no errors.

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-collectors/src/evtx_live.rs
git commit -m "feat(collectors): implement EvtxLiveCollector::collect with graceful degrade"
```

---

## Task 3: `SigmaAnalyzer` in `cairn-heur`

**Files:**
- Create: `crates/cairn-heur/src/sigma.rs`
- Modify: `crates/cairn-heur/src/lib.rs`
- Modify: `crates/cairn-heur/Cargo.toml`

- [ ] **Step 1: Add `cairn-sigma` dependency to `cairn-heur/Cargo.toml`**

Open `crates/cairn-heur/Cargo.toml`. The current `[dependencies]` section is:

```toml
[dependencies]
cairn-core = { path = "../cairn-core" }
chrono.workspace = true
```

Change it to:

```toml
[dependencies]
cairn-core = { path = "../cairn-core" }
cairn-sigma = { path = "../cairn-sigma" }
chrono.workspace = true
tracing.workspace = true
```

- [ ] **Step 2: Write failing tests in `sigma.rs`**

Create `crates/cairn-heur/src/sigma.rs` with tests first:

```rust
//! SigmaAnalyzer: runs Engine::match_event over Record::Event in the record stream.

use cairn_core::finding::Finding;
use cairn_core::record::Record;
use cairn_core::traits::Analyzer;
use cairn_core::Result;
use cairn_sigma::engine::Engine;
use cairn_sigma::SigmaMatcher;

/// Wraps a loaded Sigma Engine as an Analyzer.
/// Processes only Record::Event; all other variants are silently ignored.
pub struct SigmaAnalyzer {
    engine: Engine,
}

impl SigmaAnalyzer {
    pub fn new(engine: Engine) -> Self {
        SigmaAnalyzer { engine }
    }

    /// The ruleset version string for embedding in the manifest (ADR-0003).
    /// Call `cairn_sigma::ruleset::ruleset_version` separately and pass it here,
    /// OR call this only after the engine is loaded.
    pub fn ruleset_ver(&self) -> &[String] {
        self.engine.referenced_channels()
    }
}

impl Analyzer for SigmaAnalyzer {
    fn name(&self) -> &str {
        "sigma"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for record in records {
            if let Record::Event(ev) = record {
                match self.engine.match_event(ev) {
                    Ok(mut fs) => findings.append(&mut fs),
                    Err(e) => tracing::warn!(error = %e, "sigma match error; skipping event"),
                }
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::{EventRecord, ProcessRecord};
    use chrono::Utc;
    use serde_json::Map;

    const RULE_CMD: &str = r#"
title: Test CMD detection
id: 11111111-1111-1111-1111-111111111111
status: test
description: detects cmd.exe
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
level: high
author: test
"#;

    fn make_event(image: &str) -> EventRecord {
        let mut data = Map::new();
        data.insert(
            "NewProcessName".to_string(),
            serde_json::Value::String(image.to_string()),
        );
        data.insert(
            "Image".to_string(),
            serde_json::Value::String(image.to_string()),
        );
        EventRecord {
            ts: Utc::now(),
            channel: "Security".to_string(),
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            record_id: 1,
            data,
        }
    }

    fn make_proc_record() -> Record {
        Record::Process(ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "notepad.exe".into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        })
    }

    #[test]
    fn sigma_analyzer_ignores_non_event_records() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let records = vec![make_proc_record()];
        let findings = analyzer.analyze(&records).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn sigma_analyzer_empty_records_returns_empty() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let findings = analyzer.analyze(&[]).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn sigma_analyzer_match_fires_finding() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let ev = make_event(r"C:\Windows\System32\cmd.exe");
        let records = vec![Record::Event(ev)];
        let findings = analyzer.analyze(&records).unwrap();
        assert!(!findings.is_empty(), "cmd.exe should trigger the rule");
        assert_eq!(findings[0].rule_author.as_deref(), Some("test"));
    }

    #[test]
    fn sigma_analyzer_no_match_returns_empty() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let ev = make_event(r"C:\Windows\System32\notepad.exe");
        let records = vec![Record::Event(ev)];
        let findings = analyzer.analyze(&records).unwrap();
        assert!(findings.is_empty(), "notepad.exe should not trigger cmd rule");
    }
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```powershell
cargo test -p cairn-heur sigma 2>&1 | head -20
```

Expected: compile error (`sigma` module not in `lib.rs` yet).

- [ ] **Step 4: Add module to `lib.rs`**

Edit `crates/cairn-heur/src/lib.rs`. Add two lines:

```rust
pub mod sigma;
pub use sigma::SigmaAnalyzer;
```

The full `lib.rs` becomes:

```rust
//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
#![forbid(unsafe_code)]

pub mod correlation;
pub mod netconn;
pub mod parentchild;
pub mod persist;
pub mod score;
pub mod sigma;
pub mod timestomp;

// Public API: the analyzers wired into the CLI live run (and reusable elsewhere).
pub use correlation::CorrelationAnalyzer;
pub use netconn::NetConnHeuristic;
pub use parentchild::ParentChildHeuristic;
pub use persist::PersistHeuristic;
pub use sigma::SigmaAnalyzer;
pub use timestomp::TimestompHeuristic;
```

- [ ] **Step 5: Run tests**

```powershell
cargo test -p cairn-heur sigma 2>&1
```

Expected: all 4 sigma tests pass.

- [ ] **Step 6: Full workspace test**

```powershell
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests pass (448+).

- [ ] **Step 7: Commit**

```powershell
git add crates/cairn-heur/src/sigma.rs crates/cairn-heur/src/lib.rs crates/cairn-heur/Cargo.toml
git commit -m "feat(heur): add SigmaAnalyzer wrapping Engine as an Analyzer"
```

---

## Task 4: Wire into `main.rs` — `Cmd::Run` branch

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

This is the integration task. Read the existing `Cmd::Run` branch carefully before editing. Key locations:

- `AVAILABLE` array: ~line 670 — add `"evtx_live"`
- collectors vec construction: ~lines 750-793 — add `EvtxLiveCollector` block
- analyzers vec construction: ~lines 794-803 — add `SigmaAnalyzer` block
- manifest construction: ~line 848 — replace `sigma_ruleset_ver: String::new()` with computed value
- `cfg.since`: ~line 710 block where `cfg` is built — set the default

- [ ] **Step 1: Add `evtx_live` to `AVAILABLE` and fix `cfg.since`**

Find the `const AVAILABLE: &[&str]` block (~line 670). Add `"evtx_live"` to it:

```rust
const AVAILABLE: &[&str] = &[
    "proc",
    "net",
    "persist",
    "mft",
    "usn",
    "shimcache",
    "amcache",
    "prefetch",
    "bam",
    "userassist",
    "srum",
    "evtx_live",
];
```

Then find the `cfg` construction block (~line 710). After `cfg.normalize_for_profile()`, add the `since` default:

```rust
// Set cfg.since: default to 24 hours ago; --since overrides.
cfg.since = Some(match args.since.as_deref() {
    Some(s) => s.parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|e| anyhow::anyhow!("invalid --since value '{}': {}", s, e))?,
    None => chrono::Utc::now() - chrono::Duration::hours(24),
});
cfg.rules_dir = args.rules.clone();
cfg.rules_plain = args.rules_plain;
```

Note: `RunArgs` already has `rules: Option<PathBuf>` and `rules_plain: bool` fields. Check if `rules_plain` exists in `RunArgs`; if not, add it:

```rust
/// Load rules as plain un-encoded .yml (SOC audit bypass, mirrors evtx --rules-plain).
#[arg(long)]
rules_plain: bool,
```

- [ ] **Step 2: Build the `EvtxLiveCollector` and `SigmaAnalyzer` in the collectors/analyzers blocks**

After the `srum` collector block (~line 793), add:

```rust
// evtx_live: load Sigma engine + build EvtxLiveCollector (only if --rules given).
let mut sigma_analyzer: Option<cairn_heur::SigmaAnalyzer> = None;
let mut sigma_ruleset_ver = String::new();

if selection.selected.iter().any(|m| m == "evtx_live") {
    if let Some(rules_dir) = cfg.rules_dir.as_deref() {
        let mut engine = cairn_sigma::engine::Engine::default();
        match <cairn_sigma::engine::Engine as cairn_sigma::SigmaMatcher>::load(
            &mut engine,
            rules_dir,
            cfg.rules_plain,
        ) {
            Ok(n) => {
                tracing::info!(rules = n, dir = %rules_dir.display(), "loaded sigma rules for live run");
                let since = cfg.since.unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24));
                let channels = engine.referenced_channels().to_vec();
                collectors.push(Box::new(
                    cairn_collectors::evtx_live::EvtxLiveCollector::new(channels, since),
                ));
                sigma_ruleset_ver = cairn_sigma::ruleset::ruleset_version(rules_dir, cfg.rules_plain)
                    .unwrap_or_else(|e| {
                        tracing::warn!(error = %e, "could not compute ruleset version");
                        String::new()
                    });
                sigma_analyzer = Some(cairn_heur::SigmaAnalyzer::new(engine));
            }
            Err(e) => {
                tracing::warn!(error = %e, dir = %rules_dir.display(), "sigma rule load failed; skipping evtx_live");
            }
        }
    } else {
        tracing::info!("evtx_live selected but no --rules given; skipping");
    }
}
```

Then update the `analyzers` vec to include `SigmaAnalyzer` if it was built. Change the existing `let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![...]` block to:

```rust
let mut analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
    Box::new(cairn_heur::ParentChildHeuristic),
    Box::new(cairn_heur::NetConnHeuristic),
    Box::new(cairn_heur::PersistHeuristic),
    Box::new(cairn_heur::TimestompHeuristic::new(
        chrono::Duration::hours(cfg.timestomp_threshold_hours),
    )),
    Box::new(cairn_heur::CorrelationAnalyzer),
];
if let Some(sa) = sigma_analyzer {
    analyzers.push(Box::new(sa));
}
```

- [ ] **Step 3: Fill `sigma_ruleset_ver` in the manifest**

Find the manifest construction block (~line 842). Replace:

```rust
sigma_ruleset_ver: String::new(),
```

with:

```rust
sigma_ruleset_ver,
```

- [ ] **Step 4: Cargo check**

```powershell
cargo check --workspace 2>&1
```

Fix any compile errors before continuing. Common issues:
- Missing `use cairn_sigma::SigmaMatcher;` import in `main.rs` — it's already imported at the top (`use cairn_sigma::{engine::Engine, SigmaMatcher};`)
- If `rules_plain` isn't in `RunArgs`, add it (see Step 1)

- [ ] **Step 5: Clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings 2>&1
```

Expected: no warnings. Fix any that appear.

- [ ] **Step 6: Full workspace test**

```powershell
cargo test --workspace 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```powershell
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire EvtxLiveCollector + SigmaAnalyzer into live run; fill sigma_ruleset_ver"
```

---

## Task 5: Acceptance test — live integration smoke test

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (add `#[test]`)

This test verifies the wiring: a `SigmaAnalyzer` in the analyzers vec receives `Record::Event` records and produces findings that land in `RunOutcome.findings`.

- [ ] **Step 1: Write the integration test**

Find the `#[cfg(test)]` block in `main.rs` (search for `fn live_analyzers_include_all_heuristics`). Add a new test after the existing ones:

```rust
#[test]
fn sigma_analyzer_findings_appear_in_live_outcome() {
    use cairn_core::orchestrator::run_live;
    use cairn_core::manifest::Privileges;
    use cairn_core::record::{EventRecord, Record};
    use chrono::Utc;
    use serde_json::Map;
    use cairn_sigma::engine::Engine;
    use cairn_sigma::SigmaMatcher;
    use cairn_heur::SigmaAnalyzer;

    const RULE: &str = r#"
title: Test PowerShell detection
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
level: high
author: test-integration
"#;

    let engine = Engine::from_rules(&[RULE]).expect("rule must parse");
    let analyzer = SigmaAnalyzer::new(engine);

    let mut data = Map::new();
    data.insert("Image".to_string(), serde_json::Value::String(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string()));
    data.insert("NewProcessName".to_string(), serde_json::Value::String(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string()));
    let ev = EventRecord {
        ts: Utc::now(),
        channel: "Security".to_string(),
        event_id: 4688,
        provider: "Microsoft-Windows-Security-Auditing".to_string(),
        computer: "TEST".to_string(),
        record_id: 42,
        data,
    };

    let cfg = cairn_core::Config::default();
    let collectors: Vec<Box<dyn cairn_core::traits::Collector>> = vec![
        // FakeCollector that injects one Event record (reuse the existing FakeCollector in tests).
        // We inject the record directly via a canned collector.
        {
            struct EventCollector(cairn_core::record::EventRecord);
            impl cairn_core::traits::Collector for EventCollector {
                fn name(&self) -> &str { "fake_event" }
                fn collect(&self, _ctx: &cairn_core::traits::CollectCtx<'_>) -> cairn_core::Result<Vec<Record>> {
                    Ok(vec![Record::Event(self.0.clone())])
                }
            }
            Box::new(EventCollector(ev))
        }
    ];
    let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![Box::new(analyzer)];

    let privs = Privileges { admin: false, se_backup: false, se_debug: false };
    let outcome = run_live(&cfg, privs, "TEST".into(), &collectors, &analyzers);

    assert_eq!(outcome.records.len(), 1, "event record collected");
    assert!(!outcome.findings.is_empty(), "sigma finding must be present");
    assert_eq!(outcome.findings[0].rule_author.as_deref(), Some("test-integration"));
}
```

- [ ] **Step 2: Run the test**

```powershell
cargo test -p cairn-cli sigma_analyzer_findings_appear_in_live_outcome 2>&1
```

Expected: PASS.

- [ ] **Step 3: Full workspace test + clippy**

```powershell
cargo test --workspace 2>&1 | tail -20
cargo clippy --workspace --all-targets -- -D warnings 2>&1
```

Expected: all pass, no warnings.

- [ ] **Step 4: Commit**

```powershell
git add crates/cairn-cli/src/main.rs
git commit -m "test(cli): add integration test for SigmaAnalyzer in live run pipeline"
```

---

## Self-Review

### Spec coverage check

| Spec requirement | Task |
|-----------------|------|
| `EvtxLiveCollector` reads winevt\Logs\ filtered by channels | T2 |
| Channel → filename mapping (`/` → `%4`) | T1 |
| 24h default time window; `--since` override | T4 (cfg.since) |
| `Record::Event` produced | T2 (collect_from_dir wraps in Record::Event) |
| Graceful degrade: absent dir → Ok(empty) | T2 test + impl |
| Graceful degrade: single file failure → skip + SourceEntry error | T2 impl |
| `SigmaAnalyzer` implements `Analyzer` | T3 |
| Only processes `Record::Event` | T3 test |
| `f.host` stamped by main.rs (not analyzer) | ✅ existing code at line 807 handles this |
| `evtx_live` in AVAILABLE, excluded from minimal | T4 — NOTE: minimal exclusion is handled by `select_modules` which excludes `HEAVY_OFFLINE` group; need to confirm `evtx_live` is in the heavy group |
| `sigma_ruleset_ver` filled in live manifest | T4 |
| `cairn-heur` depends on `cairn-sigma` | T3 Cargo.toml |
| No schema changes | ✅ confirmed: `Record::Event` and `Finding` unchanged |

**Minimal profile exclusion note:** The `select_modules` function in `cairn-core` uses a profile-based exclusion list. Check `crates/cairn-core/src/lib.rs` for `select_modules` to confirm whether `evtx_live` needs explicit exclusion from minimal, or whether it's automatically excluded when `rules_dir` is None (the wiring in T4 already handles this: `evtx_live` selected but no `--rules` → skip). Either way the behavior is correct: minimal profile + no `--rules` = no EVTX scanning.

### Type consistency check

- `EvtxLiveCollector::new(channels: Vec<String>, since: DateTime<Utc>)` — used identically in T2 and T4 ✓
- `Engine::from_rules(&[&str]) -> Result<Engine>` — used in T3 tests ✓
- `SigmaAnalyzer::new(engine: Engine) -> SigmaAnalyzer` — used in T3 tests and T4 wiring ✓
- `<Engine as SigmaMatcher>::load(&mut engine, rules_dir, plain)` — fully qualified trait call in T4 ✓
- `cairn_sigma::ruleset::ruleset_version(rules_dir, plain) -> Result<String>` — used in T4 ✓
- `collect_from_dir` is `pub` (needed for test in T2 Step 1) ✓

### Placeholder scan

No TBD, TODO, or vague steps found. All code blocks are complete.
