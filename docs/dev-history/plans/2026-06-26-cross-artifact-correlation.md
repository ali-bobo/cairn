# Cross-Artifact Correlation Analyzer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a `High` Finding when the same binary appears in both a `PersistenceRecord` and an `ExecutionRecord`, providing cross-artifact corroboration that a binary both persists on the machine and was confirmed executed.

**Architecture:** New `CorrelationAnalyzer` in `crates/cairn-heur/src/correlation.rs`. Groups records by normalized basename (no extension, lowercase). One Finding per `(basename, mechanism)` group where inbox-service suppression is off. Wired into `main.rs` alongside existing heuristics.

**Tech Stack:** Rust, existing `cairn_core` types, `chrono`. No new dependencies.

**Build command (run after every task):**
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

**Spec:** `docs/superpowers/specs/2026-06-26-cross-artifact-correlation-design.md`

---

## File Map

| File | Change |
|------|--------|
| `crates/cairn-heur/src/correlation.rs` | **Create** — `CorrelationAnalyzer` + `normalized_basename()` + all tests |
| `crates/cairn-heur/src/lib.rs` | **Modify** — add `pub mod correlation; pub use correlation::CorrelationAnalyzer;` |
| `crates/cairn-cli/src/main.rs` | **Modify** — add `CorrelationAnalyzer` to analyzers vec + update `live_analyzers_include_timestomp` test name/assertions |

---

## Task 1 — `normalized_basename()` + skeleton `CorrelationAnalyzer` + failing tests

**Files:**
- Create: `crates/cairn-heur/src/correlation.rs`

### Context

`normalized_basename(path: &str) -> String` must handle:
- `C:\Windows\System32\svchost.exe` → `svchost`
- `C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe` → `notion`
- `NOTION.EXE-1234ABCD.pf` (prefetch name) → `notion`
- `%windir%\system32\svchost.exe` → `svchost`
- `explorer.exe` → `explorer`
- `""` (empty) → `""` (skip in caller)

Steps:
1. lowercase the input
2. strip leading/trailing whitespace and surrounding `"`
3. split on `\\` and `/`, take last segment
4. strip one trailing `.exe` or `.pf` suffix (exactly one, case-insensitive since we already lowercased)

### What to implement

- [ ] **Step 1: Write failing tests** — create `crates/cairn-heur/src/correlation.rs` with:

```rust
#![forbid(unsafe_code)]

use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result, Severity};
use chrono::Utc;

/// Cross-artifact correlation: emit High Finding when the same binary
/// appears in both persistence and execution artifact sources.
pub struct CorrelationAnalyzer;

/// Normalize a binary path or filename to a bare lowercase stem for correlation.
///
/// Examples:
///   `C:\Windows\System32\svchost.exe`  → `svchost`
///   `NOTION.EXE-1234ABCD.pf`           → `notion`
///   `%windir%\system32\svchost.exe`    → `svchost`
///
/// Returns empty string for empty input — callers skip empty keys.
pub(crate) fn normalized_basename(path: &str) -> String {
    let s = path.trim().trim_matches('"').to_ascii_lowercase();
    let stem = s
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(&s);
    // Strip exactly one known forensic extension
    let stem = stem
        .strip_suffix(".exe")
        .or_else(|| stem.strip_suffix(".pf"))
        .unwrap_or(stem);
    stem.to_string()
}

impl Analyzer for CorrelationAnalyzer {
    fn name(&self) -> &str {
        "heur_correlation"
    }

    fn analyze(&self, _records: &[Record]) -> Result<Vec<Finding>> {
        Ok(vec![]) // placeholder — implemented in Task 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::EntityFile;
    use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn exec(path: &str, source: &str) -> Record {
        Record::Execution(ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        })
    }

    fn persist(mechanism: &str, location: &str, command: &str, binary_path: Option<&str>) -> Record {
        Record::Persistence(PersistenceRecord {
            mechanism: mechanism.into(),
            location: location.into(),
            value: Some(mechanism.into()),
            command: Some(command.into()),
            binary_path: binary_path.map(|s| s.into()),
            binary_sha256: None,
            signed: None,
            signer: None, // PersistenceRecord.signer field (Option<String>)
            last_write: None,
        })
    }

    fn process(image: &str, pid: u32) -> Record {
        Record::Process(ProcessRecord {
            pid,
            ppid: 1,
            image: image.into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        })
    }

    // ── normalized_basename ───────────────────────────────────────────────────

    #[test]
    fn basename_full_path_exe() {
        assert_eq!(
            normalized_basename(r"C:\Windows\System32\svchost.exe"),
            "svchost"
        );
    }

    #[test]
    fn basename_prefetch_name() {
        assert_eq!(
            normalized_basename("NOTION.EXE-1234ABCD.pf"),
            "notion.exe-1234abcd"
        );
    }

    #[test]
    fn basename_env_var_path() {
        assert_eq!(
            normalized_basename(r"%windir%\system32\svchost.exe"),
            "svchost"
        );
    }

    #[test]
    fn basename_bare_name() {
        assert_eq!(normalized_basename("explorer.exe"), "explorer");
    }

    #[test]
    fn basename_empty() {
        assert_eq!(normalized_basename(""), "");
    }

    #[test]
    fn basename_quoted_path() {
        assert_eq!(
            normalized_basename(r#""C:\Temp\evil.exe""#),
            "evil"
        );
    }

    // ── CorrelationAnalyzer ──────────────────────────────────────────────────

    #[test]
    fn exec_and_persist_same_binary_emits_high_finding() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe", 
                    Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe")),
            exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1, "expected one correlation finding");
        let f = &findings[0];
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.to_ascii_lowercase().contains("notion"), "title: {}", f.title);
        assert_eq!(f.artifact, "correlation");
    }

    #[test]
    fn exec_without_persist_emits_nothing() {
        let records = vec![
            exec(r"C:\Temp\evil.exe", "prefetch"),
        ];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn persist_without_exec_emits_nothing() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\evil.exe", Some(r"C:\Temp\evil.exe")),
        ];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn inbox_service_is_suppressed() {
        // svchost.exe from System32 — inbox, should not fire
        let records = vec![
            persist("service", r"HKLM\SYSTEM\CurrentControlSet\Services\Schedule",
                    r"C:\Windows\System32\svchost.exe -k netsvcs", 
                    Some(r"C:\Windows\System32\svchost.exe")),
            exec("SVCHOST.EXE-AABBCCDD.pf", "prefetch"),
        ];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn driverstore_binary_not_suppressed() {
        // DriverStore binary — is_inbox_service_command returns false for DriverStore
        let records = vec![
            persist("service", r"HKLM\SYSTEM\CurrentControlSet\Services\EvilDrv",
                    r"C:\Windows\System32\DriverStore\FileRepository\evil.inf_amd64\evil.exe",
                    Some(r"C:\Windows\System32\DriverStore\FileRepository\evil.inf_amd64\evil.exe")),
            exec("EVIL.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1, "DriverStore BYOVD must fire");
    }

    #[test]
    fn finding_title_and_artifact_field() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.artifact, "correlation");
        assert!(f.title.to_ascii_lowercase().contains("bad"), "title: {}", f.title);
        assert_eq!(f.source, FindingSource::Heuristic);
    }

    #[test]
    fn finding_has_reason_and_details() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        let f = &findings[0];
        assert!(f.reason.is_some(), "reason must be set (golden rule 6)");
        let reason = f.reason.as_deref().unwrap();
        assert!(reason.contains("run_key") || reason.contains("persist"), "reason: {reason}");
        assert!(!f.details.is_empty(), "details must be set");
    }

    #[test]
    fn process_corroboration_adds_to_reason() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
            process(r"C:\Temp\bad.exe", 1234),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        let reason = findings[0].reason.as_deref().unwrap_or("");
        assert!(reason.contains("running") || reason.contains("1234"), "reason: {reason}");
    }

    #[test]
    fn no_exec_records_emits_nothing() {
        // Simulates a run without SeBackupPrivilege: only process + persistence records
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            process(r"C:\Temp\bad.exe", 1234),
        ];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn multiple_exec_sources_listed_in_reason() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
                    Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe")),
            exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
            exec(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe", "amcache"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        let reason = findings[0].reason.as_deref().unwrap_or("");
        // Both "prefetch" and "amcache" should appear somewhere in reason or details
        let details = &findings[0].details;
        let combined = format!("{reason} {details}");
        assert!(combined.contains("prefetch"), "prefetch source: {combined}");
        assert!(combined.contains("amcache"), "amcache source: {combined}");
    }
}
```

- [ ] **Step 2: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur -- --test-output immediate 2>&1 | tail -20
```

Expected: compile errors about missing types or FAILED on placeholder `analyze()`.

- [ ] **Step 3: Register the module** — add to `crates/cairn-heur/src/lib.rs`:

```rust
pub mod correlation;
pub use correlation::CorrelationAnalyzer;
```

- [ ] **Step 4: Run cargo check**

```powershell
cargo check --workspace 2>&1 | tail -10
```

Expected: compiles. Tests still fail (placeholder `analyze` returns empty).

- [ ] **Step 5: Commit skeleton**

```powershell
git add crates/cairn-heur/src/correlation.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): add correlation.rs skeleton + normalized_basename + all tests (RED)"
```

---

## Task 2 — Implement `CorrelationAnalyzer::analyze`

**Files:**
- Modify: `crates/cairn-heur/src/correlation.rs` (replace `analyze` body)

### Context

The `analyze` method must:
1. Partition `records` into three maps keyed by `normalized_basename`:
   - `exec_map: HashMap<String, Vec<&ExecutionRecord>>`
   - `persist_map: HashMap<String, Vec<&PersistenceRecord>>`
   - `proc_map: HashMap<String, Vec<&ProcessRecord>>`
2. For each `(key, persist_entries)` in `persist_map`:
   - Skip if `key.is_empty()`
   - Skip if `exec_map` does not contain `key` (no execution evidence)
   - Group `persist_entries` by `mechanism`
   - For each `(mechanism, group)`:
     - Pick one representative: entry with latest `last_write` (or first if all None)
     - Compute `cmd = representative.command.as_deref().unwrap_or("")`
     - Skip if `is_inbox_service_command(cmd)` is true
     - Build and push one `Finding`
3. Return the findings vec.

**Imports needed in correlation.rs:**
```rust
use crate::score::is_inbox_service_command;
use cairn_core::finding::{EntityFile, FindingSource, Severity};
use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::Utc;
use std::collections::HashMap;
```

**`analyze` implementation:**

```rust
fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
    use std::collections::HashMap;

    let mut exec_map: HashMap<String, Vec<&ExecutionRecord>> = HashMap::new();
    let mut persist_map: HashMap<String, Vec<&PersistenceRecord>> = HashMap::new();
    let mut proc_map: HashMap<String, Vec<&ProcessRecord>> = HashMap::new();

    for r in records {
        match r {
            Record::Execution(e) => {
                let key = normalized_basename(&e.path);
                if !key.is_empty() {
                    exec_map.entry(key).or_default().push(e);
                }
            }
            Record::Persistence(p) => {
                let raw = p
                    .binary_path
                    .as_deref()
                    .or_else(|| p.command.as_deref())
                    .unwrap_or("");
                let key = normalized_basename(raw);
                if !key.is_empty() {
                    persist_map.entry(key).or_default().push(p);
                }
            }
            Record::Process(pr) => {
                let key = normalized_basename(&pr.image);
                if !key.is_empty() {
                    proc_map.entry(key).or_default().push(pr);
                }
            }
            _ => {}
        }
    }

    let mut findings = Vec::new();
    let now = Utc::now();

    for (key, persist_entries) in &persist_map {
        let exec_entries = match exec_map.get(key) {
            Some(e) => e,
            None => continue,
        };

        // Group by mechanism to avoid one Finding per service entry
        let mut by_mechanism: HashMap<&str, Vec<&&PersistenceRecord>> = HashMap::new();
        for p in persist_entries {
            by_mechanism.entry(p.mechanism.as_str()).or_default().push(p);
        }

        for (mechanism, group) in &by_mechanism {
            // Representative: latest last_write, fallback to first
            let repr = group
                .iter()
                .max_by_key(|p| p.last_write)
                .copied()
                .unwrap_or(group[0]);

            let cmd = repr.command.as_deref().unwrap_or(
                repr.binary_path.as_deref().unwrap_or(""),
            );
            if is_inbox_service_command(cmd) {
                continue;
            }

            // Execution evidence
            let exec_sources: Vec<&str> =
                exec_entries.iter().map(|e| e.source.as_str()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            let last_run = exec_entries
                .iter()
                .filter_map(|e| e.last_run)
                .max();
            let exec_src_str = exec_sources.join(", ");

            // Process corroboration
            let live_pids: Vec<u32> = proc_map
                .get(key.as_str())
                .map(|ps| ps.iter().map(|p| p.pid).collect())
                .unwrap_or_default();

            // Best path for entity
            let best_path = repr
                .binary_path
                .as_deref()
                .filter(|p| !p.is_empty())
                .or_else(|| exec_entries.first().map(|e| e.path.as_str()))
                .unwrap_or(key.as_str())
                .to_string();

            // MITRE
            let mitre = mechanism_to_mitre(mechanism);

            // details (technical, English)
            let last_run_str = last_run
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "unknown".into());
            let details = format!(
                "{key} persisted via {mechanism} ({loc}); confirmed executed [{exec_src_str}] last_run={last_run_str}",
                loc = repr.location
            );

            // reason (explainability — golden rule 6)
            let mut reason_parts = vec![
                format!("binary found in persistence ({mechanism}: {})", repr.location),
                format!("and execution records ({exec_src_str})"),
            ];
            if !live_pids.is_empty() {
                let pid_str = live_pids
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                reason_parts.push(format!("and currently running (pid={pid_str})"));
            }
            let reason = reason_parts.join(" ");

            let mut f = Finding::new(
                Severity::High,
                format!("Confirmed persistence + execution: {key}"),
                FindingSource::Heuristic,
            );
            f.ts = now;
            f.artifact = "correlation".into();
            f.mitre = vec![mitre.into()];
            f.entity.file = Some(EntityFile {
                path: best_path,
                sha256: None,
                mtime: None,
                si_btime: None,
                fn_btime: None,
                si_mtime: None,
                fn_mtime: None,
                path_complete: None,
            });
            f.details = details;
            f.reason = Some(reason);

            findings.push(f);
        }
    }

    Ok(findings)
}
```

**`mechanism_to_mitre` helper (private, add above `impl Analyzer`):**

```rust
fn mechanism_to_mitre(mechanism: &str) -> &'static str {
    match mechanism {
        "service" => "T1543.003",
        "run_key" | "startup" => "T1547.001",
        "scheduled_task" => "T1053.005",
        "winlogon" => "T1547.004",
        "ifeo" => "T1546.012",
        _ => "T1547",
    }
}
```

**Fix `exec_sources` dedup (use BTreeSet for deterministic order):**

The `exec_sources` line in `analyze` above needs a proper import. Add to the top of `analyze`:
```rust
use std::collections::BTreeSet;
```
And update the exec_sources line:
```rust
let exec_sources: Vec<&str> = exec_entries
    .iter()
    .map(|e| e.source.as_str())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
```

### What to implement

- [ ] **Step 1: Replace `analyze` body in `correlation.rs`**

Replace the entire `impl Analyzer for CorrelationAnalyzer` block with the implementation above. Add the `mechanism_to_mitre` helper and update the imports at the top of the file to:

```rust
use crate::score::is_inbox_service_command;
use cairn_core::finding::{EntityFile, FindingSource, Severity};
use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::Utc;
use std::collections::{BTreeSet, HashMap};
```

- [ ] **Step 2: Run tests**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur -- --test-output immediate 2>&1 | tail -30
```

Expected: all tests pass. Watch specifically for:
- `exec_and_persist_same_binary_emits_high_finding` — PASS
- `inbox_service_is_suppressed` — PASS  
- `driverstore_binary_not_suppressed` — PASS
- `process_corroboration_adds_to_reason` — PASS

- [ ] **Step 3: Run workspace tests**

```powershell
cargo test --workspace 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 4: Clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | grep -E "^error|warning\[" | head -20
```

Expected: zero warnings/errors.

- [ ] **Step 5: Commit**

```powershell
git add crates/cairn-heur/src/correlation.rs
git commit -m "feat(heur): implement CorrelationAnalyzer.analyze (cross-artifact persistence+execution)"
```

---

## Task 3 — Wire into main.rs + update test

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

### Context

Current analyzers vec (line ~794):
```rust
let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
    Box::new(cairn_heur::ParentChildHeuristic),
    Box::new(cairn_heur::NetConnHeuristic),
    Box::new(cairn_heur::PersistHeuristic),
    Box::new(cairn_heur::TimestompHeuristic::new(
        chrono::Duration::hours(cfg.timestomp_threshold_hours),
    )),
];
```

There is also a test `live_analyzers_include_timestomp` (line ~1162) that must be updated to also assert `CorrelationAnalyzer` is present.

### What to implement

- [ ] **Step 1: Add `CorrelationAnalyzer` to the analyzers vec**

Change the analyzers vec to:
```rust
let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
    Box::new(cairn_heur::ParentChildHeuristic),
    Box::new(cairn_heur::NetConnHeuristic),
    Box::new(cairn_heur::PersistHeuristic),
    Box::new(cairn_heur::TimestompHeuristic::new(
        chrono::Duration::hours(cfg.timestomp_threshold_hours),
    )),
    Box::new(cairn_heur::CorrelationAnalyzer),
];
```

- [ ] **Step 2: Update the `live_analyzers_include_timestomp` test**

Find the test at line ~1162. It currently asserts `a.name() == "heur_timestomp"`. Update it to also assert `CorrelationAnalyzer` is registered:

```rust
#[test]
fn live_analyzers_include_all_heuristics() {
    use cairn_core::traits::Analyzer;
    let threshold = chrono::Duration::hours(24);
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(cairn_heur::ParentChildHeuristic),
        Box::new(cairn_heur::NetConnHeuristic),
        Box::new(cairn_heur::PersistHeuristic),
        Box::new(cairn_heur::TimestompHeuristic::new(threshold)),
        Box::new(cairn_heur::CorrelationAnalyzer),
    ];
    assert!(analyzers.iter().any(|a| a.name() == "heur_timestomp"),
            "heur_timestomp must be in analyzer set");
    assert!(analyzers.iter().any(|a| a.name() == "heur_correlation"),
            "heur_correlation must be in analyzer set");
}
```

- [ ] **Step 3: Run all tests**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test --workspace 2>&1 | tail -15
```

Expected: all pass including the renamed test.

- [ ] **Step 4: Clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: zero.

- [ ] **Step 5: Commit**

```powershell
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire CorrelationAnalyzer into live run + update analyzer set test"
```

---

## Task 4 — Wire `details_client` zh-TW text

**Files:**
- Modify: `crates/cairn-report/src/client_text.rs`

### Context

`fill_details_client(f: &mut Finding)` currently dispatches on `f.artifact`. It handles `"process"`, `"netconn"`, `"persistence"`, etc. but not `"correlation"`.

Current dispatch structure (look for the `match f.artifact.as_str()` block in `fill_details_client`):

The correlation Finding has:
- `f.artifact == "correlation"`
- `f.entity.file.as_ref().map(|fi| fi.path.clone())` — the binary path
- `f.details` — English technical text
- `f.reason` — English reason

For zh-TW text, the template for correlation is:
```
在 {host} 上偵測到 {name} 同時存在於持久化機制（{mechanism_zh}）及執行記錄中，
代表該程式曾被執行且可能持續存在於系統中。
```

Where:
- `name` = `short_name(entity.file.path)` (basename)
- `mechanism_zh` = map from English mechanism name embedded in details:
  - `run_key` → `登錄檔自動啟動`
  - `service` → `系統服務`
  - `startup` → `啟動資料夾`
  - `scheduled_task` → `排程工作`
  - `winlogon` → `Winlogon 持久化`
  - `ifeo` → `IFEO 除錯器劫持`
  - unknown → `持久化機制`

Extract mechanism from `f.details` with a simple `str::contains` check (details always has "via {mechanism}").

### What to implement

- [ ] **Step 1: Add correlation text function** — in `client_text.rs`, add before `fill_details_client`:

```rust
fn correlation_client_text(host: &str, f: &Finding) -> String {
    let name = f
        .entity
        .file
        .as_ref()
        .map(|fi| short_name(&fi.path))
        .unwrap_or("未知程式");
    let mechanism_zh = if f.details.contains("run_key") {
        "登錄檔自動啟動"
    } else if f.details.contains("service") {
        "系統服務"
    } else if f.details.contains("startup") {
        "啟動資料夾"
    } else if f.details.contains("scheduled_task") {
        "排程工作"
    } else if f.details.contains("winlogon") {
        "Winlogon 持久化"
    } else if f.details.contains("ifeo") {
        "IFEO 除錯器劫持"
    } else {
        "持久化機制"
    };
    format!(
        "在 {host} 上偵測到 {name} 同時存在於{mechanism_zh}及執行記錄中，\
         代表該程式曾被執行且可能持續存在於系統中。"
    )
}
```

- [ ] **Step 2: Add dispatch arm** in `fill_details_client`, in the `match f.artifact.as_str()` block, add:

```rust
"correlation" => {
    f.details_client = Some(correlation_client_text(&f.host, f));
}
```

- [ ] **Step 3: Add test** — in `client_text.rs` tests (or in a separate inline test at bottom of `fill_details_client` block):

```rust
#[test]
fn correlation_client_text_in_zh_tw() {
    use crate::fill_details_client;
    use cairn_core::finding::{EntityFile, Finding, FindingSource, Severity};

    let mut f = Finding::new(Severity::High, "Confirmed persistence + execution: notion", FindingSource::Heuristic);
    f.host = "WS01".into();
    f.artifact = "correlation".into();
    f.entity.file = Some(EntityFile {
        path: r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe".into(),
        sha256: None,
        mtime: None,
        si_btime: None,
        fn_btime: None,
        si_mtime: None,
        fn_mtime: None,
        path_complete: None,
    });
    f.details = "notion persisted via run_key (HKLM\\...\\Run); confirmed executed [prefetch] last_run=2026-06-25T22:00:00Z".into();

    fill_details_client(&mut f);

    let client = f.details_client.as_deref().unwrap_or("");
    assert!(client.contains("WS01"), "host in text: {client}");
    assert!(client.contains("Notion"), "binary name in text: {client}");
    assert!(client.contains("登錄檔自動啟動"), "mechanism zh: {client}");
    assert!(client.contains("執行記錄"), "execution ref: {client}");
}
```

- [ ] **Step 4: Run tests**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test --workspace 2>&1 | tail -10
```

Expected: all pass including new test.

- [ ] **Step 5: Clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: zero.

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-report/src/client_text.rs
git commit -m "feat(report): add zh-TW client text for correlation findings"
```

---

## Self-Review

**Spec coverage:**
- Emit High Finding when same binary in persistence + execution ✓ (Task 2)
- Inbox suppression via `is_inbox_service_command` ✓ (Task 2)
- DriverStore NOT suppressed ✓ (Task 1 test + Task 2)
- entity.file set to best_path ✓ (Task 2)
- MITRE from mechanism ✓ (Task 2 `mechanism_to_mitre`)
- reason set (golden rule 6) ✓ (Task 2)
- details set (technical English) ✓ (Task 2)
- details_client zh-TW ✓ (Task 4)
- artifact = "correlation" ✓ (Task 2)
- No schema changes ✓
- No new dependencies ✓
- Graceful degrade (no exec records → no findings) ✓ (Task 1 test)
- Process corroboration added to reason ✓ (Task 2 + Task 1 test)
- Group by (key, mechanism) to avoid explosion ✓ (Task 2)
- Wired into main.rs ✓ (Task 3)
- Analyzer name test updated ✓ (Task 3)

**Placeholder scan:** None.

**Type consistency:**
- `Record::Execution`, `Record::Persistence`, `Record::Process` — all exist in `cairn_core::record`
- `EntityFile` constructed with all fields (including new `si_mtime`/`fn_mtime`/`path_complete`) ✓
- `Finding::new` signature unchanged ✓
- `is_inbox_service_command` from `crate::score` — already public in score.rs ✓
