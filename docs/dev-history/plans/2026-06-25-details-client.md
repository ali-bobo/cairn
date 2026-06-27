# details_client (FR18) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill `Finding.details_client` with plain zh-TW text for every Finding with severity >= Medium, using static template dispatch — no LLM, no runtime I/O, no new dependencies.

**Architecture:** New module `cairn-report/src/client_text.rs` exposes `pub fn fill_details_client(f: &mut Finding)`. The CLI calls it in both `run_evtx` (before line 555) and `run_live` (before line 868) after findings are collected and before the first `sink.write_*` call. Schema unchanged — `Finding.details_client: Option<String>` already exists.

**Tech Stack:** Pure Rust string formatting; zero new crate dependencies.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/cairn-report/src/client_text.rs` | Create | Template dispatch + `fill_details_client` |
| `crates/cairn-report/src/lib.rs` | Modify | `pub mod client_text;` |
| `crates/cairn-cli/src/main.rs` | Modify | Call `fill_details_client` at two call sites |

---

## Context for Implementer

**Finding struct** (in `crates/cairn-core/src/finding.rs`):
```rust
pub enum Severity { Critical, High, Medium, Low, Info }
pub enum FindingSource { Sigma, Heuristic }

pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub source: FindingSource,
    pub host: String,
    pub entity: Entity,        // entity.process.image = process image path
    pub entity: Entity,        // entity.file.path     = file path
    pub reason: Option<String>, // heuristic reason string
    pub details_client: Option<String>, // THIS is what we fill
    // ... other fields
}

pub struct Entity {
    pub process: Option<EntityProcess>,
    pub file: Option<EntityFile>,
    // ...
}
pub struct EntityProcess { pub image: String, /* ... */ }
pub struct EntityFile    { pub path: String,  /* ... */ }
```

**`path` extraction helper** — extract the most useful path string from a Finding:
```rust
fn entity_path(f: &Finding) -> &str {
    if let Some(p) = &f.entity.process { return &p.image; }
    if let Some(fi) = &f.entity.file   { return &fi.path; }
    "未知程式"
}
```

**Template dispatch order** (first-match):

| # | Condition | Template |
|---|---|---|
| 1 | `Heuristic` + reason contains `"parent-child"` (case-insensitive) | 主機 {host} 上，{path} 以非預期的父行程方式執行，可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。 |
| 2 | `Heuristic` + reason contains `"persist"` | 主機 {host} 上，{path} 疑似建立了持久化機制，建議確認該項目是否為已知且授權的軟體。 |
| 3 | `Heuristic` + reason contains `"netconn"` | 主機 {host} 上，{path} 發起了對外網路連線，建議確認連線目標是否屬於正常業務範疇。 |
| 4 | `Heuristic` (other / no reason) | 主機 {host} 上偵測到疑似異常行為，建議分析師確認詳情。 |
| 5 | `Sigma` + severity `Critical` or `High` | 主機 {host} 上偵測到與「{title}」相關的可疑活動，此類活動具有較高風險，建議盡速進行調查。 |
| 6 | `Sigma` + severity `Medium` | 主機 {host} 上偵測到與「{title}」相關的活動，建議分析師評估是否為授權操作。 |
| 7 | Fallback | 主機 {host} 上偵測到疑似異常事件，建議進行確認。 |

**Severity gate:** Only fill when `severity` is `Critical`, `High`, or `Medium`. Leave `Low` / `Info` as `None`.

**Call sites in `crates/cairn-cli/src/main.rs`:**
- `run_evtx`: insert before line 555 (`sink.write_timeline_csv(&findings)?;`)
- `run_live`: insert before line 868 (`sink.write_timeline_csv(&outcome.findings)?;`)

---

## Task T1 — `client_text.rs`: pure logic + tests

**Files:**
- Create: `crates/cairn-report/src/client_text.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/cairn-report/src/client_text.rs` with tests only (no implementation yet):

```rust
#![forbid(unsafe_code)]

use cairn_core::finding::{Entity, EntityFile, EntityProcess, Finding, FindingSource, Severity};

fn make_heuristic(severity: Severity, reason: Option<&str>) -> Finding {
    let mut f = Finding::new(severity, "test", FindingSource::Heuristic);
    f.host = "WS01".into();
    f.reason = reason.map(str::to_owned);
    f.entity.process = Some(EntityProcess {
        pid: 1, ppid: 0,
        image: r"C:\Windows\cmd.exe".into(),
        cmdline: String::new(),
        signed: None,
        integrity: None,
    });
    f
}

fn make_sigma(severity: Severity, title: &str) -> Finding {
    let mut f = Finding::new(severity, title, FindingSource::Sigma);
    f.host = "WS01".into();
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_text::fill_details_client;

    #[test]
    fn parent_child_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, Some("parent-child mismatch: cmd under svchost"));
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("非預期的父行程"), "got: {text}");
        assert!(text.contains("WS01"), "host missing: {text}");
        assert!(text.contains("cmd.exe"), "path missing: {text}");
    }

    #[test]
    fn persist_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, Some("persist: new run key added"));
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("持久化機制"), "got: {text}");
    }

    #[test]
    fn netconn_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, Some("netconn: raw ip egress"));
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("對外網路連線"), "got: {text}");
    }

    #[test]
    fn other_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, Some("unknown anomaly"));
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("疑似異常行為"), "got: {text}");
    }

    #[test]
    fn sigma_high_filled() {
        let mut f = make_sigma(Severity::High, "Mimikatz Credential Dumping");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("較高風險"), "got: {text}");
        assert!(text.contains("Mimikatz Credential Dumping"), "title missing: {text}");
    }

    #[test]
    fn sigma_medium_filled() {
        let mut f = make_sigma(Severity::Medium, "Suspicious PowerShell");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("評估是否為授權操作"), "got: {text}");
    }

    #[test]
    fn low_severity_not_filled() {
        let mut f = make_sigma(Severity::Low, "Low Noise Rule");
        fill_details_client(&mut f);
        assert!(f.details_client.is_none(), "Low must remain None");

        let mut f2 = make_heuristic(Severity::Info, Some("parent-child mismatch"));
        fill_details_client(&mut f2);
        assert!(f2.details_client.is_none(), "Info must remain None");
    }

    #[test]
    fn fallback_for_unknown_source() {
        // Heuristic with no reason falls to template 4 (other heuristic), not template 7.
        // Test the "no reason" heuristic path specifically, which uses template 4.
        let mut f = make_heuristic(Severity::High, None);
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("疑似異常行為"), "got: {text}");
    }

    #[test]
    fn entity_path_falls_back_to_file_then_unknown() {
        // When process is None but file is present, use file path.
        let mut f = make_sigma(Severity::High, "File Event");
        f.entity.file = Some(EntityFile {
            path: r"C:\temp\evil.exe".into(),
            sha256: None, mtime: None, si_btime: None, fn_btime: None,
            si_mtime: None, fn_mtime: None, path_complete: None,
        });
        // Sigma template doesn't interpolate path, so just verify it doesn't panic.
        fill_details_client(&mut f);
        assert!(f.details_client.is_some());

        // When both are None, entity_path returns "未知程式" — exercise via heuristic template.
        let mut f2 = make_heuristic(Severity::High, Some("parent-child mismatch"));
        f2.entity.process = None;
        fill_details_client(&mut f2);
        let text = f2.details_client.unwrap();
        assert!(text.contains("未知程式"), "fallback path missing: {text}");
    }
}
```

- [ ] **Step 2: Run tests — expect compile error (function not defined)**

```
cargo test -p cairn-report 2>&1 | head -20
```

Expected: error `use of undeclared crate or module 'client_text'` or similar compile error. Tests do not pass yet.

- [ ] **Step 3: Implement `fill_details_client`**

Add the implementation above the `#[cfg(test)]` block in the same file:

```rust
use cairn_core::finding::{Entity, EntityFile, EntityProcess, Finding, FindingSource, Severity};

fn is_medium_or_above(s: Severity) -> bool {
    matches!(s, Severity::Critical | Severity::High | Severity::Medium)
}

fn entity_path(f: &Finding) -> &str {
    if let Some(p) = &f.entity.process {
        return &p.image;
    }
    if let Some(fi) = &f.entity.file {
        return &fi.path;
    }
    "未知程式"
}

fn reason_contains(f: &Finding, needle: &str) -> bool {
    f.reason
        .as_deref()
        .map(|r| r.to_ascii_lowercase().contains(needle))
        .unwrap_or(false)
}

pub fn fill_details_client(f: &mut Finding) {
    if !is_medium_or_above(f.severity) {
        return;
    }
    let host = &f.host.clone();
    let text = match f.source {
        FindingSource::Heuristic => {
            let path = entity_path(f).to_owned();
            if reason_contains(f, "parent-child") {
                format!(
                    "主機 {} 上，{} 以非預期的父行程方式執行，\
                     可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。",
                    host, path
                )
            } else if reason_contains(f, "persist") {
                format!(
                    "主機 {} 上，{} 疑似建立了持久化機制，\
                     建議確認該項目是否為已知且授權的軟體。",
                    host, path
                )
            } else if reason_contains(f, "netconn") {
                format!(
                    "主機 {} 上，{} 發起了對外網路連線，\
                     建議確認連線目標是否屬於正常業務範疇。",
                    host, path
                )
            } else {
                format!(
                    "主機 {} 上偵測到疑似異常行為，建議分析師確認詳情。",
                    host
                )
            }
        }
        FindingSource::Sigma => {
            let title = f.title.clone();
            match f.severity {
                Severity::Critical | Severity::High => format!(
                    "主機 {} 上偵測到與「{}」相關的可疑活動，\
                     此類活動具有較高風險，建議盡速進行調查。",
                    host, title
                ),
                _ => format!(
                    "主機 {} 上偵測到與「{}」相關的活動，\
                     建議分析師評估是否為授權操作。",
                    host, title
                ),
            }
        }
    };
    f.details_client = Some(text);
}
```

- [ ] **Step 4: Run tests — expect all pass**

```
cargo test -p cairn-report client_text 2>&1
```

Expected output:
```
running 9 tests
test client_text::tests::entity_path_falls_back_to_file_then_unknown ... ok
test client_text::tests::low_severity_not_filled ... ok
test client_text::tests::netconn_heuristic_filled ... ok
test client_text::tests::other_heuristic_filled ... ok
test client_text::tests::fallback_for_unknown_source ... ok
test client_text::tests::parent_child_heuristic_filled ... ok
test client_text::tests::persist_heuristic_filled ... ok
test client_text::tests::sigma_high_filled ... ok
test client_text::tests::sigma_medium_filled ... ok
test result: ok. 9 passed; 0 failed; ...
```

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-report/src/client_text.rs
git commit -m "feat(report): client_text module — fill_details_client + 9 unit tests (FR18)"
```

---

## Task T2 — Wire into `cairn-report/src/lib.rs` + verify workspace

**Files:**
- Modify: `crates/cairn-report/src/lib.rs` (add one line)

- [ ] **Step 1: Add `pub mod client_text;` to lib.rs**

Open `crates/cairn-report/src/lib.rs`. After the existing `pub mod` declarations at the top of the file (after `pub mod age_sink;`, `pub mod dry_run;`, `pub mod zip_sink;`), add:

```rust
pub mod client_text;
```

The top of `lib.rs` should now look like:

```rust
pub mod age_sink;
pub mod client_text;
pub mod dry_run;
pub mod zip_sink;
```

(alphabetical order, matching the existing style)

- [ ] **Step 2: Verify workspace compiles**

```
cargo check --workspace 2>&1 | tail -5
```

Expected: `Finished` with no errors.

- [ ] **Step 3: Run full workspace tests — all must pass**

```
cargo test --workspace 2>&1 | grep -E "^test result"
```

Expected: all `test result: ok` lines, same counts as before plus 9 new tests in `cairn-report`.

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-report/src/lib.rs
git commit -m "chore(report): expose client_text module (FR18)"
```

---

## Task T3 — Wire call sites in `cairn-cli/src/main.rs`

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (two insertions)

**Background:** There are two output paths in main.rs:

1. **`run_evtx` path** (around line 553–556): findings come from EVTX analysis.
   The block looks like:
   ```rust
   let mut manifest = build_manifest(&cfg, &hostname, records.len() as u64, &findings);
   // ...
   sink.write_timeline_csv(&findings)?;
   sink.write_findings_jsonl(&findings)?;
   ```
   Insert **before** `sink.write_timeline_csv(&findings)?;`.

2. **`run_live` path** (around line 868–869): findings come from live collectors.
   The block looks like:
   ```rust
   sink.write_timeline_csv(&outcome.findings)?;
   sink.write_findings_jsonl(&outcome.findings)?;
   ```
   Insert **before** `sink.write_timeline_csv(&outcome.findings)?;`.

- [ ] **Step 1: Add `use cairn_report::client_text;` import**

Near the top of `main.rs`, find the existing `use cairn_report::` imports (e.g., `use cairn_report::{AgeSink, DirSink, DryRunSink, ZipSink};`). Add `client_text` to the use list or add a separate line:

```rust
use cairn_report::client_text;
```

- [ ] **Step 2: Insert call in run_evtx path**

Locate the block in `run_evtx` around line 553 that reads:
```rust
let mut manifest = build_manifest(&cfg, &hostname, records.len() as u64, &findings);
```

The `findings` variable is `Vec<Finding>` and is already `mut` (confirmed from grep: `let mut findings = Vec::new();`). Insert this block **immediately before** `sink.write_timeline_csv(&findings)?;`:

```rust
for f in &mut findings {
    client_text::fill_details_client(f);
}
```

- [ ] **Step 3: Insert call in run_live path**

Locate the block in `run_live` around line 868 that reads:
```rust
sink.write_timeline_csv(&outcome.findings)?;
sink.write_findings_jsonl(&outcome.findings)?;
```

`outcome.findings` is `Vec<Finding>`. Insert **immediately before** `sink.write_timeline_csv(&outcome.findings)?;`:

```rust
for f in &mut outcome.findings {
    client_text::fill_details_client(f);
}
```

- [ ] **Step 4: Verify it compiles**

```
cargo check --workspace 2>&1 | tail -5
```

Expected: `Finished` with no errors.

- [ ] **Step 5: Run clippy**

```
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10
```

Expected: no warnings.

- [ ] **Step 6: Run fmt**

```
cargo fmt --all
```

(No output expected — just apply formatting so CI passes.)

- [ ] **Step 7: Run full test suite**

```
cargo test --workspace 2>&1 | grep -E "^test result"
```

Expected: all `test result: ok`, zero failures, counts match (new 9 tests in cairn-report).

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): call fill_details_client before sink writes — FR18 complete"
```

---

## Acceptance Gate

All three must pass before declaring done:

1. `cargo test --workspace` — all green, including the 9 new `client_text::tests::*` tests.
2. `cargo clippy --workspace --all-targets -- -D warnings` — clean.
3. `cargo fmt --all` — no diff (already applied in T3 Step 6).

Schema unchanged: `Finding.details_client: Option<String>` already existed. No new crate dependencies. `#![forbid(unsafe_code)]` maintained throughout.
