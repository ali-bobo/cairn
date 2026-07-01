# Heuristic Gate Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 cairn-heur 從「加權累分」改成「決定性信號 gate」模型，乾淨機器 High=0/Medium=0/Low<5，
盤點項走新 Observation 通道，Finding 帶結構化 evidence 與路徑優先的輸出格式。

**Architecture:** Gate（發不發：S1-S9 罕見信號）與 Severity（多嚴重：信號種類+升級因子）分離。
CorrelationAnalyzer 刪除、交叉比對併入 PersistHeuristic。cairn-core 加 Observation/EvidenceItem
（additive、schema 字串不變）。信任知識集中到新 trust.rs。

**Tech Stack:** Rust workspace（cairn-core / cairn-heur / cairn-collectors / cairn-report / cairn-cli）、
serde、chrono。零新外部依賴。

**Spec:** `docs/dev-history/specs/2026-07-02-heuristic-gate-redesign-design.md`

**每個 task 開工前：**
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
```
**每個 task 驗收：**`cargo check --workspace` → task 指定測試 → `cargo clippy --workspace --all-targets -- -D warnings`。

---

## File Structure（全計畫觸及的檔案）

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-core/src/finding.rs` | Modify | +EvidenceItem、Finding.evidence |
| `crates/cairn-core/src/observation.rs` | Create | Observation 型別 |
| `crates/cairn-core/src/lib.rs` | Modify | +observation mod、schema::OBSERVATION、re-exports |
| `crates/cairn-core/src/traits.rs` | Modify | Analyzer::observe、OutputSink::write_observations、write_html_report 簽名 |
| `crates/cairn-core/src/orchestrator.rs` | Modify | RunOutcome.observations、observe fan-in |
| `crates/cairn-core/src/manifest.rs` | Modify | Counts.observations |
| `crates/cairn-heur/src/trust.rs` | Create | 路徑/名稱信任判斷集中地 |
| `crates/cairn-heur/src/lib.rs` | Modify | +trust mod、移除 correlation |
| `crates/cairn-heur/src/persist.rs` | Modify | gate 重寫 + 交叉比對 + observe |
| `crates/cairn-heur/src/correlation.rs` | **Delete** | 併入 persist |
| `crates/cairn-heur/src/account.rs` | Modify | +evidence |
| `crates/cairn-heur/src/timestomp.rs` | Modify | +evidence |
| `crates/cairn-heur/src/netconn.rs` | Modify | gate floor |
| `crates/cairn-heur/src/parentchild.rs` | Modify | path 改 amplifier + S3 偽裝 |
| `crates/cairn-collectors/src/persist.rs` | Modify | 相對路徑解析（驗章前） |
| `crates/cairn-report/src/lib.rs` | Modify | observations_jsonl、DirSink |
| `crates/cairn-report/src/zip_sink.rs` `age_sink.rs` | Modify | write_observations |
| `crates/cairn-report/src/html.rs` | Modify | evidence 顯示 + 盤點折疊區塊 |
| `crates/cairn-report/src/client_text.rs` | Modify | 移除 correlation arm |
| `crates/cairn-cli/src/main.rs` | Modify | 接線、counts、analyzers vec |

---

### Task 1: cairn-core — EvidenceItem + Finding.evidence

**Files:**
- Modify: `crates/cairn-core/src/finding.rs`

- [ ] **Step 1: 在 `EntityRegistry` 定義後、`Finding` 定義前加入 EvidenceItem**

```rust
/// One corroborating source for a Finding (spec §7): which artifact saw the binary,
/// at what path, when. `path` is honest — prefetch carries only a file name and says so
/// in `detail`. Additive to the finding schema (old JSON deserializes to an empty vec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Source artifact: "run_key" | "service" | "prefetch" | "shimcache" | "amcache"
    /// | "bam" | "userassist" | "process" | "evtx:Security" | "mft" | ...
    pub artifact: String,
    /// Full path as seen by that source (None when the source has no path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// That source's own timestamp (last_run / last_write / event time).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<DateTime<Utc>>,
    /// Human-readable one-liner, e.g. "prefetch: run_count=12 last_run=2026-06-27T23:31Z".
    pub detail: String,
}
```

- [ ] **Step 2: `Finding` struct 的 `reason` 欄位後加**

```rust
    /// Corroborating sources (spec §7). Empty for findings with a single self-evident
    /// source (most Sigma hits). Old JSON without the field deserializes to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceItem>,
```

`Finding::new` 的初始化加 `evidence: vec![],`。

- [ ] **Step 3: 檔尾 tests mod 加兩個測試**

```rust
    #[test]
    fn evidence_roundtrips_and_old_json_defaults_empty() {
        let mut f = Finding::new(Severity::High, "x", FindingSource::Heuristic);
        f.evidence.push(EvidenceItem {
            artifact: "prefetch".into(),
            path: Some("EVIL.EXE".into()),
            ts: None,
            detail: "prefetch: run_count=3".into(),
        });
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"evidence\""));
        let back: Finding = serde_json::from_str(&j).unwrap();
        assert_eq!(back.evidence.len(), 1);
        assert_eq!(back.evidence[0].artifact, "prefetch");

        // Old JSON (no evidence field) -> empty vec, and empty vec is omitted on write.
        let f2 = Finding::new(Severity::Low, "y", FindingSource::Heuristic);
        let j2 = serde_json::to_string(&f2).unwrap();
        assert!(!j2.contains("evidence"));
        let back2: Finding = serde_json::from_str(&j2).unwrap();
        assert!(back2.evidence.is_empty());
    }

    #[test]
    fn finding_schema_string_unchanged_by_evidence() {
        let f = Finding::new(Severity::Info, "z", FindingSource::Sigma);
        assert_eq!(f.schema, "cairn.finding/1");
    }
```

- [ ] **Step 4: 跑測試**

Run: `cargo test -p cairn-core`
Expected: 全綠（含 2 個新測試）。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-core/src/finding.rs
git commit -m "feat(core): add EvidenceItem + Finding.evidence (additive, schema unchanged)"
```

---

### Task 2: cairn-core — Observation 型別 + trait 方法 + orchestrator + Counts

**Files:**
- Create: `crates/cairn-core/src/observation.rs`
- Modify: `crates/cairn-core/src/lib.rs`、`traits.rs`、`orchestrator.rs`、`manifest.rs`
- Modify（機械修正編譯）: `crates/cairn-report/src/lib.rs`、`crates/cairn-cli/src/main.rs`

- [ ] **Step 1: 新檔 `observation.rs`**

```rust
//! Observations: host-inventory items that carry investigative value but are NOT
//! detections (spec §6). Persistence entries that fail the dispositive-signal gate
//! land here instead of findings — every machine has services and autoruns; listing
//! them is inventory, alarming on them is noise.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub schema: String, // crate::schema::OBSERVATION
    /// The item's own time (e.g. registry last_write); run time when unknown.
    pub ts: DateTime<Utc>,
    pub host: String,
    /// "service" | "run_key" | "scheduled_task" | "startup" | "winlogon_default"
    pub category: String,
    /// e.g. "服務 AsusAppService → AsusAppService.exe"
    pub title: String,
    /// Binary full path when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Location (registry key / folder), signature status, last_write.
    pub details: String,
    pub source_artifact: String, // "persistence"
}

impl Observation {
    pub fn new(category: impl Into<String>, title: impl Into<String>) -> Self {
        Observation {
            schema: crate::schema::OBSERVATION.to_string(),
            ts: Utc::now(),
            host: String::new(),
            category: category.into(),
            title: title.into(),
            path: None,
            details: String::new(),
            source_artifact: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_roundtrips_with_schema_tag() {
        let mut o = Observation::new("service", "服務 X → x.exe");
        o.path = Some(r"C:\Program Files\X\x.exe".into());
        o.source_artifact = "persistence".into();
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains("cairn.observation/1"));
        let back: Observation = serde_json::from_str(&j).unwrap();
        assert_eq!(back.category, "service");
        assert_eq!(back.path.as_deref(), Some(r"C:\Program Files\X\x.exe"));
    }
}
```

- [ ] **Step 2: `lib.rs` 接線**

`pub mod observation;` 加進 mod 區（字母序，`manifest` 後）；
`pub use observation::Observation;` 加進 re-export 區；
`schema` mod 加 `pub const OBSERVATION: &str = "cairn.observation/1";`。

- [ ] **Step 3: `traits.rs` — Analyzer 加 default method、OutputSink 加兩處**

`use` 行加 `observation::Observation`。Analyzer trait 內 `analyze` 後加：

```rust
    /// Inventory items that did NOT clear the dispositive-signal gate (spec §6).
    /// Default empty: only analyzers that own an inventory (persist) override.
    fn observe(&self, _records: &[Record]) -> Result<Vec<Observation>> {
        Ok(vec![])
    }
```

OutputSink trait：`write_findings_jsonl` 後加

```rust
    /// Host-inventory channel (observations.jsonl). Default no-op.
    fn write_observations(&mut self, _observations: &[Observation]) -> Result<()> {
        Ok(())
    }
```

`write_html_report` 簽名改為（**breaking，本 task 內修所有 impl/caller**）：

```rust
    fn write_html_report(
        &mut self,
        _findings: &[Finding],
        _observations: &[Observation],
        _manifest: &crate::manifest::Manifest,
    ) -> Result<()> {
        Ok(())
    }
```

- [ ] **Step 4: `orchestrator.rs` — RunOutcome + observe fan-in**

`RunOutcome` 加 `pub observations: Vec<Observation>,`（`use crate::observation::Observation;`）。
`run_live` 的 analyzer 迴圈後加：

```rust
    // Observation fan-in (spec §6): inventory from analyzers that own one. A failing
    // observe is logged + skipped, mirroring the analyze contract.
    let mut observations = Vec::new();
    for a in analyzers {
        match a.observe(&records) {
            Ok(mut os) => observations.append(&mut os),
            Err(e) => {
                tracing::warn!(analyzer = a.name(), error = %e, "observe failed; skipping");
            }
        }
    }
```

`RunOutcome { ... }` 建構加 `observations,`。orchestrator 既有測試中建構 RunOutcome 或
斷言其欄位處若編譯錯，補 `observations: vec![]` / 忽略欄位。

- [ ] **Step 5: `manifest.rs` — Counts 加欄位**

```rust
pub struct Counts {
    pub records: u64,
    pub findings_by_sev: std::collections::BTreeMap<String, u64>,
    /// Inventory items written to observations.jsonl (spec §6). Additive.
    #[serde(default)]
    pub observations: u64,
}
```

manifest.rs 測試內建構 `Counts { .. }` 處補 `observations: 0,`。

- [ ] **Step 6: 機械修正編譯錯（本 task 只求編譯過，內容留 Task 10/11）**

- `crates/cairn-report/src/lib.rs` DirSink 的 `write_html_report` 加參數
  `_observations: &[cairn_core::Observation]`（暫不使用）。
- `crates/cairn-cli/src/main.rs` 兩處呼叫（約 570 行 evtx 路徑、約 939 行 live 路徑）改
  `sink.write_html_report(&findings, &[], &manifest)?;` 與
  `sink.write_html_report(&outcome.findings, &outcome.observations, &manifest)?;`。
- cli 兩處 `Counts { .. }` 建構（約 413、925 行）補：evtx 路徑 `observations: 0,`、
  live 路徑 `observations: outcome.observations.len() as u64,`。
- cairn-report / cairn-cli 測試裡呼叫 `write_html_report(&findings, &manifest)` 或建構
  `Counts` 的地方同步補參數/欄位。

- [ ] **Step 7: 跑 workspace 測試**

Run: `cargo test --workspace`（cairn-updater 需 admin 屬已知例外，可 `--exclude cairn-updater`）
Expected: 全綠。

- [ ] **Step 8: Commit**

```bash
git add -A crates/
git commit -m "feat(core): Observation channel — type, observe()/write_observations() seams, RunOutcome + Counts wiring"
```

---

### Task 3: cairn-heur — trust.rs（信任知識集中）

**Files:**
- Create: `crates/cairn-heur/src/trust.rs`
- Modify: `crates/cairn-heur/src/lib.rs`（`pub mod trust;`）

- [ ] **Step 1: 新檔 `trust.rs`（完整內容）**

```rust
//! Centralized "this is normal" knowledge (spec §5b). Analyzers MUST use these
//! instead of re-deriving path/name trust locally — the whack-a-mole suppression
//! patches of S2 (TRUSTED_APPDATA, inbox-service, winlogon-default, correlation
//! matrix) all came from NOT having this module.
//!
//! Existing trust fns stay in score.rs and are re-exported here so analyzers have
//! ONE import surface: `use crate::trust::*;`.
pub use crate::score::{
    is_inbox_service_command, is_trusted_appdata_location, winlogon_value_is_default,
};

/// System-binary names an attacker plants outside C:\Windows to masquerade (S3).
/// Matched against the lowercased basename.
pub const PROTECTED_SYSTEM_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "rundll32.exe", "dllhost.exe",
    "taskhostw.exe",
];

/// Directories a non-admin user can write to — the drop zones (S2/S4 ingredient).
/// Deliberately excludes the broad `\appdata\` (legitimate per-user installs live in
/// `\AppData\Local\<vendor>\`); Roaming and Temp stay in.
pub const USER_WRITABLE_DIRS: &[&str] = &[
    r"\temp\",
    r"\appdata\roaming\",
    r"\appdata\local\temp\",
    r"\downloads\",
    r"\public\",
    r"\programdata\",
];

/// True if `path` (any case) contains a user-writable drop-zone segment.
pub fn is_user_writable_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    USER_WRITABLE_DIRS.iter().any(|d| lower.contains(d))
}

/// True if `path` is an absolute path under the Windows tree on ANY drive
/// (`X:\Windows\...`). Covers System32 / SysWOW64 / WinSxS / the Windows root —
/// all locations where system-named binaries legitimately live (explorer.exe sits
/// in C:\Windows directly, not System32).
pub fn is_under_windows_tree(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // position 1 == drive-colon form "x:\windows\"
    lower.get(1..).is_some_and(|rest| rest.starts_with(r":\windows\"))
}

/// True if `path` is under the Windows tree or Program Files (either bitness).
/// Both require admin to write — "system or vendor-installed" trust tier (S4 gate).
pub fn is_system_or_program_files(path: &str) -> bool {
    if is_under_windows_tree(path) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.get(1..).is_some_and(|rest| rest.starts_with(r":\program files"))
}

/// S3: a protected system name at an ABSOLUTE path outside the Windows tree.
/// Relative/bare paths return false — no location info means no masquerade verdict
/// (honest abstain; the winlogon default `explorer.exe` is a bare name).
pub fn is_masquerade(path: &str) -> bool {
    if !path.get(1..).is_some_and(|r| r.starts_with(":\\")) {
        return false; // not absolute — abstain
    }
    if is_under_windows_tree(path) {
        return false;
    }
    let base = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    PROTECTED_SYSTEM_NAMES.contains(&base.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_writable_hits_dropzones_not_vendor_appdata() {
        assert!(is_user_writable_path(r"C:\Users\a\AppData\Roaming\evil.exe"));
        assert!(is_user_writable_path(r"C:\Users\a\Downloads\x.exe"));
        assert!(is_user_writable_path(r"C:\ProgramData\x\evil.exe"));
        assert!(!is_user_writable_path(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"));
        assert!(!is_user_writable_path(r"C:\Program Files\X\x.exe"));
    }

    #[test]
    fn windows_tree_covers_root_system32_syswow64_any_drive() {
        assert!(is_under_windows_tree(r"C:\Windows\explorer.exe"));
        assert!(is_under_windows_tree(r"C:\WINDOWS\System32\svchost.exe"));
        assert!(is_under_windows_tree(r"D:\Windows\SysWOW64\svchost.exe"));
        assert!(!is_under_windows_tree(r"C:\Windows2\evil.exe"));
        assert!(!is_under_windows_tree("explorer.exe")); // relative — not under tree
    }

    #[test]
    fn system_or_pf_includes_both_program_files() {
        assert!(is_system_or_program_files(r"C:\Program Files\V\v.exe"));
        assert!(is_system_or_program_files(r"C:\Program Files (x86)\V\v.exe"));
        assert!(is_system_or_program_files(r"C:\Windows\System32\a.exe"));
        assert!(!is_system_or_program_files(r"C:\Users\a\AppData\Local\P\p.exe"));
    }

    #[test]
    fn masquerade_fires_only_on_absolute_paths_outside_windows() {
        assert!(is_masquerade(r"C:\Users\a\AppData\Roaming\svchost.exe"));
        assert!(is_masquerade(r"C:\ProgramData\lsass.exe"));
        assert!(!is_masquerade(r"C:\Windows\System32\svchost.exe"));
        assert!(!is_masquerade(r"C:\Windows\explorer.exe"));
        assert!(!is_masquerade("explorer.exe")); // bare name — abstain
        assert!(!is_masquerade(r"C:\Users\a\AppData\Roaming\notmalware.exe")); // not protected name
    }
}
```

- [ ] **Step 2: `lib.rs` 加 `pub mod trust;`（mod 區字母序）**

- [ ] **Step 3: 跑測試 + commit**

Run: `cargo test -p cairn-heur trust::` → 4 個新測試綠。

```bash
git add crates/cairn-heur/src/trust.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): trust.rs — centralized path/name trust knowledge (spec §5b)"
```

---

### Task 4: cairn-collectors — 驗章前解析相對 binary_path

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: 在 `apply_signatures` 定義前加純函式（injected `exists`，仿既有 `pick_binary_path` 模式）**

```rust
/// Resolve a RELATIVE binary_path against the Windows standard search order
/// (System32, then the Windows root) BEFORE signature verification (spec §5).
/// Winlogon stores `explorer.exe` as a bare name; without this the verifier gets an
/// unresolvable path, returns None, and the finding can't be honestly classified.
/// Absolute paths (drive-colon or UNC) are left untouched. Unresolvable stays as-is
/// (verifier will yield None — honest "could not verify").
fn resolve_relative_binary_paths_with(
    records: &mut [PersistenceRecord],
    sysroot: &str,
    exists: impl Fn(&str) -> bool,
) {
    for r in records.iter_mut() {
        let Some(p) = r.binary_path.as_deref() else { continue };
        let is_absolute = p.get(1..).is_some_and(|rest| rest.starts_with(":\\"))
            || p.starts_with("\\\\");
        if is_absolute || p.contains('\\') || p.is_empty() {
            continue; // absolute, UNC, or already dir-qualified relative — leave alone
        }
        for base in [format!(r"{sysroot}\System32"), sysroot.to_string()] {
            let cand = format!(r"{base}\{p}");
            if exists(&cand) {
                r.binary_path = Some(cand);
                break;
            }
        }
    }
}

/// Process-env wrapper: %SystemRoot% with the conventional fallback.
fn resolve_relative_binary_paths(records: &mut [PersistenceRecord]) {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    resolve_relative_binary_paths_with(records, &sysroot, |p| std::path::Path::new(p).exists());
}
```

- [ ] **Step 2: 在 `PersistCollector::collect` 內呼叫 `apply_signatures` 的位置之前插入**

```rust
        resolve_relative_binary_paths(&mut records);
```

（用 `grep -n "apply_signatures(&mut" crates/cairn-collectors/src/persist.rs` 找唯一呼叫點。）

- [ ] **Step 3: tests mod 加測試（用既有 `PersistenceRecord` 建構模式）**

```rust
    fn rec_with_path(p: Option<&str>) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: "winlogon".into(),
            location: r"HKLM\...\Winlogon".into(),
            value: Some("Shell".into()),
            command: p.map(|s| s.to_string()),
            binary_path: p.map(|s| s.to_string()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
        }
    }

    #[test]
    fn bare_name_resolves_via_system32_then_root() {
        let mut recs = vec![rec_with_path(Some("explorer.exe"))];
        resolve_relative_binary_paths_with(&mut recs, r"C:\Windows", |p| {
            p == r"C:\Windows\explorer.exe" // not in System32, found at root
        });
        assert_eq!(recs[0].binary_path.as_deref(), Some(r"C:\Windows\explorer.exe"));

        let mut recs2 = vec![rec_with_path(Some("userinit.exe"))];
        resolve_relative_binary_paths_with(&mut recs2, r"C:\Windows", |p| {
            p == r"C:\Windows\System32\userinit.exe"
        });
        assert_eq!(
            recs2[0].binary_path.as_deref(),
            Some(r"C:\Windows\System32\userinit.exe")
        );
    }

    #[test]
    fn absolute_unc_and_unresolvable_left_untouched() {
        let mut recs = vec![
            rec_with_path(Some(r"C:\Windows\explorer.exe")),
            rec_with_path(Some(r"\\srv\share\x.exe")),
            rec_with_path(Some("ghost.exe")),
            rec_with_path(None),
        ];
        resolve_relative_binary_paths_with(&mut recs, r"C:\Windows", |_| false);
        assert_eq!(recs[0].binary_path.as_deref(), Some(r"C:\Windows\explorer.exe"));
        assert_eq!(recs[1].binary_path.as_deref(), Some(r"\\srv\share\x.exe"));
        assert_eq!(recs[2].binary_path.as_deref(), Some("ghost.exe")); // stays; verifier -> None
        assert_eq!(recs[3].binary_path, None);
    }
```

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test -p cairn-collectors persist::` → 全綠含 2 新測試。

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "fix(collectors): resolve relative persistence binary paths before signature verification"
```

---

### Task 5: cairn-heur persist — gate 純函式（先並存，不接線）

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: 檔頭 use 區加**

```rust
use crate::trust::{
    is_masquerade, is_system_or_program_files, is_user_writable_path, winlogon_value_is_default,
};
```

（既有 `use crate::score::...` 行中 winlogon_value_is_default 若已引入則改由 trust 引入，避免重複。）

- [ ] **Step 2: 在 `score_persistence` 之後加 gate 模型（暫掛 `#[allow(dead_code)]`，Task 6 接線後移除）**

```rust
/// One dispositive-signal hit (spec §4.2). `label` feeds the Finding title;
/// `reason` feeds Finding.reason (golden rule 6).
#[allow(dead_code)]
pub(crate) struct GateHit {
    pub severity: Severity,
    pub label: &'static str,
    pub reason: String,
    pub mitre: &'static str,
}

/// Bump one severity band (multi-signal / execution-corroboration escalation).
#[allow(dead_code)]
fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// S9 (spec §4.2): persistence command invoking a script interpreter.
/// Encoded/remote content -> High; a plain local script file -> Low; else None.
/// The interpreter must be the invoked binary itself (basename of binary_path, or the
/// command's first token) — a substring match would flag "PowerShell Studio\app.exe".
#[allow(dead_code)]
fn script_persistence_signal(p: &PersistenceRecord) -> Option<GateHit> {
    const INTERPRETERS: &[&str] = &[
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe",
        "powershell", "pwsh", "wscript", "cscript", "mshta", "cmd",
    ];
    let cmd = p.command.as_deref()?;
    let invoked = p
        .binary_path
        .as_deref()
        .map(|bp| short_name_persist(bp).to_ascii_lowercase())
        .or_else(|| {
            cmd.trim().trim_matches('"').split_whitespace().next().map(|t| {
                short_name_persist(t).to_ascii_lowercase()
            })
        })?;
    if !INTERPRETERS.contains(&invoked.as_str()) {
        return None;
    }
    let lower = cmd.to_ascii_lowercase();
    let encoded = lower.contains(" -enc")
        || lower.contains(" -encodedcommand")
        || lower.contains("frombase64string");
    let remote = lower.contains("http://") || lower.contains("https://");
    if encoded || remote {
        return Some(GateHit {
            severity: Severity::High,
            label: "腳本直譯器持久化（編碼/遠端內容）",
            reason: format!("persistence command runs {invoked} with encoded or remote content: {cmd}"),
            mitre: "T1059",
        });
    }
    const SCRIPT_EXTS: &[&str] = &[".vbs", ".vbe", ".js", ".jse", ".bat", ".ps1", ".hta"];
    if SCRIPT_EXTS.iter().any(|e| lower.contains(e)) {
        return Some(GateHit {
            severity: Severity::Low,
            label: "腳本檔持久化",
            reason: format!("persistence command runs {invoked} against a local script: {cmd}"),
            mitre: "T1059",
        });
    }
    None
}

/// Evaluate the dispositive-signal gate for one persistence record (spec §4.2).
/// Empty vec = no rare signal = inventory, not a detection (route to Observation).
#[allow(dead_code)]
pub(crate) fn evaluate_gate(p: &PersistenceRecord, now: DateTime<Utc>) -> Vec<GateHit> {
    let mut hits = Vec::new();
    let path = p.binary_path.as_deref().unwrap_or("");

    // S1a: winlogon value tampered (default values are inventory).
    if p.mechanism == "winlogon" {
        let is_default = p
            .value
            .as_deref()
            .zip(p.command.as_deref())
            .is_some_and(|(v, c)| winlogon_value_is_default(v, c));
        if !is_default {
            hits.push(GateHit {
                severity: Severity::High,
                label: "Winlogon 遭篡改",
                reason: format!(
                    "Winlogon {} is not the stock default: {}",
                    p.value.as_deref().unwrap_or("?"),
                    p.command.as_deref().unwrap_or("-")
                ),
                mitre: "T1547.004",
            });
        }
    }

    // S1b: IFEO debugger — always gates (rare); severity by target trust.
    if p.mechanism == "ifeo" {
        let untrusted = p.signed == Some(false) || is_user_writable_path(path);
        hits.push(GateHit {
            severity: if untrusted { Severity::High } else { Severity::Medium },
            label: "IFEO debugger 挾持",
            reason: format!(
                "IFEO Debugger set ({}); target {}",
                p.location,
                if untrusted { "unsigned or in a user-writable path" } else { "signed, system/vendor path (Process Explorer-style use)" }
            ),
            mitre: "T1546.012",
        });
    }

    // S2: explicitly unsigned + user-writable drop zone.
    if p.signed == Some(false) && is_user_writable_path(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "未簽章執行檔於使用者可寫路徑",
            reason: format!("binary is explicitly unsigned and lives in a user-writable drop zone: {path}"),
            mitre: "T1036",
        });
    }

    // S3: system-name masquerade (absolute path outside C:\Windows).
    if is_masquerade(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "系統程式名稱偽裝",
            reason: format!("system binary name at a non-Windows location: {path}"),
            mitre: "T1036.005",
        });
    }

    // S4: recent + unverifiable + outside system/vendor dirs — all three required.
    // Recency ALONE is dead (update-day mass rewrites, per-user service instances).
    if p.signed.is_none() && !path.is_empty() && !is_system_or_program_files(path) {
        if let Some(lw) = p.last_write {
            let age = now.signed_duration_since(lw);
            if age >= Duration::zero() && age <= Duration::days(RECENT_DAYS) {
                hits.push(GateHit {
                    severity: Severity::Medium,
                    label: "近期建立且簽章無法驗證",
                    reason: format!(
                        "created/modified within {RECENT_DAYS} days, signature unverifiable, non-system path: {path}"
                    ),
                    mitre: "T1547",
                });
            }
        }
    }

    // S9: script-interpreter persistence.
    if let Some(hit) = script_persistence_signal(p) {
        hits.push(hit);
    }

    hits
}
```

- [ ] **Step 3: tests mod 加 gate 測試（沿用既有 `rec(...)` helper；需要更多欄位時直接建構 struct）**

```rust
    // ── gate model (spec §4.2) ───────────────────────────────────────────────
    fn full_rec(
        mechanism: &str,
        value: Option<&str>,
        command: Option<&str>,
        binary_path: Option<&str>,
        signed: Option<bool>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: format!("HKLM\\...\\{mechanism}"),
            value: value.map(String::from),
            command: command.map(String::from),
            binary_path: binary_path.map(String::from),
            binary_sha256: None,
            signed,
            signer: None,
            last_write,
        }
    }

    #[test]
    fn gate_s1a_winlogon_tamper_high_default_silent() {
        let now = Utc::now();
        let tampered = full_rec("winlogon", Some("Shell"), Some("explorer.exe,evil.exe"),
            None, None, None);
        let hits = evaluate_gate(&tampered, now);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].mitre, "T1546.012".replace("6.012", "7.004")); // T1547.004
        let stock = full_rec("winlogon", Some("Shell"), Some("explorer.exe"),
            Some(r"C:\Windows\explorer.exe"), Some(true), Some(now));
        assert!(evaluate_gate(&stock, now).is_empty(), "stock winlogon must be inventory");
    }

    #[test]
    fn gate_s1b_ifeo_severity_by_target_trust() {
        let now = Utc::now();
        let evil = full_rec("ifeo", Some("Debugger"), Some(r"C:\Users\a\AppData\Roaming\d.exe"),
            Some(r"C:\Users\a\AppData\Roaming\d.exe"), Some(false), None);
        assert_eq!(evaluate_gate(&evil, now).iter().map(|h| h.severity).max(), Some(Severity::High));
        let procexp = full_rec("ifeo", Some("Debugger"), Some(r"C:\Program Files\SysInternals\procexp.exe"),
            Some(r"C:\Program Files\SysInternals\procexp.exe"), Some(true), None);
        let hits = evaluate_gate(&procexp, now);
        assert_eq!(hits.len(), 1, "IFEO always gates");
        assert_eq!(hits[0].severity, Severity::Medium, "signed vendor target -> Medium");
    }

    #[test]
    fn gate_s2_unsigned_dropzone_high_but_signed_or_normal_path_silent() {
        let now = Utc::now();
        let evil = full_rec("run_key", Some("Upd"), Some(r"C:\Users\a\AppData\Roaming\e.exe"),
            Some(r"C:\Users\a\AppData\Roaming\e.exe"), Some(false), None);
        assert_eq!(evaluate_gate(&evil, now)[0].severity, Severity::High);
        // signed chrome autostart -> inventory
        let chrome = full_rec("run_key", Some("Chrome"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"), Some(true), Some(now));
        assert!(evaluate_gate(&chrome, now).is_empty());
        // unsigned but in Program Files (admin-write) -> not S2
        let pf = full_rec("run_key", Some("V"), Some(r"C:\Program Files\V\v.exe"),
            Some(r"C:\Program Files\V\v.exe"), Some(false), None);
        assert!(evaluate_gate(&pf, now).is_empty());
    }

    #[test]
    fn gate_s3_masquerade_absolute_only() {
        let now = Utc::now();
        let fake = full_rec("service", None, Some(r"C:\ProgramData\svchost.exe"),
            Some(r"C:\ProgramData\svchost.exe"), None, None);
        assert!(evaluate_gate(&fake, now).iter().any(|h| h.mitre == "T1036.005"));
        let bare = full_rec("winlogon", Some("Shell"), Some("explorer.exe"), Some("explorer.exe"),
            None, None);
        // bare name: winlogon default -> no S1a; not absolute -> no S3
        assert!(evaluate_gate(&bare, now).is_empty());
    }

    #[test]
    fn gate_s4_needs_all_three_conditions() {
        let now = Utc::now();
        let recent = Some(now - Duration::days(2));
        let hit = full_rec("service", None, Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"), None, recent);
        assert_eq!(evaluate_gate(&hit, now)[0].severity, Severity::Medium);
        // signed -> no S4 (ASUS update-day services)
        let signed = full_rec("service", None, Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"), Some(true), recent);
        assert!(evaluate_gate(&signed, now).is_empty());
        // system path -> no S4 (per-user svchost instances)
        let sys = full_rec("service", None, Some(r"C:\Windows\System32\svchost.exe -k X"),
            Some(r"C:\Windows\System32\svchost.exe"), None, recent);
        assert!(evaluate_gate(&sys, now).is_empty());
        // old -> no S4
        let old = full_rec("service", None, Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"), None, Some(now - Duration::days(300)));
        assert!(evaluate_gate(&old, now).is_empty());
    }

    #[test]
    fn gate_s9_script_persistence_tiers() {
        let now = Utc::now();
        let enc = full_rec("run_key", Some("U"),
            Some("powershell.exe -NoP -Enc SQBFAFgA"), None, None, None);
        let h = evaluate_gate(&enc, now);
        assert_eq!(h[0].severity, Severity::High);
        let remote = full_rec("run_key", Some("U"),
            Some(r"mshta.exe https://evil.tld/x.hta"), None, None, None);
        assert_eq!(evaluate_gate(&remote, now)[0].severity, Severity::High);
        let local = full_rec("scheduled_task", None,
            Some(r"wscript.exe C:\Scripts\backup.vbs"), Some(r"C:\Windows\System32\wscript.exe"),
            Some(true), None);
        assert_eq!(evaluate_gate(&local, now)[0].severity, Severity::Low);
        // interpreter-in-vendor-name must NOT fire (substring guard)
        let studio = full_rec("run_key", Some("PS"),
            Some(r"C:\Program Files\PowerShell Studio\app.exe --serve"),
            Some(r"C:\Program Files\PowerShell Studio\app.exe"), Some(true), None);
        assert!(evaluate_gate(&studio, now).is_empty());
    }

    #[test]
    fn gate_service_and_runkey_existence_is_inventory() {
        let now = Utc::now();
        // The 25-Low class from the 2026-06-28 run: plain third-party service.
        let svc = full_rec("service", None, Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"), Some(true), Some(now - Duration::days(400)));
        assert!(evaluate_gate(&svc, now).is_empty());
        // The 13-Medium class: same service on update day (recent) — still inventory.
        let svc_recent = full_rec("service", None, Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"), Some(true), Some(now - Duration::days(2)));
        assert!(evaluate_gate(&svc_recent, now).is_empty());
    }

    #[test]
    fn escalate_caps_at_critical() {
        assert_eq!(escalate(Severity::Low), Severity::Medium);
        assert_eq!(escalate(Severity::Medium), Severity::High);
        assert_eq!(escalate(Severity::High), Severity::Critical);
        assert_eq!(escalate(Severity::Critical), Severity::Critical);
    }
```

注意：`gate_s1a` 測試裡 mitre 斷言直接寫 `assert_eq!(hits[0].mitre, "T1547.004");`
（上面 replace 寫法是示意錯誤，實作時用字面值）。

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test -p cairn-heur persist::` → 舊測試 + 8 個新 gate 測試全綠（舊 score 邏輯還在，未接線）。

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): persist dispositive-signal gate (S1a/S1b/S2/S3/S4/S9) — pure fns, not wired"
```

---

### Task 6: persist analyze()/observe() 重寫 — gate 接線、交叉比對、輸出格式、舊模型移除

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: use 區補**

```rust
use cairn_core::finding::EvidenceItem;
use cairn_core::observation::Observation;
use cairn_core::record::{ExecutionRecord, ProcessRecord};
use std::collections::HashMap;
```

- [ ] **Step 2: 加交叉比對 helper（normalized_basename 自 correlation.rs 移植）**

```rust
/// Lowercased basename with a trailing ".exe" stripped — the cross-artifact join key.
/// (Moved from the retired CorrelationAnalyzer.)
fn normalized_basename(path: &str) -> String {
    let base = path
        .trim()
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    base.strip_suffix(".exe").map(String::from).unwrap_or(base)
}

/// Index execution + process records by normalized basename for corroboration lookups.
struct CrossIndex<'a> {
    exec: HashMap<String, Vec<&'a ExecutionRecord>>,
    proc: HashMap<String, Vec<&'a ProcessRecord>>,
}

fn build_cross_index(records: &[Record]) -> CrossIndex<'_> {
    let mut exec: HashMap<String, Vec<&ExecutionRecord>> = HashMap::new();
    let mut proc: HashMap<String, Vec<&ProcessRecord>> = HashMap::new();
    for r in records {
        match r {
            Record::Execution(e) => {
                let k = normalized_basename(&e.path);
                if !k.is_empty() {
                    exec.entry(k).or_default().push(e);
                }
            }
            Record::Process(p) => {
                let k = normalized_basename(&p.image);
                if !k.is_empty() {
                    proc.entry(k).or_default().push(p);
                }
            }
            _ => {}
        }
    }
    CrossIndex { exec, proc }
}
```

- [ ] **Step 3: 加 Finding 組裝 helpers（輸出格式規範 spec §7.2）**

```rust
/// details starts with the FULL PATH (the investigator's first question), single line,
/// " | " separated — CSV-safe, readable without expanding the HTML row (spec §7.2).
fn gate_details(p: &PersistenceRecord) -> String {
    let path = p
        .binary_path
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&p.location);
    let sig = match p.signed {
        Some(true) => match p.signer.as_deref() {
            Some(s) => format!("已簽章 ({s})"),
            None => "已簽章".into(),
        },
        Some(false) => "未簽章".into(),
        None => "簽章無法驗證".into(),
    };
    let lw = p
        .last_write
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".into());
    format!(
        "{path} | {mech}: {loc}{val} | {sig} | last_write={lw}",
        mech = p.mechanism,
        loc = p.location,
        val = p
            .value
            .as_deref()
            .map(|v| format!(" → {v}"))
            .unwrap_or_default(),
    )
}

/// Evidence for the persistence entry itself.
fn persistence_evidence(p: &PersistenceRecord) -> EvidenceItem {
    EvidenceItem {
        artifact: p.mechanism.clone(),
        path: p.binary_path.clone(),
        ts: p.last_write,
        detail: format!(
            "{}: {} = {}",
            p.location,
            p.value.as_deref().unwrap_or("-"),
            p.command.as_deref().unwrap_or("-")
        ),
    }
}

/// Evidence rows from execution artifacts (honest about prefetch's filename-only path).
fn execution_evidence(entries: &[&ExecutionRecord]) -> Vec<EvidenceItem> {
    entries
        .iter()
        .map(|e| {
            let mut detail = format!(
                "{}: run_count={} last_run={}",
                e.source,
                e.run_count.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                e.last_run
                    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| "unknown".into()),
            );
            if e.source == "prefetch" {
                detail.push_str("（prefetch 僅記錄檔名，完整路徑見 shimcache/amcache 條目）");
            }
            EvidenceItem {
                artifact: e.source.clone(),
                path: Some(e.path.clone()),
                ts: e.last_run.or(e.first_run),
                detail,
            }
        })
        .collect()
}
```

- [ ] **Step 4: 重寫 `impl Analyzer for PersistHeuristic`（取代整個舊 analyze；加 observe）**

```rust
impl Analyzer for PersistHeuristic {
    fn name(&self) -> &str {
        "heur_persist"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let idx = build_cross_index(records);
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            let hits = evaluate_gate(p, now);
            if hits.is_empty() {
                continue; // inventory — surfaces via observe()
            }

            // Severity: max of hits; >=2 signals escalate once; execution/process
            // corroboration escalates once more (spec §4.1/§4.3). Cap: Critical.
            let mut sev = hits.iter().map(|h| h.severity).max().unwrap_or(Severity::Low);
            let mut reasons: Vec<String> = hits.iter().map(|h| h.reason.clone()).collect();
            if hits.len() >= 2 {
                sev = escalate(sev);
                reasons.push(format!("{} independent signals — escalated", hits.len()));
            }

            let key = normalized_basename(
                p.binary_path.as_deref().or(p.command.as_deref()).unwrap_or(""),
            );
            let mut evidence = vec![persistence_evidence(p)];
            let exec_hits = idx.exec.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            let proc_hits = idx.proc.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            if !exec_hits.is_empty() || !proc_hits.is_empty() {
                sev = escalate(sev);
                let mut corr = Vec::new();
                if !exec_hits.is_empty() {
                    corr.push(format!("executed ({} artifact records)", exec_hits.len()));
                    evidence.extend(execution_evidence(exec_hits));
                }
                for pr in proc_hits {
                    corr.push(format!("currently running (pid={})", pr.pid));
                    evidence.push(EvidenceItem {
                        artifact: "process".into(),
                        path: Some(pr.image.clone()),
                        ts: pr.start_time,
                        detail: format!("running pid={} image={}", pr.pid, pr.image),
                    });
                }
                reasons.push(format!("corroborated: {} — escalated", corr.join("; ")));
            }

            let top = hits
                .iter()
                .max_by_key(|h| h.severity as i32 * -1) // Severity derives Ord? see note below
                .unwrap_or(&hits[0]);
            let short = short_name_persist(
                p.binary_path.as_deref().or(p.command.as_deref()).unwrap_or(&p.location),
            );
            let mut f = Finding::new(sev, format!("{}: {short}", top.label), FindingSource::Heuristic);
            f.reason = Some(reasons.join("; "));
            f.mitre = {
                let mut m: Vec<String> = hits.iter().map(|h| h.mitre.to_string()).collect();
                m.dedup();
                m
            };
            f.artifact = "persistence".into();
            f.details = gate_details(p);
            f.ts = p.last_write.unwrap_or(now);
            f.entity = persistence_entity(p);
            f.evidence = evidence;
            out.push(f);
        }
        Ok(out)
    }

    fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> {
        let now = Utc::now();
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            if !evaluate_gate(p, now).is_empty() {
                continue; // gated items are findings, not inventory
            }
            let category = if p.mechanism == "winlogon" {
                "winlogon_default".to_string()
            } else {
                p.mechanism.clone()
            };
            let short = short_name_persist(
                p.binary_path.as_deref().or(p.command.as_deref()).unwrap_or(&p.location),
            );
            let mut o = Observation::new(category, format!("{}: {short}", p.mechanism));
            o.ts = p.last_write.unwrap_or(now);
            o.path = p.binary_path.clone();
            o.details = gate_details(p);
            o.source_artifact = "persistence".into();
            out.push(o);
        }
        Ok(out)
    }
}
```

**實作注意（top-hit 選取）**：`Severity` 未必 derive `Ord`。用明確映射取代上面示意的
`max_by_key`：

```rust
fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}
// let top = hits.iter().max_by_key(|h| sev_rank(h.severity)).unwrap();
// let mut sev = hits.iter().map(|h| h.severity).max_by_key(|s| sev_rank(*s)).unwrap();
```

（`sev_rank` 放 persist.rs 私有；analyze 內兩處 max 都用它。）

- [ ] **Step 5: 刪除舊 weight 模型**

- 刪 `score_persistence` 全函式與其 import 的 `Score`/`severity_for`（若 persist.rs 只剩 gate 用不到）。
- 刪 tests mod 中所有斷言 `s.weight` / 呼叫 `score_persistence` 的測試
  （`ifeo_in_temp_scores_critical`、`recency_window_boundary`、`old_run_key_program_files_is_quiet`、
  `winlogon_*`、`unsigned_*`、`signed_*`、`inbox_*`、`driverstore_*`、`scheduled_task_*`、
  `startup_*`、`missing_fields_still_score_mechanism`、`unknown_mechanism_scores_zero` 等
  ——凡引用 score_persistence 者全刪；`is_inbox_service_command` 相關測試在 score.rs，不動）。
- `RECENT_DAYS`、`short_name_persist`、`format_persist_details`、`persistence_entity`、`hive_prefix` 保留
  （`format_persist_details` 若已無 caller 則刪除連同其測試）。
- 移除 Task 5 掛的所有 `#[allow(dead_code)]`。

- [ ] **Step 6: 加 analyze/observe 整合測試**

```rust
    fn wrap(p: PersistenceRecord) -> Record {
        Record::Persistence(p)
    }

    #[test]
    fn analyze_emits_only_gated_and_observe_gets_the_rest() {
        let now = Utc::now();
        let records = vec![
            wrap(full_rec("run_key", Some("Upd"), Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"), Some(false), Some(now))),
            wrap(full_rec("service", None, Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
                Some(r"C:\Program Files\ASUS\AsusAppService.exe"), Some(true), Some(now))),
        ];
        let findings = PersistHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1, "only the S2 hit is a finding");
        assert_eq!(findings[0].severity, Severity::High);
        let obs = PersistHeuristic.observe(&records).unwrap();
        assert_eq!(obs.len(), 1, "the clean service is inventory");
        assert_eq!(obs[0].category, "service");
    }

    #[test]
    fn execution_corroboration_escalates_and_adds_evidence() {
        use cairn_core::record::ExecutionRecord;
        let now = Utc::now();
        let records = vec![
            wrap(full_rec("run_key", Some("U"), Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"), Some(false), Some(now))),
            Record::Execution(ExecutionRecord {
                source: "prefetch".into(),
                path: "E.EXE".into(),
                first_run: None,
                last_run: Some(now),
                run_count: Some(3),
                sha1: None,
                user_sid: None,
                execution_confirmed: Some(true),
            }),
        ];
        let findings = PersistHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical, "S2 High + exec corroboration");
        assert!(findings[0].evidence.iter().any(|e| e.artifact == "prefetch"));
        assert!(findings[0].evidence.iter().any(|e| e.artifact == "run_key"));
        assert!(findings[0].reason.as_deref().unwrap().contains("corroborated"));
    }

    #[test]
    fn details_starts_with_full_path_and_title_names_binary() {
        let now = Utc::now();
        let records = vec![wrap(full_rec("run_key", Some("U"),
            Some(r"C:\Users\a\AppData\Roaming\evil.exe"),
            Some(r"C:\Users\a\AppData\Roaming\evil.exe"), Some(false), Some(now)))];
        let f = &PersistHeuristic.analyze(&records).unwrap()[0];
        assert!(f.details.starts_with(r"C:\Users\a\AppData\Roaming\evil.exe |"),
            "details must lead with the path: {}", f.details);
        assert!(f.title.contains("evil.exe"), "title: {}", f.title);
    }

    #[test]
    fn winlogon_default_is_observation_with_category() {
        let now = Utc::now();
        let records = vec![wrap(full_rec("winlogon", Some("Shell"), Some("explorer.exe"),
            Some(r"C:\Windows\explorer.exe"), Some(true), Some(now)))];
        assert!(PersistHeuristic.analyze(&records).unwrap().is_empty());
        let obs = PersistHeuristic.observe(&records).unwrap();
        assert_eq!(obs[0].category, "winlogon_default");
    }
```

- [ ] **Step 7: 跑測試 + commit**

Run: `cargo test -p cairn-heur persist::` → gate 測試 + 4 整合測試全綠。
Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): wire persist gate — analyze/observe split, cross-artifact corroboration, path-first output"
```

---

### Task 7: 刪除 CorrelationAnalyzer + 全接線清理

**Files:**
- Delete: `crates/cairn-heur/src/correlation.rs`
- Modify: `crates/cairn-heur/src/lib.rs`、`crates/cairn-cli/src/main.rs`、
  `crates/cairn-report/src/client_text.rs`

- [ ] **Step 1: `git rm crates/cairn-heur/src/correlation.rs`**

- [ ] **Step 2: `lib.rs` 移除 `pub mod correlation;` 與 `pub use correlation::CorrelationAnalyzer;`**

- [ ] **Step 3: `main.rs` 兩處 analyzers vec（~855 行與 ~1231 行測試）移除
  `Box::new(cairn_heur::CorrelationAnalyzer),`；測試 `live_analyzers_include_all_heuristics`
  移除 `heur_correlation` 斷言，保留其餘。**

- [ ] **Step 4: `client_text.rs` 移除 `"correlation" => correlation_client_text(&host, f),`
  arm、`correlation_client_text` 函式、與其測試區（`// ── correlation:` 區塊）。
  unknown artifact 的 fallback arm 已涵蓋舊資料。**

- [ ] **Step 5: 全 workspace 驗證 + commit**

Run: `cargo test --workspace --exclude cairn-updater` → 全綠。
Run: `cargo clippy --workspace --all-targets -- -D warnings` → 零警告。

```bash
git add -A
git commit -m "refactor(heur): retire CorrelationAnalyzer — cross-artifact corroboration lives in the persist gate"
```

---

### Task 8: account + timestomp findings 補 evidence

**Files:**
- Modify: `crates/cairn-heur/src/account.rs`、`crates/cairn-heur/src/timestomp.rs`

- [ ] **Step 1: account.rs — `AccountEvent` 加 `event_id: u32` 欄位（parse_account_event 各 arm 填
  `event_id: ev.event_id`），analyze 的 Finding 組裝（`f.reason = Some(reason);` 之後）加：**

```rust
            f.evidence = vec![cairn_core::finding::EvidenceItem {
                artifact: "evtx:Security".into(),
                path: None,
                ts: Some(ae.ts),
                detail: format!(
                    "EID {}: target={} subject={}{}",
                    ae.event_id,
                    ae.target,
                    ae.subject,
                    ae.group.as_deref().map(|g| format!(" group={g}")).unwrap_or_default()
                ),
            }];
```

測試加：

```rust
    #[test]
    fn account_finding_carries_evtx_evidence() {
        let records = vec![make_event(4720, "Security", recent(), account_data("u", "admin"))];
        let f = &AccountHeuristic.analyze(&records).unwrap()[0];
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].artifact, "evtx:Security");
        assert!(f.evidence[0].detail.contains("EID 4720"));
    }
```

- [ ] **Step 2: timestomp.rs — Finding 組裝（`f.entity = ...` 之後）加：**

```rust
            f.evidence = vec![cairn_core::finding::EvidenceItem {
                artifact: "mft".into(),
                path: Some(m.path.clone()),
                ts: m.fn_btime.or(m.fn_mtime),
                detail: format!("$MFT SI/FN delta: {}", axes_detail(&hit)),
            }];
```

測試（沿用該檔既有 fixture helper 產生一個會 fire 的 FileMetaRecord）：

```rust
    #[test]
    fn timestomp_finding_carries_mft_evidence() {
        // reuse the existing fired-hit fixture from this test mod
        let records = vec![/* 既有測試中已知會 fire 的 Record::FileMeta fixture */];
        let f = &TimestompHeuristic.analyze(&records).unwrap()[0];
        assert_eq!(f.evidence[0].artifact, "mft");
        assert!(f.evidence[0].path.is_some());
    }
```

（實作者：複製該檔既有正向測試的 fixture 建構，勿新造格式。）

- [ ] **Step 3: 跑測試 + commit**

Run: `cargo test -p cairn-heur` → 全綠。

```bash
git add crates/cairn-heur/src/account.rs crates/cairn-heur/src/timestomp.rs
git commit -m "feat(heur): account + timestomp findings carry structured evidence"
```

---

### Task 9: netconn gate floor + parentchild amplifier 化 + S3 process 偽裝

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs`、`crates/cairn-heur/src/parentchild.rs`

- [ ] **Step 1: netconn.rs — analyze 的 severity 判定前加 gate floor**

```rust
/// Gate floor (spec §4.2 S7): single weak signals (rare port 20, public+rare 45,
/// suspicious-path owner 30) are inventory-grade and never emit alone; a finding
/// requires a corroborated combo (e.g. public+rare+unsigned = 65).
const NETCONN_GATE_FLOOR: u32 = 50;
```

analyze 內 `let Some(severity) = severity_for(score.weight) else { continue };` 改為：

```rust
            if score.weight < NETCONN_GATE_FLOOR {
                continue;
            }
            let Some(severity) = severity_for(score.weight) else {
                continue;
            };
```

- [ ] **Step 2: netconn 測試調整**

- `private_ip_rare_port_fires_rare_port_only`：改斷言 analyze 產出為空
  （score 仍可斷言 weight==20，finding 不再產生）。改名
  `private_ip_rare_port_below_gate_floor_no_finding`。
- `public_ip_with_rport_zero_does_not_fire`、`signed_browser_https_scores_below_floor`、
  `own_pid_netconn_not_flagged`：不變。
- `unsigned_temp_to_public_rare_port_scores_high`：權重不變（25+20+30+20=95→Critical band），
  若原斷言 High 改斷言 `>= Severity::High` 或精確 Critical（以 sev_rank 比較或直接 eq）。
- 新增正向：

```rust
    #[test]
    fn public_rare_plus_unsigned_owner_clears_gate() {
        // 25 (public+rare) + 20 (rare port) + 20 (unsigned amplifier) = 65 -> High
        // build conn to 203.0.113.9:4444 with unsigned owner at a normal path
    }
    #[test]
    fn public_rare_alone_is_dropped_by_gate() {
        // 45 < 50 -> analyze yields no finding for a signed browser-ish owner
    }
```

（兩測試用該檔既有 conn/proc fixture helper 組裝；斷言 analyze().len()。）

- [ ] **Step 3: parentchild.rs — score_process 兩處修改**

(a) 檔頭 `use crate::trust::is_masquerade;`。suspicious-path 區塊**移到**組合信號之後、
unsigned amplifier 之前，並改為 amplifier：

```rust
    // Suspicious path is an AMPLIFIER (spec §4.2 S8): alone it matches every
    // per-user app (chrome-native-host in \AppData\) — zero information. It adds
    // weight only when a behavioral combo already fired.
    let combo_fired = !s.reasons.is_empty();
    if combo_fired && is_suspicious_path(&p.image) {
        s.add(
            25,
            format!("executes from a suspicious path: {}", p.image),
            &["T1036"],
        );
    }
```

(b) 同函式開頭（Office/script 組合之前）加 S3：

```rust
    // S3 masquerade (spec §4.2): a protected system name outside C:\Windows is
    // dispositive on its own — no clean machine has an AppData svchost.exe.
    if is_masquerade(&p.image) {
        s.add(
            60,
            format!("system binary name outside C:\\Windows: {}", p.image),
            &["T1036.005"],
        );
    }
```

- [ ] **Step 4: parentchild 測試調整 + 新增**

- `other_pid_suspicious_path_still_flagged`（path 單獨 25 → 曾 Low）：改斷言 analyze 為空，
  改名 `suspicious_path_alone_is_not_a_finding`。
- `unsigned_from_temp_no_parent_scores`：原依 path(25)+unsigned(20)；新模型 path 不先 fire
  → unsigned 也不 fire → weight 0。改斷言 0 並改名 `unsigned_temp_alone_gated_out`。
- 其餘組合測試（office/encoded/lolbas）不變——組合先 fire，path/unsigned amplifier 語義不變。
- 新增：

```rust
    #[test]
    fn masquerade_svchost_in_appdata_fires_high_alone() {
        // proc fixture: image = C:\Users\a\AppData\Roaming\svchost.exe, no parent
        // assert one finding, severity >= High, mitre contains T1036.005
    }
    #[test]
    fn real_svchost_in_system32_does_not_fire() {
        // image = C:\Windows\System32\svchost.exe -> analyze empty
    }
```

（用該檔既有 proc fixture helper 寫全；60 權重單獨 = High band 50..=69。）

- [ ] **Step 5: 跑測試 + commit**

Run: `cargo test -p cairn-heur` → 全綠。
Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`

```bash
git add crates/cairn-heur/src/netconn.rs crates/cairn-heur/src/parentchild.rs
git commit -m "feat(heur): netconn gate floor + parentchild path-as-amplifier + S3 masquerade signal"
```

---

### Task 10: cairn-report — observations.jsonl、HTML 盤點區塊、evidence 顯示

**Files:**
- Modify: `crates/cairn-report/src/lib.rs`、`zip_sink.rs`、`age_sink.rs`、`html.rs`

- [ ] **Step 1: lib.rs 加序列化函式 + DirSink 實作**

```rust
/// Serialize observations to JSONL (one Observation per line).
pub fn observations_jsonl(observations: &[cairn_core::Observation]) -> Result<String> {
    let mut buf = String::new();
    for o in observations {
        buf.push_str(&serde_json::to_string(o)?);
        buf.push('\n');
    }
    Ok(buf)
}
```

DirSink 的 `impl OutputSink`（`write_findings_jsonl` 後）加：

```rust
    fn write_observations(&mut self, observations: &[cairn_core::Observation]) -> Result<()> {
        let buf = crate::observations_jsonl(observations)?;
        self.write_file("observations.jsonl", buf.as_bytes())
    }
```

- [ ] **Step 2: zip_sink.rs / age_sink.rs 各加（仿各自 write_findings_jsonl 的 buffer 模式）**

```rust
    fn write_observations(&mut self, observations: &[Observation]) -> Result<()> {
        let buf = crate::observations_jsonl(observations)?;
        self.files.push(("observations.jsonl".into(), buf.into_bytes()));
        Ok(())
    }
```

（兩檔 use 區補 `cairn_core::Observation`；DryRunSink 靠 trait default no-op，不動。）

- [ ] **Step 3: html.rs — `html_report` 簽名加 observations 參數**

```rust
pub fn html_report(
    findings: &[Finding],
    observations: &[cairn_core::Observation],
    manifest: &Manifest,
) -> String {
```

DirSink::write_html_report 改傳 `observations`（Task 2 已把參數帶進來，去掉底線）。

- [ ] **Step 4: html.rs — findings 表格列加 evidence 巢狀顯示**

在產出每列 finding row 的迴圈中，details 欄後追加（有 evidence 才產生）：

```rust
            let ev_html = if f.evidence.is_empty() {
                String::new()
            } else {
                let items: String = f
                    .evidence
                    .iter()
                    .map(|e| {
                        format!(
                            "<li><b>{}</b> {} {}<br>{}</li>",
                            esc(&e.artifact),
                            e.path.as_deref().map(esc).unwrap_or_default(),
                            e.ts.map(|t| t.format("%Y-%m-%d %H:%MZ").to_string()).unwrap_or_default(),
                            esc(&e.detail),
                        )
                    })
                    .collect();
                format!(
                    "<details><summary>佐證來源 ({})</summary><ul>{}</ul></details>",
                    f.evidence.len(),
                    items
                )
            };
```

`ev_html` 插入該列 details 儲存格內容之後。

- [ ] **Step 5: html.rs — findings 表格之後、footer 之前加盤點折疊區塊**

```rust
    // Host inventory (observations) — collapsed by default, grouped by category.
    let mut obs_html = String::new();
    if !observations.is_empty() {
        use std::collections::BTreeMap;
        let mut by_cat: BTreeMap<&str, Vec<&cairn_core::Observation>> = BTreeMap::new();
        for o in observations {
            by_cat.entry(o.category.as_str()).or_default().push(o);
        }
        let mut groups = String::new();
        for (cat, items) in &by_cat {
            let rows: String = items
                .iter()
                .map(|o| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        esc(&o.title),
                        o.path.as_deref().map(esc).unwrap_or_default(),
                        esc(&o.details),
                    )
                })
                .collect();
            groups.push_str(&format!(
                "<h3>{} ({})</h3><table><tr><th>項目</th><th>路徑</th><th>詳細</th></tr>{}</table>",
                esc(cat),
                items.len(),
                rows
            ));
        }
        obs_html = format!(
            "<details class=\"inventory\"><summary><h2 style=\"display:inline\">主機盤點 Host Inventory ({} 項)</h2></summary>{}</details>",
            observations.len(),
            groups
        );
    }
```

並在最終 HTML 模板串接處（findings table 之後）插入 `{obs_html}`。

- [ ] **Step 6: 測試**

```rust
    #[test]
    fn observations_jsonl_one_line_each() {
        let mut o = cairn_core::Observation::new("service", "服務 X → x.exe");
        o.source_artifact = "persistence".into();
        let s = observations_jsonl(&[o.clone(), o]).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.contains("cairn.observation/1"));
    }

    #[test]
    fn dirsink_writes_observations_jsonl_with_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = DirSink::new(dir.path());
        let o = cairn_core::Observation::new("run_key", "run_key: chrome.exe");
        sink.write_observations(&[o]).unwrap();
        assert!(dir.path().join("observations.jsonl").exists());
        assert!(sink.outputs_so_far().iter().any(|e| e.file == "observations.jsonl"));
    }
```

html 測試（該檔既有測試風格）：

```rust
    #[test]
    fn html_contains_inventory_block_and_evidence_details() {
        // one finding with one EvidenceItem + one observation; assert output contains
        // "主機盤點", "佐證來源 (1)", and the escaped path string.
    }
```

（實作者用該檔既有的 finding/manifest fixture helper 填肉。）

- [ ] **Step 7: 跑測試 + commit**

Run: `cargo test -p cairn-report` → 全綠。

```bash
git add crates/cairn-report/
git commit -m "feat(report): observations.jsonl (Dir/Zip/Age sinks) + HTML inventory block + evidence rendering"
```

---

### Task 11: cli 接線收尾 + 全面驗收（真機 e2e 門檻）

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`
- Modify: `docs/REMAINING-WORK.md`

- [ ] **Step 1: live 路徑（~937 行區）補 observations 處理——host 蓋章、確定性排序、寫出**

在 findings host 蓋章附近加：

```rust
            for o in &mut outcome.observations {
                o.host = manifest.host.hostname.clone();
            }
            outcome
                .observations
                .sort_by(|a, b| (a.category.as_str(), a.title.as_str())
                    .cmp(&(b.category.as_str(), b.title.as_str())));
```

寫出順序：`write_timeline_csv` → `write_findings_jsonl` →
`sink.write_observations(&outcome.observations)?;` → `write_html_report(...)` → manifest。
（Task 2 已把 counts.observations 與 write_html_report 參數接好；此處確認 live 路徑
傳的是 `&outcome.observations` 而非 `&[]`。）

- [ ] **Step 2: evtx 路徑維持 `&[]` observations（無 analyzer inventory）、counts.observations=0 已於 Task 2 完成——驗證即可。**

- [ ] **Step 3: 全 workspace 驗證**

```powershell
cargo test --workspace            # cairn-updater 若非 admin shell 屬既知例外
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: 全綠、零警告。

- [ ] **Step 4: 真機 e2e 驗收（spec §2 門檻）**

```powershell
cargo build --release -p cairn-cli
Copy-Item "$env:CARGO_TARGET_DIR\release\cairn.exe" .\dist\cairn-forensics\cairn.exe -Force
.\dist\cairn-forensics\cairn.exe run --target live --output .\out-gate-acceptance\
```

驗收斷言（人工或以 python 一行檢查 findings.jsonl）：
1. `findings.jsonl`：severity high/critical = **0**、medium = **0**、low **< 5**。
2. `observations.jsonl` 存在且 ≥ 40 行（原 60 個誤報的盤點面），含 category=service/run_key/winlogon_default。
3. `report.html` 有「主機盤點」折疊區塊；任一 finding（若有）details 以完整路徑開頭。
4. `manifest.json` 的 `counts.observations` 與 jsonl 行數一致。

若 Low ≥ 5：檢視內容——若為真實邊緣（S9 本機腳本排程等）記錄於 REMAINING-WORK
殘留風險；若為新誤報類型，回 Task 5 調 gate 條件後重驗。

- [ ] **Step 5: 更新 `docs/REMAINING-WORK.md`——待辦 A（evidence）標記完成、
  heuristic gate 重設計入已完成表、待辦 C（correlation 時間標注）標記「已被 gate 模型涵蓋
  （S4 recency 條件 + observation details 帶 last_write），關閉」。**

- [ ] **Step 6: 最終 commit**

```bash
git add -A
git commit -m "feat: heuristic gate redesign complete — clean-machine High/Medium=0, inventory to observations.jsonl

Spec: docs/dev-history/specs/2026-07-02-heuristic-gate-redesign-design.md"
```

---

## Self-Review 紀錄（plan 完成後自查）

1. **Spec 覆蓋**：§4 gate/信號（Task 5/6/9）、§4.3 correlation 併入（Task 6/7）、
   §5 signed 修正（Task 4 + gate None 中性化 in Task 5）、§5b trust 集中（Task 3）、
   §6 Observation（Task 2/6/10/11）、§7 evidence + 輸出格式（Task 1/6/8/10）、
   §2 驗收（Task 11）。無缺口。
2. **Placeholder**：Task 8 timestomp 測試 fixture、Task 9/10 部分測試以「沿用該檔既有
   fixture helper」指示——fixture 建構屬檔內既有模式的機械複用，語義已完整指定，接受。
3. **型別一致**：EvidenceItem/Observation/GateHit/escalate/sev_rank/normalized_basename
   /observations_jsonl 各 task 引用名一致；write_html_report 三參數簽名 Task 2 定、
   Task 10 實作對齊。
