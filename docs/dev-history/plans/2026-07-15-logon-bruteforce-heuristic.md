# 段 4-塊C：登入爆破偵測 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新建 `crates/cairn-heur/src/logon_bruteforce.rs`，偵測兩種登入爆破模式——單帳號多來源爆破、單來源多帳號 password spraying——並接線進 live 分析器清單。

**Architecture:** 新 `Analyzer` 實作直接掃描 `Record::Event`（channel=Security, event_id ∈ {4624,4625}），依兩組獨立分組鍵（帳號爆破用 `(TargetUserName, IpAddress)`；spraying 用 `IpAddress`）分桶、時間窗內計數觸發 Finding。閾值仿照既有 `TimestompHeuristic` 的模式：`Config` 新增 4 個欄位（有 default，無 CLI flag），analyzer 建構子接收閾值。

**Tech Stack:** Rust、`cairn-core::{Record, EventRecord, Finding, Analyzer}`、`chrono::{DateTime, Duration, Utc}`（workspace 依賴，`cairn-heur` 已有）。

---

## 前置事實（來自探查，任務執行時不需重查）

- **`EventRecord`**（`crates/cairn-core/src/record.rs:24-33`）：
  ```rust
  pub struct EventRecord {
      pub ts: DateTime<Utc>,
      pub channel: String,
      pub event_id: u32,
      pub provider: String,
      pub computer: String,
      pub record_id: u64,
      pub data: serde_json::Map<String, serde_json::Value>,
  }
  ```
  `Record::Event(EventRecord)` 是要比對的變體。取欄位值用 `account.rs` 既有的 `extract_str` pattern：
  ```rust
  fn extract_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
      data.get(key)
          .and_then(|v| v.as_str())
          .unwrap_or("-")
          .to_string()
  }
  ```
  4624/4625 常見欄位：`TargetUserName`、`IpAddress`、`WorkstationName`。`extract_str` 回傳 `"-"` 代表欄位缺失（不是 panic，graceful degrade）。

- **`Finding` / `Severity` / `FindingSource` / `EvidenceItem`**（`crates/cairn-core/src/finding.rs`）：
  ```rust
  pub enum Severity { Critical, High, Medium, Low, Info }
  pub enum FindingSource { Sigma, Heuristic }
  pub struct EvidenceItem {
      pub artifact: String,
      pub path: Option<String>,
      pub ts: Option<DateTime<Utc>>,
      pub detail: String,
  }
  pub fn Finding::new(severity: Severity, title: impl Into<String>, source: FindingSource) -> Self
  ```
  建構後另行賦值：`f.ts`、`f.artifact`、`f.mitre: Vec<String>`、`f.details: String`、`f.reason: Option<String>`、`f.evidence: Vec<EvidenceItem>`。`Entity` 沒有 logon 專屬子物件，本 heuristic **不填** `f.entity`（維持 `Entity::default()`），比照 `account.rs` 的做法，登入語意完全靠 `title`/`details`/`reason`/`evidence` 承載。

- **`Analyzer` trait**（`crates/cairn-core/src/traits.rs:43-64`）：
  ```rust
  pub trait Analyzer: Send + Sync {
      fn name(&self) -> &str;
      fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>>;
      fn observe(&self, _records: &[Record]) -> Result<Vec<Observation>> { Ok(vec![]) }
      fn depends_on(&self) -> &[&str] { &[] }
  }
  ```
  本 heuristic 不需要 `prior_findings`（用 `_prior_findings` 底線命名忽略），不覆寫 `depends_on()`/`observe()`。

- **`account.rs` 完整結構**（391行）是本次的直接範本——`parse_*_event` 純函式解析、`is_recent`/時間比對邏輯、`Finding` 組裝、`#[cfg(test)] mod tests` 用 `make_event` helper 建構 `Record::Event`。

- **`Config`**（`crates/cairn-core/src/config.rs:92-149`）新增閾值欄位仿照既有 `timestomp_threshold_hours`：
  ```rust
  /// Min FN−SI delta (hours), either axis, before a timestomp Finding fires (S2-N′).
  /// Below this, sub-day SI/FN drift from legit ops (unzip/copy/install) is ignored.
  /// Fixed default; no CLI flag — banding (Medium/High/Critical) carries severity.
  pub timestomp_threshold_hours: i64,
  ```
  這是「`Config` 欄位 + analyzer 建構子接收參數」模式的既有先例，`TimestompHeuristic::new(chrono::Duration::hours(cfg.timestomp_threshold_hours))` 是接線範例（`crates/cairn-cli/src/main.rs` 分析器清單裡）。

- **接線位置**：
  - `crates/cairn-heur/src/lib.rs`：加 `pub mod logon_bruteforce;` + `pub use logon_bruteforce::LogonBruteforceHeuristic;`
  - `crates/cairn-cli/src/main.rs` 的 live 分析器清單（兩處：實際執行路徑約 878-888 行、測試 `live_analyzers_include_all_heuristics` 約 1274-1283 行）都要加入新 analyzer 建構呼叫。

- **Synthetic integration test 範本**：`sigma_analyzer_findings_appear_in_live_outcome`（`crates/cairn-cli/src/main.rs:1576-1653`）——自訂 `Collector` 回傳固定 `Record` 陣列，透過 `run_live(&cfg, privs, hostname, &collectors, &analyzers)` 跑真正 pipeline，斷言 `outcome.findings` 內容。

- **`chrono` 依賴**：`cairn-heur/Cargo.toml` 已有 `chrono.workspace = true`（版本 0.4.45，含 serde feature），可直接 `use chrono::{DateTime, Duration, Utc};`。

- **CARGO_TARGET_DIR 與 linker**：`export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target`；本機 MSVC linker 路徑若自動偵測失效，額外設定
  `export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"`（已知本機環境限制，不寫進 `.cargo/config.toml`）。

- **測試分工**：Task 1-4 的 implementer 只跑 `cargo test -p cairn-heur`；Task 5（main.rs 接線）跨 crate 邊界，implementer 跑 `cargo test -p cairn-cli`；finishing 階段做一次全 workspace 驗證。

---

## Task 1: `Config` 新增四個閾值欄位

**Files:**
- Modify: `crates/cairn-core/src/config.rs`

- [ ] **Step 1: 讀取現有 `Config` struct 與 `Default` impl，在 `timestomp_threshold_hours` 欄位後插入四個新欄位**

在 `crates/cairn-core/src/config.rs` 的 `Config` struct 定義裡，`pub timestomp_threshold_hours: i64,` 這行後面新增：

```rust
    /// Time window (minutes) for grouping repeated failed logons (EID 4625) from the
    /// same (TargetUserName, IpAddress) pair before flagging bruteforce (segment 4-C).
    /// Fixed default; no CLI flag.
    pub logon_bruteforce_window_minutes: i64,
    /// Failure count within `logon_bruteforce_window_minutes` that triggers a
    /// bruteforce Finding for a single (TargetUserName, IpAddress) group.
    pub logon_bruteforce_threshold: u32,
    /// Time window (minutes) for grouping distinct-account logon attempts from the
    /// same source (IpAddress or WorkstationName) before flagging password spraying.
    /// Fixed default; no CLI flag.
    pub password_spraying_window_minutes: i64,
    /// Distinct TargetUserName count within `password_spraying_window_minutes` from
    /// the same source that triggers a spraying Finding.
    pub password_spraying_threshold: u32,
```

在 `impl Default for Config`，`timestomp_threshold_hours: 24,` 這行後面新增：

```rust
            logon_bruteforce_window_minutes: 5,
            logon_bruteforce_threshold: 5,
            password_spraying_window_minutes: 1,
            password_spraying_threshold: 10,
```

- [ ] **Step 2: 編譯確認欄位新增無誤**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check -p cairn-core
```

Expected: 編譯成功，無錯誤（`Config` 有其他建構呼叫點若用 struct-update 語法 `..Default::default()` 不受影響；若有任何地方手動列舉全部欄位建構 `Config`，會編譯失敗需要補上新欄位——若發生，補值為對應的 default 即可）。

- [ ] **Step 3: 跑 cairn-core 既有測試確認沒有破壞既有行為**

```bash
cargo test -p cairn-core
```

Expected: 全部通過。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-core/src/config.rs
git commit -m "feat(config): add logon bruteforce and password spraying thresholds"
```

---

## Task 2: `logon_bruteforce.rs` 核心邏輯（帳號爆破模式）

**Files:**
- Create: `crates/cairn-heur/src/logon_bruteforce.rs`

- [ ] **Step 1: 建立檔案骨架 + 解析函式 + 帳號爆破偵測邏輯**

```rust
#![forbid(unsafe_code)]

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

fn extract_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// A single parsed logon attempt (4624 success or 4625 failure).
#[derive(Debug, Clone)]
struct LogonAttempt {
    ts: DateTime<Utc>,
    target_user: String,
    /// IpAddress if present and not "-"; else WorkstationName if present and not "-";
    /// else "-" (both missing — attempt is still counted but cannot be grouped by
    /// source, so it will only ever land in a singleton group and never trigger).
    source: String,
    success: bool,
}

fn parse_logon_attempt(ev: &EventRecord) -> Option<LogonAttempt> {
    if ev.channel != "Security" {
        return None;
    }
    let success = match ev.event_id {
        4624 => true,
        4625 => false,
        _ => return None,
    };
    let d = &ev.data;
    let target_user = extract_str(d, "TargetUserName");
    let ip = extract_str(d, "IpAddress");
    let source = if ip != "-" {
        ip
    } else {
        extract_str(d, "WorkstationName")
    };
    Some(LogonAttempt {
        ts: ev.ts,
        target_user,
        source,
        success,
    })
}

/// Bruteforce group key: (TargetUserName, source). Groups repeated failures against
/// the same account from the same origin.
type BruteforceKey = (String, String);

/// Spraying group key: source only. Groups distinct-account attempts from one origin.
type SprayingKey = String;

fn group_by_bruteforce_key(attempts: &[LogonAttempt]) -> HashMap<BruteforceKey, Vec<&LogonAttempt>> {
    let mut groups: HashMap<BruteforceKey, Vec<&LogonAttempt>> = HashMap::new();
    for a in attempts {
        groups
            .entry((a.target_user.clone(), a.source.clone()))
            .or_default()
            .push(a);
    }
    groups
}

fn group_by_spraying_key(attempts: &[LogonAttempt]) -> HashMap<SprayingKey, Vec<&LogonAttempt>> {
    let mut groups: HashMap<SprayingKey, Vec<&LogonAttempt>> = HashMap::new();
    for a in attempts {
        groups.entry(a.source.clone()).or_default().push(a);
    }
    groups
}

/// Within `window`, find the max count of failures that share a window anchored at
/// any single failure's timestamp, and whether any success in that same window
/// exists (success anchors don't matter for the count, only for severity).
fn window_stats(attempts: &[&LogonAttempt], window: Duration) -> (u32, bool) {
    let mut max_failures = 0u32;
    let mut any_success_near_max = false;
    for anchor in attempts.iter().filter(|a| !a.success) {
        let window_end = anchor.ts + window;
        let in_window: Vec<&&LogonAttempt> = attempts
            .iter()
            .filter(|a| a.ts >= anchor.ts && a.ts <= window_end)
            .collect();
        let failures = in_window.iter().filter(|a| !a.success).count() as u32;
        let has_success = in_window.iter().any(|a| a.success);
        if failures > max_failures {
            max_failures = failures;
            any_success_near_max = has_success;
        } else if failures == max_failures && has_success {
            any_success_near_max = true;
        }
    }
    (max_failures, any_success_near_max)
}

pub struct LogonBruteforceHeuristic {
    bruteforce_window: Duration,
    bruteforce_threshold: u32,
    spraying_window: Duration,
    spraying_threshold: u32,
}

impl LogonBruteforceHeuristic {
    pub fn new(
        bruteforce_window: Duration,
        bruteforce_threshold: u32,
        spraying_window: Duration,
        spraying_threshold: u32,
    ) -> Self {
        LogonBruteforceHeuristic {
            bruteforce_window,
            bruteforce_threshold,
            spraying_window,
            spraying_threshold,
        }
    }

    fn analyze_bruteforce(&self, attempts: &[LogonAttempt]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let groups = group_by_bruteforce_key(attempts);
        for ((target_user, source), group) in groups {
            if source == "-" {
                continue;
            }
            let (max_failures, has_success) = window_stats(&group, self.bruteforce_window);
            if max_failures < self.bruteforce_threshold {
                continue;
            }
            let severity = if has_success { Severity::High } else { Severity::Medium };
            let title = format!("登入爆破: {target_user} ← {source}");
            let details = format!(
                "帳號 {target_user} 在 {} 分鐘內從來源 {source} 收到 {max_failures} 次失敗登入嘗試",
                self.bruteforce_window.num_minutes()
            );
            let reason = if has_success {
                format!(
                    "失敗次數 {max_failures} 達門檻 {}，且時間窗內出現成功登入——疑似爆破成功",
                    self.bruteforce_threshold
                )
            } else {
                format!(
                    "失敗次數 {max_failures} 達門檻 {}，時間窗內無成功登入接續",
                    self.bruteforce_threshold
                )
            };
            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = group.iter().map(|a| a.ts).max().unwrap_or_else(Utc::now);
            f.artifact = "logon_bruteforce".into();
            f.mitre = vec!["T1110.001".into()];
            f.user = Some(target_user.clone());
            f.details = details;
            f.reason = Some(reason);
            f.evidence = group
                .iter()
                .map(|a| EvidenceItem {
                    artifact: "evtx:Security".into(),
                    path: None,
                    ts: Some(a.ts),
                    detail: format!(
                        "{}: target={} source={}",
                        if a.success { "4624 success" } else { "4625 failure" },
                        a.target_user,
                        a.source
                    ),
                })
                .collect();
            findings.push(f);
        }
        findings
    }

    fn analyze_spraying(&self, attempts: &[LogonAttempt]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let groups = group_by_spraying_key(attempts);
        for (source, group) in groups {
            if source == "-" {
                continue;
            }
            // Distinct-account counting within the spraying window: anchor on every
            // attempt (not just failures — spraying signal is breadth, not failure
            // rate), find the window with the most distinct TargetUserName values.
            let mut max_distinct = 0u32;
            let mut any_success_near_max = false;
            let mut evidence_at_max: Vec<&LogonAttempt> = Vec::new();
            for anchor in &group {
                let window_end = anchor.ts + self.spraying_window;
                let in_window: Vec<&&LogonAttempt> = group
                    .iter()
                    .filter(|a| a.ts >= anchor.ts && a.ts <= window_end)
                    .collect();
                let distinct_users: std::collections::HashSet<&str> =
                    in_window.iter().map(|a| a.target_user.as_str()).collect();
                let count = distinct_users.len() as u32;
                if count > max_distinct {
                    max_distinct = count;
                    any_success_near_max = in_window.iter().any(|a| a.success);
                    evidence_at_max = in_window.iter().map(|a| **a).collect();
                }
            }
            if max_distinct < self.spraying_threshold {
                continue;
            }
            let severity = if any_success_near_max {
                Severity::High
            } else {
                Severity::Medium
            };
            let title = format!("Password Spraying: {source}");
            let details = format!(
                "來源 {source} 在 {} 分鐘內對 {max_distinct} 個不同帳號發起登入嘗試",
                self.spraying_window.num_minutes()
            );
            let reason = if any_success_near_max {
                format!(
                    "不同帳號數 {max_distinct} 達門檻 {}，且時間窗內有帳號成功登入——疑似 spraying 得手",
                    self.spraying_threshold
                )
            } else {
                format!(
                    "不同帳號數 {max_distinct} 達門檻 {}，時間窗內無成功登入",
                    self.spraying_threshold
                )
            };
            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = evidence_at_max.iter().map(|a| a.ts).max().unwrap_or_else(Utc::now);
            f.artifact = "logon_bruteforce".into();
            f.mitre = vec!["T1110.003".into()];
            f.details = details;
            f.reason = Some(reason);
            f.evidence = evidence_at_max
                .iter()
                .map(|a| EvidenceItem {
                    artifact: "evtx:Security".into(),
                    path: None,
                    ts: Some(a.ts),
                    detail: format!(
                        "{}: target={} source={}",
                        if a.success { "4624 success" } else { "4625 failure" },
                        a.target_user,
                        a.source
                    ),
                })
                .collect();
            findings.push(f);
        }
        findings
    }
}

impl Analyzer for LogonBruteforceHeuristic {
    fn name(&self) -> &str {
        "heur_logon_bruteforce"
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let attempts: Vec<LogonAttempt> = records
            .iter()
            .filter_map(|r| match r {
                Record::Event(ev) => parse_logon_attempt(ev),
                _ => None,
            })
            .collect();

        let mut findings = self.analyze_bruteforce(&attempts);
        findings.extend(self.analyze_spraying(&attempts));
        Ok(findings)
    }
}
```

- [ ] **Step 2: 編譯確認**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check -p cairn-heur
```

Expected: 編譯失敗（`logon_bruteforce` 尚未在 `lib.rs` 宣告為 module）——這是預期的，Task 3 會處理模組宣告。若想這步就編過，implementer 可以先在 `crates/cairn-heur/src/lib.rs` 加 `pub mod logon_bruteforce;`（不含 `pub use`），Task 3 再補 `pub use`。兩種做法皆可，以 implementer 判斷順手為準，但最終必須兩行都存在（Task 3 驗收會檢查）。

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-heur/src/logon_bruteforce.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): add logon bruteforce and password spraying detection"
```

---

## Task 3: 模組接線 + 單元測試

**Files:**
- Modify: `crates/cairn-heur/src/lib.rs`
- Modify: `crates/cairn-heur/src/logon_bruteforce.rs`（新增 `#[cfg(test)] mod tests`）

- [ ] **Step 1: 確認 `lib.rs` 已正確宣告模組**

讀取 `crates/cairn-heur/src/lib.rs`，確認含：

```rust
pub mod logon_bruteforce;
```

以及在既有 `pub use` 區塊（跟 `pub use account::AccountHeuristic;` 同一群組）新增：

```rust
pub use logon_bruteforce::LogonBruteforceHeuristic;
```

若 Task 2 已加好則跳過此步。

- [ ] **Step 2: 在 `logon_bruteforce.rs` 檔案尾端新增測試模組**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    fn make_logon_event(eid: u32, ts: DateTime<Utc>, target_user: &str, ip: &str) -> Record {
        let mut data = Map::new();
        data.insert(
            "TargetUserName".to_string(),
            Value::String(target_user.to_string()),
        );
        data.insert("IpAddress".to_string(), Value::String(ip.to_string()));
        Record::Event(EventRecord {
            ts,
            channel: "Security".to_string(),
            event_id: eid,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            record_id: 1,
            data,
        })
    }

    fn heuristic() -> LogonBruteforceHeuristic {
        LogonBruteforceHeuristic::new(
            Duration::minutes(5),
            5,
            Duration::minutes(1),
            10,
        )
    }

    #[test]
    fn five_failures_same_account_same_source_within_window_fires_medium() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "alice", "10.0.0.5"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1, "expected exactly one bruteforce finding, got {findings:?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("alice"));
    }

    #[test]
    fn four_failures_below_threshold_fires_nothing() {
        let base = Utc::now();
        let records: Vec<Record> = (0..4)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "bob", "10.0.0.9"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(findings.is_empty(), "expected no findings below threshold, got {findings:?}");
    }

    #[test]
    fn five_failures_then_success_fires_high() {
        let base = Utc::now();
        let mut records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "carol", "10.0.0.7"))
            .collect();
        records.push(make_logon_event(4624, base + Duration::seconds(200), "carol", "10.0.0.7"));
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let bruteforce_finding = findings
            .iter()
            .find(|f| f.title.contains("carol"))
            .expect("bruteforce finding for carol must exist");
        assert_eq!(bruteforce_finding.severity, Severity::High);
    }

    #[test]
    fn failures_outside_window_do_not_accumulate() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::minutes(i * 10), "dave", "10.0.0.1"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "failures spread 10 minutes apart (window=5min) should not accumulate, got {findings:?}"
        );
    }

    #[test]
    fn ten_distinct_accounts_same_source_within_window_fires_spraying_medium() {
        let base = Utc::now();
        let records: Vec<Record> = (0..10)
            .map(|i| {
                make_logon_event(
                    4625,
                    base + Duration::seconds(i * 3),
                    &format!("user{i}"),
                    "10.0.0.99",
                )
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let spraying_finding = findings
            .iter()
            .find(|f| f.title.contains("Spraying"))
            .expect("spraying finding must exist");
        assert_eq!(spraying_finding.severity, Severity::Medium);
    }

    #[test]
    fn nine_distinct_accounts_below_spraying_threshold_fires_nothing() {
        let base = Utc::now();
        let records: Vec<Record> = (0..9)
            .map(|i| {
                make_logon_event(
                    4625,
                    base + Duration::seconds(i * 3),
                    &format!("user{i}"),
                    "10.0.0.88",
                )
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.iter().all(|f| !f.title.contains("Spraying")),
            "9 distinct accounts should not trigger spraying (threshold=10), got {findings:?}"
        );
    }

    #[test]
    fn spraying_with_one_success_fires_high() {
        let base = Utc::now();
        let mut records: Vec<Record> = (0..9)
            .map(|i| {
                make_logon_event(
                    4625,
                    base + Duration::seconds(i * 3),
                    &format!("spray_user{i}"),
                    "10.0.0.77",
                )
            })
            .collect();
        records.push(make_logon_event(4624, base + Duration::seconds(30), "spray_user9", "10.0.0.77"));
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let spraying_finding = findings
            .iter()
            .find(|f| f.title.contains("Spraying"))
            .expect("spraying finding must exist (9 failures + 1 success = 10 distinct)");
        assert_eq!(spraying_finding.severity, Severity::High);
    }

    #[test]
    fn missing_ip_falls_back_to_workstation_name() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| {
                let mut data = Map::new();
                data.insert("TargetUserName".to_string(), Value::String("erin".to_string()));
                data.insert("WorkstationName".to_string(), Value::String("WORKSTATION1".to_string()));
                Record::Event(EventRecord {
                    ts: base + Duration::seconds(i * 30),
                    channel: "Security".to_string(),
                    event_id: 4625,
                    provider: "Microsoft-Windows-Security-Auditing".to_string(),
                    computer: "TEST-PC".to_string(),
                    record_id: 1,
                    data,
                })
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1, "fallback to WorkstationName must still group and fire");
        assert!(findings[0].details.contains("WORKSTATION1"));
    }

    #[test]
    fn missing_both_ip_and_workstation_never_fires() {
        let base = Utc::now();
        let records: Vec<Record> = (0..10)
            .map(|i| {
                let mut data = Map::new();
                data.insert("TargetUserName".to_string(), Value::String("frank".to_string()));
                Record::Event(EventRecord {
                    ts: base + Duration::seconds(i * 30),
                    channel: "Security".to_string(),
                    event_id: 4625,
                    provider: "Microsoft-Windows-Security-Auditing".to_string(),
                    computer: "TEST-PC".to_string(),
                    record_id: 1,
                    data,
                })
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "source='-' groups must be skipped entirely (no grouping possible), got {findings:?}"
        );
    }

    #[test]
    fn non_security_channel_ignored() {
        let base = Utc::now();
        let mut data = Map::new();
        data.insert("TargetUserName".to_string(), Value::String("grace".to_string()));
        data.insert("IpAddress".to_string(), Value::String("10.0.0.50".to_string()));
        let records: Vec<Record> = (0..5)
            .map(|i| {
                Record::Event(EventRecord {
                    ts: base + Duration::seconds(i * 30),
                    channel: "System".to_string(),
                    event_id: 4625,
                    provider: "test".to_string(),
                    computer: "TEST-PC".to_string(),
                    record_id: 1,
                    data: data.clone(),
                })
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(findings.is_empty(), "non-Security channel events must be ignored");
    }

    #[test]
    fn finding_carries_reason_and_evidence() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "henry", "10.0.0.20"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(findings[0].reason.is_some(), "golden rule 6: reason must be set");
        assert_eq!(findings[0].evidence.len(), 5, "each failure should be captured as evidence");
    }
}
```

- [ ] **Step 3: 跑測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo test -p cairn-heur logon_bruteforce
```

Expected: 11 個測試全部通過。若 `five_failures_then_success_fires_high` 或
`spraying_with_one_success_fires_high` 失敗，檢查 `window_stats`/spraying 迴圈裡
「anchor 必須是失敗事件」還是「任何事件都可當 anchor」的邏輯是否與測試資料的時間
間隔一致——`window_stats` 目前只用失敗事件當 anchor（因為爆破訊號核心是失敗次數），
但 spraying 迴圈用**任一事件**當 anchor（因為 spraying 訊號是廣度，含成功事件也要
算進距離窗口）。這是兩個函式故意不同的地方，不要在除錯時把兩者改成一致。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-heur/src/logon_bruteforce.rs crates/cairn-heur/src/lib.rs
git commit -m "test(heur): add logon bruteforce and spraying unit tests"
```

---

## Task 4: main.rs 接線（live 分析器清單 + 對應測試）

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: 讀取 live 分析器清單，在既有 `AccountHeuristic` 之後插入新 analyzer**

在 `crates/cairn-cli/src/main.rs` 的 live run 分析器建構區塊（`Box::new(cairn_heur::AccountHeuristic),` 那一行附近），新增：

```rust
        Box::new(cairn_heur::LogonBruteforceHeuristic::new(
            chrono::Duration::minutes(cfg.logon_bruteforce_window_minutes),
            cfg.logon_bruteforce_threshold,
            chrono::Duration::minutes(cfg.password_spraying_window_minutes),
            cfg.password_spraying_threshold,
        )),
```

（確認插入點在 `cfg` 變數已經在作用域內的位置——沿用 `TimestompHeuristic::new(chrono::Duration::hours(cfg.timestomp_threshold_hours))` 那行同樣讀 `cfg` 的寫法，插入點應該就在附近。）

- [ ] **Step 2: 在測試 `live_analyzers_include_all_heuristics` 的分析器清單裡同步新增**

找到該測試函式（約 main.rs:1274-1283），在建構 `analyzers` 的 `vec![...]` 裡新增對應的 `Box::new(cairn_heur::LogonBruteforceHeuristic::new(...))`（用固定測試值，例如 `chrono::Duration::minutes(5), 5, chrono::Duration::minutes(1), 10`），並在該測試函式已有的 `assert!` 群組後新增一行：

```rust
    assert!(
        analyzers.iter().any(|a| a.name() == "heur_logon_bruteforce"),
        "logon bruteforce heuristic must be registered"
    );
```

- [ ] **Step 3: 跑 cairn-cli 測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo test -p cairn-cli live_analyzers_include_all_heuristics
```

Expected: 通過。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire LogonBruteforceHeuristic into live analyzer pipeline"
```

---

## Task 5: Synthetic integration test（端到端驗證）

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`（新增一個 `#[test]` 函式，緊接在
  `sigma_analyzer_findings_appear_in_live_outcome` 之後）

- [ ] **Step 1: 新增整合測試**

```rust
/// Integration: LogonBruteforceHeuristic wired into run_live detects a bruteforce
/// pattern end-to-end (fake collector -> run_live -> RunOutcome.findings).
#[test]
fn logon_bruteforce_heuristic_fires_in_live_outcome() {
    use cairn_core::manifest::Privileges;
    use cairn_core::orchestrator::run_live;
    use cairn_core::record::{EventRecord, Record};
    use cairn_core::traits::{CollectCtx, Collector};
    use chrono::Utc;

    struct FixedEventsCollector(Vec<EventRecord>);
    impl Collector for FixedEventsCollector {
        fn name(&self) -> &str {
            "fake_security_events"
        }
        fn collect(&self, _ctx: &CollectCtx<'_>) -> cairn_core::Result<Vec<Record>> {
            Ok(self.0.iter().cloned().map(Record::Event).collect())
        }
    }

    let base = Utc::now();
    let events: Vec<EventRecord> = (0..5)
        .map(|i| {
            let mut data = serde_json::Map::new();
            data.insert(
                "TargetUserName".to_string(),
                serde_json::Value::String("integration_user".to_string()),
            );
            data.insert(
                "IpAddress".to_string(),
                serde_json::Value::String("192.0.2.10".to_string()),
            );
            EventRecord {
                ts: base + chrono::Duration::seconds(i * 20),
                channel: "Security".to_string(),
                event_id: 4625,
                provider: "Microsoft-Windows-Security-Auditing".to_string(),
                computer: "TEST".to_string(),
                record_id: 100 + i as u64,
                data,
            }
        })
        .collect();

    let cfg = cairn_core::Config::default();
    let privs = Privileges {
        admin: false,
        se_backup: false,
        se_debug: false,
    };
    let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FixedEventsCollector(events))];
    let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> =
        vec![Box::new(cairn_heur::LogonBruteforceHeuristic::new(
            chrono::Duration::minutes(cfg.logon_bruteforce_window_minutes),
            cfg.logon_bruteforce_threshold,
            chrono::Duration::minutes(cfg.password_spraying_window_minutes),
            cfg.password_spraying_threshold,
        ))];

    let outcome = run_live(&cfg, privs, "TEST".into(), &collectors, &analyzers);

    assert_eq!(outcome.records.len(), 5, "all 5 fake events must be collected");
    assert!(
        !outcome.findings.is_empty(),
        "bruteforce finding must be present in RunOutcome"
    );
    let finding = &outcome.findings[0];
    assert_eq!(finding.severity, cairn_core::finding::Severity::Medium);
    assert!(finding.reason.is_some(), "golden rule 6: reason must be set");
    assert_eq!(finding.mitre, vec!["T1110.001".to_string()]);
}
```

- [ ] **Step 2: 跑測試**

```bash
cargo test -p cairn-cli logon_bruteforce_heuristic_fires_in_live_outcome
```

Expected: 通過。若 `run_live` 簽名與範本不完全一致（例如參數順序、`RunOutcome` 欄位
命名），implementer 需要先讀取 `crates/cairn-core/src/orchestrator.rs` 的
`run_live` 與 `RunOutcome` 定義確認，並依實際簽名調整這個測試——不要臆測簽名硬寫。

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "test(cli): add end-to-end integration test for logon bruteforce heuristic"
```

---

## Task 6: 全 workspace 驗證收尾

**Files:**
- 無新增修改（純驗證 Task）

- [ ] **Step 1: 全 workspace check/test/clippy/fmt**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: 全部通過，0 failed，零 clippy 警告。`cargo fmt --check` 若抓到未格式化的
程式碼，跑 `cargo fmt` 修正後重新確認並補一個 commit（沿用段2 Task 9 的做法）。

- [ ] **Step 2: 若 Step 1 全綠，無需額外 commit；若 fmt 有修正則 commit**

```bash
git add -A
git commit -m "style: cargo fmt on logon bruteforce heuristic"
```

（僅當 Step 1 的 `cargo fmt --check` 真的有輸出 diff 時才需要這個 commit。）

---

## Self-Review

**1. Spec coverage：**
- 兩種偵測模式（帳號爆破 + spraying）→ Task 2 的 `analyze_bruteforce`/`analyze_spraying`，符合。
- 各自獨立分組鍵與閾值 → `BruteforceKey`/`SprayingKey` 型別區分，`Config` 四個獨立欄位，符合。
- Severity 邏輯（純失敗=Medium，有成功接續=High）→ 兩個 `analyze_*` 函式都實作了這個判斷，符合。
- 閾值放進 Config、無 CLI flag → Task 1，符合，且 doc comment 明確標註「no CLI flag」比照 `timestomp_threshold_hours`。
- 不依賴 prior_findings，不覆寫 depends_on → Task 2 的 `analyze()` 用 `_prior_findings` 忽略，未覆寫 `depends_on()`，符合。
- 資料前提（Security 頻道已被收集，段2確保）→ 這是既有事實不需要本計畫額外處理，spec 已載明。
- graceful degrade（IpAddress 缺失 fallback WorkstationName，兩者皆缺就 skip）→ `parse_logon_attempt` 的 fallback 邏輯 + `source == "-"` 時 `continue`，Task 3 有對應測試（`missing_ip_falls_back_to_workstation_name`、`missing_both_ip_and_workstation_never_fires`），符合。
- 不新增 Entity/Finding schema → Task 2 全程不填 `f.entity`，符合。
- golden rule 6（reason 必填）→ 兩個 `analyze_*` 函式都設定 `f.reason`，Task 3 有測試 `finding_carries_reason_and_evidence`，符合。

**2. Placeholder 掃描：** 所有 Step 都有完整程式碼，無 TBD/TODO。Task 5 提到「若 `run_live` 簽名不一致需要 implementer 自行核對調整」是誠實的資訊缺口標註（因為原始 spec 探查階段沒有完整讀取 `orchestrator.rs`），不是偷懶。

**3. Type 一致性：** `LogonBruteforceHeuristic::new` 簽名在 Task 2 定義為
`(Duration, u32, Duration, u32)`，Task 4/5 的呼叫端完全比照這個順序
（`bruteforce_window, bruteforce_threshold, spraying_window, spraying_threshold`），
一致。`EventRecord`/`Record::Event`/`Finding`/`EvidenceItem` 欄位命名全計畫一致。

**4. 執行順序相依性：** Task 1（Config）→ Task 2（核心邏輯，不依賴 Config，直接吃
建構子參數）→ Task 3（單元測試，依賴 Task 2 的型別）→ Task 4（main.rs 接線，依賴
Task 1 的 Config 欄位 + Task 2/3 的 `LogonBruteforceHeuristic`）→ Task 5（整合測試，
依賴 Task 4 已接線）→ Task 6（全量驗證）。嚴格序列，不可平行（Task 4/5 都改
`main.rs`，同檔案序列處理，符合 cairn-dev-loop 的既有教訓）。
