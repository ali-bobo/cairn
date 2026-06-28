# Account Activity Heuristic — Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to execute this plan.

**Goal:** 新增 `AccountHeuristic` analyzer，從 Security EVTX 事件中偵測近期帳號建立
（EID 4720）、刪除（EID 4726）、加入群組（EID 4732/4728），輸出帶時間窗口判斷的 Finding。

**Architecture:** 新建 `crates/cairn-heur/src/account.rs`，接線到 `lib.rs` 和 `main.rs`。
純邏輯，不做 host 查詢，所有輸入來自已收集的 `Record::Event`。

**Tech Stack:** Rust / cairn-heur / cairn-core EventRecord

**Spec:** `docs/dev-history/specs/2026-06-28-account-heuristic-design.md`

---

### Task 1: 建立 `account.rs` — 核心資料結構與純函式

**Files:**
- Create: `crates/cairn-heur/src/account.rs`

- [ ] **Step 1: 建立檔案，加入常數、enum 與輔助純函式**

```rust
#![forbid(unsafe_code)]

use cairn_core::finding::{FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

/// 帳號操作事件距今多少天以內視為「近期」。
const ACCOUNT_RECENT_DAYS: i64 = 90;

#[derive(Debug)]
enum AccountEventKind {
    Created,
    Deleted,
    AddedToGroup,
}

#[derive(Debug)]
struct AccountEvent {
    kind: AccountEventKind,
    /// 目標帳號名稱（建立/刪除）或被加入的成員名稱（群組）
    target: String,
    /// 群組名稱（僅 AddedToGroup 有值）
    group: Option<String>,
    /// 執行操作的帳號
    subject: String,
    ts: DateTime<Utc>,
    mitre: &'static str,
}

/// 從 EID 4720/4726 的 EventData 提取帳號名稱（TargetUserName）與操作者（SubjectUserName）。
fn extract_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// 將 EventRecord 解析為 AccountEvent；不符合條件的事件回傳 None。
fn parse_account_event(ev: &EventRecord) -> Option<AccountEvent> {
    if ev.channel != "Security" {
        return None;
    }
    let d = &ev.data;
    match ev.event_id {
        4720 => Some(AccountEvent {
            kind: AccountEventKind::Created,
            target: extract_str(d, "TargetUserName"),
            group: None,
            subject: extract_str(d, "SubjectUserName"),
            ts: ev.ts,
            mitre: "T1136.001",
        }),
        4726 => Some(AccountEvent {
            kind: AccountEventKind::Deleted,
            target: extract_str(d, "TargetUserName"),
            group: None,
            subject: extract_str(d, "SubjectUserName"),
            ts: ev.ts,
            mitre: "T1531",
        }),
        4732 | 4728 => Some(AccountEvent {
            kind: AccountEventKind::AddedToGroup,
            target: extract_str(d, "MemberName"),
            group: Some(extract_str(d, "TargetUserName")),
            subject: extract_str(d, "SubjectUserName"),
            ts: ev.ts,
            mitre: "T1098.001",
        }),
        _ => None,
    }
}

/// 是否在近期窗口內（距 now ≤ ACCOUNT_RECENT_DAYS 天）。
fn is_recent(ts: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    let age = now.signed_duration_since(ts);
    age >= Duration::zero() && age <= Duration::days(ACCOUNT_RECENT_DAYS)
}
```

- [ ] **Step 2: 執行 `cargo check -p cairn-heur` 確認無編譯錯誤**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo check -p cairn-heur
```

---

### Task 2: 實作 `AccountHeuristic` struct 與 `Analyzer` trait

**Files:**
- Modify: `crates/cairn-heur/src/account.rs`

- [ ] **Step 1: 在 Task 1 程式碼之後加入 struct 與 impl**

```rust
pub struct AccountHeuristic;

impl Analyzer for AccountHeuristic {
    fn name(&self) -> &str {
        "heur_account"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut findings = Vec::new();

        for r in records {
            let ev = match r {
                Record::Event(e) => e,
                _ => continue,
            };
            let ae = match parse_account_event(ev) {
                Some(a) => a,
                None => continue,
            };

            let recent = is_recent(ae.ts, now);
            let severity = if recent {
                Severity::High
            } else {
                Severity::Medium
            };

            let (title, details) = match &ae.kind {
                AccountEventKind::Created => (
                    format!("帳號建立: {}", ae.target),
                    format!(
                        "帳號 {} 由 {} 建立於 {}",
                        ae.target,
                        ae.subject,
                        ae.ts.format("%Y-%m-%dT%H:%M:%SZ")
                    ),
                ),
                AccountEventKind::Deleted => (
                    format!("帳號刪除: {}", ae.target),
                    format!(
                        "帳號 {} 由 {} 刪除於 {}",
                        ae.target,
                        ae.subject,
                        ae.ts.format("%Y-%m-%dT%H:%M:%SZ")
                    ),
                ),
                AccountEventKind::AddedToGroup => {
                    let group = ae.group.as_deref().unwrap_or("?");
                    (
                        format!("加入群組: {} ← {}", group, ae.target),
                        format!(
                            "{} 被 {} 加入群組 {} 於 {}",
                            ae.target,
                            ae.subject,
                            group,
                            ae.ts.format("%Y-%m-%dT%H:%M:%SZ")
                        ),
                    )
                }
            };

            let reason = if recent {
                format!(
                    "帳號操作發生在 {} 天內（近期窗口 {} 天）",
                    now.signed_duration_since(ae.ts).num_days(),
                    ACCOUNT_RECENT_DAYS
                )
            } else {
                format!(
                    "帳號操作發生在 {} 天前（超過近期窗口 {} 天）",
                    now.signed_duration_since(ae.ts).num_days(),
                    ACCOUNT_RECENT_DAYS
                )
            };

            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = ae.ts;
            f.artifact = "account".into();
            f.mitre = vec![ae.mitre.into()];
            f.details = details;
            f.reason = Some(reason);

            findings.push(f);
        }

        Ok(findings)
    }
}
```

- [ ] **Step 2: 執行 `cargo check -p cairn-heur` 確認無編譯錯誤**

```powershell
cargo check -p cairn-heur
```

---

### Task 3: 撰寫測試

**Files:**
- Modify: `crates/cairn-heur/src/account.rs`

- [ ] **Step 1: 在檔案尾端加入 `#[cfg(test)]` 區塊**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::Record;
    use chrono::Duration;
    use serde_json::{Map, Value};

    fn make_event(
        eid: u32,
        channel: &str,
        ts: DateTime<Utc>,
        data: Map<String, Value>,
    ) -> Record {
        Record::Event(EventRecord {
            ts,
            channel: channel.to_string(),
            event_id: eid,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            record_id: 1,
            data,
        })
    }

    fn account_data(target: &str, subject: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("TargetUserName".into(), Value::String(target.into()));
        m.insert("SubjectUserName".into(), Value::String(subject.into()));
        m
    }

    fn group_data(member: &str, group: &str, subject: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("MemberName".into(), Value::String(member.into()));
        m.insert("TargetUserName".into(), Value::String(group.into()));
        m.insert("SubjectUserName".into(), Value::String(subject.into()));
        m
    }

    fn recent() -> DateTime<Utc> {
        Utc::now() - Duration::days(30)
    }

    fn old() -> DateTime<Utc> {
        Utc::now() - Duration::days(120)
    }

    #[test]
    fn create_account_recent_is_high() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("evil_user", "SYSTEM"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1136.001".to_string()));
        assert_eq!(findings[0].artifact, "account");
    }

    #[test]
    fn create_account_old_is_medium() {
        let records = vec![make_event(
            4720,
            "Security",
            old(),
            account_data("old_user", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn delete_account_recent_is_high() {
        let records = vec![make_event(
            4726,
            "Security",
            recent(),
            account_data("victim", "attacker"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1531".to_string()));
    }

    #[test]
    fn add_to_local_group_is_high() {
        let records = vec![make_event(
            4732,
            "Security",
            recent(),
            group_data(r"DESKTOP\evil", "Administrators", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1098.001".to_string()));
        assert!(findings[0].title.contains("Administrators"));
    }

    #[test]
    fn add_to_global_group_is_high() {
        let records = vec![make_event(
            4728,
            "Security",
            recent(),
            group_data(r"DOMAIN\evil", "Domain Admins", "DA"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1098.001".to_string()));
    }

    #[test]
    fn non_security_channel_ignored() {
        let records = vec![make_event(
            4720,
            "System",
            recent(),
            account_data("user", "admin"),
        )];
        assert!(AccountHeuristic.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn wrong_eid_ignored() {
        let records = vec![make_event(
            4625,
            "Security",
            recent(),
            account_data("user", "admin"),
        )];
        assert!(AccountHeuristic.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn non_event_record_ignored() {
        use cairn_core::record::ProcessRecord;
        let records = vec![Record::Process(ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "system".into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        })];
        assert!(AccountHeuristic.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn reason_mentions_time_window() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("user", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        let reason = findings[0].reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("90") || reason.contains("近期"),
            "reason must mention window: {reason}"
        );
    }

    #[test]
    fn finding_has_artifact_account() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("user", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records).unwrap();
        assert_eq!(findings[0].artifact, "account");
    }
}
```

- [ ] **Step 2: 執行 `cargo test -p cairn-heur` 確認 10 個新測試全綠**

```powershell
cargo test -p cairn-heur
```

期望：原有 126 + 10 新測試 = 136 全綠。

---

### Task 4: 接線 lib.rs 與 main.rs，執行全套驗收

**Files:**
- Modify: `crates/cairn-heur/src/lib.rs`
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: 在 `lib.rs` 加入 module 與 re-export**

在 `pub mod correlation;` 等 mod 宣告區加入：
```rust
pub mod account;
```

在 `pub use` 區加入：
```rust
pub use account::AccountHeuristic;
```

- [ ] **Step 2: 在 `main.rs` 的 analyzers Vec 加入 AccountHeuristic**

找到：
```rust
let mut analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
    Box::new(cairn_heur::ParentChildHeuristic),
    Box::new(cairn_heur::NetConnHeuristic),
    Box::new(cairn_heur::PersistHeuristic),
    ...
    Box::new(cairn_heur::CorrelationAnalyzer),
];
```

在 `Box::new(cairn_heur::CorrelationAnalyzer)` 後加入：
```rust
Box::new(cairn_heur::AccountHeuristic),
```

- [ ] **Step 3: 更新 `main.rs` 的 `live_analyzers_include_all_heuristics` 測試**

找到測試中的 analyzers vec，加入：
```rust
Box::new(cairn_heur::AccountHeuristic),
```

並加入斷言：
```rust
assert!(
    analyzers.iter().any(|a| a.name() == "heur_account"),
    "heur_account must be in analyzer set"
);
```

- [ ] **Step 4: 執行 workspace 全套測試**

```powershell
cargo test --workspace
```

期望：全綠（含 7 ignored e2e）。

- [ ] **Step 5: 執行 clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

期望：零警告。

- [ ] **Step 6: git commit**

```powershell
git add crates/cairn-heur/src/account.rs crates/cairn-heur/src/lib.rs crates/cairn-cli/src/main.rs docs/dev-history/specs/2026-06-28-account-heuristic-design.md docs/dev-history/plans/2026-06-28-account-heuristic.md
git commit -m "feat(heur): add AccountHeuristic for account creation/deletion/group events

Detects EID 4720 (account created), 4726 (deleted), 4732/4728 (added to group)
from Security EVTX. Events within 90 days → High; older → Medium.
10 new unit tests; workspace clean; zero clippy warnings.

T1136.001 / T1531 / T1098.001

Spec: docs/dev-history/specs/2026-06-28-account-heuristic-design.md"
```
