# 段 3：TemporalWindowCorrelator v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新建獨立 Analyzer `TemporalWindowCorrelator`（`crates/cairn-heur/src/temporal.rs`），對已通過 persist/parentchild gate 的行程附加時間窗內的 USN 事件與同 PID NetConn 作為 evidence 並升級 severity；前置修正 `persist.rs` 填 `entity.process`，並把 `escalate()` 搬到共用 `score.rs`。

**Architecture:** `depends_on(["heur_persist", "heur_parentchild"])` 讀 `prior_findings`，用 `finding.entity.process.pid` 反查 `records: &[Record]` 建的 `by_pid` 索引拿回完整 `ProcessRecord`（含 `start_time`）；USN 比對用線性掃描+時間區間過濾；NetConn 比對用 pid 存在性；不新增 schema，全部沿用既有 `Entity`/`EvidenceItem` 型別。

**Tech Stack:** Rust、`cairn-core::{Record, Finding, Entity, EntityProcess, EvidenceItem}`、`chrono::{DateTime, Duration, Utc}`（`cairn-heur` 已有依賴）。

---

## 前置事實（來自探查，任務執行時不需重查）

- **`persist.rs` 的 `entity` 賦值現況**（`crates/cairn-heur/src/persist.rs:500`）：
  `f.entity = persistence_entity(p);` 只填 `file` 或 `registry`，從不填 `process`。
  S9 執行證據交叉升級的命中變數是 `proc_hits: Vec<&ProcessRecord>`
  （`persist.rs:442`，來自 `idx.lookup_proc(&key)`），非空代表這條持久化記錄有
  對應的存活 `ProcessRecord`。

- **`escalate()` 現況**（`crates/cairn-heur/src/persist.rs:33-41`）：
  ```rust
  fn escalate(sev: Severity) -> Severity {
      match sev {
          Severity::Info => Severity::Low,
          Severity::Low => Severity::Medium,
          Severity::Medium => Severity::High,
          Severity::High | Severity::Critical => Severity::Critical,
      }
  }
  ```
  私有函式，呼叫點：`persist.rs:430`、`persist.rs:444`。測試
  `escalate_caps_at_critical` 在 `persist.rs:961-967`。

- **`score.rs` 現況**（`crates/cairn-heur/src/score.rs`，485行）：已有
  `JoinKey`/`join_key`/`Score`/`severity_for` 等。**沒有 `escalate` 名稱**，
  搬移不會衝突。合理插入點：`severity_for`（約行249）之後、`#[cfg(test)]`
  之前。

- **`EntityProcess`/`Entity`**（`crates/cairn-core/src/finding.rs:24-44`）：
  ```rust
  pub struct Entity {
      pub process: Option<EntityProcess>,
      pub file: Option<EntityFile>,
      pub netconn: Option<EntityNetConn>,
      pub registry: Option<EntityRegistry>,
  }
  pub struct EntityProcess {
      pub pid: u32, pub ppid: u32, pub image: String, pub cmdline: String,
      pub signed: Option<bool>, pub integrity: Option<String>,
  }
  ```
  既有填值範例（`crates/cairn-heur/src/netconn.rs:192-209`）：
  ```rust
  process: owner.map(|o| EntityProcess {
      pid: o.pid, ppid: o.ppid, image: o.image.clone(),
      cmdline: o.cmdline.clone(), signed: o.signed, integrity: o.integrity.clone(),
  }),
  ```

- **`Record` enum**（`crates/cairn-core/src/record.rs:17-27`）：
  `Record::Process(ProcessRecord)`、`Record::NetConn(NetConnRecord)`、
  `Record::UsnEvent(UsnEventRecord)` 變體名稱確認正確。
  - `ProcessRecord`（record.rs:42-54）：`pid, ppid, image, cmdline, signed,
    signer, binary_sha256, integrity, user, start_time: Option<DateTime<Utc>>`。
  - `UsnEventRecord`（record.rs:98-104）：`ts: DateTime<Utc>, path: String,
    reason: String, mft_ref: u64`（**無 pid 欄位**）。
  - `NetConnRecord`（record.rs:56-65）：含 `pid: Option<u32>`（**無時間戳**）。

- **既有 persist.rs 測試不會被 Task 0 破壞**：`persist.rs:630` 只斷言
  `f.entity.registry.is_some()`；`persist.rs:681-682` 只斷言
  `f.entity.file.is_some()` + `f.entity.registry.is_none()`。兩者都不涉及
  `process` 欄位，且這些測試的 fixture 本身不提供 `ProcessRecord`，所以
  `proc_hits` 為空、`entity.process` 保持 `None`，行為不變。

- **`live_analyzers` 分析器清單兩處插入點**（`crates/cairn-cli/src/main.rs`）：
  正式路徑約 878-894 行，測試 `live_analyzers_include_all_heuristics` 約
  1280-1295 行。插入位置：接在 `Box::new(cairn_heur::PersistHeuristic),`
  之後、`TimestompHeuristic` 之前（兩處都要同步改）。

- **`netconn.rs` 的 `depends_on`/`prior_findings` 測試模式**（可直接抄）：
  ```rust
  #[test]
  fn depends_on_returns_heur_persist() {
      assert_eq!(NetConnHeuristic.depends_on(), &["heur_persist"]);
  }
  ```
  以及用 `PERSIST_SOURCE_MARKER` + `evidence` 建構假 prior Finding 的手法
  （`netconn.rs:783-831`，`netconn_corroborated_by_persist_finding_clears_gate`）。

- **`owner()` fixture 現況**（`netconn.rs:243-255`）：固定
  `start_time: None`——`TemporalWindowCorrelator` 的測試需要自訂
  `start_time` 的 fixture（不能直接複用 `owner()`），Task 2 會寫一個新的
  helper。

- **CARGO_TARGET_DIR 與 linker**：
  ```bash
  export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
  export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
  ```
  不寫進 `.cargo/config.toml`。

- **測試分工**：Task 0/1/2/3 的 implementer 只跑 `cargo test -p cairn-heur`；
  Task 3 若涉及 `main.rs` 改動則跑 `cargo test -p cairn-cli`；finishing 階段
  做一次全 workspace 驗證。

---

## Task 0: `persist.rs` 補填 `entity.process`

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: 在 import 區塊新增 `EntityProcess`**

找到 `crates/cairn-heur/src/persist.rs` 頂部 import（現況只有
`EntityFile, EntityRegistry, EvidenceItem`），改成：

```rust
use cairn_core::finding::{EntityFile, EntityProcess, EntityRegistry, EvidenceItem};
```

（保留該行其他既有 import 不動，只新增 `EntityProcess`。）

- [ ] **Step 2: 在 `entity` 組裝處新增 `process` 填值**

找到 `crates/cairn-heur/src/persist.rs:500` 附近的：

```rust
            f.entity = persistence_entity(p);
```

改為：

```rust
            f.entity = persistence_entity(p);
            if let Some(pr) = proc_hits.first() {
                f.entity.process = Some(EntityProcess {
                    pid: pr.pid,
                    ppid: pr.ppid,
                    image: pr.image.clone(),
                    cmdline: pr.cmdline.clone(),
                    signed: pr.signed,
                    integrity: pr.integrity.clone(),
                });
            }
```

（`proc_hits` 是同一個 `for` 迴圈作用域內已存在的變數，來自
`idx.lookup_proc(&key)`，見前置事實。此段程式碼要放在 `f.entity =
persistence_entity(p);` 這行之後、`f` 被 push 進 `findings`/`out` 之前的
同一個作用域內。）

- [ ] **Step 3: 新增測試確認 `entity.process` 在 S9 命中時被填值**

在 `persist.rs` 的 `#[cfg(test)] mod tests` 內新增（找一個現有測試如
`analyzer_emits_finding_for_malicious_only` 或
`startup_mechanism_uses_file_entity` 附近的既有 fixture 建構模式，仿照它
建構一筆有對應 `ProcessRecord`（`binary_path`/`command` 與某個
`ProcessRecord.image` 透過 `join_key` 命中）的持久化記錄）：

```rust
#[test]
fn s9_execution_hit_populates_entity_process() {
    let pr = ProcessRecord {
        pid: 4242,
        ppid: 1,
        image: r"C:\Users\victim\AppData\Local\Temp\evil.exe".to_string(),
        cmdline: r"evil.exe -x".to_string(),
        signed: Some(false),
        signer: None,
        binary_sha256: None,
        integrity: Some("Medium".to_string()),
        user: None,
        start_time: None,
    };
    let p = rec_with_binary_path(
        "ifeo",
        r"C:\Users\victim\AppData\Local\Temp\evil.exe",
    );
    let records = vec![Record::Persistence(p), Record::Process(pr)];
    let findings = PersistHeuristic.analyze(&records, &[]).unwrap();
    assert_eq!(findings.len(), 1);
    let entity_process = findings[0]
        .entity
        .process
        .as_ref()
        .expect("S9 execution hit must populate entity.process");
    assert_eq!(entity_process.pid, 4242);
    assert_eq!(entity_process.image, r"C:\Users\victim\AppData\Local\Temp\evil.exe");
}
```

**注意**：`rec_with_binary_path` 這個 helper 函式名稱是假設性的——implementer
需要先讀取 `persist.rs` 現有的 `#[cfg(test)] mod tests` 區塊裡實際的
fixture 建構 helper（可能叫 `rec()`、`persistence_record()`
或類似名稱，且可能不接受 `binary_path` 參數，需要用 struct literal 或
builder pattern 手動建構一筆 `PersistenceRecord`，欄位含
`mechanism: "ifeo".to_string()`、`binary_path: Some(...)` 使其透過
`join_key` 與上面的 `ProcessRecord.image` 命中）。找到既有 helper 後，
用完全一致的建構方式寫這個測試，不要臆測欄位名稱。

- [ ] **Step 4: 跑測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo test -p cairn-heur persist
```

Expected: 全部通過，含既有測試（`analyzer_emits_finding_for_malicious_only`、
`startup_mechanism_uses_file_entity` 等）與新增的
`s9_execution_hit_populates_entity_process`。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): persist Findings populate entity.process on S9 execution hit"
```

---

## Task 1: `escalate()` 搬到 `score.rs`

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: 在 `score.rs` 新增 `escalate`**

在 `crates/cairn-heur/src/score.rs` 的 `severity_for` 函式之後、
`#[cfg(test)] mod tests` 之前，新增：

```rust
/// Bump one severity band (multi-signal / execution-corroboration escalation).
/// Caps at Critical.
pub fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}
```

（若 `score.rs` 頂部尚未 import `Severity`，需要確認 import 語句含
`cairn_core::finding::Severity` 或類似路徑——先讀取 `score.rs` 現有的
`severity_for` 函式簽名確認 `Severity` 的 import 路徑，沿用同一個。）

- [ ] **Step 2: 把 `escalate_caps_at_critical` 測試搬到 `score.rs`**

從 `persist.rs:961-967` 剪下該測試，貼進 `score.rs` 的
`#[cfg(test)] mod tests` 區塊（測試內容不變，只是換檔案）：

```rust
#[test]
fn escalate_caps_at_critical() {
    assert_eq!(escalate(Severity::Info), Severity::Low);
    assert_eq!(escalate(Severity::Low), Severity::Medium);
    assert_eq!(escalate(Severity::Medium), Severity::High);
    assert_eq!(escalate(Severity::High), Severity::Critical);
    assert_eq!(escalate(Severity::Critical), Severity::Critical);
}
```

- [ ] **Step 3: `persist.rs` 移除私有 `escalate` 定義，改用共用版本**

刪除 `persist.rs:33-41` 的 `fn escalate(...) { ... }` 定義。在 `persist.rs`
頂部 import 區塊（現況 `use crate::score::{join_key, JoinKey};`），改為：

```rust
use crate::score::{escalate, join_key, JoinKey};
```

`persist.rs:430`、`persist.rs:444` 的 `escalate(sev)` 呼叫不用改，因為
函式名稱相同、現在指向 `crate::score::escalate`。

- [ ] **Step 4: 跑測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo test -p cairn-heur
```

Expected: 全部通過。`escalate_caps_at_critical` 現在應該出現在 `score::tests`
底下（而非 `persist::tests`），`persist.rs` 裡引用 `escalate` 的地方不需要
額外改動。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/score.rs crates/cairn-heur/src/persist.rs
git commit -m "refactor(heur): move escalate() from persist.rs to shared score.rs"
```

---

## Task 2: `temporal.rs` 核心邏輯

**Files:**
- Create: `crates/cairn-heur/src/temporal.rs`

- [ ] **Step 1: 建立檔案骨架 + 時間窗擴充邏輯**

```rust
#![forbid(unsafe_code)]

use cairn_core::finding::{EvidenceItem, Finding, FindingSource};
use cairn_core::record::{ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// Fixed window width after a process's start_time within which USN/NetConn
/// activity is considered temporally adjacent (not causally proven).
const TEMPORAL_WINDOW_MINUTES: i64 = 5;

/// Cap on USN evidence items attached to a single Finding (IR-panels quota
/// pattern: newest-first, truncate, note original count — see html.rs USN_CAP).
const USN_EVIDENCE_CAP: usize = 200;

fn by_pid(records: &[Record]) -> HashMap<u32, &ProcessRecord> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::Process(p) => Some((p.pid, p)),
            _ => None,
        })
        .collect()
}

/// USN events whose ts falls within [start_time, start_time + window].
/// Linear scan — UsnEventRecord has no pid field (Windows USN journal design
/// limitation), so no index can narrow this further than the time bound itself.
fn usn_events_in_window<'a>(
    records: &'a [Record],
    start_time: DateTime<Utc>,
    window: Duration,
) -> Vec<&'a cairn_core::record::UsnEventRecord> {
    let window_end = start_time + window;
    records
        .iter()
        .filter_map(|r| match r {
            Record::UsnEvent(u) if u.ts >= start_time && u.ts <= window_end => Some(u),
            _ => None,
        })
        .collect()
}

/// NetConn records owned by the given pid (existence, not temporal — NetConnRecord
/// has no timestamp field, see spec §1 API limitation).
fn netconns_for_pid<'a>(
    records: &'a [Record],
    pid: u32,
) -> Vec<&'a cairn_core::record::NetConnRecord> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::NetConn(c) if c.pid == Some(pid) => Some(c),
            _ => None,
        })
        .collect()
}

pub struct TemporalWindowCorrelator;

impl Analyzer for TemporalWindowCorrelator {
    fn name(&self) -> &str {
        "heur_temporal"
    }

    fn depends_on(&self) -> &[&str] {
        &["heur_persist", "heur_parentchild"]
    }

    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let procs = by_pid(records);
        let mut out = Vec::new();

        for pf in prior_findings {
            let Some(ep) = pf.entity.process.as_ref() else {
                continue;
            };
            let Some(pr) = procs.get(&ep.pid) else {
                continue;
            };
            let Some(start_time) = pr.start_time else {
                continue;
            };

            let window = Duration::minutes(TEMPORAL_WINDOW_MINUTES);
            let mut usn_hits = usn_events_in_window(records, start_time, window);
            let usn_total = usn_hits.len();
            usn_hits.sort_by_key(|u| std::cmp::Reverse(u.ts));
            usn_hits.truncate(USN_EVIDENCE_CAP);

            let netconn_hits = netconns_for_pid(records, ep.pid);

            if usn_hits.is_empty() && netconn_hits.is_empty() {
                continue;
            }

            let severity = crate::score::escalate(pf.severity);
            let mut f = Finding::new(
                severity,
                format!("時間窗口關聯: {}", ep.image),
                FindingSource::Heuristic,
            );
            f.ts = start_time;
            f.artifact = "temporal_window".into();
            f.mitre = pf.mitre.clone();
            f.entity.process = Some(ep.clone());
            f.reason = Some(format!(
                "corroborated by temporal-window evidence — escalated (source finding: {})",
                pf.title
            ));

            let mut evidence: Vec<EvidenceItem> = usn_hits
                .iter()
                .map(|u| EvidenceItem {
                    artifact: "usn_temporal".into(),
                    path: Some(u.path.clone()),
                    ts: Some(u.ts),
                    detail: format!(
                        "時間窗口內的檔案事件（非確認因果）：{} {} 於 {}，行程建立於 {}",
                        u.reason, u.path, u.ts, start_time
                    ),
                })
                .collect();

            if usn_total > USN_EVIDENCE_CAP {
                evidence.push(EvidenceItem {
                    artifact: "usn_temporal_summary".into(),
                    path: None,
                    ts: None,
                    detail: format!(
                        "時間窗口內共 {usn_total} 筆檔案事件，僅附加前 {USN_EVIDENCE_CAP} 筆"
                    ),
                });
            }

            for c in &netconn_hits {
                evidence.push(EvidenceItem {
                    artifact: "netconn_temporal".into(),
                    path: None,
                    ts: None,
                    detail: format!(
                        "同行程目前有網路連線（存在性關聯，非時序因果，NetConn 快照無時間資訊）：{}:{} state={}",
                        c.raddr.clone().unwrap_or_default(),
                        c.rport.map(|p| p.to_string()).unwrap_or_default(),
                        c.state.clone().unwrap_or_default()
                    ),
                });
            }

            f.evidence = evidence;
            out.push(f);
        }

        Ok(out)
    }
}
```

**implementer 注意**：`NetConnRecord` 的 `raddr`/`rport`/`state` 欄位型別
需要先讀取 `crates/cairn-core/src/record.rs:56-65` 的實際定義確認（本計畫
假設 `raddr: Option<String>`、`rport: Option<u16>`、`state: Option<String>`，
依既有 `netconn.rs` 的用法慣例推斷，但**必須在寫這段程式碼前用 Read 工具
核對實際型別**，若欄位是非 Option 型別或命名不同，相應調整 `.clone()`/
`.unwrap_or_default()`/格式化字串，不要不驗證就照抄）。

- [ ] **Step 2: 在 `lib.rs` 註冊模組**

在 `crates/cairn-heur/src/lib.rs` 新增（比照既有 `pub mod`/`pub use` 群組
的字母序風格插入）：

```rust
pub mod temporal;
```

```rust
pub use temporal::TemporalWindowCorrelator;
```

- [ ] **Step 3: 編譯確認**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo check -p cairn-heur
```

Expected: 編譯成功。若 `NetConnRecord` 欄位型別與假設不符，這裡會報錯，
implementer 需回頭核對 `record.rs` 實際定義修正 Step 1 的程式碼（不是
繞過型別系統硬轉型）。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-heur/src/temporal.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): add TemporalWindowCorrelator (USN + NetConn temporal evidence)"
```

---

## Task 3: 單元測試 + main.rs 接線

**Files:**
- Modify: `crates/cairn-heur/src/temporal.rs`（新增 `#[cfg(test)] mod tests`）
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: 在 `temporal.rs` 新增測試模組**

先用 Read 工具核對 `NetConnRecord`/`ProcessRecord` 的實際欄位（Task 2 Step 1
已提醒），再撰寫以下測試（fixture helper 需要自訂 `start_time`，不能複用
`netconn.rs` 的 `owner()`）：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::{Entity, EntityProcess, Severity};
    use cairn_core::record::{NetConnRecord, ProcessRecord, UsnEventRecord};

    fn process_with_start_time(pid: u32, image: &str, start_time: Option<DateTime<Utc>>) -> Record {
        Record::Process(ProcessRecord {
            pid,
            ppid: 1,
            image: image.to_string(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time,
        })
    }

    fn prior_finding_with_process(pid: u32, image: &str) -> Finding {
        let mut f = Finding::new(Severity::Medium, "test persist finding", FindingSource::Heuristic);
        f.entity = Entity {
            process: Some(EntityProcess {
                pid,
                ppid: 1,
                image: image.to_string(),
                cmdline: String::new(),
                signed: None,
                integrity: None,
            }),
            ..Entity::default()
        };
        f
    }

    fn usn_event(ts: DateTime<Utc>, path: &str) -> Record {
        Record::UsnEvent(UsnEventRecord {
            ts,
            path: path.to_string(),
            reason: "create".to_string(),
            mft_ref: 1,
        })
    }

    #[test]
    fn depends_on_returns_persist_and_parentchild() {
        assert_eq!(
            TemporalWindowCorrelator.depends_on(),
            &["heur_persist", "heur_parentchild"]
        );
    }

    #[test]
    fn usn_event_within_window_attaches_as_evidence_and_escalates() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            usn_event(start + Duration::minutes(2), r"C:\Temp\dropped.exe"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High, "Medium -> High via escalate()");
        assert!(findings[0].evidence[0].detail.contains("非確認因果"));
    }

    #[test]
    fn usn_event_outside_window_not_attached() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            usn_event(start + Duration::minutes(10), r"C:\Temp\dropped.exe"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty(), "event 10 minutes after start (window=5min) must not attach");
    }

    #[test]
    fn usn_event_in_different_directory_still_attaches() {
        // §4.3 regression: USN correlation is NOT path-restricted (attackers
        // commonly write payloads to a different directory than the dropper).
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\Users\a\dropper.exe", Some(start)),
            usn_event(start + Duration::seconds(30), r"C:\Windows\Temp\payload.dll"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\Users\a\dropper.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1, "cross-directory USN event must still attach");
    }

    #[test]
    fn missing_start_time_skips_temporal_expansion() {
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", None),
            usn_event(Utc::now(), r"C:\Temp\dropped.exe"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty(), "start_time=None must skip, not panic or guess");
    }

    #[test]
    fn missing_entity_process_on_prior_finding_skips() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            usn_event(start + Duration::seconds(30), r"C:\Temp\dropped.exe"),
        ];
        // No entity.process on this prior finding (e.g. persist Finding that's
        // file/registry-backed with no S9 execution hit).
        let mut pf = Finding::new(Severity::Medium, "no process entity", FindingSource::Heuristic);
        pf.entity = Entity::default();
        let findings = TemporalWindowCorrelator.analyze(&records, &[pf]).unwrap();
        assert!(findings.is_empty(), "Finding without entity.process must be skipped");
    }

    #[test]
    fn over_200_usn_events_are_capped_with_summary_note() {
        let start = Utc::now();
        let mut records = vec![process_with_start_time(100, r"C:\evil.exe", Some(start))];
        for i in 0..250 {
            records.push(usn_event(
                start + Duration::seconds(i),
                &format!(r"C:\Temp\file{i}.tmp"),
            ));
        }
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1);
        let usn_evidence_count = findings[0]
            .evidence
            .iter()
            .filter(|e| e.artifact == "usn_temporal")
            .count();
        assert_eq!(usn_evidence_count, 200, "must cap at USN_EVIDENCE_CAP");
        assert!(
            findings[0]
                .evidence
                .iter()
                .any(|e| e.artifact == "usn_temporal_summary" && e.detail.contains("250")),
            "must note the original total count when truncated"
        );
    }

    #[test]
    fn same_pid_netconn_attaches_as_existence_evidence() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            Record::NetConn(NetConnRecord {
                proto: "tcp".to_string(),
                laddr: "10.0.0.5".to_string(),
                lport: 51000,
                raddr: Some("203.0.113.5".to_string()),
                rport: Some(4444),
                state: Some("established".to_string()),
                pid: Some(100),
            }),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|e| e.artifact == "netconn_temporal" && e.detail.contains("存在性")));
    }

    #[test]
    fn different_pid_netconn_not_attached() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            Record::NetConn(NetConnRecord {
                proto: "tcp".to_string(),
                laddr: "10.0.0.5".to_string(),
                lport: 51000,
                raddr: Some("203.0.113.5".to_string()),
                rport: Some(4444),
                state: Some("established".to_string()),
                pid: Some(999),
            }),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty(), "netconn owned by a different pid must not attach");
    }

    #[test]
    fn no_usn_and_no_netconn_produces_no_finding() {
        let start = Utc::now();
        let records = vec![process_with_start_time(100, r"C:\evil.exe", Some(start))];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty());
    }
}
```

**implementer 注意**：`NetConnRecord` struct literal 裡的欄位（`proto`,
`laddr`, `lport`, `raddr`, `rport`, `state`, `pid`）**必須先用 Read 工具核對
`crates/cairn-core/src/record.rs:56-65` 的實際定義**再撰寫，本計畫列出的
欄位名稱與型別是基於既有 `netconn.rs` 用法推斷，若與實際定義不符（欄位
順序、Option 包裹與否、命名），依實際定義調整，不要臆測。

- [ ] **Step 2: 跑測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo test -p cairn-heur temporal
```

Expected: 10 個測試全部通過。若某個測試失敗，對照 `analyze()` 的邏輯與
測試資料的時間/pid 是否吻合，修正邏輯或測試資料本身的錯誤——不要放寬
斷言標準讓測試通過。

- [ ] **Step 3: 接線進 `main.rs`（兩處清單）**

在 `crates/cairn-cli/src/main.rs` 的正式 `run_live` 分析器清單（約
878-894行），`Box::new(cairn_heur::PersistHeuristic),` 之後新增：

```rust
        Box::new(cairn_heur::TemporalWindowCorrelator),
```

在測試 `live_analyzers_include_all_heuristics` 的清單（約 1280-1295行），
同樣在 `Box::new(cairn_heur::PersistHeuristic),` 之後新增同一行，並在該
測試已有的 `assert!` 群組後新增：

```rust
    assert!(
        analyzers.iter().any(|a| a.name() == "heur_temporal"),
        "temporal window correlator must be registered"
    );
```

（`TemporalWindowCorrelator` 是無欄位的 unit struct，不需要 `::new(...)`
建構子，直接 `Box::new(cairn_heur::TemporalWindowCorrelator)`。）

- [ ] **Step 4: 跑 cairn-cli 測試**

```bash
cargo test -p cairn-cli live_analyzers_include_all_heuristics
```

Expected: 通過。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/temporal.rs crates/cairn-cli/src/main.rs
git commit -m "test(heur): add TemporalWindowCorrelator unit tests; wire into live pipeline"
```

---

## Task 4: 整合測試 + 全 workspace 驗證

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`（新增一個 `#[test]` 函式）

- [ ] **Step 1: 讀取 `run_live`/`RunOutcome` 實際簽名確認**（沿用段4-C
  Task 5 已驗證過的簽名，本計畫直接引用，但 implementer 仍應用 Read 工具
  核對 `crates/cairn-core/src/orchestrator.rs` 的當下狀態，避免中間有其他
  改動）：

  ```rust
  pub fn run_live(
      cfg: &Config, privileges: Privileges, hostname: String,
      collectors: &[Box<dyn Collector>], analyzers: &[Box<dyn Analyzer>],
  ) -> RunOutcome
  ```

- [ ] **Step 2: 新增端到端整合測試**

在 `crates/cairn-cli/src/main.rs`，緊接在既有的
`logon_bruteforce_heuristic_fires_in_live_outcome`（段4-C新增）之後，新增：

```rust
/// Integration: TemporalWindowCorrelator, wired after PersistHeuristic in
/// run_live's analyzer chain, attaches USN evidence to a persist Finding that
/// has entity.process populated (S9 execution hit) and escalates its severity.
#[test]
fn temporal_window_correlator_fires_in_live_outcome() {
    use cairn_core::manifest::Privileges;
    use cairn_core::orchestrator::run_live;
    use cairn_core::record::{ProcessRecord, Record, UsnEventRecord};
    use cairn_core::traits::{CollectCtx, Collector};
    use chrono::Utc;

    struct FixedRecordsCollector(Vec<Record>);
    impl Collector for FixedRecordsCollector {
        fn name(&self) -> &str {
            "fake_temporal_records"
        }
        fn collect(&self, _ctx: &CollectCtx<'_>) -> cairn_core::Result<Vec<Record>> {
            Ok(self.0.clone())
        }
    }

    let start = Utc::now();
    let pr = ProcessRecord {
        pid: 777,
        ppid: 1,
        image: r"C:\Users\victim\AppData\Local\Temp\evil.exe".to_string(),
        cmdline: String::new(),
        signed: Some(false),
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: None,
        start_time: Some(start),
    };
    let usn = UsnEventRecord {
        ts: start + chrono::Duration::minutes(1),
        path: r"C:\Temp\dropped_payload.dll".to_string(),
        reason: "create".to_string(),
        mft_ref: 1,
    };

    let cfg = cairn_core::Config::default();
    let privs = Privileges {
        admin: false,
        se_backup: false,
        se_debug: false,
    };
    let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FixedRecordsCollector(vec![
        Record::Process(pr),
        Record::UsnEvent(usn),
    ]))];
    // Only TemporalWindowCorrelator; supply its prior_findings input directly
    // isn't possible via run_live (analyzers run in isolation per this harness
    // unless wired via depends_on), so this test wires PersistHeuristic ahead
    // of it to produce the real prior_findings entry end-to-end — verifying
    // Task 0's entity.process fix and Task 2's consumption of it together.
    // NOTE: PersistHeuristic requires a Record::Persistence entry that S9-hits
    // this ProcessRecord's image path to produce a Finding with entity.process
    // populated; implementer must construct that fixture using the same
    // PersistenceRecord field names verified in Task 0.
    let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
        Box::new(cairn_heur::PersistHeuristic),
        Box::new(cairn_heur::TemporalWindowCorrelator),
    ];

    let outcome = run_live(&cfg, privs, "TEST".into(), &collectors, &analyzers);

    let temporal_finding = outcome
        .findings
        .iter()
        .find(|f| f.artifact == "temporal_window");
    assert!(
        temporal_finding.is_some(),
        "temporal window finding must be present when persist Finding has entity.process \
         and a USN event falls within the window; got findings: {:?}",
        outcome.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
```

**implementer 注意**：這個測試需要一筆 `Record::Persistence` 讓
`PersistHeuristic` 產生帶 `entity.process` 的 Finding（S9 命中）——
implementer 需要用 Task 0 驗證過的相同 `PersistenceRecord` 欄位建構方式
（`mechanism`/`binary_path` 等，需與 `pr.image` 透過 `join_key` 命中）
補上這筆記錄到 `collectors` 的 `FixedRecordsCollector` 資料裡。若
`depends_on` 排序機制在 `run_live` 裡的實際執行方式與預期不同（例如
`prior_findings` 傳遞方式），需要讀取 `orchestrator.rs` 的
analyzer 執行迴圈確認，不要臆測。

- [ ] **Step 3: 跑測試**

```bash
cargo test -p cairn-cli temporal_window_correlator_fires_in_live_outcome
```

Expected: 通過。若失敗，先確認 `PersistHeuristic` 的 fixture 是否真的觸發
S9 命中（可以先跑 `cargo test -p cairn-heur persist` 裡的
`s9_execution_hit_populates_entity_process` 測試作為隔離驗證，確認 Task 0
的邏輯本身沒問題，再排查整合層的接線）。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "test(cli): add end-to-end integration test for TemporalWindowCorrelator"
```

- [ ] **Step 5: 全 workspace check/test/clippy/fmt**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: 全部通過，0 failed，零 clippy 警告。若 `cargo fmt --check` 抓到
未格式化程式碼（歷來每段都會發生，因為計畫裡的程式碼片段未跑過
`cargo fmt`），跑 `cargo fmt` 修正後重新確認並補一個 commit。

- [ ] **Step 6: 若 Step 5 有 fmt 修正則 commit**

```bash
git add -A
git commit -m "style: cargo fmt on TemporalWindowCorrelator"
```

---

## Self-Review

**1. Spec coverage：**
- Task 0（persist.rs 補填 entity.process）→ 對應 spec「前置修正」段落，符合。
- Task 1（escalate() 搬到 score.rs）→ 對應 spec「共用重構」段落，符合。
- 獨立 Analyzer + depends_on(["heur_persist", "heur_parentchild"]) → Task 2，符合。
- 反查機制用 entity.process.pid + by_pid 索引（非路徑字串比對）→ Task 2 `analyze()` 邏輯，符合。
- 5分鐘固定時間窗、USN不限路徑、NetConn存在性非時序、200筆量控三步驟、誠實用語 → Task 2 全部實作，Task 3 有對應回歸測試（`usn_event_in_different_directory_still_attaches`、`over_200_usn_events_are_capped_with_summary_note`）。
- entity.process 缺失時跳過（刻意設計非缺陷）→ Task 3 `missing_entity_process_on_prior_finding_skips` 測試。
- start_time=None 跳過 → Task 3 `missing_start_time_skips_temporal_expansion` 測試。
- severity escalate 一級 → Task 2 用 `crate::score::escalate`，Task 3 測試驗證 Medium→High。
- 端到端整合驗證 Task 0+Task 2 串接 → Task 4。
- 全 workspace 驗證 → Task 4 Step 5。

**2. Placeholder 掃描：** 所有 Step 都有具體程式碼。Task 0 Step 3 與 Task 4
Step 2 明確標註「implementer 需要先讀取既有 fixture helper 命名/欄位再
調整」是誠實的資訊缺口標註（因為探查階段沒有完整讀到 `persist.rs` 測試區
與 `PersistenceRecord` 完整欄位定義），不是偷懶——每處都給了具體的核對
方法與已知的部分資訊（如 `mechanism`/`binary_path` 欄位名稱線索）。

**3. Type 一致性：** `TemporalWindowCorrelator`（無欄位 unit struct，
`Box::new(cairn_heur::TemporalWindowCorrelator)` 不帶 `::new(...)`）在
Task 2 定義、Task 3/4 使用方式一致。`EntityProcess`/`ProcessRecord` 欄位
命名全計畫一致（`pid, ppid, image, cmdline, signed, integrity`／
`ProcessRecord` 多出 `signer, binary_sha256, user, start_time`）。

**4. 執行順序相依性：** Task 0（persist.rs 修正）→ Task 1（escalate 搬遷，
與 Task 0 各自獨立可平行，但兩者都改 persist.rs，實務上序列較安全）→
Task 2（temporal.rs 核心邏輯，依賴 Task 0 的 entity.process 填值語意與
Task 1 的共用 escalate）→ Task 3（測試+接線，依賴 Task 2 的型別）→
Task 4（整合測試，依賴 Task 0+Task 2+Task 3 全部接線完成）。Task 0 與
Task 1 都修改 `persist.rs`，若要平行派工需序列處理（同檔案衝突風險，
cairn-dev-loop 既有教訓）；Task 3/4 都改 `main.rs`，同樣序列處理。
