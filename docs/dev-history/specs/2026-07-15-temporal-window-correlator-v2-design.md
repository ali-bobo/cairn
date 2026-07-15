# 段 3：TemporalWindowCorrelator（v2 — 獨立 Analyzer 架構）

- 日期：2026-07-15
- 基準：main HEAD `3e12599`
- 對應 backlog：`docs/REMAINING-WORK.md` 段 3
- 取代/更新：`docs/dev-history/specs/2026-07-04-temporal-window-correlator-design.md`
  （原 spec 頂端「2026-07-08 前提複查」已過時，本文件是重新查證後的更新版）

## 背景：原 spec 兩處已過時的前提

原 spec（2026-07-04，2026-07-08 複查）設計了「時間窗口關聯引擎」：對已通過
persist/parentchild gate 的行程，附加時間窗內的 USN 事件與同 PID 的 NetConn 作為
evidence，並升級 severity。核心目標與非目標（不是因果鏈引擎，見原 spec §1-§2）
完全沿用，本文件只更新兩處因後續開發而過時的前提：

1. **原 spec Task 0（`ProcessRecord.start_time` 真實收集）已在段 9 完成**——
   `crates/cairn-collectors-win/src/proc.rs:199-218` 的 `read_start_time()` 已存在，
   `proc.rs:409` 呼叫填值，`proc.rs:465-478` 有真機回歸測試。原 spec 頂端「仍恆為
   None」的複查記錄已過時。**本文件範圍縮小為只做原 spec 的 Task 1**（
   `TemporalWindowCorrelator` 本身），不重複實作 start_time 收集。

2. **原 spec §4.1 決定「不新增獨立 Analyzer，把邏輯塞進 persist.rs/parentchild.rs
   內部各寫一份」——本次重新查證後推翻**。段 10（`Analyzer::depends_on()` +
   `prior_findings` 機制）與段 11（`netconn.rs` 的獨立 Analyzer 讀取 persist
   Finding 佐證模式）已提供現成先例，改成獨立 Analyzer 消除跨兩個宿主檔案的邏輯
   重複，且不違反原 spec「只服務已 gate 通過的行程，不自建觸發器」的核心顧慮——
   `prior_findings` 只包含已經跑完、已經產生的 Finding，語意等價。

## 架構

新建 `crates/cairn-heur/src/temporal.rs`，`TemporalWindowCorrelator` 實作
`Analyzer` trait：

```rust
fn name(&self) -> &str { "heur_temporal" }
fn depends_on(&self) -> &[&str] { &["heur_persist", "heur_parentchild"] }
fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>> {
    // 對 prior_findings 裡每個帶 entity.process.pid 的 Finding：
    //   1. 用 pid 反查 records 裡的 ProcessRecord（拿 start_time）
    //   2. start_time 為 None → 跳過（無法計算時間窗）
    //   3. 收集時間窗內的 UsnEventRecord（線性掃描 + ts 區間過濾）
    //   4. 收集同 pid 的 NetConnRecord（存在性）
    //   5. 命中任一項 → 產生新 Finding，evidence 追加時間窗證據，severity escalate 一級
}
```

**反查機制**（本次查證確認的關鍵設計）：`TemporalWindowCorrelator` **不**掃描
`prior_findings` 的 evidence 路徑字串去比對（那是 netconn.rs 在沒有結構化 pid
可用時的退路）。它直接讀 `finding.entity.process.pid`（`EntityProcess` 結構化
欄位，`crates/cairn-core/src/finding.rs:36-44`），再對 `records: &[Record]` 建
`by_pid: HashMap<u32, &ProcessRecord>` 索引查回完整 `ProcessRecord`（含
`start_time`）。**若 `finding.entity.process` 是 `None`，該 Finding 被跳過**——
這是本次查證發現的真實缺口，見下方「前置修正」。

## 前置修正：`persist.rs` 需穩定填 `entity.process`

**查證發現**：`PersistHeuristic` 產生的 Finding 目前常填 `entity.file`/
`entity.registry`（`persist.rs` 的 `persistence_entity()`，約行 539-570），
**不保證**填 `entity.process`——即使該 Finding 確實對應一個具體行程（有
`ProcessRecord` 佐證存在）。這會讓 `TemporalWindowCorrelator` 對 persist 產生的
Finding 完全無法擴充（拿不到 pid）。

**修正**：在寫 `TemporalWindowCorrelator` 之前，先修 `persist.rs`，讓
`persistence_entity()`（或呼叫它的地方）在該 Finding 確實有對應
`ProcessRecord`（S9 執行證據交叉升級命中時）時，一併填入 `entity.process =
Some(EntityProcess { pid: pr.pid, ppid: pr.ppid, image: pr.image.clone(),
cmdline: pr.cmdline.clone(), signed: pr.signed, integrity: pr.integrity.clone()
})`——不改變現有 `entity.file`/`entity.registry` 的既有填值邏輯，是**新增**
`entity.process` 填值，不是替換。`ParentChildHeuristic` 的 Finding 本質就是
行程對行程的關係，預期已經穩定填 `entity.process`（實作階段核對確認，若也有
缺口一併修）。

這個修正本身有獨立的驗收條件（現有 persist 測試不能因此壞掉，且新增測試確認
`entity.process` 在符合條件時確實被填），是實作計畫的第一個 Task。

## 共用重構：`escalate()` 搬到 `score.rs`

`escalate()`（severity 升一級，封頂 Critical）目前是 `persist.rs` 的私有函式
（`persist.rs:33-41`）。`TemporalWindowCorrelator` 需要同樣的邏輯。比照段 11
把 `JoinKey`/`join_key` 從 `persist.rs` 搬到共用 `score.rs` 的先例，本次把
`escalate()` 也搬過去、改 `pub`，`persist.rs` 改用 `crate::score::escalate`，
`temporal.rs` 也用同一個函式。不重複邏輯。

## 時間窗與證據收集邏輯（沿用原 spec 核心，未變動部分不重複贅述）

- **時間窗**：`[start_time, start_time + 5 分鐘]`，固定寬度常數
  `TEMPORAL_WINDOW_MINUTES: i64 = 5`（見原 spec §4.2 的理由：Toolhelp snapshot
  無行程結束時間，固定窗口把範圍限制在「dropper 剛執行後」的合理場景）。
- **USN 事件比對**：**簡單線性掃描 + 時間區間過濾**（不建 HashMap 索引）——
  查證確認 `persist.rs` 的 `CrossIndex` 模式（`HashMap<JoinKey, Vec<&T>>`）是
  為路徑/pid 精確比對設計的，對連續時間區間查詢沒有幫助；`UsnEventRecord`
  沒有 `pid` 欄位（`record.rs:98-104` 確認），比對完全依賴 `ts` 落在時間窗內，
  對每個已過 gate 且有 `entity.process.pid` 的 Finding，線性掃描全部
  `Record::UsnEvent` 篩選 `ts` 落在窗口內的記錄。不限路徑（沿用原 spec §4.3
  「不限路徑」的修正理由：攻擊者常跨目錄寫 payload）。
- **NetConn 關聯**：`NetConnRecord.pid == 該行程的 pid`（存在性，非時序——
  `NetConnRecord` 沒有時間戳，`record.rs:57-65` 確認原 spec 前提仍成立）。
- **Evidence 數量上限**：沿用 `crates/cairn-report/src/html.rs:260,285-311`
  既有的三步驟模式——`const USN_EVIDENCE_CAP: usize = 200;` → 依 `ts`
  `sort_by_key(Reverse(ts))`（最新優先）→ `truncate(CAP)` → 若原始筆數超過
  上限，evidence 的 `detail` 或獨立一筆 summary evidence 註明「時間窗口內共
  N 筆事件，僅附加前 200 筆」，不靜默丟資料。
- **誠實用語**：所有新增 `EvidenceItem.detail` 必須包含「非確認因果」（USN）
  或「存在性關聯，非時序因果」（NetConn）字樣，沿用原 spec §4.3/§4.4 的格式：
  ```
  USN: "時間窗口內的檔案事件（非確認因果）：{reason} {path} 於 {ts}，行程建立於 {start_time}"
  NetConn: "同行程目前有網路連線（存在性關聯，非時序因果，NetConn 快照無時間資訊）：{raddr}:{rport} state={state}"
  ```
- **Severity 升級**：命中任一項（USN 或 NetConn）→ `score::escalate()` 升一級，
  `reason` 追加 `"corroborated by temporal-window evidence — escalated"`。

## 已知限制與殘留風險（更新版，含本次新查證的項目）

沿用原 spec §6 全部既有風險（因果鏈固有限制、5分鐘窗口為人為預設值、USN
200筆量控可能截斷、OpenProcess 對受保護行程失敗是預期行為、效能假設待驗證），
**新增**：

6. **`entity.process` 覆蓋率是新架構的先決條件**——`TemporalWindowCorrelator`
   只能擴充「有 `entity.process.pid`」的 Finding。若 `persist.rs` 的前置修正
   （見上）覆蓋不到所有應該有 process 語意的情境，會有 Finding 靜默不被擴充
   （不是錯誤，只是少一層 evidence，原 Finding 不受影響）——這與原 spec
   「乾淨行程不會被拉進來」是同一種刻意的保守設計，非缺陷。
7. **USN 比對是全域線性掃描，無 pid 過濾**——這是 `UsnEventRecord` 本身缺
   pid 欄位的 Windows 平台限制（USN journal 設計如此），不是本次實作的疏漏，
   原 spec §1 已詳述此限制的技術原因，此處重申其對 v2 架構同樣適用。

## 分段建議（交 writing-plans）

1. **Task 0（前置修正）**：`persist.rs` 補填 `entity.process`（含測試，確認
   既有測試不壞）。
2. **Task 1（共用重構）**：`escalate()` 搬到 `score.rs`，`persist.rs` 改用。
3. **Task 2（核心邏輯）**：`temporal.rs` 新建 `TemporalWindowCorrelator`，
   USN + NetConn 兩種證據收集 + severity 升級。
4. **Task 3（接線 + 測試）**：接進 `main.rs` 分析器清單（`depends_on` 機制
   保證排序在 persist/parentchild 之後執行）+ 單元測試（含「不限路徑」「誠實
   用語」「entity.process 缺失時跳過」「200筆量控」回歸測試）。
5. **Task 4（整合測試 + 全量驗證）**：端到端 synthetic integration test（
   仿照段 4-C 的 `run_live` 模式）+ 全 workspace 驗證。

沿用跨段共通紀律：`#![forbid(unsafe_code)]` 維持（本次改動全在
`cairn-heur`/`cairn-core`，無 unsafe 面）、UTC RFC3339、graceful degrade、
Finding/Record schema 零變動（`entity.process` 是既有欄位新增填值，非新增
schema）、Cargo.lock 零變動（零新依賴）、本機 clippy --all-targets。

## Out of scope

- ETW 即時監控（架構層級的完全不同機制，見原 spec §2 非目標）
- NetConn 時序排序、USN → PID 精確歸因（Windows API 固有限制，不可解）
- 5 分鐘窗口寬度 Config 化（YAGNI，沿用原 spec 決定，未來有實證需求再議）
- `persist.rs`/`parentchild.rs` 既有 gate 判定邏輯的任何修改（本次只新增
  `entity.process` 填值，不動 gate 本身）
