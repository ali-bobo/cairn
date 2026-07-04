# Temporal Window Correlator — Design Spec

> **Date:** 2026-07-04
> **Status:** Approved direction — pending user spec review
> **Scope:** (1) Real `ProcessRecord.start_time` collection; (2) a heuristic that
> attaches time-window-adjacent USN/NetConn evidence to already-gated suspicious
> processes. **This is NOT a causal chain engine** — see §2 for why, and §1 for the
> Windows API limitations that make a true causal chain infeasible.
> **Depends on:** heuristic gate redesign (main `068983e`) — reuses gate-first
> philosophy; persist.rs's execution-evidence escalation pattern is the template.
> **SRS refs:** §4 (collectors), §10 (heuristics), golden rules 6/8.

---

## 1. 問題陳述與技術限制查證（決定整份 spec 範圍的關鍵）

使用者問「能否做到 Intezer 式行為偵測」。查證後結論：Cairn 讀系統痕跡、Intezer 做
反組譯後程式碼基因比對，是完全不同的技術棧，不可能靠加 heuristic 達到。但可以做的
是補上「行為感」——把獨立的 Record 類型（Process/NetConn/UsnEvent）串成調查者一眼
看到的時間脈絡。**Brainstorm 逐項查證後發現三個 Windows API 固有限制，徹底改變了
原始設想的範圍：**

1. **`ProcessRecord.start_time` 目前恆為 `None`**——collector 用 `CreateToolhelp32Snapshot`
   /`PROCESSENTRY32W`，這個結構**沒有** creation time 欄位。可補（見 §3），但原本
   「行程建立→...」這條鏈的起點原先不存在。
2. **`NetConnRecord` 完全沒有時間戳**——`GetExtendedTcpTable`/`GetExtendedUdpTable`
   （`MIB_TCPTABLE_OWNER_PID`）是即時快照 API，**不提供連線建立時間**。要拿到真實
   連線時序需要 ETW 即時訂閱，是完全不同等級的監控機制（非本 spec 範圍）。
   **結論：連線只能做「同 PID 存在性關聯」，永遠不是時序關聯。**
3. **USN journal 不記錄操作行程的 PID**——這是 Windows USN 的固有設計（journal 只記
   檔案系統事件，不記發起者），要拿到「哪個 PID 寫的檔案」需要 ETW FileIO 即時訂閱。
   **結論：「行程→寫入檔案」無法精確歸因，只能做「時間窗口內的所有 USN 事件」的
   弱關聯，且不能限定路徑（見 §4.2 的路徑推論方向性錯誤）。**

**因此整條「行程建立→寫入檔案→載入→對外連線」四環因果鏈，實際上只剩第一環
（行程建立時間）是真實時序點；其餘都只能做「時間窗口重疊」或「存在性」關聯。**
這是本 spec 定名為「時間窗口關聯引擎」而非「因果鏈」的直接原因。

## 2. 目標與非目標

**目標**
1. `ProcessRecord.start_time` 真實收集（不再恆為 `None`）。
2. 一個新 heuristic `TemporalWindowCorrelator`：對**已通過**現有 gate（parentchild/
   persist）判定可疑的行程，用固定寬度時間窗口把該行程存活初期的 USN 事件與同 PID
   的網路連線，作為 evidence 附加到既有 Finding 上，並作為 severity 升級因子。
3. 誠實的語言：所有輸出必須明確標示「時間窗口關聯，非確認因果」，不使用「導致」
   「觸發」等因果字眼。

**非目標（明確排除，見 §1 的技術限制）**
- NetConn 時序排序——Windows 無此 API。
- USN → PID 精確歸因——Windows USN 固有限制。
- 任何形式的因果證明語言或因果判定邏輯。
- 獨立觸發器——這個引擎**不會自己判定行程可疑**，只服務已過 gate 的行程（見 §4.1）。
- 動態沙箱 / 程式碼相似度比對 / ML 模型——architecturally 排除，違反 golden rule 1/2
  與「唯讀鑑識工具」定位（詳見使用者原始問題的討論記錄，此處不重複）。
- ETW 即時監控——完全不同等級的機制，若未來要做需獨立 spec 評估（快照 vs 即時監控
  是架構層級的決定，非本 spec 範圍）。

## 3. Task 0：`ProcessRecord.start_time` 真實收集

### 3.1 技術路徑（查證結果：比預期便宜）
現有 `crates/cairn-collectors-win/src/proc.rs` 的 `full_image_path(pid)` **已經**對
每個 pid 呼叫 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)` 並用
`ProcHandle` RAII guard 管理生命週期（見該檔案 §71-105 行）。

**本 task 不新增一次 API 呼叫**——複用同一個已開啟的 handle，多呼叫一次
`GetProcessTimes(handle, &creation_time, ...)`（`windows` crate `Win32_System_Threading`
feature 已啟用，無需新依賴）。取 `creation_time`（`FILETIME`）轉換為 `DateTime<Utc>`
（複用 `cairn_core::time::filetime_to_utc`，已存在於其他 raw-NTFS collector）。

### 3.2 Graceful degrade（golden rule 8）
- `OpenProcess` 失敗（受保護行程、PPL、權限不足、行程已結束）→ 該筆 `start_time=None`，
  **`ProcessRecord` 其餘欄位正常產出**（現有 `full_image_path` 已是這個模式，
  `start_time` 走同一條 `?`/`None` 路徑，不新增失敗分支）。
- `GetProcessTimes` 失敗（handle 開得到但查詢失敗，理論上少見）→ 同樣 `None`，不 panic。

### 3.3 效能
複用既有 handle，理論上增量開銷極小（一次額外的輕量核心呼叫，非新開 handle）。
**仍需在 plan 階段實測**：跑一次含 200+ 行程的真機 live scan，比對加這個欄位前後的
`proc` collector 耗時（manifest 或 run.log 應有計時），確認無顯著劣化（如 >20% 或
絕對值 >500ms 增量）。若實測顯示有感劣化，需在 spec 補記錄取捨（本 spec 先假設可忽略，
以現有程式碼結構為依據，但誠實標示為「待驗證假設」）。

## 4. Task 1：`TemporalWindowCorrelator`

### 4.1 前提：只服務已過 gate 的行程（不自建觸發器）
這個 heuristic **不獨立判定可疑度**。輸入是 `ParentChildHeuristic`/`PersistHeuristic`
已經產生的 Finding（透過其 `entity.process`/`evidence` 反查對應的 `ProcessRecord`），
只對這些已確認可疑的行程做時間脈絡擴充。乾淨行程即使時間窗口內剛好有其他事件重疊，
也不會被拉進來——這是刻意設計，避免重蹈舊 weight-based 模型「巧合關聯製造誤報」的
覆轍（gate 重構的核心教訓）。

**實作機制**：`TemporalWindowCorrelator` 不是獨立跑在 orchestrator 的頂層 analyzer，
而是在 `PersistHeuristic`/`ParentChildHeuristic` 的 `analyze()` 內部，於既有的
「執行證據交叉升級」邏輯之後，追加一段時間窗口證據收集（複用 `persist.rs` 現有的
`build_cross_index`/`execution_evidence` 模式，新增一個 USN/NetConn 版本）。
**不新增獨立的 `Analyzer` 實作**——這維持「只服務已 gate 通過的行程」這個前提，
不需要額外的行程間傳遞機制。

### 4.2 時間窗口（固定寬度，非行程存活期間）
- **窗口**：`[start_time, start_time + 5 分鐘]`（固定寬度常數
  `TEMPORAL_WINDOW_MINUTES: i64 = 5`）。
- **為何不用「行程存活期間」**：Toolhelp snapshot 只有「目前正在跑」的行程列表，
  沒有行程結束時間；若行程開機時啟動、跑了數天，用存活期間當窗口會產生無界關聯
  （關聯到數天內所有 USN 事件），失去意義。固定窗口把範圍限制在「dropper 剛執行
  後的短時間內動作」這個 IR 直覺合理的場景。
- **5 分鐘是人為選擇的預設值，非實證最佳值**——誠實記錄為殘留風險（§6），未來
  可 Config 化。`start_time=None` 的行程（`OpenProcess` 失敗）無法計算窗口，
  該行程跳過時間窗口擴充（不影響原本的 Finding，只是沒有這層額外 evidence）。

### 4.3 USN 事件關聯（全部事件，不限路徑）
- **範圍**：時間窗口內的**全部** `UsnEventRecord`（`ts` 落在窗口內），**不依可疑行程
  的 image 路徑或推測的工作目錄過濾**。
  **為何不限路徑**：自審發現原始設計「只看行程所在目錄」的方向性錯誤——攻擊者
  典型模式是跨目錄寫 payload（如 `A.exe` 執行後在 `%TEMP%` 寫 `B.exe`，兩者不同
  目錄），限定路徑會系統性漏掉最常見的攻擊型態。
- **量控**：比照 IR snapshot panels 的模式，附加的 USN evidence 上限 200 筆
  （依 `ts` 排序取最舊 200 筆或全部，若 ≤200 則不需上限提示；若 >200，evidence 的
  summary 需註明「時間窗口內共 N 筆事件，僅附加前 200 筆」）。
- **Evidence 格式**：每筆 `EvidenceItem { artifact: "usn_temporal", path: Some(usn.path),
  ts: Some(usn.ts), detail: format!("時間窗口內的檔案事件（非確認因果）：{reason} {path}
  於 {ts}，行程建立於 {start_time}") }`——**detail 必須包含「非確認因果」字樣**。

### 4.4 NetConn 關聯（存在性，非時序）
- **範圍**：`NetConnRecord.pid == 該可疑行程的 pid`（現有 `pid` 欄位，非新增）。
- **無時間排序**——`NetConnRecord` 沒有時間戳（§1 查證），故不能說「連線發生在窗口內」，
  只能說「該行程目前有網路連線」。
- **Evidence 格式**：`EvidenceItem { artifact: "netconn_temporal", path: None,
  ts: None, detail: format!("同行程目前有網路連線（存在性關聯，非時序因果，
  NetConn 快照無時間資訊）：{raddr}:{rport} state={state}") }`。

### 4.5 Severity 升級
命中任一項（USN 窗口內有事件 / NetConn 存在性關聯）→ 複用 persist.rs 現有的
`escalate()` 升一級（封頂 Critical），並在 `reason` 追加
`"corroborated by temporal-window evidence — escalated"`（比照現有執行證據升級的
措辭風格，明確標示是「窗口關聯」不是新的獨立信號）。

## 5. 測試策略

| 層 | 單元測試 |
|---|---|
| Task 0 `start_time` | 純函式：FILETIME→DateTime 轉換往返；`OpenProcess`/`GetProcessTimes` 失敗路徑回 None 不 panic（用既有 fixture 模式，不需真機） |
| Task 1 USN 窗口 | 合成 fixture：窗口內事件 → 附加為 evidence；窗口外事件 → 不附加；跨目錄事件仍被納入（驗證 §4.3 的「不限路徑」修正）；>200 筆 → 量控 + 註記；`start_time=None` → 跳過時間窗口擴充但原 Finding 不受影響 |
| Task 1 NetConn | 同 PID → 存在性 evidence 附加；不同 PID → 不附加；evidence 的 `ts=None`（驗證誠實標示） |
| Task 1 升級 | 命中 USN 或 NetConn 任一 → severity escalate 一級；reason 含「escalated」與時間窗口用語；乾淨行程（未過 gate）即使巧合重疊也不產生任何輸出 |
| 誠實用語 | 所有新增 evidence 的 `detail` 字串必須含「非確認因果」或「存在性」等免責用語（測試斷言字串包含這些關鍵詞，防止未來修改時不小心用了因果語言）|

**真機驗收**：乾淨機器掃描，確認 `start_time` 大部分行程有值（少數受保護行程
`None` 屬預期）；若機器上有任何行程通過 parentchild/persist gate（正常情況下應為 0），
確認其 Finding 的 evidence 含時間窗口項且用語誠實；效能上與加此欄位前的 baseline
掃描時間比較（見 §3.3）。

## 6. 已知約束與殘留風險（實作前必讀）

1. **這不是因果鏈**——§1 的三個 API 限制是 Windows 平台固有的，非本專案能力不足。
   任何未來想「修復」這個限制的嘗試都需要先評估 ETW 即時監控這個完全不同的架構
   （快照式 vs 即時流式），不是加個欄位就能解決。
2. **5 分鐘窗口寬度是人為預設值**——沒有實證資料支撐這個數字，只是「IR 直覺合理」
   的起點。可能漏掉延遲執行（sleep 後才動作）的攻擊，也可能對正常但短時間內恰好
   有磁碟活動的行程產生較多 evidence（不是誤報，是 evidence 噪音——因為升級只在
   行程已過 gate 之後才發生，不會憑空產生新 Finding）。
3. **USN 200 筆量控可能截斷真正相關的證據**——若一個行程在窗口內產生大量正常
   I/O（如安裝程式），前 200 筆可能不包含真正可疑的那一筆。這是呈現層的取捨
   （同 IR panels 的量控哲學），完整資料仍在 `records.jsonl`。
4. **`OpenProcess` 對受保護行程失敗是預期行為**——防毒/EDR 自身行程、PPL 保護行程
   會使 `start_time=None`，這些行程本來就不太可能被 parentchild/persist gate 判定
   可疑，實務影響低。
5. **效能假設未經真機量化**（§3.3）——plan 階段必須實測，若證明有顯著劣化需要
   回頭調整（如平行化 API 呼叫，但這超出本 spec 範圍，屬於未來優化）。

## 7. 分段建議（交 writing-plans）

1. **段 1（Task 0）**：`start_time` 真實收集 + graceful degrade + 效能實測 + 單元測試。
   這段必須先完成且驗證效能可接受，才進段 2。
2. **段 2（Task 1）**：`TemporalWindowCorrelator` 邏輯（USN + NetConn 兩種證據）整合進
   `persist.rs`/`parentchild.rs` 既有的 evidence 組裝 + 單元測試（含「不限路徑」與
   「誠實用語」的回歸測試）+ 真機驗收。

沿用跨段共通紀律：`#![forbid(unsafe_code)]` 維持（Task 0 的 unsafe 在既有
`cairn-collectors-win` 邊界內，複用既有 handle，不新增 unsafe 面）、UTC RFC3339、
graceful degrade、Finding/Record schema 零變動（`start_time` 已是既有欄位只是填值；
evidence 是既有機制的新用法）、Cargo.lock 零變動（零新依賴）、本機 clippy --all-targets。
