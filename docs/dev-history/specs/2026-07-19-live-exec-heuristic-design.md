# LiveExecHeuristic 設計文件

- 日期：2026-07-19
- 狀態：spec 待審 → brainstorm 完成
- 來源待辦：`docs/REMAINING-WORK.md` 段 5（原待辦 D）
- 對應 backlog 描述：「正在跑（ProcessRecord）+ 最近才首次出現
  （ExecutionRecord.first_run ≤30 天）+ unsigned」→ High；
  「正在跑但執行文物完全缺席」→ High。

## 動機

`docs/dev-history/2026-07-10-resilience-audit.md` 沒有直接點名本項，但
`REMAINING-WORK.md` 段 5 明確列出這兩個訊號，是既有 heuristic 集合中尚未涵蓋的
缺口：目前沒有任何 analyzer 把「正在跑的行程」與「執行文物歷史」直接交叉比對。
`persist.rs` 的 `CrossIndex` 已經為持久化機制的「S9 gate」建了這套三來源
（prefetch/amcache/shimcache）索引基礎設施，但只用在持久化情境；本段把同一套
索引邏輯用在**所有正在跑的行程**上，填補「live process 沒有對應執行史」與
「live process 剛剛才第一次出現且未簽章」這兩類訊號的空白。

## 範圍

新增一個獨立 `Analyzer`：`LiveExecHeuristic`（analyzer name: `heur_live_exec`），
位於新檔案 `crates/cairn-heur/src/live_exec.rs`。不修改任何既有 analyzer 的行為。

## 資料來源與既有基礎設施複用

- `ProcessRecord`（`cairn-core::record`）：`pid`、`image`、`signed: Option<bool>`、
  `start_time`。
- `ExecutionRecord`（`cairn-core::record`）：`source`（`"prefetch"` /
  `"amcache"` / `"shimcache"`）、`path`、`first_run: Option<DateTime<Utc>>`。
  三個 collector 的語意差異（已於 brainstorm 階段查證，直接影響設計）：
  - **prefetch**（`crates/cairn-collectors/src/prefetch.rs:188-195`）：`path`
    是 `.pf` 檔內部 header 的 NAME 欄位（例：`NOTEPAD.EXE`），不含目錄、
    **也不含 hash 後綴**——`first_run`/`last_run` 取自 8 組 run_times 的
    min/max，是精確的執行時間戳。
  - **amcache**（`crates/cairn-collectors/src/amcache.rs:268-274`）：`path`
    是登錄機碼還原出的完整路徑，`first_run` 填的是登錄 subkey 的
    `LastWrite`，是「近似值」，不是真正的首次執行時間。
  - **shimcache**（`crates/cairn-collectors/src/shimcache.rs:234-240`）：
    `path` 是完整路徑，`first_run`/`last_run` **故意不填**（shimcache 的
    `last_modified` 是檔案 mtime，不是執行時間，collector 拒絕把它誤植為
    first_run）。
- 比對邏輯複用 `persist.rs` 現有的 `CrossIndex`/`build_cross_index`
  （`crates/cairn-heur/src/persist.rs:250-330`）：對 `ExecutionRecord` 建
  `exact`（`JoinKey`，路徑感知）與 `degraded`（純 basename，僅收
  `JoinKey::Name` 來源）兩層索引，`lookup_exec(key)` 回傳
  `(Vec<&ExecutionRecord>, bool 是否降級命中)`。**本段直接呼叫既有函式，不重寫
  索引邏輯**；若 `CrossIndex` 目前是 `persist.rs` 內部私有型別，實作階段需評估
  搬到 `score.rs`（比照段 11 `JoinKey` 搬遷、段 3 `escalate()` 搬遷的先例）
  供兩個模組共用。

## 已知坑澄清（更正 backlog 原始描述）

backlog 原文「prefetch 檔名粒度需 basename 正規化」在 brainstorm 階段查證後
**不成立**：這個坑指的是 `.pf` 檔案本身的檔名格式（`PROGRAM.EXE-A1B2C3D4.pf`，
同一程式不同執行路徑會產生不同 hash 前綴），但 `prefetch.rs` collector 從未把
`.pf` 檔名寫進 `ExecutionRecord.path`——它寫的是檔案內部 header 的 NAME 欄位，
本身就是純 basename、不含 hash。因此現有 `join_key()`（`score.rs:190-213`，
trim+去引號+小寫）已足夠處理 prefetch 來源的比對，**本段不需要新增額外的
正規化邏輯**。此澄清會回寫進 `REMAINING-WORK.md` 段 5 記錄，避免未來重工。

## 核心邏輯

對每一筆 live `ProcessRecord`：

1. 用 `join_key(&process.image)` 在三來源合併的 `CrossIndex` 中查詢（`exact`
   優先，降級到 `degraded` 純 basename 比對，沿用 `persist.rs` 既有的降級語意）。
2. **訊號 A（執行文物完全缺席）**：三個來源（prefetch/amcache/shimcache）**皆**
   查無結果（`exact` 與 `degraded` 都沒有命中任何一筆，來源不限）→ 觸發。
   - reason 誠實標注：「三個既有執行文物來源（prefetch/amcache/shimcache）均
     無記錄，不代表程式絕對未曾執行——各來源皆有已知限制（prefetch 僅保留近期
     ~1024 筆且 Windows Server 預設關閉；amcache/shimcache 有清除週期與大小
     上限）」。
3. **訊號 B（近期首見 + 未簽章）**：若至少一個來源有命中，取所有命中記錄中
   `first_run.is_some()` 的最早值（跨來源取 min，undefined 的 shimcache 記錄
   天然不參與比較）；若該值距今 ≤ `RECENT_DAYS`（模組常數，見下）**且**
   `process.signed == Some(false)`（`signed == None` 一律 abstain，不觸發，
   因為那是採集失敗/權限不足，不是「查證後確認未簽章」）→ 觸發。
   - reason 附註 amcache 語意差異：若最早命中來源包含 amcache，標注
     「first_run 來自 amcache 為 registry LastWrite 近似值，非精確執行時間戳」。
4. 訊號 A、B **天然互斥**：A 要求三來源皆缺席，B 要求至少一來源有紀錄命中。
   不需要額外去重或優先序判斷。

## Severity / Gate

沿用 `parentchild.rs`/`netconn.rs` 既有模式（weight 累加 → `severity_for(weight)`
→ 低於 gate floor 則 `continue` 不發），不做成寫死的字面 `Severity::High`：

- 訊號 A、B 各自設計成單一觸發即可達到 High 對應的 weight 門檻（具體數值於
  writing-plans 階段對照 `severity_for()` 現有分界值決定，保持與其他 heuristic
  的權重量級一致，避免同分不同義）。
- `depends_on()` 回傳空陣列——LiveExecHeuristic 完全獨立，不依賴任何其他
  analyzer 的 `prior_findings`（brainstorm 階段確認：兩個訊號只需要
  `ProcessRecord` + `ExecutionRecord` 本身，與 persist/netconn 無直接關聯，
  YAGNI；未來若發現需要跨 analyzer 佐證可再加 `depends_on`）。

## 參數化決定

`RECENT_DAYS`（訊號 B 的 30 天門檻）**先寫死為模組常數**，不進 `Config`——比照
`persist.rs::RECENT_DAYS`（現有先例：純模組常數、未進 Config）。目前沒有使用者
回饋要求可調整此門檻，YAGNI；未來有需求時提升為 Config 欄位（比照
`timestomp_threshold_hours` 模式）不困難。

## Finding 輸出

- `entity.process`：填 `pid`，讓下游（如未來的關聯分析）可反查。
- `artifact`：訊號 A 填 `"process"`（無執行文物可引用）；訊號 B 填命中的
  `ExecutionRecord.source`（`"prefetch"`/`"amcache"`/`"shimcache"`，取最早
  命中那筆的來源）。
- MITRE：暫定 `T1055`（Process Injection 不適用）改為 `T1204`（User Execution）
  或 `T1027`（Obfuscated Files or Information，若強調未簽章規避偵測）——實作
  階段依現有規則的 MITRE 標籤慣例對照確認，避免重蹈段 11 的誤用教訓
  （T1071→T1036 修正案例）。
- `reason` 必須包含第 3 節澄清的誠實用語（資料來源限制、amcache 近似值語意），
  不得省略。

## 測試計畫

比照 `netconn.rs`/`parentchild.rs` 既有測試風格：

- 純函式單元測試（`score_xxx()` 輸入輸出斷言）：
  - 訊號 A 觸發：三來源皆無記錄。
  - 訊號 A 不觸發：任一來源有記錄（即使 `first_run` 為 `None`，如 shimcache
    命中）。
  - 訊號 B 觸發：單一來源命中、`first_run` 在 30 天內、`signed == Some(false)`。
  - 訊號 B 不觸發：`signed == None`（abstain）。
  - 訊號 B 不觸發：`first_run` 超過 30 天。
  - 訊號 B 不觸發：`signed == Some(true)`。
  - 多來源命中時正確取最早 `first_run`（構造 prefetch 30 天內 + amcache
    40 天前的情境，驗證仍以 30 天內那筆為準而不觸發——因為訊號 B 定義是
    「最早的 first_run」，40 天前的那筆會讓最早值超過門檻，此案例驗證
    「取最早」而非「取任一」的邏輯正確性）。
- 一個端到端 synthetic integration test，串接真正的 `run_live` pipeline
  （比照 `byovd_driver_list_override_pipeline_end_to_end`、
  `sigma_analyzer_findings_appear_in_live_outcome` 先例），用假造的
  collector 資料驗證 Finding 真的能從 pipeline 產出。

## 待實作階段確認的技術細節（非設計爭議，寫進 writing-plans）

- `CrossIndex`/`build_cross_index` 目前是否為 `persist.rs` 私有型別；若是，
  搬遷到 `score.rs` 的具體 diff 範圍。
- weight 數值與 gate floor 的精確常數，對照 `severity_for()` 現有分界。

**已於 writing-plans 階段解決**：MITRE 標籤——查證後發現訊號A（完全無執行文物）
沒有任何 ATT&CK 技術能誠實對應「文物缺席」本身（可能是從未執行、可能是清除
痕跡、也可能只是 prefetch 關閉之類的覆蓋率缺口，三者無法區分），標記任何具體
技術都是過度宣稱；決定訊號A留空 `mitre: vec![]`，不憑印象硬套（呼應
judgment.md §4：查不到就是誠實標註，不是缺陷）。訊號B（近期+未簽章）採用
`T1036`（Masquerading），與 `netconn.rs`/`persist.rs` 既有「未簽章+可疑」類訊號
的標籤慣例一致。
