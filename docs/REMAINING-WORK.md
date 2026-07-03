# Cairn — 最後補齊路線圖 (Remaining Work)

> 盤點日期：2026-06-28（更新）。本檔是**待辦索引 + 排序 + 已知風險登記**，不是設計 spec，
> 也不是逐步實作計畫。每一段（segment）開工前**仍須各自跑 brainstorming → writing-plans
> → subagent-driven-development**；本檔只決定「做哪些、什麼順序、各自的已知坑」。
>
> 權威來源：`cairn-SRS.md`（§4 collector 表、§16 stage gate、NFR9-12）。
> 進度記憶：`~/.claude/projects/.../memory/MEMORY.md`。

---

## 目前位置（2026-07-03）

- **IR Snapshot Panels**（`feature/ir-snapshot-panels` 分支，10 task subagent-driven）✅
  **完成**——把已收集但埋在 records.jsonl 的 IR 關鍵資料攤成 report.html 的折疊面板。
  設計：`docs/dev-history/specs/2026-07-03-ir-snapshot-panels-design.md`；
  計畫：`docs/dev-history/plans/2026-07-03-ir-snapshot-panels.md`。
  - **起因**：使用者反饋「跑完看不到有用資訊」；查證後發現根因是呈現層問題，不是收集層——
    proc/net/execution/USN/MOTW 全部已收集，只是 `html_report()` 拿不到 records。
  - `html_report()` 簽名加 `records: &[Record]` 參數（連帶 `OutputSink` trait + 全部 caller），
    解鎖五個純呈現面板：
    1. **對外連線**（established/listening，公網連線排前）
    2. **執行中程序**（未簽章排前）
    3. **近期執行證據**（末次執行新的排前，prefetch 誠實標「僅檔名」）
    4. **可疑檔案活動**（MOTW 標記檔案排前 + USN create/rename，200 筆量控 + 總數誠實註記）
    5. **登入 session**（新 `LogonSessionCollector`，RDP/RemoteInteractive 排前）
  - 新增 `Record::LogonSession` 變體 + `LogonSessionRecord`（`user`/`logon_type`/`logon_time`/
    `source`/`session_id`）；`cairn-collectors-win/src/logon.rs`（WTS API `WTSEnumerateSessionsW`
    unsafe FFI，唯讀官方 API，符合 golden rule 1/3）+ `cairn-collectors/src/logon_session.rs`
    安全包裝，forbid-unsafe 維持。
  - **零新偵測邏輯**——五個面板全部純呈現，findings 數量不受影響（真機驗收全程維持 0）。
  - **真機驗收**（2026-07-03，分兩階段）：非 admin 掃描確認對外連線（168 條/93 條公網）+
    執行中程序（278 個/4 個未簽章）正確渲染；admin 掃描（有 Administrator 但無 SeBackupPrivilege）
    確認近期執行證據（365→381 條，來自 prefetch 部分成功）+ 登入 session（1 條，接進
    `selected_modules`）正確渲染；可疑檔案面板因本機無 USN record（缺 SeBackupPrivilege）+
    無 MOTW 檔案而空白，屬正確的「無資料不輸出」行為，非缺陷。
  - **開發中修正**：`WTS_CLIENT_ADDRESS` 的 IPv4 位元組配置無法在此環境驗證，`client_address`
    誠實留 `None`（NFR12 精神：寧可不猜，不可猜錯）——**已知殘留項**，未來若需要遠端登入來源
    IP，需找到 windows crate 該版本的權威位元組配置文件再補上。
  - **既有殘留限制（非本次引入，記錄延續）**：`mft`/`usn`/`shimcache`/`amcache`/`bam`/
    `userassist`/`srum` 除了 Administrator 還需額外的 **SeBackupPrivilege**（一般「以系統管理員
    身分執行」不會自動附帶，需 `psexec -s` 或群組原則另外授予）。這導致一般 admin 掃描仍看不到
    完整的可疑檔案活動面板；不在本次計畫範圍內。
  - 全 workspace 測試綠、clippy 零警告。**待辦事項：merge 回 main**（finishing-a-development-branch）。
  - **Opus 整體審查抓到並修正的真缺陷**：`logon_session.rs` 原本用永遠是 `None` 的
    `client_address` 判斷 `logon_type`，導致「RDP 排前」這個面板核心功能在真機上永遠失效
    （每個 session 都被標成 Interactive）。修正：改讀 `WTS_SESSION_INFOW.pWinStationName`
    （官方可靠、免猜位元組配置，RDP session 站名固定為 `RDP-Tcp#N`）。
  - **審查殘留項（低優先，未修）**：(1) `WtsSession.state_active`（session 是否為 Active
    連線狀態）已收集但目前沒有任何面板/邏輯讀取，可考慮未來顯示；(2)「對外連線」面板標題
    涵蓋 listener（其實是入站）與所有 UDP socket（`state=None`），標題語意略寬於實際內容，
    低影響的命名精確度問題。

## 前次位置（2026-07-02）

- **Heuristic Gate Redesign**（`feature/heuristic-gate-redesign` 分支，11 task subagent-driven）✅
  **完成**——修正 >90% 誤報率。設計：`docs/dev-history/specs/2026-07-02-heuristic-gate-redesign-design.md`；
  計畫：`docs/dev-history/plans/2026-07-02-heuristic-gate-redesign.md`。
  - Gate/Severity 分離模型：Finding 只在命中 S1a/S1b/S2/S3/S4/S9 決定性信號時才發，
    未命中的持久化項目走新 `Observation` 通道（`observations.jsonl` + HTML 折疊區塊）。
  - `CorrelationAnalyzer` 刪除，交叉比對（執行證據 + 正在執行進程）併入 `PersistHeuristic`
    作為 severity 升級因子，不再單獨成立 Finding。
  - `signed=None` 語義修正：驗章前解析相對路徑（`explorer.exe` 等 winlogon 預設值）；
    `None` 不再是告警依據。
  - `Finding.evidence: Vec<EvidenceItem>` 結構化佐證來源（artifact/path/ts/detail），
    `details` 首行固定為完整路徑（原「待辦 A」需求，併入本次一次做完，**關閉**）。
  - `trust.rs` 集中信任知識（USER_WRITABLE_DIRS/PROTECTED_SYSTEM_NAMES/is_masquerade 等）。
  - netconn 加 gate floor（弱信號單獨不發）；parentchild 路徑信號改 amplifier + 新增 S3 偽裝信號。
  - **真機 e2e 驗收**（ASUS 筆電，2026-07-02）：**High=0、Medium=0、Low=0**（原 60 個含 1 High+27
    Medium 誤報全數消除），`observations.jsonl` 265 條（service 252/run_key 10/winlogon_default 2/
    startup 1），manifest counts 一致。**唯一發現的真缺陷**：S2 未排除 `startup` 機制的路徑檢查，
    導致 AnyDesk.lnk（Startup 資料夾本身就是持久化位置，非可疑 drop zone）誤觸發 High——e2e
    當場抓到、修正 gate 加 `path_signals_apply = mechanism != "startup"` 豁免、補回歸測試、重跑
    驗收後乾淨。**待辦 C（correlation 時間標注）視為已被 S4 recency 條件 + observation details
    帶 last_write 涵蓋，關閉**。全 workspace 測試綠、clippy 零警告。**待辦事項：merge 回 main**
    （finishing-a-development-branch）。
  - **Opus 整體審查殘留風險（接受，已文件化於 `persist.rs::analyze` 註解）**：
    `analyze()`/`observe()` 各自獨立呼叫 `Utc::now()`（orchestrator 分兩次呼叫），S4 的 7 天
    recency 邊界理論上可能在極窄時間窗（毫秒級）內漂移，導致單一 persistence record 同時
    出現在 findings 與 observations（或都不出現）。真正修復需改 `Analyzer` trait 簽名讓
    analyze/observe 共享時間戳，波及全部 6 個 analyzer + orchestrator，與影響面（非告警類
    盤點通道偶爾重複/遺漏一筆）不成比例——評估後採小範圍緩解（誠實註解 + 此處記錄），不修
    trait。另一低優先殘留項：`trust.rs` 的 `is_masquerade`/`is_under_windows_tree` 只認反斜線
    絕對路徑，正斜線或 UNC 路徑會abstain；目前所有 persistence collector 只產生反斜線路徑，
    屬理論風險。

## 前次位置（2026-06-28）

- **Stage 1**：✅ 全完成（EVTX + Sigma + timeline + manifest）。
- **Stage 2**：✅ **正式封頂**（main `df29f72`，2026-06-23）。
- **Stage 3**：✅ **完成**（main `5b210b7`，2026-06-25）。
- **Stage 4**：✅ update-rules（FR19）完成（main `f4bab7e`，2026-06-26）。
- **Post-S4 heuristic 補強**（2026-06-28，main `00b2efe`）：
  - `fix(heur)` `0a18758`：Correlation 嚴重性調整——依路徑可疑度 + 簽章狀態決定 High/Medium，修正 Chrome/Notion 誤報為 High 的問題。
  - `feat(heur)` `00b2efe`：AccountHeuristic——EID 4720/4726/4732/4728，近期（≤90天）→ High，歷史 → Medium。T1136.001/T1531/T1098.001。

測試：**547 pass，7 ignored（elevated e2e），1 ignored（network）**，零 clippy 警告。

---

## 待辦清單（依建議實作順序）

---

### 已完成段落（歸檔）

| 段 | 功能 | commit/PR | 完成日 |
|---|---|---|---|
| 1 | bam_collector | PR #24 `0ba542d` | 2026-06-22 |
| 2 | userassist_collector | PR #25 `df29f72` | 2026-06-23（S2 封頂）|
| 3 | srum_collector | PR #27 `9c0f2a4` | 2026-06-25 |
| 4 | output_sink（DirSink/ZipSink/AgeSink/DryRunSink）| main | 2026-06-25 |
| 5 | details_client（FR18）| `2fa6b03` | 2026-06-25 |
| 5b | bodyfile/plaso（FR20）| `5b210b7` | 2026-06-25 |
| 6 | update-rules（FR19，S4）| `f4bab7e` | 2026-06-26 |
| heur-P1 | Correlation 嚴重性調整 | `0a18758` | 2026-06-28 |
| heur-P2 | AccountHeuristic（EID 4720/4726/4732/4728）| `00b2efe` | 2026-06-28 |

---

### 待辦 A — Finding.evidence 結構化來源欄位（最高優先）

**問題**：調查者看到 Finding 只知道 binary 名稱，不知道：
- 完整路徑在哪
- 從哪幾個 collector 各自偵測到（prefetch？shimcache？run key？）
- 每個來源各自的時間戳、執行次數等

**解法**：在 `cairn-core::finding` 加入 `EvidenceItem` struct + `Finding.evidence: Vec<EvidenceItem>`。

```
EvidenceItem {
    artifact: String,           // "prefetch" | "shimcache" | "run_key" | "evtx:Security"
    path: Option<String>,       // 完整路徑（prefetch 只有檔名，誠實標注）
    ts: Option<DateTime<Utc>>,  // 該來源的時間戳
    detail: String,             // 人讀描述，例如 "執行次數: 12，首次: 2026-06-01"
}
```

**向後相容**：`#[serde(default)]` + `skip_serializing_if = "Vec::is_empty"`，舊 JSON 反序列化自動填空 Vec，schema 版本不變。

**需要更新的 analyzer**：
- `CorrelationAnalyzer`：每個 PersistenceRecord 一條（registry key + binary_path）、每個 ExecutionRecord 一條（path + source + 執行時間）
- `PersistHeuristic`：填 registry key / 檔案路徑
- `AccountHeuristic`：填 Security log 事件欄位（操作者、目標帳號、時間）
- `TimestompHeuristic`：填 $MFT 路徑 + MACB 四軸時間
- `SigmaAnalyzer`：選填（entity 已有，evidence 可留空）

**已知坑**：
- prefetch `path` 是檔名粒度（`EVIL.EXE`），非完整路徑——在 `detail` 說明「prefetch 格式限制，完整路徑需 shimcache/amcache 交叉比對」
- HTML 報告需配合更新以展示 evidence 清單
- schema 版本維持 `cairn.finding/1`（additive change，backward-compatible）

**估**：2 段（schema+analyzer 各一段）

---

### 待辦 B — HTML 報告強化（配合 evidence 欄位）

**問題**：`report.html` 目前是靜態表格，無法：
- 展開 Finding 看 evidence 明細
- 依 binary 名稱、artifact、severity 篩選
- 跨 Finding 關聯同一個 binary 出現在哪幾個地方

**解法**：
1. Finding 展開/收合（accordion）——點擊 row 展開 evidence 清單
2. 依 severity / artifact / title 關鍵字 client-side 篩選
3. 「同 binary 出現次數」摘要欄

**依賴**：待辦 A 先完成（evidence 欄位有資料才有意義）

**估**：1 段

---

### 待辦 C — Correlation 時間維度標注（P2，中優先）

**問題**：CorrelationAnalyzer 發現持久化 + 執行的交叉，但沒有說明持久化 entry 是什麼時候寫入的（`last_write`），調查者無法判斷是最近才裝的還是舊的合法軟體。

**解法**：在 correlation Finding 的 `reason` 裡加上 `last_write` 年齡標注：
- ≤ 90 天：`「近期建立（${n} 天前）」` → 升高關注度
- > 90 天：`「歷史建立（${n} 天前）」` → 降低優先度

**前提**：`PersistenceRecord.last_write` 已有值（run key / scheduled task 都有）

**估**：0.5 段（純邏輯，不改 schema）

---

### 待辦 D — 近期首執行 × 目前進程關聯（P3，中優先）

**問題**：目前 live 收集的 `ProcessRecord`（正在跑的進程）和 offline 解析的 `ExecutionRecord`（歷史執行記錄）是分開的，沒有 analyzer 把「正在跑 + 最近才第一次出現」這兩個信號結合。

**解法**：新 `LiveExecHeuristic`——比對 ProcessRecord.image 和 ExecutionRecord.path：
- 有 ProcessRecord 對應 AND ExecutionRecord.first_run ≤ 30 天 AND unsigned → High
- 有 ProcessRecord 對應 AND ExecutionRecord 完全缺席（新進程從未在 prefetch/shimcache 出現）→ High（可疑新進程）

**已知坑**：prefetch 只有檔名，比對時需正規化（basename 比對）

**估**：1 段

---

### 待辦 E — 對外連線異常強化（P3，中優先）

**問題**：`NetConnHeuristic` 目前只看單一 NetConnRecord，沒有跨進程分析：
- 同一個進程同時有多個不同國家 IP 的連線
- 正常 svchost 但 parent 是 wscript/cscript

**解法**：擴充 NetConnHeuristic 加入：
1. 同 PID 多連線聚合：超過閾值個不同 /24 段 → High
2. 進程 + 連線交叉：process 有可疑 parent + 有外連 → 升級 severity

**估**：1 段

---

### 待辦 F — 合法性層（給真實客戶用前必做；自用可跳過）

> 2026-06-22 決定：**自用階段先跳過。**

- Authenticode 簽章 + timestamp release
- 嵌入 version/manifest resource；發布 hash；open-source
- SOC pre-allowlist runbook（`docs/SOC-runbook-template.md`）
- 提交 binary 至 MS WDSI

---

## 建議執行順序

```
A（evidence schema）→ B（HTML 報告）→ C（correlation 時間）→ D（live exec 交叉）→ E（netconn 強化）
```

A + B 是最直接提升調查可用性的，先做。C/D/E 是 heuristic 精度補強，之後依需求排序。

---

## 跨段共通紀律（每段都適用）

- 每段 brainstorm → writing-plans → subagent-driven-development → finishing-a-development-branch。
- `#![forbid(unsafe_code)]` 在 cairn-collectors 維持；唯一 unsafe 在 cairn-collectors-win。
- 所有時間 UTC RFC3339；offline 解析器格式不認得就 **abstain**（NFR12），絕不謊報。
- graceful degrade（golden rule 8）：單檔/單 entry 失敗 skip + 旗標表面化，不中止整段。
- 每段 e2e 真機驗（raw-NTFS 段需 admin+SeBackup）。
- schema 零變動，除非該段明確要改（且需說明 backward-compat 策略）。
- Cargo.lock pin、新依賴先過 license/CVE/forbid-unsafe/供應鏈四關。
- 本機 clippy 必加 `--all-targets`（等同 CI）。CARGO_TARGET_DIR 在 OneDrive 外。
