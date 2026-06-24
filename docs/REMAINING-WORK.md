# Cairn — 最後補齊路線圖 (Remaining Work)

> 盤點日期：2026-06-25（更新）。本檔是**待辦索引 + 排序 + 已知風險登記**，不是設計 spec，
> 也不是逐步實作計畫。每一段（segment）開工前**仍須各自跑 brainstorming → writing-plans
> → subagent-driven-development**；本檔只決定「做哪些、什麼順序、各自的已知坑」。
>
> 權威來源：`cairn-SRS.md`（§4 collector 表、§16 stage gate、NFR9-12）。
> 進度記憶：`~/.claude/projects/.../memory/MEMORY.md`。

---

## 目前位置（2026-06-25）

- **Stage 1**：✅ 全完成（EVTX + Sigma + timeline + manifest）。
- **Stage 2**：✅ **正式封頂**（main `df29f72`，2026-06-23）。已在 main：
  - live：proc / net / persist（Run/IFEO/service/sched-task/WMI sub/winlogon/startup）
  - heuristics：parent-child / persist / netconn + 校準
  - raw-NTFS：$MFT（MACB + timestomp + path map）、$J（USN）、offline hive reader
  - hive consumer：shimcache、amcache、amcache_driver
  - prefetch（第一個非 raw-NTFS offline collector）
  - bam（PR #24，main `0ba542d`，2026-06-22）
  - userassist（PR #25，main `df29f72`，2026-06-23）
  - governance：NFR9（--max-threads / --full-speed / --profile minimal / below-normal 優先權）、
    NFR10（per-artifact 記憶體上限 + truncation 表面化）
- **Stage 3 部分完成**（main `9c0f2a4`，2026-06-25）：
  - srum_collector（PR #27，FR12）✅
  - output_sink（DirSink / ZipSink / AgeSink / DryRunSink，FR15/16/17）✅
  - details_client（FR18）⏳ **下一段**
- **Stage 4**：未動。
- 測試：**420 pass，7 ignored（elevated e2e）**，零 clippy 警告，schema 零變動。

SRS §16 的 S2 gate（admin 跑、非 admin 降級、零 target 寫入、persistence 涵蓋
WMI/sched/service/Run/IFEO）**全部達標**。S3 gate 部分達標（srum+output_sink；
待 details_client）。

---

## 待辦清單（依建議實作順序）

### ~~段 1 — bam_collector~~（✅ 完成，PR #24，main `0ba542d`，2026-06-22）

SYSTEM hive `{ControlSet}\Services\bam\State\UserSettings\<SID>` → per-SID `Record::Execution`
source="bam"。地基新增 `list_values`。真機 e2e 129 條零 abstain。

### ~~段 2 — userassist_collector~~（✅ 完成，PR #25，main `df29f72`，2026-06-23；**S2 封頂**）

per-user NTUSER.DAT → ROT13 解碼 → 72-byte 結構 → `Record::Execution` source="userassist"。
地基新增 `list_dir_names`（NTFS 目錄列舉）+ 動態 HivePath + ProfileList SID 反查。
真機 elevated e2e 326 條零 abstain。

### ~~段 3 — srum_collector~~（✅ 完成，PR #27，main `9c0f2a4`，2026-06-25；**S3 開端**）

`srum-parser 0.1.0`（MIT 純 Rust）+ `tempfile`，VolumeReader 讀 SRUDB.dat →
NamedTempFile 暫存 → parse → `srum_app` + `srum_net` 兩個 source。420 tests 綠。

### ~~段 4 — output_sink / 封裝層~~（✅ 完成，已在 main）

FR15/16/17：DirSink / ZipSink（zip crate）/ AgeSink（age X25519 非對稱加密）/ DryRunSink。
`--dry-run` 零寫入測試通過。`--encrypt` 只嵌公鑰，私鑰永不進 binary。symlink 拒寫測試通過。

### 段 5 — details_client（S3，i18n）

- **SRS**：FR18（每個 medium 以上 Finding 產 `details_client` zh-TW 白話說明）。
- **產出**：Finding → 客戶可讀的繁中說明欄位 + 渲染。
- **安全注意**：**禁止把 Finding 內的外部字串（rule 內容、樣本路徑）直接拼接進任何 LLM
  prompt**（若用 LLM 生說明）——須 XML 標籤隔離 + 去活性化（全域 Prompt Injection 防禦
  框架）。若改用**模板**（無 LLM）則無此風險，且更可重現——brainstorm 時優先評估模板路線。
- **已知風險**：低（模板路線）/ 中（LLM 路線，安全審查重）。
- **估**：1 段。

---

### 段 6 — update-rules（S4，網路 + 簽章驗證，安全審查最重）

- **SRS**：FR19（線上抓 Sigma 規則 + version pin + noisy/exclude/level-tuning 清單）。
- **這是全專案唯一允許 runtime 網路行為的功能（NFR6）**，安全要求最高：
  - 目標 URL 必須**白名單域名驗證**（防 SSRF，全域規範）。
  - 下載的規則須**驗證簽章/雜湊**後才採用（供應鏈防禦）；版本 pin。
  - 規則是**資料非程式碼**（ADR-0002 已定 XOR 編碼、decoded-as-data-never-executed）。
- **已知風險**：中高。網路白名單 + 簽章驗證 + 不破壞既有 rule-encoding 機制。
- **估**：1~2 段。

### 段 7 — bodyfile/plaso + Velociraptor 封裝（S4，匯出格式）

- **SRS**：FR20（bodyfile/plaso 匯出、選用 Velociraptor offline-collector artifact 封裝）。
- **產出**：既有 Record/timeline → bodyfile（mactime）/ plaso 格式匯出器。
- **已知風險**：低（純格式轉換，無新外部依賴風險）。
- **估**：1 段。

---

## 合法性層（任何 stage 上線「給真實客戶用」前必做；自用可跳過）

- Authenticode 簽章 + timestamp release（golden rule 2：release profile 維持正常，
  **不可** strip/panic=abort/UPX）。
- 嵌入 version/manifest resource；發布 hash；open-source。
- SOC pre-allowlist runbook（`docs/SOC-runbook-template.md`）。
- 提交 binary 至 MS WDSI。

> 使用者 2026-06-22 決定：**自用階段先跳過簽章/合法性層。**

---

## 總量估算（Opus 4.8，一段 ≈ 一個長 session）

| 里程碑 | 段數 | 備註 |
|---|---|---|
| S2 正式封頂（段 1+2） | ✅ **已完成** | |
| S3 srum + output_sink（段 3+4） | ✅ **已完成** | |
| S3 details_client（段 5） | ⏳ **進行中** | 下一段 |
| S4 全功能（段 6+7） | 未動 | update-rules 安全審查最重 |
| **剩餘（自用，含 S4）** | **約 3~4 段** | details_client(1) + update-rules(1~2) + bodyfile(1) |

---

## 跨段共通紀律（每段都適用，寫在這避免重複）

- 每段 brainstorm → writing-plans → subagent-driven-development → finishing-a-development-branch。
- `#![forbid(unsafe_code)]` 在 cairn-collectors 維持；唯一 unsafe 在 cairn-collectors-win。
- 所有時間 UTC RFC3339；offline 解析器格式不認得就 **abstain**（NFR12），絕不謊報。
- graceful degrade（golden rule 8）：單檔/單 entry 失敗 skip + 旗標表面化，不中止整段。
- 每段 e2e 真機驗（raw-NTFS 段需 admin+SeBackup；prefetch 教訓：medium-confidence 格式
  offset 必須真機 e2e 驗，自造 fixture 的單元測試會 false-positive）。
- schema（Record/Finding/Manifest）零變動，除非該段明確要改。
- Cargo.lock pin、新依賴先過 license/CVE/forbid-unsafe/供應鏈四關。
- 本機 clippy 必加 `--all-targets`（等同 CI）。CARGO_TARGET_DIR 在 OneDrive 外。
