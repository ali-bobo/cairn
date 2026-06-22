# Cairn — 最後補齊路線圖 (Remaining Work)

> 盤點日期：2026-06-22。本檔是**待辦索引 + 排序 + 已知風險登記**，不是設計 spec，
> 也不是逐步實作計畫。每一段（segment）開工前**仍須各自跑 brainstorming → writing-plans
> → subagent-driven-development**；本檔只決定「做哪些、什麼順序、各自的已知坑」。
>
> 權威來源：`cairn-SRS.md`（§4 collector 表、§16 stage gate、NFR9-12）。
> 進度記憶：`~/.claude/projects/.../memory/MEMORY.md`。

---

## 目前位置（2026-06-22）

- **Stage 1**：全完成（EVTX + Sigma + timeline + manifest）。
- **Stage 2**：功能面幾乎封頂。已在 main：
  - live：proc / net / persist（Run/IFEO/service/sched-task/WMI sub/winlogon/startup）
  - heuristics：parent-child / persist / netconn + 校準
  - raw-NTFS：$MFT（MACB + timestomp + path map）、$J（USN）、offline hive reader
  - hive consumer：shimcache、amcache、amcache_driver
  - prefetch（第一個非 raw-NTFS offline collector）
  - governance：NFR9（--max-threads / --full-speed / --profile minimal / below-normal 優先權）、
    NFR10（per-artifact 記憶體上限 + truncation 表面化）
- **缺**：見下方。S2 只差 userassist/bam 即可宣告完整；S3/S4 整段未動。

SRS §16 的 S2 gate（admin 跑、非 admin 降級、零 target 寫入、persistence 涵蓋
WMI/sched/service/Run/IFEO）**核心都已達標**。

---

## 待辦清單（依建議實作順序）

### 段 1 — bam_collector（S2 收尾，輕）

- **SRS**：§4 `userassist/bam_collector` row、FR12、NFR12。
- **產出**：`Record::Execution` source=`"bam"`，per-SID 最近執行視窗（FILETIME）。
- **資料來源**：SYSTEM hive，`ControlSet001\Services\bam\State\UserSettings\<SID>`
  （部分 build 在 `bam\UserSettings`；須 brainstorm 時實證該機路徑）。每個 value 名是
  執行檔 NT 路徑、data 前 8 bytes 是 little-endian FILETIME。
- **複用**：`SYSTEM_HIVE` 常數、`open_hive`、`list_subkeys`（列 `<SID>` 子鍵）、
  `get_value_bytes`（取每個 value 的 binary）。**地基零擴充**。
- **新工作**：(a) 需要一個「列舉某 key 底下所有 value 名 + data」的 primitive——
  hive_reader 目前只有 `get_value_bytes`（單一已知 value 名）和 `list_subkeys`，
  **沒有「列出一個 key 的全部 values」**。這是本段唯一的地基新增（小，notatin 的
  CellKeyNode 應有 value 迭代器，brainstorm 時實證 API）。(b) 純解析 FILETIME（複用
  prefetch/usn 已有的 `filetime_to_utc`）。(c) SID→user_sid 直接用子鍵名。
- **mapping**：path=value 名（NT 路徑，如 `\Device\HarddiskVolume3\...`，誠實標示其為
  NT 路徑非 DOS 路徑，NFR12）；last_run=FILETIME；run_count=None；user_sid=SID；
  execution_confirmed=Some(true)。
- **已知風險**：低。唯一未知是「列舉 key 全部 values」的 notatin API，須實證。
- **估**：1 段（輕，等同 amcache 等級）。

### 段 2 — userassist_collector（S2 收尾，中重；需先擴充地基）

- **SRS**：§4 `userassist/bam_collector` row、FR12、NFR12。
- **產出**：`Record::Execution` source=`"userassist"`，GUI 啟動次數 + 最後執行時間，per-user。
- **資料來源**：**每個使用者各自的 `C:\Users\<name>\NTUSER.DAT`**，key=
  `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`。
  value **名**是 ROT13 編碼的執行檔路徑；value **data** 是 Win7+ 72-byte 結構
  （offset 4 = run_count u32；offset 60 = FILETIME 最後執行）。
- **本段是 S2 最後一塊也最貴的一塊。三項地基擴充（這就是它不能跟 bam 綁的原因）**：
  1. **動態 HivePath**：現有 `HivePath{components:&'static [&'static str]}` 是寫死常數，
     撐不住 per-user 動態路徑。須改成可接 owned/動態建構（不可破壞 SYSTEM_HIVE/
     AMCACHE_HIVE 兩個現有 consumer——保持向後相容）。
  2. **raw-NTFS 目錄列舉**：須列舉 `C:\Users\` 下所有子目錄。hive_reader 目前只有
     `find_child_dir`（單一已知名稱查找）。**`ntfs` 0.4 是否有乾淨的「iterate directory
     index 全部子項」API 是本段最大未知數，brainstorm 第一件事就是實證它**——
     底層 finder 走的就是 index，很可能能 iterate；若不行要 hand-roll，成本顯著上升。
  3. **per-user 開檔 + SID 反查**：每個 NTUSER.DAT 開一次 hive；userassist 在 NTUSER
     裡沒有 SID，user_sid 須從 ProfileList（SOFTWARE hive `ProfileList\<SID>\
     ProfileImagePath`）反查使用者目錄名——或誠實地只填使用者目錄名、user_sid=None。
- **新工作（純解析）**：ROT13 解碼 value 名（ASCII rotate，never-panic）；72-byte 結構
  bounds-checked 解 run_count + FILETIME。格式比 prefetch 穩定（無 version 漂移困擾）。
- **mapping**：path=ROT13 解碼後的執行檔路徑；run_count=offset 4；last_run=offset 60
  FILETIME；user_sid=ProfileList 反查或 None；execution_confirmed=Some(true)。
- **已知風險**：中。卡在 `ntfs` 目錄列舉 API + 動態 HivePath 重構不破壞現有 consumer。
- **估**：1 段（中重，含地基擴充）。

> **段 1 + 段 2 完成 = Stage 2 正式封頂。** 之後可宣告 S2 done。

---

### 段 3 — srum_collector（S3，**可行性風險最高，可能 cut**）

- **SRS**：§4 `srum_collector` row（標 stage 3）、D2（「ESE crate 成熟度 TBD，可能 slip/cut」）、
  FR12、NFR12。
- **產出**：`Record::Execution`，per-app/user 資源 + 網路位元組數（SRUDB.dat）。
- **資料來源**：`C:\Windows\System32\sru\SRUDB.dat`，**ESE (Extensible Storage Engine)
  資料庫格式**——與前面所有 collector 的格式（registry hive / 自訂 binary）完全不同。
- **本段的特殊性：brainstorm 的主任務是「可行性 + crate 抉擇」，不是實作細節。**
  - 須查證有無**乾淨的純 Rust ESE parser**（license MIT/Apache、forbid-unsafe 或 unsafe
    可控、無已知 CVE、近期有維護）。若只有 C FFI 綁定或 GPL crate → 可能直接判 **cut**
    （GPL 會傳染簽章 binary；C FFI 違反 forbid-unsafe 邊界與供應鏈規範）。
  - 若無可用 crate，選項：(a) cut srum，文件化「ESE 無可用純 Rust parser，srum 延後/不做」；
    (b) 評估 hand-roll ESE（成本極高，**不建議**，ESE 是複雜 B+tree 格式）。
- **已知風險**：**高**。光 brainstorm 可能就燒掉半段甚至直接判 cut。**不要在沒確認 crate
  之前排進實作。**
- **估**：1~2 段，或 0（cut）。

### 段 4 — output_sink / 封裝層（S3，安全審查重）

- **SRS**：FR15（單一 zip + manifest，選用非對稱加密、只嵌公鑰）、FR16（`--dry-run` 虛擬
  封裝、零 target 寫入）、FR17（footprint 最小化、必要時還原原始時間戳）、NFR11（輸出
  體積紀律：預設只打包 findings+manifest+run.log+evidence 片段，**不**整包 $MFT/$J/full
  hive，除非 `--collect-raw`）。
- **產出**：`cairn-report` 的 output_sink 完整化（dir / zip / encrypted / dry-run 四模式）。
- **安全邊界（審查會比一般 collector 重）**：
  - 加密：只嵌入**公鑰**（私鑰永不進 binary）；非對稱（RSA/age）封裝，符合全域「禁止硬編
    憑證」。
  - `--dry-run` 必須**真的零寫入**（golden rule 4），須有測試證明 target 無任何 byte 變動。
  - off-target 預設輸出位置（golden rule 4）。
- **已知風險**：中。加密選型（rsa crate vs age）+ dry-run 零寫入驗證 + zip 串流避免
  記憶體爆（NFR10/NFR11）。
- **估**：1~2 段。

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
| S2 正式封頂（段 1+2） | **2** | bam 輕、userassist 中重（含地基擴充） |
| S3 功能完整（段 3+4+5） | **+3~5** | srum 可行性風險最高，可能 cut 變 +2~4 |
| S4 全功能（段 6+7） | **+2~3** | update-rules 安全審查最重 |
| **合計（自用，含 S4）** | **約 7~10 段** | srum cut 則約 6~8 |

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
