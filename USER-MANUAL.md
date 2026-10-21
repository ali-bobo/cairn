# Cairn 使用手冊

> 版本：0.1.0 ｜ 最後更新：2026-10-21

---

## 目錄

0. [它怎麼運作、能幫你什麼](#0-它怎麼運作能幫你什麼)
1. [這是什麼](#1-這是什麼)
2. [支援平台](#2-支援平台)
3. [需要的權限](#3-需要的權限)
4. [安裝 / 取得 binary](#4-安裝--取得-binary)
5. [快速開始](#5-快速開始)
6. [指令參考](#6-指令參考)
7. [輸出格式說明](#7-輸出格式說明)
8. [Sigma 規則管理](#8-sigma-規則管理)
9. [常見情境](#9-常見情境)
10. [已知限制](#10-已知限制)

---

## 0. 它怎麼運作、能幫你什麼

這一章不假設你懂程式或資安術語，目的是讓你在按下「掃描」之前，知道 Cairn 實際在做什麼、以及它的結果為什麼值得信任。

### 三個階段：收集 → 分析 → 報告

Cairn 每次執行都分三步走：

1. **收集（唯讀）**：讀取這台電腦上的各種痕跡——事件日誌、目前執行中的程式、網路連線、開機自動啟動的項目等。這一步**只讀取，不修改任何東西**，也不會刪除或竄改電腦上原本的紀錄。
2. **分析**：把收集到的資料拿去比對兩種偵測邏輯。第一種是 **Sigma 規則**——業界共用的一套「什麼樣的行為算可疑」的偵測規則庫（類似防毒軟體的病毒特徵碼，但針對的是行為模式而非檔案本身）。第二種是**可解釋的啟發式偵測**——針對特定攻擊手法（例如程式偽裝、持久化後門、可疑網路連線）寫的判斷邏輯，每一筆判斷都會附上「為什麼觸發」的理由，不是丟給你一個看不懂的分數。分析結果會標上對應的 **ATT&CK 編號**——這是資安業界用來描述「這是哪一種攻擊手法」的標準對照表（例如編號 T1059 代表用命令列工具執行程式），方便你或資安工程師查閱該手法的詳細說明。
3. **報告**：把分析結果整理成一份時間軸與一份網頁報告，並附上 **SHA-256 雜湊**——一種數位指紋，任何人都可以重新計算來確認報告內容沒有被事後竄改。

### 為什麼可以信任這份結果

- **manifest（執行清單）誠實記錄每個模組的狀態**：哪些收集模組實際跑了、跑出幾筆資料；哪些因為權限不夠被跳過——跳過的原因會寫清楚，不會靜默失敗、假裝什麼都沒發生。
- **每個輸出檔案都有 SHA-256 雜湊**：報告產生後可以隨時重新驗證雜湊，確認檔案內容與產生當下完全一致，沒有被人動過手腳。
- **每個啟發式偵測結果都附「reason」欄位**：告訴你「為什麼這筆被標記為可疑」，而不是一個沒有解釋的黑箱分數。

### 什麼情境用它

當你懷疑某一台 Windows 電腦可能已經被入侵、需要快速判斷「這台機器有沒有問題、要不要進一步深入調查」時使用。它是**第一線快速篩檢（triage）工具**，目的是幫你在幾分鐘內縮小範圍；它**不是**完整鑑識調查的替代品——如果篩檢出高風險結果，仍需要專業的深入鑑識分析。

### 它不做什麼

- **不修改主機**：所有收集動作都是唯讀的，不會寫入、刪除或竄改這台電腦上的任何原始資料。
- **不迴避防護軟體**：Cairn 刻意設計成會被防毒/EDR（端點偵測與應變）軟體看見並辨識為正常程式，不會嘗試隱藏自己或繞過安全防護的偵測機制——這是設計原則，不是疏漏。
- **不連網**：所有指令都完全在本機執行，不會把你的資料傳到任何外部伺服器；程式本身不含任何連網功能。

---

## 1. 這是什麼

**Cairn** 是一支單一 Rust binary，專門給授權的事件應變（IR）分析師在 Windows 端點上執行快速分類（triage）：

- 解析 **EVTX 事件日誌**並比對 Sigma 規則
- 枚舉**即時系統狀態**（process tree、網路連線、persistence 機制、登入 session）
- 讀取 **Prefetch** 執行紀錄、WMI 訂閱與排程工作
- 套用**可解釋的 heuristic**（parent-child 異常、persistence dispositive-signal 判定、可疑網路連線、帳號異動、登入暴力破解、事件記錄清除與服務安裝、ClickFix）
- 輸出**帶 MITRE ATT&CK 標籤、SHA-256 完整性簽章的時間軸**、`report.html` 網頁報告和 manifest
- 提供 **`cairn-launcher`** 雙擊執行檔，讓非工程師使用者不需要背指令就能完成掃描

Cairn **不是**攻擊工具：不注入 process、不繞過 EDR、不混淆自身、不刪除 artifact。所有動作都記錄在 `run.log`，且它設計為對 EDR 可見並應被辨識為良性。

Cairn 以 **MIT License** 授權（詳見 `LICENSE` / `NOTICE`）；內建的 Sigma 規則另受其上游各自的授權條款規範（DRL 1.1，詳見規則檔內 `author`/`license` 欄位），不受本專案授權異動影響。

---

## 2. 支援平台

| 平台 | 支援度 | 備註 |
|------|--------|------|
| **Windows 10 / 11 x64** | ✅ 完整支援 | 所有 collector 均可用 |
| **Windows Server 2016 / 2019 / 2022 x64** | ✅ 完整支援 | |
| **Windows arm64** | ⚠️ 計畫中 | 目前僅 x64 CI |
| Linux / macOS | ❌ 不支援 | `cairn evtx` 可在 Linux 編譯，但 live collector 全部 Windows-only |

> **重要**：live process / network / persistence 等 collector 全部依賴 Windows API，在非 Windows 環境下會被自動跳過（graceful degrade），並在 manifest 中記錄原因。`cairn evtx`（純 EVTX + Sigma）可跨平台使用。

---

## 3. 需要的權限

| 功能 | 最低權限 | 備註 |
|------|----------|------|
| `cairn evtx`（EVTX 解析） | 標準使用者（可讀 .evtx） | |
| live proc / net 枚舉 | 標準使用者 | 其他 user 的 process 需 Admin |
| persistence 枚舉（Run keys、services、sched tasks、WMI subs） | 標準使用者（部分）/ Admin（全部） | |
| Prefetch | Administrator | `C:\Windows\Prefetch` ACL |
| Security 事件記錄（live EVTX） | Administrator | |

**缺少權限時 Cairn 不會 crash**：該 collector 會被跳過，在 `manifest.json` 的 `sources[].errors` 中留下說明，其餘 collector 繼續執行（golden rule 8）。

### 以提升權限執行

```powershell
# 在 Admin PowerShell 執行（建議）
.\cairn.exe run --target live --output C:\IR\case001

# 或透過 runas
runas /user:Administrator "cairn.exe run --target live --output D:\IR\out"
```

---

## 4. 安裝 / 取得 binary

### 一般使用者：雙擊執行 launcher（建議）

大多數使用者不需要記任何指令。從發布的封存檔解壓後，資料夾內會有：

```
cairn.exe             主分析引擎
cairn-launcher.exe     ← 雙擊這個
rules\sigma\          內建 Sigma 規則
USER-MANUAL.md
LICENSE / NOTICE
CHECKSUMS.txt         每個檔案的 SHA-256（打包時自動產生）
```

**雙擊 `cairn-launcher.exe` 就會直接開始掃描，沒有選單。**

1. Windows 會跳出「使用者帳戶控制」詢問是否允許執行，按「是」。以系統管理員身分執行，才讀得到 Security 事件記錄和其他使用者的登錄資料；如果你沒有管理員權限，仍然可以掃描，但部分檢查會略過，報告會寫明略過了什麼。
2. 如果 `cairn-launcher.exe` 放在系統磁碟（通常是 C:），畫面會警告「結果會寫進這台被調查電腦的硬碟」，並詢問是否繼續（預設 N，直接按 Enter 就會取消、不寫入任何檔案）。建議把整個資料夾複製到 USB 隨身碟再執行。
3. 輸入案件編號與操作人員（都是選填，直接按 Enter 略過），會記錄在 manifest.json。
4. 掃描這台主機最近 30 天的狀況，並把這段期間的事件記錄匯出到結果資料夾的 `evidence\evtx\`，通常需要幾分鐘，期間不要關閉視窗。
5. 跑完後畫面會顯示是否發現高風險項目，並自動做兩件事：
   - 把結果壓縮成一個 zip（路徑會顯示在畫面上），旁邊另有一個 `.zip.sha256` 記錄壓縮檔的雜湊值，兩個檔案一起交給資安人員；
   - 用預設瀏覽器打開 `report.html`。
6. 按 Enter 關閉視窗。

**分析別台電腦匯出的事件記錄**：把 `.evtx` 檔（或裝著 `.evtx` 的資料夾）直接拖到 `cairn-launcher.exe` 上。這時不會掃描這台主機，只分析拖進來的記錄，結果一樣會打包並打開報告。

`cairn-launcher` 會自動使用同資料夾內的 `cairn.exe` 與 `rules\sigma\`；找不到規則目錄時只跑內建偵測（不跑 Sigma 規則），並在畫面上提示。需要其他時間範圍或模組組合的工程師，請直接使用 `cairn run`（見第 6 章）。

### 工程師：從源碼編譯

```powershell
# 需要 Rust toolchain（https://rustup.rs）
git clone <repo>
cd cairn
cargo build --release --workspace
# binary 在 target/release/cairn.exe（另需 cairn-launcher.exe，同一 workspace 產出）
```

> **注意**：設定 `CARGO_TARGET_DIR` 指向 OneDrive 以外的路徑，避免 AV 鎖定 build probe：
> ```powershell
> $env:CARGO_TARGET_DIR = "C:\Users\<user>\AppData\Local\cairn-target"
> ```

### 驗證 binary 完整性

```powershell
# 確認 SHA-256 與發布的 hash 一致（或對照打包時產生的 CHECKSUMS.txt）
(Get-FileHash .\cairn.exe -Algorithm SHA256).Hash.ToLower()

# 確認版本與 build commit
.\cairn.exe --version
# cairn 0.1.0 (<build_sha>)
```

詳見 `docs/verifying-a-release.md`。

---

## 5. 快速開始

### 情境 A：純 EVTX 分析（不需 Admin）

```powershell
# 解析單一或多個 EVTX，比對 Sigma 規則
cairn evtx Security.evtx Sysmon.evtx --rules rules/sigma

# 輸出在當前目錄的 out/ 資料夾：
#   timeline.csv       偵測時間軸
#   findings.jsonl     詳細發現
#   report.html        網頁報告（含 IR 面板與篩選功能）
#   manifest.json      完整性清單
#   run.log            工具自身行動記錄

# 驗證輸出完整性
cairn verify out/manifest.json --rules rules/sigma
```

### 情境 B：完整 live triage（需 Admin）

```powershell
# 在 Admin PowerShell 執行
cairn run --target live --output D:\IR\case001 --case-id "IR-2026-001" --operator "analyst"

# 輸出：
#   D:\IR\case001\timeline.csv
#   D:\IR\case001\findings.jsonl
#   D:\IR\case001\report.html
#   D:\IR\case001\observations.jsonl
#   D:\IR\case001\records.jsonl
#   D:\IR\case001\evidence\evtx\*.evtx   （匯出的事件記錄，--no-export-evtx 可關閉）
#   D:\IR\case001\manifest.json
#   D:\IR\case001\run.log
#   （加上各 collector 子目錄的原始 record）

# 驗證
cairn verify D:\IR\case001\manifest.json --rules rules/sigma
```

### 情境 C：打包輸出 / 試跑

```powershell
# --zip 把輸出打包成 .zip（另寫 case001.zip.sha256），可直接驗證壓縮檔
cairn run --target live --output D:\IR\case001.zip --zip
cairn verify D:\IR\case001.zip

# dry-run：不寫入任何檔案，確認流程
cairn run --target live --output D:\IR\case001 --dry-run
```

### 情境 D：非工程師使用者——雙擊 launcher

不需要任何指令：雙擊 `cairn-launcher.exe` → 允許 UAC 提示 → 等待完成 → 畫面顯示是否發現高風險項目，報告自動打包並在瀏覽器打開。詳見第 4 章。

---

## 6. 指令參考

### `cairn run` — 完整 triage

```
cairn run --output <OUTPUT> [OPTIONS]
```

| 參數 | 說明 |
|------|------|
| `--target live` | 對當前 host 執行 live collection（預設值，也是唯一支援的值；離線 EVTX 請用 `cairn evtx`） |
| `--output <dir>` | 輸出目錄（建議 off-target：USB / 網路磁碟） |
| `--zip` | 輸出打包為 .zip |
| `--dry-run` | 模擬執行，零寫入 |
| `--rules <dir>` | 指定 Sigma 規則目錄（預設 `rules/sigma`） |
| `--profile minimal\|standard` | `standard`（預設）：全部 collector；`minimal`：跳過 Prefetch 與 live EVTX |
| `--only evtx_live,process,...` | 只跑指定 collector（逗號分隔） |
| `--since <RFC3339>` | 只分析（及匯出）指定時間之後的事件（預設：執行前 30 天） |
| `--export-evtx` / `--no-export-evtx` | 把 live EVTX 頻道（`--since` 範圍）匯出到輸出位置的 `evidence/evtx/<頻道>.evtx`，雜湊記入 manifest（預設開啟；`--dry-run` 或未選 `evtx_live` 模組時略過） |
| `--reference-time <RFC3339>` | 開始執行當下、從可信時鐘（手機 / NTP）讀到的 UTC 時間；manifest 會記錄主機時鐘偏差秒數（未提供時記為 not measured） |
| `--case-id <id>` | 案件編號（記入 manifest） |
| `--operator <name>` | 分析師姓名（記入 manifest） |
| `--full-speed` | 不降低 process 優先權（預設為 below-normal） |

### `cairn evtx` — 純 EVTX + Sigma

```
cairn evtx [FILES]... [--rules <dir>]
```

| 參數 | 說明 |
|------|------|
| `[FILES]...` | 一或多個 .evtx 檔案路徑 |
| `--rules <dir>` | Sigma 規則目錄 |

### `cairn verify` — 輸出完整性驗證

```
cairn verify <MANIFEST> [--rules <dir>]
```

重新計算 manifest 所列所有輸出的 SHA-256，並驗證 Sigma 規則集版本（ADR-0003）。任何不一致、或 manifest 的 outputs 是空的，則 exit code 非零。`<MANIFEST>` 也可以直接給 `--zip` 產生的 .zip：會讀取壓縮檔內的 manifest.json 驗證每個成員，並以旁邊的 `<zip>.sha256` 驗證壓縮檔本身（沒有 sidecar 時只警告）。

### `cairn coverage` — 偵測覆蓋範圍

```
cairn coverage [--rules <dir>]
```

列出內建 heuristic 與已載入 Sigma 規則涵蓋的 ATT&CK 技術（詳見 `docs/COVERAGE.md`）。

---

## 7. 輸出格式說明

每次 `run` 或 `evtx` 都會在 `--output` 目錄產生以下檔案：

### `timeline.csv` — 偵測時間軸

CSV 格式，每列代表一筆規則命中。欄位：

```
Timestamp, Host, Channel, EventID, Severity, RecordID, RuleTitle, RuleAuthor, MITRE, Details, Reason, Entity, DetailsClient
```

- Reason：heuristic 的判斷理由；Sigma 命中則寫「規則名稱、作者、等級、比對到的事件記錄編號」

- Severity：`critical` / `high` / `medium` / `low` / `info`
- MITRE：ATT&CK 技術 ID（例如 `T1059.001`）
- RuleAuthor：Sigma 規則作者（DRL 1.1 要求，每條命中都會帶）

### `findings.jsonl` — 詳細發現

JSON Lines 格式，每行一個 Finding。關鍵欄位：

```jsonc
{
  "schema": "cairn.finding/1",
  "id": "uuid",
  "ts": "2026-06-26T10:00:00Z",
  "severity": "high",
  "title": "Suspicious MSHTA Execution",
  "source": "sigma",
  "rule_id": "...",
  "rule_author": "...",
  "mitre": ["T1218.005"],
  "artifact": "evtx:Security",
  "details": "技術說明（英文）",
  "details_client": "中文白話說明（medium 以上 severity）"
}
```

### `report.html` — 網頁報告（IR 即時狀態面板）

單一自包含 HTML 檔案，供不熟悉 CLI 的使用者或需要快速視覺化的分析師開啟閱讀。包含以下面板：

- **連線（Connections）**：目前/近期網路連線狀態
- **程序（Processes）**：process tree 與可疑父子關係
- **執行（Execution）**：Prefetch 的程式執行紀錄
- **登入（Logon）**：登入 session 紀錄

報告內建**篩選與聚合功能**：可依嚴重度（critical/high/medium/low/info）、文物來源（artifact）、關鍵字篩選 finding 列表；同一個 binary（依路徑或雜湊判定同源）觸發的多筆 finding 會聚合到同一個面板，避免同一支程式的多筆事件洗版。

### `manifest.json` — 完整性與執行記錄

```jsonc
{
  "schema": "cairn.manifest/1",
  "run_id": "uuid",
  "host": {
    "hostname": "...", "os_build": "...", "timezone": "Taipei Standard Time (UTC+08:00)",
    "utc_offset_seconds": 28800,
    "wall_clock_utc_skew": "not measured (no network time source)",  // 有 --reference-time 時為 "+12s"
    "reference_time_utc": "...", "skew_seconds": 12                   // 只在有 --reference-time 時出現
  },
  "tool": { "version": "0.1.0", "build_sha": "...", "sigma_ruleset_ver": "<pin>+<hash>" },
  "sources": [
    { "name": "evtx:Security", "record_count": 1234, "sha256": "...", "errors": [] }
  ],
  "outputs": [   // 每個寫出的檔案（manifest.json 與 run.log 本身除外），dir 與 zip 皆同
    { "file": "timeline.csv", "sha256": "...", "size": 1234 },
    { "file": "records.jsonl", "sha256": "...", "size": 56789 },
    { "file": "report.html", "sha256": "...", "size": 4321 },
    { "file": "evidence/evtx/Security.evtx", "sha256": "...", "size": 1052672 }
  ],
  "governance": {
    "low_priority_applied": true
  }
}
```

### `run.log` — 工具自身行動記錄

結構化 log（tracing 格式），記錄 Cairn 讀取的每個檔案、每個 collector 的執行狀態與任何跳過的原因。chain-of-custody 用。

---

## 8. Sigma 規則管理

### 規則儲存方式

`rules/sigma/` 中的 `.yml` 規則是 SigmaHQ 原始 YAML（純文字，未經任何編碼），固定在 `rules/sigma/PROVENANCE` 記錄的上游 commit。

### 查看 / 稽核規則

直接用文字編輯器打開 `rules/sigma/` 底下的 `.yml` 即可，這就是實際執行的內容。

### 擴充規則集

從 SigmaHQ（同一個 pin commit）取得規則檔，放到 `rules/sigma/<SigmaHQ 相對路徑>`，並在 `rules/ruleset.toml` 加上對應的 `path`；測試會檢查兩者一致。所有規則必須有 `author:` 欄位（DRL 1.1）。

### 驗證規則集完整性

```powershell
cairn verify out/manifest.json --rules rules/sigma
```

`manifest.json` 的 `tool.sigma_ruleset_ver` 欄位記錄了規則集的 pin commit + aggregate SHA-256，可跨時重現。

---

## 9. 常見情境

### IR 分析師快速 triage 清單

```powershell
# 1. 確認 binary hash 與發布版一致
(Get-FileHash .\cairn.exe -Algorithm SHA256).Hash.ToLower()

# 2. 確認版本
.\cairn.exe --version

# 3. 設定輸出到 off-target（USB 或網路磁碟）
$OUT = "E:\IR\$CaseId"

# 4. 執行（Admin PowerShell）
.\cairn.exe run --target live --output "$OUT.zip" `
  --case-id $CaseId --operator $AnalystName `
  --zip

# 5. 驗證輸出（壓縮檔內每個成員 + 旁邊的 .zip.sha256）
.\cairn.exe verify "$OUT.zip" --rules .\rules\sigma

# 6. 透過受控管道傳輸 zip
```

### 低影響掃描

```powershell
# --profile minimal 跳過 Prefetch 與 live EVTX
cairn run --target live --output D:\IR\quick --profile minimal
```

### 只跑 EVTX（Linux/macOS 也適用）

```powershell
cairn evtx C:\Windows\System32\winevt\Logs\Security.evtx --rules rules/sigma
```

### 非工程師使用者的日常巡檢

雙擊 `cairn-launcher.exe` → 看畫面摘要和瀏覽器裡的報告是否顯示「發現高風險事件」→ 若有，聯絡資安工程師並提供自動產生的 zip 報告。詳見第 4 章。

### 用規則集重新驗證舊的 manifest

```powershell
cairn verify old_run/manifest.json --rules rules/sigma
```

---

## 10. 已知限制

| 限制 | 說明 |
|------|------|
| **僅 Windows x64**（live collector） | arm64 計畫中；Linux/macOS 只能跑 `cairn evtx` |
| **規則集固定**（80 條） | 規則更新需手動替換 `rules/sigma/` 並同步 `rules/ruleset.toml` |
| **Binary 目前未 Authenticode 簽章** | 簽章工作列為 legitimacy layer，正式給客戶前必須完成；目前以 hash 識別 |
| **不讀 raw 磁碟** | 不解析 $MFT、USN、Amcache、Shimcache、BAM、UserAssist、SRUM |
| **Velociraptor 封裝**（FR20 延伸） | 尚未實作 |
| **`--collect-raw`**（完整 raw artifact 打包） | 尚未實作；目前封存只含 findings/manifest/run.log |
