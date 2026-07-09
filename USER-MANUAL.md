# Cairn 使用手冊

> 版本：0.1.0 ｜ 最後更新：2026-07-09 ｜ 適用 commit：`33184b4`

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
- **平時不連網**：日常掃描完全在本機執行，不會把你的資料傳到任何外部伺服器。唯一的例外是 `update-rules` 這個指令——那是給工程師手動執行、用來更新 Sigma 偵測規則庫的維護動作，一般使用者平常掃描完全不會觸發任何連網行為。

---

## 1. 這是什麼

**Cairn** 是一支單一 Rust binary，專門給授權的事件應變（IR）分析師在 Windows 端點上執行快速分類（triage）：

- 解析 **EVTX 事件日誌**並比對 Sigma 規則
- 枚舉**即時系統狀態**（process tree、網路連線、persistence 機制、登入 session）
- 從 **raw 磁碟**讀取被鎖定的離線 artifact（$MFT、$J、hive、Amcache、Shimcache、UserAssist、BAM、Prefetch、SRUM）
- 套用**可解釋的 heuristic**（parent-child 異常、persistence dispositive-signal 判定、可疑網路連線、帳號異動、timestomp、BYOVD 驅動比對）
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

> **重要**：live process / network / raw-NTFS / hive 等 collector 全部依賴 Windows API，在非 Windows 環境下會被自動跳過（graceful degrade），並在 manifest 中記錄原因。`cairn evtx`（純 EVTX + Sigma）可跨平台使用。

---

## 3. 需要的權限

| 功能 | 最低權限 | 備註 |
|------|----------|------|
| `cairn evtx`（EVTX 解析） | 標準使用者（可讀 .evtx） | |
| live proc / net 枚舉 | 標準使用者 | 其他 user 的 process 需 Admin |
| persistence 枚舉（Run keys、services、sched tasks、WMI subs） | 標準使用者（部分）/ Admin（全部） | |
| raw-NTFS $MFT / $J | **Administrator + SeBackupPrivilege** | |
| 離線 hive（SYSTEM / NTUSER.DAT / Amcache） | **Administrator + SeBackupPrivilege** | |
| Prefetch | Administrator | `C:\Windows\Prefetch` ACL |
| SRUM（SRUDB.dat） | **Administrator + SeBackupPrivilege** | |
| BAM / UserAssist | **Administrator + SeBackupPrivilege** | SYSTEM hive ACL |

**缺少權限時 Cairn 不會 crash**：該 collector 會被跳過，在 `manifest.json` 的 `sources[].errors` 中留下說明，其餘 collector 繼續執行（golden rule 8）。

> 一般 Administrator 登入 token 預設**不含** `SeBackupPrivilege`（需另外顯式啟用）。若用 `cairn-launcher` 或一般 Admin PowerShell 執行，上表標「+SeBackupPrivilege」的 collector 可能不會產生任何紀錄——這不是錯誤，是權限不足的正常降級，manifest 會記錄原因。

### 以提升權限執行

```powershell
# 在 Admin PowerShell 執行（建議）
.\cairn.exe run --target live --output C:\IR\case001 --admin-features

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

雙擊 `cairn-launcher.exe` 會開啟一個文字選單，主畫面：

```
[1] 快速掃描（最近 24 小時）
[2] 自訂時間範圍
[3] 工程師模式
[Q] 離開
```

- **[1] 快速掃描**：對本機執行最近 24 小時的標準掃描，跑完自動打包成 zip、顯示結果摘要（是否發現高風險項目）。
- **[2] 自訂時間範圍**：選擇 1 / 6 / 24 / 72 小時或 7 天的掃描範圍。
- **[3] 工程師模式**：進入子選單，見下一節。
- **[Q] 離開**。

`cairn-launcher` 會自動偵測同資料夾內的 `cairn.exe` 與 `rules\sigma\`；找不到規則目錄時只會用啟發式偵測（Sigma 部分停用），並在畫面上提示。

### 工程師模式（launcher 子選單）

```
[1] 選擇 Profile 掃描
[2] 離線 EVTX 分析
[B] 返回主選單
```

- **[1] 選擇 Profile 掃描**：先選擇掃描的 Profile（模組集），再對本機執行最近 24 小時掃描：
  - `Minimal`（最小模組集，速度優先）——跳過耗時的 raw-NTFS 全解析，適合快速確認或資源受限的環境。
  - `Standard`（標準模組集，預設）——一般 triage 的建議選項。
  - `Verbose`（完整模組集，含耗時的 raw-NTFS 收集）——涵蓋 $MFT/$J 等 raw 磁碟解析，最完整但耗時最長，需要 Admin + SeBackupPrivilege 才能取得完整資料。
- **[2] 離線 EVTX 分析**：適用於手邊已經有 `.evtx` 檔案（例如從其他機器匯出、或不方便/不需要對本機即時掃描）的情境。可以輸入單一 `.evtx` 檔案路徑，也可以輸入一個資料夾路徑——輸入資料夾時會自動抓出該資料夾下所有 `.evtx` 檔案一併分析。

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

### 情境 B：完整 live triage（需 Admin + SeBackup）

```powershell
# 在 Admin PowerShell 執行
cairn run --target live --output D:\IR\case001 --admin-features --case-id "IR-2026-001" --operator "analyst"

# 輸出：
#   D:\IR\case001\timeline.csv
#   D:\IR\case001\findings.jsonl
#   D:\IR\case001\report.html
#   D:\IR\case001\manifest.json
#   D:\IR\case001\run.log
#   （加上各 collector 子目錄的原始 record）

# 驗證
cairn verify D:\IR\case001\manifest.json --rules rules/sigma
```

### 情境 C：打包並加密輸出

```powershell
# --zip 打包成 .zip，--encrypt 加 X25519 公鑰加密（輸出 .zip.age）
cairn run --target live --output D:\IR\case001 --admin-features --zip --encrypt age1xxxx...

# dry-run：不寫入任何檔案，確認流程
cairn run --target live --output D:\IR\case001 --dry-run
```

### 情境 D：非工程師使用者——雙擊 launcher

不需要任何指令：雙擊 `cairn-launcher.exe` → `[1] 快速掃描` → 等待完成 → 畫面顯示是否發現高風險項目 → 報告自動打包，按 Enter 開啟資料夾。詳見第 4 章。

---

## 6. 指令參考

### `cairn run` — 完整 triage

```
cairn run --target <TARGET> --output <OUTPUT> [OPTIONS]
```

| 參數 | 說明 |
|------|------|
| `--target live` | 對當前 host 執行 live collection |
| `--target <dir>` | 從離線 artifact 目錄讀取 |
| `--output <dir>` | 輸出目錄（建議 off-target：USB / 網路磁碟） |
| `--admin-features` | 啟用 Admin-only collector（需要實際有 Admin 權限） |
| `--zip` | 輸出打包為 .zip |
| `--encrypt <pubkey>` | .zip 再以 age X25519 公鑰加密（.zip.age） |
| `--dry-run` | 模擬執行，零寫入 |
| `--rules <dir>` | 指定 Sigma 規則目錄（預設 `rules/sigma`） |
| `--rules-plain` | 讀取未 XOR 編碼的 .yml 規則（供 SOC 稽核用） |
| `--profile minimal\|standard\|verbose` | `minimal`：最小模組集，跳過 raw-NTFS 全解析；`standard`（預設）：標準模組集；`verbose`：完整模組集，含耗時的 raw-NTFS 收集 |
| `--only evtx,process,...` | 只跑指定 collector（逗號分隔） |
| `--since <RFC3339>` | 只分析指定時間之後的事件 |
| `--case-id <id>` | 案件編號（記入 manifest） |
| `--operator <name>` | 分析師姓名（記入 manifest） |
| `--bodyfile <path>` | 同時輸出 mactime bodyfile（供 plaso 使用） |
| `--driver-list <path>` | 覆蓋內建的已知漏洞驅動 SHA1 清單（BYOVD 偵測，一行一個小寫 40-hex SHA1，`#` 開頭為註解） |
| `--use-vss` | 使用 Volume Shadow Copy（旗標已定義，實作尚未完成，見第 10 章） |
| `--max-threads <N>` | 限制 rayon 執行緒數（預設 min(cores, 8)） |
| `--full-speed` | 不降低 process 優先權（預設為 below-normal） |
| `--max-mft-records <N>` | $MFT 記錄上限（預設 1,000,000） |
| `--max-usn-records <N>` | $J 記錄上限（預設 1,000,000） |

### `cairn evtx` — 純 EVTX + Sigma

```
cairn evtx [FILES]... [--rules <dir>] [--rules-plain]
```

| 參數 | 說明 |
|------|------|
| `[FILES]...` | 一或多個 .evtx 檔案路徑 |
| `--rules <dir>` | Sigma 規則目錄 |
| `--rules-plain` | 讀取未 XOR 編碼的 .yml 規則（供 SOC 稽核用） |

### `cairn verify` — 輸出完整性驗證

```
cairn verify <MANIFEST> [--rules <dir>] [--rules-plain]
```

重新計算 manifest 所列所有輸出的 SHA-256，並驗證 Sigma 規則集版本（ADR-0003）。任何不一致則 exit code 非零。

### `cairn update-rules` — 更新 Sigma 規則

```
cairn update-rules [--pin <40-hex-sha>]
```

從 SigmaHQ 抓取 `rules/ruleset.toml` 中列出的規則，XOR 編碼後寫入 `rules/sigma/`，並更新 `PROVENANCE` 檔案。**這是唯一會連網的指令**，且僅供工程師手動維護規則庫時使用；一般使用者的日常掃描完全不會觸發此行為。

- `--pin <sha>`：覆蓋 ruleset.toml 裡的 pin，指定特定 SigmaHQ commit
- 壞的 pin 格式在觸網前就會被拒絕（SSRF 防護）
- 每條規則都要有 `author:` 欄位（DRL 1.1 驗證）

```powershell
# 用 ruleset.toml 中的預設 pin 更新
cairn update-rules

# 指定特定 SigmaHQ commit
cairn update-rules --pin 98781da19cf60c48ce6e7f2d3ad11c9ba389191a
```

---

## 7. 輸出格式說明

每次 `run` 或 `evtx` 都會在 `--output` 目錄產生以下檔案：

### `timeline.csv` — 偵測時間軸

CSV 格式，每列代表一筆規則命中。欄位：

```
Timestamp, Host, Channel, EventID, Severity, RecordID, RuleTitle, RuleAuthor, MITRE, Details
```

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

單一自包含 HTML 檔案，供不熟悉 CLI 的使用者或需要快速視覺化的分析師開啟閱讀。包含 5 個面板：

- **連線（Connections）**：目前/近期網路連線狀態
- **程序（Processes）**：process tree 與可疑父子關係
- **執行（Execution）**：各執行證據來源（Prefetch/Amcache/Shimcache/BAM/UserAssist/SRUM 等）彙整的程式執行紀錄
- **檔案（Files）**：$MFT/$J 相關檔案活動
- **登入（Logon）**：登入 session 紀錄

報告內建**篩選與聚合功能**：可依嚴重度（critical/high/medium/low/info）、文物來源（artifact）、關鍵字篩選 finding 列表；同一個 binary（依路徑或雜湊判定同源）觸發的多筆 finding 會聚合到同一個面板，避免同一支程式的多筆事件洗版。

### `manifest.json` — 完整性與執行記錄

```jsonc
{
  "schema": "cairn.manifest/1",
  "run_id": "uuid",
  "host": { "name": "...", "os": "...", "os_build": "...", "tz": "..." },
  "tool": { "version": "0.1.0", "build_sha": "...", "sigma_ruleset_ver": "<pin>+<hash>" },
  "sources": [
    { "name": "evtx:Security", "record_count": 1234, "sha256": "...", "errors": [] }
  ],
  "outputs": [
    { "name": "timeline.csv", "sha256": "..." },
    { "name": "findings.jsonl", "sha256": "..." },
    { "name": "report.html", "sha256": "..." }
  ],
  "governance": {
    "max_threads": 8,
    "truncations": []
  }
}
```

### `run.log` — 工具自身行動記錄

結構化 log（tracing 格式），記錄 Cairn 讀取的每個檔案、每個 collector 的執行狀態與任何跳過的原因。chain-of-custody 用。

### `*.bodyfile`（可選，`--bodyfile` 旗標）

mactime 格式，11 欄，供 plaso / log2timeline 使用。每列代表一個 `$MFT` / USN 條目的時間事件。

---

## 8. Sigma 規則管理

### 規則儲存方式

`rules/sigma/` 中的 `.yml` 規則為 **XOR 編碼**，避免 AV 對偵測字串誤報（XOR key 是公開的，不是安全控制，詳見 ADR-0002）。

### 查看 / 稽核規則

```powershell
# 讀取未編碼版本（供 SOC 稽核）
cairn evtx *.evtx --rules rules/plain --rules-plain

# 或直接看 rules/plain/ 目錄（需先有此目錄，或用 fetch-and-encode.sh 產生）
```

### 擴充規則集

編輯 `rules/ruleset.toml`，加入更多 SigmaHQ 規則路徑，然後執行：

```powershell
cairn update-rules
```

所有列出的規則必須有 `author:` 欄位（DRL 1.1），否則會被拒絕。

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
.\cairn.exe run --target live --output $OUT --admin-features `
  --case-id $CaseId --operator $AnalystName `
  --zip --encrypt $PubKey

# 5. 驗證輸出
.\cairn.exe verify "$OUT\manifest.json" --rules .\rules\sigma

# 6. 傳輸加密封存（.zip.age）
```

### 低影響掃描（不降速、不跑 raw-NTFS）

```powershell
# --profile minimal 跳過 $MFT/$J 全解析
cairn run --target live --output D:\IR\quick --profile minimal
```

### 完整掃描（含耗時的 raw-NTFS 收集）

```powershell
# --profile verbose 開啟完整模組集，需 Admin + SeBackupPrivilege 才能取得完整資料
cairn run --target live --output D:\IR\full --admin-features --profile verbose
```

### 只跑 EVTX（Linux/macOS 也適用）

```powershell
cairn evtx C:\Windows\System32\winevt\Logs\Security.evtx --rules rules/sigma
```

### 疑似 BYOVD（Bring Your Own Vulnerable Driver）攻擊排查

Amcache 的 `amcache_driver` 資料來源會擷取本機已載入驅動程式的 SHA1，並與內建（或 `--driver-list` 指定）的已知漏洞驅動清單比對，協助找出攻擊者濫用合法簽章但有漏洞的驅動程式來取得核心層權限的手法：

```powershell
cairn run --target live --output D:\IR\case002 --admin-features --driver-list custom_drivers.txt
```

### 非工程師使用者的日常巡檢

雙擊 `cairn-launcher.exe` → `[1] 快速掃描` → 看畫面摘要是否顯示「發現高風險事件」→ 若有，聯絡資安工程師並提供自動產生的 zip 報告。詳見第 4 章。

### 更新規則並驗證

```powershell
# 更新到最新 pin
cairn update-rules

# 用新規則重新驗證舊的 manifest
cairn verify old_run/manifest.json --rules rules/sigma
```

---

## 10. 已知限制

| 限制 | 說明 |
|------|------|
| **僅 Windows x64**（live collector） | arm64 計畫中；Linux/macOS 只能跑 `cairn evtx` |
| **規則集小**（目前 3 條） | `rules/ruleset.toml` 中只有 3 條示範規則；正式使用前需用 `update-rules` 擴充 |
| **Binary 目前未 Authenticode 簽章** | 簽章工作列為 legitimacy layer，正式給客戶前必須完成；目前以 hash 識別 |
| **SRUM 解析依賴暫存檔** | 需有可寫的 temp 目錄（`tempfile` crate）；隔離環境需確認 |
| **Amcache / Shimcache / BAM 在未知 Windows build 會 abstain** | NFR12 誠實降級，而非謊報；若遇到新 build 需等待 parser 更新 |
| **Velociraptor 封裝**（FR20 延伸） | 尚未實作 |
| **`--collect-raw`**（完整 raw artifact 打包） | 尚未實作；目前封存只含 findings/manifest/run.log |
| **VSS（Volume Shadow Copy）** | `--use-vss` 旗標已定義，實作尚未完成 |
| **一般 Admin token 預設無 SeBackupPrivilege** | 標「+SeBackupPrivilege」的 collector（$MFT/$J/hive/Amcache/Prefetch/SRUM/BAM/UserAssist）在一般 Admin 權限下可能靜默產生 0 筆紀錄，需另外顯式啟用該權限才能取得完整資料 |
