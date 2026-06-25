# Cairn 使用手冊

> 版本：0.1.0 ｜ 最後更新：2026-06-26 ｜ 適用 commit：`1717a19`（S4 封頂）

---

## 目錄

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

## 1. 這是什麼

**Cairn** 是一支單一 Rust binary，專門給授權的事件應變（IR）分析師在 Windows 端點上執行快速分類（triage）：

- 解析 **EVTX 事件日誌**並比對 Sigma 規則
- 枚舉**即時系統狀態**（process tree、網路連線、persistence 機制）
- 從 **raw 磁碟**讀取被鎖定的離線 artifact（$MFT、$J、hive、Amcache、Shimcache、UserAssist、BAM、Prefetch、SRUM）
- 套用**可解釋的 heuristic**（parent-child 異常、persistence 評分、可疑網路連線）
- 輸出**帶 MITRE ATT&CK 標籤、SHA-256 完整性簽章的時間軸**和 manifest

Cairn **不是**攻擊工具：不注入 process、不繞過 EDR、不混淆自身、不刪除 artifact。所有動作都記錄在 `run.log`，且它設計為對 EDR 可見並應被辨識為良性。

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

### 以提升權限執行

```powershell
# 在 Admin PowerShell 執行（建議）
.\cairn.exe run --target live --output C:\IR\case001 --admin-features

# 或透過 runas
runas /user:Administrator "cairn.exe run --target live --output D:\IR\out"
```

---

## 4. 安裝 / 取得 binary

### 從源碼編譯

```powershell
# 需要 Rust toolchain（https://rustup.rs）
git clone <repo>
cd cairn
cargo build --release --workspace
# binary 在 target/release/cairn.exe
```

> **注意**：設定 `CARGO_TARGET_DIR` 指向 OneDrive 以外的路徑，避免 AV 鎖定 build probe：
> ```powershell
> $env:CARGO_TARGET_DIR = "C:\Users\<user>\AppData\Local\cairn-target"
> ```

### 驗證 binary 完整性

```powershell
# 確認 SHA-256 與發布的 hash 一致
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
| `--profile minimal\|standard` | `minimal`：跳過 raw-NTFS $MFT/$J；`standard`（預設）：全開 |
| `--only evtx,process,...` | 只跑指定 collector（逗號分隔） |
| `--since <RFC3339>` | 只分析指定時間之後的事件 |
| `--case-id <id>` | 案件編號（記入 manifest） |
| `--operator <name>` | 分析師姓名（記入 manifest） |
| `--bodyfile <path>` | 同時輸出 mactime bodyfile（供 plaso 使用） |
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

從 SigmaHQ 抓取 `rules/ruleset.toml` 中列出的規則，XOR 編碼後寫入 `rules/sigma/`，並更新 `PROVENANCE` 檔案。

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
    { "name": "findings.jsonl", "sha256": "..." }
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

### 只跑 EVTX（Linux/macOS 也適用）

```powershell
cairn evtx C:\Windows\System32\winevt\Logs\Security.evtx --rules rules/sigma
```

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
