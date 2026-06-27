# cairn-launcher Design Spec (Spec A: Core + User Mode)

> **Status:** Approved for implementation.
> **Date:** 2026-06-27

---

## Problem

`cairn.exe` 是命令列工具，每次執行都需要手打：
- `--rules` 路徑（常常不知道在哪）
- `--output` 路徑（要自己想）
- `--since` ISO8601 格式（容易打錯）

對非技術使用者（IT 同事、被通知的受害者）完全不友善。換台電腦還需要裝 Visual C++ Redistributable（`VCRUNTIME140.dll` 依賴）。

---

## Goal

提供一個 **雙擊即用的 `cairn-launcher.exe`**：
1. 互動式 CLI 選單，零指令背誦
2. 自動偵測同目錄的 `cairn.exe` + `rules\sigma\`
3. 執行完顯示「有沒有問題」一句話結論 + High/Critical 事件清單
4. 自動壓縮報告成 `.zip`，開啟所在資料夾讓使用者上傳雲端
5. 兩個 exe 均 CRT 靜態連結，零外部 DLL 依賴

---

## 部署結構

```
cairn-forensics\          ← 整包發給使用者/同事
├── cairn-launcher.exe    ← 雙擊入口（本 spec 實作）
├── cairn.exe             ← 底層引擎（現有，不改）
└── rules\
    └── sigma\            ← XOR-encoded rules（現有，不改）
```

`output\` 由 launcher 在同目錄自動建立，每次掃描產生帶時間戳的子目錄。

---

## 使用者互動流程

### 主選單
```
╔══════════════════════════════════════════╗
║    Cairn 威脅鑑識工具  v0.1.0            ║
╠══════════════════════════════════════════╣
║  主機名稱：DESKTOP-ABC123                ║
║  規則版本：98781da + a3f2...             ║
╠══════════════════════════════════════════╣
║  [1] 快速掃描（最近 24 小時）             ║
║  [2] 自訂時間範圍                        ║
║  [3] 工程師模式                          ║
║  [Q] 離開                               ║
╚══════════════════════════════════════════╝
請選擇：
```

### 選 [2] 自訂時間範圍
```
選擇掃描範圍：
  [1] 最近 1 小時
  [2] 最近 6 小時
  [3] 最近 24 小時
  [4] 最近 72 小時
  [5] 最近 7 天
請選擇：
```

### 執行中
```
執行掃描中，請稍候...
（cairn.exe 的即時 log 輸出顯示於此）
```

### 完成摘要（無高風險）
```
╔══════════════════════════════════════════╗
║  掃描完成                                ║
║  時間範圍：最近 24 小時                  ║
║  掃描時間：2026-06-27 14:30 UTC          ║
║  管理員權限：是                          ║
╠══════════════════════════════════════════╣
║                                          ║
║  ✅ 未發現高風險威脅                      ║
║                                          ║
║  Low: 2（一般性記錄，無需立即處理）       ║
║  Medium: 1（建議稍後請工程師確認）        ║
╠══════════════════════════════════════════╣
║  報告已壓縮：                            ║
║  .\output\20260627_143022.zip            ║
╚══════════════════════════════════════════╝
按 Enter 開啟報告資料夾...
```

### 完成摘要（有高風險）
```
╔══════════════════════════════════════════╗
║  掃描完成                                ║
║  時間範圍：最近 24 小時                  ║
║  掃描時間：2026-06-27 14:30 UTC          ║
║  管理員權限：是                          ║
╠══════════════════════════════════════════╣
║                                          ║
║  ⚠️  發現高風險事件，請立即聯絡資安工程師 ║
║                                          ║
║  [CRITICAL] Mimikatz-like LSASS Access  ║
║  [HIGH]     Suspicious PowerShell       ║
║  [HIGH]     Scheduled Task via CMD      ║
║  （還有 2 筆，請查看完整報告）            ║
║                                          ║
║  Medium: 3  Low: 5                      ║
╠══════════════════════════════════════════╣
║  報告已壓縮：                            ║
║  .\output\20260627_143022.zip            ║
╚══════════════════════════════════════════╝
按 Enter 開啟報告資料夾...
```

---

## 啟動時環境檢查

Launcher 啟動時立即檢查（找不到就印清楚錯誤 + 等 Enter 離開，不 panic）：

| 檢查項目 | 路徑 | 找不到的錯誤訊息 |
|---------|------|----------------|
| cairn.exe | `<launcher同目錄>\cairn.exe` | `找不到 cairn.exe，請確認與 cairn-launcher.exe 在同一資料夾` |
| rules 目錄 | `<launcher同目錄>\rules\sigma\` | `找不到規則目錄 rules\sigma\，Sigma 偵測將無法執行` |

rules 目錄找不到時：**不中止**，改為執行不帶 `--rules` 的掃描（heuristics-only 模式），並在選單和摘要中明確標示「Sigma 規則未載入」。

---

## 技術架構

### 新 crate：`crates/cairn-launcher`

```
crates/cairn-launcher/
├── Cargo.toml
└── src/
    ├── main.rs       — 啟動、環境檢查、主迴圈
    ├── menu.rs       — 選單渲染、鍵盤輸入（純 stdin 讀行）
    ├── runner.rs     — 組合 cairn.exe 參數、std::process::Command 執行
    ├── summary.rs    — 讀 manifest.json + findings.jsonl，產生摘要結構
    └── package.rs    — 把 output 子目錄壓縮成 .zip、開啟資料夾
```

### 各模組職責

**`main.rs`**
- `main()`: 環境檢查 → 主選單迴圈 → 分發到各功能
- `Env` struct: `{ cairn_exe: PathBuf, rules_dir: Option<PathBuf>, launcher_dir: PathBuf }`
- 啟動時呼叫 `detect_env()` 建立 `Env`

**`menu.rs`**
- `print_main_menu(env: &Env)`: 印主選單（含主機名稱、rules 版本）
- `read_choice() -> char`: 讀一行 stdin，取第一個字元，大小寫不分
- `print_time_menu() -> Duration`: 印時間選單，回傳使用者選的 Duration
- 純 I/O，無業務邏輯

**`runner.rs`**
- `RunConfig { cairn_exe, rules_dir, output_dir, since }`: 執行參數
- `run_scan(cfg: &RunConfig) -> Result<PathBuf>`: 呼叫 `cairn.exe`，繼承 stdout/stderr，回傳 output 子目錄路徑
- output 子目錄命名：`output\YYYYMMDD_HHMMSS\`（用 `chrono::Local::now()` 格式化）

**`summary.rs`**
- `ScanSummary { started_utc, finished_utc, hostname, admin, time_window_hours, findings_by_sev, top_findings }` 
- `top_findings: Vec<(Severity, String)>` — 只取 Critical + High，最多 5 筆，欄位是 `(severity, title)`
- `load_summary(output_dir: &Path) -> Result<ScanSummary>`: 讀 `manifest.json`（counts + run + host + privileges）+ `findings.jsonl`（取 Critical/High title）
- `print_summary(s: &ScanSummary)`: 印完整摘要框
- 判斷邏輯：`critical > 0 || high > 0` → ⚠️，否則 → ✅

**`package.rs`**
- `zip_output(output_dir: &Path) -> Result<PathBuf>`: 用 `zip` crate 把 output 子目錄壓縮成同名 `.zip`（存在 `output\` 下），回傳 zip 路徑
- `open_folder(path: &Path)`: Windows 上執行 `explorer.exe <path>` 開啟資料夾

---

## 依賴套件

| crate | 用途 | 版本策略 |
|-------|------|---------|
| `zip` | 壓縮報告 | `workspace` 新增，pin 精確版本 |
| `chrono` | 時間格式化（已在 workspace） | 複用現有 |
| `serde` / `serde_json` | 讀 manifest.json / findings.jsonl（已在 workspace） | 複用現有 |
| `cairn-core` | 反序列化 `Manifest`、`Finding`、`Severity` | path dep |

不引入 TUI 框架（`ratatui`、`crossterm` 等）——純 `println!` + `stdin().read_line()`，確保在任何 Windows terminal 環境（cmd、PowerShell、遠端 RDP）下都能正常運作。

---

## CRT 靜態連結（消除 VCRUNTIME140.dll 依賴）

在 `Cargo.toml`（workspace 根）新增：

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]
```

這讓所有 crate（含 `cairn.exe` 和 `cairn-launcher.exe`）都靜態連結 CRT，不依賴外部 DLL。

> **注意：** `.cargo/config.toml` 已有 `target-dir` 設定，`rustflags` 要加在 `Cargo.toml` 而不是 `config.toml`（`config.toml` 含機器特定路徑，不進版控）。

---

## 打包腳本

`scripts/package.ps1`（PowerShell）：

```powershell
# 產生 dist\cairn-forensics\ 可直接壓縮發送
$dist = "dist\cairn-forensics"
cargo build --release -p cairn-cli -p cairn-launcher
New-Item -ItemType Directory -Force $dist
Copy-Item "target\release\cairn.exe" $dist
Copy-Item "target\release\cairn-launcher.exe" $dist
Copy-Item -Recurse "rules" $dist
```

---

## 工程師模式（Spec A 的最小版本）

Spec A 只實作進入工程師模式的入口（選 [3] 後顯示「工程師模式開發中，敬請期待」並回主選單）。完整工程師功能在 Spec B 實作，骨架由本 spec 的 `menu.rs` 預留。

---

## 測試策略

由於 launcher 是 I/O 密集（stdin/stdout、subprocess、filesystem），測試聚焦在純邏輯函式：

| 測試 | 位置 | 測試什麼 |
|------|------|---------|
| `summary_no_high_is_green` | `summary.rs` | counts 無 high/critical → ✅ |
| `summary_with_high_is_red` | `summary.rs` | counts 有 high → ⚠️ |
| `summary_top_findings_capped_at_5` | `summary.rs` | 超過 5 筆 critical/high 只取前 5 |
| `zip_output_creates_file` | `package.rs` | 壓縮後 .zip 存在且非空 |
| `detect_env_missing_cairn` | `main.rs` | cairn.exe 不存在 → Err |
| `runner_builds_correct_args` | `runner.rs` | since + rules 參數組合正確 |

---

## 不在 Spec A 範圍內

- 工程師模式（攻擊時間線、FP 標記、Markdown 報告）→ Spec B
- 雲端上傳整合 → 未來版本（目前靠 zip + 手動上傳）
- GUI → 不做
- 離線 EVTX 分析入口 → Spec B
