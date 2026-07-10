# Cairn 易用性與治理統整（段 8）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Launcher 補實工程師模式兩項真需求（profile 掃描 + 離線 EVTX 分析）、打包流程健全化並重建 dist、使用手冊更新含概念章節、授權 Apache-2.0 → MIT、健全性混合審計。

**Architecture:** 全部沿 `cairn-launcher` 既有分層（`menu.rs` 純 I/O / `runner.rs` 純參數組裝+spawn / `summary.rs` 純解析）擴充，不開新模式；打包與授權是純檔案操作；審計是唯讀差距分析。

**Tech Stack:** Rust（cairn-launcher, anyhow, std::process::Command）、PowerShell（package.ps1）、Markdown 文件。

**這份 plan 修正了 spec 裡兩個對照原始碼後發現有誤的假設**（見 Task 2 開頭說明）：`cairn evtx` 子指令實際上是 `files: Vec<PathBuf>`（位置參數，不是 `--input`）且**沒有 `--output` 旗標**——輸出目錄固定是 `Config::default()` 的 `./out`（相對於子程序的工作目錄），必須靠 `Command::current_dir` 導向；而且 `evtx` 不接受目錄，只接受檔案清單，所以 launcher 端要自己展開目錄。

---

## 檔案結構總覽

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-launcher/src/runner.rs` | 修改 | 加 `profile` 欄位到 `RunConfig`；新增 `EvtxConfig` + `build_evtx_args` + `run_evtx` |
| `crates/cairn-launcher/src/menu.rs` | 修改 | 加 `read_path_input`、`print_engineer_menu`、`print_profile_menu`、`clean_evtx_input` |
| `crates/cairn-launcher/src/main.rs` | 修改 | `'3'` 分支從 stub 換成工程師子選單迴圈；新增 `run_evtx_flow` |
| `scripts/package.ps1` | 修改 | 加入手冊/授權檔複製 + CHECKSUMS 產生 |
| `USER-MANUAL.md` | 修改 | 新增第 0 章 + 全文更新至現況 |
| `LICENSE` | 覆寫 | Apache-2.0 全文 → MIT 全文 |
| `NOTICE` | 修改 | 授權引用改 MIT，Sigma DRL 段落逐字保留 |
| `Cargo.toml`（workspace 根） | 修改 | `license = "MIT"` |
| `README.md` | 修改 | 授權章節同步 |
| `docs/REMAINING-WORK.md` | 修改 | 併入審計 finding + 段 1 狀態校正 + 附錄 |

---

## Task 1: `RunConfig` 加 profile 欄位，快速掃描與工程師掃描共用同一流程

**Files:**
- Modify: `crates/cairn-launcher/src/runner.rs:6-34`
- Modify: `crates/cairn-launcher/src/main.rs:69-116`（`run_scan_flow` 簽名擴充）

- [ ] **Step 1: 寫失敗測試（`RunConfig` 帶 profile 時 `build_args` 含 `--profile`）**

在 `crates/cairn-launcher/src/runner.rs` 的 `#[cfg(test)] mod tests` 內新增：

```rust
    #[test]
    fn build_args_with_profile_includes_profile_flag() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = RunConfig {
            cairn_exe: &exe,
            rules_dir: None,
            output_dir: &output,
            since: "2026-06-27T14:30:00Z",
            profile: Some("verbose"),
        };
        let args = build_args(&cfg);
        assert!(args.contains(&"--profile".to_string()));
        assert!(args.contains(&"verbose".to_string()));
    }

    #[test]
    fn build_args_without_profile_has_no_profile_flag() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = RunConfig {
            cairn_exe: &exe,
            rules_dir: None,
            output_dir: &output,
            since: "2026-06-27T14:30:00Z",
            profile: None,
        };
        let args = build_args(&cfg);
        assert!(!args.contains(&"--profile".to_string()));
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cd crates/cairn-launcher && cargo test -p cairn-launcher build_args_with_profile -- --nocapture`
Expected: FAIL（`RunConfig` 沒有 `profile` 欄位，編譯錯誤 E0063 或 E0560）

- [ ] **Step 3: 實作 — 加 `profile` 欄位並在 `build_args` 對應擴充**

修改 `crates/cairn-launcher/src/runner.rs` 第 6-34 行，`RunConfig` 結構與 `build_args`：

```rust
/// cairn.exe 執行所需的所有參數。
pub struct RunConfig<'a> {
    /// cairn.exe 的完整路徑
    pub cairn_exe: &'a Path,
    /// rules/sigma 目錄，None 表示 heuristics-only 模式
    pub rules_dir: Option<&'a Path>,
    /// 掃描結果的輸出目錄（cairn 會在此目錄寫入所有報告）
    pub output_dir: &'a Path,
    /// --since 的 UTC datetime（RFC3339 格式，如 "2026-06-27T14:30:00Z"）
    pub since: &'a str,
    /// --profile 的值（"minimal"/"standard"/"verbose"）。None 時不帶旗標，
    /// cairn.exe 自身預設 "standard"（見 cairn-cli RunArgs::profile default_value）。
    pub profile: Option<&'a str>,
}

/// 根據 `RunConfig` 建立 cairn.exe 的完整參數列表。
/// 純函式，便於測試（不實際執行任何程序）。
pub fn build_args(cfg: &RunConfig<'_>) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--target".to_string(),
        "live".to_string(),
        "--output".to_string(),
        cfg.output_dir.display().to_string(),
        "--since".to_string(),
        cfg.since.to_string(),
    ];
    if let Some(rules) = cfg.rules_dir {
        args.push("--rules".to_string());
        args.push(rules.display().to_string());
    }
    if let Some(profile) = cfg.profile {
        args.push("--profile".to_string());
        args.push(profile.to_string());
    }
    args
}
```

也要更新既有測試的 `make_cfg` helper（第 60-72 行）與呼叫點，加上 `profile: None`：

```rust
    fn make_cfg<'a>(
        exe: &'a Path,
        rules: Option<&'a Path>,
        output: &'a Path,
        since: &'a str,
    ) -> RunConfig<'a> {
        RunConfig {
            cairn_exe: exe,
            rules_dir: rules,
            output_dir: output,
            since,
            profile: None,
        }
    }
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-launcher`
Expected: 全部通過，含新增的兩個 profile 測試（總數從 4 增至 6）

- [ ] **Step 5: main.rs — `run_scan_flow` 加 profile 參數**

修改 `crates/cairn-launcher/src/main.rs` 第 69-116 行的 `run_scan_flow`：

```rust
fn run_scan_flow(env: &Env, hours: u64, desc: &str, profile: Option<&str>) -> anyhow::Result<()> {
    let output_dir = runner::timestamped_output_dir(&env.output_base);
    std::fs::create_dir_all(&output_dir)?;

    let since = since_from_hours(hours);
    let cfg = runner::RunConfig {
        cairn_exe: &env.cairn_exe,
        rules_dir: env.rules_dir.as_deref(),
        output_dir: &output_dir,
        since: &since,
        profile,
    };

    println!("\n執行掃描中，請稍候...");
    println!(
        "（掃描範圍：{}，輸出目錄：{}）\n",
        desc,
        output_dir.display()
    );

    runner::run_scan(&cfg)?;

    match summary::load_summary(&output_dir, desc) {
        Ok(s) => {
            menu::print_summary(&s);
            match package::zip_output(&output_dir) {
                Ok(zip_path) => {
                    println!("║  報告已壓縮：{:<28}║", "");
                    println!("║  {:<40}║", zip_path.display().to_string());
                    println!("╚══════════════════════════════════════════╝");
                    menu::wait_enter("\n按 Enter 開啟報告資料夾...");
                    package::open_folder(&env.output_base);
                }
                Err(e) => {
                    eprintln!("壓縮失敗（{e}），報告目錄：{}", output_dir.display());
                    menu::wait_enter("\n按 Enter 繼續...");
                }
            }
        }
        Err(e) => {
            eprintln!(
                "無法讀取掃描結果（{e}），報告目錄：{}",
                output_dir.display()
            );
            menu::wait_enter("\n按 Enter 繼續...");
        }
    }
    Ok(())
}
```

更新兩個既有呼叫點（第 141-146、147-153 行）補上 `None`：

```rust
            '1' => {
                if let Err(e) = run_scan_flow(&env, 24, "最近 24 小時", None) {
                    eprintln!("\n掃描發生錯誤：{e}");
                    menu::wait_enter("按 Enter 繼續...");
                }
            }
            '2' => {
                let (hours, desc) = menu::print_time_menu();
                if let Err(e) = run_scan_flow(&env, hours, desc, None) {
                    eprintln!("\n掃描發生錯誤：{e}");
                    menu::wait_enter("按 Enter 繼續...");
                }
            }
```

- [ ] **Step 6: 全 crate 編譯與測試確認**

Run: `cargo check -p cairn-launcher && cargo test -p cairn-launcher`
Expected: 編譯成功、全部測試通過

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-launcher/src/runner.rs crates/cairn-launcher/src/main.rs
git commit -m "feat(launcher): add optional --profile passthrough to RunConfig"
```

---

## Task 2: Profile 選單 + 工程師模式子選單接線（profile 掃描分支）

**Files:**
- Modify: `crates/cairn-launcher/src/menu.rs`（新增 `print_profile_menu`、`print_engineer_menu`）
- Modify: `crates/cairn-launcher/src/main.rs`（`'3'` 分支換成子選單迴圈）

- [ ] **Step 1: 寫失敗測試 — profile 選單回傳正確值**

在 `crates/cairn-launcher/src/menu.rs` 的 `#[cfg(test)]` 區塊新增（若無測試模組，於檔尾新增 `#[cfg(test)] mod tests { use super::*; ... }`）：

```rust
#[cfg(test)]
mod engineer_menu_tests {
    // print_profile_menu 依賴 stdin，這裡只測試映射邏輯本身，
    // 抽出成不吃 stdin 的純函式 profile_choice_to_value 供測試。
    use super::profile_choice_to_value;

    #[test]
    fn maps_known_choices() {
        assert_eq!(profile_choice_to_value('1'), "minimal");
        assert_eq!(profile_choice_to_value('2'), "standard");
        assert_eq!(profile_choice_to_value('3'), "verbose");
    }

    #[test]
    fn unknown_choice_defaults_to_standard() {
        assert_eq!(profile_choice_to_value('9'), "standard");
        assert_eq!(profile_choice_to_value('\0'), "standard");
    }
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-launcher profile_choice_to_value`
Expected: FAIL（函式不存在，E0425）

- [ ] **Step 3: 實作 — `profile_choice_to_value` 純函式 + 選單渲染**

在 `crates/cairn-launcher/src/menu.rs` 檔尾（`fn truncate_rules_ver` 之後、測試模組之前）新增：

```rust
/// 數字選項 → cairn --profile 的字串值。對應 `cairn_core::Profile` 三個變體
/// （Minimal/Standard/Verbose，見 crates/cairn-core/src/config.rs:17-21）。
/// 未知選項一律回退 "standard"（與 cairn-cli RunArgs::profile 的預設值一致，
/// 不是自造的行為）。
pub fn profile_choice_to_value(choice: char) -> &'static str {
    match choice {
        '1' => "minimal",
        '3' => "verbose",
        _ => "standard",
    }
}

/// 印工程師模式子選單，回傳使用者選擇的字元。
pub fn print_engineer_menu() {
    println!("\n╔══════════════════════════════════════════╗");
    println!("║  工程師模式                              ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  [1] 選擇 Profile 掃描                   ║");
    println!("║  [2] 離線 EVTX 分析                      ║");
    println!("║  [B] 返回主選單                          ║");
    println!("╚══════════════════════════════════════════╝");
    print!("請選擇：");
    let _ = io::stdout().flush();
}

/// 印 profile 選單，回傳 (cairn --profile 值, 描述字串)。
pub fn print_profile_menu() -> (&'static str, &'static str) {
    println!("\n選擇掃描 Profile：");
    println!("  [1] Minimal（最小模組集，速度優先）");
    println!("  [2] Standard（標準模組集，預設）");
    println!("  [3] Verbose（完整模組集，含耗時的 raw-NTFS 收集）");
    print!("請選擇（預設 2）：");
    let _ = io::stdout().flush();
    let choice = read_choice();
    let value = profile_choice_to_value(choice);
    let desc = match value {
        "minimal" => "Minimal",
        "verbose" => "Verbose",
        _ => "Standard",
    };
    (value, desc)
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-launcher`
Expected: 全部通過

- [ ] **Step 5: main.rs — `'3'` 分支換成真正的子選單迴圈**

修改 `crates/cairn-launcher/src/main.rs` 第 154-158 行（原本的 stub）：

```rust
            '3' => {
                loop {
                    menu::clear_screen();
                    menu::print_engineer_menu();
                    match menu::read_choice() {
                        '1' => {
                            let (profile_value, profile_desc) = menu::print_profile_menu();
                            let desc = format!("最近 24 小時（{profile_desc} profile）");
                            if let Err(e) =
                                run_scan_flow(&env, 24, &desc, Some(profile_value))
                            {
                                eprintln!("\n掃描發生錯誤：{e}");
                                menu::wait_enter("按 Enter 繼續...");
                            }
                        }
                        '2' => {
                            if let Err(e) = run_evtx_flow(&env) {
                                eprintln!("\nEVTX 分析發生錯誤：{e}");
                                menu::wait_enter("按 Enter 繼續...");
                            }
                        }
                        'B' => break,
                        _ => {}
                    }
                }
            }
```

（`run_evtx_flow` 在 Task 3 定義；這裡先留呼叫點，Task 3 會補上函式本體，Task 2 結束時 `cargo check` 會因缺函式而失敗——這是預期的，Task 3 立刻接續。）

- [ ] **Step 6: Commit（與 Task 3 合併提交，因 main.rs 這處尚未能獨立編譯）**

不在此步驟提交；直接接續 Task 3，Task 3 結束時一併 `cargo check` 通過後才 commit Task 2+3 的變更。

---

## Task 3: 離線 EVTX 分析（`EvtxConfig` + `build_evtx_args` + `run_evtx` + 路徑輸入清理）

**Files:**
- Modify: `crates/cairn-launcher/src/runner.rs`（新增 `EvtxConfig`、`build_evtx_args`、`run_evtx`）
- Modify: `crates/cairn-launcher/src/menu.rs`（新增 `read_path_input`）
- Modify: `crates/cairn-launcher/src/main.rs`（新增 `run_evtx_flow`，接續 Task 2 的呼叫點）

安全護欄提醒（spec §段 A）：路徑輸入必須先去引號/去空白，再驗證存在與副檔名/目錄，
不符合的輸入絕不能傳給 `Command::args`；`evtx` 子指令本身**不接受目錄**（`Cmd::Evtx.files:
Vec<PathBuf>` 是位置參數清單），所以目錄輸入必須由 launcher 展開成 `.evtx` 檔案清單再傳。
另外 `cairn evtx` 沒有 `--output` 旗標——輸出目錄固定是 `cairn_core::config::Config::default()`
的 `./out`（相對子程序工作目錄），必須用 `Command::current_dir` 把子程序的工作目錄設成
launcher 想要的輸出目錄，讓 `./out` 落在期望位置。

- [ ] **Step 1: 寫失敗測試 — `clean_path_input` 去引號/去空白/空輸入**

在 `crates/cairn-launcher/src/menu.rs` 的 `#[cfg(test)] mod engineer_menu_tests`（Task 2 建立的區塊）追加：

```rust
    use super::clean_path_input;

    #[test]
    fn strips_surrounding_quotes_and_whitespace() {
        assert_eq!(
            clean_path_input("  \"C:\\logs\\Security.evtx\"  "),
            Some("C:\\logs\\Security.evtx".to_string())
        );
    }

    #[test]
    fn plain_path_unchanged() {
        assert_eq!(
            clean_path_input("C:\\logs"),
            Some("C:\\logs".to_string())
        );
    }

    #[test]
    fn empty_input_is_none() {
        assert_eq!(clean_path_input(""), None);
        assert_eq!(clean_path_input("   "), None);
        assert_eq!(clean_path_input("\"\""), None);
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-launcher clean_path_input`
Expected: FAIL（函式不存在）

- [ ] **Step 3: 實作 `clean_path_input`（純函式，不吃 stdin）+ `read_path_input`（吃 stdin 的薄包裝）**

在 `crates/cairn-launcher/src/menu.rs`，`profile_choice_to_value` 之前新增：

```rust
/// 清理使用者貼上的路徑輸入：去前後空白、去頭尾成對的雙引號（使用者從檔案總管
/// 複製路徑常帶引號）。空輸入（或去除後為空）回傳 None。純函式，可測試。
pub fn clean_path_input(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .trim();
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted.to_string())
    }
}

/// 提示使用者輸入路徑，回傳清理過的字串；空輸入回傳 None。
pub fn read_path_input(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let mut line = String::new();
    let _ = stdin.lock().read_line(&mut line);
    clean_path_input(&line)
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-launcher`
Expected: 全部通過

- [ ] **Step 5: 寫失敗測試 — `build_evtx_args`（含/不含 rules）**

在 `crates/cairn-launcher/src/runner.rs` 的 `#[cfg(test)] mod tests` 追加：

```rust
    #[test]
    fn build_evtx_args_with_rules() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let rules = PathBuf::from(r"C:\tools\rules\sigma");
        let files = vec![PathBuf::from(r"C:\logs\Security.evtx")];
        let cfg = EvtxConfig {
            cairn_exe: &exe,
            files: &files,
            rules_dir: Some(&rules),
            output_dir: &PathBuf::from(r"C:\tools\output\20260709_120000"),
        };
        let args = build_evtx_args(&cfg);
        assert_eq!(args[0], "evtx");
        assert!(args.contains(&files[0].display().to_string()));
        assert!(args.contains(&"--rules".to_string()));
        assert!(args.contains(&rules.display().to_string()));
    }

    #[test]
    fn build_evtx_args_without_rules_has_no_rules_flag() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let files = vec![PathBuf::from(r"C:\logs\System.evtx")];
        let cfg = EvtxConfig {
            cairn_exe: &exe,
            files: &files,
            rules_dir: None,
            output_dir: &PathBuf::from(r"C:\tools\output\20260709_120000"),
        };
        let args = build_evtx_args(&cfg);
        assert!(!args.contains(&"--rules".to_string()));
        assert!(args.contains(&files[0].display().to_string()));
    }

    #[test]
    fn build_evtx_args_multiple_files() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let files = vec![
            PathBuf::from(r"C:\logs\Security.evtx"),
            PathBuf::from(r"C:\logs\System.evtx"),
        ];
        let cfg = EvtxConfig {
            cairn_exe: &exe,
            files: &files,
            rules_dir: None,
            output_dir: &PathBuf::from(r"C:\tools\output\20260709_120000"),
        };
        let args = build_evtx_args(&cfg);
        assert!(args.contains(&files[0].display().to_string()));
        assert!(args.contains(&files[1].display().to_string()));
    }
```

- [ ] **Step 6: 執行測試確認失敗**

Run: `cargo test -p cairn-launcher build_evtx_args`
Expected: FAIL（`EvtxConfig`/`build_evtx_args` 不存在）

- [ ] **Step 7: 實作 `EvtxConfig` + `build_evtx_args` + `run_evtx`**

在 `crates/cairn-launcher/src/runner.rs`，`run_scan` 函式之後新增：

```rust
/// 離線 EVTX 分析所需的參數。`cairn evtx` 子指令沒有 `--output` 旗標
/// （見 cairn-cli::main::Cmd::Evtx 定義）——輸出目錄固定是
/// `cairn_core::config::Config::default()` 的 `./out`（相對子程序工作目錄），
/// 所以這裡的 `output_dir` 是拿來設 `Command::current_dir`，不是命令列參數。
pub struct EvtxConfig<'a> {
    pub cairn_exe: &'a Path,
    pub files: &'a [PathBuf],
    pub rules_dir: Option<&'a Path>,
    pub output_dir: &'a Path,
}

/// 建立 `cairn evtx` 的參數列表（不含 output——見上方結構註解）。
pub fn build_evtx_args(cfg: &EvtxConfig<'_>) -> Vec<String> {
    let mut args = vec!["evtx".to_string()];
    for f in cfg.files {
        args.push(f.display().to_string());
    }
    if let Some(rules) = cfg.rules_dir {
        args.push("--rules".to_string());
        args.push(rules.display().to_string());
    }
    args
}

/// 執行 `cairn evtx`，把子程序工作目錄設成 `cfg.output_dir` 的上一層，讓
/// `cairn.exe` 預設輸出的 `./out` 落在 `cfg.output_dir` 裡（golden rule 4：
/// 輸出離 target，不寫進來源目錄）。呼叫前 `cfg.output_dir` 必須已存在。
pub fn run_evtx(cfg: &EvtxConfig<'_>) -> anyhow::Result<PathBuf> {
    let args = build_evtx_args(cfg);
    let status = std::process::Command::new(cfg.cairn_exe)
        .args(&args)
        .current_dir(cfg.output_dir)
        .status()?;
    if !status.success() {
        anyhow::bail!("cairn.exe evtx 執行失敗（exit code: {:?}）", status.code());
    }
    Ok(cfg.output_dir.join("out"))
}
```

- [ ] **Step 8: 執行測試確認通過**

Run: `cargo test -p cairn-launcher`
Expected: 全部通過

- [ ] **Step 9: main.rs — 新增 `run_evtx_flow`（含目錄展開 + 副檔名/存在性驗證）**

在 `crates/cairn-launcher/src/main.rs`，`run_scan_flow` 之後新增：

```rust
/// 展開輸入路徑成 .evtx 檔案清單：檔案直接回傳單一項；目錄則列舉其下（非遞迴）
/// 所有 .evtx 副檔名檔案。不存在或無 .evtx 檔的目錄回傳空清單。
fn expand_evtx_input(input: &Path) -> Vec<PathBuf> {
    if input.is_file() {
        if input
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
        {
            vec![input.to_path_buf()]
        } else {
            vec![]
        }
    } else if input.is_dir() {
        std::fs::read_dir(input)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| {
                        p.is_file()
                            && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    }
}

fn run_evtx_flow(env: &Env) -> anyhow::Result<()> {
    let Some(raw) = menu::read_path_input("請輸入 .evtx 檔案或目錄路徑：") else {
        println!("\n未輸入路徑，取消。");
        menu::wait_enter("按 Enter 繼續...");
        return Ok(());
    };
    let input_path = PathBuf::from(&raw);
    if !input_path.exists() {
        eprintln!("\n路徑不存在：{raw}");
        menu::wait_enter("按 Enter 繼續...");
        return Ok(());
    }
    let files = expand_evtx_input(&input_path);
    if files.is_empty() {
        eprintln!("\n找不到任何 .evtx 檔案：{raw}");
        menu::wait_enter("按 Enter 繼續...");
        return Ok(());
    }

    let output_dir = runner::timestamped_output_dir(&env.output_base);
    std::fs::create_dir_all(&output_dir)?;

    println!("\n分析 {} 個 EVTX 檔案中，請稍候...", files.len());
    println!("（輸出目錄：{}）\n", output_dir.display());

    let cfg = runner::EvtxConfig {
        cairn_exe: &env.cairn_exe,
        files: &files,
        rules_dir: env.rules_dir.as_deref(),
        output_dir: &output_dir,
    };
    let report_dir = runner::run_evtx(&cfg)?;

    match summary::load_summary(&report_dir, "離線 EVTX 分析") {
        Ok(s) => menu::print_summary(&s),
        Err(e) => eprintln!("無法讀取分析結果（{e}），報告目錄：{}", report_dir.display()),
    }
    menu::wait_enter("\n按 Enter 繼續...");
    Ok(())
}
```

- [ ] **Step 10: 全 crate 編譯與測試確認（Task 2 + Task 3 一起驗證）**

Run: `cargo check -p cairn-launcher && cargo test -p cairn-launcher && cargo clippy -p cairn-launcher --all-targets -- -D warnings`
Expected: 編譯成功、全部測試通過、無 clippy 警告

- [ ] **Step 11: Commit（Task 2 + 3 合併提交）**

```bash
git add crates/cairn-launcher/src/runner.rs crates/cairn-launcher/src/menu.rs crates/cairn-launcher/src/main.rs
git commit -m "feat(launcher): implement engineer-mode submenu (profile scan + offline EVTX analysis)"
```

---

## Task 4: 打包流程健全化（`scripts/package.ps1`）

**Files:**
- Modify: `scripts/package.ps1`

- [ ] **Step 1: 修改複製清單，加入手冊/授權檔**

修改 `scripts/package.ps1`，在 `Copy-Item -Recurse "rules" "$OutDir\rules"` 之後（Task 5/6 完成後 LICENSE 內容才是 MIT；此步驟先處理複製邏輯，順序不影響腳本正確性）：

```powershell
Copy-Item -Recurse "rules" "$OutDir\rules"
Copy-Item "USER-MANUAL.md" "$OutDir\USER-MANUAL.md"
Copy-Item "LICENSE"        "$OutDir\LICENSE"
Copy-Item "NOTICE"         "$OutDir\NOTICE"
```

- [ ] **Step 2: 加入 CHECKSUMS.txt 產生邏輯**

在複製區塊之後、`Write-Host "Done!..."` 之前插入：

```powershell
Write-Host "Generating CHECKSUMS.txt..." -ForegroundColor Cyan
$checksumLines = Get-ChildItem $OutDir -Recurse -File |
    Where-Object { $_.Name -ne "CHECKSUMS.txt" } |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
        $relPath = $_.FullName.Substring($OutDir.Length + 1) -replace '\\', '/'
        "$hash  $relPath"
    }
$checksumLines | Set-Content "$OutDir\CHECKSUMS.txt" -Encoding utf8
```

- [ ] **Step 3: 驗證腳本語法（不需要 Windows 特有指令跑得動，先靜態檢查）**

Run: `powershell -NoProfile -Command "Get-Command -Syntax { . '.\scripts\package.ps1' }" 2>&1 | Select-String -Pattern "error" ; echo "no syntax error if empty above"`

若環境無法跑 PowerShell 語法檢查，改為人工 read-back 確認：新增的三行 Copy-Item 與 CHECKSUMS 區塊縮排、變數名與既有腳本風格一致（`$OutDir`、`$TargetDir` 已在用）。

- [ ] **Step 4: Commit**

```bash
git add scripts/package.ps1
git commit -m "build(package): bundle manual/license/notice and regenerate CHECKSUMS.txt"
```

（本 task 尚不執行打包重建 dist——留給 Task 8，等 Task 5/6 授權變更與 Task 7 手冊更新都完成後，一次性重建，避免 dist 內容中途過時。）

---

## Task 5: 授權 Apache-2.0 → MIT

**Files:**
- Modify: `LICENSE`（整檔覆寫）
- Modify: `NOTICE`
- Modify: `Cargo.toml`（workspace 根，`license = "MIT"`）
- Modify: `README.md`

- [ ] **Step 1: 讀取現有 NOTICE 開頭段確認著作權人字串**

Run: `head -5 NOTICE`（已知內容："Cairn / Copyright 2026 Cairn project (ali-bobo) / This product is licensed under the Apache License, Version 2.0..."）

- [ ] **Step 2: 覆寫 `LICENSE` 為 MIT 全文**

```
MIT License

Copyright (c) 2026 Cairn project (ali-bobo)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: 修改 `NOTICE` 開頭授權引用行，Sigma DRL 段落逐字保留**

`NOTICE` 目前結構（前 10 行已讀取）：

```
Cairn
Copyright 2026 Cairn project (ali-bobo)

This product is licensed under the Apache License, Version 2.0 (see LICENSE).

Cairn bundles a small subset of Sigma detection rules from the SigmaHQ project
(https://github.com/SigmaHQ/sigma), pinned by commit and stored XOR-encoded under
rules/sigma/ (see docs/adr/adr-0002-rule-encoding.md and rules/sigma/PROVENANCE).
Those rules retain their own authorship (DRL 1.1 `author` field) and are governed by
the Detection Rule License (DRL) 1.1 of their upstream project, not by this LICENSE.
```

只改第 4 行，其餘（含 Sigma DRL 段落）逐字保留：

```
This product is licensed under the MIT License (see LICENSE).
```

- [ ] **Step 4: 修改 workspace 根 `Cargo.toml` 的 license 欄位**

修改 `Cargo.toml` 第 19 行：

```toml
license = "MIT"
```

（各 crate 的 `license.workspace = true` 會自動繼承，不需逐一修改各 crate 的 Cargo.toml。）

- [ ] **Step 5: grep 全 repo 確認 Apache 引用清理完畢**

Run: `grep -rli "apache" --include="*.toml" --include="LICENSE*" --include="NOTICE" --include="README.md" .`
Expected: 無輸出（或僅剩 `docs/` 下記錄歷史決策的檔案，那些不改，因為是史料）

- [ ] **Step 6: 檢查並同步 `README.md` 授權章節**

Run: `grep -n -i "license\|apache" README.md`

若有找到授權章節，把提及 Apache-2.0 之處改為 MIT（沿用同一份 grep 結果人工確認，因為 README 目前內容未讀取，實作者需先讀該行上下文再改，禁止盲改）。

- [ ] **Step 7: 編譯確認 license 欄位改動未破壞 workspace**

Run: `cargo check --workspace`
Expected: 編譯成功（license 欄位是 metadata，不影響編譯，但仍要跑一次確認 Cargo.toml 語法正確）

- [ ] **Step 8: Commit**

```bash
git add LICENSE NOTICE Cargo.toml README.md
git commit -m "chore(license): relicense from Apache-2.0 to MIT

Sigma-rule DRL 1.1 attribution in NOTICE is unaffected (upstream license,
not ours to change)."
```

---

## Task 6: 使用手冊更新（第 0 章 + 全文更新至現況）

**Files:**
- Modify: `USER-MANUAL.md`

此 task 交給實作者時必須先讀完整份 `USER-MANUAL.md`（391 行）與
`docs/dev-history/INDEX.md` 取得目前已合併功能清單，因為手冊要「補新功能」
（BYOVD、IR 面板、HTML 篩選、launcher 工程師模式）——這些描述無法在 plan 裡
預先寫死逐字文案（YAGNI：手冊文字不是可預先鎖定的程式碼），改為明確的
**內容需求清單**，實作者對照現況撰寫：

- [ ] **Step 1: 讀取現況依據**

Run: `cat USER-MANUAL.md`（391 行全讀）
Run: `cat docs/dev-history/INDEX.md`（取得已合併功能清單與 commit SHA）
Run: `git log --oneline -1`（取得當下 HEAD 供版本戳使用）

- [ ] **Step 2: 新增「第 0 章：它怎麼運作、能幫你什麼」**

插入於「目錄」章節之後、原「1. 這是什麼」之前。內容需求（非逐字文案，實作者
撰寫，但必須涵蓋以下四點，每點至少一段）：
1. 三階段管線：收集（唯讀）→ 分析（Sigma 規則 + 可解釋啟發式）→ 報告（SHA-256
   完整性簽章的時間軸 + HTML 報告）。
2. 為什麼結果可信：manifest 記錄哪些模組跑了/為什麼跳過（graceful degrade）、
   每個輸出檔有 SHA-256、每個 heuristic finding 都附 `reason` 欄位不是黑箱分數。
3. 什麼情境用它：疑似入侵端點的快速分類（triage），非完整鑑識取證的替代品。
4. 它不做什麼：不修改主機、不迴避 EDR/AMSI/ETW、不連網（`update-rules` 例外且
   僅供工程師手動執行）——直接對應 `cairn/CLAUDE.md` 的 GOLDEN RULES 1/2/3/4。

- [ ] **Step 3: 更新「4. 安裝 / 取得 binary」與「5. 快速開始」章節**

把 launcher 雙擊流程列為一般使用者的主要入口（對照 Task 1-3 剛完成的工程師
子選單，補上「[3] 工程師模式」的說明：profile 掃描三選項的用途差異、離線
EVTX 分析的使用時機——手邊已有 .evtx 檔案、無法或不需要即時掃描時）。CLI
指令參考章節（原「6. 指令參考」）保留給工程師，說明保持不動的部分不重寫，
只在新增旗標處補充（例如 `--profile` 若原本章節未列出三個合法值）。

- [ ] **Step 4: 補新功能說明**

對照 INDEX.md 取得的已合併項目，在對應既有章節（可能是「7. 輸出格式說明」或
「9. 常見情境」）補上：
- BYOVD 偵測（`amcache_driver` source，SHA1 比對已知漏洞驅動清單）
- IR 即時狀態面板（report.html 的 5 個面板：conn/proc/exec/file/logon）
- HTML 報告篩選與聚合（嚴重度/文物/關鍵字篩選、同源 binary 聚合面板）
- gate 重構後的 persistence 判定行為（若原手冊有描述舊的
  CorrelationAnalyzer，需更新為現行的 dispositive-signal persist gate 模型）

- [ ] **Step 5: 更新版本戳**

修改檔首（原第 3 行 `> 版本：0.1.0 ｜ 最後更新：2026-06-26 ｜ 適用 commit：1717a19`）
為 Step 1 取得的當下 HEAD 短 SHA 與日期；授權敘述若手冊內有提及 Apache-2.0
之處，改為 MIT（配合 Task 5）。

- [ ] **Step 6: Read-back 驗證（judgment.md §5 文件驗證標準）**

實作者自行逐條核對：
- 文內每個 CLI 旗標名稱與 `crates/cairn-cli/src/main.rs` 的 clap 定義逐字相符
- 文內每個 launcher 選單項編號與 `crates/cairn-launcher/src/menu.rs` 的
  `print_main_menu`/`print_engineer_menu` 輸出逐字相符
- 概念章節（第 0 章）不出現未在文中解釋的縮寫或術語（如 Sigma、ATT&CK 首次
  出現需有一句話解釋）

- [ ] **Step 7: Commit**

```bash
git add USER-MANUAL.md
git commit -m "docs(manual): add concept chapter and update to current feature set"
```

---

## Task 7: 打包重建 + Task 4-6 整合驗收

**Files:**
- 無程式碼修改；執行 `scripts/package.ps1` 並驗證 `dist/cairn-forensics/` 內容

- [ ] **Step 1: 設定 `CARGO_TARGET_DIR`（避免 OneDrive 鎖定）並執行打包腳本**

Run（PowerShell，Windows 環境執行）:
```powershell
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\AppData\Local\cairn-target"
.\scripts\package.ps1
```
Expected: `dist\cairn-forensics\` 重建完成，無錯誤訊息

- [ ] **Step 2: 驗證 dist 內容完整（7 項）**

Run: `Get-ChildItem dist\cairn-forensics -Recurse | Select-Object FullName`
Expected 包含：`cairn.exe`、`cairn-launcher.exe`、`rules\`（目錄）、
`USER-MANUAL.md`、`LICENSE`、`NOTICE`、`CHECKSUMS.txt`

- [ ] **Step 3: 驗證 build_sha 追上當下 HEAD**

Run: `.\dist\cairn-forensics\cairn.exe --version`
Expected: 顯示的 commit SHA 等於 Task 6 Step 1 取得的 HEAD SHA

- [ ] **Step 4: 真機 e2e — 雙擊 launcher 走一次快樂路徑（手動操作，不可自動化跳過）**

雙擊 `dist\cairn-forensics\cairn-launcher.exe`：
1. 主選單應顯示（含規則版本或「僅啟發式偵測」訊息）
2. 選 `[3]` 進工程師模式，應看到新的子選單（Profile 掃描 / 離線 EVTX 分析 / 返回）
3. 選 `[1]` 進 profile 選單，選 `[3]` Verbose，確認掃描執行、輸出摘要框正確顯示
4. 回主選單，選 `[3][2]`，輸入一個真實 `.evtx` 檔案路徑（可用
   `C:\Windows\System32\winevt\Logs\System.evtx`），確認分析完成並顯示摘要
5. 確認兩次掃描的輸出各自落在 `output\<timestamp>\` 獨立子目錄，互不覆寫

- [ ] **Step 5: 若 Step 4 任一項失敗，回到對應 Task（1-3 為 launcher 邏輯、4 為打包）修正，不在本 task 內修改程式碼**

- [ ] **Step 6: Commit（僅當 dist/ 有被版本控制追蹤時才需要；若 dist/ 在 .gitignore 中則跳過此步驟）**

Run: `git check-ignore dist/cairn-forensics 2>&1; echo "exit code: $?"`

若 exit code 為 0（表示被忽略），本步驟跳過，不 commit dist/ 內容。
若未被忽略，執行：
```bash
git add dist/cairn-forensics
git commit -m "build: rebuild dist package with current HEAD (launcher engineer mode, MIT license, updated manual)"
```

---

## Task 8: 健全性混合審計（獨立派工，fresh-context agent）

**Files:**
- Modify: `docs/REMAINING-WORK.md`（併入審計結果）

此 task 不由本 plan 的實作者連續執行——依 delegation.md §6，審計必須是獨立
fresh-context agent，且審計者不應是完成 Task 1-7 的同一個 agent。派工時使用
以下驗收條件原文（不得由 controller 改寫後轉交）：

**派工 prompt 骨架**（controller 在此 plan 執行到 Task 8 時，用此骨架組出完整
派工訊息，補上 CLAUDE.md 全文路徑提示）：

```
目標：對 cairn 專案做一輪獨立健全性審計，範圍是錯誤處理缺口、擴充點健全度、
發佈流程缺口，並將 docs/REMAINING-WORK.md 段 1-7 的狀態描述對照目前程式碼
實況做差距校正。

動機：專案已完成 S1-S4 + 多輪 post-S4 hardening（gate 重構、IR 面板、BYOVD、
HTML 篩選），累積的 backlog 文件可能與實況脫節；同時想找出程式碼裡尚未被
記錄的健全性問題。

背景：
- 先讀 cairn/CLAUDE.md 全文（golden rules 8 條、workspace map、coding
  conventions）。
- 再讀 docs/REMAINING-WORK.md 全文（現有段 1-7 + 已知殘留風險登記）。
- 再讀 docs/dev-history/INDEX.md（各功能合併狀態速查，避免對已合併功能重複
  提報告落後的 finding）。

審查重點（按序）：
1. 錯誤處理缺口：搜尋 `.unwrap()`、`.expect()`、被吞掉的 `Err` （`let _ = `
   模式）在非測試程式碼中的使用，逐一判斷是否為 golden rule 8（graceful
   degrade）的違規，或是合理的「不可能失敗」場景。
2. 擴充點健全度：新增一個 collector 或 heuristic 目前的接線成本（需要改幾個
   檔案？trait 邊界是否乾淨？）；對照 crates/cairn-heur/src/ 現有範本評估
   一致性。
3. 發佈流程缺口：對照 cairn/CLAUDE.md 的「Legitimacy work」清單（Authenticode
   簽章、版本資源嵌入、hash 發佈、SOC pre-allowlist runbook、MS WDSI 送審）
   逐項確認目前狀態（已完成/未開始/部分完成），給檔案路徑或指令證據。
4. REMAINING-WORK.md 段 1-7 差距校正：每段的「目前狀態」描述是否仍與程式碼
   相符（例如若某段已在後續 PR 悄悄完成但文件未更新）。

驗收條件：
- [ ] 每個 finding 含：檔案:行號、嚴重度（高/中/低）、具體問題、一行修法建議
- [ ] 發佈流程四項逐項給出目前狀態與證據（檔案路徑或指令輸出）
- [ ] REMAINING-WORK.md 段 1-7 逐段給出「相符」或「需更新（原因）」的結論
- [ ] 沒問題的類別明確寫「此類未發現問題」，不要沉默帶過
- [ ] 只審查，不動手改任何程式碼或文件

回報格式：finding 按嚴重度排序列出；≤20 條，超過就只回最重要的 20 條並註明
還有多少。全文 ≤500 字（審計型放寬，因為要覆蓋四個審查重點）。
```

- [ ] **Step 1: Controller 派工（agent type: general-purpose, model: sonnet）**

依上方骨架組出完整 prompt，用 Agent 工具派工，`isolation` 不需要 worktree
（唯讀審計，無檔案修改）。

- [ ] **Step 2: 收到審計報告後，Controller 將 finding 依嚴重度插入
  `docs/REMAINING-WORK.md`**

新增一個「## 段 8 附錄：健全性審計結果（2026-07-09）」章節，貼審計報告的
finding 清單（含檔案:行號），並更新受影響段落的狀態欄位。

- [ ] **Step 3: Commit**

```bash
git add docs/REMAINING-WORK.md
git commit -m "docs(backlog): incorporate hybrid resilience audit findings (segment 8)"
```

---

## Self-Review 完成度檢查

**Spec coverage：**
- 段 A（launcher 工程師模式）→ Task 1-3 ✓
- 段 B（打包健全化）→ Task 4 + Task 7 ✓
- 段 C（手冊更新）→ Task 6 ✓
- 段 D（授權 MIT）→ Task 5 ✓
- 段 E（健全性審計）→ Task 8 ✓
- 跨段紀律（PR + CI、測試範圍分工、零新依賴）→ 每個 task 的 commit 訊息與
  測試範圍已按 cairn/CLAUDE.md 慣例；finishing-a-development-branch 會補上
  全 workspace 權威驗證，本 plan 不重複。

**與 spec 的差異（已在 plan 開頭聲明）：**
spec 原文假設 `cairn evtx` 有 `--input`/`--output` 旗標，經對照原始碼
（`crates/cairn-cli/src/main.rs:56-64`）證實不成立，plan 已改用位置參數
`files: Vec<PathBuf>` + `Command::current_dir` 的正確設計。

**Placeholder scan：** 無 TBD/TODO；Task 6 因手冊文字本質上無法逐字預先鎖定，
改用明確可核對的內容需求清單取代逐字文案，非佔位符。

**Type consistency：** `RunConfig.profile: Option<&'a str>` 在 Task 1 定義，
Task 2 的 `profile_choice_to_value` 回傳 `&'static str` 可直接餵入；
`EvtxConfig` 在 Task 3 定義並在同一 task 內的 `main.rs` 呼叫端使用，欄位名稱
（`cairn_exe`/`files`/`rules_dir`/`output_dir`）全程一致。
