# cairn-launcher Implementation Plan (Spec A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 `cairn-launcher.exe`——雙擊執行、互動式 CLI 選單、自動呼叫同目錄 `cairn.exe`、掃完顯示摘要並壓縮報告，兩個 exe 均 CRT 靜態連結消除 VCRUNTIME 依賴。

**Architecture:** 新 crate `crates/cairn-launcher` 加入 workspace。純 stdin/stdout 互動（無 TUI 框架），`std::process::Command` 呼叫 cairn.exe，掃完讀 `manifest.json` + `findings.jsonl` 產生摘要，用 `zip` crate 壓縮報告，`explorer.exe` 開啟資料夾。CRT 靜態連結透過 workspace `Cargo.toml` 的 `[target.x86_64-pc-windows-msvc] rustflags` 設定。

**Tech Stack:** Rust stable、`serde_json`（workspace 現有）、`chrono`（workspace 現有）、`zip`（workspace 現有 v2.4 deflate）、`cairn-core`（path dep，取 `Manifest`/`Finding`/`Severity`）。

---

## 背景知識：你需要了解的現有程式碼

### `cairn-core` 的重要型別（`crates/cairn-core/src/`）

**`manifest.rs`** — 掃描後產生的 `manifest.json` 結構：
```rust
pub struct Manifest {
    pub tool: ToolInfo,    // .tool.sigma_ruleset_ver: String
    pub run: RunInfo,      // .run.started_utc, .run.finished_utc, .run.operator
    pub host: HostInfo,    // .host.hostname
    pub privileges: Privileges, // .privileges.admin: bool
    pub counts: Counts,    // .counts.findings_by_sev: BTreeMap<String, u64>
    // key 是 "critical"/"high"/"medium"/"low"/"info"（小寫）
}
```

**`finding.rs`** — `findings.jsonl` 每行一個 Finding：
```rust
pub struct Finding {
    pub severity: Severity,  // Critical/High/Medium/Low/Info
    pub title: String,
    pub ts: DateTime<Utc>,
    // ... 其他欄位
}
pub enum Severity { Critical, High, Medium, Low, Info }
```

### `cairn.exe` 的呼叫方式

完整掃描（有 rules）：
```
cairn.exe run --target live --rules <rules_dir> --output <output_dir>
            --since <ISO8601 UTC datetime>
```

掃描（無 rules，只跑 heuristics）：
```
cairn.exe run --target live --output <output_dir>
            --since <ISO8601 UTC datetime>
```

`--since` 格式：`2026-06-27T14:30:00Z`（RFC3339 UTC）

output_dir 是掃描結果的子目錄，cairn 會在裡面產生：
- `manifest.json`
- `findings.jsonl`
- `timeline.csv`
- `records.jsonl`
- `run.log`

### 現有 workspace deps（可直接用，不需新增）
- `serde = { version = "1.0.228", features = ["derive"] }`
- `serde_json = "1.0.150"`
- `chrono = { version = "0.4.45", features = ["serde"] }`
- `zip = { version = "2.4", default-features = false, features = ["deflate"] }`

### Cargo 環境變數
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
```

---

## File Map

| 動作 | 檔案 | 職責 |
|------|------|------|
| 建立 | `crates/cairn-launcher/Cargo.toml` | crate 宣告 + 依賴 |
| 建立 | `crates/cairn-launcher/src/main.rs` | 啟動、環境檢查、主迴圈 |
| 建立 | `crates/cairn-launcher/src/menu.rs` | 選單渲染、鍵盤輸入 |
| 建立 | `crates/cairn-launcher/src/runner.rs` | 組合 cairn.exe 參數、執行子程序 |
| 建立 | `crates/cairn-launcher/src/summary.rs` | 讀 manifest.json + findings.jsonl、產生摘要 |
| 建立 | `crates/cairn-launcher/src/package.rs` | 壓縮 zip、開啟資料夾 |
| 修改 | `Cargo.toml`（workspace 根） | 加入 `cairn-launcher` + CRT rustflags |
| 建立 | `scripts/package.ps1` | 打包腳本 |

---

## Task 1：Workspace 設定 — crate 骨架 + CRT 靜態連結

**Files:**
- Modify: `Cargo.toml`（workspace 根）
- Create: `crates/cairn-launcher/Cargo.toml`
- Create: `crates/cairn-launcher/src/main.rs`

- [ ] **Step 1: 在 workspace `Cargo.toml` 新增 `cairn-launcher` 成員 + CRT rustflags**

開啟 `Cargo.toml`（workspace 根），在 `members` 陣列新增一行，並在檔案**末尾**新增 rustflags section：

```toml
# members 陣列中加入：
"crates/cairn-launcher",

# 檔案末尾新增（消除 VCRUNTIME140.dll 依賴）：
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]
```

- [ ] **Step 2: 建立 `crates/cairn-launcher/Cargo.toml`**

```toml
[package]
name = "cairn-launcher"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "cairn-launcher"
path = "src/main.rs"

[dependencies]
cairn-core = { path = "../cairn-core" }
serde_json.workspace = true
chrono.workspace = true
zip.workspace = true
```

- [ ] **Step 3: 建立最小 `crates/cairn-launcher/src/main.rs`**

```rust
fn main() {
    println!("cairn-launcher starting");
}
```

- [ ] **Step 4: 確認編譯**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo check --workspace 2>&1
```

Expected：`Finished` 無 error。

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/cairn-launcher/
git commit -m "feat(launcher): add cairn-launcher crate skeleton + CRT static link"
```

---

## Task 2：`summary.rs` — 讀報告、產生摘要結構（TDD）

**Files:**
- Create: `crates/cairn-launcher/src/summary.rs`
- Modify: `crates/cairn-launcher/src/main.rs`（加 `mod summary;`）

這是最核心的純邏輯模組，先寫測試。

- [ ] **Step 1: 建立 `summary.rs`，先寫型別和測試**

```rust
//! 讀取掃描結果 manifest.json + findings.jsonl，產生人類可讀摘要。

use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Clean,   // 無 critical / high
    Alert,   // 有 critical 或 high
}

#[derive(Debug)]
pub struct ScanSummary {
    pub hostname: String,
    pub started_utc: String,       // 已格式化字串 "2026-06-27 14:30 UTC"
    pub time_window_desc: String,  // 由 runner 傳入，如 "最近 24 小時"
    pub admin: bool,
    pub verdict: Verdict,
    pub counts: std::collections::BTreeMap<String, u64>, // "critical"->N ...
    /// Critical + High findings，最多 5 筆，格式 ("CRITICAL", "title")
    pub top_findings: Vec<(String, String)>,
    pub sigma_ruleset_ver: String,
}

/// 從 output 子目錄（含 manifest.json + findings.jsonl）載入摘要。
/// output_dir: cairn 執行後產生的子目錄，如 .\output\20260627_143022\
pub fn load_summary(output_dir: &Path, time_window_desc: &str) -> anyhow::Result<ScanSummary> {
    // 讀 manifest.json
    let manifest_path = output_dir.join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text)?;

    let hostname = manifest["host"]["hostname"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let admin = manifest["privileges"]["admin"].as_bool().unwrap_or(false);
    let sigma_ruleset_ver = manifest["tool"]["sigma_ruleset_ver"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let started_utc = manifest["run"]["started_utc"]
        .as_str()
        .unwrap_or("")
        .to_string();
    // 格式化為 "YYYY-MM-DD HH:MM UTC"
    let started_utc = started_utc
        .get(..16)
        .unwrap_or(&started_utc)
        .replace('T', " ")
        + " UTC";

    // counts
    let counts: std::collections::BTreeMap<String, u64> = manifest["counts"]["findings_by_sev"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();

    let critical = counts.get("critical").copied().unwrap_or(0);
    let high = counts.get("high").copied().unwrap_or(0);
    let verdict = if critical > 0 || high > 0 {
        Verdict::Alert
    } else {
        Verdict::Clean
    };

    // 讀 findings.jsonl，取 Critical + High，最多 5 筆
    let findings_path = output_dir.join("findings.jsonl");
    let mut top_findings: Vec<(String, String)> = Vec::new();
    if findings_path.exists() {
        let content = std::fs::read_to_string(&findings_path)?;
        for line in content.lines() {
            if top_findings.len() >= 5 {
                break;
            }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let sev = v["severity"].as_str().unwrap_or("").to_lowercase();
            if sev == "critical" || sev == "high" {
                let label = sev.to_uppercase();
                let title = v["title"].as_str().unwrap_or("(unknown)").to_string();
                top_findings.push((label, title));
            }
        }
    }

    Ok(ScanSummary {
        hostname,
        started_utc,
        time_window_desc: time_window_desc.to_string(),
        admin,
        verdict,
        counts,
        top_findings,
        sigma_ruleset_ver,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    fn minimal_manifest(critical: u64, high: u64, medium: u64) -> String {
        format!(r#"{{
  "tool": {{"name":"cairn","version":"0.1.0","build_sha":"abc","sigma_ruleset_ver":"98781da+abcd"}},
  "run": {{"started_utc":"2026-06-27T14:30:00Z","finished_utc":"2026-06-27T14:31:00Z","cmdline":"","operator":"","case_id":"","profile":"standard","selected_modules":[]}},
  "host": {{"hostname":"TEST-PC","os_build":"","timezone":"UTC","wall_clock_utc_skew":"unknown"}},
  "privileges": {{"admin":true,"se_backup":false,"se_debug":false}},
  "sources": [], "outputs": [],
  "counts": {{"records":100,"findings_by_sev":{{"critical":{},"high":{},"medium":{},"low":0,"info":0}}}},
  "integrity_note":"",
  "governance": {{"effective_threads":4,"low_priority_applied":false,"truncations":[]}}
}}"#, critical, high, medium)
    }

    #[test]
    fn no_high_critical_is_clean() {
        let dir = temp_dir();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(0, 0, 2));
        write_temp(dir.path(), "findings.jsonl", "");
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.verdict, Verdict::Clean);
        assert_eq!(s.hostname, "TEST-PC");
        assert!(s.admin);
    }

    #[test]
    fn has_high_is_alert() {
        let dir = temp_dir();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(0, 2, 0));
        write_temp(dir.path(), "findings.jsonl", "");
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.verdict, Verdict::Alert);
    }

    #[test]
    fn has_critical_is_alert() {
        let dir = temp_dir();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(1, 0, 0));
        write_temp(dir.path(), "findings.jsonl", "");
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.verdict, Verdict::Alert);
    }

    #[test]
    fn top_findings_capped_at_5() {
        let dir = temp_dir();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(0, 10, 0));
        // 10 high findings
        let mut jsonl = String::new();
        for i in 0..10 {
            jsonl.push_str(&format!(
                r#"{{"severity":"high","title":"Event {i}","ts":"2026-06-27T14:30:00Z","detected_at":"2026-06-27T14:30:00Z","id":"00000000-0000-0000-0000-00000000000{i}","schema":"","source":"heuristic","mitre":[],"host":"TEST","artifact":"","entity":{{}},"details":"","rule_author":null,"rule_id":null,"user":null,"event_id":null,"evidence_ref":null,"details_client":null,"reason":null}}"#
            ));
            jsonl.push('\n');
        }
        write_temp(dir.path(), "findings.jsonl", &jsonl);
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.top_findings.len(), 5);
    }

    #[test]
    fn only_critical_and_high_in_top_findings() {
        let dir = temp_dir();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(1, 1, 5));
        let jsonl = concat!(
            r#"{"severity":"medium","title":"Medium Event","ts":"2026-06-27T14:30:00Z","detected_at":"2026-06-27T14:30:00Z","id":"00000000-0000-0000-0000-000000000001","schema":"","source":"heuristic","mitre":[],"host":"TEST","artifact":"","entity":{},"details":"","rule_author":null,"rule_id":null,"user":null,"event_id":null,"evidence_ref":null,"details_client":null,"reason":null}"#,
            "\n",
            r#"{"severity":"high","title":"High Event","ts":"2026-06-27T14:30:00Z","detected_at":"2026-06-27T14:30:00Z","id":"00000000-0000-0000-0000-000000000002","schema":"","source":"heuristic","mitre":[],"host":"TEST","artifact":"","entity":{},"details":"","rule_author":null,"rule_id":null,"user":null,"event_id":null,"evidence_ref":null,"details_client":null,"reason":null}"#,
            "\n",
        );
        write_temp(dir.path(), "findings.jsonl", jsonl);
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.top_findings.len(), 1);
        assert_eq!(s.top_findings[0].0, "HIGH");
        assert_eq!(s.top_findings[0].1, "High Event");
    }
}
```

- [ ] **Step 2: 在 `Cargo.toml`（launcher）加入 `tempfile` dev-dep**

```toml
[dev-dependencies]
tempfile = "3"
```

同時確認 `tempfile` 在 workspace 根的 `[workspace.dependencies]` 是否已存在——如果有就用 `tempfile.workspace = true`，如果沒有就直接 `tempfile = "3"`（dev-dep 不需要進 workspace）。

- [ ] **Step 3: 在 `main.rs` 加 `mod summary;`**

```rust
mod summary;

fn main() {
    println!("cairn-launcher starting");
}
```

- [ ] **Step 4: 執行測試，確認全通過**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-launcher 2>&1
```

Expected：5 個測試全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-launcher/
git commit -m "feat(launcher): add summary module with load_summary + 5 tests"
```

---

## Task 3：`package.rs` — 壓縮 zip + 開啟資料夾（TDD）

**Files:**
- Create: `crates/cairn-launcher/src/package.rs`
- Modify: `crates/cairn-launcher/src/main.rs`（加 `mod package;`）

- [ ] **Step 1: 建立 `package.rs`**

```rust
//! 把掃描結果目錄壓縮成 .zip，並開啟所在資料夾。

use std::io::Write;
use std::path::{Path, PathBuf};

/// 把 `output_dir`（如 `.\output\20260627_143022\`）內的所有檔案
/// 壓縮成 `.\output\20260627_143022.zip`。
/// 回傳 zip 檔案的路徑。
pub fn zip_output(output_dir: &Path) -> anyhow::Result<PathBuf> {
    // zip 存放位置：output_dir 的 parent + output_dir 的 dir name + ".zip"
    let dir_name = output_dir
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("output_dir has no file name"))?
        .to_string_lossy()
        .into_owned();
    let zip_path = output_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output_dir has no parent"))?
        .join(format!("{dir_name}.zip"));

    let file = std::fs::File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for entry in std::fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            zip.start_file(&name, options)?;
            let content = std::fs::read(&path)?;
            zip.write_all(&content)?;
        }
    }
    zip.finish()?;
    Ok(zip_path)
}

/// Windows 上用 explorer.exe 開啟資料夾。
/// 非 Windows 環境下靜默跳過（單元測試環境）。
pub fn open_folder(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer.exe")
            .arg(path)
            .spawn();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path; // 靜默跳過
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn zip_output_creates_zip_file() {
        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("20260627_143022");
        std::fs::create_dir(&output_dir).unwrap();
        std::fs::write(output_dir.join("manifest.json"), b"{}").unwrap();
        std::fs::write(output_dir.join("findings.jsonl"), b"").unwrap();

        let zip_path = zip_output(&output_dir).unwrap();
        assert!(zip_path.exists(), "zip file should exist");
        assert!(zip_path.metadata().unwrap().len() > 0, "zip should not be empty");
        assert_eq!(zip_path.extension().unwrap(), "zip");
    }

    #[test]
    fn zip_output_contains_expected_files() {
        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("20260627_143022");
        std::fs::create_dir(&output_dir).unwrap();
        std::fs::write(output_dir.join("manifest.json"), b"test-manifest").unwrap();
        std::fs::write(output_dir.join("findings.jsonl"), b"test-findings").unwrap();

        let zip_path = zip_output(&output_dir).unwrap();
        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"findings.jsonl".to_string()));
    }
}
```

- [ ] **Step 2: 在 `main.rs` 加 `mod package;`**

```rust
mod package;
mod summary;

fn main() {
    println!("cairn-launcher starting");
}
```

- [ ] **Step 3: 執行測試**

```powershell
cargo test -p cairn-launcher 2>&1
```

Expected：7 個測試全部 PASS（5 from summary + 2 from package）。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-launcher/src/package.rs crates/cairn-launcher/src/main.rs
git commit -m "feat(launcher): add package module with zip_output + open_folder"
```

---

## Task 4：`runner.rs` — 組合參數、執行 cairn.exe（TDD）

**Files:**
- Create: `crates/cairn-launcher/src/runner.rs`
- Modify: `crates/cairn-launcher/src/main.rs`（加 `mod runner;`）

- [ ] **Step 1: 建立 `runner.rs`**

```rust
//! 組合 cairn.exe 的執行參數並啟動子程序。

use std::path::{Path, PathBuf};

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
    args
}

/// 建立 output 子目錄路徑（時間戳命名，不實際建立目錄）。
/// 格式：`<base_output_dir>\YYYYMMDD_HHMMSS`
pub fn timestamped_output_dir(base: &Path) -> PathBuf {
    let now = chrono::Local::now();
    base.join(now.format("%Y%m%d_%H%M%S").to_string())
}

/// 執行 cairn.exe，繼承 stdout/stderr（使用者可看到即時 log）。
/// 回傳 output 子目錄路徑（掃完後可讀取 manifest.json）。
pub fn run_scan(cfg: &RunConfig<'_>) -> anyhow::Result<()> {
    let args = build_args(cfg);
    let status = std::process::Command::new(cfg.cairn_exe)
        .args(&args)
        .status()?;
    if !status.success() {
        anyhow::bail!(
            "cairn.exe 執行失敗（exit code: {:?}）",
            status.code()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_cfg<'a>(
        exe: &'a Path,
        rules: Option<&'a Path>,
        output: &'a Path,
        since: &'a str,
    ) -> RunConfig<'a> {
        RunConfig { cairn_exe: exe, rules_dir: rules, output_dir: output, since }
    }

    #[test]
    fn build_args_with_rules() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let rules = PathBuf::from(r"C:\tools\rules\sigma");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = make_cfg(&exe, Some(&rules), &output, "2026-06-27T14:30:00Z");
        let args = build_args(&cfg);
        assert_eq!(args[0], "run");
        assert!(args.contains(&"--rules".to_string()));
        assert!(args.contains(&rules.display().to_string()));
        assert!(args.contains(&"--since".to_string()));
        assert!(args.contains(&"2026-06-27T14:30:00Z".to_string()));
    }

    #[test]
    fn build_args_without_rules_has_no_rules_flag() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = make_cfg(&exe, None, &output, "2026-06-27T14:30:00Z");
        let args = build_args(&cfg);
        assert!(!args.contains(&"--rules".to_string()));
        assert!(args.contains(&"--target".to_string()));
        assert!(args.contains(&"live".to_string()));
    }

    #[test]
    fn build_args_output_dir_is_included() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = make_cfg(&exe, None, &output, "2026-06-27T14:30:00Z");
        let args = build_args(&cfg);
        assert!(args.contains(&"--output".to_string()));
        assert!(args.contains(&output.display().to_string()));
    }

    #[test]
    fn timestamped_output_dir_format() {
        let base = PathBuf::from(r"C:\tools\output");
        let result = timestamped_output_dir(&base);
        let name = result.file_name().unwrap().to_str().unwrap();
        // 格式應為 YYYYMMDD_HHMMSS（15 字元）
        assert_eq!(name.len(), 15, "format should be YYYYMMDD_HHMMSS: {name}");
        assert_eq!(&name[8..9], "_");
    }
}
```

- [ ] **Step 2: 在 `main.rs` 加 `mod runner;`**

```rust
mod package;
mod runner;
mod summary;

fn main() {
    println!("cairn-launcher starting");
}
```

- [ ] **Step 3: 執行測試**

```powershell
cargo test -p cairn-launcher 2>&1
```

Expected：11 個測試全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-launcher/src/runner.rs crates/cairn-launcher/src/main.rs
git commit -m "feat(launcher): add runner module with build_args + timestamped_output_dir"
```

---

## Task 5：`menu.rs` — 選單渲染 + 鍵盤輸入

**Files:**
- Create: `crates/cairn-launcher/src/menu.rs`
- Modify: `crates/cairn-launcher/src/main.rs`（加 `mod menu;`）

menu.rs 是純 I/O，邏輯很薄，不需要 TDD。直接實作。

- [ ] **Step 1: 建立 `menu.rs`**

```rust
//! 選單渲染與使用者輸入。純 I/O，無業務邏輯。

use std::io::{self, BufRead, Write};

/// 清除終端畫面（Windows cmd/PowerShell）
pub fn clear_screen() {
    print!("\x1B[2J\x1B[H");
    let _ = io::stdout().flush();
}

/// 讀取使用者輸入的一行，回傳第一個非空白字元（大寫）。
/// 若輸入為空或 EOF，回傳 '\0'。
pub fn read_choice() -> char {
    let stdin = io::stdin();
    let mut line = String::new();
    let _ = stdin.lock().read_line(&mut line);
    line.trim().chars().next().map(|c| c.to_ascii_uppercase()).unwrap_or('\0')
}

/// 印主選單（標題 + 環境資訊 + 選項）
pub fn print_main_menu(hostname: &str, rules_ver: &str, rules_loaded: bool) {
    let rules_info = if rules_loaded {
        format!("規則版本：{}", truncate_rules_ver(rules_ver))
    } else {
        "規則：未載入（僅啟發式偵測）".to_string()
    };
    println!("╔══════════════════════════════════════════╗");
    println!("║    Cairn 威脅鑑識工具                    ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  主機名稱：{:<30}║", hostname);
    println!("║  {:<40}║", rules_info);
    println!("╠══════════════════════════════════════════╣");
    println!("║  [1] 快速掃描（最近 24 小時）            ║");
    println!("║  [2] 自訂時間範圍                        ║");
    println!("║  [3] 工程師模式                          ║");
    println!("║  [Q] 離開                               ║");
    println!("╚══════════════════════════════════════════╝");
    print!("請選擇：");
    let _ = io::stdout().flush();
}

/// 印時間範圍選單，回傳使用者選擇的小時數和描述字串。
/// 回傳 (hours, description)
pub fn print_time_menu() -> (u64, &'static str) {
    println!("\n選擇掃描時間範圍：");
    println!("  [1] 最近 1 小時");
    println!("  [2] 最近 6 小時");
    println!("  [3] 最近 24 小時");
    println!("  [4] 最近 72 小時");
    println!("  [5] 最近 7 天（168 小時）");
    print!("請選擇（預設 3）：");
    let _ = io::stdout().flush();
    let choice = read_choice();
    match choice {
        '1' => (1, "最近 1 小時"),
        '2' => (6, "最近 6 小時"),
        '4' => (72, "最近 72 小時"),
        '5' => (168, "最近 7 天"),
        _ => (24, "最近 24 小時"),  // 預設：3 或任何其他輸入
    }
}

/// 印摘要框
pub fn print_summary(s: &crate::summary::ScanSummary) {
    use crate::summary::Verdict;
    println!("\n╔══════════════════════════════════════════╗");
    println!("║  掃描完成                                ║");
    println!("║  時間範圍：{:<30}║", s.time_window_desc);
    println!("║  掃描時間：{:<30}║", s.started_utc);
    println!("║  管理員權限：{:<28}║", if s.admin { "是" } else { "否（部分功能受限）" });
    println!("╠══════════════════════════════════════════╣");
    match s.verdict {
        Verdict::Clean => {
            println!("║                                          ║");
            println!("║  ✅ 未發現高風險威脅                      ║");
            println!("║                                          ║");
        }
        Verdict::Alert => {
            println!("║                                          ║");
            println!("║  ⚠️  發現高風險事件，請立即聯絡資安工程師 ║");
            println!("║                                          ║");
            for (sev, title) in &s.top_findings {
                let line = format!("  [{sev}] {title}");
                println!("║  {:<40}║", truncate(&line, 40));
            }
            let total_high = s.counts.get("critical").copied().unwrap_or(0)
                + s.counts.get("high").copied().unwrap_or(0);
            if total_high > s.top_findings.len() as u64 {
                let extra = total_high - s.top_findings.len() as u64;
                println!("║  （還有 {} 筆，請查看完整報告）          ║", extra);
            }
            println!("║                                          ║");
        }
    }
    // 顯示 medium / low（無論 verdict）
    let medium = s.counts.get("medium").copied().unwrap_or(0);
    let low = s.counts.get("low").copied().unwrap_or(0);
    if medium > 0 || low > 0 {
        if matches!(s.verdict, Verdict::Clean) {
            println!("║  Medium: {:>3}（建議稍後請工程師確認）     ║", medium);
            println!("║  Low:    {:>3}（一般性記錄，無需立即處理） ║", low);
        } else {
            println!("║  Medium: {:>3}  Low: {:>3}               ║", medium, low);
        }
    }
    println!("╚══════════════════════════════════════════╝");
}

/// 等待 Enter，顯示提示訊息
pub fn wait_enter(msg: &str) {
    print!("{}", msg);
    let _ = io::stdout().flush();
    let _ = read_choice();
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn truncate_rules_ver(ver: &str) -> String {
    // "98781da19cf60c48ce6e7f2d3ad11c9ba389191a+abcd..." -> "98781da+abcd…"
    if let Some((pin, agg)) = ver.split_once('+') {
        let short_pin = &pin[..pin.len().min(7)];
        let short_agg = &agg[..agg.len().min(8)];
        format!("{short_pin}+{short_agg}…")
    } else {
        truncate(ver, 20)
    }
}
```

- [ ] **Step 2: 在 `main.rs` 加 `mod menu;`**

```rust
mod menu;
mod package;
mod runner;
mod summary;

fn main() {
    println!("cairn-launcher starting");
}
```

- [ ] **Step 3: cargo check**

```powershell
cargo check -p cairn-launcher 2>&1
```

Expected：無 error。

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-launcher/src/menu.rs crates/cairn-launcher/src/main.rs
git commit -m "feat(launcher): add menu module with print/input helpers"
```

---

## Task 6：`main.rs` — 環境檢查 + 主迴圈組裝

**Files:**
- Modify: `crates/cairn-launcher/src/main.rs`（完整實作）

- [ ] **Step 1: 完整實作 `main.rs`**

```rust
mod menu;
mod package;
mod runner;
mod summary;

use std::path::{Path, PathBuf};

/// launcher 啟動時偵測到的環境
struct Env {
    /// launcher 所在目錄（cairn.exe 和 rules\ 應在同一目錄）
    launcher_dir: PathBuf,
    /// cairn.exe 完整路徑
    cairn_exe: PathBuf,
    /// rules\sigma\ 目錄，None 表示找不到（heuristics-only 模式）
    rules_dir: Option<PathBuf>,
    /// output\ 目錄（自動建立）
    output_base: PathBuf,
}

fn detect_env() -> anyhow::Result<Env> {
    let launcher_exe = std::env::current_exe()?;
    let launcher_dir = launcher_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("無法取得 launcher 所在目錄"))?
        .to_path_buf();

    let cairn_exe = launcher_dir.join("cairn.exe");
    if !cairn_exe.exists() {
        anyhow::bail!(
            "找不到 cairn.exe\n請確認 cairn.exe 與 cairn-launcher.exe 在同一資料夾\n路徑：{}",
            cairn_exe.display()
        );
    }

    let rules_dir = {
        let p = launcher_dir.join("rules").join("sigma");
        if p.exists() { Some(p) } else { None }
    };

    let output_base = launcher_dir.join("output");
    std::fs::create_dir_all(&output_base)?;

    Ok(Env { launcher_dir, cairn_exe, rules_dir, output_base })
}

fn hostname() -> String {
    // 從環境變數取，cairn.exe 執行時才會有精確的 hostname
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

fn rules_ver(rules_dir: Option<&Path>) -> String {
    rules_dir
        .and_then(|d| cairn_sigma::ruleset::ruleset_version(d, false).ok())
        .unwrap_or_default()
}

fn since_from_hours(hours: u64) -> String {
    let dt = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn run_scan_flow(env: &Env, hours: u64, desc: &str) -> anyhow::Result<()> {
    let output_dir = runner::timestamped_output_dir(&env.output_base);
    std::fs::create_dir_all(&output_dir)?;

    let since = since_from_hours(hours);
    let cfg = runner::RunConfig {
        cairn_exe: &env.cairn_exe,
        rules_dir: env.rules_dir.as_deref(),
        output_dir: &output_dir,
        since: &since,
    };

    println!("\n執行掃描中，請稍候...");
    println!("（掃描範圍：{}，輸出目錄：{}）\n", desc, output_dir.display());

    runner::run_scan(&cfg)?;

    // 讀摘要
    match summary::load_summary(&output_dir, desc) {
        Ok(s) => {
            menu::print_summary(&s);
            // 壓縮報告
            match package::zip_output(&output_dir) {
                Ok(zip_path) => {
                    println!("║  報告已壓縮：                            ║");
                    println!("║  {:<40}║", zip_path.display().to_string());
                    println!("╚══════════════════════════════════════════╝");
                    menu::wait_enter("\n按 Enter 開啟報告資料夾...");
                    package::open_folder(&env.output_base);
                }
                Err(e) => {
                    eprintln!("壓縮失敗（{e}），報告仍可在以下目錄找到：");
                    eprintln!("{}", output_dir.display());
                    menu::wait_enter("\n按 Enter 繼續...");
                }
            }
        }
        Err(e) => {
            eprintln!("無法讀取掃描結果（{e}）");
            eprintln!("報告目錄：{}", output_dir.display());
            menu::wait_enter("\n按 Enter 繼續...");
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // 環境檢查
    let env = match detect_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("\n❌ 初始化失敗：{e}\n");
            menu::wait_enter("按 Enter 離開...");
            return Ok(());
        }
    };

    if env.rules_dir.is_none() {
        eprintln!(
            "⚠️  找不到規則目錄 rules\\sigma\\，Sigma 偵測將無法執行（僅啟發式偵測）\n"
        );
    }

    let host = hostname();
    let ver = rules_ver(env.rules_dir.as_deref());
    let rules_loaded = env.rules_dir.is_some();

    loop {
        menu::clear_screen();
        menu::print_main_menu(&host, &ver, rules_loaded);

        match menu::read_choice() {
            '1' => {
                if let Err(e) = run_scan_flow(&env, 24, "最近 24 小時") {
                    eprintln!("\n掃描發生錯誤：{e}");
                    menu::wait_enter("按 Enter 繼續...");
                }
            }
            '2' => {
                let (hours, desc) = menu::print_time_menu();
                if let Err(e) = run_scan_flow(&env, hours, desc) {
                    eprintln!("\n掃描發生錯誤：{e}");
                    menu::wait_enter("按 Enter 繼續...");
                }
            }
            '3' => {
                menu::clear_screen();
                println!("\n工程師模式開發中，敬請期待。\n");
                menu::wait_enter("按 Enter 回到主選單...");
            }
            'Q' => {
                println!("\n離開 Cairn 鑑識工具。");
                break;
            }
            _ => {
                // 無效輸入，重新顯示選單
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_from_hours_produces_valid_rfc3339() {
        let s = since_from_hours(24);
        // 格式應為 "YYYY-MM-DDTHH:MM:SSZ"
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }
}
```

- [ ] **Step 2: 在 `cairn-launcher/Cargo.toml` 加 `cairn-sigma` 依賴**（用於 `rules_ver()`）

```toml
[dependencies]
cairn-core = { path = "../cairn-core" }
cairn-sigma = { path = "../cairn-sigma" }
serde_json.workspace = true
chrono.workspace = true
zip.workspace = true
anyhow.workspace = true
```

- [ ] **Step 3: cargo check + test**

```powershell
cargo check --workspace 2>&1
cargo test -p cairn-launcher 2>&1
```

Expected：check 無 error，12 個測試全部 PASS（11 前面的 + 1 新的）。

- [ ] **Step 4: cargo clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings 2>&1
```

Fix any warnings。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-launcher/
git commit -m "feat(launcher): implement main loop with env check + scan flow"
```

---

## Task 7：打包腳本 + 最終驗證

**Files:**
- Create: `scripts/package.ps1`
- 驗證整體 workspace build + test

- [ ] **Step 1: 建立 `scripts/package.ps1`**

```powershell
# scripts/package.ps1
# 用途：建立可發佈的 cairn-forensics 套件
# 執行：在 cairn/ 根目錄執行 .\scripts\package.ps1

param(
    [string]$OutDir = "dist\cairn-forensics"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Building release binaries..." -ForegroundColor Cyan

# 確保 CARGO_TARGET_DIR 設定
if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = "$env:USERPROFILE\AppData\Local\cairn-target"
}

cargo build --release -p cairn-cli -p cairn-launcher
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

$TargetDir = "$env:CARGO_TARGET_DIR\release"

Write-Host "Packaging to $OutDir..." -ForegroundColor Cyan

# 清除舊的 dist
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force $OutDir | Out-Null

# 複製 exe
Copy-Item "$TargetDir\cairn.exe"          "$OutDir\cairn.exe"
Copy-Item "$TargetDir\cairn-launcher.exe" "$OutDir\cairn-launcher.exe"

# 複製 rules
Copy-Item -Recurse "rules" "$OutDir\rules"

Write-Host ""
Write-Host "Done! Package ready at: $OutDir" -ForegroundColor Green
Write-Host "Contents:"
Get-ChildItem $OutDir -Recurse | Select-Object FullName
```

- [ ] **Step 2: 執行打包腳本確認輸出正確**

```powershell
.\scripts\package.ps1
```

Expected：`dist\cairn-forensics\` 包含 `cairn.exe`、`cairn-launcher.exe`、`rules\sigma\`。

- [ ] **Step 3: 確認 CRT 靜態連結（無 VCRUNTIME 依賴）**

```powershell
# 用 dumpbin 或 python 檢查 launcher exe
python3 -c "
import sys
data = open(r'dist\cairn-forensics\cairn-launcher.exe','rb').read()
if b'VCRUNTIME' in data:
    print('FAIL: VCRUNTIME dependency found')
    sys.exit(1)
else:
    print('OK: No VCRUNTIME dependency')
"
```

Expected：`OK: No VCRUNTIME dependency`。

- [ ] **Step 4: 全 workspace test**

```powershell
cargo test --workspace 2>&1 | tail -15
```

Expected：所有測試通過（520+ tests）。

- [ ] **Step 5: Commit**

```bash
git add scripts/package.ps1
git commit -m "feat(launcher): add package.ps1 build script"
```

---

## Self-Review

### Spec coverage

| Spec 需求 | Task |
|----------|------|
| 新 crate `cairn-launcher` 加入 workspace | T1 |
| CRT 靜態連結 rustflags | T1 |
| `summary.rs` 讀 manifest.json + findings.jsonl | T2 |
| verdict 判斷（critical/high → ⚠️）| T2 |
| top_findings 最多 5 筆 Critical/High | T2 |
| zip_output 壓縮報告目錄 | T3 |
| open_folder 開啟資料夾 | T3 |
| build_args 組合 cairn.exe 參數 | T4 |
| timestamped_output_dir 時間戳命名 | T4 |
| run_scan 執行子程序 | T4 |
| print_main_menu / read_choice / print_time_menu | T5 |
| print_summary 摘要框（含 medium/low 說明文字）| T5 |
| detect_env 環境檢查（cairn.exe 找不到 → 清楚錯誤）| T6 |
| rules 找不到 → 警告但繼續（heuristics-only）| T6 |
| 主迴圈（1/2/3/Q）| T6 |
| 工程師模式入口（顯示開發中訊息）| T6 |
| 打包腳本 package.ps1 | T7 |
| 驗證 CRT 靜態連結 | T7 |

### Placeholder scan

無 TBD/TODO。所有程式碼區塊完整。

### Type consistency

- `runner::RunConfig` 在 T4 定義，T6 使用 → 一致 ✅
- `summary::ScanSummary` + `Verdict` 在 T2 定義，T5 `print_summary` 使用 → 一致 ✅
- `runner::timestamped_output_dir` 在 T4 定義，T6 使用 → 一致 ✅
