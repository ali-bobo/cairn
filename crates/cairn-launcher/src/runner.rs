//! 組合 cairn.exe 的執行參數並啟動子程序。
//!
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

/// 建立 output 子目錄路徑（時間戳命名，不實際建立目錄）。
/// 格式：`<base_output_dir>\YYYYMMDD_HHMMSS`
pub fn timestamped_output_dir(base: &Path) -> PathBuf {
    let now = chrono::Local::now();
    base.join(now.format("%Y%m%d_%H%M%S").to_string())
}

/// 執行 cairn.exe，繼承 stdout/stderr（使用者可看到即時 log）。
pub fn run_scan(cfg: &RunConfig<'_>) -> anyhow::Result<()> {
    let args = build_args(cfg);
    let status = std::process::Command::new(cfg.cairn_exe)
        .args(&args)
        .status()?;
    if !status.success() {
        anyhow::bail!("cairn.exe 執行失敗（exit code: {:?}）", status.code());
    }
    Ok(())
}

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

/// 執行 `cairn evtx`，把子程序工作目錄設成 `cfg.output_dir`，讓
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
        RunConfig {
            cairn_exe: exe,
            rules_dir: rules,
            output_dir: output,
            since,
            profile: None,
        }
    }

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
}
