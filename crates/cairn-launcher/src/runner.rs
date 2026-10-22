//! 組合 cairn.exe 的執行參數並啟動子程序。
//!
use std::ffi::OsString;
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
    /// --profile 的值（"minimal"/"standard"）。None 時不帶旗標，
    /// cairn.exe 自身預設 "standard"（見 cairn-cli RunArgs::profile default_value）。
    pub profile: Option<&'a str>,
    /// --case-id（案件編號），None 時不帶旗標。
    pub case_id: Option<&'a str>,
    /// --operator（操作人員），None 時不帶旗標。
    pub operator: Option<&'a str>,
    /// true 時明確帶 --export-evtx（把事件記錄匯出到輸出資料夾的 evidence\evtx\）。
    pub export_evtx: bool,
}

/// 根據 `RunConfig` 建立 cairn.exe 的完整參數列表。
/// 純函式，便於測試（不實際執行任何程序）。
///
/// 路徑以 `OsString` 原樣傳遞，不經 `display()`：含空白或中文的路徑（例如中文
/// 使用者名稱）各自是「一個」參數（`Command` 會正確加引號），而 Windows 允許、
/// 但不是合法 Unicode 的檔名也不會被替換成 U+FFFD 而指向不存在的路徑。
pub fn build_args(cfg: &RunConfig<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "run".into(),
        "--target".into(),
        "live".into(),
        "--output".into(),
        cfg.output_dir.as_os_str().to_owned(),
        "--since".into(),
        cfg.since.into(),
    ];
    if let Some(rules) = cfg.rules_dir {
        args.push("--rules".into());
        args.push(rules.as_os_str().to_owned());
    }
    if let Some(profile) = cfg.profile {
        args.push("--profile".into());
        args.push(profile.into());
    }
    if let Some(case_id) = cfg.case_id {
        args.push("--case-id".into());
        args.push(case_id.into());
    }
    if let Some(operator) = cfg.operator {
        args.push("--operator".into());
        args.push(operator.into());
    }
    args.push(if cfg.export_evtx {
        "--export-evtx".into()
    } else {
        "--no-export-evtx".into()
    });
    args
}

/// 啟動 cairn.exe 並等它結束；任何失敗都轉成使用者看得懂的中文訊息。
fn run_child(exe: &Path, args: &[OsString], cwd: Option<&Path>) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!(spawn_error(exe, &e)))?;
    if !status.success() {
        anyhow::bail!(exit_error(status.code()));
    }
    Ok(())
}

/// cairn.exe 無法啟動時的說明。純函式，可測試。
pub fn spawn_error(exe: &Path, e: &std::io::Error) -> String {
    let why = match e.kind() {
        std::io::ErrorKind::NotFound => "找不到檔案（可能已被移動、刪除或被防毒軟體隔離）",
        std::io::ErrorKind::PermissionDenied => "沒有執行權限（可能被防毒軟體或應用程式控管封鎖）",
        _ => "系統拒絕執行",
    };
    format!(
        "無法啟動 cairn.exe：{why}\n路徑：{}\n系統訊息：{e}",
        exe.display()
    )
}

/// cairn.exe 以非 0 結束（或被終止）時的說明。純函式，可測試。
pub fn exit_error(code: Option<i32>) -> String {
    match code {
        Some(c) => format!(
            "cairn.exe 執行失敗（結束代碼 {c}）。詳細原因請看上方訊息或結果資料夾中的 run.log。"
        ),
        None => "cairn.exe 被中途終止（可能被防毒軟體或使用者結束）。結果可能不完整，請勿使用。"
            .to_string(),
    }
}

/// 建立 output 子目錄路徑（時間戳命名，不實際建立目錄）。
/// 格式：`<base_output_dir>\YYYYMMDD_HHMMSS`
pub fn timestamped_output_dir(base: &Path) -> PathBuf {
    let now = chrono::Local::now();
    base.join(now.format("%Y%m%d_%H%M%S").to_string())
}

/// 執行 cairn.exe，繼承 stdout/stderr（使用者可看到即時 log）。
pub fn run_scan(cfg: &RunConfig<'_>) -> anyhow::Result<()> {
    run_child(cfg.cairn_exe, &build_args(cfg), None)
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
pub fn build_evtx_args(cfg: &EvtxConfig<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["evtx".into()];
    for f in cfg.files {
        args.push(f.as_os_str().to_owned());
    }
    if let Some(rules) = cfg.rules_dir {
        args.push("--rules".into());
        args.push(rules.as_os_str().to_owned());
    }
    args
}

/// 執行 `cairn evtx`，把子程序工作目錄設成 `cfg.output_dir`，讓
/// `cairn.exe` 預設輸出的 `./out` 落在 `cfg.output_dir` 裡（golden rule 4：
/// 輸出離 target，不寫進來源目錄）。呼叫前 `cfg.output_dir` 必須已存在。
pub fn run_evtx(cfg: &EvtxConfig<'_>) -> anyhow::Result<PathBuf> {
    run_child(cfg.cairn_exe, &build_evtx_args(cfg), Some(cfg.output_dir))?;
    Ok(cfg.output_dir.join("out"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The arguments as text, for assertions.
    fn strs(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

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
            case_id: None,
            operator: None,
            export_evtx: true,
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
            profile: Some("minimal"),
            case_id: None,
            operator: None,
            export_evtx: true,
        };
        let args = strs(build_args(&cfg));
        assert!(args.contains(&"--profile".to_string()));
        assert!(args.contains(&"minimal".to_string()));
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
            case_id: None,
            operator: None,
            export_evtx: true,
        };
        let args = strs(build_args(&cfg));
        assert!(!args.contains(&"--profile".to_string()));
    }

    #[test]
    fn build_args_with_rules() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let rules = PathBuf::from(r"C:\tools\rules\sigma");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = make_cfg(&exe, Some(&rules), &output, "2026-06-27T14:30:00Z");
        let args = strs(build_args(&cfg));
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
        let args = strs(build_args(&cfg));
        assert!(!args.contains(&"--rules".to_string()));
        assert!(args.contains(&"--target".to_string()));
        assert!(args.contains(&"live".to_string()));
    }

    #[test]
    fn build_args_output_dir_is_included() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let output = PathBuf::from(r"C:\tools\output\20260627_143022");
        let cfg = make_cfg(&exe, None, &output, "2026-06-27T14:30:00Z");
        let args = strs(build_args(&cfg));
        assert!(args.contains(&"--output".to_string()));
        assert!(args.contains(&output.display().to_string()));
    }

    #[test]
    fn build_args_passes_case_operator_and_export() {
        let exe = PathBuf::from(r"C:\tools\cairn.exe");
        let output = PathBuf::from(r"C:\tools\output\x");
        let mut cfg = make_cfg(&exe, None, &output, "2026-06-27T14:30:00Z");
        let args = strs(build_args(&cfg));
        assert!(
            args.contains(&"--export-evtx".to_string()),
            "export on by default"
        );
        assert!(!args.contains(&"--case-id".to_string()));
        assert!(!args.contains(&"--operator".to_string()));
        cfg.case_id = Some("IR-2026-07");
        cfg.operator = Some("王小明");
        cfg.export_evtx = false;
        let args = strs(build_args(&cfg));
        let pos = |f: &str| args.iter().position(|a| a == f).unwrap();
        assert_eq!(args[pos("--case-id") + 1], "IR-2026-07");
        assert_eq!(args[pos("--operator") + 1], "王小明");
        assert!(args.contains(&"--no-export-evtx".to_string()));
        assert!(
            !args.contains(&"--reference-time".to_string()),
            "never prompted"
        );
    }

    /// Paths with spaces and Chinese characters (a Chinese Windows user name) stay ONE
    /// argument each, unchanged, for both the live and the evtx command lines.
    #[test]
    fn paths_with_spaces_and_chinese_are_single_arguments() {
        let exe = PathBuf::from(r"C:\Users\王小明\My Tools\cairn.exe");
        let rules = PathBuf::from(r"C:\Users\王小明\My Tools\rules\sigma");
        let output = PathBuf::from(r"C:\Users\王小明\My Tools\output\20260627_143022");
        let cfg = make_cfg(&exe, Some(&rules), &output, "2026-06-27T14:30:00Z");
        let args = strs(build_args(&cfg));
        let after = |f: &str| args[args.iter().position(|a| a == f).unwrap() + 1].clone();
        assert_eq!(after("--output"), output.to_str().unwrap());
        assert_eq!(after("--rules"), rules.to_str().unwrap());

        let files = vec![PathBuf::from(r"D:\事件 記錄\Security (1).evtx")];
        let ecfg = EvtxConfig {
            cairn_exe: &exe,
            files: &files,
            rules_dir: None,
            output_dir: &output,
        };
        assert_eq!(
            strs(build_evtx_args(&ecfg)),
            vec!["evtx", r"D:\事件 記錄\Security (1).evtx"]
        );
    }

    /// A file name that is not valid Unicode is passed through byte-for-byte, not
    /// replaced with U+FFFD (which would name a different, non-existent file).
    #[cfg(unix)]
    #[test]
    fn non_unicode_paths_pass_through_unchanged() {
        use std::os::unix::ffi::OsStringExt;
        let odd = PathBuf::from(OsString::from_vec(b"/evtx/\xff\xfe.evtx".to_vec()));
        let exe = PathBuf::from("/cairn");
        let files = vec![odd.clone()];
        let ecfg = EvtxConfig {
            cairn_exe: &exe,
            files: &files,
            rules_dir: None,
            output_dir: &odd,
        };
        assert_eq!(build_evtx_args(&ecfg)[1], odd.as_os_str());
    }

    /// Spawn and exit failures read as Chinese guidance, not a raw OS error.
    #[test]
    fn child_failures_have_chinese_messages() {
        let exe = Path::new(r"E:\cairn\cairn.exe");
        let nf = spawn_error(exe, &std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(nf.contains("找不到檔案") && nf.contains(r"E:\cairn\cairn.exe"));
        let pd = spawn_error(
            exe,
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(pd.contains("防毒"));
        assert!(exit_error(Some(2)).contains("結束代碼 2"));
        assert!(exit_error(None).contains("不完整"));
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
        let args = strs(build_evtx_args(&cfg));
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
        let args = strs(build_evtx_args(&cfg));
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
        let args = strs(build_evtx_args(&cfg));
        assert!(args.contains(&files[0].display().to_string()));
        assert!(args.contains(&files[1].display().to_string()));
    }
}
