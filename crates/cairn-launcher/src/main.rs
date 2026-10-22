#![forbid(unsafe_code)]

mod menu;
mod package;
mod runner;
mod summary;

use cairn_core::paths::{on_system_drive, volume_of};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Exit codes, so a wrapper script (or the SOC collecting the result) can tell what
/// happened without reading the window.
const EXIT_OK: u8 = 0;
/// cairn.exe missing or the launcher's own folder unreadable: nothing ran.
const EXIT_INIT_FAILED: u8 = 1;
/// The scan or analysis failed (cairn.exe failed, output not writable, no .evtx).
const EXIT_SCAN_FAILED: u8 = 2;
/// The operator declined to write onto the system drive: nothing ran or was written.
const EXIT_CANCELLED: u8 = 3;

/// launcher 啟動時偵測到的環境
struct Env {
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
    if !cairn_exe.is_file() {
        anyhow::bail!(
            "找不到 cairn.exe\n請確認 cairn.exe 與 cairn-launcher.exe 在同一資料夾\n路徑：{}",
            cairn_exe.display()
        );
    }

    let rules_dir = {
        let p = launcher_dir.join("rules").join("sigma");
        if p.exists() {
            Some(p)
        } else {
            None
        }
    };

    // Not created here: the live scan first checks whether this location is on the
    // system drive and may stop without writing anything.
    let output_base = launcher_dir.join("output");

    Ok(Env {
        cairn_exe,
        rules_dir,
        output_base,
    })
}

/// Create the output folder, turning the usual failure (a read-only medium such as a
/// write-protected USB stick or a CD, or a folder the user may not write) into a
/// Chinese explanation of what to do instead of a raw OS error.
fn prepare_output_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!(output_dir_error(dir, &e)))
}

/// The message for a failed output-folder creation. Pure, testable.
fn output_dir_error(dir: &Path, e: &std::io::Error) -> String {
    use std::io::ErrorKind;
    let why = match e.kind() {
        ErrorKind::ReadOnlyFilesystem => {
            "這個位置是唯讀的（例如防寫的 USB 隨身碟或光碟），無法寫入結果。"
        }
        ErrorKind::PermissionDenied => "沒有寫入這個資料夾的權限。",
        ErrorKind::StorageFull => "磁碟空間不足。",
        _ => "無法建立結果資料夾。",
    };
    format!(
        "{why}\n路徑：{}\n請把整個 Cairn 資料夾複製到可寫入的 USB 隨身碟後再執行。\n系統訊息：{e}",
        dir.display()
    )
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

fn rules_ver(rules_dir: Option<&Path>) -> String {
    rules_dir
        .and_then(|d| cairn_sigma::ruleset::ruleset_version(d).ok())
        .unwrap_or_default()
}

/// Warn (zh-TW) and ask before writing evidence onto the system drive. Default N.
/// Returns true when it is OK to continue.
fn confirm_output_location(output_base: &Path) -> bool {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    if !on_system_drive(output_base, &system_root) {
        return true;
    }
    let vol = volume_of(&system_root).unwrap_or_default();
    println!("⚠️  注意：結果資料夾位於系統磁碟 {vol}（與 Windows 安裝在同一顆硬碟）：");
    println!("    {}", output_base.display());
    println!("    掃描結果與匯出的事件記錄會寫進這台「被調查的電腦」的硬碟，");
    println!("    可能覆蓋已刪除檔案的殘留痕跡，影響之後的鑑識。");
    println!("    建議：把整個 Cairn 資料夾複製到 USB 隨身碟，從隨身碟執行。");
    let answer = menu::prompt("仍要寫入系統磁碟並繼續嗎？(Y/N，預設 N)：");
    if menu::is_yes(&answer) {
        println!();
        true
    } else {
        println!("已取消，沒有寫入任何檔案。");
        false
    }
}

fn since_from_hours(hours: u64) -> String {
    let dt = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

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
                            && p.extension()
                                .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    }
}

/// 開始掃描前印出的標題：主機、規則版本，以及這次會做什麼。
fn print_banner(host: &str, ver: &str, rules_loaded: bool, admin: bool) {
    println!("Cairn 威脅鑑識工具");
    println!("主機名稱：{host}");
    if !admin {
        // highestAvailable: a standard user (or an admin who chose "No" at the UAC
        // prompt — Windows then does not start the launcher at all, so that case
        // never reaches here) runs unelevated and the scan degrades gracefully.
        println!("⚠️  未以系統管理員身分執行：安全性記錄、其他使用者的設定等項目會被略過，");
        println!("    結果會比較不完整。若可以，請右鍵選「以系統管理員身分執行」。");
    }
    if rules_loaded {
        println!("規則版本：{}", menu::truncate_rules_ver(ver));
    } else {
        println!("⚠️  找不到規則目錄 rules\\sigma\\，只執行內建偵測（不跑 Sigma 規則）");
    }
    println!();
}

/// 掃描結束後：印摘要、壓縮、用預設瀏覽器打開 report.html。
fn finish(output_dir: &Path, report_dir: &Path, desc: &str) {
    match summary::load_summary(report_dir, desc) {
        Ok(s) => menu::print_summary(&s),
        Err(e) => eprintln!(
            "無法讀取掃描結果（{e}），報告目錄：{}",
            report_dir.display()
        ),
    }
    match package::zip_output(report_dir) {
        Ok(zip_path) => println!("\n要交給資安人員的壓縮檔：{}", zip_path.display()),
        Err(e) => eprintln!("\n壓縮失敗（{e}），報告目錄：{}", output_dir.display()),
    }
    let report = report_dir.join("report.html");
    if report.exists() {
        println!("正在用瀏覽器開啟報告：{}", report.display());
        package::open_path(&report);
    }
}

/// 雙擊：直接掃描這台主機最近 30 天。Ok(false) = 使用者取消（沒有寫入任何東西）。
fn run_live(env: &Env) -> anyhow::Result<bool> {
    if !confirm_output_location(&env.output_base) {
        return Ok(false);
    }
    let case_id = menu::optional_field(&menu::prompt("案件編號（選填，直接按 Enter 略過）："));
    let operator = menu::optional_field(&menu::prompt("操作人員（選填，直接按 Enter 略過）："));
    let output_dir = runner::timestamped_output_dir(&env.output_base);
    prepare_output_dir(&output_dir)?;
    let desc = "最近 30 天";
    let since = since_from_hours(LIVE_HOURS);
    let cfg = runner::RunConfig {
        cairn_exe: &env.cairn_exe,
        rules_dir: env.rules_dir.as_deref(),
        output_dir: &output_dir,
        since: &since,
        profile: None,
        case_id: case_id.as_deref(),
        operator: operator.as_deref(),
        export_evtx: true,
    };
    println!("開始掃描這台主機（{desc}），通常需要幾分鐘，請不要關閉這個視窗。");
    println!("結果會存到：{}\n", output_dir.display());
    runner::run_scan(&cfg)?;
    finish(&output_dir, &output_dir, desc);
    Ok(true)
}

/// 把 .evtx 檔或資料夾拖到程式上：分析這些事件記錄，不掃描這台主機。
fn run_dropped_evtx(env: &Env, dropped: &[PathBuf]) -> anyhow::Result<()> {
    let files: Vec<PathBuf> = dropped.iter().flat_map(|p| expand_evtx_input(p)).collect();
    if files.is_empty() {
        anyhow::bail!("拖進來的檔案裡沒有 .evtx 事件記錄檔");
    }
    let output_dir = runner::timestamped_output_dir(&env.output_base);
    prepare_output_dir(&output_dir)?;
    println!("分析 {} 個事件記錄檔，請稍候...", files.len());
    println!("結果會存到：{}\n", output_dir.display());
    let cfg = runner::EvtxConfig {
        cairn_exe: &env.cairn_exe,
        files: &files,
        rules_dir: env.rules_dir.as_deref(),
        output_dir: &output_dir,
    };
    let report_dir = runner::run_evtx(&cfg)?;
    finish(&output_dir, &report_dir, "離線事件記錄分析");
    Ok(())
}

/// Look-back window of the double-click scan, in hours (30 days): cairn's own default.
const LIVE_HOURS: u64 = cairn_core::config::DEFAULT_SINCE_HOURS as u64;

/// What a launch should do, from its command-line arguments. Windows passes the paths
/// of files dropped onto the exe as arguments; a plain double-click passes none.
#[derive(Debug, PartialEq)]
enum Mode {
    Live,
    Evtx(Vec<PathBuf>),
}

/// Arguments are taken as `OsString` (`std::env::args_os`): `std::env::args` panics on
/// a file name that is not valid Unicode, which Windows allows, so dropping such a file
/// would crash the launcher. A non-Unicode argument is used as-is (Windows passes
/// dropped paths unquoted); a Unicode one is cleaned of quotes and blanks.
fn mode_from_args(args: &[OsString]) -> Mode {
    let paths: Vec<PathBuf> = args
        .iter()
        .filter_map(|a| match a.to_str() {
            Some(s) => menu::clean_path_input(s).map(PathBuf::from),
            None => Some(PathBuf::from(a)),
        })
        .collect();
    if paths.is_empty() {
        Mode::Live
    } else {
        Mode::Evtx(paths)
    }
}

fn main() -> ExitCode {
    let env = match detect_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("\n❌ 初始化失敗：{e}\n");
            menu::wait_enter("按 Enter 離開...");
            return ExitCode::from(EXIT_INIT_FAILED);
        }
    };

    let host = hostname();
    let ver = rules_ver(env.rules_dir.as_deref());
    let admin = cairn_collectors_win::privilege::probe().admin;
    print_banner(&host, &ver, env.rules_dir.is_some(), admin);

    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match mode_from_args(&args) {
        Mode::Live => run_live(&env),
        Mode::Evtx(paths) => run_dropped_evtx(&env, &paths).map(|()| true),
    };
    let code = match result {
        Ok(true) => EXIT_OK,
        Ok(false) => EXIT_CANCELLED,
        Err(e) => {
            eprintln!("\n❌ 掃描發生錯誤：{e}");
            EXIT_SCAN_FAILED
        }
    };
    menu::wait_enter("\n按 Enter 關閉視窗...");
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_means_live_scan() {
        assert_eq!(mode_from_args(&[]), Mode::Live);
        assert_eq!(mode_from_args(&["  ".into()]), Mode::Live);
    }

    #[test]
    fn dropped_paths_mean_evtx_analysis() {
        let m = mode_from_args(&[r#""C:\logs\Security.evtx""#.into(), r"C:\more".into()]);
        assert_eq!(
            m,
            Mode::Evtx(vec![
                PathBuf::from(r"C:\logs\Security.evtx"),
                PathBuf::from(r"C:\more")
            ])
        );
    }

    /// Dropped paths with spaces and Chinese characters arrive intact.
    #[test]
    fn dropped_chinese_paths_with_spaces_are_kept() {
        let m = mode_from_args(&[r"C:\Users\王小明\桌面\事件 記錄".into()]);
        assert_eq!(
            m,
            Mode::Evtx(vec![PathBuf::from(r"C:\Users\王小明\桌面\事件 記錄")])
        );
    }

    /// A dropped file whose name is not valid Unicode is kept as-is (std::env::args
    /// would have panicked on it).
    #[cfg(unix)]
    #[test]
    fn non_unicode_dropped_path_does_not_panic() {
        use std::os::unix::ffi::OsStringExt;
        let odd = OsString::from_vec(b"/logs/\xff.evtx".to_vec());
        assert_eq!(
            mode_from_args(std::slice::from_ref(&odd)),
            Mode::Evtx(vec![PathBuf::from(odd)])
        );
    }

    /// A read-only medium, a denied folder and a full disk each get a Chinese
    /// explanation that names the folder and what to do.
    #[test]
    fn output_dir_errors_are_explained() {
        use std::io::{Error, ErrorKind};
        let dir = Path::new(r"E:\Cairn\output\20260101_000000");
        let ro = output_dir_error(dir, &Error::from(ErrorKind::ReadOnlyFilesystem));
        assert!(ro.contains("唯讀") && ro.contains(r"E:\Cairn\output") && ro.contains("複製"));
        assert!(output_dir_error(dir, &Error::from(ErrorKind::PermissionDenied)).contains("權限"));
        assert!(output_dir_error(dir, &Error::from(ErrorKind::StorageFull)).contains("空間"));
    }

    /// Creating the output under a path whose parent is a FILE fails with the
    /// explained message instead of a bare OS error.
    #[test]
    fn prepare_output_dir_failure_is_explained() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("output");
        std::fs::write(&blocker, b"not a dir").unwrap();
        let err = prepare_output_dir(&blocker.join("20260101_000000")).unwrap_err();
        assert!(err.to_string().contains("請把整個 Cairn 資料夾"), "{err}");
    }

    #[test]
    fn exit_codes_are_distinct() {
        let codes = [EXIT_OK, EXIT_INIT_FAILED, EXIT_SCAN_FAILED, EXIT_CANCELLED];
        for (i, a) in codes.iter().enumerate() {
            assert!(codes[i + 1..].iter().all(|b| a != b));
        }
        assert_eq!(EXIT_OK, 0);
    }

    #[test]
    fn live_window_is_thirty_days() {
        assert_eq!(LIVE_HOURS, 720);
    }

    #[test]
    fn since_from_hours_produces_valid_rfc3339() {
        let s = since_from_hours(24);
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }
}
