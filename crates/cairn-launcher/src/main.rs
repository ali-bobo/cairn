#![forbid(unsafe_code)]

mod menu;
mod package;
mod runner;
mod summary;

use std::path::{Path, PathBuf};

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
    if !cairn_exe.exists() {
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

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

fn rules_ver(rules_dir: Option<&Path>) -> String {
    rules_dir
        .and_then(|d| cairn_sigma::ruleset::ruleset_version(d).ok())
        .unwrap_or_default()
}

/// The volume a Windows path lives on: `C:` (upper-cased) for a drive path, or
/// `\\SERVER\SHARE` for a UNC path; the `\\?\` / `\\?\UNC\` verbatim prefixes are
/// understood. None when the path names no volume (relative). Pure string logic so it
/// is testable off Windows.
fn volume_of(path: &str) -> Option<String> {
    let p = path.trim();
    let (p, unc) = if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        (rest, true)
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        (rest, false)
    } else if let Some(rest) = p.strip_prefix(r"\\") {
        (rest, true)
    } else {
        (p, false)
    };
    if unc {
        let mut parts = p.split(['\\', '/']).filter(|s| !s.is_empty());
        let server = parts.next()?;
        let share = parts.next()?;
        return Some(format!(r"\\{}\{}", server, share).to_uppercase());
    }
    let b = p.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        .then(|| p[..2].to_ascii_uppercase())
}

/// True when `output` is on the same volume as `system_root` (%SystemRoot%), i.e.
/// evidence would be written onto the disk under investigation.
fn on_system_drive(output: &Path, system_root: &str) -> bool {
    match (
        volume_of(&output.display().to_string()),
        volume_of(system_root),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
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
fn print_banner(host: &str, ver: &str, rules_loaded: bool) {
    println!("Cairn 威脅鑑識工具");
    println!("主機名稱：{host}");
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

/// 雙擊：直接掃描這台主機最近 30 天。
fn run_live(env: &Env) -> anyhow::Result<()> {
    if !confirm_output_location(&env.output_base) {
        return Ok(());
    }
    let case_id = menu::optional_field(&menu::prompt("案件編號（選填，直接按 Enter 略過）："));
    let operator = menu::optional_field(&menu::prompt("操作人員（選填，直接按 Enter 略過）："));
    let output_dir = runner::timestamped_output_dir(&env.output_base);
    std::fs::create_dir_all(&output_dir)?;
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
    Ok(())
}

/// 把 .evtx 檔或資料夾拖到程式上：分析這些事件記錄，不掃描這台主機。
fn run_dropped_evtx(env: &Env, dropped: &[PathBuf]) -> anyhow::Result<()> {
    let files: Vec<PathBuf> = dropped.iter().flat_map(|p| expand_evtx_input(p)).collect();
    if files.is_empty() {
        anyhow::bail!("拖進來的檔案裡沒有 .evtx 事件記錄檔");
    }
    let output_dir = runner::timestamped_output_dir(&env.output_base);
    std::fs::create_dir_all(&output_dir)?;
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

fn mode_from_args(args: &[String]) -> Mode {
    let paths: Vec<PathBuf> = args
        .iter()
        .filter_map(|a| menu::clean_path_input(a))
        .map(PathBuf::from)
        .collect();
    if paths.is_empty() {
        Mode::Live
    } else {
        Mode::Evtx(paths)
    }
}

fn main() -> anyhow::Result<()> {
    let env = match detect_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("\n❌ 初始化失敗：{e}\n");
            menu::wait_enter("按 Enter 離開...");
            return Ok(());
        }
    };

    let host = hostname();
    let ver = rules_ver(env.rules_dir.as_deref());
    print_banner(&host, &ver, env.rules_dir.is_some());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match mode_from_args(&args) {
        Mode::Live => run_live(&env),
        Mode::Evtx(paths) => run_dropped_evtx(&env, &paths),
    };
    if let Err(e) = result {
        eprintln!("\n掃描發生錯誤：{e}");
    }
    menu::wait_enter("\n按 Enter 關閉視窗...");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_means_live_scan() {
        assert_eq!(mode_from_args(&[]), Mode::Live);
        assert_eq!(mode_from_args(&["  ".to_string()]), Mode::Live);
    }

    #[test]
    fn dropped_paths_mean_evtx_analysis() {
        let m = mode_from_args(&[
            r#""C:\logs\Security.evtx""#.to_string(),
            r"C:\more".to_string(),
        ]);
        assert_eq!(
            m,
            Mode::Evtx(vec![
                PathBuf::from(r"C:\logs\Security.evtx"),
                PathBuf::from(r"C:\more")
            ])
        );
    }

    #[test]
    fn volume_of_drive_unc_and_verbatim_paths() {
        assert_eq!(volume_of(r"c:\Tools\cairn\output"), Some("C:".into()));
        assert_eq!(volume_of(r"\\?\D:\cairn\output"), Some("D:".into()));
        assert_eq!(volume_of(r"\\srv\share\cairn"), Some(r"\\SRV\SHARE".into()));
        assert_eq!(
            volume_of(r"\\?\UNC\srv\share\x"),
            Some(r"\\SRV\SHARE".into())
        );
        assert_eq!(volume_of("output"), None);
    }

    #[test]
    fn system_drive_detection() {
        assert!(on_system_drive(
            Path::new(r"C:\Users\a\Desktop\cairn\output"),
            r"C:\WINDOWS"
        ));
        assert!(!on_system_drive(
            Path::new(r"E:\cairn\output"),
            r"C:\Windows"
        ));
        assert!(!on_system_drive(Path::new("relative"), r"C:\Windows"));
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
