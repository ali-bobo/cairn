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

    let output_base = launcher_dir.join("output");
    std::fs::create_dir_all(&output_base)?;

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

fn main() -> anyhow::Result<()> {
    let env = match detect_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("\n❌ 初始化失敗：{e}\n");
            menu::wait_enter("按 Enter 離開...");
            return Ok(());
        }
    };

    if env.rules_dir.is_none() {
        eprintln!("⚠️  找不到規則目錄 rules\\sigma\\，Sigma 偵測將無法執行（僅啟發式偵測）\n");
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
            _ => {}
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
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }
}
