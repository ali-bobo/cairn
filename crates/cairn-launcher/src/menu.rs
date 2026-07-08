//! 選單渲染與使用者輸入。純 I/O，無業務邏輯。
use std::io::{self, BufRead, Write};

/// 清除終端畫面（ANSI escape sequence，支援 Windows Terminal / PowerShell）
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
    line.trim()
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('\0')
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
    println!("║  主機名稱：{:<30}║", truncate(hostname, 28));
    println!("║  {:<40}║", truncate(&rules_info, 38));
    println!("╠══════════════════════════════════════════╣");
    println!("║  [1] 快速掃描（最近 24 小時）            ║");
    println!("║  [2] 自訂時間範圍                        ║");
    println!("║  [3] 工程師模式                          ║");
    println!("║  [Q] 離開                               ║");
    println!("╚══════════════════════════════════════════╝");
    print!("請選擇：");
    let _ = io::stdout().flush();
}

/// 印時間範圍選單，回傳使用者選擇的 (小時數, 描述字串)。
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
        _ => (24, "最近 24 小時"),
    }
}

/// 印掃描摘要框
pub fn print_summary(s: &crate::summary::ScanSummary) {
    use crate::summary::Verdict;
    println!("\n╔══════════════════════════════════════════╗");
    println!("║  掃描完成                                ║");
    println!("║  主機名稱：{:<30}║", truncate(&s.hostname, 28));
    println!("║  時間範圍：{:<30}║", s.time_window_desc);
    println!("║  掃描時間：{:<30}║", s.started_utc);
    println!(
        "║  管理員權限：{:<28}║",
        if s.admin {
            "是"
        } else {
            "否（部分功能受限）"
        }
    );
    if !s.sigma_ruleset_ver.is_empty() {
        println!("║  規則版本：{:<30}║", truncate(&s.sigma_ruleset_ver, 28));
    }
    println!("╠══════════════════════════════════════════╣");
    match s.verdict {
        Verdict::Clean => {
            println!("║                                          ║");
            println!("║  ✓ 未發現高風險威脅                       ║");
            println!("║                                          ║");
        }
        Verdict::Alert => {
            println!("║                                          ║");
            println!("║  ! 發現高風險事件，請立即聯絡資安工程師  ║");
            println!("║                                          ║");
            for (sev, title) in &s.top_findings {
                let line = format!("  [{sev}] {title}");
                println!("║  {:<40}║", truncate(&line, 40));
            }
            let total_high = s.counts.get("critical").copied().unwrap_or(0)
                + s.counts.get("high").copied().unwrap_or(0);
            if total_high > s.top_findings.len() as u64 {
                let extra = total_high - s.top_findings.len() as u64;
                println!("║  （還有 {} 筆，請查看完整報告）         ║", extra);
            }
            println!("║                                          ║");
        }
    }
    let medium = s.counts.get("medium").copied().unwrap_or(0);
    let low = s.counts.get("low").copied().unwrap_or(0);
    if medium > 0 || low > 0 {
        if matches!(s.verdict, Verdict::Clean) {
            println!("║  Medium: {:>3}（建議稍後請工程師確認）    ║", medium);
            println!("║  Low:    {:>3}（一般性記錄）              ║", low);
        } else {
            println!("║  Medium: {:>3}  Low: {:>3}               ║", medium, low);
        }
    }
    println!("╚══════════════════════════════════════════╝");
}

/// 等待使用者按 Enter，顯示提示訊息
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
    if let Some((pin, agg)) = ver.split_once('+') {
        let short_pin = &pin[..pin.len().min(7)];
        let short_agg = &agg[..agg.len().min(8)];
        format!("{short_pin}+{short_agg}")
    } else {
        truncate(ver, 20)
    }
}
