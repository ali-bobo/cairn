//! 終端輸出與使用者輸入（摘要框、按 Enter、路徑清理）。純 I/O，無業務邏輯。
use std::io::{self, BufRead, Write};

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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

/// 規則版本的短格式（pin 前 7 碼 + 聚合雜湊前 8 碼）。
pub fn truncate_rules_ver(ver: &str) -> String {
    if let Some((pin, agg)) = ver.split_once('+') {
        let short_pin = &pin[..pin.len().min(7)];
        let short_agg = &agg[..agg.len().min(8)];
        format!("{short_pin}+{short_agg}")
    } else {
        truncate(ver, 20)
    }
}

#[cfg(test)]
mod path_input_tests {
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
        assert_eq!(clean_path_input("C:\\logs"), Some("C:\\logs".to_string()));
    }

    #[test]
    fn empty_input_is_none() {
        assert_eq!(clean_path_input(""), None);
        assert_eq!(clean_path_input("   "), None);
        assert_eq!(clean_path_input("\"\""), None);
    }
}
