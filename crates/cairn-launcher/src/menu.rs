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

#[cfg(test)]
mod engineer_menu_tests {
    use super::clean_path_input;
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
}
