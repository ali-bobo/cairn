//! FR18: plain zh-TW client-facing text for Findings >= Medium severity.
//!
//! `fill_details_client` fills `Finding.details_client` with a one-sentence
//! summary addressed to a non-technical audience. It is idempotent when the
//! severity is below Medium (Low / Info) — it simply returns without touching
//! the field.
//!
//! R3: `entity_name()` reads registry data/value/key so persistence findings
//!     never say "未知程式" when registry context is available.
//! R4: mechanism-aware zh-TW templates for persistence findings (service,
//!     run_key, startup, scheduled_task, winlogon, ifeo).
//! R5: netconn client text includes the owning process name when available.
#![forbid(unsafe_code)]

use chrono::{DateTime, Duration, Utc};

use cairn_core::finding::{Finding, FindingSource, Severity};

fn is_medium_or_above(s: Severity) -> bool {
    matches!(s, Severity::Critical | Severity::High | Severity::Medium)
}

/// Return the last path segment, stripping surrounding double-quotes first.
fn short_name(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

/// Best human-readable name for the implicated entity.
///
/// Priority: process image > file path >
///   registry data (if it looks like a path) > registry value name >
///   registry key last segment > "未知程式".
fn entity_name(f: &Finding) -> String {
    if let Some(p) = &f.entity.process {
        return short_name(&p.image);
    }
    if let Some(fi) = &f.entity.file {
        return short_name(&fi.path);
    }
    if let Some(reg) = &f.entity.registry {
        let data = reg.data.trim_matches('"');
        if data.contains('\\') || data.starts_with('%') {
            return short_name(data);
        }
        if !reg.value.is_empty() {
            return reg.value.clone();
        }
        if let Some(seg) = reg.key.rsplit('\\').next() {
            if !seg.is_empty() {
                return seg.to_owned();
            }
        }
    }
    "未知程式".to_owned()
}

/// Human-readable relative-time hint derived from a registry last-write time.
fn timing_hint(last_write: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match last_write {
        Some(lw) => {
            let age = now.signed_duration_since(lw);
            if age >= Duration::zero() && age <= Duration::days(30) {
                format!("{}天前新增", age.num_days())
            } else {
                "時間較久遠".to_owned()
            }
        }
        None => "時間不明".to_owned(),
    }
}

/// Mechanism-specific zh-TW sentence for persistence findings.
///
/// The mechanism is the suffix of `f.title` after `"Suspicious persistence: "`.
fn persistence_client_text(host: &str, f: &Finding) -> String {
    let now = Utc::now();
    let reg = f.entity.registry.as_ref();
    let bin = reg
        .map(|r| short_name(r.data.trim_matches('"')))
        .unwrap_or_else(|| entity_name(f));
    let svc_name = reg
        .and_then(|r| r.key.rsplit('\\').next().map(str::to_owned))
        .unwrap_or_else(|| entity_name(f));
    let timing = timing_hint(reg.and_then(|r| r.last_write), now);
    let value_name = reg.map(|r| r.value.as_str()).unwrap_or("?");

    let mechanism = f
        .title
        .strip_prefix("Suspicious persistence: ")
        .unwrap_or("unknown");

    match mechanism {
        "service" => format!(
            "主機 {} 上偵測到服務 {} 指向 {}（{}），建議確認是否為已知且授權的軟體。",
            host, svc_name, bin, timing
        ),
        "run_key" | "startup" => format!(
            "主機 {} 上，{} 在自動啟動項目中新增了 {}（{}），建議確認是否為已知且授權的操作。",
            host, svc_name, bin, timing
        ),
        "scheduled_task" => format!(
            "主機 {} 上偵測到排程工作 {} 指向 {}（{}），建議確認是否為已知且授權的操作。",
            host, svc_name, bin, timing
        ),
        "winlogon" => format!(
            "主機 {} 上，Winlogon {} 設定為 {}（{}），若非預期值請立即調查。",
            host, value_name, bin, timing
        ),
        "ifeo" => format!(
            "主機 {} 上，{} 的 IFEO Debugger 被設定為 {}，此手法幾乎僅用於攻擊，建議立即調查。",
            host, svc_name, bin
        ),
        _ => format!(
            "主機 {} 上，{} 疑似建立了持久化機制（{}），建議確認該項目是否為已知且授權的軟體。",
            host,
            entity_name(f),
            timing
        ),
    }
}

/// zh-TW sentence for network-connection findings, naming the owning process.
fn netconn_client_text(host: &str, f: &Finding) -> String {
    let proc_name = f
        .entity
        .process
        .as_ref()
        .map(|p| short_name(&p.image))
        .unwrap_or_else(|| "未知程式".to_owned());
    let remote = f
        .entity
        .netconn
        .as_ref()
        .map(|c| {
            format!(
                "{}:{}",
                c.raddr.as_deref().unwrap_or("-"),
                c.rport
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into())
            )
        })
        .unwrap_or_else(|| "未知目標".to_owned());
    format!(
        "主機 {} 上，{} 發起了對外連線至 {}，建議確認連線目標是否屬於正常業務範疇。",
        host, proc_name, remote
    )
}

pub fn fill_details_client(f: &mut Finding) {
    if !is_medium_or_above(f.severity) {
        return;
    }
    let host = f.host.clone();
    let text = match f.source {
        FindingSource::Heuristic => match f.artifact.as_str() {
            "process" => {
                let name = entity_name(f);
                format!(
                    "主機 {} 上，{} 以非預期的父行程方式執行，\
                     可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。",
                    host, name
                )
            }
            "persistence" => persistence_client_text(&host, f),
            "netconn" => netconn_client_text(&host, f),
            "file_meta" => {
                let name = entity_name(f);
                format!(
                    "主機 {} 上，{} 的時間戳記疑似遭到竄改，\
                     建議進一步確認該檔案的真實建立時間。",
                    host, name
                )
            }
            _ => format!("主機 {} 上偵測到疑似異常行為，建議分析師確認詳情。", host),
        },
        FindingSource::Sigma => {
            let title = f.title.clone();
            match f.severity {
                Severity::Critical | Severity::High => format!(
                    "主機 {} 上偵測到與「{}」相關的可疑活動，\
                     此類活動具有較高風險，建議盡速進行調查。",
                    host, title
                ),
                _ => format!(
                    "主機 {} 上偵測到與「{}」相關的活動，\
                     建議分析師評估是否為授權操作。",
                    host, title
                ),
            }
        }
    };
    f.details_client = Some(text);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::{
        EntityNetConn, EntityProcess, EntityRegistry, Finding, FindingSource, Severity,
    };

    fn make_heuristic(severity: Severity, artifact: &str) -> Finding {
        let mut f = Finding::new(severity, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.artifact = artifact.into();
        f.entity.process = Some(EntityProcess {
            pid: 1,
            ppid: 0,
            image: r"C:\Windows\cmd.exe".into(),
            cmdline: String::new(),
            signed: None,
            integrity: None,
        });
        f
    }

    fn make_sigma(severity: Severity, title: &str) -> Finding {
        let mut f = Finding::new(severity, title, FindingSource::Sigma);
        f.host = "WS01".into();
        f
    }

    #[test]
    fn parent_child_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "process");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("非預期的父行程"), "got: {text}");
        assert!(text.contains("WS01"), "host missing: {text}");
        assert!(text.contains("cmd.exe"), "path missing: {text}");
    }

    #[test]
    fn persist_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, "persistence");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("持久化機制"), "got: {text}");
    }

    #[test]
    fn netconn_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "netconn");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("對外連線"), "got: {text}");
    }

    #[test]
    fn timestomp_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "file_meta");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("時間戳記疑似遭到竄改"), "got: {text}");
    }

    #[test]
    fn other_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, "unknown_artifact");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("疑似異常行為"), "got: {text}");
    }

    #[test]
    fn sigma_high_filled() {
        let mut f = make_sigma(Severity::High, "Mimikatz Credential Dumping");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("較高風險"), "got: {text}");
        assert!(
            text.contains("Mimikatz Credential Dumping"),
            "title missing: {text}"
        );
    }

    #[test]
    fn sigma_medium_filled() {
        let mut f = make_sigma(Severity::Medium, "Suspicious PowerShell");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("評估是否為授權操作"), "got: {text}");
    }

    #[test]
    fn low_severity_not_filled() {
        let mut f = make_sigma(Severity::Low, "Low Noise Rule");
        fill_details_client(&mut f);
        assert!(f.details_client.is_none(), "Low must remain None");

        let mut f2 = make_heuristic(Severity::Info, "process");
        fill_details_client(&mut f2);
        assert!(f2.details_client.is_none(), "Info must remain None");
    }

    #[test]
    fn entity_path_falls_back_to_unknown_when_no_entity() {
        let mut f = make_heuristic(Severity::High, "process");
        f.entity.process = None;
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(text.contains("未知程式"), "fallback path missing: {text}");
    }

    // ── R3: registry entity → entity_name uses registry data/value/key ──────

    #[test]
    fn service_client_text_not_unknown() {
        let mut f = Finding::new(
            Severity::Medium,
            "Suspicious persistence: service",
            FindingSource::Heuristic,
        );
        f.host = "WS01".into();
        f.artifact = "persistence".into();
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService".into(),
            value: "CoworkVMService".into(),
            data: r#""C:\Program Files\WindowsApps\Claude\cowork-svc.exe""#.into(),
            last_write: None,
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(!text.contains("未知程式"), "must not say 未知程式: {text}");
        assert!(
            text.contains("cowork-svc.exe") || text.contains("CoworkVMService"),
            "must mention name or binary: {text}"
        );
    }

    // ── R4: service with recent last_write includes binary name and host ─────

    #[test]
    fn service_client_text_includes_binary_and_host() {
        let now = Utc::now();
        let recent = now - Duration::days(2);
        let mut f = Finding::new(
            Severity::Medium,
            "Suspicious persistence: service",
            FindingSource::Heuristic,
        );
        f.host = "WS01".into();
        f.artifact = "persistence".into();
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc".into(),
            value: "EvilSvc".into(),
            data: r"C:\Users\x\AppData\Local\Temp\evil.exe".into(),
            last_write: Some(recent),
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(text.contains("evil.exe"), "must name binary: {text}");
        assert!(text.contains("WS01"), "must name host: {text}");
    }

    // ── R4: IFEO text warns about attack technique ───────────────────────────

    #[test]
    fn ifeo_client_text_mentions_attack() {
        let mut f = Finding::new(
            Severity::High,
            "Suspicious persistence: ifeo",
            FindingSource::Heuristic,
        );
        f.host = "WS01".into();
        f.artifact = "persistence".into();
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe".into(),
            value: "Debugger".into(),
            data: r"C:\Temp\cmd.exe".into(),
            last_write: None,
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(
            text.contains("幾乎僅用於攻擊") || text.contains("調查"),
            "IFEO text must mention attack context: {text}"
        );
    }

    // ── R4: winlogon text mentions the value name ────────────────────────────

    #[test]
    fn winlogon_client_text_mentions_value() {
        let mut f = Finding::new(
            Severity::Medium,
            "Suspicious persistence: winlogon",
            FindingSource::Heuristic,
        );
        f.host = "WS01".into();
        f.artifact = "persistence".into();
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".into(),
            value: "Shell".into(),
            data: "explorer.exe".into(),
            last_write: None,
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(
            text.contains("Shell") || text.contains("Winlogon"),
            "winlogon text must mention value: {text}"
        );
    }

    // ── R5: netconn with owning process names the process ────────────────────

    #[test]
    fn netconn_client_text_includes_process_name() {
        let mut f = Finding::new(Severity::High, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.artifact = "netconn".into();
        f.entity.netconn = Some(EntityNetConn {
            laddr: "192.168.0.1".into(),
            lport: 50000,
            raddr: Some("185.0.0.1".into()),
            rport: Some(4444),
            pid: Some(1234),
        });
        f.entity.process = Some(EntityProcess {
            pid: 1234,
            ppid: 4,
            image: r"C:\Users\x\AppData\Local\Temp\beacon.exe".into(),
            cmdline: String::new(),
            signed: None,
            integrity: None,
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(text.contains("beacon.exe"), "must name process: {text}");
        assert!(text.contains("WS01"), "must name host: {text}");
    }

    // ── R5: netconn without owning process still produces text ───────────────

    #[test]
    fn netconn_client_text_without_process_graceful() {
        let mut f = Finding::new(Severity::High, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.artifact = "netconn".into();
        f.entity.netconn = Some(EntityNetConn {
            laddr: "0.0.0.0".into(),
            lport: 50000,
            raddr: Some("185.0.0.1".into()),
            rport: Some(4444),
            pid: Some(9999),
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(!text.is_empty(), "must still produce text: {text}");
        assert!(text.contains("WS01"));
    }
}
