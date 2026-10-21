//! Built-in detections over native Windows event logs: the few event IDs that every
//! Windows host writes by default (no Sysmon, no extra audit policy) and that are
//! strong evidence on their own. Unlike Sigma rules they do not depend on the bundled
//! rule set being present, and each one maps to an Atomic Red Team test.
//!
//! | Event | Channel | Meaning | ATT&CK |
//! |---|---|---|---|
//! | 1102 | Security | audit log cleared | T1070.001 |
//! | 104 | System | event log cleared | T1070.001 |
//! | 7045 | System | service installed | T1543.003 |
//! | 4698 | Security | scheduled task created (needs "Other Object Access" audit) | T1053.005 |
//! | 5001 | Defender | real-time protection turned off | T1562.001 |
//! | 5007 | Defender | configuration changed (exclusion added) | T1562.001 |
//! | 1116 | Defender | malware detected | — |
//!
//! Pure logic over EventRecords; touches no host state.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use serde_json::{Map, Value};

use crate::trust::{
    is_system_or_program_files, is_user_writable_path, launchers_in, script_marker_labels,
    MICROSOFT_PROGRAMDATA,
};

/// Defender's operational channel.
pub const DEFENDER_CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";

/// Channels this analyzer reads. The live EVTX collector reads these even when no
/// Sigma rules are loaded.
pub const CHANNELS: &[&str] = &["Security", "System", DEFENDER_CHANNEL];

/// A string field from an event's flattened data. UserData payloads (1102 / 104) are
/// nested one level (`LogFileCleared.SubjectUserName`), so that level is searched too.
fn field(data: &Map<String, Value>, key: &str) -> Option<String> {
    if let Some(v) = data.get(key) {
        return value_str(v);
    }
    data.values()
        .filter_map(Value::as_object)
        .find_map(|o| o.get(key).and_then(value_str))
}

fn value_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn field_or_dash(ev: &EventRecord, key: &str) -> String {
    field(&ev.data, key).unwrap_or_else(|| "-".to_string())
}

/// Why a service ImagePath / task command looks like a payload, if it does.
fn command_red_flags(cmd: &str) -> Vec<String> {
    let lower = cmd.to_ascii_lowercase();
    let mut flags: Vec<String> = Vec::new();
    if is_user_writable_path(&lower) {
        flags.push("runs from a user-writable folder".to_string());
    }
    // Interpreters and proxy binaries a legitimate service or task rarely launches
    // directly; attackers use them to run a payload without dropping an exe.
    if let Some(l) = launchers_in(cmd).first() {
        flags.push(format!("launches {l}"));
    }
    let markers = script_marker_labels(cmd);
    if !markers.is_empty() {
        flags.push(format!("contains {}", markers.join(", ")));
    }
    flags
}

/// Normalize a service ImagePath / task command to an absolute path for the trust
/// check: quotes stripped, `\??\` dropped, and the `\SystemRoot\`, `%SystemRoot%`,
/// `%windir%` and bare `System32\` forms that drivers and services use mapped to
/// `C:\Windows`. Only the trust tier reads this; output shows the original string.
fn normalize_image(cmd: &str) -> String {
    let lower = cmd.trim().trim_start_matches('"').to_ascii_lowercase();
    let lower = lower.strip_prefix(r"\??\").unwrap_or(&lower).to_string();
    for prefix in [r"\systemroot\", r"%systemroot%\", r"%windir%\"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return format!(r"c:\windows\{rest}");
        }
    }
    if lower.starts_with(r"system32\") {
        return format!(r"c:\windows\{lower}");
    }
    lower
}

/// The `<Command>` and `<Arguments>` of a task definition XML, joined.
fn task_command(xml: &str) -> String {
    let tag = |name: &str| -> Option<String> {
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        Some(xml[start..end].trim().to_string())
    };
    match (tag("Command"), tag("Arguments")) {
        (Some(c), Some(a)) if !a.is_empty() => format!("{c} {a}"),
        (Some(c), _) => c,
        (None, _) => String::new(),
    }
}

fn finding(
    ev: &EventRecord,
    severity: Severity,
    title: String,
    mitre: &[&str],
    details: String,
    reason: String,
    client: String,
) -> Finding {
    let mut f = Finding::new(severity, title, FindingSource::Heuristic);
    f.ts = ev.ts;
    f.artifact = format!("evtx:{}", ev.channel);
    f.event_id = Some(ev.event_id);
    f.mitre = mitre.iter().map(|m| m.to_string()).collect();
    f.details = details;
    f.reason = Some(reason);
    f.details_client = Some(client);
    f.evidence_ref = Some(format!("{}#{}", ev.channel, ev.record_id));
    f
}

fn log_cleared(ev: &EventRecord) -> Finding {
    let who = field_or_dash(ev, "SubjectUserName");
    let log = if ev.event_id == 1102 {
        "Security".to_string()
    } else {
        field(&ev.data, "Channel")
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| "System".to_string())
    };
    finding(
        ev,
        Severity::High,
        format!("事件記錄被清除：{log}"),
        &["T1070.001"],
        format!(
            "EID {} ({}): {log} log cleared by {who}",
            ev.event_id, ev.channel
        ),
        "clearing an event log destroys evidence; admins rarely do it on a working host"
            .to_string(),
        format!(
            "{who} 在 {} 清除了 {log} 事件記錄。清除記錄會讓之前發生的事無法追查，\
             除非是已知的維護作業，否則應視為攻擊者在湮滅證據。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    )
}

fn service_installed(ev: &EventRecord) -> Finding {
    let name = field_or_dash(ev, "ServiceName");
    let image = field_or_dash(ev, "ImagePath");
    let account = field_or_dash(ev, "AccountName");
    let flags = command_red_flags(&image);
    let (severity, reason) = if !flags.is_empty() {
        (Severity::High, flags.join("; "))
    } else if is_system_or_program_files(&normalize_image(&image))
        || image.to_ascii_lowercase().contains(MICROSOFT_PROGRAMDATA)
    {
        (
            Severity::Low,
            "installed from the Windows or Program Files tree".to_string(),
        )
    } else {
        (
            Severity::Medium,
            "binary is outside the Windows and Program Files trees".to_string(),
        )
    };
    finding(
        ev,
        severity,
        format!("新安裝服務：{name}"),
        &["T1543.003"],
        format!("EID 7045: service {name} installed, ImagePath={image}, account={account}"),
        reason,
        format!(
            "{} 有新的服務「{name}」被安裝，執行的程式是 {image}。服務會在開機時自動執行，\
             是常見的後門手法；請確認這是不是已知的軟體安裝。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    )
}

fn task_created(ev: &EventRecord) -> Finding {
    let name = field_or_dash(ev, "TaskName");
    let who = field_or_dash(ev, "SubjectUserName");
    let cmd = task_command(&field(&ev.data, "TaskContent").unwrap_or_default());
    let shown = if cmd.is_empty() {
        "-".to_string()
    } else {
        cmd.clone()
    };
    let flags = command_red_flags(&cmd);
    let (severity, reason) = if !flags.is_empty() {
        (Severity::High, flags.join("; "))
    } else if cmd.is_empty() || is_system_or_program_files(&normalize_image(&cmd)) {
        (
            Severity::Low,
            "action runs from the Windows or Program Files tree (or is not a command)".to_string(),
        )
    } else {
        (
            Severity::Medium,
            "action runs outside the Windows and Program Files trees".to_string(),
        )
    };
    finding(
        ev,
        severity,
        format!("新建排程工作：{name}"),
        &["T1053.005"],
        format!("EID 4698: task {name} created by {who}, action={shown}"),
        reason,
        format!(
            "{who} 在 {} 建立了排程工作「{name}」，會執行 {shown}。排程工作可以讓程式定期\
             或在開機時自動執行，請確認是不是已知的軟體或管理作業。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    )
}

fn defender_rtp_off(ev: &EventRecord) -> Finding {
    finding(
        ev,
        Severity::High,
        "Defender 即時保護被關閉".to_string(),
        &["T1562.001"],
        "Defender EID 5001: real-time protection disabled".to_string(),
        "attackers turn real-time protection off before dropping tools".to_string(),
        format!(
            "{} Microsoft Defender 的即時保護被關閉。關閉防毒是攻擊者植入工具前常見的步驟；\
             如果不是管理員刻意關的，請立即重新開啟並調查。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    )
}

fn defender_exclusion(ev: &EventRecord) -> Option<Finding> {
    let new = field(&ev.data, "New Value").unwrap_or_default();
    if !new.to_ascii_lowercase().contains("\\exclusions\\") {
        return None;
    }
    Some(finding(
        ev,
        Severity::High,
        "Defender 新增排除項目".to_string(),
        &["T1562.001"],
        format!("Defender EID 5007: exclusion added: {new}"),
        "an exclusion makes Defender skip a path, extension or process".to_string(),
        format!(
            "{} Microsoft Defender 新增了排除項目（{new}）。被排除的位置不會被掃描，\
             攻擊者常用這招藏放工具；請確認是不是管理員刻意設定的。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    ))
}

/// One finding per (threat, path): Defender logs a 1116 for every re-detection.
fn defender_detections(events: &[&EventRecord]) -> Vec<Finding> {
    let mut by_threat: BTreeMap<(String, String), Vec<&EventRecord>> = BTreeMap::new();
    for ev in events {
        let threat = field_or_dash(ev, "Threat Name");
        let path = field_or_dash(ev, "Path");
        by_threat.entry((threat, path)).or_default().push(ev);
    }
    by_threat
        .into_iter()
        .map(|((threat, path), evs)| {
            let first = evs[0];
            let last = evs[evs.len() - 1];
            let mut f = finding(
                last,
                Severity::High,
                format!("Defender 偵測到惡意程式：{threat}"),
                &[],
                format!(
                    "Defender EID 1116 x{}: {threat} at {path} (severity {})",
                    evs.len(),
                    field_or_dash(last, "Severity Name")
                ),
                "Microsoft Defender identified this file as malware".to_string(),
                format!(
                    "Microsoft Defender 在這台主機偵測到惡意程式 {threat}（位置：{path}），\
                     共 {} 次，最早在 {}。偵測到不代表已清除，請確認 Defender 的處理結果，\
                     並找出它是怎麼進來的。",
                    evs.len(),
                    first.ts.format("%Y-%m-%d %H:%M UTC")
                ),
            );
            f.evidence = evs
                .iter()
                .map(|e| EvidenceItem {
                    artifact: format!("evtx:{}", e.channel),
                    path: Some(path.clone()),
                    ts: Some(e.ts),
                    detail: format!("EID 1116 record {}", e.record_id),
                })
                .collect();
            f
        })
        .collect()
}

/// Native event-log detections (see module docs).
pub struct EventLogHeuristic;

impl EventLogHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::EVENTLOG;
}

impl Analyzer for EventLogHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let mut detections = Vec::new();
        for r in records {
            let Record::Event(ev) = r else { continue };
            match (ev.channel.as_str(), ev.event_id) {
                ("Security", 1102) | ("System", 104) => out.push(log_cleared(ev)),
                ("System", 7045) => out.push(service_installed(ev)),
                ("Security", 4698) => out.push(task_created(ev)),
                (DEFENDER_CHANNEL, 5001) => out.push(defender_rtp_off(ev)),
                (DEFENDER_CHANNEL, 5007) => out.extend(defender_exclusion(ev)),
                (DEFENDER_CHANNEL, 1116) => detections.push(ev),
                _ => {}
            }
        }
        out.extend(defender_detections(&detections));
        Ok(crate::stamped(out, Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use serde_json::json;

    fn ev(channel: &str, eid: u32, data: Value) -> Record {
        let ts: DateTime<Utc> = "2026-10-20T08:00:00Z".parse().unwrap();
        Record::Event(EventRecord {
            ts,
            channel: channel.into(),
            event_id: eid,
            provider: "p".into(),
            computer: "WS01".into(),
            record_id: 7,
            data: data.as_object().unwrap().clone(),
        })
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        EventLogHeuristic.analyze(records, &[]).unwrap()
    }

    #[test]
    fn security_log_cleared_reads_nested_user_data() {
        let f = run(&[ev(
            "Security",
            1102,
            json!({"LogFileCleared": {"SubjectUserName": "mallory"}}),
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1070.001"]);
        assert!(f[0].details.contains("mallory"), "{}", f[0].details);
        assert!(f[0].reason.is_some() && f[0].details_client.is_some());
    }

    #[test]
    fn system_log_cleared_names_the_cleared_channel() {
        let f = run(&[ev(
            "System",
            104,
            json!({"Channel": "System", "LogFileCleared": {"SubjectUserName": "bob", "Channel": "Windows PowerShell"}}),
        )]);
        // Top-level Channel (from System) wins; still a High T1070.001.
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn service_from_temp_running_powershell_is_high() {
        let f = run(&[ev(
            "System",
            7045,
            json!({"ServiceName": "upd", "ImagePath": "cmd.exe /c powershell -enc SQBFAFgA", "AccountName": "LocalSystem"}),
        )]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].reason.as_deref().unwrap().contains("cmd"));
    }

    #[test]
    fn service_from_program_files_is_low() {
        let f = run(&[ev(
            "System",
            7045,
            json!({"ServiceName": "Vendor", "ImagePath": "\"C:\\Program Files\\Vendor\\svc.exe\""}),
        )]);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn driver_image_paths_resolve_to_the_windows_tree() {
        for image in [
            r"\SystemRoot\System32\drivers\x.sys",
            r"System32\drivers\x.sys",
            r"%SystemRoot%\system32\svchost.exe -k netsvcs",
            r"\??\C:\Windows\system32\drivers\y.sys",
        ] {
            let f = run(&[ev(
                "System",
                7045,
                json!({"ServiceName": "d", "ImagePath": image}),
            )]);
            assert_eq!(f[0].severity, Severity::Low, "{image}");
        }
    }

    #[test]
    fn defender_platform_update_service_is_low() {
        let image =
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25010.11-0\MsMpEng.exe";
        let f = run(&[ev(
            "System",
            7045,
            json!({"ServiceName": "WinDefend", "ImagePath": image}),
        )]);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn service_elsewhere_is_medium() {
        let f = run(&[ev(
            "System",
            7045,
            json!({"ServiceName": "x", "ImagePath": "D:\\tools\\x.exe"}),
        )]);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn task_action_is_parsed_from_xml() {
        let xml = "<Task><Actions><Exec><Command>C:\\Users\\a\\AppData\\Roaming\\u.exe</Command>\
                   <Arguments>-q</Arguments></Exec></Actions></Task>";
        let f = run(&[ev(
            "Security",
            4698,
            json!({"TaskName": "\\Updater", "TaskContent": xml, "SubjectUserName": "a"}),
        )]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].details.contains("u.exe -q"), "{}", f[0].details);
        assert_eq!(f[0].mitre, vec!["T1053.005"]);
    }

    #[test]
    fn defender_rtp_off_and_exclusion() {
        let f = run(&[
            ev(DEFENDER_CHANNEL, 5001, json!({})),
            ev(
                DEFENDER_CHANNEL,
                5007,
                json!({"New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\x = 0x0"}),
            ),
            ev(
                DEFENDER_CHANNEL,
                5007,
                json!({"New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\x"}),
            ),
        ]);
        assert_eq!(f.len(), 2, "non-exclusion 5007 is ignored");
        assert!(f.iter().all(|x| x.mitre == vec!["T1562.001"]));
    }

    #[test]
    fn defender_detections_group_by_threat_and_path() {
        let d = json!({"Threat Name": "Trojan:Win32/X", "Path": "file:_C:\\a.exe", "Severity Name": "Severe"});
        let f = run(&[
            ev(DEFENDER_CHANNEL, 1116, d.clone()),
            ev(DEFENDER_CHANNEL, 1116, d),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence.len(), 2);
        assert!(f[0].details.contains("x2"));
    }

    #[test]
    fn unrelated_events_are_ignored() {
        assert!(run(&[ev("Security", 4624, json!({}))]).is_empty());
    }
}
