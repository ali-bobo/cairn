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
//! | 1116 | Defender | malware detected (PUA/adware Low–Medium, else High) | — |
//! | 1117 / 1118 / 1119 | Defender | action taken / action failed (High) | — |
//!
//! Pure logic over EventRecords; touches no host state.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use serde_json::{Map, Value};

use crate::defense::{exclusion_value_note, exclusion_value_risk};
use crate::trust::{
    invocation_args, is_system_or_program_files, is_user_writable_path, launchers_in, risky_args,
    script_markers, MarkerKind, MICROSOFT_PROGRAMDATA,
};
use cairn_core::record::ExclusionKind;

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

/// What makes a service ImagePath / task command look like a payload.
#[derive(Debug, Default)]
struct RedFlags {
    /// The binary itself sits in a user-writable folder.
    writable_binary: bool,
    /// Everything else: a launcher, script markers.
    other: Vec<String>,
}

impl RedFlags {
    fn is_empty(&self) -> bool {
        !self.writable_binary && self.other.is_empty()
    }

    fn reason(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.writable_binary {
            parts.push("runs from a user-writable folder".to_string());
        }
        parts.extend(self.other.iter().cloned());
        parts.join("; ")
    }
}

/// Why a service ImagePath / task command looks like a payload, if it does. The
/// drop-zone check reads only the binary being run: a vendor service passing its own
/// `C:\ProgramData\Vendor\config.xml` as an argument is not "running from" there. A URL
/// counts only next to an interpreter / LOLBin (an agent's `--server https://...` is
/// configuration, not a download).
fn command_red_flags(cmd: &str) -> RedFlags {
    let mut flags = RedFlags {
        writable_binary: is_user_writable_path(invoked_path(cmd)),
        ..RedFlags::default()
    };
    // Interpreters and proxy binaries a legitimate service or task rarely launches
    // directly; attackers use them to run a payload without dropping an exe.
    let launcher = launchers_in(cmd).into_iter().next();
    if let Some(l) = &launcher {
        let risks: Vec<String> = risky_args(invocation_args(cmd))
            .iter()
            .map(ToString::to_string)
            .collect();
        if risks.is_empty() {
            flags.other.push(format!("launches {l}"));
        } else {
            flags
                .other
                .push(format!("launches {l} with {}", risks.join(", ")));
        }
    }
    let markers: Vec<&str> = script_markers(cmd)
        .into_iter()
        .filter(|m| launcher.is_some() || m.kind != MarkerKind::Remote)
        .map(|m| m.label)
        .collect();
    if !markers.is_empty() {
        flags.other.push(format!("contains {}", markers.join(", ")));
    }
    flags
}

/// The binary a command line runs: the quoted first token, or for an unquoted command
/// the text up to the first executable extension followed by a space (so
/// `C:\Users\Public\My Tools\x.exe -a` keeps its spaces), else the first token.
fn invoked_path(cmd: &str) -> &str {
    let t = cmd.trim();
    if let Some(rest) = t.strip_prefix('"') {
        return rest.split('"').next().unwrap_or(rest);
    }
    let lower = t.to_ascii_lowercase();
    let earliest = [".exe", ".sys", ".dll", ".com", ".bat", ".cmd", ".scr"]
        .iter()
        .filter_map(|ext| {
            lower
                .match_indices(ext)
                .map(|(i, _)| i + ext.len())
                .find(|&end| {
                    lower
                        .get(end..)
                        .is_some_and(|r| r.is_empty() || r.starts_with(char::is_whitespace))
                })
        })
        .min();
    match earliest {
        Some(end) => &t[..end],
        None => t.split_whitespace().next().unwrap_or(""),
    }
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
        // A service runs as SYSTEM: a binary in a user-writable folder is a privilege
        // escalation path on its own, so every red flag is High here.
        (Severity::High, flags.reason())
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
    let (severity, reason) = if !flags.other.is_empty() {
        (Severity::High, flags.reason())
    } else if flags.writable_binary {
        // Per-user updaters (OneDrive, Teams, Zoom) register exactly this: a task
        // running a binary under the user's AppData. Without a launcher or payload
        // marker it is worth a look, not an alarm.
        (
            Severity::Medium,
            format!(
                "{}; per-user updaters (OneDrive, Teams, ...) also do this, so check the \
                 binary's signer",
                flags.reason()
            ),
        )
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

/// The exclusion a 5007 `New Value` adds: `...\Exclusions\Paths\C:\x = 0x0` ->
/// (Path, `C:\x`). None when the kind list is not recognised.
fn parse_exclusion_value(new: &str) -> Option<(ExclusionKind, String)> {
    let lower = new.to_ascii_lowercase();
    let at = lower.find(r"\exclusions\")? + r"\exclusions\".len();
    let rest = new.get(at..)?;
    let (list, item) = rest.split_once('\\')?;
    let kind = match list.to_ascii_lowercase().as_str() {
        "paths" => ExclusionKind::Path,
        "extensions" => ExclusionKind::Extension,
        "processes" => ExclusionKind::Process,
        "ipaddresses" => ExclusionKind::IpAddress,
        _ => return None,
    };
    let item = item.rsplit_once(" = ").map_or(item, |(v, _)| v).trim();
    (!item.is_empty()).then(|| (kind, item.to_string()))
}

fn defender_exclusion(ev: &EventRecord) -> Option<Finding> {
    let new = field(&ev.data, "New Value").unwrap_or_default();
    if !new.to_ascii_lowercase().contains("\\exclusions\\") {
        return None;
    }
    // Rated like the same exclusion found in the registry (heur_defense): High when it
    // opens a drop zone, a drive, an executable type or an interpreter; Medium for a
    // narrower one. An entry that cannot be parsed stays High (fail loud).
    let (severity, why) = match parse_exclusion_value(&new) {
        Some((kind, value)) => match exclusion_value_risk(kind, &value) {
            Some(risk) => (Severity::High, risk),
            None => (
                Severity::Medium,
                exclusion_value_note(kind, &value)
                    .unwrap_or(
                        "a narrow exclusion (no drop zone, drive, executable type or interpreter)",
                    )
                    .to_string(),
            ),
        },
        None => (
            Severity::High,
            "exclusion entry could not be parsed".to_string(),
        ),
    };
    Some(finding(
        ev,
        severity,
        "Defender 新增排除項目".to_string(),
        &["T1562.001"],
        format!("Defender EID 5007: exclusion added: {new}"),
        format!("an exclusion makes Defender skip a path, extension or process: {why}"),
        format!(
            "{} Microsoft Defender 新增了排除項目（{new}）。被排除的位置不會被掃描，\
             攻擊者常用這招藏放工具；請確認是不是管理員刻意設定的。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    ))
}

/// Defender threat-name prefixes and category names of potentially unwanted software:
/// unwanted, not malicious.
const PUA_THREAT_PREFIXES: &[&str] = &["pua:", "adware:", "softwarebundler:", "puadlmgr"];
const PUA_CATEGORIES: &[&str] = &["potentially unwanted", "adware", "software bundler"];

/// True if this detection is PUA / adware rather than malware.
fn is_pua(threat: &str, category: &str) -> bool {
    let t = threat.to_ascii_lowercase();
    let c = category.to_ascii_lowercase();
    PUA_THREAT_PREFIXES.iter().any(|p| t.starts_with(p))
        || PUA_CATEGORIES.iter().any(|p| c.contains(p))
}

/// What Defender did about one threat, from its 1117 / 1118 / 1119 events.
#[derive(Debug, Default)]
struct DefenderOutcome {
    /// 1117: actions that succeeded ("Quarantine", "Remove", ...).
    done: Vec<String>,
    /// 1118 / 1119: actions that failed, with the error text.
    failed: Vec<String>,
}

impl DefenderOutcome {
    fn add(&mut self, ev: &EventRecord) {
        let action = field_or_dash(ev, "Action Name");
        match ev.event_id {
            1117 => {
                if !self.done.contains(&action) {
                    self.done.push(action);
                }
            }
            _ => {
                let err = field(&ev.data, "Error Description")
                    .filter(|e| !e.is_empty() && e != "-")
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default();
                let critical = if ev.event_id == 1119 { "critical " } else { "" };
                self.failed.push(format!(
                    "{action} {critical}failed (EID {}){err}",
                    ev.event_id
                ));
            }
        }
    }

    /// English summary for details / reason.
    fn summary(&self) -> String {
        match (self.done.is_empty(), self.failed.is_empty()) {
            (true, true) => "no action recorded (no 1117/1118/1119)".to_string(),
            (false, true) => format!("action taken: {}", self.done.join(", ")),
            (true, false) => format!("action FAILED: {}", self.failed.join("; ")),
            (false, false) => format!(
                "action taken: {}; action FAILED: {}",
                self.done.join(", "),
                self.failed.join("; ")
            ),
        }
    }

    /// zh-TW sentence for the client.
    fn client(&self) -> String {
        if !self.failed.is_empty() {
            "Defender 嘗試處理但失敗，威脅可能仍在主機上，請立即處理。".to_string()
        } else if !self.done.is_empty() {
            format!(
                "Defender 已處理（{}），但仍請找出它是怎麼進來的。",
                self.done.join("、")
            )
        } else {
            "記錄中看不到 Defender 的處理結果，偵測到不代表已清除，請確認處理狀態。".to_string()
        }
    }
}

/// One threat group: the 1116 detections and 1117-1119 outcomes of one (threat, path).
#[derive(Default)]
struct ThreatGroup<'a> {
    detections: Vec<&'a EventRecord>,
    outcome_events: Vec<&'a EventRecord>,
    outcome: DefenderOutcome,
}

/// One finding per (threat, path): Defender logs a 1116 for every re-detection, and
/// the 1117 (action taken) / 1118-1119 (action failed) events for the same threat
/// are attached to it. Severity: failed action -> High; PUA/adware -> Low when an
/// action succeeded, else Medium; any other detection -> High.
fn defender_detections(events: &[&EventRecord]) -> Vec<Finding> {
    let mut groups: BTreeMap<(String, String), ThreatGroup> = BTreeMap::new();
    let (detections, outcomes): (Vec<&EventRecord>, Vec<&EventRecord>) =
        events.iter().partition(|e| e.event_id == 1116);
    for ev in detections {
        let key = (field_or_dash(ev, "Threat Name"), field_or_dash(ev, "Path"));
        groups.entry(key).or_default().detections.push(ev);
    }
    for ev in outcomes {
        let threat = field_or_dash(ev, "Threat Name");
        let exact = (threat.clone(), field_or_dash(ev, "Path"));
        // Same threat and path; else the same threat at any path (the action events
        // sometimes list the path differently); else a group of its own.
        let key = if groups.contains_key(&exact) {
            exact
        } else {
            groups
                .keys()
                .find(|(t, _)| *t == threat)
                .cloned()
                .unwrap_or(exact)
        };
        let g = groups.entry(key).or_default();
        g.outcome.add(ev);
        g.outcome_events.push(ev);
    }
    groups
        .into_iter()
        .map(|((threat, path), g)| {
            let all: Vec<&EventRecord> = {
                let mut v: Vec<&EventRecord> =
                    g.detections.iter().chain(&g.outcome_events).copied().collect();
                v.sort_by_key(|e| (e.ts, e.record_id));
                v
            };
            let first = all[0];
            let last = all[all.len() - 1];
            let rep = g.detections.last().copied().unwrap_or(last);
            let category = field_or_dash(rep, "Category Name");
            let pua = is_pua(&threat, &category);
            let failed = !g.outcome.failed.is_empty();
            let handled = !g.outcome.done.is_empty();
            let (severity, why) = if failed {
                (Severity::High, "Defender could not remove or quarantine it")
            } else if pua && handled {
                (Severity::Low, "potentially unwanted software (PUA/adware), and Defender acted on it")
            } else if pua {
                (Severity::Medium, "potentially unwanted software (PUA/adware), no successful action recorded")
            } else {
                (Severity::High, "Microsoft Defender identified this file as malware")
            };
            let summary = g.outcome.summary();
            let kind = if pua { "可能不需要的軟體" } else { "惡意程式" };
            let mut f = finding(
                rep,
                severity,
                format!("Defender 偵測到{kind}：{threat}"),
                &[],
                format!(
                    "Defender EID 1116 x{}: {threat} at {path} (category {category}, severity {}); {summary}",
                    g.detections.len(),
                    field_or_dash(rep, "Severity Name")
                ),
                format!("{why}; {summary}"),
                format!(
                    "Microsoft Defender 在這台主機偵測到{kind} {threat}（位置：{path}），\
                     共 {} 次，最早在 {}。{}",
                    g.detections.len(),
                    first.ts.format("%Y-%m-%d %H:%M UTC"),
                    g.outcome.client()
                ),
            );
            f.evidence = all
                .iter()
                .map(|e| EvidenceItem {
                    artifact: format!("evtx:{}", e.channel),
                    path: Some(path.clone()),
                    ts: Some(e.ts),
                    detail: format!("EID {} record {}", e.event_id, e.record_id),
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
                (DEFENDER_CHANNEL, 1116..=1119) => detections.push(ev),
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
        // A bare AppData binary is what per-user updaters register: Medium.
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].details.contains("u.exe -q"), "{}", f[0].details);
        assert_eq!(f[0].mitre, vec!["T1053.005"]);
    }

    fn task_xml(cmd: &str, args: &str) -> String {
        format!(
            "<Task><Actions><Exec><Command>{cmd}</Command><Arguments>{args}</Arguments>\
             </Exec></Actions></Task>"
        )
    }

    #[test]
    fn per_user_updater_task_is_medium_but_launcher_task_is_high() {
        let onedrive = task_xml(
            r"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
            "/reporting",
        );
        let f = run(&[ev(
            "Security",
            4698,
            json!({"TaskName": "\\OneDrive Standalone Update Task", "TaskContent": onedrive}),
        )]);
        assert_eq!(f[0].severity, Severity::Medium, "{:?}", f[0].reason);

        let bad = task_xml(r"C:\Users\a\AppData\Local\Temp\x.exe", "-enc SQBFAFgA");
        let f = run(&[ev(
            "Security",
            4698,
            json!({"TaskName": "\\x", "TaskContent": bad}),
        )]);
        assert_eq!(f[0].severity, Severity::High);

        let ps = task_xml("powershell.exe", "-w hidden -c iex");
        let f = run(&[ev(
            "Security",
            4698,
            json!({"TaskName": "\\y", "TaskContent": ps}),
        )]);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn service_arguments_do_not_count_as_the_binary() {
        for image in [
            r#""C:\Program Files\Vendor\svc.exe" -config C:\ProgramData\Vendor\cfg.xml"#,
            r#""C:\Program Files\Vendor\agent.exe" --server https://mgmt.vendor.example"#,
            r"C:\Program Files\Vendor\svc.exe -log C:\Users\Public\v.log",
        ] {
            let f = run(&[ev(
                "System",
                7045,
                json!({"ServiceName": "Vendor", "ImagePath": image}),
            )]);
            assert_eq!(f[0].severity, Severity::Low, "{image}: {:?}", f[0].reason);
        }
        // The binary itself in a writable folder stays High.
        let f = run(&[ev(
            "System",
            7045,
            json!({"ServiceName": "u", "ImagePath": r"C:\Users\Public\svc.exe -k"}),
        )]);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn defender_exclusion_severity_follows_the_shared_risk_table() {
        let excl = |path: &str| {
            json!({"New Value": format!(
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\{path} = 0x0"
            )})
        };
        let f = run(&[ev(DEFENDER_CHANNEL, 5007, excl(r"C:\Program Files\Veeam"))]);
        assert_eq!(f[0].severity, Severity::Medium, "{:?}", f[0].reason);
        let f = run(&[ev(
            DEFENDER_CHANNEL,
            5007,
            excl(r"C:\Users\a\AppData\Local\Temp"),
        )]);
        assert_eq!(f[0].severity, Severity::High, "{:?}", f[0].reason);
        let f = run(&[ev(DEFENDER_CHANNEL, 5007, excl(r"C:\"))]);
        assert_eq!(f[0].severity, Severity::High);
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
    fn defender_severity_by_category_and_outcome() {
        let pua = json!({"Threat Name": "PUA:Win32/Presenoker", "Path": "file:_C:\\a.exe", "Category Name": "Potentially Unwanted Software"});
        // PUA, no action recorded -> Medium
        let f = run(&[ev(DEFENDER_CHANNEL, 1116, pua.clone())]);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("no action recorded"));
        // PUA quarantined -> Low, outcome attached
        let mut done = pua.clone();
        done["Action Name"] = json!("Quarantine");
        let f = run(&[
            ev(DEFENDER_CHANNEL, 1116, pua.clone()),
            ev(DEFENDER_CHANNEL, 1117, done),
        ]);
        assert_eq!(f.len(), 1, "1117 joins the 1116 group");
        assert_eq!(f[0].severity, Severity::Low);
        assert!(
            f[0].details.contains("action taken: Quarantine"),
            "{}",
            f[0].details
        );
        assert_eq!(f[0].evidence.len(), 2);
        // adware by category
        let adw = json!({"Threat Name": "BrowserModifier:Win32/X", "Path": "p", "Category Name": "Adware"});
        assert_eq!(
            run(&[ev(DEFENDER_CHANNEL, 1116, adw)])[0].severity,
            Severity::Medium
        );
        // trojan -> High even when quarantined
        let tro = json!({"Threat Name": "Trojan:Win32/X", "Path": "p", "Category Name": "Trojan", "Action Name": "Quarantine"});
        let f = run(&[
            ev(DEFENDER_CHANNEL, 1116, tro.clone()),
            ev(DEFENDER_CHANNEL, 1117, tro),
        ]);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn defender_failed_action_is_high_and_joins_by_threat() {
        let det = json!({"Threat Name": "PUA:Win32/X", "Path": "file:_C:\\a.exe", "Category Name": "Potentially Unwanted Software"});
        // the 1118 lists the path differently: joined by threat name
        let fail = json!({"Threat Name": "PUA:Win32/X", "Path": "file:_C:\\a.exe; process:_pid:4", "Action Name": "Remove", "Error Description": "Access is denied."});
        let f = run(&[
            ev(DEFENDER_CHANNEL, 1116, det),
            ev(DEFENDER_CHANNEL, 1118, fail),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        let reason = f[0].reason.as_deref().unwrap();
        assert!(
            reason.contains("FAILED") && reason.contains("Access is denied"),
            "{reason}"
        );
        assert!(f[0].details_client.as_deref().unwrap().contains("失敗"));
        // a 1119 with no 1116 still reports
        let crit =
            json!({"Threat Name": "Trojan:Win32/Y", "Path": "p", "Action Name": "Quarantine"});
        let f = run(&[ev(DEFENDER_CHANNEL, 1119, crit)]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].details.contains("critical failed"));
    }

    #[test]
    fn unrelated_events_are_ignored() {
        assert!(run(&[ev("Security", 4624, json!({}))]).is_empty());
    }
}
