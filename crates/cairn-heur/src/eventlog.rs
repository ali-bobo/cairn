//! Built-in detections over native Windows event logs: the few event IDs that every
//! Windows host writes by default (no Sysmon, no extra audit policy) and that are
//! strong evidence on their own. Unlike Sigma rules they do not depend on the bundled
//! rule set being present, and each one maps to an Atomic Red Team test.
//!
//! | Event | Channel | Meaning | ATT&CK |
//! |---|---|---|---|
//! | 1102 | Security | audit log cleared | T1070.001 |
//! | 104 | System | event log cleared | T1070.001 |
//! | 7045 | System | service installed with a red flag (trusted installs are inventory) | T1543.003 |
//! | 7040 | System | Windows Event Log service set to disabled | T1562.002 |
//! | 4698 | Security | scheduled task created (needs "Other Object Access" audit) | T1053.005 |
//! | 5001 | Defender | real-time protection turned off | T1562.001 |
//! | 5007 | Defender | configuration changed (exclusion added) | T1562.001 |
//! | 1116 | Defender | malware detected (PUA/adware Low–Medium, else High) | — |
//! | 1117 / 1118 / 1119 | Defender | action taken / action failed (High) | — |
//!
//! A 7045 with no red flag whose binary sits in a folder only administrators can write
//! is host inventory (observation category [`OBS_SERVICE_INSTALL`]), not a finding: see
//! `assess_service`.
//!
//! Runs after Sigma; `heur_lateral` and `heur_defense` run after this analyzer. A
//! per-event finding here follows the same-evidence rule (`dedup.rs`): skipped when a
//! Sigma hit on the same event already says it, absorbed when `heur_lateral` reports
//! the same 7045 as remote execution or `heur_defense` finds the 5007 exclusion still
//! in the registry.
//!
//! Field names, checked against real logs (EVTX-ATTACK-SAMPLES, DeepBlueCLI samples;
//! see `tests/fixtures/README.md`):
//! - 1102 / 104: UserData `LogFileCleared` { `SubjectUserName`, `SubjectDomainName`,
//!   104 also `Channel` (the cleared log) and `BackupPath` }, one level below `data`.
//! - 7045: EventData `ServiceName`, `ImagePath`, `ServiceType`, `StartType`,
//!   `AccountName`. Its System `EventID` carries `Qualifiers` (the collector reads it).
//! - 7040: `param1` display name, `param2` old / `param3` new start type (localized
//!   text), `param4` service key name.
//! - 4698: `TaskName`, `TaskContent` (the task XML), `SubjectUserName`.
//! - Defender 5001 / 5007 / 1116-1119 (`New Value`, `Threat Name`, `Action Name`,
//!   `Error Description`, ...) are NOT yet checked against a real log: no public
//!   sample was found.
//!
//! Pure logic over EventRecords; touches no host state.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use cairn_core::finding::{EntityRegistry, EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Observation, Result};
use serde_json::{Map, Value};

use crate::dedup::EvidenceKey;
use crate::defense::{exclusion_value_note, exclusion_value_risk};
use crate::trust::{
    invocation_args, invoked_path, is_system_or_program_files, is_user_writable_path,
    is_windows_root_exe, is_windows_user_writable_dir, launchers_in, risky_args, script_markers,
    MarkerKind, MICROSOFT_PROGRAMDATA,
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
    let binary = invoked_path(cmd);
    let mut flags = RedFlags {
        writable_binary: is_user_writable_path(binary)
            || is_windows_user_writable_dir(&normalize_image(binary)),
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

/// Driver file names that EDR-killer and ransomware campaigns install for a known
/// vulnerability (bring-your-own-vulnerable-driver; loldrivers.io lists them). The
/// vendor's own product ships the same file (MSI Afterburner, Process Explorer, ...),
/// so a name is a lead to check, not proof.
const VULNERABLE_DRIVER_NAMES: &[(&str, &str)] = &[
    ("rtcore64.sys", "MSI Afterburner; BlackByte, AvosLocker"),
    ("gdrv.sys", "Gigabyte tools; RobbinHood"),
    ("dbutil_2_3.sys", "Dell BIOS utility, CVE-2021-21551"),
    (
        "mhyprot2.sys",
        "Genshin Impact anti-cheat; ransomware EDR kill",
    ),
    (
        "procexp152.sys",
        "Process Explorer, which also installs it when an admin runs it; AuKill",
    ),
    ("aswarpot.sys", "Avast anti-rootkit; AvosLocker, Cuba"),
    ("zam64.sys", "Zemana; Terminator / Spyboy"),
    ("zamguard64.sys", "Zemana; Terminator / Spyboy"),
    ("iqvw64e.sys", "Intel network diagnostics; kdmapper"),
    ("kprocesshacker.sys", "Process Hacker"),
    ("truesight.sys", "RogueKiller anti-rootkit; EDR killers"),
];

/// How one 7045 service install is reported.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ServiceVerdict {
    /// A finding: severity, reason, ATT&CK techniques beyond T1543.003.
    Finding(Severity, String, Vec<&'static str>),
    /// Host inventory, not a finding: a driver or service from a folder only an
    /// administrator can write, with no red flag. The reason says which tier.
    Inventory(String),
}

/// Judge a 7045 ImagePath. Checked in order, the first match decides:
///
/// 1. Red flags ([`command_red_flags`]: user-writable binary, launcher, script
///    markers) -> High. A service runs as SYSTEM, so each is an escalation path.
/// 2. An exe directly in the Windows folder (the `ADMIN$` root, where PsExec-style
///    tools drop their service) -> Medium.
/// 3. A driver whose file name is a known vulnerable driver -> Medium (T1068).
/// 4. A binary outside the Windows / Program Files / Microsoft ProgramData trees ->
///    Medium.
/// 5. A user-mode service with an unquoted path with a space in the binary -> Low
///    (T1574.009: Windows tries `C:\Program.exe` first, an old privilege-escalation
///    path).
/// 6. Otherwise (driver or service from an admin-only folder, no red flag) ->
///    inventory. A real System log (DeepBlueCLI `many-events-system.evtx`) has 42
///    such installs (23 drivers under System32\drivers or Program Files, VMware /
///    Hyper-V / .NET / Google Update / EMET services); each was a Low finding, 42 rows
///    that never told an analyst anything. The event carries no signature, so the
///    tier is the folder's ACL, the same "system or vendor-installed" tier the
///    persistence gate uses.
fn assess_service(image: &str) -> ServiceVerdict {
    let flags = command_red_flags(image);
    if !flags.is_empty() {
        return ServiceVerdict::Finding(Severity::High, flags.reason(), vec![]);
    }
    if is_windows_root_exe(image) {
        // Checked before the Windows-tree trust tier: the root of C:\Windows is the
        // ADMIN$ share, where PsExec-style tools drop their service binary.
        return ServiceVerdict::Finding(
            Severity::Medium,
            "binary sits directly in the Windows folder (the ADMIN$ share root), where \
             PsExec-style remote execution drops its service exe; stock services run from \
             System32 or a vendor folder"
                .to_string(),
            vec![],
        );
    }
    let binary = invoked_path(image);
    let normalized = normalize_image(binary);
    let file = normalized.rsplit('\\').next().unwrap_or(&normalized);
    if let Some((name, known)) = VULNERABLE_DRIVER_NAMES.iter().find(|(n, _)| *n == file) {
        return ServiceVerdict::Finding(
            Severity::Medium,
            format!(
                "driver {name} is a known vulnerable driver ({known}) that attackers load \
                 to kill security software (BYOVD); check that the product it belongs to \
                 is installed on purpose"
            ),
            vec!["T1068"],
        );
    }
    if !(is_system_or_program_files(&normalized) || normalized.contains(MICROSOFT_PROGRAMDATA)) {
        return ServiceVerdict::Finding(
            Severity::Medium,
            "binary is outside the Windows and Program Files trees".to_string(),
            vec![],
        );
    }
    // Drivers are excluded: the kernel loads the ImagePath as given, with no
    // CreateProcess-style search (the real VMware `memctl` driver is registered
    // unquoted under `C:\Program Files\Common Files\...`).
    let quoted = image.trim_start().starts_with('"');
    if !quoted && binary.trim().contains(' ') && !is_driver_image(image) {
        return ServiceVerdict::Finding(
            Severity::Low,
            format!(
                "unquoted service path with a space ({}): Windows tries each shorter \
                 path first, so a writable parent folder lets another exe run as the \
                 service (path interception)",
                binary.trim()
            ),
            vec!["T1574.009"],
        );
    }
    ServiceVerdict::Inventory(
        "no red flag; binary in a folder only administrators can write (Windows, \
         Program Files or Microsoft ProgramData)"
            .to_string(),
    )
}

/// True when the 7045 ImagePath is a driver (`.sys`), by file name: the `ServiceType`
/// text is localized.
fn is_driver_image(image: &str) -> bool {
    invoked_path(image)
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .ends_with(".sys")
}

fn service_installed(ev: &EventRecord) -> Option<Finding> {
    let name = field_or_dash(ev, "ServiceName");
    let image = field_or_dash(ev, "ImagePath");
    let account = field_or_dash(ev, "AccountName");
    let ServiceVerdict::Finding(severity, reason, extra) = assess_service(&image) else {
        return None;
    };
    let mut mitre = vec!["T1543.003"];
    mitre.extend(extra);
    Some(finding(
        ev,
        severity,
        format!("新安裝服務：{name}"),
        &mitre,
        format!("EID 7045: service {name} installed, ImagePath={image}, account={account}"),
        reason,
        format!(
            "{} 有新的服務「{name}」被安裝，執行的程式是 {image}。服務會在開機時自動執行，\
             是常見的後門手法；請確認這是不是已知的軟體安裝。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    ))
}

/// Observation category of a 7045 install kept as inventory (see [`assess_service`]).
pub const OBS_SERVICE_INSTALL: &str = cairn_core::observation::CATEGORY_SERVICE_INSTALL;

/// The inventory side of [`service_installed`]: a 7045 with no red flag from an
/// admin-only folder.
fn service_inventory(ev: &EventRecord) -> Option<Observation> {
    let image = field_or_dash(ev, "ImagePath");
    let ServiceVerdict::Inventory(why) = assess_service(&image) else {
        return None;
    };
    let name = field_or_dash(ev, "ServiceName");
    let kind = if is_driver_image(&image) {
        "驅動程式"
    } else {
        "服務"
    };
    let mut o = Observation::new(OBS_SERVICE_INSTALL, format!("新安裝{kind}：{name}"));
    o.ts = ev.ts;
    o.host = ev.computer.clone();
    o.path = Some(image.clone());
    o.source_artifact = format!("evtx:{}", ev.channel);
    o.details = format!(
        "EID 7045 record {}: ServiceType={}, StartType={}, account={}; {why}",
        ev.record_id,
        field_or_dash(ev, "ServiceType"),
        field_or_dash(ev, "StartType"),
        field_or_dash(ev, "AccountName"),
    );
    Some(o)
}

/// 7040 start-type text meaning "disabled" (English, zh-TW); `param3` is localized.
const START_TYPE_DISABLED: &[&str] = &["disabled", "已停用"];

/// System 7040 turning the Windows Event Log service (`param4` key name `EventLog`)
/// to disabled: T1562.002. Real shape (DeepBlueCLI `disablestop-eventlog.evtx`):
/// `param1` display name, `param2` old start type, `param3` new start type, `param4`
/// service key name.
fn eventlog_service_disabled(ev: &EventRecord) -> Option<Finding> {
    let key = field_or_dash(ev, "param4");
    let new_type = field_or_dash(ev, "param3");
    if !key.trim().eq_ignore_ascii_case("eventlog")
        || !START_TYPE_DISABLED
            .iter()
            .any(|d| new_type.trim().eq_ignore_ascii_case(d))
    {
        return None;
    }
    let old_type = field_or_dash(ev, "param2");
    Some(finding(
        ev,
        Severity::High,
        "事件記錄服務被停用".to_string(),
        &["T1562.002"],
        format!(
            "EID 7040: {} ({key}) start type changed from {old_type} to {new_type}",
            field_or_dash(ev, "param1")
        ),
        "the Windows Event Log service was set to disabled: once it stops, nothing more is \
         logged, which attackers do to work unseen"
            .to_string(),
        format!(
            "{} Windows 事件記錄服務被設定為停用。服務停止後系統就不再留下任何紀錄，\
             這是攻擊者隱藏行蹤的手法；除非是已知的維護作業，請立即恢復並調查。",
            ev.ts.format("%Y-%m-%d %H:%M UTC")
        ),
    ))
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
    let mut f = finding(
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
    );
    // The exclusion as typed data, so heur_defense can recognise the same exclusion it
    // reads from the registry (same-evidence rule, `dedup.rs`).
    if let Some(entity) = exclusion_entity(&new) {
        f.entity.registry = Some(entity);
    }
    Some(f)
}

/// The registry entity a 5007 `New Value` names:
/// `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0` ->
/// hive HKLM, key `SOFTWARE\...\Exclusions\Paths`, value `C:\x`.
fn exclusion_entity(new: &str) -> Option<EntityRegistry> {
    let (_, item) = parse_exclusion_value(new)?;
    let lower = new.to_ascii_lowercase();
    let at = lower.find(r"\exclusions\")? + r"\exclusions\".len();
    let list_end = at + new.get(at..)?.find('\\')?;
    let full_key = new.get(..list_end)?;
    let (hive, key) = match full_key.split_once('\\') {
        Some((h, k)) if h.eq_ignore_ascii_case("HKLM") || h.starts_with("HKEY_") => {
            ("HKLM".to_string(), k.to_string())
        }
        _ => ("HKLM".to_string(), full_key.to_string()),
    };
    Some(EntityRegistry {
        hive,
        key,
        value: item,
        data: String::new(),
        last_write: None,
    })
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

    /// Runs after Sigma: a per-event finding a Sigma hit on the same event already
    /// covers is skipped or merged (same-evidence rule, `dedup.rs`).
    fn depends_on(&self) -> &[&str] {
        &[cairn_core::analyzers::SIGMA]
    }

    fn analyze(&self, records: &[Record], prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let mut detections = Vec::new();
        for r in records {
            let Record::Event(ev) = r else { continue };
            let one = match (ev.channel.as_str(), ev.event_id) {
                ("Security", 1102) | ("System", 104) => Some(log_cleared(ev)),
                ("System", 7045) => service_installed(ev),
                ("System", 7040) => eventlog_service_disabled(ev),
                ("Security", 4698) => Some(task_created(ev)),
                (DEFENDER_CHANNEL, 5001) => Some(defender_rtp_off(ev)),
                (DEFENDER_CHANNEL, 5007) => defender_exclusion(ev),
                (DEFENDER_CHANNEL, 1116..=1119) => {
                    detections.push(ev);
                    None
                }
                _ => None,
            };
            if let Some(f) = one {
                let mut f = f;
                f.analyzer = Self::NAME.to_string();
                out.extend(crate::dedup::resolve(f, &EvidenceKey::event(ev), prior));
            }
        }
        out.extend(defender_detections(&detections));
        Ok(crate::stamped(out, Self::NAME))
    }

    /// Service installs kept as inventory instead of findings (see `assess_service`).
    fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> {
        Ok(records
            .iter()
            .filter_map(|r| match r {
                Record::Event(ev) if ev.channel == "System" && ev.event_id == 7045 => {
                    service_inventory(ev)
                }
                _ => None,
            })
            .collect())
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

    fn observe(records: &[Record]) -> Vec<Observation> {
        EventLogHeuristic.observe(records).unwrap()
    }

    fn svc(name: &str, image: &str) -> Record {
        ev(
            "System",
            7045,
            json!({"ServiceName": name, "ImagePath": image, "ServiceType": "kernel mode driver"}),
        )
    }

    /// A service or driver from an admin-only folder with no red flag is inventory,
    /// not a finding (real shapes from DeepBlueCLI many-events-system.evtx).
    #[test]
    fn trusted_installs_are_inventory_not_findings() {
        for image in [
            "\"C:\\Program Files\\Vendor\\svc.exe\"",
            r"\SystemRoot\System32\drivers\x.sys",
            r"System32\drivers\x.sys",
            r"system32\DRIVERS\VMBusVideoM.sys",
            r"%SystemRoot%\system32\svchost.exe -k netsvcs",
            r"\??\C:\Windows\system32\drivers\y.sys",
            r"C:\Windows\system32\dllhost.exe /Processid:{F3F72FE3-CF58-4A21-BBED-F596E5AFE5C0}",
            r#""C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25010.11-0\MsMpEng.exe""#,
            r"C:\Program Files\Common Files\VMware\Drivers\memctl\vmmemctl.sys",
        ] {
            let recs = [svc("d", image)];
            assert!(run(&recs).is_empty(), "{image}: {:?}", run(&recs));
            let o = observe(&recs);
            assert_eq!(o.len(), 1, "{image}");
            assert_eq!(o[0].category, OBS_SERVICE_INSTALL);
            assert_eq!(o[0].path.as_deref(), Some(image));
            assert!(o[0].details.contains("record 7"), "{}", o[0].details);
        }
        let o = observe(&[svc("vm3dmp", r"system32\DRIVERS\vm3dmp.sys")]);
        assert!(o[0].title.contains("驅動程式"), "{}", o[0].title);
    }

    /// Anything with a red flag stays a finding and never reaches the inventory.
    #[test]
    fn flagged_installs_are_findings_not_inventory() {
        for (image, sev) in [
            (r"C:\Users\a\AppData\Local\Temp\x.sys", Severity::High),
            (r"cmd.exe /c echo x > \\.\pipe\x", Severity::High),
            (r"C:\ProgramData\Vendor\svc.exe", Severity::High),
            (r"C:\Windows\Tasks\svc.exe", Severity::High),
            (
                r"C:\Windows\System32\spool\drivers\color\x.sys",
                Severity::High,
            ),
            (r"%SYSTEMROOT%\duKhLYUX.exe", Severity::Medium),
            (r"D:\tools\x.exe", Severity::Medium),
            (r"C:\Program Files Evil\x.exe", Severity::Medium),
        ] {
            let recs = [svc("x", image)];
            let f = run(&recs);
            assert_eq!(f.len(), 1, "{image}");
            assert_eq!(f[0].severity, sev, "{image}: {:?}", f[0].reason);
            assert!(observe(&recs).is_empty(), "{image}");
        }
    }

    /// Known vulnerable drivers (BYOVD) stay Medium findings even from System32.
    #[test]
    fn known_vulnerable_driver_is_a_medium_finding() {
        for image in [
            r"System32\drivers\RTCore64.sys",
            r"\??\C:\Windows\System32\drivers\PROCEXP152.SYS",
            r"C:\Program Files\MSI\gdrv.sys",
        ] {
            let f = run(&[svc("v", image)]);
            assert_eq!(f.len(), 1, "{image}");
            assert_eq!(f[0].severity, Severity::Medium, "{image}");
            assert!(f[0].mitre.contains(&"T1068".to_string()));
            assert!(f[0].reason.as_deref().unwrap().contains("BYOVD"));
        }
        // From a drop zone the red flag wins: High.
        let f = run(&[svc("v", r"C:\Users\Public\RTCore64.sys")]);
        assert_eq!(f[0].severity, Severity::High);
    }

    /// An unquoted path with a space stays a Low finding (T1574.009).
    #[test]
    fn unquoted_path_with_spaces_is_a_low_finding() {
        let image =
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25010.11-0\MsMpEng.exe";
        let f = run(&[svc("WinDefend", image)]);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].mitre.contains(&"T1574.009".to_string()));
        assert!(observe(&[svc("WinDefend", image)]).is_empty());
    }

    /// Real Metasploit psexec 7045 (DeepBlueCLI metasploit-psexec-native-target-system):
    /// a random exe directly in %SYSTEMROOT% is not "the trusted Windows tree".
    #[test]
    fn service_exe_directly_in_the_windows_folder_is_medium() {
        for image in [r"%SYSTEMROOT%\duKhLYUX.exe", r"C:\Windows\PSEXESVC.exe"] {
            let f = run(&[ev(
                "System",
                7045,
                json!({"ServiceName": "KgXItsbKgTJzdzwl", "ImagePath": image}),
            )]);
            assert_eq!(f[0].severity, Severity::Medium, "{image}");
            assert!(f[0].reason.as_deref().unwrap().contains("ADMIN$"));
        }
        // A subfolder of the Windows tree is the trusted tier: inventory.
        let recs = [ev(
            "System",
            7045,
            json!({"ServiceName": "n", "ImagePath": r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\SMSvcHost.exe"}),
        )];
        assert!(run(&recs).is_empty());
        assert_eq!(observe(&recs).len(), 1);
    }

    /// Real 7040 shape (DeepBlueCLI disablestop-eventlog.evtx).
    #[test]
    fn eventlog_service_disabled_is_high() {
        let ev7040 = |old: &str, new: &str, key: &str| {
            ev(
                "System",
                7040,
                json!({"param1": "Windows Event Log", "param2": old, "param3": new, "param4": key}),
            )
        };
        let f = run(&[ev7040("auto start", "disabled", "EventLog")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1562.002"]);
        // Re-enabling it, or another service, is not this detection.
        assert!(run(&[
            ev7040("disabled", "auto start", "EventLog"),
            ev7040("auto start", "disabled", "BITS"),
        ])
        .is_empty());
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
            let recs = [ev(
                "System",
                7045,
                json!({"ServiceName": "Vendor", "ImagePath": image}),
            )];
            // No red flag: the quoted ones are inventory, the unquoted one a Low
            // unquoted-path finding; none is judged by its argument's folder.
            let f = run(&recs);
            assert!(
                f.iter().all(|x| x.severity == Severity::Low),
                "{image}: {f:?}"
            );
            assert_eq!(f.len() + observe(&recs).len(), 1, "{image}");
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
