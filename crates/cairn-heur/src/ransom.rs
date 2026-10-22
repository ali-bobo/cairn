//! Ransomware precursors (ATT&CK T1490 Inhibit System Recovery): before encrypting,
//! ransomware deletes the shadow copies and backups and turns off Windows recovery.
//!
//! - **Command lines** (live processes and Security 4688): `vssadmin delete shadows` /
//!   `resize shadowstorage`, `wmic shadowcopy delete`, PowerShell / WMI deletion of
//!   `Win32_ShadowCopy`, `wbadmin delete catalog|systemstatebackup|backup`, and
//!   `bcdedit` turning off recovery or ignoring boot failures. High.
//! - **No shadow copies** (`dropscan` [`ShadowCopyRecord`]): a client edition with
//!   System Restore on but zero shadow copies. Medium: a new install or a cleanup tool
//!   also leaves zero, so the reason says so. Raised only when all three facts were
//!   read; any unknown leaves it silent.
//! - **Default VSS / backup events** ([`vss_signal`]), all written without extra
//!   auditing:
//!   - Application 524 from `Microsoft-Windows-Backup` (backup catalog deleted, the
//!     event behind the Sigma rule "Backup Catalog Deleted");
//!   - System 7040 changing the Volume Shadow Copy service (`VSS`) start type to
//!     disabled;
//!   - System 7036 VSS service entering the stopped / running state;
//!   - Application `VSS` errors 8193 / 8194 / 12289.
//!
//!   One within [`VSS_CORRELATION_MINUTES`] of a deletion command is attached to that
//!   High finding as evidence (and named in its reason). Without a nearby command,
//!   524 and 7040-disabled each raise one Medium finding; the 7036 state changes and
//!   the 8193 / 8194 / 12289 errors stay silent, because VSS stops after every idle
//!   period and its writer errors are common on healthy hosts.
//!
//! The 7036 / 7040 shapes are checked against real System logs (DeepBlueCLI samples,
//! `tests/fixtures/README.md`): 7040 `param1` display name, `param2` old and `param3`
//! new start type (localized text), `param4` service key name; 7036 `param1` display
//! name, `param2` state, `Binary` = UTF-16LE hex of `<key name>/<state code>`. No public
//! sample with a VSS 7036 / 7040, Application 524 or VSS 8193 / 8194 / 12289 was found,
//! so those event IDs themselves are not yet checked against a real log.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record, ShadowCopyRecord};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

use crate::cmdline::{command_lines, event_str, program, CommandLine};

const INHIBIT_RECOVERY: &str = "T1490";

/// Channels this analyzer reads (written by default). The live EVTX collector reads
/// them even when no Sigma rules are loaded.
pub const CHANNELS: &[&str] = &["Application", "System"];

/// How far (either side) a VSS / backup event may be from a deletion command to be
/// attached to it as evidence.
pub const VSS_CORRELATION_MINUTES: i64 = 30;

/// Provider of the Windows Server Backup / wbadmin events (Application 524).
const BACKUP_PROVIDER: &str = "Microsoft-Windows-Backup";
/// Service key name of the Volume Shadow Copy service.
const VSS_SERVICE: &str = "VSS";
/// Its display name (English, zh-TW), lowercase.
const VSS_DISPLAY_NAMES: &[&str] = &["volume shadow copy", "磁碟區陰影複製"];
/// 7040 start-type text meaning "disabled" (English, zh-TW).
const DISABLED_WORDS: &[&str] = &["disabled", "停用"];

/// What a default VSS / backup event says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VssSignal {
    /// Application 524 (Microsoft-Windows-Backup): backup catalog deleted.
    CatalogDeleted,
    /// System 7040: VSS start type set to disabled.
    ServiceDisabled,
    /// System 7036: VSS entered the stopped / running state.
    ServiceState,
    /// Application VSS 8193 / 8194 / 12289.
    VssError,
}

impl VssSignal {
    fn label(self) -> &'static str {
        match self {
            VssSignal::CatalogDeleted => "backup catalog deleted (Application 524)",
            VssSignal::ServiceDisabled => "VSS service set to disabled (System 7040)",
            VssSignal::ServiceState => "VSS service state change (System 7036)",
            VssSignal::VssError => "VSS error (Application 8193/8194/12289)",
        }
    }

    /// Raises a finding on its own (without a nearby deletion command).
    fn standalone(self) -> bool {
        matches!(self, VssSignal::CatalogDeleted | VssSignal::ServiceDisabled)
    }
}

/// UTF-16LE text of a hex `<Binary>` blob (7036 carries `VSS/1`: key name / state).
fn binary_text(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect();
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units).replace('\0', "")
}

fn field(ev: &EventRecord, key: &str) -> String {
    event_str(&ev.data, key).unwrap_or_default()
}

/// The event names the VSS service: by key name (`param4` of 7040, the `<Binary>`
/// of 7036) or by display name (`param1`).
fn names_vss(ev: &EventRecord) -> bool {
    let p1 = field(ev, "param1").trim().to_lowercase();
    if VSS_DISPLAY_NAMES.contains(&p1.as_str()) {
        return true;
    }
    if field(ev, "param4").trim().eq_ignore_ascii_case(VSS_SERVICE) {
        return true;
    }
    let bin = binary_text(field(ev, "Binary").trim());
    bin.split('/')
        .next()
        .is_some_and(|k| k.trim().eq_ignore_ascii_case(VSS_SERVICE))
}

fn provider_is(ev: &EventRecord, name: &str) -> bool {
    ev.provider.eq_ignore_ascii_case(name) || field(ev, "Provider_Name").eq_ignore_ascii_case(name)
}

/// The VSS / backup signal an event carries, if any.
pub fn vss_signal(ev: &EventRecord) -> Option<VssSignal> {
    let ch = ev.channel.as_str();
    let app = ch.eq_ignore_ascii_case("Application");
    let system = ch.eq_ignore_ascii_case("System");
    match ev.event_id {
        524 if (app || ch.eq_ignore_ascii_case(BACKUP_PROVIDER))
            && provider_is(ev, BACKUP_PROVIDER) =>
        {
            Some(VssSignal::CatalogDeleted)
        }
        7040 if system && names_vss(ev) => {
            let new_type = field(ev, "param3").to_lowercase();
            DISABLED_WORDS
                .iter()
                .any(|w| new_type.contains(w))
                .then_some(VssSignal::ServiceDisabled)
        }
        7036 if system && names_vss(ev) => Some(VssSignal::ServiceState),
        8193 | 8194 | 12289 if app && provider_is(ev, VSS_SERVICE) => Some(VssSignal::VssError),
        _ => None,
    }
}

fn vss_detail(ev: &EventRecord, sig: VssSignal) -> String {
    let extra = match sig {
        VssSignal::ServiceDisabled => format!(
            ": start type {} -> {}",
            field(ev, "param2"),
            field(ev, "param3")
        ),
        VssSignal::ServiceState => format!(": entered {}", field(ev, "param2")),
        _ => String::new(),
    };
    format!("EID {}: {}{extra}", ev.event_id, sig.label())
}

fn vss_evidence(ev: &EventRecord, sig: VssSignal) -> EvidenceItem {
    EvidenceItem {
        artifact: format!("evtx:{}", ev.channel),
        path: None,
        ts: Some(ev.ts),
        detail: vss_detail(ev, sig),
    }
}

fn fmt_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// One Medium finding for the uncorroborated events of one standalone signal.
fn vss_finding(sig: VssSignal, list: &[&EventRecord]) -> Finding {
    let first = list[0];
    let title = match sig {
        VssSignal::CatalogDeleted => "備份目錄被刪除（Windows 備份事件 524）",
        _ => "磁碟區陰影複製服務（VSS）被設為停用",
    };
    let mut f = Finding::new(Severity::Medium, title, FindingSource::Heuristic);
    f.ts = first.ts;
    f.artifact = format!("evtx:{}", first.channel);
    f.event_id = Some(first.event_id);
    f.evidence_ref = Some(format!("{}#{}", first.channel, first.record_id));
    f.mitre = vec![INHIBIT_RECOVERY.into()];
    f.details = list
        .iter()
        .map(|e| format!("{} {}", fmt_ts(e.ts), vss_detail(e, sig)))
        .collect::<Vec<_>>()
        .join("\n");
    f.reason = Some(format!(
        "{} ({} event(s), first {}); ransomware removes backups and shadow copies before \
         encrypting. No recovery-deletion command line was seen within \
         {VSS_CORRELATION_MINUTES} min (4688 command-line auditing may be off), and backup \
         maintenance does this too, so confirm with IT",
        sig.label(),
        list.len(),
        fmt_ts(first.ts)
    ));
    f.evidence = list.iter().take(10).map(|e| vss_evidence(e, sig)).collect();
    let when = first.ts.format("%Y-%m-%d %H:%M UTC");
    f.details_client = Some(match sig {
        VssSignal::CatalogDeleted => format!(
            "{when} 這台主機的 Windows 備份目錄被刪除。勒索軟體在加密前常會刪除備份，讓受害者無法還原；\
             也可能是 IT 人員在整理備份。請向 IT 確認，並檢查備份是否完好。"
        ),
        _ => format!(
            "{when} 這台主機的「磁碟區陰影複製」服務被設為停用，之後無法建立系統還原點。勒索軟體常這樣做，\
             讓受害者無法還原檔案；請向 IT 確認是否為刻意的設定。"
        ),
    });
    f
}

/// Attach each VSS / backup event to the nearest deletion command within the window;
/// return the standalone-worthy events left over, per signal.
fn correlate<'a>(
    cmds: &mut [(Option<DateTime<Utc>>, Finding)],
    records: &'a [Record],
) -> BTreeMap<VssSignal, Vec<&'a EventRecord>> {
    let mut events: Vec<(&EventRecord, VssSignal)> = records
        .iter()
        .filter_map(|r| match r {
            Record::Event(e) => vss_signal(e).map(|s| (e, s)),
            _ => None,
        })
        .collect();
    events.sort_by_key(|(e, _)| (e.ts, e.record_id));
    let window = Duration::minutes(VSS_CORRELATION_MINUTES);
    let mut attached: Vec<Vec<(&EventRecord, VssSignal)>> = vec![Vec::new(); cmds.len()];
    let mut alone: BTreeMap<VssSignal, Vec<&EventRecord>> = BTreeMap::new();
    for (ev, sig) in events {
        let nearest = cmds
            .iter()
            .enumerate()
            .filter_map(|(i, (ts, _))| ts.map(|t| (i, (t - ev.ts).abs())))
            .filter(|(_, d)| *d <= window)
            .min_by_key(|(_, d)| *d);
        match nearest {
            Some((i, _)) => attached[i].push((ev, sig)),
            None if sig.standalone() => alone.entry(sig).or_default().push(ev),
            None => {}
        }
    }
    for ((_, f), evs) in cmds.iter_mut().zip(&attached) {
        if evs.is_empty() {
            continue;
        }
        let mut labels: Vec<&str> = evs.iter().map(|(_, s)| s.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        if let Some(r) = f.reason.as_mut() {
            r.push_str(&format!(
                "; corroborated by {} default VSS / backup event(s) within \
                 {VSS_CORRELATION_MINUTES} min: {}",
                evs.len(),
                labels.join(", ")
            ));
        }
        f.evidence
            .extend(evs.iter().take(10).map(|(e, s)| vss_evidence(e, *s)));
    }
    alone
}

/// What a command line does to recovery, if anything. `prog` is the
/// [`crate::trust::exe_name`] of the program, `cmd` the normalized command line.
pub fn recovery_action(prog: &str, cmd: &str) -> Option<&'static str> {
    let has = |s: &str| cmd.contains(s);
    let runs = |exe: &str| prog == exe || has(&format!("{exe}.exe ")) || has(&format!("{exe} "));
    if runs("vssadmin") && has("delete shadows") {
        return Some("vssadmin delete shadows");
    }
    if runs("vssadmin") && has("resize shadowstorage") {
        return Some("vssadmin resize shadowstorage (shrinking it deletes shadow copies)");
    }
    if runs("wmic") && has("shadowcopy") && has("delete") {
        return Some("wmic shadowcopy delete");
    }
    if has("win32_shadowcopy")
        && ["delete", "remove-wmiobject", "remove-ciminstance"]
            .iter()
            .any(|v| has(v))
    {
        return Some("Win32_ShadowCopy deleted through WMI / PowerShell");
    }
    if runs("wbadmin")
        && has("delete")
        && ["catalog", "systemstatebackup", "backup"]
            .iter()
            .any(|v| has(v))
    {
        return Some("wbadmin deletes the backup catalog / backups");
    }
    if runs("bcdedit") && (has("recoveryenabled no") || has("recoveryenabled off")) {
        return Some("bcdedit turns off Windows recovery");
    }
    if runs("bcdedit") && has("bootstatuspolicy") && has("ignoreallfailures") {
        return Some("bcdedit ignores boot failures (no recovery screen)");
    }
    None
}

fn cmd_finding(c: &CommandLine<'_>, action: &str) -> Finding {
    let mut f = Finding::new(
        Severity::High,
        format!("疑似勒索前置動作：{action}"),
        FindingSource::Heuristic,
    );
    c.apply_to(&mut f);
    f.mitre = vec![INHIBIT_RECOVERY.into()];
    f.details = format!("{} ({}): {}", c.image, c.artifact, c.cmd);
    f.reason = Some(format!(
        "command line removes recovery options: {action}; ransomware does this right before encrypting"
    ));
    f.details_client = Some(format!(
        "這台主機上執行過刪除系統還原點或備份的指令：{}。勒索軟體在加密檔案前通常會先這麼做，\
         讓受害者無法自行還原；若不是 IT 人員的已知維護作業，請立即隔離這台主機並確認備份是否完好。",
        c.cmd
    ));
    f
}

/// True when the host is a client with System Restore on and zero shadow copies.
pub fn no_shadow_copies(s: &ShadowCopyRecord) -> bool {
    s.client_os == Some(true) && s.system_restore_enabled == Some(true) && s.count == Some(0)
}

fn shadow_finding(deletions: usize) -> Finding {
    let mut f = Finding::new(
        Severity::Medium,
        "系統還原已開啟但沒有任何還原點",
        FindingSource::Heuristic,
    );
    f.artifact = "wmi:Win32_ShadowCopy".into();
    f.mitre = vec![INHIBIT_RECOVERY.into()];
    f.details = "client edition, System Restore enabled, Win32_ShadowCopy count = 0".into();
    let corroboration = if deletions > 0 {
        format!("; {deletions} shadow-copy / backup deletion command(s) were also seen this run")
    } else {
        "; a fresh install or a disk-cleanup tool also leaves zero, so confirm with the user".into()
    };
    f.reason = Some(format!(
        "System Restore is on for this workstation but it holds no shadow copies; ransomware \
         deletes them before encrypting{corroboration}"
    ));
    f.details_client = Some(
        "這台電腦開啟了系統還原功能，卻一個還原點都沒有。勒索軟體常在加密前刪光還原點；\
         也可能是剛重灌或使用了清理工具。請詢問使用者近期是否做過這些事，\
         並確認重要資料有其他備份。"
            .into(),
    );
    f
}

/// Shadow-copy / backup deletion and missing restore points (see module docs).
pub struct RansomHeuristic;

impl RansomHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::RANSOM;
}

impl Analyzer for RansomHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut cmds: Vec<(Option<DateTime<Utc>>, Finding)> = command_lines(records)
            .iter()
            .filter_map(|c| {
                recovery_action(&program(c), &c.normalized()).map(|a| (c.ts, cmd_finding(c, a)))
            })
            .collect();
        let alone = correlate(&mut cmds, records);
        let mut out: Vec<Finding> = cmds.into_iter().map(|(_, f)| f).collect();
        let deletions = out.len();
        for (sig, list) in &alone {
            out.push(vss_finding(*sig, list));
        }
        if records
            .iter()
            .any(|r| matches!(r, Record::ShadowCopies(s) if no_shadow_copies(s)))
        {
            out.push(shadow_finding(deletions));
        }
        Ok(crate::stamped(out, Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::ProcessRecord;

    fn proc(cmd: &str) -> Record {
        Record::Process(ProcessRecord {
            pid: 7,
            ppid: 1,
            image: String::new(),
            cmdline: cmd.into(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        })
    }

    fn shadows(count: Option<u32>, client: Option<bool>, sr: Option<bool>) -> Record {
        Record::ShadowCopies(ShadowCopyRecord {
            count,
            client_os: client,
            system_restore_enabled: sr,
        })
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        RansomHeuristic.analyze(records, &[]).unwrap()
    }

    #[test]
    fn recovery_inhibition_commands_are_high() {
        for cmd in [
            "vssadmin.exe Delete Shadows /All /Quiet",
            r"C:\Windows\System32\vssadmin.exe resize shadowstorage /for=c: /on=c: /maxsize=401MB",
            "wmic shadowcopy delete /nointeractive",
            "powershell -c \"Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }\"",
            "wbadmin delete catalog -quiet",
            "wbadmin DELETE SYSTEMSTATEBACKUP",
            "bcdedit /set {default} recoveryenabled No",
            "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
            "cmd.exe /c vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no",
        ] {
            let f = run(&[proc(cmd)]);
            assert_eq!(f.len(), 1, "{cmd}");
            assert_eq!(f[0].severity, Severity::High);
            assert_eq!(f[0].mitre, vec!["T1490"]);
            assert_eq!(f[0].analyzer, cairn_core::analyzers::RANSOM);
            assert!(f[0].reason.is_some());
        }
    }

    #[test]
    fn benign_commands_are_quiet() {
        for cmd in [
            "vssadmin list shadows",
            "vssadmin create shadow /for=C:",
            "wmic shadowcopy list brief",
            "wbadmin get versions",
            "bcdedit /enum",
            "bcdedit /set {default} recoveryenabled yes",
        ] {
            assert!(run(&[proc(cmd)]).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn zero_shadow_copies_on_a_protected_client_is_medium() {
        let f = run(&[shadows(Some(0), Some(true), Some(true))]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].reason.as_deref().unwrap().contains("fresh install"));
        let f = run(&[
            shadows(Some(0), Some(true), Some(true)),
            proc("vssadmin delete shadows /all"),
        ]);
        assert_eq!(f.len(), 2);
        assert!(f[1].reason.as_deref().unwrap().contains("1 shadow-copy"));
    }

    #[test]
    fn unknown_or_other_shadow_states_are_quiet() {
        for r in [
            shadows(None, Some(true), Some(true)),
            shadows(Some(0), None, Some(true)),
            shadows(Some(0), Some(false), Some(true)),
            shadows(Some(0), Some(true), Some(false)),
            shadows(Some(0), Some(true), None),
            shadows(Some(3), Some(true), Some(true)),
        ] {
            assert!(run(&[r]).is_empty());
        }
    }

    fn t0() -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
    }

    fn proc_at(cmd: &str, min: i64) -> Record {
        let Record::Process(mut p) = proc(cmd) else {
            unreachable!()
        };
        p.start_time = Some(t0() + Duration::minutes(min));
        Record::Process(p)
    }

    fn event(channel: &str, provider: &str, id: u32, min: i64, fields: &[(&str, &str)]) -> Record {
        let mut data = serde_json::Map::new();
        for (k, v) in fields {
            data.insert((*k).into(), serde_json::Value::String((*v).into()));
        }
        Record::Event(EventRecord {
            ts: t0() + Duration::minutes(min),
            channel: channel.into(),
            event_id: id,
            provider: provider.into(),
            computer: "WS1".into(),
            record_id: min.unsigned_abs() * 100 + u64::from(id % 100),
            data,
        })
    }

    fn catalog_deleted(min: i64) -> Record {
        event("Application", "Microsoft-Windows-Backup", 524, min, &[])
    }

    /// `VSS/1` as UTF-16LE hex, what 7036 carries in `<Binary>`.
    const VSS_STOPPED_BINARY: &str = "5600530053002F0031000000";

    fn vss_state(min: i64, state: &str) -> Record {
        event(
            "System",
            "Service Control Manager",
            7036,
            min,
            &[
                ("param1", "Volume Shadow Copy"),
                ("param2", state),
                ("Binary", VSS_STOPPED_BINARY),
            ],
        )
    }

    fn vss_error(min: i64, id: u32) -> Record {
        event("Application", "VSS", id, min, &[])
    }

    fn vss_start_type(min: i64, new: &str) -> Record {
        event(
            "System",
            "Service Control Manager",
            7040,
            min,
            &[
                ("param1", "Volume Shadow Copy"),
                ("param2", "demand start"),
                ("param3", new),
                ("param4", "VSS"),
            ],
        )
    }

    fn sig(r: &Record) -> Option<VssSignal> {
        match r {
            Record::Event(e) => vss_signal(e),
            _ => None,
        }
    }

    #[test]
    fn vss_and_backup_event_signals() {
        assert_eq!(sig(&catalog_deleted(0)), Some(VssSignal::CatalogDeleted));
        assert_eq!(
            sig(&event("Application", "SomeApp", 524, 0, &[])),
            None,
            "524 from another provider"
        );
        assert_eq!(sig(&vss_state(0, "stopped")), Some(VssSignal::ServiceState));
        // Localized display name: the <Binary> key name still identifies VSS.
        assert_eq!(
            sig(&event(
                "System",
                "Service Control Manager",
                7036,
                0,
                &[
                    ("param1", "Volumeschattenkopie"),
                    ("param2", "Beendet"),
                    ("Binary", VSS_STOPPED_BINARY)
                ],
            )),
            Some(VssSignal::ServiceState)
        );
        assert_eq!(
            sig(&event(
                "System",
                "Service Control Manager",
                7036,
                0,
                &[("param1", "Windows Update"), ("param2", "running")],
            )),
            None
        );
        assert_eq!(
            sig(&vss_start_type(0, "disabled")),
            Some(VssSignal::ServiceDisabled)
        );
        assert_eq!(
            sig(&vss_start_type(0, "已停用")),
            Some(VssSignal::ServiceDisabled)
        );
        assert_eq!(sig(&vss_start_type(0, "auto start")), None);
        for id in [8193, 8194, 12289] {
            assert_eq!(sig(&vss_error(0, id)), Some(VssSignal::VssError));
        }
        assert_eq!(
            sig(&event("Application", "MsiInstaller", 8193, 0, &[])),
            None
        );
        assert_eq!(binary_text(VSS_STOPPED_BINARY), "VSS/1");
    }

    #[test]
    fn uncorroborated_catalog_deletion_and_vss_disable_are_medium() {
        let f = run(&[
            catalog_deleted(0),
            catalog_deleted(1),
            vss_start_type(5, "disabled"),
        ]);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|f| f.severity == Severity::Medium));
        assert!(f.iter().all(|f| f.mitre == vec!["T1490"]));
        let cat = f.iter().find(|f| f.event_id == Some(524)).unwrap();
        assert_eq!(cat.evidence.len(), 2);
        assert!(cat.reason.as_deref().unwrap().contains("2 event(s)"));
        assert!(f.iter().any(|f| f.event_id == Some(7040)));
    }

    #[test]
    fn vss_churn_and_writer_errors_alone_are_quiet() {
        let f = run(&[
            vss_state(0, "running"),
            vss_state(3, "stopped"),
            vss_error(4, 8193),
            vss_error(5, 12289),
            vss_start_type(6, "demand start"),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn events_near_a_deletion_command_corroborate_the_high_finding() {
        let f = run(&[
            proc_at("vssadmin delete shadows /all /quiet", 0),
            vss_state(-1, "running"),
            vss_error(1, 8194),
            catalog_deleted(10),
            // Two hours later: not this command's, stands alone.
            catalog_deleted(120),
        ]);
        assert_eq!(f.len(), 2, "{f:?}");
        let high = f.iter().find(|f| f.severity == Severity::High).unwrap();
        assert_eq!(high.evidence.len(), 3);
        let r = high.reason.as_deref().unwrap();
        assert!(r.contains("corroborated by 3"), "{r}");
        assert!(r.contains("backup catalog deleted"), "{r}");
        let medium = f.iter().find(|f| f.severity == Severity::Medium).unwrap();
        assert_eq!(medium.event_id, Some(524));
        assert_eq!(medium.evidence.len(), 1);
    }
}
