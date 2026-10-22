//! Defense posture (phase 3E `heur_defense`), judged from the `posture` collector's
//! [`PostureRecord`]:
//!
//! - Defender exclusions (T1562.001): user-writable dirs, whole drives, executable or
//!   script extensions and interpreters are High; any other exclusion is Medium. An
//!   exclusion `heur_eventlog` also saw being added (Defender 5007) is reported once,
//!   here, with that event as evidence (same-evidence rule, `dedup.rs`).
//! - Defender disabled by policy (T1562.001): DisableAntiSpyware,
//!   DisableRealtimeMonitoring, DisableBehaviorMonitoring = 1 are High; Tamper
//!   Protection not on (`TamperProtection != 5`) is Medium.
//! - Hidden scheduled tasks ("Tarrask", T1053.005): a TaskCache\Tree task without its
//!   `SD` value, or without its XML under System32\Tasks, is High.
//! - Accessibility binary replaced (T1546.008): a System32 sethc/utilman/osk/... whose
//!   version resource says it is cmd.exe, PowerShell or explorer.exe, or that is
//!   unsigned, is High; any other OriginalFilename mismatch is Medium (Low when the
//!   file is validly signed).
//!
//! Logging blind spots (audit policy, 4688 command line, PowerShell logging, Sysmon)
//! and unreadable exclusion lists are not detections: they are reported as
//! observations, so an analyst knows which evidence this host could not have produced.

use cairn_core::finding::{EntityFile, EntityRegistry, FindingSource, Severity};
use cairn_core::record::{
    AccessibilityBinary, DefenderExclusion, ExclusionKind, PostureRecord, Record, TaskCacheEntry,
};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Observation, Result};
use chrono::{DateTime, Utc};

use crate::trust::{
    exe_name, launcher_kind, normalize_path, MICROSOFT_PROGRAMDATA, USER_WRITABLE_DIRS,
};

/// Extensions whose exclusion lets any payload run unscanned.
const RISKY_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "pif", "cpl", "ocx", "msi", "ps1", "psm1", "bat", "cmd",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "jar", "sct",
];

/// What an accessibility binary must not really be.
const SHELL_ORIGINAL_NAMES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "pwsh.dll",
    "explorer.exe",
];

/// OriginalFilename values in-box accessibility binaries carry (some differ from the
/// file name).
const EXPECTED_ORIGINAL_NAMES: &[(&str, &[&str])] = &[
    ("sethc.exe", &["sethc.exe"]),
    ("utilman.exe", &["utilman.exe", "utilman2.exe"]),
    ("osk.exe", &["osk.exe"]),
    ("magnify.exe", &["magnify.exe", "screenmagnifier.exe"]),
    ("narrator.exe", &["narrator.exe", "sr.exe"]),
    ("displayswitch.exe", &["displayswitch.exe"]),
    ("atbroker.exe", &["atbroker.exe"]),
];

/// Observation category for logging / visibility gaps.
pub const OBS_CATEGORY: &str = "logging_posture";

/// Defender, TaskCache and accessibility-binary checks over the posture snapshot.
pub struct DefenseHeuristic;

impl DefenseHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::DEFENSE;
}

fn postures(records: &[Record]) -> impl Iterator<Item = &PostureRecord> {
    records.iter().filter_map(|r| match r {
        Record::Posture(p) => Some(p),
        _ => None,
    })
}

fn heuristic(severity: Severity, title: String, mitre: &str, reason: String) -> Finding {
    let mut f = Finding::new(severity, title, FindingSource::Heuristic);
    f.mitre = vec![mitre.to_string()];
    f.reason = Some(reason);
    f
}

/// A drop zone other than ProgramData (Temp, AppData, Downloads, Public, ...).
fn writable_outside_programdata(norm: &str) -> bool {
    USER_WRITABLE_DIRS
        .iter()
        .any(|d| *d != r"\programdata\" && norm.contains(d))
}

/// `x:\programdata\<vendor>\...` outside Microsoft's subtree: a vendor folder that
/// backup / EDR / database products tell admins to exclude.
fn is_programdata_vendor_folder(norm: &str) -> bool {
    norm.get(1..)
        .is_some_and(|r| r.starts_with(r":\programdata\"))
        && !norm.contains(MICROSOFT_PROGRAMDATA)
}

/// How dangerous one exclusion is: `Some(reason)` = High (it opens a drop zone, a
/// whole drive, an executable type or an interpreter to unscanned use), `None` = a
/// narrower exclusion, Medium. Shared by the posture snapshot (Defender exclusion keys)
/// and the event log (Defender 5007 "exclusion added"), so both rate one exclusion
/// the same way.
pub(crate) fn exclusion_value_risk(kind: ExclusionKind, value: &str) -> Option<String> {
    let v = value.trim().trim_matches('"');
    let lower = v.to_ascii_lowercase();
    match kind {
        ExclusionKind::Path => {
            let norm = normalize_path(v);
            let bare = norm.trim_end_matches(['\\', '*', '.']);
            if lower == "*" || lower == "\\" || (bare.len() <= 2 && bare.ends_with(':')) {
                Some("excludes a whole drive".into())
            } else if bare.len() > 2 && bare.ends_with(r":\users") {
                Some(r"excludes every user profile (\Users)".into())
            } else if bare
                .get(1..)
                .and_then(|r| r.strip_prefix(r":\users\"))
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('\\'))
            {
                Some("excludes a whole user profile".into())
            } else if bare.get(1..) == Some(r":\programdata") {
                Some(r"excludes the whole ProgramData folder".into())
            } else if writable_outside_programdata(&format!("{bare}\\")) {
                Some("excludes a user-writable folder".into())
            } else {
                None
            }
        }
        ExclusionKind::Extension => {
            let ext = lower.trim_start_matches('*').trim_start_matches('.');
            RISKY_EXTENSIONS
                .contains(&ext)
                .then(|| format!("excludes every .{ext} file (executable or script)"))
        }
        ExclusionKind::Process => {
            let exe = exe_name(&lower);
            if launcher_kind(&exe).is_some() {
                Some(format!(
                    "excludes {exe}.exe, an interpreter / proxy-execution binary"
                ))
            } else if writable_outside_programdata(&normalize_path(v)) {
                Some("excludes a process in a user-writable folder".into())
            } else {
                None
            }
        }
        ExclusionKind::IpAddress => None,
    }
}

/// Context for a Medium exclusion that sits in a vendor folder under ProgramData:
/// users can sometimes add files there, but excluding a product's own data folder is
/// what backup / EDR / database vendors document.
pub(crate) fn exclusion_value_note(kind: ExclusionKind, value: &str) -> Option<&'static str> {
    let norm = normalize_path(value);
    (matches!(kind, ExclusionKind::Path | ExclusionKind::Process)
        && exclusion_value_risk(kind, value).is_none()
        && is_programdata_vendor_folder(&norm))
    .then_some(
        "a vendor folder under ProgramData, which products commonly ask to exclude; \
         check that the vendor is installed and that the folder is not user-writable",
    )
}

/// Why an exclusion is dangerous (None = only "an exclusion exists").
fn exclusion_risk(e: &DefenderExclusion) -> Option<String> {
    exclusion_value_risk(e.kind, &e.value)
}

fn kind_label(k: ExclusionKind) -> &'static str {
    match k {
        ExclusionKind::Path => "path",
        ExclusionKind::Extension => "extension",
        ExclusionKind::Process => "process",
        ExclusionKind::IpAddress => "IP address",
    }
}

fn exclusion_finding(e: &DefenderExclusion, now: DateTime<Utc>) -> Finding {
    let risk = exclusion_risk(e);
    let severity = if risk.is_some() {
        Severity::High
    } else {
        Severity::Medium
    };
    let source = if e.policy {
        "Group Policy key"
    } else {
        "Defender preference key"
    };
    let reason = format!(
        "defender_exclusions: {} exclusion {:?} under {} ({source}){}; excluded items are \
         never scanned",
        kind_label(e.kind),
        e.value,
        e.key,
        risk.as_deref()
            .or(exclusion_value_note(e.kind, &e.value))
            .map(|r| format!(": {r}"))
            .unwrap_or_default()
    );
    let mut f = heuristic(
        severity,
        format!("Defender 排除項目（{}）：{}", kind_label(e.kind), e.value),
        "T1562.001",
        reason,
    );
    f.ts = e.last_write.unwrap_or(now);
    f.artifact = "registry".into();
    f.details = format!("{}\\{} ({})", e.key, e.value, kind_label(e.kind));
    f.details_client = Some(format!(
        "Microsoft Defender 被設定為不掃描「{}」。攻擊者常加入排除項目，讓惡意程式放在這裡不被偵測；\
         請確認這個排除項目是否由資訊人員為特定軟體設定，不是的話應移除並檢查該位置的檔案。",
        e.value
    ));
    f.entity.registry = Some(EntityRegistry {
        hive: "HKLM".into(),
        key: e.key.trim_start_matches(r"HKLM\").to_string(),
        value: e.value.clone(),
        data: String::new(),
        last_write: e.last_write,
    });
    f
}

fn policy_findings(p: &PostureRecord, now: DateTime<Utc>, out: &mut Vec<Finding>) {
    let dp = &p.defender_policy;
    for (val, name, key, what) in [
        (
            dp.disable_antispyware,
            "DisableAntiSpyware",
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "Microsoft Defender 被原則整個停用",
        ),
        (
            dp.disable_realtime_monitoring,
            "DisableRealtimeMonitoring",
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "Microsoft Defender 即時保護被原則關閉",
        ),
        (
            dp.disable_behavior_monitoring,
            "DisableBehaviorMonitoring",
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "Microsoft Defender 行為監控被原則關閉",
        ),
    ] {
        if val != Some(1) {
            continue;
        }
        let mut f = heuristic(
            Severity::High,
            format!("{what}（{name}=1）"),
            "T1562.001",
            format!("defender_policy.{name} = 1 under HKLM\\{key}: Defender protection turned off by policy"),
        );
        f.ts = now;
        f.artifact = "registry".into();
        f.details = format!(r"HKLM\{key}\{name} = 1");
        f.details_client = Some(format!(
            "{what}。攻擊者常先關掉防毒再執行惡意程式；請確認這是否為公司政策（例如改用其他防毒），\
             不是的話應立即恢復並全面掃描。"
        ));
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: key.into(),
            value: name.into(),
            data: "1".into(),
            last_write: None,
        });
        out.push(f);
    }
    if let Some(tp) = p.tamper_protection.filter(|v| *v != 5) {
        let mut f = heuristic(
            Severity::Medium,
            format!("Defender 防竄改保護未開啟（TamperProtection={tp}）"),
            "T1562.001",
            format!(
                "tamper_protection = {tp} (5 = on) at HKLM\\SOFTWARE\\Microsoft\\Windows \
                 Defender\\Features: Defender settings can be changed by any administrator \
                 or malware running as one; a posture weakness, not proof of tampering"
            ),
        );
        f.ts = now;
        f.artifact = "registry".into();
        f.details =
            format!(r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = {tp}");
        f.details_client = Some(
            "Microsoft Defender 的「防竄改保護」沒有開啟，惡意程式取得管理員權限後可以直接關閉防毒。\
             這是設定上的弱點，不代表已被入侵；建議開啟。"
                .into(),
        );
        out.push(f);
    }
}

fn task_finding(t: &TaskCacheEntry, now: DateTime<Utc>) -> Option<Finding> {
    let mut why = Vec::new();
    if !t.sd_present {
        why.push("task_cache.sd_present = false (SD value deleted: hidden from schtasks and Task Scheduler)");
    }
    if t.file_present == Some(false) {
        why.push("task_cache.file_present = false (no XML under System32\\Tasks)");
    }
    if why.is_empty() {
        return None;
    }
    let mut f = heuristic(
        Severity::High,
        format!("隱藏的排程工作：{}", t.path),
        "T1053.005",
        format!(
            "TaskCache\\Tree entry {} ({}){}: {}",
            t.path,
            t.key,
            t.id.as_deref()
                .map(|i| format!(" Id {i}"))
                .unwrap_or_default(),
            why.join("; ")
        ),
    );
    f.ts = t.last_write.unwrap_or(now);
    f.artifact = "registry".into();
    f.details = t.key.clone();
    f.details_client = Some(format!(
        "排程工作「{}」在登錄檔裡存在，但被刻意藏起來（工作排程器看不到它）。這是攻擊者讓惡意程式\
         定期執行又不被發現的手法（Tarrask）；請檢查這個工作執行的程式並移除。",
        t.path
    ));
    f.entity.registry = Some(EntityRegistry {
        hive: "HKLM".into(),
        key: t.key.trim_start_matches(r"HKLM\").to_string(),
        value: "Id".into(),
        data: t.id.clone().unwrap_or_default(),
        last_write: t.last_write,
    });
    Some(f)
}

fn accessibility_finding(a: &AccessibilityBinary, now: DateTime<Utc>) -> Option<Finding> {
    if !a.exists {
        return None;
    }
    let orig = a
        .original_filename
        .as_deref()
        .map(|o| o.trim().to_ascii_lowercase());
    let expected = EXPECTED_ORIGINAL_NAMES
        .iter()
        .find(|(n, _)| *n == a.name)
        .map(|(_, e)| *e)
        .unwrap_or(&[]);
    let is_shell = orig
        .as_deref()
        .is_some_and(|o| SHELL_ORIGINAL_NAMES.contains(&o));
    let mismatch = orig
        .as_deref()
        .is_some_and(|o| !expected.is_empty() && !expected.contains(&o));
    let unsigned = a.signed == Some(false);
    let mut why = Vec::new();
    if let (true, Some(o)) = (mismatch, a.original_filename.as_deref()) {
        why.push(format!(
            "original_filename = {o:?} (expected {})",
            expected.join(" / ")
        ));
    }
    if unsigned {
        why.push("signed = false".into());
    }
    if why.is_empty() {
        return None;
    }
    let severity = if is_shell || unsigned {
        Severity::High
    } else if a.signed == Some(true) {
        Severity::Low
    } else {
        Severity::Medium
    };
    let mut f = heuristic(
        severity,
        format!("協助工具程式被替換：{}", a.name),
        "T1546.008",
        format!(
            "accessibility binary {}: {}{}; it runs as SYSTEM from the logon screen",
            a.path,
            why.join(", "),
            a.sha256
                .as_deref()
                .map(|h| format!(", sha256 {h}"))
                .unwrap_or_default()
        ),
    );
    f.ts = a.last_write.unwrap_or(now);
    f.artifact = "file".into();
    f.details = format!(
        "{} OriginalFilename={:?} signed={:?} signer={:?}",
        a.path, a.original_filename, a.signed, a.signer
    );
    f.details_client = Some(if severity == Severity::High {
        format!(
            "Windows 的協助工具程式 {} 被換成別的程式。攻擊者用這招在登入畫面按快速鍵（例如連按 Shift）\
             就能不用密碼取得最高權限的命令列；請從乾淨的系統還原這個檔案，並檢查是否有遠端登入紀錄。",
            a.name
        )
    } else {
        // Signed (or signature unknown) and not a shell: a vendor accessibility tool or
        // an OEM build can carry another internal name. Worth a check, not a verdict.
        format!(
            "Windows 的協助工具程式 {} 的內部檔名與 Windows 內建版本不同。這可能是廠商或第三方的\
             協助工具取代了它，也可能是被換成別的程式（攻擊者可藉此在登入畫面不用密碼取得最高權限）；\
             請確認這個檔案的來源與簽章是否為已知軟體。",
            a.name
        )
    });
    f.entity.file = Some(EntityFile {
        path: a.path.clone(),
        sha256: a.sha256.clone(),
        mtime: a.last_write,
    });
    Some(f)
}

fn observation(now: DateTime<Utc>, title: String, details: String) -> Observation {
    let mut o = Observation::new(OBS_CATEGORY, title);
    o.ts = now;
    o.details = details;
    o.source_artifact = "posture".into();
    o
}

/// Logging gaps as (field, state, what is missing): `Some(false)` = off, `None` = unknown.
fn blind_spots(p: &PostureRecord) -> Vec<(&'static str, Option<bool>, &'static str)> {
    [
        (
            "audit_process_creation",
            p.audit_process_creation,
            "Security 4688 process creation is not audited",
        ),
        (
            "cmdline_in_4688",
            p.cmdline_in_4688,
            "Security 4688 events carry no command line",
        ),
        (
            "audit_logon",
            p.audit_logon,
            "Security 4624/4625 logons are not audited",
        ),
        (
            "audit_other_object_access",
            p.audit_other_object_access,
            "Security 4698 (scheduled task created) is not audited",
        ),
        (
            "audit_user_account_management",
            p.audit_user_account_management,
            "account creation/changes (4720/4722/4724/4726/4738) are not audited",
        ),
        (
            "audit_security_group_management",
            p.audit_security_group_management,
            "group membership changes (4728/4732/4756) are not audited",
        ),
        (
            "ps_scriptblock",
            p.ps_scriptblock,
            "PowerShell script block logging (4104) is off",
        ),
        (
            "sysmon_present",
            p.sysmon_present,
            "Sysmon is not installed (no Sysmon-based Sigma rule can fire)",
        ),
    ]
    .into_iter()
    .filter(|(_, v, _)| *v != Some(true))
    .collect()
}

impl Analyzer for DefenseHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    /// Runs after `heur_eventlog`: an exclusion still in the registry is the same
    /// exclusion a Defender 5007 event recorded being added. This analyzer's finding
    /// (the current state) absorbs those events (same-evidence rule, `dedup.rs`), so
    /// the analyst reads it once, with the time it was added as evidence.
    fn depends_on(&self) -> &[&str] {
        &[cairn_core::analyzers::EVENTLOG]
    }

    fn analyze(&self, records: &[Record], prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        for p in postures(records) {
            let now = p.collected_at.unwrap_or_else(Utc::now);
            for e in &p.defender_exclusions {
                let mut f = exclusion_finding(e, now);
                f.analyzer = Self::NAME.to_string();
                let key = crate::dedup::EvidenceKey::Exclusion {
                    kind: e.kind,
                    value: e.value.clone(),
                };
                out.extend(crate::dedup::resolve(f, &key, prior));
            }
            policy_findings(p, now, &mut out);
            out.extend(p.task_cache.iter().filter_map(|t| task_finding(t, now)));
            out.extend(
                p.accessibility_binaries
                    .iter()
                    .filter_map(|a| accessibility_finding(a, now)),
            );
        }
        Ok(crate::stamped(out, Self::NAME))
    }

    fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> {
        let mut out = Vec::new();
        for p in postures(records) {
            let now = p.collected_at.unwrap_or_else(Utc::now);
            for (field, state, what) in blind_spots(p) {
                let (title, details) = match state {
                    Some(_) => (
                        format!("記錄缺口：{what}"),
                        format!("{field} = false: {what}; detections that need it cannot fire"),
                    ),
                    None => (
                        format!("無法確認：{field}"),
                        format!(
                            "{field} could not be read (see manifest source errors); do not \
                             assume it is on"
                        ),
                    ),
                };
                out.push(observation(now, title, details));
            }
            for key in &p.exclusions_unreadable {
                out.push(observation(
                    now,
                    "無法讀取 Defender 排除清單".into(),
                    format!(
                        "{key} exists but could not be read: exclusions on this list are \
                         unknown, not absent"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn excl(kind: ExclusionKind, value: &str) -> DefenderExclusion {
        DefenderExclusion {
            kind,
            value: value.into(),
            policy: false,
            key: r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths".into(),
            last_write: None,
        }
    }

    fn run(p: PostureRecord) -> Vec<Finding> {
        DefenseHeuristic
            .analyze(&[Record::Posture(p)], &[])
            .unwrap()
    }

    fn sev_of(kind: ExclusionKind, v: &str) -> Severity {
        let f = run(PostureRecord {
            defender_exclusions: vec![excl(kind, v)],
            ..PostureRecord::default()
        });
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].mitre, vec!["T1562.001"]);
        assert_eq!(f[0].analyzer, DefenseHeuristic::NAME);
        f[0].severity
    }

    #[test]
    fn risky_exclusions_are_high_others_medium() {
        use ExclusionKind::*;
        assert_eq!(sev_of(Path, r"C:\"), Severity::High);
        assert_eq!(sev_of(Path, "D:"), Severity::High);
        assert_eq!(sev_of(Path, r"C:\Users"), Severity::High);
        assert_eq!(
            sev_of(Path, r"C:\Users\bob\AppData\Local\Temp"),
            Severity::High
        );
        assert_eq!(sev_of(Path, r"%APPDATA%\x"), Severity::High);
        assert_eq!(sev_of(Path, r"C:\ProgramData"), Severity::High);
        assert_eq!(sev_of(Path, r"C:\Program Files\Veeam"), Severity::Medium);
        assert_eq!(sev_of(Extension, ".ps1"), Severity::High);
        assert_eq!(sev_of(Extension, "exe"), Severity::High);
        assert_eq!(sev_of(Extension, "log"), Severity::Medium);
        assert_eq!(sev_of(Process, "powershell.exe"), Severity::High);
        assert_eq!(
            sev_of(Process, r"C:\Windows\System32\mshta.exe"),
            Severity::High
        );
        assert_eq!(
            sev_of(Process, r"C:\Users\bob\Downloads\x.exe"),
            Severity::High
        );
        assert_eq!(sev_of(Process, "sqlservr.exe"), Severity::Medium);
        assert_eq!(sev_of(IpAddress, "10.0.0.5"), Severity::Medium);
    }

    /// Regression: a vendor data folder under ProgramData (what Veeam, SQL Server and
    /// EDR products document as a required exclusion) was High on a clean image,
    /// because all of ProgramData counts as a drop zone. The ProgramData root, a whole
    /// profile and the real drop zones stay High.
    #[test]
    fn programdata_vendor_exclusion_is_medium_with_a_note() {
        use ExclusionKind::*;
        assert_eq!(
            sev_of(Path, r"C:\ProgramData\Veeam\Backup"),
            Severity::Medium
        );
        assert_eq!(sev_of(Path, r"%ProgramData%\Sophos\"), Severity::Medium);
        assert_eq!(
            sev_of(Process, r"C:\ProgramData\Vendor\agent.exe"),
            Severity::Medium
        );
        assert_eq!(sev_of(Path, r"C:\ProgramData\"), Severity::High);
        assert_eq!(sev_of(Path, "%ProgramData%"), Severity::High);
        assert_eq!(sev_of(Path, "%USERPROFILE%"), Severity::High);
        assert_eq!(sev_of(Path, r"C:\Users\bob"), Severity::High);
        assert_eq!(
            sev_of(Path, r"C:\ProgramData\x\..\..\Users\Public"),
            Severity::High
        );
        assert_eq!(sev_of(Path, r"C:\Windows\Temp"), Severity::High);
        let f = run(PostureRecord {
            defender_exclusions: vec![excl(Path, r"C:\ProgramData\Veeam\Backup")],
            ..PostureRecord::default()
        });
        assert!(
            f[0].reason.as_deref().unwrap().contains("vendor folder"),
            "{:?}",
            f[0].reason
        );
    }

    #[test]
    fn exclusion_reason_names_the_field_and_key() {
        let f = run(PostureRecord {
            defender_exclusions: vec![excl(ExclusionKind::Path, r"C:\")],
            ..PostureRecord::default()
        });
        let r = f[0].reason.as_deref().unwrap();
        assert!(
            r.contains("defender_exclusions") && r.contains(r"Exclusions\Paths"),
            "{r}"
        );
        assert!(r.contains("whole drive"), "{r}");
        assert!(f[0].details_client.is_some());
    }

    #[test]
    fn defender_disabled_by_policy_is_high_and_tamper_off_medium() {
        let mut p = PostureRecord::default();
        p.defender_policy.disable_antispyware = Some(1);
        p.defender_policy.disable_realtime_monitoring = Some(0);
        p.defender_policy.disable_behavior_monitoring = Some(1);
        p.tamper_protection = Some(4);
        let f = run(p);
        let highs: Vec<_> = f.iter().filter(|f| f.severity == Severity::High).collect();
        assert_eq!(highs.len(), 2, "{f:?}");
        assert!(highs[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("DisableAntiSpyware"));
        let tp: Vec<_> = f
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .collect();
        assert_eq!(tp.len(), 1);
        assert!(tp[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("tamper_protection = 4"));

        let on = PostureRecord {
            tamper_protection: Some(5),
            ..PostureRecord::default()
        };
        assert!(run(on).is_empty());
    }

    fn task(sd: bool, file: Option<bool>) -> TaskCacheEntry {
        TaskCacheEntry {
            path: r"\Microsoft\Windows\Update\Hidden".into(),
            key: r"HKLM\SOFTWARE\...\TaskCache\Tree\Microsoft\Windows\Update\Hidden".into(),
            id: Some("{0}".into()),
            sd_present: sd,
            file_present: file,
            last_write: None,
        }
    }

    #[test]
    fn tarrask_tasks_are_high() {
        let f = run(PostureRecord {
            task_cache: vec![
                task(true, Some(true)),
                task(false, Some(true)),
                task(true, Some(false)),
                task(true, None),
            ],
            ..PostureRecord::default()
        });
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f
            .iter()
            .all(|f| f.severity == Severity::High && f.mitre == vec!["T1053.005".to_string()]));
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("sd_present = false"));
        assert!(f[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("file_present = false"));
    }

    fn acc(name: &str, orig: Option<&str>, signed: Option<bool>) -> AccessibilityBinary {
        AccessibilityBinary {
            name: name.into(),
            path: format!(r"C:\Windows\System32\{name}"),
            exists: true,
            original_filename: orig.map(str::to_string),
            signed,
            signer: None,
            sha256: Some("aa".into()),
            last_write: None,
        }
    }

    fn acc_sev(name: &str, orig: Option<&str>, signed: Option<bool>) -> Option<Severity> {
        let f = run(PostureRecord {
            accessibility_binaries: vec![acc(name, orig, signed)],
            ..PostureRecord::default()
        });
        f.first().map(|f| {
            assert_eq!(f.mitre, vec!["T1546.008"]);
            f.severity
        })
    }

    #[test]
    fn sticky_keys_replacement() {
        // The classic: cmd.exe copied over sethc.exe (still Microsoft-signed).
        assert_eq!(
            acc_sev("sethc.exe", Some("Cmd.Exe"), Some(true)),
            Some(Severity::High)
        );
        assert_eq!(
            acc_sev("utilman.exe", Some("explorer.exe"), Some(true)),
            Some(Severity::High)
        );
        assert_eq!(
            acc_sev("osk.exe", Some("osk.exe"), Some(false)),
            Some(Severity::High)
        );
        assert_eq!(
            acc_sev("osk.exe", Some("evil.exe"), None),
            Some(Severity::Medium)
        );
        assert_eq!(
            acc_sev("osk.exe", Some("other.exe"), Some(true)),
            Some(Severity::Low)
        );
        // Only the High case tells the client the binary was replaced as an attack.
        for (orig, signed, replaced) in [
            (Some("cmd.exe"), Some(true), true),
            (Some("evil.exe"), None, false),
            (Some("other.exe"), Some(true), false),
        ] {
            let f = run(PostureRecord {
                accessibility_binaries: vec![acc("osk.exe", orig, signed)],
                ..PostureRecord::default()
            });
            let text = f[0].details_client.as_deref().unwrap();
            assert_eq!(
                text.contains("被換成別的程式。"),
                replaced,
                "{orig:?}: {text}"
            );
        }
        // In-box: no finding (including names that differ from the file name).
        assert_eq!(acc_sev("sethc.exe", Some("sethc.exe"), Some(true)), None);
        assert_eq!(
            acc_sev("utilman.exe", Some("utilman2.exe"), Some(true)),
            None
        );
        assert_eq!(acc_sev("sethc.exe", None, None), None);
        let mut missing = acc("sethc.exe", Some("cmd.exe"), Some(true));
        missing.exists = false;
        assert!(run(PostureRecord {
            accessibility_binaries: vec![missing],
            ..PostureRecord::default()
        })
        .is_empty());
    }

    #[test]
    fn blind_spots_and_unreadable_lists_are_observations() {
        let p = PostureRecord {
            audit_process_creation: Some(false),
            cmdline_in_4688: Some(true),
            audit_logon: Some(true),
            audit_other_object_access: Some(true),
            audit_user_account_management: Some(true),
            audit_security_group_management: Some(true),
            ps_scriptblock: None,
            sysmon_present: Some(true),
            exclusions_unreadable: vec![r"HKLM\...\Exclusions\Paths".into()],
            ..PostureRecord::default()
        };
        let obs = DefenseHeuristic.observe(&[Record::Posture(p)]).unwrap();
        assert_eq!(obs.len(), 3, "{obs:?}");
        assert!(obs.iter().all(|o| o.category == OBS_CATEGORY));
        assert!(obs[0].details.contains("audit_process_creation = false"));
        assert!(obs[1].details.contains("ps_scriptblock could not be read"));
        assert!(obs[2].details.contains("unknown, not absent"));
    }

    #[test]
    fn no_posture_record_no_output() {
        assert!(DefenseHeuristic.analyze(&[], &[]).unwrap().is_empty());
        assert!(DefenseHeuristic.observe(&[]).unwrap().is_empty());
    }
}
