//! heur_persist (FR9 ranking, SRS §10): rank persistence records by mechanism stealth +
//! suspicious binary path + recent LastWrite. Emits a Finding per record that clears the
//! noise floor (weight >= 15). See score.rs for severity thresholds.
use crate::score::{is_suspicious_path, severity_for, Score};
use cairn_core::finding::{EntityFile, EntityRegistry};
use cairn_core::record::{PersistenceRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
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
        "service" => s.add(20, "service autostart persistence", &["T1543.003"]),
        "run_key" => s.add(10, "Run/RunOnce key persistence", &["T1547.001"]),
        "startup" => s.add(10, "Startup folder persistence", &["T1547.001"]),
        _ => {}
    }

    // Weight from the mechanism alone, captured before path/recency so the unsigned
    // amplifier can tell whether ANOTHER signal (path or recency) fired.
    let mechanism_weight = s.weight;

    // Suspicious binary path — but NOT for the startup mechanism: the Startup folder is
    // itself the canonical persistence location, so its own path is not a suspicion
    // signal (the mechanism base weight already accounts for it). Other mechanisms point
    // at an arbitrary binary path, where Temp/AppData/etc. IS suspicious.
    if p.mechanism != "startup" {
        if let Some(path) = p.binary_path.as_deref() {
            if is_suspicious_path(path) {
                s.add(
                    30,
                    format!("binary in a suspicious path: {path}"),
                    &["T1036"],
                );
            }
        }
    }

    if let Some(lw) = p.last_write {
        if now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
            && now.signed_duration_since(lw) >= Duration::zero()
        {
            s.add(15, "recently created/modified (last 7 days)", &[]);
        }
    }

    // Unsigned amplifier: an unsigned binary is a signal only when ANOTHER suspicion is
    // already present (a suspicious path or a recent write added weight beyond the mechanism
    // base). Many legitimate tools are unsigned in normal locations — penalizing that alone
    // floods false positives. We never penalize what we could not verify (None) nor what is
    // trusted (Some(true)). `signed` is backfilled by the persist collector via WinVerifyTrust.
    let another_signal_fired = s.weight > mechanism_weight;
    if p.signed == Some(false) && another_signal_fired {
        s.add(20, "binary is unsigned (amplifies the above)", &["T1036"]);
    }

    s
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
            f.details = format!(
                "mechanism={} location={} command={}",
                p.mechanism,
                p.location,
                p.command.as_deref().unwrap_or("-")
            );
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
        assert_eq!(s.weight, 60, "run_key 10 + path 30 + unsigned 20"); // weight {}
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

    /// Unsigned + recent (no suspicious path): recency is the other signal, amplifier fires.
    #[test]
    fn unsigned_amplifies_recency() {
        let now = Utc::now();
        let p = rec_signed(
            "service",
            Some(r"C:\Windows\System32\svc.exe"),
            Some(now),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 55, "service 20 + recent 15 + unsigned 20");
        assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
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
}
