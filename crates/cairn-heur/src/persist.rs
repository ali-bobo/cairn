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

    if let Some(path) = p.binary_path.as_deref() {
        if is_suspicious_path(path) {
            s.add(
                30,
                format!("binary in a suspicious path: {path}"),
                &["T1036"],
            );
        }
    }

    if let Some(lw) = p.last_write {
        if now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
            && now.signed_duration_since(lw) >= Duration::zero()
        {
            s.add(15, "recently created/modified (last 7 days)", &[]);
        }
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

    /// The startup mechanism scores its base (+10, T1547.001) and stacks path + recency —
    /// guards the startup arm (otherwise only run_key exercises the +10/T1547.001 path).
    #[test]
    fn startup_in_appdata_recent_scores() {
        let now = Utc::now();
        let p = rec(
            "startup",
            Some(r"C:\Users\a\AppData\Roaming\x.exe"),
            Some(now),
        );
        let s = score_persistence(&p, now);
        // startup 10 + suspicious path 30 + recent 15 = 55
        assert!(s.weight >= 50, "weight {}", s.weight);
        assert!(s.mitre.contains(&"T1547.001".to_string()));
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
