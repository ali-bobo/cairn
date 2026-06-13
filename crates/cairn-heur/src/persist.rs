//! heur_persist (FR9 ranking, SRS §10): rank persistence records by mechanism stealth +
//! suspicious binary path + recent LastWrite. Pure scoring (Analyzer impl is Task 3).
//! `signed` is not yet available (S2-D); weights compensate so malicious persistence still
//! surfaces without it.
// Task 2: pure scoring only; Task 3 adds the Analyzer that consumes score_persistence.
#![allow(dead_code)]
use crate::score::{is_suspicious_path, Score};
use cairn_core::record::PersistenceRecord;
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
}
