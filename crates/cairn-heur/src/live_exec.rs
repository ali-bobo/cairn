//! heur_live_exec (docs/REMAINING-WORK.md segment 5): a live process with no
//! execution-artifact history across prefetch/amcache/shimcache (signal A), or a
//! live process whose earliest execution-artifact record is both recent (≤30 days)
//! and unsigned (signal B). Independent of every other analyzer — depends_on()
//! returns &[].
use crate::score::{build_cross_index, join_key, severity_for, Score};
use cairn_core::finding::EntityProcess;
use cairn_core::record::{ExecutionRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use chrono::{Duration, Utc};

/// Signal B's recency window: an execution artifact whose earliest first_run is
/// within this many days of "now" counts as "recently first seen". Fixed module
/// constant (no Config entry) — mirrors persist.rs::RECENT_DAYS; nobody has asked
/// to tune this yet (YAGNI).
const RECENT_DAYS: i64 = 30;

/// Weight for signal A (no execution artifact in any of prefetch/amcache/shimcache).
/// Chosen to land in the High band (50..=69) on its own — see score.rs::severity_for.
const SIGNAL_A_WEIGHT: u32 = 55;

/// Weight for signal B (recent first-seen + unsigned). Same High-band target as
/// signal A; the two signals are mutually exclusive (see score_process doc comment)
/// so there is no double-counting to guard against.
const SIGNAL_B_WEIGHT: u32 = 55;

/// Score one live process against the three-source execution-artifact index.
/// Signal A (no artifact anywhere) and signal B (recent + unsigned) are mutually
/// exclusive by construction: A requires zero matches across all three sources; B
/// requires at least one match. See the spec's "Signal互斥" section.
fn score_process(p: &ProcessRecord, idx: &crate::score::CrossIndex<'_>, now: chrono::DateTime<Utc>) -> Score {
    let mut s = Score::default();
    let key = join_key(&p.image);
    let (hits, _degraded) = idx.lookup_exec(&key);

    if hits.is_empty() {
        s.add(
            SIGNAL_A_WEIGHT,
            format!(
                "process {} is running but has no execution-artifact record in \
                 prefetch, amcache, or shimcache — does not by itself prove the \
                 binary never ran (each source has known coverage limits: prefetch \
                 retains only the ~1024 most recent entries and is disabled by \
                 default on Windows Server; amcache/shimcache have their own \
                 retention limits and clearing cycles)",
                p.image
            ),
            &[],
        );
        return s;
    }

    // Signal B: earliest first_run across all matched sources, if any carry one.
    let earliest = hits.iter().filter_map(|e| e.first_run).min();
    if let Some(first_run) = earliest {
        let age = now.signed_duration_since(first_run);
        let recent = age >= Duration::zero() && age <= Duration::days(RECENT_DAYS);
        if recent && p.signed == Some(false) {
            let amcache_involved = hits
                .iter()
                .any(|e| e.source == "amcache" && e.first_run == Some(first_run));
            let mut reason = format!(
                "process {} is unsigned and its earliest execution-artifact record \
                 ({}) is only {} day(s) old",
                p.image,
                first_run.format("%Y-%m-%dT%H:%M:%SZ"),
                age.num_days()
            );
            if amcache_involved {
                reason.push_str(
                    "; note: amcache's first_run is a registry LastWrite \
                     approximation, not a precise execution timestamp",
                );
            }
            s.add(SIGNAL_B_WEIGHT, reason, &[]);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(image: &str, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 100,
            ppid: 4,
            image: image.into(),
            cmdline: String::new(),
            signed,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        }
    }

    fn exec_rec(source: &str, path: &str, first_run: Option<chrono::DateTime<Utc>>) -> ExecutionRecord {
        ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: None,
        }
    }

    /// Signal A: a live process with zero matches across prefetch/amcache/shimcache
    /// scores SIGNAL_A_WEIGHT (High band).
    #[test]
    fn signal_a_fires_when_no_execution_artifact_exists() {
        let p = proc(r"C:\Users\a\AppData\Local\Temp\ghost.exe", None);
        let records = vec![Record::Process(p.clone())];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, Utc::now());
        assert_eq!(s.weight, SIGNAL_A_WEIGHT);
        assert!(s.reasons.iter().any(|r| r.contains("prefetch")
            && r.contains("amcache")
            && r.contains("shimcache")));
    }

    /// Signal A must NOT fire when any one of the three sources has a match, even
    /// if that record carries no first_run (shimcache's normal case).
    #[test]
    fn signal_a_does_not_fire_when_shimcache_alone_has_a_match() {
        let p = proc(r"C:\Windows\System32\notepad.exe", None);
        let records = vec![
            Record::Process(p.clone()),
            Record::Execution(exec_rec(
                "shimcache",
                r"C:\Windows\System32\notepad.exe",
                None,
            )),
        ];
        let idx = build_cross_index(&records);
        let s = score_process(&p, &idx, Utc::now());
        assert_eq!(s.weight, 0, "any source match suppresses signal A");
    }
}
