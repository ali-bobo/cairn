//! heur_timestomp (SRS §10, ATT&CK T1070.006): flag files whose $STANDARD_INFORMATION
//! (SI) timestamps are directionally earlier than their $FILE_NAME (FN) timestamps
//! beyond a threshold — the classic timestomp signature (`SetFileTime` backdates SI;
//! FN is kernel-only and stays at the real, later time). Pure logic over
//! `Record::FileMeta` (S2-N); touches no host state. Every Finding carries a `reason`
//! (golden rule 6) and the T1070.006 tag.
//!
//! Severity is MAGNITUDE-BANDED on the max fired delta — it is NOT additive scoring,
//! so it deliberately does NOT use `score.rs::severity_for` (a weight→severity map).
use cairn_core::record::FileMetaRecord;
use cairn_core::Severity;
use chrono::{DateTime, Duration, Utc};

/// One axis that fired the directional-delta test, kept for the reason string + entity.
#[derive(Debug, Clone, PartialEq)]
pub struct AxisHit {
    /// "btime" or "mtime".
    pub axis: &'static str,
    pub si: DateTime<Utc>,
    pub fn_: DateTime<Utc>,
    pub delta: Duration,
}

/// The outcome of evaluating one file: the axes that fired and the max delta.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestompHit {
    pub hits: Vec<AxisHit>,
    pub max_delta: Duration,
}

/// Evaluate one axis: returns a hit only when BOTH sides are Some, SI is earlier
/// than FN (delta = FN − SI > 0), AND delta exceeds `threshold`. None otherwise
/// (missing data → no guess; SI≥FN → legit direction; sub-threshold → legit noise).
fn eval_axis(
    axis: &'static str,
    si: Option<DateTime<Utc>>,
    fn_: Option<DateTime<Utc>>,
    threshold: Duration,
) -> Option<AxisHit> {
    let (si, fn_) = (si?, fn_?);
    let delta = fn_ - si; // positive == SI earlier than FN == backdating direction
    if delta > threshold {
        Some(AxisHit {
            axis,
            si,
            fn_,
            delta,
        })
    } else {
        None
    }
}

/// Detect timestomp on one file. Evaluates the btime and mtime axes independently;
/// returns Some when either fires, carrying every fired axis and the max delta.
pub fn detect_timestomp(meta: &FileMetaRecord, threshold: Duration) -> Option<TimestompHit> {
    let mut hits = Vec::new();
    if let Some(h) = eval_axis("btime", meta.si_btime, meta.fn_btime, threshold) {
        hits.push(h);
    }
    if let Some(h) = eval_axis("mtime", meta.si_mtime, meta.fn_mtime, threshold) {
        hits.push(h);
    }
    if hits.is_empty() {
        return None;
    }
    let max_delta = hits.iter().map(|h| h.delta).max().expect("non-empty");
    Some(TimestompHit { hits, max_delta })
}

/// Map the max fired delta to a Severity. A fired hit always has delta > threshold
/// (≥ 24h by default), so this never returns below Medium.
pub fn timestomp_severity(max_delta: Duration) -> Severity {
    if max_delta > Duration::days(365) {
        Severity::Critical
    } else if max_delta > Duration::days(30) {
        Severity::High
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A FileMetaRecord builder defaulting all four times to None.
    fn meta(
        si_btime: Option<DateTime<Utc>>,
        fn_btime: Option<DateTime<Utc>>,
        si_mtime: Option<DateTime<Utc>>,
        fn_mtime: Option<DateTime<Utc>>,
    ) -> FileMetaRecord {
        FileMetaRecord {
            path: r"C:\Users\a\evil.exe".into(),
            size: 0,
            sha256: None,
            si_btime,
            si_mtime,
            fn_btime,
            fn_mtime,
            zone_identifier: None,
        }
    }

    fn thresh() -> Duration {
        Duration::hours(24)
    }

    #[test]
    fn si_earlier_than_fn_btime_beyond_threshold_fires() {
        // SI.btime backdated ~2 years before FN.btime → fires, Critical.
        let m = meta(
            Some(t("2011-01-01T00:00:00Z")),
            Some(t("2013-01-05T18:15:00Z")),
            None,
            None,
        );
        let hit = detect_timestomp(&m, thresh()).expect("should fire");
        assert_eq!(hit.hits.len(), 1);
        assert_eq!(hit.hits[0].axis, "btime");
        assert_eq!(timestomp_severity(hit.max_delta), Severity::Critical);
    }

    #[test]
    fn mtime_axis_independently_fires() {
        // btime aligned (no hit), only mtime backdated → fires on mtime alone.
        let aligned = t("2024-06-01T00:00:00Z");
        let m = meta(
            Some(aligned),
            Some(aligned),
            Some(t("2020-01-01T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
        );
        let hit = detect_timestomp(&m, thresh()).expect("should fire on mtime");
        assert_eq!(hit.hits.len(), 1);
        assert_eq!(hit.hits[0].axis, "mtime");
    }

    #[test]
    fn legit_si_after_fn_does_not_fire() {
        // SI later than FN (unzip/copy/install direction) → delta negative → no fire.
        let m = meta(
            Some(t("2024-06-02T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
            None,
            None,
        );
        assert_eq!(detect_timestomp(&m, thresh()), None);
    }

    #[test]
    fn delta_within_threshold_does_not_fire() {
        // 2h drift (< 24h) → legit noise → no fire.
        let m = meta(
            Some(t("2024-06-01T00:00:00Z")),
            Some(t("2024-06-01T02:00:00Z")),
            None,
            None,
        );
        assert_eq!(detect_timestomp(&m, thresh()), None);
    }

    #[test]
    fn none_timestamps_do_not_fire() {
        // any axis with a None side contributes nothing; all-None → None (no guess).
        let m = meta(Some(t("2011-01-01T00:00:00Z")), None, None, None);
        assert_eq!(detect_timestomp(&m, thresh()), None);
        let empty = meta(None, None, None, None);
        assert_eq!(detect_timestomp(&empty, thresh()), None);
    }

    #[test]
    fn equal_si_fn_does_not_fire() {
        let same = t("2024-06-01T00:00:00Z");
        let m = meta(Some(same), Some(same), Some(same), Some(same));
        assert_eq!(detect_timestomp(&m, thresh()), None);
    }

    #[test]
    fn severity_bands() {
        // just over each edge: 25h → Medium, 31d → High, 366d → Critical.
        assert_eq!(timestomp_severity(Duration::hours(25)), Severity::Medium);
        assert_eq!(timestomp_severity(Duration::days(31)), Severity::High);
        assert_eq!(timestomp_severity(Duration::days(366)), Severity::Critical);
        // band edges themselves: exactly 30d is NOT > 30d → Medium; exactly 365d → High.
        assert_eq!(timestomp_severity(Duration::days(30)), Severity::Medium);
        assert_eq!(timestomp_severity(Duration::days(365)), Severity::High);
    }

    #[test]
    fn both_axes_fire_max_delta_drives_severity() {
        // btime delta ~2d (Medium-band magnitude), mtime delta ~2y (Critical) →
        // both recorded, severity from the MAX (mtime).
        let m = meta(
            Some(t("2024-05-30T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
            Some(t("2022-06-01T00:00:00Z")),
            Some(t("2024-06-01T00:00:00Z")),
        );
        let hit = detect_timestomp(&m, thresh()).expect("both axes fire");
        assert_eq!(hit.hits.len(), 2);
        assert_eq!(timestomp_severity(hit.max_delta), Severity::Critical);
    }
}
