//! heur_timestomp (SRS §10, ATT&CK T1070.006): flag files whose $STANDARD_INFORMATION
//! (SI) timestamps are directionally earlier than their $FILE_NAME (FN) timestamps
//! beyond a threshold — the classic timestomp signature (`SetFileTime` backdates SI;
//! FN is kernel-only and stays at the real, later time). Pure logic over
//! `Record::FileMeta` (S2-N); touches no host state. Every Finding carries a `reason`
//! (golden rule 6) and the T1070.006 tag.
//!
//! Severity is MAGNITUDE-BANDED on the max fired delta — it is NOT additive scoring,
//! so it deliberately does NOT use `score.rs::severity_for` (a weight→severity map).
use cairn_core::finding::EntityFile;
use cairn_core::record::{FileMetaRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result, Severity};
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
    // positive == SI earlier than FN == backdating direction. Cannot overflow: both
    // times come from filetime_to_utc (S2-N), which clamps to chrono's representable range.
    let delta = fn_ - si;
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
    let max_delta = hits
        .iter()
        .map(|h| h.delta)
        .max()
        .unwrap_or_else(|| unreachable!("hits is non-empty — checked above"));
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

/// Analyzer: flags timestomped files from the FileMeta stream. Holds the threshold
/// (read from `Config.timestomp_threshold_hours` when the analyzer vec is built).
pub struct TimestompHeuristic {
    threshold: Duration,
}

impl TimestompHeuristic {
    pub fn new(threshold: Duration) -> Self {
        TimestompHeuristic { threshold }
    }
}

impl Analyzer for TimestompHeuristic {
    fn name(&self) -> &str {
        "heur_timestomp"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        for r in records {
            let Record::FileMeta(m) = r else { continue };
            let Some(hit) = detect_timestomp(m, self.threshold) else {
                continue;
            };
            let severity = timestomp_severity(hit.max_delta);

            let mut f = Finding::new(
                severity,
                "Timestomp: SI timestamps backdated vs $FILE_NAME",
                FindingSource::Heuristic,
            );
            f.reason = Some(reason_for(&hit, &m.path));
            f.mitre = vec!["T1070.006".to_string()];
            f.artifact = "file_meta".into();
            f.details = format!("path={} {}", m.path, axes_detail(&hit));
            // Anchor the finding at the real creation time (FN.btime) when known.
            // A fired hit always has both sides Some on at least one axis (eval_axis
            // requires it), so fn_btime OR fn_mtime is Some here — the now() fallback
            // is unreachable, present only to keep ts total.
            f.ts = m.fn_btime.or(m.fn_mtime).unwrap_or_else(Utc::now);
            f.entity = Entity {
                file: Some(EntityFile {
                    path: m.path.clone(),
                    sha256: m.sha256.clone(),
                    // Generic mtime = SI mtime ON PURPOSE: it surfaces the attacker's
                    // backdated value in the generic timeline field; the real value is
                    // preserved in fn_mtime below. Do not "fix" this to fn_mtime.
                    mtime: m.si_mtime,
                    si_btime: m.si_btime,
                    fn_btime: m.fn_btime,
                    si_mtime: m.si_mtime,
                    fn_mtime: m.fn_mtime,
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        Ok(out)
    }
}

/// Human-readable explanation (golden rule 6): names each fired axis and its delta.
fn reason_for(hit: &TimestompHit, path: &str) -> String {
    let parts: Vec<String> = hit
        .hits
        .iter()
        .map(|h| {
            format!(
                "SI.{} {} is earlier than FN.{} {} by {}",
                h.axis,
                h.si.to_rfc3339(),
                h.axis,
                h.fn_.to_rfc3339(),
                humanize(h.delta),
            )
        })
        .collect();
    format!("{} ({})", parts.join("; "), path)
}

/// Compact technical axis listing for `details`.
fn axes_detail(hit: &TimestompHit) -> String {
    hit.hits
        .iter()
        .map(|h| format!("{}_delta={}", h.axis, humanize(h.delta)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render a Duration as a coarse human string (days when ≥ 1 day, else hours).
fn humanize(d: Duration) -> String {
    let days = d.num_days();
    if days >= 1 {
        format!("{days}d")
    } else {
        format!("{}h", d.num_hours())
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

    #[test]
    fn delta_exactly_equal_to_threshold_does_not_fire() {
        // strict `>`: a delta of EXACTLY the threshold (24h) must NOT fire.
        let m = meta(
            Some(t("2024-06-01T00:00:00Z")),
            Some(t("2024-06-02T00:00:00Z")), // exactly +24h == threshold
            None,
            None,
        );
        assert_eq!(detect_timestomp(&m, thresh()), None);
    }

    #[test]
    fn analyzer_emits_finding_with_four_axis_entity() {
        use cairn_core::record::Record;
        use cairn_core::traits::Analyzer;
        // one stomped file (SI.btime 2y before FN.btime, SI.mtime 2y before FN.mtime)
        // and one clean file → exactly one Finding, carrying all four times + T1070.006.
        let stomped = Record::FileMeta(meta(
            Some(t("2011-01-01T00:00:00Z")),
            Some(t("2013-01-05T18:15:00Z")),
            Some(t("2011-01-01T00:00:00Z")),
            Some(t("2013-01-05T18:15:00Z")),
        ));
        let clean_t = t("2024-06-01T00:00:00Z");
        let clean = Record::FileMeta(meta(
            Some(clean_t),
            Some(clean_t),
            Some(clean_t),
            Some(clean_t),
        ));

        let h = TimestompHeuristic::new(Duration::hours(24));
        let findings = h.analyze(&[stomped, clean]).expect("analyze");

        assert_eq!(findings.len(), 1, "only the stomped file fires");
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some(), "golden rule 6: reason required");
        assert!(f.mitre.contains(&"T1070.006".to_string()));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.artifact, "file_meta");
        let ef = f.entity.file.as_ref().expect("file entity");
        assert!(ef.si_btime.is_some() && ef.fn_btime.is_some());
        assert!(ef.si_mtime.is_some() && ef.fn_mtime.is_some());
        assert_eq!(ef.path, r"C:\Users\a\evil.exe");
    }

    #[test]
    fn analyzer_yields_nothing_on_empty_stream() {
        use cairn_core::traits::Analyzer;
        // an empty stream yields zero findings (no crash).
        let h = TimestompHeuristic::new(Duration::hours(24));
        assert!(h.analyze(&[]).unwrap().is_empty());
    }

    #[test]
    fn analyzer_skips_non_filemeta_records() {
        // A non-FileMeta record must be silently skipped (no panic, no finding).
        use cairn_core::traits::Analyzer;
        let nc = Record::NetConn(cairn_core::record::NetConnRecord {
            proto: "tcp".into(),
            laddr: "127.0.0.1".into(),
            lport: 0,
            raddr: None,
            rport: None,
            state: Some("LISTEN".into()),
            pid: None,
        });
        let h = TimestompHeuristic::new(Duration::hours(24));
        assert!(h.analyze(&[nc]).unwrap().is_empty());
    }
}
