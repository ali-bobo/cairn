#![forbid(unsafe_code)]

use cairn_core::finding::{EvidenceItem, Finding, FindingSource};
use cairn_core::record::{ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// Fixed window width after a process's start_time within which USN/NetConn
/// activity is considered temporally adjacent (not causally proven).
const TEMPORAL_WINDOW_MINUTES: i64 = 5;

/// Cap on USN evidence items attached to a single Finding (IR-panels quota
/// pattern: newest-first, truncate, note original count — see html.rs USN_CAP).
const USN_EVIDENCE_CAP: usize = 200;

fn by_pid(records: &[Record]) -> HashMap<u32, &ProcessRecord> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::Process(p) => Some((p.pid, p)),
            _ => None,
        })
        .collect()
}

/// USN events whose ts falls within [start_time, start_time + window].
/// Linear scan — UsnEventRecord has no pid field (Windows USN journal design
/// limitation), so no index can narrow this further than the time bound itself.
fn usn_events_in_window<'a>(
    records: &'a [Record],
    start_time: DateTime<Utc>,
    window: Duration,
) -> Vec<&'a cairn_core::record::UsnEventRecord> {
    let window_end = start_time + window;
    records
        .iter()
        .filter_map(|r| match r {
            Record::UsnEvent(u) if u.ts >= start_time && u.ts <= window_end => Some(u),
            _ => None,
        })
        .collect()
}

/// NetConn records owned by the given pid (existence, not temporal — NetConnRecord
/// has no timestamp field, see spec §1 API limitation).
fn netconns_for_pid<'a>(
    records: &'a [Record],
    pid: u32,
) -> Vec<&'a cairn_core::record::NetConnRecord> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::NetConn(c) if c.pid == Some(pid) => Some(c),
            _ => None,
        })
        .collect()
}

pub struct TemporalWindowCorrelator;

impl Analyzer for TemporalWindowCorrelator {
    fn name(&self) -> &str {
        "heur_temporal"
    }

    fn depends_on(&self) -> &[&str] {
        &["heur_persist", "heur_parentchild"]
    }

    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let procs = by_pid(records);
        let mut out = Vec::new();

        for pf in prior_findings {
            let Some(ep) = pf.entity.process.as_ref() else {
                continue;
            };
            let Some(pr) = procs.get(&ep.pid) else {
                continue;
            };
            let Some(start_time) = pr.start_time else {
                continue;
            };

            let window = Duration::minutes(TEMPORAL_WINDOW_MINUTES);
            let mut usn_hits = usn_events_in_window(records, start_time, window);
            let usn_total = usn_hits.len();
            usn_hits.sort_by_key(|u| std::cmp::Reverse(u.ts));
            usn_hits.truncate(USN_EVIDENCE_CAP);

            let netconn_hits = netconns_for_pid(records, ep.pid);

            if usn_hits.is_empty() && netconn_hits.is_empty() {
                continue;
            }

            let severity = crate::score::escalate(pf.severity);
            let mut f = Finding::new(
                severity,
                format!("時間窗口關聯: {}", ep.image),
                FindingSource::Heuristic,
            );
            f.ts = start_time;
            f.artifact = "temporal_window".into();
            f.mitre = pf.mitre.clone();
            f.entity.process = Some(ep.clone());
            f.reason = Some(format!(
                "corroborated by temporal-window evidence — escalated (source finding: {})",
                pf.title
            ));

            let mut evidence: Vec<EvidenceItem> = usn_hits
                .iter()
                .map(|u| EvidenceItem {
                    artifact: "usn_temporal".into(),
                    path: Some(u.path.clone()),
                    ts: Some(u.ts),
                    detail: format!(
                        "時間窗口內的檔案事件（非確認因果）：{} {} 於 {}，行程建立於 {}",
                        u.reason, u.path, u.ts, start_time
                    ),
                })
                .collect();

            if usn_total > USN_EVIDENCE_CAP {
                evidence.push(EvidenceItem {
                    artifact: "usn_temporal_summary".into(),
                    path: None,
                    ts: None,
                    detail: format!(
                        "時間窗口內共 {usn_total} 筆檔案事件，僅附加前 {USN_EVIDENCE_CAP} 筆"
                    ),
                });
            }

            for c in &netconn_hits {
                evidence.push(EvidenceItem {
                    artifact: "netconn_temporal".into(),
                    path: None,
                    ts: None,
                    detail: format!(
                        "同行程目前有網路連線（存在性關聯，非時序因果，NetConn 快照無時間資訊）：{}:{} state={}",
                        c.raddr.clone().unwrap_or_default(),
                        c.rport.map(|p| p.to_string()).unwrap_or_default(),
                        c.state.clone().unwrap_or_default()
                    ),
                });
            }

            f.evidence = evidence;
            out.push(f);
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::{Entity, EntityProcess, Severity};
    use cairn_core::record::{NetConnRecord, ProcessRecord, UsnEventRecord};

    fn process_with_start_time(pid: u32, image: &str, start_time: Option<DateTime<Utc>>) -> Record {
        Record::Process(ProcessRecord {
            pid,
            ppid: 1,
            image: image.to_string(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time,
        })
    }

    fn prior_finding_with_process(pid: u32, image: &str) -> Finding {
        let mut f = Finding::new(Severity::Medium, "test persist finding", FindingSource::Heuristic);
        f.entity = Entity {
            process: Some(EntityProcess {
                pid,
                ppid: 1,
                image: image.to_string(),
                cmdline: String::new(),
                signed: None,
                integrity: None,
            }),
            ..Entity::default()
        };
        f
    }

    fn usn_event(ts: DateTime<Utc>, path: &str) -> Record {
        Record::UsnEvent(UsnEventRecord {
            ts,
            path: path.to_string(),
            reason: "create".to_string(),
            mft_ref: 1,
        })
    }

    #[test]
    fn depends_on_returns_persist_and_parentchild() {
        assert_eq!(
            TemporalWindowCorrelator.depends_on(),
            &["heur_persist", "heur_parentchild"]
        );
    }

    #[test]
    fn usn_event_within_window_attaches_as_evidence_and_escalates() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            usn_event(start + Duration::minutes(2), r"C:\Temp\dropped.exe"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High, "Medium -> High via escalate()");
        assert!(findings[0].evidence[0].detail.contains("非確認因果"));
    }

    #[test]
    fn usn_event_outside_window_not_attached() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            usn_event(start + Duration::minutes(10), r"C:\Temp\dropped.exe"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty(), "event 10 minutes after start (window=5min) must not attach");
    }

    #[test]
    fn usn_event_in_different_directory_still_attaches() {
        // §4.3 regression: USN correlation is NOT path-restricted (attackers
        // commonly write payloads to a different directory than the dropper).
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\Users\a\dropper.exe", Some(start)),
            usn_event(start + Duration::seconds(30), r"C:\Windows\Temp\payload.dll"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\Users\a\dropper.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1, "cross-directory USN event must still attach");
    }

    #[test]
    fn missing_start_time_skips_temporal_expansion() {
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", None),
            usn_event(Utc::now(), r"C:\Temp\dropped.exe"),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty(), "start_time=None must skip, not panic or guess");
    }

    #[test]
    fn missing_entity_process_on_prior_finding_skips() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            usn_event(start + Duration::seconds(30), r"C:\Temp\dropped.exe"),
        ];
        // No entity.process on this prior finding (e.g. persist Finding that's
        // file/registry-backed with no S9 execution hit).
        let mut pf = Finding::new(Severity::Medium, "no process entity", FindingSource::Heuristic);
        pf.entity = Entity::default();
        let findings = TemporalWindowCorrelator.analyze(&records, &[pf]).unwrap();
        assert!(findings.is_empty(), "Finding without entity.process must be skipped");
    }

    #[test]
    fn over_200_usn_events_are_capped_with_summary_note() {
        let start = Utc::now();
        let mut records = vec![process_with_start_time(100, r"C:\evil.exe", Some(start))];
        for i in 0..250 {
            records.push(usn_event(
                start + Duration::seconds(i),
                &format!(r"C:\Temp\file{i}.tmp"),
            ));
        }
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1);
        let usn_evidence_count = findings[0]
            .evidence
            .iter()
            .filter(|e| e.artifact == "usn_temporal")
            .count();
        assert_eq!(usn_evidence_count, 200, "must cap at USN_EVIDENCE_CAP");
        assert!(
            findings[0]
                .evidence
                .iter()
                .any(|e| e.artifact == "usn_temporal_summary" && e.detail.contains("250")),
            "must note the original total count when truncated"
        );
    }

    #[test]
    fn same_pid_netconn_attaches_as_existence_evidence() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            Record::NetConn(NetConnRecord {
                proto: "tcp".to_string(),
                laddr: "10.0.0.5".to_string(),
                lport: 51000,
                raddr: Some("203.0.113.5".to_string()),
                rport: Some(4444),
                state: Some("established".to_string()),
                pid: Some(100),
            }),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|e| e.artifact == "netconn_temporal" && e.detail.contains("存在性")));
    }

    #[test]
    fn different_pid_netconn_not_attached() {
        let start = Utc::now();
        let records = vec![
            process_with_start_time(100, r"C:\evil.exe", Some(start)),
            Record::NetConn(NetConnRecord {
                proto: "tcp".to_string(),
                laddr: "10.0.0.5".to_string(),
                lport: 51000,
                raddr: Some("203.0.113.5".to_string()),
                rport: Some(4444),
                state: Some("established".to_string()),
                pid: Some(999),
            }),
        ];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty(), "netconn owned by a different pid must not attach");
    }

    #[test]
    fn no_usn_and_no_netconn_produces_no_finding() {
        let start = Utc::now();
        let records = vec![process_with_start_time(100, r"C:\evil.exe", Some(start))];
        let prior = vec![prior_finding_with_process(100, r"C:\evil.exe")];
        let findings = TemporalWindowCorrelator.analyze(&records, &prior).unwrap();
        assert!(findings.is_empty());
    }
}
