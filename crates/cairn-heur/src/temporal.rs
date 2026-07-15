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
