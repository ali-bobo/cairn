#![forbid(unsafe_code)]

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

fn extract_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// A single parsed logon attempt (4624 success or 4625 failure).
#[derive(Debug, Clone)]
struct LogonAttempt {
    ts: DateTime<Utc>,
    target_user: String,
    /// IpAddress if present and not "-"; else WorkstationName if present and not "-";
    /// else "-" (both missing — attempt is still counted but cannot be grouped by
    /// source, so it will only ever land in a singleton group and never trigger).
    source: String,
    success: bool,
}

fn parse_logon_attempt(ev: &EventRecord) -> Option<LogonAttempt> {
    if ev.channel != "Security" {
        return None;
    }
    let success = match ev.event_id {
        4624 => true,
        4625 => false,
        _ => return None,
    };
    let d = &ev.data;
    let target_user = extract_str(d, "TargetUserName");
    let ip = extract_str(d, "IpAddress");
    let source = if ip != "-" {
        ip
    } else {
        extract_str(d, "WorkstationName")
    };
    Some(LogonAttempt {
        ts: ev.ts,
        target_user,
        source,
        success,
    })
}

/// Bruteforce group key: (TargetUserName, source). Groups repeated failures against
/// the same account from the same origin.
type BruteforceKey = (String, String);

/// Spraying group key: source only. Groups distinct-account attempts from one origin.
type SprayingKey = String;

fn group_by_bruteforce_key(attempts: &[LogonAttempt]) -> HashMap<BruteforceKey, Vec<&LogonAttempt>> {
    let mut groups: HashMap<BruteforceKey, Vec<&LogonAttempt>> = HashMap::new();
    for a in attempts {
        groups
            .entry((a.target_user.clone(), a.source.clone()))
            .or_default()
            .push(a);
    }
    groups
}

fn group_by_spraying_key(attempts: &[LogonAttempt]) -> HashMap<SprayingKey, Vec<&LogonAttempt>> {
    let mut groups: HashMap<SprayingKey, Vec<&LogonAttempt>> = HashMap::new();
    for a in attempts {
        groups.entry(a.source.clone()).or_default().push(a);
    }
    groups
}

/// Within `window`, find the max count of failures that share a window anchored at
/// any single failure's timestamp, and whether any success in that same window
/// exists (success anchors don't matter for the count, only for severity).
fn window_stats(attempts: &[&LogonAttempt], window: Duration) -> (u32, bool) {
    let mut max_failures = 0u32;
    let mut any_success_near_max = false;
    for anchor in attempts.iter().filter(|a| !a.success) {
        let window_end = anchor.ts + window;
        let in_window: Vec<&&LogonAttempt> = attempts
            .iter()
            .filter(|a| a.ts >= anchor.ts && a.ts <= window_end)
            .collect();
        let failures = in_window.iter().filter(|a| !a.success).count() as u32;
        let has_success = in_window.iter().any(|a| a.success);
        if failures > max_failures {
            max_failures = failures;
            any_success_near_max = has_success;
        } else if failures == max_failures && has_success {
            any_success_near_max = true;
        }
    }
    (max_failures, any_success_near_max)
}

pub struct LogonBruteforceHeuristic {
    bruteforce_window: Duration,
    bruteforce_threshold: u32,
    spraying_window: Duration,
    spraying_threshold: u32,
}

impl LogonBruteforceHeuristic {
    pub fn new(
        bruteforce_window: Duration,
        bruteforce_threshold: u32,
        spraying_window: Duration,
        spraying_threshold: u32,
    ) -> Self {
        LogonBruteforceHeuristic {
            bruteforce_window,
            bruteforce_threshold,
            spraying_window,
            spraying_threshold,
        }
    }

    fn analyze_bruteforce(&self, attempts: &[LogonAttempt]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let groups = group_by_bruteforce_key(attempts);
        for ((target_user, source), group) in groups {
            if source == "-" {
                continue;
            }
            let (max_failures, has_success) = window_stats(&group, self.bruteforce_window);
            if max_failures < self.bruteforce_threshold {
                continue;
            }
            let severity = if has_success { Severity::High } else { Severity::Medium };
            let title = format!("登入爆破: {target_user} ← {source}");
            let details = format!(
                "帳號 {target_user} 在 {} 分鐘內從來源 {source} 收到 {max_failures} 次失敗登入嘗試",
                self.bruteforce_window.num_minutes()
            );
            let reason = if has_success {
                format!(
                    "失敗次數 {max_failures} 達門檻 {}，且時間窗內出現成功登入——疑似爆破成功",
                    self.bruteforce_threshold
                )
            } else {
                format!(
                    "失敗次數 {max_failures} 達門檻 {}，時間窗內無成功登入接續",
                    self.bruteforce_threshold
                )
            };
            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = group.iter().map(|a| a.ts).max().unwrap_or_else(Utc::now);
            f.artifact = "logon_bruteforce".into();
            f.mitre = vec!["T1110.001".into()];
            f.user = Some(target_user.clone());
            f.details = details;
            f.reason = Some(reason);
            f.evidence = group
                .iter()
                .map(|a| EvidenceItem {
                    artifact: "evtx:Security".into(),
                    path: None,
                    ts: Some(a.ts),
                    detail: format!(
                        "{}: target={} source={}",
                        if a.success { "4624 success" } else { "4625 failure" },
                        a.target_user,
                        a.source
                    ),
                })
                .collect();
            findings.push(f);
        }
        findings
    }

    fn analyze_spraying(&self, attempts: &[LogonAttempt]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let groups = group_by_spraying_key(attempts);
        for (source, group) in groups {
            if source == "-" {
                continue;
            }
            // Distinct-account counting within the spraying window: anchor on every
            // attempt (not just failures — spraying signal is breadth, not failure
            // rate), find the window with the most distinct TargetUserName values.
            let mut max_distinct = 0u32;
            let mut any_success_near_max = false;
            let mut evidence_at_max: Vec<&LogonAttempt> = Vec::new();
            for anchor in &group {
                let window_end = anchor.ts + self.spraying_window;
                let in_window: Vec<&&LogonAttempt> = group
                    .iter()
                    .filter(|a| a.ts >= anchor.ts && a.ts <= window_end)
                    .collect();
                let distinct_users: std::collections::HashSet<&str> =
                    in_window.iter().map(|a| a.target_user.as_str()).collect();
                let count = distinct_users.len() as u32;
                if count > max_distinct {
                    max_distinct = count;
                    any_success_near_max = in_window.iter().any(|a| a.success);
                    evidence_at_max = in_window.iter().map(|a| **a).collect();
                }
            }
            if max_distinct < self.spraying_threshold {
                continue;
            }
            let severity = if any_success_near_max {
                Severity::High
            } else {
                Severity::Medium
            };
            let title = format!("Password Spraying: {source}");
            let details = format!(
                "來源 {source} 在 {} 分鐘內對 {max_distinct} 個不同帳號發起登入嘗試",
                self.spraying_window.num_minutes()
            );
            let reason = if any_success_near_max {
                format!(
                    "不同帳號數 {max_distinct} 達門檻 {}，且時間窗內有帳號成功登入——疑似 spraying 得手",
                    self.spraying_threshold
                )
            } else {
                format!(
                    "不同帳號數 {max_distinct} 達門檻 {}，時間窗內無成功登入",
                    self.spraying_threshold
                )
            };
            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = evidence_at_max.iter().map(|a| a.ts).max().unwrap_or_else(Utc::now);
            f.artifact = "logon_bruteforce".into();
            f.mitre = vec!["T1110.003".into()];
            f.details = details;
            f.reason = Some(reason);
            f.evidence = evidence_at_max
                .iter()
                .map(|a| EvidenceItem {
                    artifact: "evtx:Security".into(),
                    path: None,
                    ts: Some(a.ts),
                    detail: format!(
                        "{}: target={} source={}",
                        if a.success { "4624 success" } else { "4625 failure" },
                        a.target_user,
                        a.source
                    ),
                })
                .collect();
            findings.push(f);
        }
        findings
    }
}

impl Analyzer for LogonBruteforceHeuristic {
    fn name(&self) -> &str {
        "heur_logon_bruteforce"
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let attempts: Vec<LogonAttempt> = records
            .iter()
            .filter_map(|r| match r {
                Record::Event(ev) => parse_logon_attempt(ev),
                _ => None,
            })
            .collect();

        let mut findings = self.analyze_bruteforce(&attempts);
        findings.extend(self.analyze_spraying(&attempts));
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    fn make_logon_event(eid: u32, ts: DateTime<Utc>, target_user: &str, ip: &str) -> Record {
        let mut data = Map::new();
        data.insert(
            "TargetUserName".to_string(),
            Value::String(target_user.to_string()),
        );
        data.insert("IpAddress".to_string(), Value::String(ip.to_string()));
        Record::Event(EventRecord {
            ts,
            channel: "Security".to_string(),
            event_id: eid,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            record_id: 1,
            data,
        })
    }

    fn heuristic() -> LogonBruteforceHeuristic {
        LogonBruteforceHeuristic::new(Duration::minutes(5), 5, Duration::minutes(1), 10)
    }

    #[test]
    fn five_failures_same_account_same_source_within_window_fires_medium() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "alice", "10.0.0.5"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one bruteforce finding, got {findings:?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("alice"));
    }

    #[test]
    fn four_failures_below_threshold_fires_nothing() {
        let base = Utc::now();
        let records: Vec<Record> = (0..4)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "bob", "10.0.0.9"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "expected no findings below threshold, got {findings:?}"
        );
    }

    #[test]
    fn five_failures_then_success_fires_high() {
        let base = Utc::now();
        let mut records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "carol", "10.0.0.7"))
            .collect();
        records.push(make_logon_event(
            4624,
            base + Duration::seconds(200),
            "carol",
            "10.0.0.7",
        ));
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let bruteforce_finding = findings
            .iter()
            .find(|f| f.title.contains("carol"))
            .expect("bruteforce finding for carol must exist");
        assert_eq!(bruteforce_finding.severity, Severity::High);
    }

    #[test]
    fn failures_outside_window_do_not_accumulate() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::minutes(i * 10), "dave", "10.0.0.1"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "failures spread 10 minutes apart (window=5min) should not accumulate, got {findings:?}"
        );
    }

    #[test]
    fn ten_distinct_accounts_same_source_within_window_fires_spraying_medium() {
        let base = Utc::now();
        let records: Vec<Record> = (0..10)
            .map(|i| {
                make_logon_event(
                    4625,
                    base + Duration::seconds(i * 3),
                    &format!("user{i}"),
                    "10.0.0.99",
                )
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let spraying_finding = findings
            .iter()
            .find(|f| f.title.contains("Spraying"))
            .expect("spraying finding must exist");
        assert_eq!(spraying_finding.severity, Severity::Medium);
    }

    #[test]
    fn nine_distinct_accounts_below_spraying_threshold_fires_nothing() {
        let base = Utc::now();
        let records: Vec<Record> = (0..9)
            .map(|i| {
                make_logon_event(
                    4625,
                    base + Duration::seconds(i * 3),
                    &format!("user{i}"),
                    "10.0.0.88",
                )
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.iter().all(|f| !f.title.contains("Spraying")),
            "9 distinct accounts should not trigger spraying (threshold=10), got {findings:?}"
        );
    }

    #[test]
    fn spraying_with_one_success_fires_high() {
        let base = Utc::now();
        let mut records: Vec<Record> = (0..9)
            .map(|i| {
                make_logon_event(
                    4625,
                    base + Duration::seconds(i * 3),
                    &format!("spray_user{i}"),
                    "10.0.0.77",
                )
            })
            .collect();
        records.push(make_logon_event(
            4624,
            base + Duration::seconds(30),
            "spray_user9",
            "10.0.0.77",
        ));
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let spraying_finding = findings
            .iter()
            .find(|f| f.title.contains("Spraying"))
            .expect("spraying finding must exist (9 failures + 1 success = 10 distinct)");
        assert_eq!(spraying_finding.severity, Severity::High);
    }

    #[test]
    fn missing_ip_falls_back_to_workstation_name() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| {
                let mut data = Map::new();
                data.insert(
                    "TargetUserName".to_string(),
                    Value::String("erin".to_string()),
                );
                data.insert(
                    "WorkstationName".to_string(),
                    Value::String("WORKSTATION1".to_string()),
                );
                Record::Event(EventRecord {
                    ts: base + Duration::seconds(i * 30),
                    channel: "Security".to_string(),
                    event_id: 4625,
                    provider: "Microsoft-Windows-Security-Auditing".to_string(),
                    computer: "TEST-PC".to_string(),
                    record_id: 1,
                    data,
                })
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "fallback to WorkstationName must still group and fire"
        );
        assert!(findings[0].details.contains("WORKSTATION1"));
    }

    #[test]
    fn missing_both_ip_and_workstation_never_fires() {
        let base = Utc::now();
        let records: Vec<Record> = (0..10)
            .map(|i| {
                let mut data = Map::new();
                data.insert(
                    "TargetUserName".to_string(),
                    Value::String("frank".to_string()),
                );
                Record::Event(EventRecord {
                    ts: base + Duration::seconds(i * 30),
                    channel: "Security".to_string(),
                    event_id: 4625,
                    provider: "Microsoft-Windows-Security-Auditing".to_string(),
                    computer: "TEST-PC".to_string(),
                    record_id: 1,
                    data,
                })
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "source='-' groups must be skipped entirely (no grouping possible), got {findings:?}"
        );
    }

    #[test]
    fn non_security_channel_ignored() {
        let base = Utc::now();
        let mut data = Map::new();
        data.insert(
            "TargetUserName".to_string(),
            Value::String("grace".to_string()),
        );
        data.insert(
            "IpAddress".to_string(),
            Value::String("10.0.0.50".to_string()),
        );
        let records: Vec<Record> = (0..5)
            .map(|i| {
                Record::Event(EventRecord {
                    ts: base + Duration::seconds(i * 30),
                    channel: "System".to_string(),
                    event_id: 4625,
                    provider: "test".to_string(),
                    computer: "TEST-PC".to_string(),
                    record_id: 1,
                    data: data.clone(),
                })
            })
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "non-Security channel events must be ignored"
        );
    }

    #[test]
    fn finding_carries_reason_and_evidence() {
        let base = Utc::now();
        let records: Vec<Record> = (0..5)
            .map(|i| make_logon_event(4625, base + Duration::seconds(i * 30), "henry", "10.0.0.20"))
            .collect();
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        assert!(
            findings[0].reason.is_some(),
            "golden rule 6: reason must be set"
        );
        assert_eq!(
            findings[0].evidence.len(),
            5,
            "each failure should be captured as evidence"
        );
    }
}
