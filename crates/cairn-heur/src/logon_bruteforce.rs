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

/// A numeric field that may be written as a string ("3", "0xC000006A") or a number.
fn extract_num(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    match data.get(key)? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => {
            let t = s.trim();
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => t.parse().ok(),
            }
        }
        _ => None,
    }
}

/// NTSTATUS codes of a password-guessing failure: bad password, no such user,
/// account locked out (the lockout itself is a result of guessing).
const NTLM_GUESS_STATUS: &[u64] = &[0xC000_006A, 0xC000_0064, 0xC000_0234];
/// Generic "unknown user name or bad password"; the detail is in SubStatus.
const STATUS_LOGON_FAILURE: u64 = 0xC000_006D;
/// Kerberos 4771 failure codes of a guess: bad password (0x18), unknown principal
/// (0x6), client revoked / locked (0x12).
const KERBEROS_GUESS_STATUS: &[u64] = &[0x18, 0x6, 0x12];

/// Logon types never counted: 0 (system), 4 (batch), 5 (service) — a service with a
/// stale password fails forever without anyone guessing. Network (3) and
/// RemoteInteractive (10) are the remote-guessing types; the other interactive types
/// are kept (their sources are usually loopback and dropped below anyway).
const IGNORED_LOGON_TYPES: &[u64] = &[0, 4, 5];
/// Logon types a successful remote guess produces: Network (3), RemoteInteractive (10).
const REMOTE_SUCCESS_TYPES: &[u64] = &[3, 10];

/// A single parsed logon attempt (a 4624 remote success, or a 4625/4771/4776 guessing
/// failure).
#[derive(Debug, Clone)]
struct LogonAttempt {
    ts: DateTime<Utc>,
    target_user: String,
    /// IpAddress (IPv4-mapped prefix stripped) if present and not "-"; else
    /// WorkstationName / Workstation.
    source: String,
    success: bool,
    event_id: u32,
}

/// Normalize a source address; None for local / loopback / unknown sources.
fn normalize_source(raw: &str) -> Option<String> {
    let t = raw.trim();
    let t = t.strip_prefix("::ffff:").unwrap_or(t);
    let lower = t.to_ascii_lowercase();
    if matches!(lower.as_str(), "" | "-" | "127.0.0.1" | "::1" | "localhost") {
        return None;
    }
    Some(t.to_string())
}

/// Window Manager / font driver session accounts Windows logs on by itself.
fn is_system_session_account(user: &str) -> bool {
    let u = user.to_ascii_uppercase();
    u.starts_with("DWM-") || u.starts_with("UMFD-")
}

fn parse_logon_attempt(ev: &EventRecord) -> Option<LogonAttempt> {
    if ev.channel != "Security" {
        return None;
    }
    let d = &ev.data;
    let logon_type = extract_num(d, "LogonType");
    let success = match ev.event_id {
        4624 => {
            if !logon_type.is_some_and(|t| REMOTE_SUCCESS_TYPES.contains(&t)) {
                return None;
            }
            true
        }
        4625 => {
            if logon_type.is_some_and(|t| IGNORED_LOGON_TYPES.contains(&t)) {
                return None;
            }
            let code = extract_num(d, "SubStatus")
                .filter(|c| *c != 0)
                .or_else(|| extract_num(d, "Status"));
            if let Some(c) = code {
                if !NTLM_GUESS_STATUS.contains(&c) && c != STATUS_LOGON_FAILURE {
                    return None; // expired, disabled, clock skew, logon-hours, ...
                }
            }
            false
        }
        4771 => {
            if let Some(c) = extract_num(d, "Status") {
                if !KERBEROS_GUESS_STATUS.contains(&c) {
                    return None;
                }
            }
            false
        }
        4776 => {
            // 4776 is logged for successes too (Status 0x0); only guessing failures count.
            if !extract_num(d, "Status").is_some_and(|c| NTLM_GUESS_STATUS.contains(&c)) {
                return None;
            }
            false
        }
        _ => return None,
    };
    let target_user = extract_str(d, "TargetUserName");
    if target_user == "-" || is_system_session_account(&target_user) {
        return None;
    }
    let source = normalize_source(&extract_str(d, "IpAddress"))
        .or_else(|| normalize_source(&extract_str(d, "WorkstationName")))
        .or_else(|| normalize_source(&extract_str(d, "Workstation")))?;
    Some(LogonAttempt {
        ts: ev.ts,
        target_user,
        source,
        success,
        event_id: ev.event_id,
    })
}

/// True if a remote success from this source follows a failure window starting at
/// `start` and ending at `end`: success after the first failure, at most one window
/// length after the last.
fn success_after(
    group: &[&LogonAttempt],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    window: Duration,
) -> bool {
    group
        .iter()
        .any(|a| a.success && a.ts > start && a.ts <= end + window)
}

fn evidence_label(a: &LogonAttempt) -> &'static str {
    match (a.event_id, a.success) {
        (_, true) => "4624 success",
        (4771, _) => "4771 Kerberos pre-auth failure",
        (4776, _) => "4776 NTLM validation failure",
        _ => "4625 failure",
    }
}

/// Bruteforce group key: (TargetUserName, source). Groups repeated failures against
/// the same account from the same origin.
type BruteforceKey = (String, String);

/// Spraying group key: source only. Groups distinct-account attempts from one origin.
type SprayingKey = String;

fn group_by_bruteforce_key(
    attempts: &[LogonAttempt],
) -> HashMap<BruteforceKey, Vec<&LogonAttempt>> {
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

/// Within `window`, the max count of failures in a window anchored at any single
/// failure, and whether a remote success from the same group follows that window.
fn window_stats(attempts: &[&LogonAttempt], window: Duration) -> (u32, bool) {
    let mut max_failures = 0u32;
    let mut succeeded = false;
    for anchor in attempts.iter().filter(|a| !a.success) {
        let window_end = anchor.ts + window;
        let in_window: Vec<&&LogonAttempt> = attempts
            .iter()
            .filter(|a| !a.success && a.ts >= anchor.ts && a.ts <= window_end)
            .collect();
        let failures = in_window.len() as u32;
        let last = in_window.iter().map(|a| a.ts).max().unwrap_or(anchor.ts);
        let has_success = success_after(attempts, anchor.ts, last, window);
        if failures > max_failures {
            max_failures = failures;
            succeeded = has_success;
        } else if failures == max_failures && has_success {
            succeeded = true;
        }
    }
    (max_failures, succeeded)
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
            let (max_failures, has_success) = window_stats(&group, self.bruteforce_window);
            if max_failures < self.bruteforce_threshold {
                continue;
            }
            let severity = if has_success {
                Severity::High
            } else {
                Severity::Medium
            };
            let title = format!("登入爆破: {target_user} ← {source}");
            let details = format!(
                "帳號 {target_user} 在 {} 分鐘內從來源 {source} 收到 {max_failures} 次失敗登入嘗試",
                self.bruteforce_window.num_minutes()
            );
            let reason = if has_success {
                format!(
                    "失敗次數 {max_failures} 達門檻 {}，之後同一來源以網路／遠端桌面登入成功（4624 type 3/10）——疑似爆破成功",
                    self.bruteforce_threshold
                )
            } else {
                format!(
                    "失敗次數 {max_failures} 達門檻 {}，之後無同一來源的遠端登入成功",
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
                        evidence_label(a),
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
            // Distinct-account counting within the spraying window: anchor on every
            // failure and find the window with the most distinct TargetUserName values
            // among FAILURES (successes are not guesses; they only decide severity).
            let mut max_distinct = 0u32;
            let mut any_success_near_max = false;
            let mut evidence_at_max: Vec<&LogonAttempt> = Vec::new();
            for anchor in group.iter().filter(|a| !a.success) {
                let window_end = anchor.ts + self.spraying_window;
                let in_window: Vec<&LogonAttempt> = group
                    .iter()
                    .filter(|a| !a.success && a.ts >= anchor.ts && a.ts <= window_end)
                    .copied()
                    .collect();
                let distinct_users: std::collections::HashSet<&str> =
                    in_window.iter().map(|a| a.target_user.as_str()).collect();
                let count = distinct_users.len() as u32;
                if count > max_distinct {
                    max_distinct = count;
                    let last = in_window.iter().map(|a| a.ts).max().unwrap_or(anchor.ts);
                    any_success_near_max =
                        success_after(&group, anchor.ts, last, self.spraying_window);
                    evidence_at_max = in_window;
                    evidence_at_max.extend(group.iter().copied().filter(|a| {
                        a.success && a.ts > anchor.ts && a.ts <= last + self.spraying_window
                    }));
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
                    "失敗的不同帳號數 {max_distinct} 達門檻 {}，之後同一來源以網路／遠端桌面登入成功（4624 type 3/10）——疑似 spraying 得手",
                    self.spraying_threshold
                )
            } else {
                format!(
                    "失敗的不同帳號數 {max_distinct} 達門檻 {}，之後無同一來源的遠端登入成功",
                    self.spraying_threshold
                )
            };
            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = evidence_at_max
                .iter()
                .map(|a| a.ts)
                .max()
                .unwrap_or_else(Utc::now);
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
                        evidence_label(a),
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

impl LogonBruteforceHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::LOGON_BRUTEFORCE;
}

impl Analyzer for LogonBruteforceHeuristic {
    fn name(&self) -> &str {
        Self::NAME
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
        Ok(crate::stamped(findings, Self::NAME))
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
        data.insert("LogonType".to_string(), Value::String("3".to_string()));
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
        let mut records: Vec<Record> = (0..10)
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
            base + Duration::seconds(32),
            "spray_user9",
            "10.0.0.77",
        ));
        let h = heuristic();
        let findings = h.analyze(&records, &[]).unwrap();
        let spraying_finding = findings
            .iter()
            .find(|f| f.title.contains("Spraying"))
            .expect("spraying finding must exist (10 distinct failures, then a success)");
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

    fn event_with(eid: u32, ts: DateTime<Utc>, fields: &[(&str, &str)]) -> Record {
        let data: Map<String, Value> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect();
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

    fn five(eid: u32, extra: &[(&str, &str)]) -> Vec<Record> {
        let base = Utc::now();
        (0..5)
            .map(|i| {
                let mut f = vec![("TargetUserName", "alice"), ("IpAddress", "10.0.0.5")];
                f.extend_from_slice(extra);
                event_with(eid, base + Duration::seconds(i * 10), &f)
            })
            .collect()
    }

    #[test]
    fn service_and_batch_logon_failures_are_not_counted() {
        for t in ["0", "4", "5"] {
            assert!(
                heuristic()
                    .analyze(&five(4625, &[("LogonType", t)]), &[])
                    .unwrap()
                    .is_empty(),
                "type {t}"
            );
        }
        for t in ["3", "10"] {
            assert_eq!(
                heuristic()
                    .analyze(&five(4625, &[("LogonType", t)]), &[])
                    .unwrap()
                    .len(),
                1,
                "type {t}"
            );
        }
    }

    #[test]
    fn only_guessing_substatus_codes_count() {
        for code in ["0xC000006A", "0xc0000064", "0xC0000234"] {
            let r = five(
                4625,
                &[
                    ("LogonType", "3"),
                    ("Status", "0xC000006D"),
                    ("SubStatus", code),
                ],
            );
            assert_eq!(heuristic().analyze(&r, &[]).unwrap().len(), 1, "{code}");
        }
        // expired password / disabled account / clock skew are not guesses
        for code in ["0xC0000071", "0xC0000072", "0xC0000133"] {
            let r = five(
                4625,
                &[
                    ("LogonType", "3"),
                    ("Status", "0xC000006E"),
                    ("SubStatus", code),
                ],
            );
            assert!(heuristic().analyze(&r, &[]).unwrap().is_empty(), "{code}");
        }
    }

    #[test]
    fn loopback_sources_and_session_accounts_are_excluded() {
        for ip in ["127.0.0.1", "::1", "-"] {
            assert!(
                heuristic()
                    .analyze(&five(4625, &[("IpAddress", ip)]), &[])
                    .unwrap()
                    .is_empty(),
                "{ip}"
            );
        }
        let base = Utc::now();
        let dwm: Vec<Record> = (0..5)
            .map(|i| {
                event_with(
                    4625,
                    base + Duration::seconds(i),
                    &[("TargetUserName", "DWM-3"), ("IpAddress", "10.0.0.5")],
                )
            })
            .collect();
        assert!(heuristic().analyze(&dwm, &[]).unwrap().is_empty());
    }

    #[test]
    fn kerberos_and_ntlm_failures_count() {
        let kerb = five(
            4771,
            &[("IpAddress", "::ffff:10.0.0.5"), ("Status", "0x18")],
        );
        let f = heuristic().analyze(&kerb, &[]).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].details.contains("10.0.0.5") && !f[0].details.contains("::ffff:"));
        assert!(f[0].evidence[0].detail.contains("4771"));
        let ntlm = five(
            4776,
            &[
                ("IpAddress", "-"),
                ("Workstation", "ATTACKER-PC"),
                ("Status", "0xC000006A"),
            ],
        );
        assert_eq!(heuristic().analyze(&ntlm, &[]).unwrap().len(), 1);
        // 4776 success (Status 0x0) is not a failure
        let ok = five(4776, &[("Workstation", "PC1"), ("Status", "0x0")]);
        assert!(heuristic().analyze(&ok, &[]).unwrap().is_empty());
    }

    #[test]
    fn success_must_be_remote_and_after_the_failures() {
        let base = Utc::now();
        let mk = |ty: &str, offset: i64| {
            let mut r = five(4625, &[("LogonType", "3")]);
            // keep the failures on a fixed base so the success offset is relative
            for (i, rec) in r.iter_mut().enumerate() {
                if let Record::Event(e) = rec {
                    e.ts = base + Duration::seconds(i as i64 * 10);
                }
            }
            r.push(event_with(
                4624,
                base + Duration::seconds(offset),
                &[
                    ("TargetUserName", "alice"),
                    ("IpAddress", "10.0.0.5"),
                    ("LogonType", ty),
                ],
            ));
            heuristic().analyze(&r, &[]).unwrap()[0].severity
        };
        assert_eq!(mk("3", 60), Severity::High);
        assert_eq!(mk("10", 60), Severity::High);
        assert_eq!(
            mk("2", 60),
            Severity::Medium,
            "interactive success is not the remote guess"
        );
        assert_eq!(
            mk("3", -60),
            Severity::Medium,
            "success before the failures"
        );
    }
}
