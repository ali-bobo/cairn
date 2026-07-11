#![forbid(unsafe_code)]

use cairn_core::finding::{FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

/// Events within this many days of analysis time are considered "recent" → High.
const ACCOUNT_RECENT_DAYS: i64 = 90;

#[derive(Debug)]
enum AccountEventKind {
    Created,
    Deleted,
    AddedToGroup,
}

#[derive(Debug)]
struct AccountEvent {
    kind: AccountEventKind,
    /// Target account name (created/deleted) or member name (group add).
    target: String,
    /// Group name — only set for AddedToGroup.
    group: Option<String>,
    /// Account that performed the operation.
    subject: String,
    ts: DateTime<Utc>,
    mitre: &'static str,
    /// Source EVTX EventID (4720/4726/4732/4728), kept for evidence detail.
    event_id: u32,
}

fn extract_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// Parse a Security channel EventRecord into an AccountEvent; return None for irrelevant events.
fn parse_account_event(ev: &EventRecord) -> Option<AccountEvent> {
    if ev.channel != "Security" {
        return None;
    }
    let d = &ev.data;
    match ev.event_id {
        4720 => Some(AccountEvent {
            kind: AccountEventKind::Created,
            target: extract_str(d, "TargetUserName"),
            group: None,
            subject: extract_str(d, "SubjectUserName"),
            ts: ev.ts,
            mitre: "T1136.001",
            event_id: ev.event_id,
        }),
        4726 => Some(AccountEvent {
            kind: AccountEventKind::Deleted,
            target: extract_str(d, "TargetUserName"),
            group: None,
            subject: extract_str(d, "SubjectUserName"),
            ts: ev.ts,
            mitre: "T1531",
            event_id: ev.event_id,
        }),
        4732 | 4728 => Some(AccountEvent {
            kind: AccountEventKind::AddedToGroup,
            target: extract_str(d, "MemberName"),
            group: Some(extract_str(d, "TargetUserName")),
            subject: extract_str(d, "SubjectUserName"),
            ts: ev.ts,
            mitre: "T1098.001",
            event_id: ev.event_id,
        }),
        _ => None,
    }
}

fn is_recent(ts: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    let age = now.signed_duration_since(ts);
    age >= Duration::zero() && age <= Duration::days(ACCOUNT_RECENT_DAYS)
}

/// Heuristic analyzer for account lifecycle events (EID 4720/4726/4732/4728).
///
/// Severity: events within ACCOUNT_RECENT_DAYS → High; older → Medium.
/// All findings carry an explainable reason (golden rule 6).
pub struct AccountHeuristic;

impl Analyzer for AccountHeuristic {
    fn name(&self) -> &str {
        "heur_account"
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut findings = Vec::new();

        for r in records {
            let ev = match r {
                Record::Event(e) => e,
                _ => continue,
            };
            let ae = match parse_account_event(ev) {
                Some(a) => a,
                None => continue,
            };

            let recent = is_recent(ae.ts, now);
            let severity = if recent {
                Severity::High
            } else {
                Severity::Medium
            };

            let age_days = now.signed_duration_since(ae.ts).num_days();

            let (title, details) = match &ae.kind {
                AccountEventKind::Created => (
                    format!("帳號建立: {}", ae.target),
                    format!(
                        "帳號 {} 由 {} 建立於 {}",
                        ae.target,
                        ae.subject,
                        ae.ts.format("%Y-%m-%dT%H:%M:%SZ")
                    ),
                ),
                AccountEventKind::Deleted => (
                    format!("帳號刪除: {}", ae.target),
                    format!(
                        "帳號 {} 由 {} 刪除於 {}",
                        ae.target,
                        ae.subject,
                        ae.ts.format("%Y-%m-%dT%H:%M:%SZ")
                    ),
                ),
                AccountEventKind::AddedToGroup => {
                    let group = ae.group.as_deref().unwrap_or("?");
                    (
                        format!("加入群組: {} ← {}", group, ae.target),
                        format!(
                            "{} 被 {} 加入群組 {} 於 {}",
                            ae.target,
                            ae.subject,
                            group,
                            ae.ts.format("%Y-%m-%dT%H:%M:%SZ")
                        ),
                    )
                }
            };

            let reason = if recent {
                format!(
                    "帳號操作發生在 {} 天內（近期窗口 {} 天）",
                    age_days, ACCOUNT_RECENT_DAYS
                )
            } else {
                format!(
                    "帳號操作發生在 {} 天前（超過近期窗口 {} 天）",
                    age_days, ACCOUNT_RECENT_DAYS
                )
            };

            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = ae.ts;
            f.artifact = "account".into();
            f.mitre = vec![ae.mitre.into()];
            f.details = details;
            f.reason = Some(reason);
            f.evidence = vec![cairn_core::finding::EvidenceItem {
                artifact: "evtx:Security".into(),
                path: None,
                ts: Some(ae.ts),
                detail: format!(
                    "EID {}: target={} subject={}{}",
                    ae.event_id,
                    ae.target,
                    ae.subject,
                    ae.group
                        .as_deref()
                        .map(|g| format!(" group={g}"))
                        .unwrap_or_default()
                ),
            }];

            findings.push(f);
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::Record;
    use serde_json::{Map, Value};

    fn make_event(eid: u32, channel: &str, ts: DateTime<Utc>, data: Map<String, Value>) -> Record {
        Record::Event(EventRecord {
            ts,
            channel: channel.to_string(),
            event_id: eid,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            record_id: 1,
            data,
        })
    }

    fn account_data(target: &str, subject: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("TargetUserName".into(), Value::String(target.into()));
        m.insert("SubjectUserName".into(), Value::String(subject.into()));
        m
    }

    fn group_data(member: &str, group: &str, subject: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("MemberName".into(), Value::String(member.into()));
        m.insert("TargetUserName".into(), Value::String(group.into()));
        m.insert("SubjectUserName".into(), Value::String(subject.into()));
        m
    }

    fn recent() -> DateTime<Utc> {
        Utc::now() - Duration::days(30)
    }

    fn old() -> DateTime<Utc> {
        Utc::now() - Duration::days(120)
    }

    #[test]
    fn create_account_recent_is_high() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("evil_user", "SYSTEM"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1136.001".to_string()));
        assert_eq!(findings[0].artifact, "account");
    }

    #[test]
    fn create_account_old_is_medium() {
        let records = vec![make_event(
            4720,
            "Security",
            old(),
            account_data("old_user", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn delete_account_recent_is_high() {
        let records = vec![make_event(
            4726,
            "Security",
            recent(),
            account_data("victim", "attacker"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1531".to_string()));
    }

    #[test]
    fn add_to_local_group_is_high() {
        let records = vec![make_event(
            4732,
            "Security",
            recent(),
            group_data(r"DESKTOP\evil", "Administrators", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1098.001".to_string()));
        assert!(
            findings[0].title.contains("Administrators"),
            "title: {}",
            findings[0].title
        );
    }

    #[test]
    fn add_to_global_group_is_high() {
        let records = vec![make_event(
            4728,
            "Security",
            recent(),
            group_data(r"DOMAIN\evil", "Domain Admins", "DA"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1098.001".to_string()));
    }

    #[test]
    fn non_security_channel_ignored() {
        let records = vec![make_event(
            4720,
            "System",
            recent(),
            account_data("user", "admin"),
        )];
        assert!(AccountHeuristic.analyze(&records, &[]).unwrap().is_empty());
    }

    #[test]
    fn wrong_eid_ignored() {
        let records = vec![make_event(
            4625,
            "Security",
            recent(),
            account_data("user", "admin"),
        )];
        assert!(AccountHeuristic.analyze(&records, &[]).unwrap().is_empty());
    }

    #[test]
    fn non_event_record_ignored() {
        use cairn_core::record::ProcessRecord;
        let records = vec![Record::Process(ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "system".into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        })];
        assert!(AccountHeuristic.analyze(&records, &[]).unwrap().is_empty());
    }

    #[test]
    fn reason_mentions_time_window() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("user", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        let reason = findings[0].reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("90") || reason.contains("近期"),
            "reason must mention window: {reason}"
        );
    }

    #[test]
    fn account_finding_carries_evtx_evidence() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("u", "admin"),
        )];
        let f = &AccountHeuristic.analyze(&records, &[]).unwrap()[0];
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].artifact, "evtx:Security");
        assert!(f.evidence[0].detail.contains("EID 4720"));
    }

    #[test]
    fn finding_has_artifact_account() {
        let records = vec![make_event(
            4720,
            "Security",
            recent(),
            account_data("user", "admin"),
        )];
        let findings = AccountHeuristic.analyze(&records, &[]).unwrap();
        assert_eq!(findings[0].artifact, "account");
    }
}
