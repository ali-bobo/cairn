//! heur_account: account lifecycle and privilege changes in the Security log.
//!
//! | Event | Meaning | Severity | ATT&CK |
//! |---|---|---|---|
//! | 4720 | account created | High within 90 days, else Medium | T1136.001 |
//! | 4726 | account deleted | High within 90 days, else Medium | T1531 |
//! | 4728 / 4732 / 4756 | member added to a global / local / universal group | High for a privileged group, else Low | T1098.007 |
//! | 4722 | account enabled | Medium | T1098 |
//! | 4724 | password reset by another account | Medium | T1098 |
//! | 4738 | account changed, a risky UAC flag turned on | Medium | T1098 |
//!
//! Every reason states who did what to whom. A group-add event that a Sigma rule
//! already reported (same event ID and record) is skipped so the analyst sees it once.
#![forbid(unsafe_code)]

use cairn_core::finding::{FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

/// Events within this many days of analysis time are considered "recent" → High.
const ACCOUNT_RECENT_DAYS: i64 = 90;

/// Groups whose membership grants control of the host or domain (or interactive
/// remote access / raw file access): adding someone is High. Matched by name
/// (case-insensitive) and by well-known SID, so localized group names still match.
const PRIVILEGED_GROUP_NAMES: &[&str] = &[
    "administrators",
    "domain admins",
    "enterprise admins",
    "remote desktop users",
    "backup operators",
];

/// Well-known SIDs (or domain-relative RID suffixes) of the privileged groups.
const PRIVILEGED_LOCAL_SIDS: &[&str] = &["S-1-5-32-544", "S-1-5-32-555", "S-1-5-32-551"];
const PRIVILEGED_DOMAIN_RIDS: &[&str] = &["-512", "-519"];

/// SAM user-account-control bits (the `OldUacValue`/`NewUacValue` of 4738, which are
/// the SAM flags, not AD's userAccountControl) whose turning on weakens the account.
/// Bit index i also maps to the message code `%%(2048+i)` ("... - Enabled").
const RISKY_UAC_FLAGS: &[(u32, &str)] = &[
    (2, "Password Not Required"),
    (9, "Don't Expire Password"),
    (
        11,
        "Encrypted Text Password Allowed (reversible encryption)",
    ),
    (13, "Trusted For Delegation"),
    (15, "Use DES Key Only"),
    (16, "Don't Require Kerberos Preauthentication"),
    (18, "Trusted To Authenticate For Delegation"),
];

#[derive(Debug, PartialEq)]
enum AccountEventKind {
    Created,
    Deleted,
    AddedToGroup,
    Enabled,
    PasswordReset,
    UacChanged(Vec<&'static str>),
}

#[derive(Debug)]
struct AccountEvent {
    kind: AccountEventKind,
    /// Target account (created/deleted/enabled/reset/changed) or member (group add).
    target: String,
    /// Group name — only set for AddedToGroup.
    group: Option<String>,
    /// Group SID — only set for AddedToGroup.
    group_sid: Option<String>,
    /// Account that performed the operation (DOMAIN\user when the domain is known).
    subject: String,
    ts: DateTime<Utc>,
    mitre: &'static str,
    /// Source EVTX EventID, kept for evidence detail.
    event_id: u32,
    record_id: u64,
}

/// A string field, `None` when absent, empty or the EVTX placeholder "-".
fn opt_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    data.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "-")
        .map(str::to_string)
}

fn extract_str(data: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    opt_str(data, key).unwrap_or_else(|| "-".to_string())
}

/// `DOMAIN\user` from a `<prefix>DomainName` / `<prefix>UserName` pair.
fn qualified(data: &serde_json::Map<String, serde_json::Value>, prefix: &str) -> String {
    let user = extract_str(data, &format!("{prefix}UserName"));
    match opt_str(data, &format!("{prefix}DomainName")) {
        Some(d) if user != "-" => format!("{d}\\{user}"),
        _ => user,
    }
}

/// The member of a group-add event: MemberName, or MemberSid when the name is "-"
/// (local-group adds usually log only the SID).
fn member(data: &serde_json::Map<String, serde_json::Value>) -> String {
    opt_str(data, "MemberName")
        .or_else(|| opt_str(data, "MemberSid"))
        .unwrap_or_else(|| "-".to_string())
}

/// True if this group is one of [`PRIVILEGED_GROUP_NAMES`] (by name or SID).
fn is_privileged_group(name: &str, sid: Option<&str>) -> bool {
    let lower = name.to_ascii_lowercase();
    let bare = lower.rsplit('\\').next().unwrap_or(&lower);
    if PRIVILEGED_GROUP_NAMES.contains(&bare) {
        return true;
    }
    sid.is_some_and(|s| {
        let s = s.to_ascii_uppercase();
        PRIVILEGED_LOCAL_SIDS.contains(&s.as_str())
            || (s.starts_with("S-1-5-21-") && PRIVILEGED_DOMAIN_RIDS.iter().any(|r| s.ends_with(r)))
    })
}

/// Parse a hex (`0x210`) or decimal UAC value.
fn parse_uac(v: &str) -> Option<u32> {
    let v = v.trim();
    match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Risky UAC flags a 4738 turned on: from the Old/New UAC values when present,
/// otherwise from the `%%20xx` codes (or rendered "'X' - Enabled" text) in
/// `UserAccountControl`.
fn risky_uac_changes(data: &serde_json::Map<String, serde_json::Value>) -> Vec<&'static str> {
    let old = opt_str(data, "OldUacValue").and_then(|v| parse_uac(&v));
    let new = opt_str(data, "NewUacValue").and_then(|v| parse_uac(&v));
    if let (Some(old), Some(new)) = (old, new) {
        let turned_on = new & !old;
        return RISKY_UAC_FLAGS
            .iter()
            .filter(|(bit, _)| turned_on & (1 << bit) != 0)
            .map(|(_, name)| *name)
            .collect();
    }
    let uac = opt_str(data, "UserAccountControl").unwrap_or_default();
    let lower = uac.to_ascii_lowercase();
    RISKY_UAC_FLAGS
        .iter()
        .filter(|(bit, name)| {
            let code = format!("%%{}", 2048 + bit);
            let short = name.split(" (").next().unwrap_or(name).to_ascii_lowercase();
            uac.contains(&code) || lower.contains(&format!("'{short}' - enabled"))
        })
        .map(|(_, name)| *name)
        .collect()
}

/// True if the subject and target of a 4724 are the same account.
fn same_account(d: &serde_json::Map<String, serde_json::Value>) -> bool {
    match (opt_str(d, "SubjectUserSid"), opt_str(d, "TargetSid")) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
        _ => opt_str(d, "SubjectUserName")
            .zip(opt_str(d, "TargetUserName"))
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(&b)),
    }
}

/// Parse a Security channel EventRecord into an AccountEvent; return None for irrelevant events.
fn parse_account_event(ev: &EventRecord) -> Option<AccountEvent> {
    if ev.channel != "Security" {
        return None;
    }
    let d = &ev.data;
    let base = |kind, mitre| AccountEvent {
        kind,
        target: qualified(d, "Target"),
        group: None,
        group_sid: None,
        subject: qualified(d, "Subject"),
        ts: ev.ts,
        mitre,
        event_id: ev.event_id,
        record_id: ev.record_id,
    };
    match ev.event_id {
        4720 => Some(base(AccountEventKind::Created, "T1136.001")),
        4726 => Some(base(AccountEventKind::Deleted, "T1531")),
        4722 => Some(base(AccountEventKind::Enabled, "T1098")),
        4724 if !same_account(d) => Some(base(AccountEventKind::PasswordReset, "T1098")),
        4738 => {
            let risky = risky_uac_changes(d);
            (!risky.is_empty()).then(|| base(AccountEventKind::UacChanged(risky), "T1098"))
        }
        4732 | 4728 | 4756 => Some(AccountEvent {
            target: member(d),
            group: Some(qualified(d, "Target")),
            group_sid: opt_str(d, "TargetSid"),
            ..base(AccountEventKind::AddedToGroup, "T1098.007")
        }),
        _ => None,
    }
}

fn is_recent(ts: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    let age = now.signed_duration_since(ts);
    age >= Duration::zero() && age <= Duration::days(ACCOUNT_RECENT_DAYS)
}

/// True if a Sigma finding in `prior` already reports this exact event (same event
/// ID and record id).
fn sigma_already_reported(prior: &[Finding], ae: &AccountEvent) -> bool {
    let rid = ae.record_id.to_string();
    prior.iter().any(|f| {
        f.analyzer == cairn_core::analyzers::SIGMA
            && f.event_id == Some(ae.event_id)
            && f.evidence_ref.as_deref() == Some(rid.as_str())
    })
}

/// Heuristic analyzer for account lifecycle and privilege events (see module docs).
/// All findings carry an explainable reason (golden rule 6).
pub struct AccountHeuristic;

impl AccountHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::ACCOUNT;
}

impl Analyzer for AccountHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    /// Runs after Sigma so a group-add a Sigma rule already reported is not repeated.
    fn depends_on(&self) -> &[&str] {
        &[cairn_core::analyzers::SIGMA]
    }

    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut findings = Vec::new();

        for r in records {
            let Record::Event(ev) = r else { continue };
            let Some(ae) = parse_account_event(ev) else {
                continue;
            };
            if sigma_already_reported(prior_findings, &ae) {
                continue;
            }

            let when = ae.ts.format("%Y-%m-%dT%H:%M:%SZ");
            let recent = is_recent(ae.ts, now);
            let age_days = now.signed_duration_since(ae.ts).num_days();
            let window = if recent {
                format!("{age_days} 天內（近期窗口 {ACCOUNT_RECENT_DAYS} 天）")
            } else {
                format!("{age_days} 天前（超過近期窗口 {ACCOUNT_RECENT_DAYS} 天）")
            };
            let by_recency = if recent {
                Severity::High
            } else {
                Severity::Medium
            };
            let (t, s) = (&ae.target, &ae.subject);

            let (severity, title, details, reason) = match &ae.kind {
                AccountEventKind::Created => (
                    by_recency,
                    format!("帳號建立: {t}"),
                    format!("帳號 {t} 由 {s} 建立於 {when}"),
                    format!("{s} 建立了帳號 {t}；帳號操作發生在 {window}"),
                ),
                AccountEventKind::Deleted => (
                    by_recency,
                    format!("帳號刪除: {t}"),
                    format!("帳號 {t} 由 {s} 刪除於 {when}"),
                    format!("{s} 刪除了帳號 {t}；帳號操作發生在 {window}"),
                ),
                AccountEventKind::AddedToGroup => {
                    let group = ae.group.as_deref().unwrap_or("?");
                    let privileged = is_privileged_group(group, ae.group_sid.as_deref());
                    (
                        if privileged {
                            Severity::High
                        } else {
                            Severity::Low
                        },
                        format!("加入群組: {group} ← {t}"),
                        format!("{t} 被 {s} 加入群組 {group} 於 {when}"),
                        if privileged {
                            format!(
                                "{s} 把 {t} 加入特權群組 {group}（取得系統管理、遠端桌面或備份權限）於 {when}"
                            )
                        } else {
                            format!("{s} 把 {t} 加入群組 {group}（非特權群組）於 {when}")
                        },
                    )
                }
                AccountEventKind::Enabled => (
                    Severity::Medium,
                    format!("帳號啟用: {t}"),
                    format!("帳號 {t} 由 {s} 啟用於 {when}"),
                    format!(
                        "{s} 啟用了原本停用的帳號 {t} 於 {when}（攻擊者常重新啟用 Guest 等停用帳號）"
                    ),
                ),
                AccountEventKind::PasswordReset => (
                    Severity::Medium,
                    format!("密碼被他人重設: {t}"),
                    format!("帳號 {t} 的密碼由 {s} 重設於 {when}"),
                    format!("{s} 重設了另一個帳號 {t} 的密碼於 {when}（可藉此接管該帳號）"),
                ),
                AccountEventKind::UacChanged(flags) => (
                    Severity::Medium,
                    format!("帳號安全旗標變更: {t}"),
                    format!("帳號 {t} 由 {s} 修改於 {when}：開啟 {}", flags.join(", ")),
                    format!(
                        "{s} 在帳號 {t} 上開啟了 {}，降低了該帳號的安全性（{when}）",
                        flags.join(", ")
                    ),
                ),
            };

            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            f.ts = ae.ts;
            f.artifact = "account".into();
            f.event_id = Some(ae.event_id);
            f.mitre = vec![ae.mitre.into()];
            f.details = details;
            f.reason = Some(reason);
            f.evidence = vec![cairn_core::finding::EvidenceItem {
                artifact: "evtx:Security".into(),
                path: None,
                ts: Some(ae.ts),
                detail: format!(
                    "EID {} record {}: target={} subject={}{}",
                    ae.event_id,
                    ae.record_id,
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

        Ok(crate::stamped(findings, Self::NAME))
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

    fn map(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    fn account_data(target: &str, subject: &str) -> Map<String, Value> {
        map(&[("TargetUserName", target), ("SubjectUserName", subject)])
    }

    fn group_data(member: &str, group: &str, subject: &str) -> Map<String, Value> {
        map(&[
            ("MemberName", member),
            ("TargetUserName", group),
            ("SubjectUserName", subject),
        ])
    }

    fn recent() -> DateTime<Utc> {
        Utc::now() - Duration::days(30)
    }

    fn old() -> DateTime<Utc> {
        Utc::now() - Duration::days(120)
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        AccountHeuristic.analyze(records, &[]).unwrap()
    }

    #[test]
    fn create_account_recent_is_high() {
        let findings = run(&[make_event(
            4720,
            "Security",
            recent(),
            account_data("evil_user", "SYSTEM"),
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1136.001".to_string()));
        assert_eq!(findings[0].artifact, "account");
    }

    #[test]
    fn create_account_old_is_medium() {
        let findings = run(&[make_event(
            4720,
            "Security",
            old(),
            account_data("old_user", "admin"),
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn delete_account_recent_is_high() {
        let findings = run(&[make_event(
            4726,
            "Security",
            recent(),
            account_data("victim", "attacker"),
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].mitre.contains(&"T1531".to_string()));
    }

    #[test]
    fn add_to_local_admins_is_high_and_reason_says_who_whom_what() {
        let findings = run(&[make_event(
            4732,
            "Security",
            old(),
            group_data(r"DESKTOP\evil", "Administrators", "admin"),
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "privileged, even when old"
        );
        assert!(findings[0].mitre.contains(&"T1098.007".to_string()));
        assert!(findings[0].title.contains("Administrators"));
        let reason = findings[0].reason.as_deref().unwrap();
        for part in ["admin", r"DESKTOP\evil", "Administrators"] {
            assert!(reason.contains(part), "{reason}");
        }
    }

    #[test]
    fn add_to_domain_and_enterprise_admins_is_high() {
        for (eid, group) in [(4728, "Domain Admins"), (4756, "Enterprise Admins")] {
            let findings = run(&[make_event(
                eid,
                "Security",
                recent(),
                group_data(r"DOMAIN\evil", group, "DA"),
            )]);
            assert_eq!(findings.len(), 1, "{eid}");
            assert_eq!(findings[0].severity, Severity::High, "{group}");
        }
    }

    #[test]
    fn privileged_group_matched_by_sid_when_name_is_localized() {
        let mut d = group_data("-", "Administratoren", "admin");
        d.insert(
            "MemberSid".into(),
            Value::String("S-1-5-21-1-2-3-1009".into()),
        );
        d.insert("TargetSid".into(), Value::String("S-1-5-32-544".into()));
        let f = run(&[make_event(4732, "Security", recent(), d)]);
        assert_eq!(f[0].severity, Severity::High);
        let reason = f[0].reason.as_deref().unwrap();
        assert!(
            reason.contains("S-1-5-21-1-2-3-1009"),
            "MemberSid used when MemberName is '-': {reason}"
        );
        assert!(is_privileged_group("x", Some("S-1-5-21-9-9-9-512")));
        assert!(is_privileged_group(r"BUILTIN\Remote Desktop Users", None));
    }

    #[test]
    fn ordinary_group_add_is_low() {
        let f = run(&[make_event(
            4732,
            "Security",
            recent(),
            group_data("bob", "Performance Log Users", "admin"),
        )]);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn sigma_duplicate_group_add_is_skipped() {
        let records = vec![make_event(
            4732,
            "Security",
            recent(),
            group_data("evil", "Administrators", "admin"),
        )];
        let mut sigma = Finding::new(
            Severity::High,
            "User Added to Local Administrators",
            FindingSource::Sigma,
        );
        sigma.analyzer = cairn_core::analyzers::SIGMA.into();
        sigma.event_id = Some(4732);
        sigma.evidence_ref = Some("1".into());
        assert!(AccountHeuristic
            .analyze(&records, std::slice::from_ref(&sigma))
            .unwrap()
            .is_empty());
        // a Sigma hit on a different record does not suppress
        sigma.evidence_ref = Some("2".into());
        assert_eq!(
            AccountHeuristic.analyze(&records, &[sigma]).unwrap().len(),
            1
        );
        assert_eq!(
            AccountHeuristic.depends_on(),
            &[cairn_core::analyzers::SIGMA]
        );
    }

    #[test]
    fn account_enabled_is_medium() {
        let f = run(&[make_event(
            4722,
            "Security",
            recent(),
            account_data("Guest", "attacker"),
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        let reason = f[0].reason.as_deref().unwrap();
        assert!(
            reason.contains("attacker") && reason.contains("Guest"),
            "{reason}"
        );
    }

    #[test]
    fn password_reset_by_other_account_is_medium_self_reset_ignored() {
        let mut other = account_data("alice", "helpdesk");
        other.insert(
            "SubjectUserSid".into(),
            Value::String("S-1-5-21-1-1104".into()),
        );
        other.insert("TargetSid".into(), Value::String("S-1-5-21-1-1105".into()));
        let f = run(&[make_event(4724, "Security", recent(), other)]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        let mut own = account_data("alice", "alice");
        own.insert(
            "SubjectUserSid".into(),
            Value::String("S-1-5-21-1-1105".into()),
        );
        own.insert("TargetSid".into(), Value::String("S-1-5-21-1-1105".into()));
        assert!(run(&[make_event(4724, "Security", recent(), own)]).is_empty());
    }

    #[test]
    fn uac_change_flags_risky_bits_only() {
        // 0x10 (normal) -> 0x214 (normal | password not required | don't expire)
        let mut d = account_data("svc", "admin");
        d.insert("OldUacValue".into(), Value::String("0x10".into()));
        d.insert("NewUacValue".into(), Value::String("0x214".into()));
        let f = run(&[make_event(4738, "Security", recent(), d)]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        let reason = f[0].reason.as_deref().unwrap();
        assert!(reason.contains("Password Not Required"), "{reason}");
        assert!(reason.contains("Don't Expire Password"), "{reason}");
        // message-code form
        let mut d = account_data("svc", "admin");
        d.insert(
            "UserAccountControl".into(),
            Value::String("\n\t\t%%2064".into()),
        );
        let f = run(&[make_event(4738, "Security", recent(), d)]);
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("Preauthentication"));
        // a benign change (display name only, UAC untouched) is ignored
        let mut d = account_data("svc", "admin");
        d.insert("OldUacValue".into(), Value::String("0x10".into()));
        d.insert("NewUacValue".into(), Value::String("0x10".into()));
        d.insert("UserAccountControl".into(), Value::String("-".into()));
        assert!(run(&[make_event(4738, "Security", recent(), d)]).is_empty());
    }

    #[test]
    fn non_security_channel_ignored() {
        assert!(run(&[make_event(
            4720,
            "System",
            recent(),
            account_data("user", "admin")
        )])
        .is_empty());
    }

    #[test]
    fn wrong_eid_ignored() {
        assert!(run(&[make_event(
            4625,
            "Security",
            recent(),
            account_data("user", "admin")
        )])
        .is_empty());
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
        assert!(run(&records).is_empty());
    }

    #[test]
    fn reason_mentions_time_window() {
        let findings = run(&[make_event(
            4720,
            "Security",
            recent(),
            account_data("user", "admin"),
        )]);
        let reason = findings[0].reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("90") || reason.contains("近期"),
            "reason must mention window: {reason}"
        );
    }

    #[test]
    fn account_finding_carries_evtx_evidence() {
        let f = &run(&[make_event(
            4720,
            "Security",
            recent(),
            account_data("u", "admin"),
        )])[0];
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].artifact, "evtx:Security");
        assert!(f.evidence[0].detail.contains("EID 4720"));
        assert_eq!(f.analyzer, AccountHeuristic::NAME);
    }

    #[test]
    fn subject_domain_is_shown() {
        let mut d = account_data("u", "admin");
        d.insert("SubjectDomainName".into(), Value::String("CORP".into()));
        let f = run(&[make_event(4720, "Security", recent(), d)]);
        assert!(f[0].reason.as_deref().unwrap().contains(r"CORP\admin"));
    }
}
