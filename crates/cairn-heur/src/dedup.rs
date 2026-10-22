//! The same-evidence rule: one piece of evidence, one heuristic finding.
//!
//! Several analyzers can judge the same evidence: a System 7045 service install is
//! read by `heur_eventlog` (service install, T1543.003) and by `heur_lateral`
//! (remote-execution service, T1569.002); a Defender exclusion is seen by
//! `heur_defense` in the registry and by `heur_eventlog` in the 5007 event that added
//! it; a Sigma rule can match the very event a heuristic judges. Reporting each one
//! separately makes analysts read the same thing two or three times.
//!
//! The rule, applied by the analyzer that runs LATER (its `depends_on()` names the
//! earlier one), with evidence matched on typed fields only, never on titles or
//! reason text ([`EvidenceKey`]):
//!
//! 1. No earlier finding covers the evidence: emit as usual.
//! 2. An earlier heuristic finding covers it: emit ONE merged finding that keeps the
//!    later analyzer's title and wording, the higher severity, every ATT&CK technique
//!    of both, the earlier reason (appended) and an evidence line per merged finding,
//!    and list the earlier finding in `Finding.supersedes`; the orchestrator then
//!    drops it.
//! 3. Only Sigma findings cover it: a Sigma finding is never dropped (the rule hit and
//!    its author attribution stay, DRL 1.1). The heuristic finding is skipped when it
//!    adds nothing — its severity is not higher and every technique it names is
//!    already among the Sigma rule's (compared at the parent technique, so T1098.007
//!    is covered by `attack.t1098`). Otherwise it is emitted merged as in 2, without
//!    superseding the Sigma finding.
//!
//! Ordering (declared through `depends_on()`): Sigma -> `heur_account`; Sigma ->
//! `heur_eventlog` -> `heur_lateral` (7045) and `heur_defense` (Defender
//! exclusions). The later analyzer of each pair is the more specific one, so the
//! merged finding carries its sharper title and wording.
#![forbid(unsafe_code)]

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, ExclusionKind};
use cairn_core::Finding;
use chrono::{DateTime, Utc};

/// What a finding is about, as typed data.
#[derive(Debug, Clone)]
pub(crate) enum EvidenceKey {
    /// One event: channel, event ID, record id and its timestamp. Record ids repeat
    /// across logs of different hosts, so the time must match too.
    Event {
        channel: String,
        event_id: u32,
        record_id: u64,
        ts: DateTime<Utc>,
    },
    /// One Defender exclusion: its list (path / extension / process / IP) and value.
    Exclusion { kind: ExclusionKind, value: String },
}

impl EvidenceKey {
    pub(crate) fn event(ev: &EventRecord) -> Self {
        EvidenceKey::Event {
            channel: ev.channel.clone(),
            event_id: ev.event_id,
            record_id: ev.record_id,
            ts: ev.ts,
        }
    }
}

/// `evtx:<channel>` as findings spell their artifact.
fn evtx_artifact(channel: &str) -> String {
    format!("evtx:{channel}")
}

/// The exclusion list a registry key names (`...\Exclusions\Paths` -> Path).
pub(crate) fn exclusion_kind_of_key(key: &str) -> Option<ExclusionKind> {
    let leaf = key.trim_end_matches('\\').rsplit('\\').next()?;
    match leaf.to_ascii_lowercase().as_str() {
        "paths" => Some(ExclusionKind::Path),
        "extensions" => Some(ExclusionKind::Extension),
        "processes" => Some(ExclusionKind::Process),
        "ipaddresses" => Some(ExclusionKind::IpAddress),
        _ => None,
    }
}

/// True when `f` reports the evidence `key` names.
///
/// - Event: same event ID, `evtx:<channel>` artifact and time, and the record id in
///   `evidence_ref` (heuristics write `<channel>#<id>`, Sigma the bare id). A Sigma
///   finding that merged a flood of hits lists each hit as an evidence item with its
///   artifact and time; one of those matching counts too.
/// - Exclusion: a finding whose registry entity names the same exclusion list and
///   value (case-insensitive; Windows paths and names are).
pub(crate) fn covers(f: &Finding, key: &EvidenceKey) -> bool {
    match key {
        EvidenceKey::Event {
            channel,
            event_id,
            record_id,
            ts,
        } => {
            if !f
                .artifact
                .eq_ignore_ascii_case(&evtx_artifact(channel.as_str()))
            {
                return false;
            }
            let eid_ok = f.event_id.is_none_or(|e| e == *event_id);
            if !eid_ok {
                return false;
            }
            let rid = record_id.to_string();
            let primary = f.event_id == Some(*event_id)
                && f.ts == *ts
                && f.evidence_ref.as_deref().is_some_and(|r| {
                    r == rid
                        || r.rsplit_once('#')
                            .is_some_and(|(ch, id)| id == rid && ch.eq_ignore_ascii_case(channel))
                });
            let listed = f.source == FindingSource::Sigma
                && f.evidence.iter().any(|e| {
                    e.ts == Some(*ts) && e.artifact.eq_ignore_ascii_case(&evtx_artifact(channel))
                });
            primary || listed
        }
        EvidenceKey::Exclusion { kind, value } => f.entity.registry.as_ref().is_some_and(|r| {
            exclusion_kind_of_key(&r.key) == Some(*kind) && r.value.eq_ignore_ascii_case(value)
        }),
    }
}

fn rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// An ATT&CK technique ID in the heuristic spelling (`T1543.003`), from either
/// spelling (`attack.t1543.003`); None for tactics and other tags.
pub(crate) fn technique_id(tag: &str) -> Option<String> {
    let t = tag.trim();
    let t = t.strip_prefix("attack.").unwrap_or(t).to_ascii_uppercase();
    let digits = t.strip_prefix('T')?;
    let (main, sub) = match digits.split_once('.') {
        Some((m, s)) => (m, Some(s)),
        None => (digits, None),
    };
    let ok = main.len() == 4
        && main.bytes().all(|b| b.is_ascii_digit())
        && sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()));
    ok.then_some(t)
}

fn parent(technique: &str) -> &str {
    technique.split('.').next().unwrap_or(technique)
}

/// Short zh-TW name of who else reported the evidence, for the merged client text.
fn reporter_label(f: &Finding) -> String {
    match f.analyzer.as_str() {
        cairn_core::analyzers::SIGMA => format!("Sigma 規則「{}」", f.title),
        cairn_core::analyzers::EVENTLOG => "事件記錄檢查（服務安裝 / Defender 設定事件）".into(),
        cairn_core::analyzers::LATERAL => "橫向移動檢查".into(),
        cairn_core::analyzers::DEFENSE => "防護設定檢查（登錄檔）".into(),
        cairn_core::analyzers::ACCOUNT => "帳號異動檢查".into(),
        other => other.to_string(),
    }
}

/// One line naming an earlier finding merged into this one (English, for `reason`).
fn merged_reason(p: &Finding) -> String {
    let why = if p.source == FindingSource::Sigma {
        format!(
            "Sigma rule \"{}\" by {}",
            p.title,
            p.rule_author.as_deref().unwrap_or("unknown author")
        )
    } else {
        p.reason.clone().unwrap_or_else(|| p.title.clone())
    };
    format!(
        "same evidence also reported by {} ({:?}): {why}",
        p.analyzer, p.severity
    )
}

/// Apply the same-evidence rule (module docs) to `own`, a finding about `key`, given
/// every earlier finding of this run. None = skip it (a Sigma finding already says
/// everything it would).
pub(crate) fn resolve(mut own: Finding, key: &EvidenceKey, prior: &[Finding]) -> Option<Finding> {
    let covering: Vec<&Finding> = prior.iter().filter(|p| covers(p, key)).collect();
    if covering.is_empty() {
        return Some(own);
    }
    let any_heuristic = covering.iter().any(|p| p.source != FindingSource::Sigma);
    if !any_heuristic {
        let prior_max = covering.iter().map(|p| rank(p.severity)).max().unwrap_or(0);
        let prior_parents: Vec<String> = covering
            .iter()
            .flat_map(|p| p.mitre.iter().filter_map(|m| technique_id(m)))
            .map(|t| parent(&t).to_string())
            .collect();
        let adds_technique = own
            .mitre
            .iter()
            .filter_map(|m| technique_id(m))
            .any(|t| !prior_parents.iter().any(|p| p == parent(&t)));
        if rank(own.severity) <= prior_max && !adds_technique {
            return None;
        }
    }
    let mut labels: Vec<String> = Vec::new();
    // Heuristic findings first: one of them may already have merged the Sigma hit,
    // whose line is then not repeated.
    let mut covering = covering;
    covering.sort_by_key(|p| p.source == FindingSource::Sigma);
    for p in &covering {
        if rank(p.severity) > rank(own.severity) {
            own.severity = p.severity;
        }
        for t in p.mitre.iter().filter_map(|m| technique_id(m)) {
            if !own
                .mitre
                .iter()
                .any(|m| technique_id(m).as_deref() == Some(t.as_str()))
            {
                own.mitre.push(t);
            }
        }
        let line = merged_reason(p);
        own.reason = Some(match own.reason.take() {
            Some(r) if r.contains(&line) => r,
            Some(r) if !r.is_empty() => format!("{r}; {line}"),
            _ => line,
        });
        own.evidence.push(EvidenceItem {
            artifact: p.artifact.clone(),
            path: None,
            ts: Some(p.ts),
            detail: format!(
                "merged: {} finding \"{}\" ({:?}) on the same evidence",
                p.analyzer, p.title, p.severity
            ),
        });
        if p.source != FindingSource::Sigma {
            own.supersedes.push(p.id);
        }
        let label = reporter_label(p);
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if let Some(text) = own.details_client.as_mut() {
        text.push_str(&format!(
            "（同一筆證據也被{}判讀到，已合併為這一筆，風險等級取兩者中較高者。）",
            labels.join("、")
        ));
    }
    Some(own)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::EntityRegistry;
    use serde_json::Map;

    fn ts() -> DateTime<Utc> {
        "2026-10-20T08:00:00Z".parse().unwrap()
    }

    fn ev(record_id: u64) -> EventRecord {
        EventRecord {
            ts: ts(),
            channel: "System".into(),
            event_id: 7045,
            provider: "p".into(),
            computer: "WS01".into(),
            record_id,
            data: Map::new(),
        }
    }

    fn heur(analyzer: &str, sev: Severity, mitre: &[&str], e: &EventRecord) -> Finding {
        let mut f = Finding::new(sev, format!("{analyzer} title"), FindingSource::Heuristic);
        f.analyzer = analyzer.into();
        f.ts = e.ts;
        f.artifact = format!("evtx:{}", e.channel);
        f.event_id = Some(e.event_id);
        f.evidence_ref = Some(format!("{}#{}", e.channel, e.record_id));
        f.mitre = mitre.iter().map(|m| m.to_string()).collect();
        f.reason = Some(format!("{analyzer} reason"));
        f.details_client = Some("說明。".into());
        f
    }

    fn sigma(sev: Severity, tags: &[&str], e: &EventRecord) -> Finding {
        let mut f = Finding::new(sev, "Rule Title", FindingSource::Sigma);
        f.analyzer = cairn_core::analyzers::SIGMA.into();
        f.rule_author = Some("Author".into());
        f.ts = e.ts;
        f.artifact = format!("evtx:{}", e.channel);
        f.event_id = Some(e.event_id);
        f.evidence_ref = Some(e.record_id.to_string());
        f.mitre = tags.iter().map(|m| m.to_string()).collect();
        f
    }

    #[test]
    fn technique_ids_from_both_spellings() {
        assert_eq!(
            technique_id("attack.t1543.003").as_deref(),
            Some("T1543.003")
        );
        assert_eq!(technique_id("T1021").as_deref(), Some("T1021"));
        assert_eq!(technique_id("attack.persistence"), None);
        assert_eq!(technique_id("car.2013-09-005"), None);
        assert_eq!(technique_id("attack.t15"), None);
    }

    #[test]
    fn nothing_covering_keeps_the_finding_unchanged() {
        let e = ev(7);
        let own = heur("heur_lateral", Severity::High, &["T1569.002"], &e);
        let other = heur("heur_eventlog", Severity::Low, &["T1543.003"], &ev(8));
        let out = resolve(own, &EvidenceKey::event(&e), &[other]).unwrap();
        assert!(out.supersedes.is_empty());
        assert_eq!(out.mitre, vec!["T1569.002"]);
    }

    #[test]
    fn earlier_heuristic_is_merged_and_superseded() {
        let e = ev(7);
        let earlier = heur("heur_eventlog", Severity::Medium, &["T1543.003"], &e);
        let own = heur(
            "heur_lateral",
            Severity::High,
            &["T1569.002", "T1021.002"],
            &e,
        );
        let out = resolve(own, &EvidenceKey::event(&e), std::slice::from_ref(&earlier)).unwrap();
        assert_eq!(out.severity, Severity::High);
        assert_eq!(out.mitre, vec!["T1569.002", "T1021.002", "T1543.003"]);
        assert_eq!(out.supersedes, vec![earlier.id]);
        let reason = out.reason.unwrap();
        assert!(reason.contains("heur_lateral reason") && reason.contains("heur_eventlog reason"));
        assert!(out.details_client.unwrap().contains("已合併"));
        assert_eq!(out.evidence.len(), 1);
    }

    #[test]
    fn merged_finding_keeps_the_higher_severity_of_the_earlier_one() {
        let e = ev(7);
        let earlier = heur("heur_eventlog", Severity::High, &["T1543.003"], &e);
        let own = heur("heur_lateral", Severity::Medium, &["T1569.002"], &e);
        let out = resolve(own, &EvidenceKey::event(&e), &[earlier]).unwrap();
        assert_eq!(out.severity, Severity::High);
    }

    #[test]
    fn sigma_alone_skips_a_heuristic_that_adds_nothing() {
        let e = ev(7);
        let s = sigma(
            Severity::High,
            &["attack.persistence", "attack.t1543.003"],
            &e,
        );
        let own = heur("heur_eventlog", Severity::High, &["T1543.003"], &e);
        assert!(resolve(own, &EvidenceKey::event(&e), std::slice::from_ref(&s)).is_none());
        // Sub-technique of a technique the rule already names: still nothing new.
        let s = sigma(Severity::Medium, &["attack.t1098"], &e);
        let own = heur("heur_account", Severity::Medium, &["T1098.007"], &e);
        assert!(resolve(own, &EvidenceKey::event(&e), &[s]).is_none());
    }

    #[test]
    fn sigma_is_never_superseded_but_a_higher_heuristic_is_kept_merged() {
        let e = ev(7);
        let s = sigma(Severity::Medium, &["attack.t1543.003"], &e);
        let own = heur("heur_eventlog", Severity::High, &["T1543.003"], &e);
        let out = resolve(own, &EvidenceKey::event(&e), std::slice::from_ref(&s)).unwrap();
        assert_eq!(out.severity, Severity::High);
        assert!(out.supersedes.is_empty());
        assert!(out
            .reason
            .unwrap()
            .contains("Sigma rule \"Rule Title\" by Author"));
        // A new technique keeps it even at equal severity.
        let s = sigma(Severity::High, &["attack.t1543.003"], &e);
        let own = heur("heur_lateral", Severity::High, &["T1569.002"], &e);
        let out = resolve(own, &EvidenceKey::event(&e), &[s]).unwrap();
        assert!(out.mitre.contains(&"T1543.003".to_string()));
    }

    #[test]
    fn sigma_flood_finding_covers_its_listed_hits() {
        let e = ev(7);
        let mut s = sigma(Severity::High, &["attack.t1543.003"], &ev(3));
        s.ts = "2026-10-20T07:00:00Z".parse().unwrap();
        s.evidence.push(EvidenceItem {
            artifact: "evtx:System".into(),
            path: None,
            ts: Some(e.ts),
            detail: "record 7 (EID 7045)".into(),
        });
        assert!(covers(&s, &EvidenceKey::event(&e)));
        // Another channel's event at the same second is not covered.
        let mut other = ev(7);
        other.channel = "Security".into();
        assert!(!covers(&s, &EvidenceKey::event(&other)));
    }

    #[test]
    fn same_record_id_at_another_time_is_another_event() {
        let e = ev(7);
        let mut earlier = heur("heur_eventlog", Severity::Medium, &["T1543.003"], &e);
        earlier.ts = "2020-01-01T00:00:00Z".parse().unwrap();
        assert!(!covers(&earlier, &EvidenceKey::event(&e)));
    }

    /// Through the orchestrator with the real analyzers: a PsExec-style 7045 is ONE
    /// finding (heur_lateral's, carrying heur_eventlog's technique and reason), and a
    /// Defender exclusion seen in the registry and in its 5007 event is ONE finding
    /// (heur_defense's, with the event as evidence).
    #[test]
    fn real_analyzers_report_shared_evidence_once() {
        use cairn_core::record::{DefenderExclusion, PostureRecord, Record};
        use cairn_core::traits::Analyzer;
        let mk = |channel: &str, id: u32, rid: u64, data: serde_json::Value| {
            Record::Event(EventRecord {
                ts: ts(),
                channel: channel.into(),
                event_id: id,
                provider: "p".into(),
                computer: "WS01".into(),
                record_id: rid,
                data: data.as_object().unwrap().clone(),
            })
        };
        let records = vec![
            mk(
                "System",
                7045,
                1,
                serde_json::json!({"ServiceName": "KgX", "ImagePath": r"%SYSTEMROOT%\duKhLYUX.exe"}),
            ),
            mk(
                crate::eventlog::DEFENDER_CHANNEL,
                5007,
                2,
                serde_json::json!({"New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0"}),
            ),
            Record::Posture(PostureRecord {
                defender_exclusions: vec![DefenderExclusion {
                    kind: ExclusionKind::Path,
                    value: r"C:\Users\Public".into(),
                    policy: false,
                    key: r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths".into(),
                    last_write: None,
                }],
                ..PostureRecord::default()
            }),
        ];
        // Registry order puts heur_eventlog after heur_defense and heur_lateral after
        // it; depends_on() must still run the generic analyzer first.
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(crate::DefenseHeuristic),
            Box::new(crate::LateralHeuristic),
            Box::new(crate::EventLogHeuristic),
        ];
        let out = cairn_core::orchestrator::run_analyzers(&records, &analyzers);
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        let svc: Vec<&Finding> = out
            .findings
            .iter()
            .filter(|f| f.event_id == Some(7045))
            .collect();
        assert_eq!(svc.len(), 1, "{:#?}", out.findings);
        assert_eq!(svc[0].analyzer, cairn_core::analyzers::LATERAL);
        assert_eq!(svc[0].severity, Severity::High);
        assert!(svc[0].mitre.contains(&"T1543.003".to_string()));
        assert!(svc[0].mitre.contains(&"T1569.002".to_string()));
        assert!(svc[0].reason.as_deref().unwrap().contains("heur_eventlog"));
        let excl: Vec<&Finding> = out
            .findings
            .iter()
            .filter(|f| f.mitre.contains(&"T1562.001".to_string()))
            .collect();
        assert_eq!(excl.len(), 1, "{:#?}", out.findings);
        assert_eq!(excl[0].analyzer, cairn_core::analyzers::DEFENSE);
        assert_eq!(excl[0].severity, Severity::High);
        assert!(excl[0]
            .evidence
            .iter()
            .any(|e| e.ts == Some(ts()) && e.artifact.contains("Defender")));
        assert_eq!(out.findings.len(), 2, "{:#?}", out.findings);
    }

    #[test]
    fn exclusion_key_matches_the_registry_entity() {
        let mut f = Finding::new(Severity::High, "x", FindingSource::Heuristic);
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths".into(),
            value: r"C:\Temp".into(),
            data: String::new(),
            last_write: None,
        });
        let k = |kind, v: &str| EvidenceKey::Exclusion {
            kind,
            value: v.into(),
        };
        assert!(covers(&f, &k(ExclusionKind::Path, r"c:\temp")));
        assert!(!covers(&f, &k(ExclusionKind::Process, r"C:\Temp")));
        assert!(!covers(&f, &k(ExclusionKind::Path, r"C:\Temp2")));
    }
}
