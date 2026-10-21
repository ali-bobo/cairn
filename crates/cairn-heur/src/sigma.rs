//! SigmaAnalyzer: runs Engine::match_event over Record::Event in the record stream.

use cairn_core::finding::{EvidenceItem, Finding};
use cairn_core::observation::{
    LoggingRequirement, RuleViability, SigmaRuleStatus, CATEGORY_SIGMA_RULE,
};
use cairn_core::record::{EventRecord, PostureRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Observation, Result};
use cairn_sigma::engine::Engine;
use cairn_sigma::viability::HostLogging;
use cairn_sigma::SigmaMatcher;
use std::collections::BTreeMap;

/// Wraps a loaded Sigma Engine as an Analyzer.
/// Processes only Record::Event; all other variants are silently ignored.
pub struct SigmaAnalyzer {
    engine: Engine,
}

impl SigmaAnalyzer {
    pub fn new(engine: Engine) -> Self {
        SigmaAnalyzer { engine }
    }

    /// Ruleset version string from the loaded Engine (`"<pin>+<aggregate>"` or `""`).
    pub fn ruleset_ver(&self) -> &str {
        self.engine.ruleset_ver()
    }

    /// Channels referenced by the loaded rules (load-optimization hint for EvtxLiveCollector).
    pub fn channels(&self) -> &[String] {
        self.engine.referenced_channels()
    }
}

impl SigmaAnalyzer {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::SIGMA;
}

impl Analyzer for SigmaAnalyzer {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for record in records {
            if let Record::Event(ev) = record {
                match self.engine.match_event(ev) {
                    Ok(mut fs) => findings.append(&mut fs),
                    Err(e) => tracing::warn!(error = %e, "sigma match error; skipping event"),
                }
            }
        }
        Ok(crate::stamped(aggregate(findings), Self::NAME))
    }

    /// One `sigma_rule` observation per loaded rule: could it fire on this host's logs?
    /// Decided from the events this run collected (see `cairn_sigma::viability`), with
    /// the live `posture` snapshot's settings filling in what the events cannot show.
    fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> {
        let events: Vec<&EventRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Event(ev) => Some(ev),
                _ => None,
            })
            .collect();
        let host_name = events
            .iter()
            .map(|e| e.computer.as_str())
            .find(|c| !c.is_empty())
            .unwrap_or_default()
            .to_string();
        let mut logging = HostLogging::from_events(events.iter().copied());
        if let Some(p) = records.iter().find_map(|r| match r {
            Record::Posture(p) => Some(p),
            _ => None,
        }) {
            apply_posture(&mut logging, p);
        }
        Ok(self
            .engine
            .rule_statuses(&logging)
            .into_iter()
            .map(|(profile, status)| {
                let mut o = Observation::new(CATEGORY_SIGMA_RULE, profile.title.clone());
                o.host = host_name.clone();
                o.source_artifact = "sigma".into();
                o.details = status_details(&status);
                o.sigma_rule = Some(status);
                o
            })
            .collect())
    }
}

/// Hits of one rule on one host above this count are merged into a single finding.
pub const AGGREGATE_ABOVE: usize = 3;
/// Most individual hits listed as evidence on a merged finding.
pub const AGGREGATE_EVIDENCE_MAX: usize = 20;

/// Merge floods: when a rule matches more than [`AGGREGATE_ABOVE`] events on a host, one
/// finding stands for all of them (time span in `details`, each hit's record and matched
/// fields as evidence) instead of hundreds of identical rows. Fewer hits stay separate.
/// Output keeps the first-seen order of each rule.
fn aggregate(findings: Vec<Finding>) -> Vec<Finding> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut groups: BTreeMap<(String, String), Vec<Finding>> = BTreeMap::new();
    for f in findings {
        let key = (
            f.rule_id.clone().unwrap_or_else(|| f.title.clone()),
            f.host.clone(),
        );
        let g = groups.entry(key.clone()).or_default();
        if g.is_empty() {
            order.push(key);
        }
        g.push(f);
    }
    let mut out = Vec::new();
    for key in order {
        let Some(mut group) = groups.remove(&key) else {
            continue;
        };
        if group.len() <= AGGREGATE_ABOVE {
            out.append(&mut group);
            continue;
        }
        group.sort_by_key(|f| f.ts);
        let n = group.len();
        let (first_ts, last_ts) = (group[0].ts, group[n - 1].ts);
        let same_eid = group.iter().all(|f| f.event_id == group[0].event_id);
        let mut evidence: Vec<EvidenceItem> = group
            .iter()
            .take(AGGREGATE_EVIDENCE_MAX)
            .map(|f| EvidenceItem {
                artifact: f.artifact.clone(),
                path: None,
                ts: Some(f.ts),
                detail: hit_detail(f),
            })
            .collect();
        if n > AGGREGATE_EVIDENCE_MAX {
            evidence.push(EvidenceItem {
                artifact: group[0].artifact.clone(),
                path: None,
                ts: None,
                detail: format!("{} more matches not listed", n - AGGREGATE_EVIDENCE_MAX),
            });
        }
        // The earliest hit (index 0 after the sort) carries the merged finding.
        let mut merged = group.swap_remove(0);
        merged.ts = first_ts;
        if !same_eid {
            merged.event_id = None;
        }
        let first_fields = std::mem::take(&mut merged.details);
        merged.details = format!(
            "{n} matches from {} to {}; first {}",
            first_ts.to_rfc3339(),
            last_ts.to_rfc3339(),
            if first_fields.is_empty() {
                "match".to_string()
            } else {
                first_fields
            }
        );
        merged.evidence = evidence;
        out.push(merged);
    }
    out
}

/// `record 123 (EID 4688): matched fields: ...` for one hit.
fn hit_detail(f: &Finding) -> String {
    let mut s = format!("record {}", f.evidence_ref.as_deref().unwrap_or("?"));
    if let Some(eid) = f.event_id {
        s.push_str(&format!(" (EID {eid})"));
    }
    if !f.details.is_empty() {
        s.push_str(": ");
        s.push_str(&f.details);
    }
    s
}

/// Plain technical summary of a rule status (the report words it for people).
fn status_details(s: &SigmaRuleStatus) -> String {
    let names = |v: &[LoggingRequirement]| {
        v.iter()
            .map(|r| {
                serde_json::to_value(r)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    match s.viability {
        RuleViability::Runnable => "runnable".into(),
        RuleViability::MissingLogging => format!("cannot fire: missing {}", names(&s.missing)),
        RuleViability::Unknown => format!("unknown: could not check {}", names(&s.unknown)),
    }
}

/// Feed the read settings from a posture snapshot into `logging`. A setting read as
/// off does not override events that prove it was on during the collected window
/// (the policy may have been changed since); unread settings (None) stay inferred.
fn apply_posture(logging: &mut HostLogging, p: &PostureRecord) {
    use LoggingRequirement as R;
    let settings = [
        (R::ProcessCreationAudit, p.audit_process_creation),
        (R::CommandLineIn4688, p.cmdline_in_4688),
        (R::ScriptBlockLogging, p.ps_scriptblock),
        (R::ModuleLogging, p.ps_module_logging),
        (R::Sysmon, p.sysmon_present),
        (R::LogonAudit, p.audit_logon),
        (
            R::UserAccountManagementAudit,
            p.audit_user_account_management,
        ),
        (
            R::SecurityGroupManagementAudit,
            p.audit_security_group_management,
        ),
        (R::OtherObjectAccessAudit, p.audit_other_object_access),
    ];
    for (req, read) in settings {
        match read {
            Some(true) => logging.set(req, true),
            Some(false) if logging.state(req) != Some(true) => logging.set(req, false),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::{EventRecord, ProcessRecord};
    use cairn_sigma::engine::Engine;
    use chrono::Utc;
    use serde_json::Map;

    const RULE_CMD: &str = r#"
title: Test CMD detection
id: 11111111-1111-1111-1111-111111111111
status: test
description: detects cmd.exe
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
level: high
author: test
"#;

    fn make_event(image: &str) -> EventRecord {
        let mut data = Map::new();
        data.insert(
            "NewProcessName".to_string(),
            serde_json::Value::String(image.to_string()),
        );
        data.insert(
            "Image".to_string(),
            serde_json::Value::String(image.to_string()),
        );
        EventRecord {
            ts: Utc::now(),
            channel: "Security".to_string(),
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST-PC".to_string(),
            record_id: 1,
            data,
        }
    }

    fn make_proc_record() -> Record {
        Record::Process(ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "notepad.exe".into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        })
    }

    #[test]
    fn sigma_analyzer_ignores_non_event_records() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let records = vec![make_proc_record()];
        let findings = analyzer.analyze(&records, &[]).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn sigma_analyzer_empty_records_returns_empty() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let findings = analyzer.analyze(&[], &[]).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn sigma_analyzer_match_fires_finding() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let ev = make_event(r"C:\Windows\System32\cmd.exe");
        let records = vec![Record::Event(ev)];
        let findings = analyzer.analyze(&records, &[]).unwrap();
        assert!(!findings.is_empty(), "cmd.exe should trigger the rule");
        assert_eq!(findings[0].rule_author.as_deref(), Some("test"));
    }

    fn numbered(image: &str, record_id: u64, secs: i64) -> Record {
        let mut ev = make_event(image);
        ev.record_id = record_id;
        ev.ts = chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap();
        Record::Event(ev)
    }

    #[test]
    fn few_hits_stay_separate_with_matched_fields() {
        let analyzer = SigmaAnalyzer::new(Engine::from_rules(&[RULE_CMD]).unwrap());
        let records: Vec<Record> = (0..AGGREGATE_ABOVE as u64)
            .map(|i| numbered(r"C:\Windows\System32\cmd.exe", i + 1, i as i64))
            .collect();
        let findings = analyzer.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), AGGREGATE_ABOVE);
        assert!(
            findings[0]
                .details
                .contains(r"Image=C:\Windows\System32\cmd.exe"),
            "{}",
            findings[0].details
        );
        assert!(findings[0].evidence.is_empty());
    }

    #[test]
    fn flood_of_one_rule_merges_into_one_finding() {
        let analyzer = SigmaAnalyzer::new(Engine::from_rules(&[RULE_CMD]).unwrap());
        let n = AGGREGATE_EVIDENCE_MAX + 5;
        // Out of time order on purpose: the merged finding takes the earliest hit.
        let mut records: Vec<Record> = (0..n as u64)
            .map(|i| numbered(r"C:\Windows\System32\cmd.exe", i + 100, i as i64 + 10))
            .collect();
        records.push(numbered(r"C:\Windows\System32\cmd.exe", 7, 0));
        let findings = analyzer.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = &findings[0];
        assert_eq!(f.evidence_ref.as_deref(), Some("7"));
        assert_eq!(f.ts.timestamp(), 1_700_000_000);
        assert!(
            f.details.starts_with(&format!("{} matches from ", n + 1)),
            "{}",
            f.details
        );
        assert!(f.details.contains("Image="), "{}", f.details);
        assert_eq!(f.evidence.len(), AGGREGATE_EVIDENCE_MAX + 1);
        assert!(f.evidence[0]
            .detail
            .starts_with("record 7 (EID 4688): matched fields: "));
        assert_eq!(f.event_id, Some(4688));
        assert_eq!(
            f.rule_author.as_deref(),
            Some("test"),
            "DRL 1.1 survives merging"
        );
        assert_eq!(f.analyzer, SigmaAnalyzer::NAME);
    }

    #[test]
    fn observe_reports_each_rule_viability() {
        let analyzer = SigmaAnalyzer::new(Engine::from_rules(&[RULE_CMD]).unwrap());
        // A Security log with no 4688: process-creation auditing is off.
        let mut ev = make_event("x");
        ev.event_id = 4624;
        let obs = analyzer.observe(&[Record::Event(ev)]).unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].category, CATEGORY_SIGMA_RULE);
        assert_eq!(obs[0].host, "TEST-PC");
        let s = obs[0].sigma_rule.as_ref().unwrap();
        assert_eq!(s.viability, RuleViability::MissingLogging);
        assert!(s
            .missing
            .contains(&LoggingRequirement::ProcessCreationAudit));
        assert!(
            obs[0].details.contains("process_creation_audit"),
            "{}",
            obs[0].details
        );

        let obs = analyzer
            .observe(&[Record::Event(make_event(r"C:\a.exe"))])
            .unwrap();
        assert_eq!(
            obs[0].sigma_rule.as_ref().unwrap().viability,
            RuleViability::Runnable,
            "a seen 4688 proves auditing; the rule needs no command line"
        );
    }

    #[test]
    fn observe_takes_logging_settings_from_posture() {
        use cairn_core::record::PostureRecord;
        let analyzer = SigmaAnalyzer::new(Engine::from_rules(&[RULE_CMD]).unwrap());
        let mut logon = make_event("x");
        logon.event_id = 4624;
        let on = PostureRecord {
            audit_process_creation: Some(true),
            ..Default::default()
        };
        let obs = analyzer
            .observe(&[Record::Event(logon), Record::Posture(on)])
            .unwrap();
        assert_eq!(
            obs[0].sigma_rule.as_ref().unwrap().viability,
            RuleViability::Runnable,
            "posture says process-creation auditing is on, though no 4688 was collected"
        );

        let off = PostureRecord {
            audit_process_creation: Some(false),
            ..Default::default()
        };
        let obs = analyzer
            .observe(&[Record::Event(make_event(r"C:\a.exe")), Record::Posture(off)])
            .unwrap();
        assert_eq!(
            obs[0].sigma_rule.as_ref().unwrap().viability,
            RuleViability::Runnable,
            "a collected 4688 outweighs a policy read as off now"
        );
    }

    #[test]
    fn sigma_analyzer_no_match_returns_empty() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let ev = make_event(r"C:\Windows\System32\notepad.exe");
        let records = vec![Record::Event(ev)];
        let findings = analyzer.analyze(&records, &[]).unwrap();
        assert!(
            findings.is_empty(),
            "notepad.exe should not trigger cmd rule"
        );
    }
}
