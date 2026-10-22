//! Rule viability: can a Sigma rule ever fire on this host's logs?
//!
//! Most of a stock Sigma rule set is written against Sysmon or against audit settings a
//! default Windows install leaves off, so a clean Sigma result means little unless the
//! report also says which rules could have matched at all. This module answers that in
//! two steps:
//!
//! 1. **Static profile** ([`RuleProfile`], from the rule YAML). The logsource is resolved
//!    through [`LogsourceMap`] to concrete (channel, event ID) alternatives, each with
//!    the logging settings it needs ([`LoggingRequirement`]). For `process_creation` the
//!    detection is evaluated abstractly against the fields a Security 4688 actually
//!    carries: a rule whose condition needs `OriginalFileName`, `Hashes`,
//!    `ParentCommandLine`, ... in every branch can only fire through Sysmon, and one
//!    that needs `CommandLine` in every branch also needs command-line auditing.
//! 2. **Host check** ([`HostLogging`] + [`assess`]). What is known about the host's
//!    logging (set explicitly from a posture snapshot, or inferred from the events this
//!    run collected) decides each requirement: on, off, or unknown. The best alternative
//!    gives the rule's [`RuleViability`].
//!
//! The detection section is read with `serde_norway` because sigma-rust keeps its
//! detection/selection types private.

use crate::LogsourceMap;
use cairn_core::observation::{LoggingRequirement, RuleViability, SigmaRuleStatus};
use cairn_core::record::EventRecord;
use cairn_core::{CairnError, Result};
use serde_norway::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Channel names the requirement table keys on.
const SECURITY: &str = "Security";
const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";
const PS_OPERATIONAL: &str = "Microsoft-Windows-PowerShell/Operational";
const PS_CLASSIC: &str = "Windows PowerShell";
const NTLM: &str = "Microsoft-Windows-NTLM/Operational";
const TASK_SCHEDULER: &str = "Microsoft-Windows-TaskScheduler/Operational";

/// Fields a Security 4688 event offers a Sigma rule: its EventData, the System fields,
/// and the `LogsourceMap` aliases (`Image`, `ParentImage`). Everything a Sysmon EID 1
/// has beyond this (OriginalFileName, Hashes, ParentCommandLine, Company, Product,
/// Description, CurrentDirectory, IntegrityLevel, User, LogonId, ...) is absent.
const FIELDS_4688: &[&str] = &[
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
    "NewProcessId",
    "NewProcessName",
    "TokenElevationType",
    "ProcessId",
    "CommandLine",
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetLogonId",
    "ParentProcessName",
    "MandatoryLabel",
    "Image",
    "ParentImage",
];

/// System-section fields every event carries (always available to a rule).
const SYSTEM_FIELDS: &[&str] = &[
    "EventID",
    "Channel",
    "Provider_Name",
    "Computer",
    "EventRecordID",
    "Level",
    "Task",
    "Keywords",
    "TimeCreated",
    "Version",
    "Opcode",
    "Correlation",
    "Execution",
    "Security",
];

/// Fields left out of a finding's "matched fields" line: they identify the event, which
/// the finding already does.
pub(crate) const UNINTERESTING_FIELDS: &[&str] = &["EventID", "Channel", "Provider_Name"];

/// One concrete way a rule can match: a (channel, event ID) source and the settings it
/// needs. `event_id == 0` means any event in the channel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Alternative {
    pub channel: String,
    pub event_id: u32,
    pub requirements: BTreeSet<LoggingRequirement>,
}

/// Static facts about one rule, derived from its YAML.
#[derive(Debug, Clone)]
pub struct RuleProfile {
    pub id: Option<String>,
    pub title: String,
    /// Sigma `level`, lowercase.
    pub level: Option<String>,
    /// Every field name the detection references (modifiers stripped), sorted.
    pub fields: Vec<String>,
    /// Ways the rule can match; never empty.
    pub alternatives: Vec<Alternative>,
}

impl RuleProfile {
    /// True when no alternative works without Sysmon: on a host without Sysmon the rule
    /// can never fire, whatever the audit policy.
    pub fn sysmon_only(&self) -> bool {
        self.alternatives
            .iter()
            .all(|a| a.requirements.contains(&LoggingRequirement::Sysmon))
    }
}

/// Build a rule's static profile.
pub fn profile_rule(yaml: &str, map: &LogsourceMap) -> Result<RuleProfile> {
    let doc: Value = serde_norway::from_str(yaml)
        .map_err(|e| CairnError::Other(format!("sigma rule yaml: {e}")))?;
    let text = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_owned);
    let id = text(doc.get("id"));
    let title = text(doc.get("title")).unwrap_or_default();
    let level = text(doc.get("level")).map(|l| l.to_ascii_lowercase());
    let ls = doc.get("logsource");
    let ls_field = |k: &str| ls.and_then(|l| l.get(k)).and_then(Value::as_str);
    let (category, product, service) = (
        ls_field("category"),
        ls_field("product"),
        ls_field("service"),
    );

    let detection = Detection::parse(doc.get("detection"));
    let fields: Vec<String> = detection.fields().into_iter().collect();
    let eids = detection.event_ids();

    let mut alternatives: BTreeSet<Alternative> = BTreeSet::new();
    let entries = map.resolve(category, product, service);
    if entries.is_empty() {
        alternatives.insert(Alternative {
            channel: String::new(),
            event_id: 0,
            requirements: [LoggingRequirement::UnmappedLogsource].into(),
        });
    }
    for entry in entries {
        let candidate_eids: Vec<u32> = if entry.event_id != 0 {
            vec![entry.event_id]
        } else if !eids.is_empty() {
            eids.iter().copied().collect()
        } else {
            vec![0]
        };
        for eid in candidate_eids {
            let Some(requirements) = requirements_for(&entry.channel, eid, category, &detection)
            else {
                continue; // this source can never satisfy the detection
            };
            alternatives.insert(Alternative {
                channel: entry.channel.clone(),
                event_id: eid,
                requirements,
            });
        }
    }
    if alternatives.is_empty() {
        // Every resolved source was ruled out structurally (e.g. a process_creation rule
        // mapped only to 4688 that needs Sysmon fields). Keep a Sysmon alternative so the
        // profile says what would make it fire.
        alternatives.insert(Alternative {
            channel: SYSMON.into(),
            event_id: 0,
            requirements: [LoggingRequirement::Sysmon].into(),
        });
    }
    Ok(RuleProfile {
        id,
        title,
        level,
        fields,
        alternatives: alternatives.into_iter().collect(),
    })
}

/// Settings one (channel, event ID) source needs. `None` when the source can never
/// satisfy the detection (a 4688 lacking the fields the condition requires).
fn requirements_for(
    channel: &str,
    eid: u32,
    category: Option<&str>,
    detection: &Detection,
) -> Option<BTreeSet<LoggingRequirement>> {
    use LoggingRequirement as R;
    let mut reqs = BTreeSet::new();
    match channel {
        SECURITY if category == Some("process_creation") || eid == 4688 => {
            let all: BTreeSet<&str> = FIELDS_4688.iter().chain(SYSTEM_FIELDS).copied().collect();
            if !detection.satisfiable(&all) {
                return None;
            }
            reqs.insert(R::ProcessCreationAudit);
            let mut without_cmdline = all.clone();
            without_cmdline.remove("CommandLine");
            if !detection.satisfiable(&without_cmdline) {
                reqs.insert(R::CommandLineIn4688);
            }
        }
        SECURITY => {
            reqs.extend(security_eid_requirements(eid));
        }
        SYSMON => {
            reqs.insert(R::Sysmon);
        }
        PS_OPERATIONAL => match eid {
            4104 => {
                reqs.insert(R::ScriptBlockLogging);
            }
            4103 => {
                reqs.insert(R::ModuleLogging);
            }
            _ => {}
        },
        // 400/403/600 are written by default; 800 (pipeline detail) needs module logging.
        PS_CLASSIC if eid == 800 => {
            reqs.insert(R::ModuleLogging);
        }
        NTLM => {
            reqs.insert(R::NtlmAudit);
        }
        TASK_SCHEDULER => {
            reqs.insert(R::TaskSchedulerLog);
        }
        // System, Application, WMI-Activity, Defender and the TerminalServices
        // LocalSessionManager / RemoteConnectionManager operational logs: written by
        // default; the live run always collects them for the built-in heuristics.
        _ => {}
    }
    Some(reqs)
}

/// Audit subcategory behind a Security event ID.
fn security_eid_requirements(eid: u32) -> Vec<LoggingRequirement> {
    use LoggingRequirement as R;
    match eid {
        // The event log service writes 1102 itself, whatever the audit policy.
        1102 => vec![],
        4624 | 4625 | 4634 | 4647 | 4648 | 4672 => vec![R::LogonAudit],
        4720 | 4722 | 4723 | 4724 | 4725 | 4726 | 4738 | 4740 | 4767 | 4781 => {
            vec![R::UserAccountManagementAudit]
        }
        4727..=4737 | 4754..=4758 | 4798 | 4799 => vec![R::SecurityGroupManagementAudit],
        4688 => vec![R::ProcessCreationAudit],
        4697 => vec![R::SecuritySystemExtensionAudit],
        4698..=4702 => vec![R::OtherObjectAccessAudit],
        5140 => vec![R::FileShareAudit],
        5145 => vec![R::DetailedFileShareAudit],
        4656 | 4658 | 4663 => vec![R::ObjectAccessSacl],
        4768 | 4769 | 4771 | 4662 | 5136 => vec![R::DomainController],
        _ => vec![R::OtherAuditPolicy],
    }
}

/// The detection section, reduced to what viability needs.
struct Detection {
    /// selection name -> OR of AND-groups of field names; `None` = keyword selection
    /// (matches any field, so always satisfiable).
    selections: BTreeMap<String, Option<Vec<Vec<String>>>>,
    condition: Option<String>,
    event_ids: BTreeSet<u32>,
}

impl Detection {
    fn parse(det: Option<&Value>) -> Self {
        let mut selections = BTreeMap::new();
        let mut condition = None;
        let mut event_ids = BTreeSet::new();
        if let Some(Value::Mapping(m)) = det {
            for (k, v) in m {
                let Some(name) = k.as_str() else { continue };
                if name == "condition" {
                    condition = match v {
                        Value::String(s) => Some(s.clone()),
                        // A list of conditions is OR'd by Sigma; join them so the
                        // evaluator sees one expression.
                        Value::Sequence(seq) => Some(
                            seq.iter()
                                .filter_map(Value::as_str)
                                .map(|c| format!("({c})"))
                                .collect::<Vec<_>>()
                                .join(" or "),
                        ),
                        _ => None,
                    };
                    continue;
                }
                if name == "timeframe" {
                    continue;
                }
                // Event IDs in a `filter*` selection are ones the rule excludes (Sigma
                // naming convention), not sources it matches.
                if !name.starts_with("filter") {
                    collect_event_ids(v, &mut event_ids);
                }
                selections.insert(name.to_owned(), selection_groups(v));
            }
        }
        Detection {
            selections,
            condition,
            event_ids,
        }
    }

    fn fields(&self) -> BTreeSet<String> {
        self.selections
            .values()
            .flatten()
            .flatten()
            .flatten()
            .cloned()
            .collect()
    }

    fn event_ids(&self) -> &BTreeSet<u32> {
        &self.event_ids
    }

    /// Can the condition be true on an event that has exactly `available` fields?
    /// Conservative (never says "no" for a rule that could fire): a negated term counts
    /// as satisfiable, and an unparseable condition counts as satisfiable.
    fn satisfiable(&self, available: &BTreeSet<&str>) -> bool {
        let sat: BTreeMap<&str, bool> = self
            .selections
            .iter()
            .map(|(name, groups)| {
                let ok = match groups {
                    None => true,
                    Some(groups) => groups
                        .iter()
                        .any(|g| g.iter().all(|f| available.contains(f.as_str()))),
                };
                (name.as_str(), ok)
            })
            .collect();
        let Some(cond) = &self.condition else {
            return true;
        };
        eval_condition(cond, &sat).unwrap_or(true)
    }
}

/// `Some(groups)` for a field selection (a mapping, or a list of mappings), `None` for a
/// keyword selection (a list of strings / scalars).
fn selection_groups(v: &Value) -> Option<Vec<Vec<String>>> {
    match v {
        Value::Mapping(m) => Some(vec![group_fields(m)]),
        Value::Sequence(seq) if !seq.is_empty() && seq.iter().all(Value::is_mapping) => Some(
            seq.iter()
                .filter_map(Value::as_mapping)
                .map(group_fields)
                .collect(),
        ),
        _ => None,
    }
}

fn group_fields(m: &serde_norway::Mapping) -> Vec<String> {
    m.keys()
        .filter_map(Value::as_str)
        .map(|k| k.split('|').next().unwrap_or_default().to_owned())
        .filter(|k| !k.is_empty())
        .collect()
}

fn collect_event_ids(v: &Value, out: &mut BTreeSet<u32>) {
    match v {
        Value::Mapping(m) => {
            for (k, val) in m {
                if k.as_str().map(|k| k.split('|').next()) == Some(Some("EventID")) {
                    push_eids(val, out);
                } else {
                    collect_event_ids(val, out);
                }
            }
        }
        Value::Sequence(seq) => seq.iter().for_each(|x| collect_event_ids(x, out)),
        _ => {}
    }
}

fn push_eids(v: &Value, out: &mut BTreeSet<u32>) {
    match v {
        Value::Number(n) => {
            if let Some(n) = n.as_u64().and_then(|n| u32::try_from(n).ok()) {
                out.insert(n);
            }
        }
        Value::String(s) => {
            if let Ok(n) = s.trim().parse() {
                out.insert(n);
            }
        }
        Value::Sequence(seq) => seq.iter().for_each(|x| push_eids(x, out)),
        _ => {}
    }
}

/// Evaluate a Sigma condition over per-selection satisfiability. `Err` on anything the
/// evaluator does not understand (aggregations, stray tokens): callers fail open.
fn eval_condition(cond: &str, sat: &BTreeMap<&str, bool>) -> std::result::Result<bool, ()> {
    let spaced = cond.replace('(', " ( ").replace(')', " ) ");
    let toks: Vec<&str> = spaced.split_whitespace().collect();
    let mut p = CondParser { toks, pos: 0, sat };
    let v = p.or()?;
    if p.pos != p.toks.len() {
        return Err(());
    }
    Ok(v)
}

struct CondParser<'a> {
    toks: Vec<&'a str>,
    pos: usize,
    sat: &'a BTreeMap<&'a str, bool>,
}

impl<'a> CondParser<'a> {
    fn peek_is(&self, kw: &str) -> bool {
        self.toks
            .get(self.pos)
            .is_some_and(|t| t.eq_ignore_ascii_case(kw))
    }

    fn next(&mut self) -> std::result::Result<&'a str, ()> {
        let t = self.toks.get(self.pos).copied().ok_or(())?;
        self.pos += 1;
        Ok(t)
    }

    fn or(&mut self) -> std::result::Result<bool, ()> {
        let mut v = self.and()?;
        while self.peek_is("or") {
            self.pos += 1;
            let r = self.and()?;
            v = v || r;
        }
        Ok(v)
    }

    fn and(&mut self) -> std::result::Result<bool, ()> {
        let mut v = self.not()?;
        while self.peek_is("and") {
            self.pos += 1;
            let r = self.not()?;
            v = v && r;
        }
        Ok(v)
    }

    fn not(&mut self) -> std::result::Result<bool, ()> {
        if self.peek_is("not") {
            self.pos += 1;
            // "not X" holds whenever X fails to match, which a missing field guarantees.
            self.not()?;
            return Ok(true);
        }
        self.primary()
    }

    fn primary(&mut self) -> std::result::Result<bool, ()> {
        let t = self.next()?;
        if t == "(" {
            let v = self.or()?;
            return (self.next()? == ")").then_some(v).ok_or(());
        }
        let quant = t.to_ascii_lowercase();
        if (quant == "1" || quant == "any" || quant == "all") && self.peek_is("of") {
            self.pos += 1;
            let target = self.next()?;
            let matched: Vec<bool> = self
                .sat
                .iter()
                .filter(|(name, _)| target.eq_ignore_ascii_case("them") || glob(target, name))
                .map(|(_, ok)| *ok)
                .collect();
            if matched.is_empty() {
                return Err(());
            }
            return Ok(if quant == "all" {
                matched.iter().all(|b| *b)
            } else {
                matched.iter().any(|b| *b)
            });
        }
        if t == ")" || t.contains('|') {
            return Err(());
        }
        self.sat.get(t).copied().ok_or(())
    }
}

/// Sigma selection-name glob: `*` matches any run of characters.
fn glob(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || !name[first.len()..].ends_with(last) {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

/// What is known about the host's logging for this run.
///
/// Explicit settings ([`HostLogging::set`], e.g. from a posture snapshot of the audit
/// policy and PowerShell/Sysmon registry state) win. Without them, the collected events
/// are the evidence: seeing a rule's event proves it is logged, and a readable Security
/// log with no 4688 in the window means process-creation auditing is off.
#[derive(Debug, Clone, Default)]
pub struct HostLogging {
    known: BTreeMap<LoggingRequirement, bool>,
    seen: BTreeSet<(String, u32)>,
    channels: BTreeSet<String>,
    cmdline_4688: bool,
}

impl HostLogging {
    /// Evidence from the events this run collected.
    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a EventRecord>) -> Self {
        let mut h = HostLogging::default();
        for ev in events {
            h.channels.insert(ev.channel.clone());
            h.seen.insert((ev.channel.clone(), ev.event_id));
            if ev.channel == SECURITY
                && ev.event_id == 4688
                && ev
                    .data
                    .get("CommandLine")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|c| !c.trim().is_empty())
            {
                h.cmdline_4688 = true;
            }
        }
        h
    }

    /// Record an authoritative setting (overrides what the events suggest).
    pub fn set(&mut self, req: LoggingRequirement, on: bool) {
        self.known.insert(req, on);
    }

    fn seen(&self, channel: &str, eid: u32) -> bool {
        if eid == 0 {
            self.channels.contains(channel)
        } else {
            self.seen.contains(&(channel.to_owned(), eid))
        }
    }

    /// On / off / unknown for one requirement.
    pub fn state(&self, req: LoggingRequirement) -> Option<bool> {
        use LoggingRequirement as R;
        if let Some(on) = self.known.get(&req) {
            return Some(*on);
        }
        let security_read = self.channels.contains(SECURITY);
        match req {
            R::ProcessCreationAudit => {
                if self.seen(SECURITY, 4688) {
                    Some(true)
                } else if security_read {
                    Some(false)
                } else {
                    None
                }
            }
            R::CommandLineIn4688 => {
                if self.cmdline_4688 {
                    Some(true)
                } else if self.seen(SECURITY, 4688) {
                    Some(false)
                } else {
                    None
                }
            }
            R::ScriptBlockLogging => self.seen(PS_OPERATIONAL, 4104).then_some(true),
            R::ModuleLogging => {
                (self.seen(PS_OPERATIONAL, 4103) || self.seen(PS_CLASSIC, 800)).then_some(true)
            }
            R::Sysmon => {
                // Sysmon is chatty: events from other channels but none from Sysmon over
                // the whole look-back window means it is not installed (or not logging).
                if self.channels.contains(SYSMON) {
                    Some(true)
                } else if !self.channels.is_empty() {
                    Some(false)
                } else {
                    None
                }
            }
            R::LogonAudit | R::UserAccountManagementAudit | R::SecurityGroupManagementAudit => {
                // On by default; a readable Security log is taken to run the default policy.
                security_read.then_some(true)
            }
            R::DomainController => {
                (self.seen(SECURITY, 4768) || self.seen(SECURITY, 4769)).then_some(true)
            }
            _ => None,
        }
    }
}

/// Decide a rule's viability on this host.
pub fn assess(profile: &RuleProfile, host: &HostLogging) -> SigmaRuleStatus {
    let mut best: Option<(u8, usize, SigmaRuleStatus)> = None;
    for alt in &profile.alternatives {
        let observed = !alt.channel.is_empty() && host.seen(&alt.channel, alt.event_id);
        let mut missing = Vec::new();
        let mut unknown = Vec::new();
        for req in &alt.requirements {
            // Seeing the event proves its audit setting; the command-line flag is the one
            // thing a seen 4688 does not prove.
            let state = if observed && *req != LoggingRequirement::CommandLineIn4688 {
                Some(true)
            } else {
                host.state(*req)
            };
            match state {
                Some(true) => {}
                Some(false) => missing.push(*req),
                None => unknown.push(*req),
            }
        }
        let viability = if !missing.is_empty() {
            RuleViability::MissingLogging
        } else if !unknown.is_empty() {
            RuleViability::Unknown
        } else {
            RuleViability::Runnable
        };
        let rank = match viability {
            RuleViability::Runnable => 0,
            RuleViability::Unknown => 1,
            RuleViability::MissingLogging => 2,
        };
        // Among equally good alternatives prefer the one without Sysmon: "turn on
        // process-creation auditing" is the fix an operator can actually apply.
        let weight = usize::from(alt.requirements.contains(&LoggingRequirement::Sysmon)) * 1000
            + missing.len()
            + unknown.len();
        let better = best
            .as_ref()
            .is_none_or(|(r, w, _)| (rank, weight) < (*r, *w));
        if better {
            best = Some((
                rank,
                weight,
                SigmaRuleStatus {
                    rule_id: profile.id.clone(),
                    level: profile.level.clone(),
                    viability,
                    requirements: alt.requirements.iter().copied().collect(),
                    missing,
                    unknown,
                },
            ));
        }
    }
    best.map(|(_, _, s)| s).unwrap_or(SigmaRuleStatus {
        rule_id: profile.id.clone(),
        level: profile.level.clone(),
        viability: RuleViability::Unknown,
        requirements: vec![],
        missing: vec![],
        unknown: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::observation::LoggingRequirement as R;
    use chrono::Utc;

    fn map() -> LogsourceMap {
        LogsourceMap::windows_builtin()
    }

    fn proc_rule(detection: &str) -> String {
        format!(
            "title: T\nid: t-1\nlevel: high\nauthor: x\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n{detection}"
        )
    }

    fn security_rule(eid: u32) -> String {
        format!(
            "title: S\nid: s-1\nauthor: x\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: {eid}\n    condition: selection\n"
        )
    }

    fn ev(channel: &str, eid: u32, data: serde_json::Value) -> EventRecord {
        EventRecord {
            ts: Utc::now(),
            channel: channel.into(),
            event_id: eid,
            provider: String::new(),
            computer: "PC".into(),
            record_id: 1,
            data: data.as_object().cloned().unwrap_or_default(),
        }
    }

    fn reqs(p: &RuleProfile, channel: &str) -> Vec<LoggingRequirement> {
        p.alternatives
            .iter()
            .find(|a| a.channel == channel)
            .map(|a| a.requirements.iter().copied().collect())
            .unwrap_or_default()
    }

    #[test]
    fn image_or_original_filename_works_on_4688() {
        let y = proc_rule(
            "    selection_img:\n        - Image|endswith: '\\x.exe'\n        - OriginalFileName: 'x.exe'\n    selection_cli:\n        CommandLine|contains: ' -y'\n    condition: all of selection_*\n",
        );
        let p = profile_rule(&y, &map()).unwrap();
        assert!(!p.sysmon_only());
        assert_eq!(
            reqs(&p, SECURITY),
            vec![R::ProcessCreationAudit, R::CommandLineIn4688]
        );
        assert_eq!(reqs(&p, SYSMON), vec![R::Sysmon]);
        assert!(p.fields.contains(&"OriginalFileName".to_string()));
    }

    #[test]
    fn original_filename_only_rule_is_sysmon_only() {
        let y = proc_rule(
            "    selection:\n        OriginalFileName: 'whoami.exe'\n    filter:\n        Image|endswith: '\\whoami.exe'\n    condition: selection and not filter\n",
        );
        let p = profile_rule(&y, &map()).unwrap();
        assert!(p.sysmon_only(), "{:?}", p.alternatives);
    }

    #[test]
    fn image_only_rule_does_not_need_cmdline() {
        let y = proc_rule(
            "    selection:\n        Image|endswith: '\\msxsl.exe'\n    condition: selection\n",
        );
        let p = profile_rule(&y, &map()).unwrap();
        assert_eq!(reqs(&p, SECURITY), vec![R::ProcessCreationAudit]);
    }

    #[test]
    fn negated_sysmon_field_does_not_block_4688() {
        // A filter on a Sysmon-only field only removes matches; the rule still fires.
        let y = proc_rule(
            "    selection:\n        CommandLine|contains: 'x'\n    filter_main:\n        ParentCommandLine|contains: 'y'\n    condition: selection and not 1 of filter_main*\n",
        );
        let p = profile_rule(&y, &map()).unwrap();
        assert!(!p.sysmon_only());
    }

    #[test]
    fn or_branch_with_4688_fields_keeps_4688() {
        let y = proc_rule(
            "    selection_ofn:\n        OriginalFileName: 'p.exe'\n    selection_cli:\n        CommandLine|contains: ' -ma '\n    condition: selection_ofn or selection_cli\n",
        );
        let p = profile_rule(&y, &map()).unwrap();
        assert_eq!(
            reqs(&p, SECURITY),
            vec![R::ProcessCreationAudit, R::CommandLineIn4688]
        );
    }

    #[test]
    fn security_event_ids_map_to_audit_subcategories() {
        let cases = [
            (4624, vec![R::LogonAudit]),
            (4732, vec![R::SecurityGroupManagementAudit]),
            (4720, vec![R::UserAccountManagementAudit]),
            (4697, vec![R::SecuritySystemExtensionAudit]),
            (5140, vec![R::FileShareAudit]),
            (4769, vec![R::DomainController]),
            (1102, vec![]),
            (4999, vec![R::OtherAuditPolicy]),
        ];
        for (eid, want) in cases {
            let p = profile_rule(&security_rule(eid), &map()).unwrap();
            assert_eq!(p.alternatives.len(), 1, "{eid}");
            assert_eq!(p.alternatives[0].event_id, eid);
            assert_eq!(reqs(&p, SECURITY), want, "{eid}");
        }
    }

    #[test]
    fn unmapped_logsource_is_unknown() {
        let y = "title: U\nlogsource:\n    category: nothing_known\n    product: linux\ndetection:\n    s:\n        a: b\n    condition: s\n";
        let p = profile_rule(y, &map()).unwrap();
        let s = assess(&p, &HostLogging::default());
        assert_eq!(s.viability, RuleViability::Unknown);
        assert_eq!(s.unknown, vec![R::UnmappedLogsource]);
    }

    #[test]
    fn security_log_without_4688_means_process_audit_off() {
        let p = profile_rule(
            &proc_rule("    s:\n        CommandLine|contains: 'x'\n    condition: s\n"),
            &map(),
        )
        .unwrap();
        let host = HostLogging::from_events(&[ev(SECURITY, 4624, serde_json::json!({}))]);
        let s = assess(&p, &host);
        assert_eq!(s.viability, RuleViability::MissingLogging);
        assert!(s.missing.contains(&R::ProcessCreationAudit), "{s:?}");
    }

    #[test]
    fn seen_4688_without_cmdline_flags_cmdline_missing() {
        let p = profile_rule(
            &proc_rule("    s:\n        CommandLine|contains: 'x'\n    condition: s\n"),
            &map(),
        )
        .unwrap();
        let host = HostLogging::from_events(&[ev(
            SECURITY,
            4688,
            serde_json::json!({"NewProcessName": "C:\\a.exe", "CommandLine": ""}),
        )]);
        let s = assess(&p, &host);
        assert_eq!(s.viability, RuleViability::MissingLogging);
        assert_eq!(s.missing, vec![R::CommandLineIn4688]);

        let host = HostLogging::from_events(&[ev(
            SECURITY,
            4688,
            serde_json::json!({"CommandLine": "a.exe -x"}),
        )]);
        assert_eq!(assess(&p, &host).viability, RuleViability::Runnable);
    }

    #[test]
    fn explicit_setting_overrides_inference() {
        let p = profile_rule(
            &proc_rule("    s:\n        Image|endswith: 'x'\n    condition: s\n"),
            &map(),
        )
        .unwrap();
        let mut host = HostLogging::default();
        assert_eq!(assess(&p, &host).viability, RuleViability::Unknown);
        host.set(R::ProcessCreationAudit, true);
        assert_eq!(assess(&p, &host).viability, RuleViability::Runnable);
    }

    #[test]
    fn default_on_logon_rule_runs_when_security_is_readable() {
        let p = profile_rule(&security_rule(4625), &map()).unwrap();
        let host = HostLogging::from_events(&[ev(SECURITY, 4672, serde_json::json!({}))]);
        assert_eq!(assess(&p, &host).viability, RuleViability::Runnable);
        let s = assess(&p, &HostLogging::default());
        assert_eq!(s.viability, RuleViability::Unknown);
    }

    #[test]
    fn seeing_the_event_proves_an_opt_in_audit_setting() {
        let p = profile_rule(&security_rule(4697), &map()).unwrap();
        let host = HostLogging::from_events(&[ev(SECURITY, 4624, serde_json::json!({}))]);
        let s = assess(&p, &host);
        assert_eq!(s.viability, RuleViability::Unknown);
        assert_eq!(s.unknown, vec![R::SecuritySystemExtensionAudit]);
        let host = HostLogging::from_events(&[ev(SECURITY, 4697, serde_json::json!({}))]);
        assert_eq!(assess(&p, &host).viability, RuleViability::Runnable);
    }

    #[test]
    fn condition_evaluator_handles_quantifiers_and_parens() {
        let sat: BTreeMap<&str, bool> =
            [("sel_a", true), ("sel_b", false), ("filter", false)].into();
        assert_eq!(eval_condition("1 of sel_*", &sat), Ok(true));
        assert_eq!(eval_condition("all of sel_*", &sat), Ok(false));
        assert_eq!(
            eval_condition("sel_b or (sel_a and not filter)", &sat),
            Ok(true)
        );
        assert_eq!(eval_condition("sel_b and not filter", &sat), Ok(false));
        assert_eq!(eval_condition("all of them", &sat), Ok(false));
        assert!(eval_condition("sel_a | count() > 5", &sat).is_err());
        assert!(eval_condition("missing", &sat).is_err());
    }

    #[test]
    fn glob_matches_sigma_patterns() {
        assert!(glob("selection_*", "selection_img"));
        assert!(glob("selection*", "selection"));
        assert!(glob("*_cli_*", "selection_cli_a"));
        assert!(!glob("filter_*", "selection_x"));
        assert!(glob("exact", "exact"));
    }
}
