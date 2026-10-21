//! Concrete SigmaMatcher over the `sigma-rust` engine (ADR-0001).
//!
//! Loads Sigma 2.0 rules, matches them against EventRecords, and emits Findings with
//! the rule's author (DRL 1.1, golden rule 5), severity (from `level`), and MITRE
//! tags (from `tags`). The engine stays behind the `SigmaMatcher` trait so it can be
//! swapped (e.g. for tau-engine) per ADR-0001's fallback.

use crate::viability::{self, HostLogging, RuleProfile};
use crate::{LogsourceMap, SigmaMatcher};
use cairn_core::finding::{Finding, FindingSource, Severity};
use cairn_core::observation::SigmaRuleStatus;
use cairn_core::record::EventRecord;
use cairn_core::{CairnError, Result};
use sigma_rust::Rule;
use std::path::Path;

/// SigmaMatcher backed by sigma-rust. Holds compiled rules, the set of channels they
/// reference (load-optimization hook), and the de-abstraction map used to gate a rule
/// to the EVTX channel/event_id its logsource actually denotes.
#[derive(Default)]
pub struct Engine {
    rules: Vec<Rule>,
    /// Viability profile per rule, index-aligned with `rules`.
    profiles: Vec<RuleProfile>,
    channels: Vec<String>,
    logsource: LogsourceMap,
    ruleset_ver: String,
}

impl Engine {
    /// Build an engine from in-memory YAML rule strings (used by tests and by `load`
    /// after decoding). A rule that fails to parse is a hard error — bundled rules are
    /// trusted/pinned (ADR-0003), so a parse failure is a packaging bug, not input.
    pub fn from_rules(rules: &[&str]) -> Result<Self> {
        let logsource = LogsourceMap::windows_builtin();
        let mut parsed = Vec::with_capacity(rules.len());
        let mut profiles = Vec::with_capacity(rules.len());
        for (i, yaml) in rules.iter().enumerate() {
            let rule = sigma_rust::rule_from_yaml(yaml)
                .map_err(|e| CairnError::Other(format!("sigma rule #{i} parse error: {e}")))?;
            let profile = viability::profile_rule(yaml, &logsource)
                .map_err(|e| CairnError::Other(format!("sigma rule #{i} profile error: {e}")))?;
            parsed.push(rule);
            profiles.push(profile);
        }
        Ok(Self::from_parsed(parsed, profiles, logsource))
    }

    fn from_parsed(rules: Vec<Rule>, profiles: Vec<RuleProfile>, logsource: LogsourceMap) -> Self {
        // Distinct EVTX channel names the rules' logsources resolve to (e.g.
        // `service: security` -> "Security", `category: process_creation` -> "Security"
        // + Sysmon). These are real channel names, so EvtxLiveCollector can map them to
        // on-disk `.evtx` files. A rule whose logsource is unmapped contributes nothing.
        let mut channels: Vec<String> = rules
            .iter()
            .flat_map(|r| {
                let ls = &r.logsource;
                logsource
                    .resolve(
                        ls.category.as_deref(),
                        ls.product.as_deref(),
                        ls.service.as_deref(),
                    )
                    .into_iter()
                    .map(|e| e.channel.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
        channels.sort();
        channels.dedup();
        Engine {
            rules,
            profiles,
            channels,
            logsource,
            ruleset_ver: String::new(),
        }
    }

    /// Static viability profile of every loaded rule, in load order.
    pub fn profiles(&self) -> &[RuleProfile] {
        &self.profiles
    }

    /// Each loaded rule's viability on a host with the given logging, in load order.
    pub fn rule_statuses(&self, host: &HostLogging) -> Vec<(&RuleProfile, SigmaRuleStatus)> {
        self.profiles
            .iter()
            .map(|p| (p, viability::assess(p, host)))
            .collect()
    }

    /// Number of loaded rules tagged with each ATT&CK technique, keyed by the
    /// upper-case technique ID (`attack.t1059.001` -> `T1059.001`). Tactic tags
    /// (`attack.execution`) and non-ATT&CK tags are ignored.
    pub fn technique_counts(&self) -> std::collections::BTreeMap<String, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for rule in &self.rules {
            let mut seen = std::collections::BTreeSet::new();
            for tag in rule.tags.iter().flatten() {
                if let Some(id) = technique_from_tag(tag) {
                    seen.insert(id);
                }
            }
            for id in seen {
                *counts.entry(id).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Version string recorded by `load()` from the PROVENANCE file in the rules dir.
    /// Format: `"<pin>+<aggregate>"` (ADR-0003). Empty when no rules were loaded via `load()`.
    pub fn ruleset_ver(&self) -> &str {
        &self.ruleset_ver
    }

    /// Logsource gate: does `ev` belong to the EVTX channel/event_id that `rule`'s
    /// `logsource` denotes? Resolves the rule's (category, product, service) via the
    /// de-abstraction map; the event passes if its (channel, event_id) is among the
    /// resolved entries (an entry's `event_id == 0` means "any EID in that channel").
    ///
    /// **Fail-open:** a logsource that resolves to nothing (unknown category, or a rule
    /// with no logsource) passes — the gate only constrains rules it can map, so it
    /// never silently drops a detection it doesn't understand. This trades a little
    /// over-firing on unmapped rules for zero false-negatives, the right bias for triage.
    fn event_passes_logsource(&self, rule: &Rule, ev: &EventRecord) -> bool {
        let ls = &rule.logsource;
        let entries = self.logsource.resolve(
            ls.category.as_deref(),
            ls.product.as_deref(),
            ls.service.as_deref(),
        );
        if entries.is_empty() {
            return true; // fail-open: unmapped logsource
        }
        entries
            .iter()
            .any(|e| e.channel == ev.channel && (e.event_id == 0 || e.event_id == ev.event_id))
    }

    /// Convert one normalized EventRecord into a sigma-rust Event by serializing its
    /// flattened `data` map to JSON (the fields Sigma matches against).
    ///
    /// Field aliases from every LogsourceMap entry matching the event's channel/EID are
    /// applied first: e.g. a Security 4688 carries `NewProcessName`, so `Image` is added
    /// with the same value, letting process_creation rules written against Sysmon
    /// field names match it. An alias never overwrites a field the event already has.
    fn to_sigma_event(
        &self,
        ev: &EventRecord,
    ) -> Result<(
        sigma_rust::Event,
        serde_json::Map<String, serde_json::Value>,
    )> {
        let mut data = ev.data.clone();
        // The flattened System section keeps `Provider` as an object and `EventID` as an
        // object when it has qualifiers; Sigma rules match `Provider_Name` and a numeric
        // `EventID`, so give them the normalized values the EventRecord already holds.
        if !data.contains_key("Provider_Name") && !ev.provider.is_empty() {
            data.insert(
                "Provider_Name".into(),
                serde_json::Value::String(ev.provider.clone()),
            );
        }
        if !data
            .get("EventID")
            .is_some_and(serde_json::Value::is_number)
        {
            data.insert("EventID".into(), serde_json::Value::from(ev.event_id));
        }
        for entry in self
            .logsource
            .entries
            .iter()
            .filter(|e| e.channel == ev.channel && e.event_id == ev.event_id)
        {
            for (sigma_field, evtx_field) in &entry.field_aliases {
                if data.contains_key(sigma_field) {
                    continue;
                }
                if let Some(v) = ev.data.get(evtx_field) {
                    data.insert(sigma_field.clone(), v.clone());
                }
            }
        }
        let json = serde_json::Value::Object(data.clone()).to_string();
        let event = sigma_rust::event_from_json(&json)
            .map_err(|e| CairnError::Other(format!("event to sigma: {e}")))?;
        Ok((event, data))
    }

    fn finding_from(
        rule: &Rule,
        profile: &RuleProfile,
        ev: &EventRecord,
        data: &serde_json::Map<String, serde_json::Value>,
    ) -> Finding {
        let mut f = Finding::new(
            level_to_severity(&rule.level),
            &rule.title,
            FindingSource::Sigma,
        );
        f.rule_id = rule.id.clone();
        f.rule_author = rule.author.clone(); // DRL 1.1
        f.mitre = rule.tags.clone().unwrap_or_default();
        f.ts = ev.ts;
        f.host = ev.computer.clone();
        f.artifact = format!("evtx:{}", ev.channel);
        f.event_id = Some(ev.event_id);
        f.evidence_ref = Some(ev.record_id.to_string());
        f.details = matched_fields(profile, data);
        f
    }
}

/// Longest field value quoted in a finding's matched-fields line.
const MATCHED_VALUE_MAX: usize = 200;

/// `matched fields: CommandLine=...; Image=...` — the values of the fields the rule's
/// detection references, as this event carried them (after field aliasing). Empty when
/// the event has none of them (a keyword rule).
pub(crate) fn matched_fields(
    profile: &RuleProfile,
    data: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let parts: Vec<String> = profile
        .fields
        .iter()
        .filter(|f| !viability::UNINTERESTING_FIELDS.contains(&f.as_str()))
        .filter_map(|f| {
            let v = data.get(f)?;
            let text = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => return None,
                other => other.to_string(),
            };
            let text = if text.chars().count() > MATCHED_VALUE_MAX {
                let cut: String = text.chars().take(MATCHED_VALUE_MAX).collect();
                format!("{cut}...")
            } else {
                text
            };
            Some(format!("{f}={text}"))
        })
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("matched fields: {}", parts.join("; "))
    }
}

/// `attack.t1059.001` -> `Some("T1059.001")`; tactic or other tags -> None.
fn technique_from_tag(tag: &str) -> Option<String> {
    let id = tag.strip_prefix("attack.")?;
    let rest = id.strip_prefix('t').or_else(|| id.strip_prefix('T'))?;
    let (major, sub) = rest
        .split_once('.')
        .map_or((rest, None), |(a, b)| (a, Some(b)));
    if major.len() != 4 || !major.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(sub) = sub {
        if sub.len() != 3 || !sub.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!("T{}", rest))
}

/// Map sigma-rust's `Level` to our `Severity`. sigma-rust does not re-export the
/// `Level` type (its module is private), so we map via its stable `Debug` name rather
/// than naming the variants. Absent level -> Info (conservative). The engine tests
/// pin this mapping, so an upstream Debug change can't slip through silently.
fn level_to_severity<L: std::fmt::Debug>(level: &Option<L>) -> Severity {
    let Some(lvl) = level else {
        return Severity::Info;
    };
    match format!("{lvl:?}").as_str() {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info, // Informational or anything unexpected
    }
}

/// Recursively collect rule YAML strings from `dir` and all subdirectories.
/// A directory that cannot be read is skipped (graceful degrade, golden rule 8).
fn collect_rule_yamls(dir: &Path, out: &mut Vec<String>) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    for entry in rd {
        let path = entry?.path();
        if path.is_dir() {
            collect_rule_yamls(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            let bytes = std::fs::read(&path)?;
            out.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    Ok(())
}

impl SigmaMatcher for Engine {
    fn load(&mut self, rules_dir: &Path) -> Result<usize> {
        let mut yamls: Vec<String> = Vec::new();
        collect_rule_yamls(rules_dir, &mut yamls)?;
        let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();
        *self = Engine::from_rules(&refs)?;
        // Populate ruleset_ver from the PROVENANCE file for manifest integrity (ADR-0003).
        self.ruleset_ver = crate::ruleset::ruleset_version(rules_dir).unwrap_or_default();
        Ok(self.rules.len())
    }

    fn match_event(&self, ev: &EventRecord) -> Result<Vec<Finding>> {
        let (sigma_ev, data) = self.to_sigma_event(ev)?;
        let findings = self
            .rules
            .iter()
            .zip(&self.profiles)
            // Gate first (cheap channel/EID check) so a rule only matches events of the
            // type its logsource denotes; then run the full content match.
            .filter(|(rule, _)| self.event_passes_logsource(rule, ev) && rule.is_match(&sigma_ev))
            .map(|(rule, profile)| Self::finding_from(rule, profile, ev, &data))
            .collect();
        Ok(findings)
    }

    fn referenced_channels(&self) -> &[String] {
        &self.channels
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigmaMatcher;
    use cairn_core::finding::{FindingSource, Severity};
    use cairn_core::record::EventRecord;
    use chrono::Utc;

    const RULE: &str = r#"
title: Suspicious cmd.exe
id: test-0001
author: Test Author
level: high
tags:
    - attack.t1059
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
"#;

    fn event(image: &str) -> EventRecord {
        let mut data = serde_json::Map::new();
        data.insert("Image".into(), serde_json::json!(image));
        EventRecord {
            ts: Utc::now(),
            channel: "Security".into(),
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".into(),
            computer: "WS01".into(),
            record_id: 1,
            data,
        }
    }

    #[test]
    fn technique_tags_are_parsed_and_tactics_ignored() {
        assert_eq!(
            technique_from_tag("attack.t1059.001").as_deref(),
            Some("T1059.001")
        );
        assert_eq!(technique_from_tag("attack.t1218").as_deref(), Some("T1218"));
        assert_eq!(technique_from_tag("attack.execution"), None);
        assert_eq!(technique_from_tag("attack.g0016"), None);
        assert_eq!(technique_from_tag("car.2013-05-004"), None);
        let engine = Engine::from_rules(&[RULE]).unwrap();
        assert_eq!(engine.technique_counts().get("T1059"), Some(&1));
    }

    /// A matching event fires the rule and the Finding carries author (DRL 1.1),
    /// severity mapped from `level`, MITRE from `tags`, and the rule id + source=sigma.
    #[test]
    fn matching_event_fires_with_author_severity_mitre() {
        let engine = Engine::from_rules(&[RULE]).unwrap();
        let findings = engine
            .match_event(&event(r"C:\Windows\System32\cmd.exe"))
            .unwrap();

        assert_eq!(findings.len(), 1, "rule should fire once");
        let f = &findings[0];
        assert_eq!(f.source, FindingSource::Sigma);
        assert_eq!(f.rule_author.as_deref(), Some("Test Author")); // DRL 1.1
        assert_eq!(f.rule_id.as_deref(), Some("test-0001"));
        assert_eq!(f.severity, Severity::High);
        assert!(f.mitre.iter().any(|t| t == "attack.t1059"));
        assert_eq!(f.title, "Suspicious cmd.exe");
    }

    /// A non-matching event produces no finding.
    #[test]
    fn non_matching_event_does_not_fire() {
        let engine = Engine::from_rules(&[RULE]).unwrap();
        let findings = engine
            .match_event(&event(r"C:\Windows\System32\notepad.exe"))
            .unwrap();
        assert!(findings.is_empty());
    }

    /// referenced_channels() reflects nothing special here yet, but must not panic and
    /// returns a slice (load-optimization hook for T7+).
    #[test]
    fn referenced_channels_is_available() {
        let engine = Engine::from_rules(&[RULE]).unwrap();
        let _ = engine.referenced_channels();
    }

    /// referenced_channels() returns real EVTX channel names resolved from each rule's
    /// logsource (not raw Sigma service names like "security"), so the live collector
    /// can map them to on-disk files. process_creation -> Security + Sysmon.
    #[test]
    fn referenced_channels_are_resolved_channel_names() {
        const SVC: &str = r#"
title: Svc rule
id: svc-0001
author: T
level: low
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
"#;
        let engine = Engine::from_rules(&[RULE, SVC]).unwrap();
        assert_eq!(
            engine.referenced_channels(),
            &[
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Security".to_string(),
            ]
        );
    }

    /// A real Security 4688 carries `NewProcessName`/`ParentProcessName`, not the Sysmon
    /// `Image`/`ParentImage` names that process_creation rules use. The 4688 field
    /// aliases bridge that, so the rule fires on a real-shaped 4688.
    #[test]
    fn process_creation_rule_fires_on_real_shaped_4688() {
        let engine = Engine::from_rules(&[RULE]).unwrap();
        let mut data = serde_json::Map::new();
        data.insert(
            "NewProcessName".into(),
            serde_json::json!(r"C:\Windows\System32\cmd.exe"),
        );
        let ev = EventRecord {
            ts: Utc::now(),
            channel: "Security".into(),
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".into(),
            computer: "WS01".into(),
            record_id: 1,
            data,
        };
        assert_eq!(engine.match_event(&ev).unwrap().len(), 1);
    }

    /// Aliases only fill in missing fields: an event that already carries `Image`
    /// keeps its own value even if `NewProcessName` says otherwise.
    #[test]
    fn field_alias_never_overwrites_existing_field() {
        let engine = Engine::from_rules(&[RULE]).unwrap();
        let mut ev = event(r"C:\Windows\System32\notepad.exe");
        ev.data.insert(
            "NewProcessName".into(),
            serde_json::json!(r"C:\Windows\System32\cmd.exe"),
        );
        assert!(engine.match_event(&ev).unwrap().is_empty());
    }

    /// Logsource gate (T8 follow-up): a `process_creation` rule must fire on a
    /// process-creation event (Sysmon EID 1) but NOT on a same-channel image_load event
    /// (Sysmon EID 7) that happens to carry a matching `Image` field. Before this gate,
    /// the engine matched on field content alone and over-fired on EID 7.
    #[test]
    fn logsource_gate_blocks_wrong_event_id_in_same_channel() {
        let engine = Engine::from_rules(&[RULE]).unwrap();
        let sysmon = |eid: u32| {
            let mut data = serde_json::Map::new();
            data.insert(
                "Image".into(),
                serde_json::json!(r"C:\Windows\System32\cmd.exe"),
            );
            EventRecord {
                ts: Utc::now(),
                channel: "Microsoft-Windows-Sysmon/Operational".into(),
                event_id: eid,
                provider: "Microsoft-Windows-Sysmon".into(),
                computer: "WS01".into(),
                record_id: 1,
                data,
            }
        };
        // EID 1 = process_creation -> rule fires.
        assert_eq!(
            engine.match_event(&sysmon(1)).unwrap().len(),
            1,
            "EID 1 should fire"
        );
        // EID 7 = image_load -> same Image, but wrong event type, gate blocks it.
        assert!(
            engine.match_event(&sysmon(7)).unwrap().is_empty(),
            "EID 7 (image_load) must NOT fire a process_creation rule"
        );
    }

    /// Fail-open: a rule whose logsource doesn't resolve to any concrete EVTX entry
    /// (unknown category) still matches on field content — the gate only constrains
    /// rules it can map, so unmapped detections are never silently dropped.
    #[test]
    fn logsource_gate_fails_open_for_unmapped_logsource() {
        const ODD: &str = r#"
title: Odd logsource
id: odd-0001
author: T
level: low
logsource:
    category: definitely_not_a_known_category
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
"#;
        let engine = Engine::from_rules(&[ODD]).unwrap();
        // event() builds a Security 4688 record carrying cmd.exe.
        assert_eq!(
            engine
                .match_event(&event(r"C:\Windows\System32\cmd.exe"))
                .unwrap()
                .len(),
            1,
            "unmapped logsource must fail open (still match on content)"
        );
    }

    /// `load` reads every `.yml` under a directory tree as plain YAML.
    #[test]
    fn load_reads_plain_yaml_dir() {
        let root = std::env::temp_dir().join("cairn_engine_plain_test");
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("sub");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("r.yml"), RULE).unwrap();

        let mut engine = Engine::default();
        assert_eq!(engine.load(&root).unwrap(), 1);
        let hits = engine
            .match_event(&event(r"C:\Windows\System32\cmd.exe"))
            .unwrap();
        assert_eq!(hits.len(), 1);
    }
}
