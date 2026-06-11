//! Concrete SigmaMatcher over the `sigma-rust` engine (ADR-0001).
//!
//! Loads Sigma 2.0 rules, matches them against EventRecords, and emits Findings with
//! the rule's author (DRL 1.1, golden rule 5), severity (from `level`), and MITRE
//! tags (from `tags`). The engine stays behind the `SigmaMatcher` trait so it can be
//! swapped (e.g. for tau-engine) per ADR-0001's fallback.

use crate::SigmaMatcher;
use cairn_core::finding::{Finding, FindingSource, Severity};
use cairn_core::record::EventRecord;
use cairn_core::{CairnError, Result};
use sigma_rust::Rule;
use std::path::Path;

/// SigmaMatcher backed by sigma-rust. Holds compiled rules and the set of channels
/// they reference (load-optimization hook).
#[derive(Default)]
pub struct Engine {
    rules: Vec<Rule>,
    channels: Vec<String>,
}

impl Engine {
    /// Build an engine from in-memory YAML rule strings (used by tests and by `load`
    /// after decoding). A rule that fails to parse is a hard error — bundled rules are
    /// trusted/pinned (ADR-0003), so a parse failure is a packaging bug, not input.
    pub fn from_rules(rules: &[&str]) -> Result<Self> {
        let mut parsed = Vec::with_capacity(rules.len());
        for (i, yaml) in rules.iter().enumerate() {
            let rule = sigma_rust::rule_from_yaml(yaml)
                .map_err(|e| CairnError::Other(format!("sigma rule #{i} parse error: {e}")))?;
            parsed.push(rule);
        }
        Ok(Self::from_parsed(parsed))
    }

    fn from_parsed(rules: Vec<Rule>) -> Self {
        // Distinct channels referenced via logsource.service (used as a channel hint).
        let mut channels: Vec<String> = rules
            .iter()
            .filter_map(|r| r.logsource.service.clone())
            .collect();
        channels.sort();
        channels.dedup();
        Engine { rules, channels }
    }

    /// Convert one normalized EventRecord into a sigma-rust Event by serializing its
    /// flattened `data` map to JSON (the fields Sigma matches against).
    fn to_sigma_event(ev: &EventRecord) -> Result<sigma_rust::Event> {
        let json = serde_json::Value::Object(ev.data.clone()).to_string();
        sigma_rust::event_from_json(&json)
            .map_err(|e| CairnError::Other(format!("event to sigma: {e}")))
    }

    fn finding_from(rule: &Rule, ev: &EventRecord) -> Finding {
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
        f
    }
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

impl SigmaMatcher for Engine {
    fn load(&mut self, rules_dir: &Path) -> Result<usize> {
        let mut yamls: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(rules_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                // Bundled rules are XOR-encoded by default; load_rule_bytes decodes.
                let bytes = crate::codec::load_rule_bytes(&path, false)?;
                yamls.push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();
        *self = Engine::from_rules(&refs)?;
        Ok(self.rules.len())
    }

    fn match_event(&self, ev: &EventRecord) -> Result<Vec<Finding>> {
        let sigma_ev = Self::to_sigma_event(ev)?;
        let findings = self
            .rules
            .iter()
            .filter(|rule| rule.is_match(&sigma_ev))
            .map(|rule| Self::finding_from(rule, ev))
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
}
