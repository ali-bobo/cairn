//! Concrete SigmaMatcher over the `sigma-rust` engine (ADR-0001).
//!
//! Loads Sigma 2.0 rules, matches them against EventRecords, and emits Findings with
//! the rule's author (DRL 1.1, golden rule 5), severity (from `level`), and MITRE
//! tags (from `tags`). The engine stays behind the `SigmaMatcher` trait so it can be
//! swapped (e.g. for tau-engine) per ADR-0001's fallback.

use crate::{LogsourceMap, SigmaMatcher};
use cairn_core::finding::{Finding, FindingSource, Severity};
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
    channels: Vec<String>,
    logsource: LogsourceMap,
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
        Engine {
            rules,
            channels,
            logsource: LogsourceMap::windows_builtin(),
        }
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

/// Recursively collect decoded rule YAML strings from `dir` and all subdirectories.
/// Bundled rules are XOR-encoded (`plain=false`); `--rules-plain` passes `true`.
/// A directory that cannot be read is skipped (graceful degrade, golden rule 8).
fn collect_rule_yamls(dir: &Path, plain: bool, out: &mut Vec<String>) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    for entry in rd {
        let path = entry?.path();
        if path.is_dir() {
            collect_rule_yamls(&path, plain, out)?;
        } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            let bytes = crate::codec::load_rule_bytes(&path, plain)?;
            out.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    Ok(())
}

impl SigmaMatcher for Engine {
    fn load(&mut self, rules_dir: &Path, plain: bool) -> Result<usize> {
        let mut yamls: Vec<String> = Vec::new();
        collect_rule_yamls(rules_dir, plain, &mut yamls)?;
        let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();
        *self = Engine::from_rules(&refs)?;
        Ok(self.rules.len())
    }

    fn match_event(&self, ev: &EventRecord) -> Result<Vec<Finding>> {
        let sigma_ev = Self::to_sigma_event(ev)?;
        let findings = self
            .rules
            .iter()
            // Gate first (cheap channel/EID check) so a rule only matches events of the
            // type its logsource denotes; then run the full content match.
            .filter(|rule| self.event_passes_logsource(rule, ev) && rule.is_match(&sigma_ev))
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

    /// `--rules-plain` parity (ADR-0002 / T8b): loading the SAME rule from a plain `.yml`
    /// dir (plain=true) and from an XOR-encoded dir (plain=false) yields an engine that
    /// matches identically — the codec layer is invisible to detection results.
    #[test]
    fn load_plain_and_encoded_dirs_match_identically() {
        let root = std::env::temp_dir().join("cairn_engine_plain_test");
        let _ = std::fs::remove_dir_all(&root);
        let plain_dir = root.join("plain");
        let enc_dir = root.join("encoded");
        std::fs::create_dir_all(&plain_dir).unwrap();
        std::fs::create_dir_all(&enc_dir).unwrap();

        std::fs::write(plain_dir.join("r.yml"), RULE).unwrap();
        std::fs::write(enc_dir.join("r.yml"), crate::codec::xor(RULE.as_bytes())).unwrap();

        let mut plain_engine = Engine::default();
        let n_plain = plain_engine.load(&plain_dir, true).unwrap();
        let mut enc_engine = Engine::default();
        let n_enc = enc_engine.load(&enc_dir, false).unwrap();
        assert_eq!(n_plain, 1);
        assert_eq!(n_enc, 1);

        let ev = event(r"C:\Windows\System32\cmd.exe");
        let p = plain_engine.match_event(&ev).unwrap();
        let e = enc_engine.match_event(&ev).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(e.len(), 1);
        assert_eq!(p[0].rule_id, e[0].rule_id);
        assert_eq!(p[0].rule_author, e[0].rule_author);
        assert_eq!(p[0].severity, e[0].severity);
    }
}
