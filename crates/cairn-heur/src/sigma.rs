//! SigmaAnalyzer: runs Engine::match_event over Record::Event in the record stream.

use cairn_core::finding::Finding;
use cairn_core::record::Record;
use cairn_core::traits::Analyzer;
use cairn_core::Result;
use cairn_sigma::engine::Engine;
use cairn_sigma::SigmaMatcher;

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

impl Analyzer for SigmaAnalyzer {
    fn name(&self) -> &str {
        "sigma"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for record in records {
            if let Record::Event(ev) = record {
                match self.engine.match_event(ev) {
                    Ok(mut fs) => findings.append(&mut fs),
                    Err(e) => tracing::warn!(error = %e, "sigma match error; skipping event"),
                }
            }
        }
        Ok(findings)
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
        })
    }

    #[test]
    fn sigma_analyzer_ignores_non_event_records() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let records = vec![make_proc_record()];
        let findings = analyzer.analyze(&records).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn sigma_analyzer_empty_records_returns_empty() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let findings = analyzer.analyze(&[]).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn sigma_analyzer_match_fires_finding() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let ev = make_event(r"C:\Windows\System32\cmd.exe");
        let records = vec![Record::Event(ev)];
        let findings = analyzer.analyze(&records).unwrap();
        assert!(!findings.is_empty(), "cmd.exe should trigger the rule");
        assert_eq!(findings[0].rule_author.as_deref(), Some("test"));
    }

    #[test]
    fn sigma_analyzer_no_match_returns_empty() {
        let engine = Engine::from_rules(&[RULE_CMD]).unwrap();
        let analyzer = SigmaAnalyzer::new(engine);
        let ev = make_event(r"C:\Windows\System32\notepad.exe");
        let records = vec![Record::Event(ev)];
        let findings = analyzer.analyze(&records).unwrap();
        assert!(
            findings.is_empty(),
            "notepad.exe should not trigger cmd rule"
        );
    }
}
