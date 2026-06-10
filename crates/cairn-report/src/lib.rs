//! cairn-report: timeline + summary + manifest + output sinks. SRS §5.2, §6, §12.
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    Result,
};
use sha2::{Digest, Sha256};

/// SHA-256 of bytes-as-collected. Used for manifest source/output entries.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Hayabusa-compatible timeline columns (SRS §5.2).
pub const TIMELINE_COLS: &[&str] = &[
    "Timestamp",
    "Host",
    "Channel",
    "EventID",
    "Severity",
    "RecordID",
    "RuleTitle",
    "RuleAuthor",
    "MITRE",
    "Details",
];

/// Detection summary built from Findings (counts by severity, tops). Summary-first (FR4).
#[derive(Debug, Default)]
pub struct Summary {
    pub total_records: u64,
    pub by_severity: std::collections::BTreeMap<String, u64>,
    pub top_hosts: Vec<(String, u64)>,
    pub top_rules: Vec<(String, u64)>,
}

impl Summary {
    pub fn from_findings(findings: &[Finding], total_records: u64) -> Self {
        let mut s = Summary {
            total_records,
            ..Default::default()
        };
        for f in findings {
            let sev = serde_json::to_value(f.severity)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "info".into());
            *s.by_severity.entry(sev).or_insert(0) += 1;
        }
        s
    }
}

/// Writes to a plain directory. S1 default. Off-target path recommended (FR16).
pub struct DirSink {/* TODO(claude-code) T7: dir path, file handles */}

impl OutputSink for DirSink {
    fn write_timeline_csv(&mut self, _findings: &[Finding]) -> Result<()> {
        // TODO T7: write csv with TIMELINE_COLS; project each Finding -> a timeline row;
        // dedupe identical detections w/ count (FR5).
        Ok(())
    }
    fn write_findings_jsonl(&mut self, _findings: &[Finding]) -> Result<()> {
        // TODO T7: one Finding JSON per line.
        Ok(())
    }
    fn write_manifest(&mut self, _manifest: &Manifest) -> Result<()> {
        // TODO T7: serialize manifest.json; then hash it into outputs.
        Ok(())
    }
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        Ok(vec![])
    }
}
// TODO(claude-code) S3: ZipSink + EncryptedZipSink (asymmetric, public key only); DryRunSink.
