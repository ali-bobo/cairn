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

/// Project a Finding into the TIMELINE_COLS row (detection timeline, SRS §5.2).
fn timeline_row(f: &Finding) -> [String; 10] {
    let channel = f
        .artifact
        .strip_prefix("evtx:")
        .unwrap_or(&f.artifact)
        .to_string();
    let severity = serde_json::to_value(f.severity)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "info".into());
    [
        f.ts.to_rfc3339(),
        f.host.clone(),
        channel,
        f.event_id.map(|e| e.to_string()).unwrap_or_default(),
        severity,
        f.evidence_ref.clone().unwrap_or_default(),
        f.title.clone(),
        f.rule_author.clone().unwrap_or_default(),
        f.mitre.join(";"),
        f.details.clone(),
    ]
}

/// Render the detection timeline as Hayabusa-compatible CSV (SRS §5.2): one row per
/// rule hit, sorted by (ts, record_id) for reproducibility (NFR4), with identical
/// detections de-duplicated (FR5 — the count is reflected in the Summary, not here).
pub fn timeline_csv(findings: &[Finding]) -> String {
    let mut rows: Vec<[String; 10]> = findings.iter().map(timeline_row).collect();
    // Deterministic order: Timestamp then RecordID (cols 0 and 5).
    rows.sort_by(|a, b| (&a[0], &a[5]).cmp(&(&b[0], &b[5])));
    rows.dedup(); // identical adjacent detections collapse (rows are sorted)

    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(TIMELINE_COLS).expect("header");
    for r in &rows {
        wtr.write_record(r).expect("row");
    }
    let bytes = wtr.into_inner().expect("csv buffer");
    String::from_utf8(bytes).expect("csv is utf-8")
}

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

/// Writes results to a plain directory. S1 default. Off-target path recommended (FR16).
/// Records each written file's SHA-256 so `finalize` can emit the manifest outputs
/// (chain-of-custody, SRS §12).
pub struct DirSink {
    dir: std::path::PathBuf,
    outputs: Vec<OutputEntry>,
}

impl DirSink {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        DirSink {
            dir: dir.into(),
            outputs: Vec::new(),
        }
    }

    /// The output entries recorded so far (file + SHA-256), without consuming them.
    /// Lets the caller hash the data outputs (timeline, findings) and embed those
    /// hashes in the manifest *before* writing the manifest itself — the manifest
    /// records the data outputs' integrity, not its own (chain-of-custody, SRS §12).
    pub fn outputs_so_far(&self) -> Vec<OutputEntry> {
        self.outputs.clone()
    }

    /// Write `bytes` to `name` in the output dir and record its SHA-256.
    ///
    /// Output-path safety (threat-model #3): refuse to write if the target name is
    /// already a symlink — following it could redirect the write through to another
    /// volume (e.g. the source/target being investigated). We never modify sources.
    fn write_file(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(cairn_core::CairnError::Other(format!(
                    "refusing to write through a symlinked output: {}",
                    path.display()
                )));
            }
        }
        std::fs::write(&path, bytes)?;
        self.outputs.push(OutputEntry {
            file: name.to_string(),
            sha256: sha256_hex(bytes),
        });
        Ok(())
    }
}

impl OutputSink for DirSink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        let csv = timeline_csv(findings);
        self.write_file("timeline.csv", csv.as_bytes())
    }

    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> {
        let mut buf = String::new();
        for f in findings {
            buf.push_str(&serde_json::to_string(f)?);
            buf.push('\n');
        }
        self.write_file("findings.jsonl", buf.as_bytes())
    }

    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec_pretty(manifest)?;
        self.write_file("manifest.json", &json)
    }

    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        Ok(std::mem::take(&mut self.outputs))
    }
}
// TODO(claude-code) S3: ZipSink + EncryptedZipSink (asymmetric, public key only); DryRunSink.

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::{FindingSource, Severity};
    use chrono::{TimeZone, Utc};

    fn finding(ts_sec: i64, title: &str, record: u64) -> Finding {
        let mut f = Finding::new(Severity::High, title, FindingSource::Sigma);
        f.ts = Utc.timestamp_opt(ts_sec, 0).unwrap();
        f.event_id = Some(4688);
        f.rule_id = Some("rule-1".into());
        f.rule_author = Some("Author A".into());
        f.mitre = vec!["attack.t1059".into(), "attack.execution".into()];
        f.host = "WS01".into();
        f.artifact = "evtx:Security".into();
        f.evidence_ref = Some(record.to_string());
        f.details = "suspicious".into();
        f
    }

    /// The CSV starts with the Hayabusa-compatible header and projects a Finding into
    /// the right columns (channel from artifact, EventID, RecordID, joined MITRE).
    #[test]
    fn timeline_csv_has_header_and_projects_finding() {
        let csv = timeline_csv(&[finding(1_700_000_000, "Susp PS", 42)]);
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), TIMELINE_COLS.join(","));

        let row = lines.next().unwrap();
        assert!(row.contains("WS01"), "host: {row}");
        assert!(row.contains("Security"), "channel: {row}");
        assert!(row.contains("4688"), "event_id: {row}");
        assert!(row.contains("42"), "record id: {row}");
        assert!(row.contains("Author A"), "author: {row}");
        assert!(row.contains("attack.t1059"), "mitre: {row}");
    }

    /// Rows are sorted by (ts, record_id) for deterministic, reproducible output (NFR4).
    #[test]
    fn timeline_csv_sorts_by_ts_then_record() {
        let csv = timeline_csv(&[finding(200, "later", 1), finding(100, "earlier", 2)]);
        let body: Vec<&str> = csv.lines().skip(1).collect();
        assert!(body[0].contains("earlier"), "earlier ts first: {body:?}");
        assert!(body[1].contains("later"));
    }

    /// Identical detections (same ts/host/channel/event/record/rule/title) collapse to
    /// one row (FR5 dedupe); the count lives in the Summary, not the timeline.
    #[test]
    fn timeline_csv_dedupes_identical_rows() {
        let f = finding(100, "dup", 7);
        let csv = timeline_csv(&[f.clone(), f.clone(), f]);
        let body: Vec<&str> = csv.lines().skip(1).collect();
        assert_eq!(
            body.len(),
            1,
            "identical detections should dedupe: {body:?}"
        );
    }

    use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
    use cairn_core::traits::OutputSink;

    fn minimal_manifest() -> Manifest {
        Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo {
                name: "cairn".into(),
                version: "0.1.0".into(),
                build_sha: "abc1234".into(),
                sigma_ruleset_ver: String::new(),
            },
            run: RunInfo {
                started_utc: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                finished_utc: None,
                cmdline: "cairn evtx x.evtx".into(),
                operator: String::new(),
                case_id: String::new(),
            },
            host: HostInfo {
                hostname: "WS01".into(),
                os_build: String::new(),
                timezone: "UTC".into(),
                wall_clock_utc_skew: "+0s".into(),
            },
            privileges: Privileges {
                admin: false,
                se_backup: false,
                se_debug: false,
            },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
        }
    }

    /// DirSink writes timeline.csv, findings.jsonl and manifest.json into its dir;
    /// findings.jsonl has one JSON object per line; finalize() returns each output
    /// file with the SHA-256 of its bytes (chain-of-custody, SRS §12).
    #[test]
    fn dirsink_writes_outputs_and_hashes_them() {
        let dir = std::env::temp_dir().join("cairn_dirsink_test_a");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = DirSink::new(dir.clone());

        let findings = vec![finding(100, "f1", 1), finding(200, "f2", 2)];
        sink.write_timeline_csv(&findings).unwrap();
        sink.write_findings_jsonl(&findings).unwrap();
        sink.write_manifest(&minimal_manifest()).unwrap();
        let outputs = sink.finalize().unwrap();

        // findings.jsonl: one object per line.
        let jsonl = std::fs::read_to_string(dir.join("findings.jsonl")).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        let _: serde_json::Value = serde_json::from_str(lines[0]).unwrap();

        // manifest.json parses back.
        let mtext = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        let _: Manifest = serde_json::from_str(&mtext).unwrap();

        // finalize lists the outputs with hashes that match the files on disk.
        assert!(outputs.iter().any(|o| o.file == "timeline.csv"));
        let je = outputs.iter().find(|o| o.file == "findings.jsonl").unwrap();
        assert_eq!(je.sha256, sha256_hex(jsonl.as_bytes()));
        assert_eq!(je.sha256.len(), 64);
    }

    /// `outputs_so_far` returns the data outputs' hashes without consuming them, so the
    /// caller can embed them in the manifest before writing the manifest. The hashes
    /// match the files on disk, and finalize() still works afterward.
    #[test]
    fn outputs_so_far_returns_data_hashes_without_consuming() {
        let dir = std::env::temp_dir().join("cairn_outputs_so_far_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = DirSink::new(dir.clone());

        let findings = vec![finding(100, "f1", 1)];
        sink.write_timeline_csv(&findings).unwrap();
        sink.write_findings_jsonl(&findings).unwrap();

        let snapshot = sink.outputs_so_far();
        assert_eq!(snapshot.len(), 2, "two data outputs recorded");
        assert!(snapshot.iter().any(|o| o.file == "timeline.csv"));
        let jsonl = std::fs::read_to_string(dir.join("findings.jsonl")).unwrap();
        let je = snapshot
            .iter()
            .find(|o| o.file == "findings.jsonl")
            .unwrap();
        assert_eq!(je.sha256, sha256_hex(jsonl.as_bytes()));

        // Non-consuming: writing the manifest then finalize still lists all three.
        sink.write_manifest(&minimal_manifest()).unwrap();
        let outputs = sink.finalize().unwrap();
        assert_eq!(outputs.len(), 3);
    }

    /// Output-path safety (threat-model #3): if an output name is a pre-planted symlink,
    /// DirSink must refuse rather than follow it and write through to the target.
    #[cfg(windows)]
    #[test]
    fn dirsink_refuses_to_follow_a_symlinked_output() {
        let base = std::env::temp_dir().join("cairn_dirsink_symlink_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // A file we must NOT be tricked into overwriting, and a symlink pointing at it.
        let victim = base.join("victim.txt");
        std::fs::write(&victim, b"do not touch").unwrap();
        let link = base.join("timeline.csv");
        if std::os::windows::fs::symlink_file(&victim, &link).is_err() {
            eprintln!("skipping: no privilege to create symlinks on this host");
            return;
        }

        let mut sink = DirSink::new(base.clone());
        let res = sink.write_timeline_csv(&[finding(1, "x", 1)]);

        assert!(res.is_err(), "writing through a symlink must be refused");
        // The victim's content must be untouched.
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
    }
}
