//! cairn-report: timeline + summary + manifest + output sinks. SRS §5.2, §6, §12.
#![forbid(unsafe_code)] // pure formatting + hashing + file I/O; no raw-volume/WinAPI.

pub mod age_sink;
pub mod bodyfile;
pub mod client_text;
pub mod dry_run;
pub mod zip_sink;

pub use age_sink::AgeSink;
pub use dry_run::DryRunSink;
pub use zip_sink::ZipSink;

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
///
/// Panic-free by contract: this is on a forensic tool's output path, so even the
/// theoretically-impossible CSV-buffer errors must not abort a run. On any internal
/// writer error we fall back to a hand-built CSV (the inputs are our own owned Strings,
/// which the manual path quotes safely), so the worst case is a slightly less optimal
/// quoting, never a panic.
pub fn timeline_csv(findings: &[Finding]) -> String {
    let mut rows: Vec<[String; 10]> = findings.iter().map(timeline_row).collect();
    // Deterministic order: Timestamp then RecordID (cols 0 and 5).
    rows.sort_by(|a, b| (&a[0], &a[5]).cmp(&(&b[0], &b[5])));
    rows.dedup(); // identical adjacent detections collapse (rows are sorted)

    let mut wtr = csv::Writer::from_writer(Vec::new());
    let via_csv = wtr
        .write_record(TIMELINE_COLS)
        .and_then(|()| {
            for r in &rows {
                wtr.write_record(r)?;
            }
            Ok(())
        })
        .ok()
        .and_then(|()| wtr.into_inner().ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());

    via_csv.unwrap_or_else(|| manual_csv(&rows))
}

/// RFC-4180 fallback used only if the `csv` writer ever errs (it shouldn't for our
/// owned-String inputs). Quotes a field when it contains `,`, `"`, CR or LF; doubles
/// embedded quotes. Keeps `timeline_csv` total (never panics).
fn manual_csv(rows: &[[String; 10]]) -> String {
    fn field(s: &str) -> std::borrow::Cow<'_, str> {
        if s.contains([',', '"', '\n', '\r']) {
            std::borrow::Cow::Owned(format!("\"{}\"", s.replace('"', "\"\"")))
        } else {
            std::borrow::Cow::Borrowed(s)
        }
    }
    let mut out = String::new();
    out.push_str(&TIMELINE_COLS.join(","));
    out.push_str("\r\n");
    for r in rows {
        let line: Vec<std::borrow::Cow<'_, str>> = r.iter().map(|c| field(c)).collect();
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    out
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

/// Write `bytes` to `path`, refusing to follow a pre-planted symlink (threat-model §3).
/// Returns Err if path is a symlink; otherwise creates parent dirs and writes.
pub(crate) fn write_output_safe(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(cairn_core::CairnError::Other(format!(
                "refusing to write through a symlinked output: {}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
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

/// One file's integrity status during `verify` (SRS §12 / stage1-plan T9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    /// File present and its SHA-256 matches the manifest.
    Ok,
    /// File present but its hash differs from the manifest (tampered).
    Mismatch { expected: String, actual: String },
    /// File listed in the manifest is absent on disk.
    Missing,
}

/// One verified entry: which file, and whether it matched.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub file: String,
    pub status: CheckStatus,
}

/// Result of re-hashing a manifest's outputs and sources against the files on disk.
/// `ok()` is true only if every checked file is present and matches.
#[derive(Debug, Default)]
pub struct VerifyReport {
    pub outputs: Vec<CheckResult>,
    pub sources: Vec<CheckResult>,
}

impl VerifyReport {
    /// All checked entries are `Ok` (no mismatch, no missing).
    pub fn ok(&self) -> bool {
        self.outputs
            .iter()
            .chain(&self.sources)
            .all(|c| c.status == CheckStatus::Ok)
    }

    /// Just the failing entries (mismatch or missing), for reporting.
    pub fn failures(&self) -> Vec<&CheckResult> {
        self.outputs
            .iter()
            .chain(&self.sources)
            .filter(|c| c.status != CheckStatus::Ok)
            .collect()
    }
}

/// Read and parse a `manifest.json` from disk (verify entry point). Keeps serde_json in
/// the report crate so the CLI doesn't need it directly.
pub fn read_manifest(path: &std::path::Path) -> Result<Manifest> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Re-hash every output (relative to `base_dir`) and every source (by its recorded
/// absolute path) listed in `manifest`, comparing each to the recorded SHA-256
/// (stage1-plan T9). Does NOT verify the manifest's own integrity (a manifest can't
/// self-hash) nor the ruleset — the CLI composes the ADR-0003 ruleset check separately.
///
/// A read error on a listed file is reported as `Missing` rather than aborting the whole
/// verify (graceful degrade, golden rule 8) — verify should report ALL problems at once.
pub fn verify_manifest(manifest: &Manifest, base_dir: &std::path::Path) -> VerifyReport {
    let check = |name: &str, path: std::path::PathBuf, expected: &str| -> CheckResult {
        let status = match std::fs::read(&path) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual == expected {
                    CheckStatus::Ok
                } else {
                    CheckStatus::Mismatch {
                        expected: expected.to_string(),
                        actual,
                    }
                }
            }
            Err(_) => CheckStatus::Missing,
        };
        CheckResult {
            file: name.to_string(),
            status,
        }
    };

    VerifyReport {
        outputs: manifest
            .outputs
            .iter()
            .map(|o| check(&o.file, base_dir.join(&o.file), &o.sha256))
            .collect(),
        // Only file-backed sources can be re-hashed. A live/API source (process or net
        // table) has an empty sha256 and a `live:` pseudo-path — there are no bytes to
        // re-read, so it is not a verifiable artifact. Skip those (don't flag Missing).
        sources: manifest
            .sources
            .iter()
            .filter(|s| !s.sha256.is_empty())
            .map(|s| check(&s.path, std::path::PathBuf::from(&s.path), &s.sha256))
            .collect(),
    }
}

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

    /// The manual CSV fallback (used only if the csv writer ever errs) produces the
    /// same header and quotes a field containing a comma (RFC 4180), so timeline_csv is
    /// total — it never panics on the output path.
    #[test]
    fn manual_csv_fallback_quotes_and_matches_header() {
        // A finding whose author contains a comma (real SigmaHQ authors do, e.g.
        // "Name, oscd.community") — must be quoted in the fallback path.
        let mut f = finding(100, "t", 1);
        f.rule_author = Some("Alice, Bob".into());
        let rows: Vec<[String; 10]> = std::iter::once(&f).map(timeline_row).collect();
        let csv = manual_csv(&rows);

        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), TIMELINE_COLS.join(","));
        let row = lines.next().unwrap();
        assert!(
            row.contains("\"Alice, Bob\""),
            "comma field must be quoted: {row}"
        );
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
                profile: "standard".into(),
                selected_modules: vec!["evtx".into()],
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
            governance: cairn_core::manifest::GovernanceReport::default(),
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

    /// verify passes on a clean output set: every file the manifest lists is present and
    /// its SHA-256 matches (stage1-plan T9 happy path).
    #[test]
    fn verify_passes_on_clean_outputs() {
        let dir = std::env::temp_dir().join("cairn_verify_clean_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = DirSink::new(dir.clone());
        let findings = vec![finding(100, "f1", 1)];
        sink.write_timeline_csv(&findings).unwrap();
        sink.write_findings_jsonl(&findings).unwrap();

        let mut manifest = minimal_manifest();
        manifest.outputs = sink.outputs_so_far();

        let report = verify_manifest(&manifest, &dir);
        assert!(
            report.ok(),
            "clean outputs should verify: {:?}",
            report.failures()
        );
        assert_eq!(report.outputs.len(), 2);
    }

    /// A live/API source (empty sha256, `live:` pseudo-path — e.g. a process or net
    /// table) is NOT a file and must be skipped by verify, not flagged Missing. This is
    /// the fix surfaced by the S2-A `cairn run --target live` end-to-end run.
    #[test]
    fn verify_skips_live_sources_without_bytes() {
        use cairn_core::manifest::SourceEntry;
        let dir = std::env::temp_dir().join("cairn_verify_live_src_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = DirSink::new(dir.clone());
        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();

        let mut manifest = minimal_manifest();
        manifest.outputs = sink.outputs_so_far();
        manifest.sources = vec![SourceEntry {
            artifact: "process".into(),
            path: "live:process".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(), // no bytes to hash
            errors: vec![],
        }];

        let report = verify_manifest(&manifest, &dir);
        assert!(
            report.ok(),
            "live source must be skipped, not flagged: {:?}",
            report.failures()
        );
        assert_eq!(
            report.sources.len(),
            0,
            "live source is not a verifiable file"
        );
    }

    /// verify fails loudly when a single output byte is tampered after the manifest was
    /// written (stage1-plan T9 acceptance: tampered byte must be caught).
    #[test]
    fn verify_fails_on_tampered_output_byte() {
        let dir = std::env::temp_dir().join("cairn_verify_tamper_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = DirSink::new(dir.clone());
        let findings = vec![finding(100, "f1", 1)];
        sink.write_timeline_csv(&findings).unwrap();
        let mut manifest = minimal_manifest();
        manifest.outputs = sink.outputs_so_far();

        // Tamper: append a byte to timeline.csv after its hash was recorded.
        let p = dir.join("timeline.csv");
        let mut content = std::fs::read(&p).unwrap();
        content.push(b'!');
        std::fs::write(&p, &content).unwrap();

        let report = verify_manifest(&manifest, &dir);
        assert!(!report.ok(), "tampered output must fail verify");
        assert!(matches!(
            report.outputs[0].status,
            CheckStatus::Mismatch { .. }
        ));
    }

    /// verify reports a listed output that's gone as Missing (not a panic, not silently OK).
    #[test]
    fn verify_reports_missing_output() {
        let dir = std::env::temp_dir().join("cairn_verify_missing_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut manifest = minimal_manifest();
        manifest.outputs = vec![OutputEntry {
            file: "nope.csv".into(),
            sha256: "0".repeat(64),
        }];

        let report = verify_manifest(&manifest, &dir);
        assert!(!report.ok());
        assert_eq!(report.outputs[0].status, CheckStatus::Missing);
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
            // Creating a symlink needs Developer Mode / admin. On a dev box without it we
            // skip — but CI sets CAIRN_REQUIRE_SYMLINK_TESTS=1 so the guard is genuinely
            // exercised there; a silent skip in CI would hide a broken guard.
            if std::env::var_os("CAIRN_REQUIRE_SYMLINK_TESTS").is_some() {
                panic!(
                    "CAIRN_REQUIRE_SYMLINK_TESTS set but symlink creation failed — \
                        the output-path-safety guard was not exercised"
                );
            }
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
