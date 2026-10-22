//! `cairn evtx <files>`: offline EVTX triage. Parses the files, runs the offline
//! analyzers from the shared registry (plus Sigma) through the same analyzer fan-in as
//! the live run, and writes timeline/findings/report/manifest to the output dir.
use crate::output::{self, BUILD_SHA};
use crate::registry::{self, Mode};
use cairn_core::traits::OutputSink;
use cairn_core::{Config, OutputKind, SourceEntry, Target};
use cairn_report::{client_text, DirSink};
use std::path::PathBuf;

/// A one-line, human-readable run plan, logged to run.log for transparency
/// (SRS §13 / FR6). Pure function so it is unit-testable.
fn evtx_plan(cfg: &Config) -> String {
    let n = match &cfg.target {
        Target::Files(f) => f.len(),
        _ => 0,
    };
    let rules = cfg
        .rules_dir
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<bundled>".to_string());
    let out = match &cfg.output {
        OutputKind::Dir(p) => p.display().to_string(),
        OutputKind::Zip(p) => format!("{} (zip)", p.display()),
        OutputKind::DryRun => "<dry-run, no writes>".to_string(),
    };
    format!("plan: evtx triage of {n} file(s); rules={rules}; output={out}")
}

/// Off-target output directory for the evtx run (golden rule 4); run.log goes here.
fn output_dir(cfg: &Config) -> PathBuf {
    match &cfg.output {
        OutputKind::Dir(p) | OutputKind::Zip(p) => p.clone(),
        OutputKind::DryRun => PathBuf::from("."),
    }
}

/// Manifest entry for an input file that could not be read completely (graceful
/// degrade is recorded, not only logged). No sha256: the entry records the failure,
/// it does not vouch for the file's bytes.
fn input_failure_entry(path: &std::path::Path, errors: Vec<String>) -> SourceEntry {
    SourceEntry {
        collector: "evtx".into(),
        artifact: "evtx".into(),
        path: path.display().to_string(),
        method: "file".into(),
        size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        sha256: String::new(),
        errors,
    }
}

/// Parse every input file and run the offline analyzer set (plus Sigma) over the
/// records: `(records, hostname, analysis)`, findings stamped with the host and sorted.
/// A file that fails to parse is logged, recorded first in `analysis.errors` (it becomes
/// a manifest source) and skipped, never fatal (golden rule 8).
pub(crate) fn analyze(
    cfg: &Config,
) -> (
    Vec<cairn_core::Record>,
    String,
    cairn_core::orchestrator::AnalysisOutcome,
) {
    let files: &[PathBuf] = match &cfg.target {
        Target::Files(f) => f,
        _ => &[],
    };
    let mut events = Vec::new();
    let mut input_errors = Vec::new();
    for path in files {
        let (recs, errors) = cairn_collectors::evtx::parse_evtx_contained(path);
        tracing::info!(file = %path.display(), records = recs.len(), "parsed evtx");
        events.extend(recs);
        if !errors.is_empty() {
            tracing::warn!(file = %path.display(), errors = ?errors, "evtx input incomplete");
            input_errors.push(input_failure_entry(path, errors));
        }
    }
    tracing::info!(records = events.len(), "evtx parse complete");
    let hostname = events
        .first()
        .map(|r| r.computer.clone())
        .unwrap_or_default();
    let records: Vec<cairn_core::Record> =
        events.into_iter().map(cairn_core::Record::Event).collect();

    // Built-in event-log heuristics run with or without Sigma rules.
    let analyzers = registry::analyzers(cfg, Mode::Evtx, output::load_sigma(cfg));
    let mut analysis = cairn_core::orchestrator::run_analyzers(&records, &analyzers);
    input_errors.append(&mut analysis.errors);
    analysis.errors = input_errors;
    for f in &mut analysis.findings {
        f.host = hostname.clone();
    }
    output::sort_findings(&mut analysis.findings);
    (records, hostname, analysis)
}

pub fn run(files: Vec<PathBuf>, rules: Option<PathBuf>) -> anyhow::Result<()> {
    let started_utc = chrono::Utc::now();
    let cfg = Config::for_evtx(files, rules.or_else(output::default_rules_dir));
    let dir = output_dir(&cfg);
    std::fs::create_dir_all(&dir)?;
    let guard = output::init_file_logging(&dir);

    tracing::info!(
        "cairn {} ({}) starting",
        env!("CARGO_PKG_VERSION"),
        BUILD_SHA
    );
    tracing::info!("{}", evtx_plan(&cfg));

    let (records, hostname, analysis) = analyze(&cfg);
    let mut findings = analysis.findings;
    tracing::info!(findings = findings.len(), "analysis complete");

    // The data outputs are written first so their SHA-256s can be embedded into the
    // manifest's `outputs` (chain-of-custody; `cairn verify` re-checks them).
    let mut manifest = output::base_manifest(
        &cfg,
        &hostname,
        records.len() as u64,
        &findings,
        analysis.observations.len() as u64,
        started_utc,
    );
    // No live collectors ran: the selected module is the evtx engine itself.
    manifest.run.profile = "standard".into();
    manifest.run.selected_modules = vec!["evtx".into()];
    manifest.sources = analysis.errors;
    for f in &mut findings {
        client_text::fill_details_client(f, manifest.run.started_utc);
    }
    let mut sink = DirSink::new(dir.clone());
    sink.write_timeline_csv(&findings)?;
    sink.write_findings_jsonl(&findings)?;
    // No live records: the report renders its offline (event-log only) overview.
    sink.write_html_report(&findings, &analysis.observations, &[], &manifest)?;
    manifest.outputs = sink.outputs_so_far();
    sink.write_manifest(&manifest)?;
    for o in sink.finalize()? {
        tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
    }
    tracing::info!(dir = %dir.display(), "report complete");
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evtx_plan_reports_file_count_rules_and_output() {
        let cfg = Config::for_evtx(
            vec![PathBuf::from("a.evtx"), PathBuf::from("b.evtx")],
            Some(PathBuf::from("./rules")),
        );
        let line = evtx_plan(&cfg);
        assert!(line.contains("2 file(s)"), "{line}");
        assert!(line.contains("rules=./rules"), "{line}");
        assert!(line.contains("output="), "{line}");
    }

    /// An unreadable input is recorded for the manifest with its reason, no hash.
    #[test]
    fn unreadable_input_becomes_a_manifest_source_with_errors() {
        let p = PathBuf::from("/definitely/missing/Security.evtx");
        let (evs, errs) = cairn_collectors::evtx::parse_evtx_contained(&p);
        assert!(evs.is_empty());
        let e = input_failure_entry(&p, errs);
        assert_eq!(e.collector, "evtx");
        assert!(e.path.ends_with("Security.evtx"));
        assert!(!e.errors.is_empty());
        assert!(e.sha256.is_empty(), "verify must not try to re-hash it");
    }

    #[test]
    fn evtx_plan_shows_bundled_rules_when_none() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert!(evtx_plan(&cfg).contains("rules=<bundled>"));
    }
}
