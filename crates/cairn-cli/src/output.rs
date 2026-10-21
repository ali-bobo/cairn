//! Output plumbing shared by the live and offline runs: logging setup, rules lookup,
//! Sigma loading, deterministic finding order, sinks and the manifest skeleton.
use cairn_core::finding::Finding;
use cairn_core::manifest::{
    Counts, GovernanceReport, HostInfo, Manifest, Privileges, RunInfo, ToolInfo,
};
use cairn_core::traits::OutputSink;
use cairn_core::{Config, OutputKind};
use cairn_report::{DirSink, DryRunSink, ZipSink};
use cairn_sigma::{engine::Engine, SigmaMatcher};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

/// Git commit this binary was built from (stamped by build.rs). Recorded in the run
/// manifest as `tool.build_sha` (SRS §5.3 / §13 legitimacy & transparency).
pub const BUILD_SHA: &str = env!("CAIRN_BUILD_SHA");

/// run.log should record Cairn's own actions only — not the internal trace/info of
/// dependencies like the `evtx` parser. Keep cairn crates at info; everything else
/// must reach warn to be logged. RUST_LOG overrides this for debugging.
///
/// NOTE: the binary's tracing target is `cairn` (from `[[bin]] name`), not the
/// package name `cairn_cli` — events from this binary are tagged `cairn`.
fn log_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "warn,cairn=info,cairn_collectors=info,cairn_core=info,\
             cairn_sigma=info,cairn_report=info",
        )
    })
}

/// Transparent self-logging (FR6 / SRS §13): tracing goes to `<dir>/run.log`. The
/// returned guard must live until logging is done (the non-blocking writer flushes on
/// drop).
pub fn init_file_logging(dir: &Path) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = tracing_appender::rolling::never(dir, "run.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .with_target(false)
        .with_ansi(false)
        .with_writer(file_writer)
        .init();
    guard
}

/// Logging to stderr only (dry-run, coverage, verify: nothing is written to disk).
pub fn init_stderr_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

/// The bundled rules directory used when `--rules` is omitted: `rules/sigma` next to
/// the running binary (the packaged layout), else `rules/sigma` under the current
/// directory (a source checkout). None if neither exists — the run then logs that
/// Sigma is skipped.
pub fn default_rules_dir() -> Option<PathBuf> {
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("rules").join("sigma")));
    let in_cwd = std::env::current_dir()
        .ok()
        .map(|d| d.join("rules").join("sigma"));
    [beside_exe, in_cwd]
        .into_iter()
        .flatten()
        .find(|d| d.is_dir())
}

/// Load the Sigma rules from `cfg.rules_dir` as an analyzer. A missing rules dir or a
/// load failure is logged and yields None: the run continues without Sigma (golden
/// rule 8).
pub fn load_sigma(cfg: &Config) -> Option<cairn_heur::SigmaAnalyzer> {
    let Some(rules_dir) = cfg.rules_dir.as_deref() else {
        tracing::warn!(
            "no --rules and no bundled rules/sigma beside the binary or in the current \
             directory; skipping Sigma"
        );
        return None;
    };
    let mut engine = Engine::default();
    match engine.load(rules_dir) {
        Ok(n) => {
            tracing::info!(rules = n, dir = %rules_dir.display(), "loaded sigma rules");
            Some(cairn_heur::SigmaAnalyzer::new(engine))
        }
        Err(e) => {
            tracing::warn!(error = %e, dir = %rules_dir.display(), "rule load failed; skipping Sigma");
            None
        }
    }
}

/// Deterministic output ordering (NFR4): sort by (ts, then a stable tiebreak key).
/// Heuristic findings have no record_id, so the tiebreak is (title, then entity pid for
/// process / lport for netconn). Never sort by the random Finding.id (uuid).
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.ts.cmp(&b.ts)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| finding_tiebreak(a).cmp(&finding_tiebreak(b)))
    });
}

/// Stable secondary key: process pid or netconn lport (0 if neither).
fn finding_tiebreak(f: &Finding) -> u32 {
    if let Some(p) = &f.entity.process {
        p.pid
    } else if let Some(n) = &f.entity.netconn {
        n.lport as u32
    } else {
        0
    }
}

/// Dump collected Records as JSONL (the internal bus type; versioned by
/// schema::RECORD) so a live run's raw data is reviewable and replayable.
pub fn write_records_jsonl(
    dir: &Path,
    records: &[cairn_core::record::Record],
) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(dir.join("records.jsonl"))?;
    for r in records {
        writeln!(f, "{}", serde_json::to_string(r)?)?;
    }
    Ok(())
}

/// Construct the correct OutputSink variant from the resolved OutputKind (FR15/FR16).
pub fn build_sink(output: &OutputKind) -> Box<dyn OutputSink + Send> {
    match output {
        OutputKind::Dir(p) => Box::new(DirSink::new(p)),
        OutputKind::Zip(p) => Box::new(ZipSink::new(p)),
        OutputKind::DryRun => Box::new(DryRunSink),
    }
}

/// The manifest's `sigma_ruleset_ver` for this run (ADR-0003): `"<pin>+<aggregate>"`
/// computed over the rules dir actually used, or empty when no rules ran. A hash
/// failure degrades to empty rather than aborting the manifest (golden rule 8); the
/// rule-load path already surfaces real load errors to run.log.
pub fn ruleset_ver(cfg: &Config) -> String {
    match cfg.rules_dir.as_deref() {
        Some(dir) => cairn_sigma::ruleset::ruleset_version(dir).unwrap_or_default(),
        None => String::new(),
    }
}

/// The run manifest (SRS §5.3) with the fields both runs share filled in: tool
/// identity, the command, operator/case, counts, and `started_utc` (when the run
/// began, not when the manifest is built). Host, privileges, profile, modules, sources
/// and governance default to the offline-run values; the live run overrides them.
pub fn base_manifest(
    cfg: &Config,
    hostname: &str,
    records: u64,
    findings: &[Finding],
    observations: u64,
    started_utc: chrono::DateTime<chrono::Utc>,
) -> Manifest {
    let by_sev = cairn_report::Summary::from_findings(findings, records).by_severity;
    Manifest {
        schema: cairn_core::schema::MANIFEST.to_string(),
        tool: ToolInfo {
            name: "cairn".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build_sha: BUILD_SHA.into(),
            sigma_ruleset_ver: ruleset_ver(cfg),
        },
        run: RunInfo {
            started_utc,
            finished_utc: Some(chrono::Utc::now()),
            cmdline: std::env::args().collect::<Vec<_>>().join(" "),
            operator: cfg.operator.clone(),
            case_id: cfg.case_id.clone(),
            profile: format!("{:?}", cfg.profile).to_lowercase(),
            selected_modules: vec![],
        },
        host: HostInfo {
            hostname: hostname.to_string(),
            os_build: String::new(),
            timezone: "UTC".into(),
            wall_clock_utc_skew: "unknown".into(),
        },
        privileges: Privileges {
            admin: false,
            se_backup: false,
            se_debug: false,
        },
        sources: vec![],
        outputs: vec![],
        counts: Counts {
            records,
            findings_by_sev: by_sev,
            observations,
        },
        integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
        governance: GovernanceReport::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::{FindingSource, Severity};

    #[test]
    fn findings_sort_is_deterministic_by_ts_then_title() {
        let mut a = Finding::new(Severity::High, "b-title", FindingSource::Heuristic);
        let mut b = Finding::new(Severity::High, "a-title", FindingSource::Heuristic);
        let ts = chrono::Utc::now();
        a.ts = ts;
        b.ts = ts;
        let mut v = vec![a, b];
        sort_findings(&mut v);
        assert_eq!(v[0].title, "a-title");
        assert_eq!(v[1].title, "b-title");
    }

    /// The manifest records when the run started, not when the manifest was built.
    #[test]
    fn base_manifest_keeps_the_given_start_time() {
        let cfg = Config::for_evtx(vec![], None);
        let started = chrono::Utc::now() - chrono::Duration::minutes(5);
        let m = base_manifest(&cfg, "WS01", 0, &[], 0, started);
        assert_eq!(m.run.started_utc, started);
        assert!(m.run.finished_utc.expect("finished set") > started);
    }

    /// With no rules dir the manifest's sigma_ruleset_ver is empty (no rules ran).
    #[test]
    fn ruleset_ver_is_empty_without_rules() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert_eq!(ruleset_ver(&cfg), "");
    }

    /// With the bundled rules dir, sigma_ruleset_ver is "<pin>+<aggregate>"
    /// (ADR-0003): the pin from PROVENANCE and a 64-char aggregate, computed over the
    /// real bundled rules this binary ships.
    #[test]
    fn ruleset_ver_is_pin_plus_aggregate_for_bundled_rules() {
        let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma");
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], Some(bundled));
        let ver = ruleset_ver(&cfg);
        let (pin, agg) = ver.split_once('+').expect("ver must be pin+aggregate");
        assert_eq!(
            pin, "98781da19cf60c48ce6e7f2d3ad11c9ba389191a",
            "ADR-0003 pin"
        );
        assert_eq!(agg.len(), 64, "aggregate is a SHA-256 hex");
        assert!(agg.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
