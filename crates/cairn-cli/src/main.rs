//! cairn: Windows live-forensics triage engine (CLI). SRS §6.
//!
//! Authorized DFIR use only. The tool logs its own actions (run.log) and is
//! designed to be SEEN and recognized as benign by EDR — never to evade it.
//! See README.md and docs/threat-model.md.

use cairn_core::finding::Finding;
use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
use cairn_core::traits::OutputSink;
use cairn_core::{Config, OutputKind, Target};
use cairn_report::DirSink;
use cairn_sigma::{engine::Engine, SigmaMatcher};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// run.log should record Cairn's own actions only — not the internal trace/info of
/// dependencies like the `evtx` parser. Keep cairn crates at info; everything else
/// must reach warn to be logged. RUST_LOG overrides this for debugging.
///
/// NOTE: the binary's tracing target is `cairn` (from `[[bin]] name`), not the
/// package name `cairn_cli` — events from main.rs are tagged `cairn`.
fn log_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "warn,cairn=info,cairn_collectors=info,cairn_core=info,\
             cairn_sigma=info,cairn_report=info",
        )
    })
}

/// Git commit this binary was built from (stamped by build.rs). Recorded in the run
/// manifest as `tool.build_sha` (SRS §5.3 / §13 legitimacy & transparency).
pub const BUILD_SHA: &str = env!("CAIRN_BUILD_SHA");

#[derive(Parser)]
#[command(
    name = "cairn",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CAIRN_BUILD_SHA"), ")"),
    about = "Authorized Windows live-forensics triage engine"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Full run: collect + analyze + report.
    Run(RunArgs),
    /// Stage-1 engine only: parse EVTX files and run Sigma.
    Evtx {
        files: Vec<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Load un-encoded `.yml` rules instead of the XOR-encoded bundle (ADR-0002).
        /// Lets a SOC audit exactly what runs; off by default (bundle is encoded).
        #[arg(long)]
        rules_plain: bool,
    },
    /// Fetch + pin the Sigma ruleset (S4).
    UpdateRules {
        #[arg(long)]
        pin: Option<String>,
    },
    /// Re-hash an output archive and verify against its manifest.
    Verify { manifest: PathBuf },
}

#[derive(Parser)]
struct RunArgs {
    /// "live" or a directory of artifacts.
    #[arg(long)]
    target: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    zip: bool,
    #[arg(long)]
    encrypt: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    /// enable Administrator-only collectors (only effective if priv present).
    #[arg(long)]
    admin_features: bool,
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    profile: String,
    /// comma-separated module allow-list, e.g. evtx,process,persist
    #[arg(long)]
    only: Option<String>,
    #[arg(long)]
    since: Option<String>,
    #[arg(long)]
    case_id: Option<String>,
    #[arg(long)]
    operator: Option<String>,
    #[arg(long)]
    use_vss: bool,
}

/// A one-line, human-readable run plan for the `evtx` subcommand, logged to run.log
/// for transparency (SRS §13 / FR6). Pure function so it is unit-testable.
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
        OutputKind::EncryptedZip { path, .. } => format!("{} (encrypted)", path.display()),
        OutputKind::DryRun => "<dry-run, no writes>".to_string(),
    };
    let encoding = if cfg.rules_plain { "plain" } else { "xor" };
    format!("plan: evtx triage of {n} file(s); rules={rules} (encoding={encoding}); output={out}")
}

/// Off-target output directory for a Stage-1 evtx run (golden rule 4). Resolved from
/// the Config; run.log is written here.
fn output_dir(cfg: &Config) -> PathBuf {
    match &cfg.output {
        OutputKind::Dir(p) | OutputKind::Zip(p) => p.clone(),
        OutputKind::EncryptedZip { path, .. } => path.clone(),
        OutputKind::DryRun => PathBuf::from("."),
    }
}

/// The manifest's `sigma_ruleset_ver` for this run (ADR-0003): `"<pin>+<aggregate>"`
/// computed over the rules dir actually used, or empty when no rules ran. A hash
/// failure degrades to empty rather than aborting the manifest (golden rule 8); the
/// rule-load path already surfaces real load errors to run.log.
fn ruleset_ver(cfg: &Config) -> String {
    match cfg.rules_dir.as_deref() {
        Some(dir) => {
            cairn_sigma::ruleset::ruleset_version(dir, cfg.rules_plain).unwrap_or_default()
        }
        None => String::new(),
    }
}

/// Assemble the run manifest (SRS §5.3). Stage-1 evtx run: user-space, no privileges,
/// sources hashing is added when the collector reports provenance (T8+); for now the
/// manifest carries tool identity, the command, host, and detection counts.
fn build_manifest(cfg: &Config, hostname: &str, records: u64, findings: &[Finding]) -> Manifest {
    // Reuse the report crate's severity tally instead of recomputing it here.
    let by_sev = cairn_report::Summary::from_findings(findings, records).by_severity;
    Manifest {
        schema: cairn_core::schema::MANIFEST.to_string(),
        tool: ToolInfo {
            name: "cairn".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build_sha: BUILD_SHA.into(),
            sigma_ruleset_ver: ruleset_ver(cfg), // "<pin>+<aggregate>" (ADR-0003)
        },
        run: RunInfo {
            started_utc: chrono::Utc::now(),
            finished_utc: Some(chrono::Utc::now()),
            cmdline: std::env::args().collect::<Vec<_>>().join(" "),
            operator: cfg.operator.clone(),
            case_id: cfg.case_id.clone(),
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
        outputs: vec![], // filled by verify against the on-disk files (T9)
        counts: Counts {
            records,
            findings_by_sev: by_sev,
        },
        integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Evtx {
            files,
            rules,
            rules_plain,
        } => {
            let cfg = Config::for_evtx(files, rules).with_rules_plain(rules_plain);
            let dir = output_dir(&cfg);
            std::fs::create_dir_all(&dir)?;

            // Transparent self-logging (FR6 / SRS §13): tee tracing to run.log in the
            // output dir AND to stderr so the analyst sees activity live. Full
            // per-file/per-action logging lands in T3.
            let file_appender = tracing_appender::rolling::never(&dir, "run.log");
            let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::fmt()
                .with_env_filter(log_filter())
                .with_target(false)
                .with_ansi(false)
                .with_writer(file_writer)
                .init();

            tracing::info!(
                "cairn {} ({}) starting",
                env!("CARGO_PKG_VERSION"),
                BUILD_SHA
            );
            tracing::info!("{}", evtx_plan(&cfg));

            // T3/T4: open each input, parse it, and log the read with a UTC timestamp
            // and record count. A failed file is logged and skipped, never fatal
            // (graceful degrade, golden rule 8).
            let files: &[PathBuf] = match &cfg.target {
                Target::Files(f) => f,
                _ => &[],
            };
            let mut records = Vec::new();
            for path in files {
                match cairn_collectors::evtx::parse_evtx(path) {
                    Ok(recs) => {
                        tracing::info!(file = %path.display(), records = recs.len(), "parsed evtx");
                        records.extend(recs);
                    }
                    Err(e) => {
                        tracing::warn!(file = %path.display(), error = %e, "skipped (parse failed)");
                    }
                }
            }
            tracing::info!(records = records.len(), "evtx parse complete");

            // T6: run Sigma over the parsed events (if a rules dir was given).
            let mut findings = Vec::new();
            if let Some(rules_dir) = cfg.rules_dir.as_deref() {
                let mut engine = Engine::default();
                match engine.load(rules_dir, cfg.rules_plain) {
                    Ok(n) => {
                        tracing::info!(rules = n, dir = %rules_dir.display(), plain = cfg.rules_plain, "loaded sigma rules");
                        for ev in &records {
                            match engine.match_event(ev) {
                                Ok(mut fs) => findings.append(&mut fs),
                                Err(e) => tracing::warn!(error = %e, "match error"),
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, dir = %rules_dir.display(), "rule load failed")
                    }
                }
            } else {
                tracing::info!("no --rules dir; skipping Sigma (parse-only run)");
            }
            tracing::info!(findings = findings.len(), "analysis complete");

            // T7: write timeline.csv + findings.jsonl + manifest.json.
            let hostname = records
                .first()
                .map(|r| r.computer.clone())
                .unwrap_or_default();
            let manifest = build_manifest(&cfg, &hostname, records.len() as u64, &findings);
            let mut sink = DirSink::new(dir.clone());
            sink.write_timeline_csv(&findings)?;
            sink.write_findings_jsonl(&findings)?;
            sink.write_manifest(&manifest)?;
            let outputs = sink.finalize()?;
            for o in &outputs {
                tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
            }
            tracing::info!(dir = %dir.display(), "report complete");
            // _guard must live until logging is done; non-blocking writer flushes on drop.
            drop(_guard);
        }
        other => {
            tracing_subscriber::fmt()
                .with_env_filter(log_filter())
                .with_target(false)
                .init();
            match other {
                Cmd::Run(_args) => {
                    tracing::info!("TODO S2+: orchestrate collectors + analyzers + report");
                }
                Cmd::UpdateRules { .. } => tracing::info!("TODO S4"),
                Cmd::Verify { .. } => tracing::info!("TODO S3: re-hash archive vs manifest"),
                Cmd::Evtx { .. } => unreachable!(),
            }
        }
    }
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

    #[test]
    fn evtx_plan_shows_bundled_rules_when_none() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert!(evtx_plan(&cfg).contains("rules=<bundled>"));
    }

    /// The plan records the rule-encoding mode so run.log shows whether `--rules-plain`
    /// was used (transparency: a SOC reading the log knows if rules were decoded).
    #[test]
    fn evtx_plan_records_rules_plain_mode() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], Some(PathBuf::from("./r")));
        assert!(
            evtx_plan(&cfg).contains("encoding=xor"),
            "default is encoded"
        );
        let cfg = cfg.with_rules_plain(true);
        assert!(evtx_plan(&cfg).contains("encoding=plain"));
    }

    /// With no rules dir the manifest's sigma_ruleset_ver is empty (no rules ran).
    #[test]
    fn ruleset_ver_is_empty_without_rules() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert_eq!(ruleset_ver(&cfg), "");
    }

    /// With the bundled (encoded) rules dir, sigma_ruleset_ver is "<pin>+<aggregate>"
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
