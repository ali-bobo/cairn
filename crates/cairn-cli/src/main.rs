//! cairn: Windows live-forensics triage engine (CLI). SRS §6.
//!
//! Authorized DFIR use only. The tool logs its own actions (run.log) and is
//! designed to be SEEN and recognized as benign by EDR — never to evade it.
//! See README.md and docs/threat-model.md.

use cairn_core::{Config, OutputKind, Target};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    format!("plan: evtx triage of {n} file(s); rules={rules}; output={out}")
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Evtx { files, rules } => {
            let cfg = Config::for_evtx(files, rules);
            let dir = output_dir(&cfg);
            std::fs::create_dir_all(&dir)?;

            // Transparent self-logging (FR6 / SRS §13): tee tracing to run.log in the
            // output dir AND to stderr so the analyst sees activity live. Full
            // per-file/per-action logging lands in T3.
            let file_appender = tracing_appender::rolling::never(&dir, "run.log");
            let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::fmt()
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
            tracing::info!("TODO T4-T7: parse EVTX, run Sigma, write timeline");
            // _guard must live until logging is done; non-blocking writer flushes on drop.
            drop(_guard);
        }
        other => {
            tracing_subscriber::fmt().with_target(false).init();
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
}
