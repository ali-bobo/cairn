//! cairn: Windows live-forensics triage engine (CLI). SRS §6.
//!
//! Authorized DFIR use only. The tool logs its own actions (run.log) and is
//! designed to be SEEN and recognized as benign by EDR — never to evade it.
//! See README.md and docs/threat-model.md.

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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Evtx { files, rules } => {
            tracing::info!(
                ?files,
                ?rules,
                "TODO T4-T7: parse EVTX, run Sigma, write timeline"
            );
            // Build order for this subcommand IS Stage 1. See docs/stage1-plan.md.
        }
        Cmd::Run(_args) => {
            tracing::info!("TODO S2+: orchestrate collectors + analyzers + report");
        }
        Cmd::UpdateRules { .. } => tracing::info!("TODO S4"),
        Cmd::Verify { .. } => tracing::info!("TODO S3: re-hash archive vs manifest"),
    }
    Ok(())
}
