//! Command-line surface (SRS §6): clap argument types only. Behaviour lives in the
//! per-subcommand modules (run, evtx, coverage, verify).
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cairn",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CAIRN_BUILD_SHA"), ")"),
    about = "Authorized Windows live-forensics triage engine"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Full run: collect + analyze + report.
    Run(Box<RunArgs>),
    /// Stage-1 engine only: parse EVTX files and run Sigma.
    Evtx {
        files: Vec<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Print which ATT&CK techniques this build can detect: built-in heuristics plus
    /// the Sigma rules' technique tags. Use it to know what a clean result does NOT
    /// rule out.
    Coverage {
        /// Rules dir to count Sigma techniques from (default: bundled rules/sigma).
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Re-hash a run's outputs (and optionally its ruleset) against the manifest.
    Verify {
        /// Path to manifest.json. Outputs are resolved relative to its directory.
        manifest: PathBuf,
        /// Rules dir to re-verify against manifest.tool.sigma_ruleset_ver (ADR-0003).
        /// Omit to skip the ruleset check and verify only the output/source hashes.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
}

#[derive(Parser)]
pub struct RunArgs {
    /// What to triage. Only "live" (this host) is supported, and it is the default;
    /// the flag is kept so existing `--target live` invocations still parse. For EVTX
    /// files use `cairn evtx`.
    #[arg(long, default_value = "live", value_parser = ["live"], ignore_case = true)]
    pub target: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub zip: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub rules: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    pub profile: String,
    /// comma-separated module allow-list, e.g. process,persist,evtx_live
    #[arg(long)]
    pub only: Option<String>,
    /// Only analyze live EVTX events at or after this RFC3339 UTC time.
    /// Default: 7 days before the run.
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub case_id: Option<String>,
    #[arg(long)]
    pub operator: Option<String>,
    /// Do NOT lower process priority on a live run (opt out of below-normal).
    #[arg(long)]
    pub full_speed: bool,
}

impl RunArgs {
    /// `--only` as a list (comma-separated, trimmed, empties dropped). None = no
    /// restriction.
    pub fn only_list(&self) -> Option<Vec<String>> {
        self.only.as_deref().map(|csv| {
            csv.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// --case-id / --operator parse (run copies them into the live manifest).
    #[test]
    fn run_args_case_id_and_operator_parse() {
        let cli = Cli::parse_from([
            "cairn",
            "run",
            "--target",
            "live",
            "--output",
            "out",
            "--case-id",
            "IR-1",
            "--operator",
            "sam",
        ]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("expected run");
        };
        assert_eq!(args.case_id.as_deref(), Some("IR-1"));
        assert_eq!(args.operator.as_deref(), Some("sam"));
    }

    #[test]
    fn run_target_defaults_to_live_and_rejects_dirs() {
        let args = RunArgs::try_parse_from(["cairn", "--output", "out"]).unwrap();
        assert_eq!(args.target, "live");
        assert!(RunArgs::try_parse_from(["cairn", "--target", "LIVE", "--output", "o"]).is_ok());
        assert!(
            RunArgs::try_parse_from(["cairn", "--target", "C:\\evidence", "--output", "o"])
                .is_err()
        );
    }

    /// Clap-parse assertion: --full-speed wires correctly into RunArgs.
    #[test]
    fn run_args_full_speed_parses_correctly() {
        let args = RunArgs::parse_from(["cairn", "--target", "live", "--output", "out"]);
        assert!(!args.full_speed, "--full-speed absent => false");
        let args_fs = RunArgs::parse_from([
            "cairn",
            "--target",
            "live",
            "--output",
            "out",
            "--full-speed",
        ]);
        assert!(args_fs.full_speed, "--full-speed present => true");
    }

    #[test]
    fn only_list_splits_and_trims() {
        let args = RunArgs::parse_from(["cairn", "--output", "o", "--only", " proc, ,persist "]);
        assert_eq!(
            args.only_list(),
            Some(vec!["proc".to_string(), "persist".to_string()])
        );
        let none = RunArgs::parse_from(["cairn", "--output", "o"]);
        assert_eq!(none.only_list(), None);
    }

    #[test]
    fn coverage_subcommand_parses() {
        let cli = Cli::parse_from(["cairn", "coverage"]);
        assert!(matches!(cli.cmd, Cmd::Coverage { rules: None }));
    }
}
