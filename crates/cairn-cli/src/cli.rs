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
    /// Only analyze (and export) live EVTX events at or after this RFC3339 UTC time.
    /// Default: 30 days before the run.
    #[arg(long)]
    pub since: Option<String>,
    /// Export the live EVTX channels (the --since window) to evidence/evtx/*.evtx in
    /// the OUTPUT location for re-parsing off-host. On by default; skipped under
    /// --dry-run and when the evtx_live module is not selected.
    #[arg(long, overrides_with = "no_export_evtx")]
    pub export_evtx: bool,
    /// Do not export EVTX channels (see --export-evtx).
    #[arg(long, overrides_with = "export_evtx")]
    pub no_export_evtx: bool,
    /// The true UTC time (RFC3339) at the moment you start the run, read from a
    /// trusted clock (phone / NTP). Recorded in the manifest with the host clock skew
    /// in seconds. Without it the skew is recorded as not measured.
    #[arg(long)]
    pub reference_time: Option<String>,
    #[arg(long)]
    pub case_id: Option<String>,
    #[arg(long)]
    pub operator: Option<String>,
    /// Do NOT lower process priority on a live run (opt out of below-normal).
    #[arg(long)]
    pub full_speed: bool,
    /// Per-collector time budget in seconds (0 = unlimited). A collector still running
    /// after this long (e.g. a stuck WMI query) is abandoned and recorded in the
    /// manifest; the run continues with the next one.
    #[arg(long, default_value_t = cairn_core::config::DEFAULT_COLLECTOR_TIMEOUT_SECS)]
    pub collector_timeout: u64,
}

impl RunArgs {
    /// EVTX export is on unless `--no-export-evtx` was the last word.
    pub fn export_evtx_enabled(&self) -> bool {
        !self.no_export_evtx
    }

    /// `--reference-time` parsed as UTC. A malformed value is a CLI error, raised
    /// before any output is created.
    pub fn reference_time(&self) -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
        self.reference_time
            .as_deref()
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|t| t.with_timezone(&chrono::Utc))
                    .map_err(|e| anyhow::anyhow!("--reference-time parse error: {e}"))
            })
            .transpose()
    }

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
    fn export_evtx_defaults_on_and_last_flag_wins() {
        let on = RunArgs::parse_from(["cairn", "--output", "o"]);
        assert!(on.export_evtx_enabled());
        let off = RunArgs::parse_from(["cairn", "--output", "o", "--no-export-evtx"]);
        assert!(!off.export_evtx_enabled());
        let back_on = RunArgs::parse_from([
            "cairn",
            "--output",
            "o",
            "--no-export-evtx",
            "--export-evtx",
        ]);
        assert!(back_on.export_evtx_enabled());
    }

    #[test]
    fn reference_time_parses_rfc3339_with_offset_and_rejects_garbage() {
        let a = RunArgs::parse_from([
            "cairn",
            "--output",
            "o",
            "--reference-time",
            "2026-10-21T10:00:00+08:00",
        ]);
        let t = a.reference_time().unwrap().unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-21T02:00:00+00:00");
        let none = RunArgs::parse_from(["cairn", "--output", "o"]);
        assert!(none.reference_time().unwrap().is_none());
        let bad = RunArgs::parse_from(["cairn", "--output", "o", "--reference-time", "now"]);
        assert!(bad.reference_time().is_err());
    }

    #[test]
    fn coverage_subcommand_parses() {
        let cli = Cli::parse_from(["cairn", "coverage"]);
        assert!(matches!(cli.cmd, Cmd::Coverage { rules: None }));
    }
}
