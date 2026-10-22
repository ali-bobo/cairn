//! cairn: Windows live-forensics triage engine (CLI). SRS §6.
//!
//! Authorized DFIR use only. The tool logs its own actions (run.log) and is
//! designed to be SEEN and recognized as benign by EDR — never to evade it.
//! See README.md and docs/threat-model.md.
//!
//! Layout: `cli` (clap args), `registry` (the one collector + analyzer list), `run`
//! (live triage), `evtx` (offline EVTX), `coverage`, `verify`, `enrich` (IOC hashes)
//! and `output` (logging, sinks, manifest skeleton shared by run and evtx).
#![forbid(unsafe_code)] // CLI orchestration only; WinAPI lives in cairn-collectors-win.

mod cli;
mod coverage;
mod enrich;
mod evtx;
mod export;
mod output;
mod registry;
mod run;
mod verify;

#[cfg(test)]
mod real_evtx;

use clap::Parser;
use cli::{Cli, Cmd};

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Run(args) => run::run(&args),
        Cmd::Evtx { files, rules } => evtx::run(files, rules),
        Cmd::Coverage { rules } => {
            output::init_stderr_logging();
            coverage::run(rules);
            Ok(())
        }
        Cmd::Verify { manifest, rules } => {
            output::init_stderr_logging();
            // Non-zero exit on any integrity failure so scripts/CI can detect it.
            if !verify::run_verify(&manifest, rules)? {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
