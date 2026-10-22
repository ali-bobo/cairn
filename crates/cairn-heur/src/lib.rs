//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
//!
//! When two analyzers judge the same evidence (a 7045 read by `heur_eventlog` and
//! `heur_lateral`, a Defender exclusion seen in the registry and in its 5007 event, a
//! Sigma hit on an event a heuristic also judges), the later one applies the
//! same-evidence rule in `dedup.rs`: one merged finding, never two.
#![forbid(unsafe_code)]

pub mod account;
pub mod asep;
pub mod clickfix;
pub(crate) mod cmdline;
pub mod coverage;
pub mod cred_dump;
pub(crate) mod dedup;
pub mod defense;
pub mod eventlog;
pub mod lateral;
pub mod logon_bruteforce;
pub mod netconn;
pub mod parentchild;
pub mod persist;
pub mod ransom;
pub mod rmm;
pub mod score;
pub mod sigma;
pub mod trust;

// Public API: the analyzers wired into the CLI live run (and reusable elsewhere).
pub use account::AccountHeuristic;
pub use clickfix::ClickFixHeuristic;
pub use cred_dump::CredDumpHeuristic;
pub use defense::DefenseHeuristic;
pub use eventlog::EventLogHeuristic;
pub use lateral::LateralHeuristic;
pub use logon_bruteforce::LogonBruteforceHeuristic;
pub use netconn::NetConnHeuristic;
pub use parentchild::ParentChildHeuristic;
pub use persist::PersistHeuristic;
pub use ransom::RansomHeuristic;
pub use rmm::RmmHeuristic;
pub use sigma::SigmaAnalyzer;

/// Every event-log channel a built-in heuristic reads (each analyzer's own `CHANNELS`
/// list), first spelling kept, duplicates dropped case-insensitively. The live EVTX
/// collector reads all of them even when no Sigma rules are loaded.
pub fn heuristic_channels() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for ch in eventlog::CHANNELS
        .iter()
        .chain(lateral::CHANNELS)
        .chain(ransom::CHANNELS)
    {
        if !out.iter().any(|c| c.eq_ignore_ascii_case(ch)) {
            out.push(ch);
        }
    }
    out
}

/// Stamp `Finding.analyzer` on every finding an analyzer returns (typed provenance;
/// other analyzers and the report match on it instead of parsing `reason`).
pub(crate) fn stamped(
    mut findings: Vec<cairn_core::Finding>,
    analyzer: &str,
) -> Vec<cairn_core::Finding> {
    for f in &mut findings {
        f.analyzer = analyzer.to_string();
    }
    findings
}
