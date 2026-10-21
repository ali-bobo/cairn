//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
#![forbid(unsafe_code)]

pub mod account;
pub mod asep;
pub mod clickfix;
pub mod coverage;
pub mod defense;
pub mod eventlog;
pub mod logon_bruteforce;
pub mod netconn;
pub mod parentchild;
pub mod persist;
pub mod rmm;
pub mod score;
pub mod sigma;
pub mod trust;

// Public API: the analyzers wired into the CLI live run (and reusable elsewhere).
pub use account::AccountHeuristic;
pub use clickfix::ClickFixHeuristic;
pub use defense::DefenseHeuristic;
pub use eventlog::EventLogHeuristic;
pub use logon_bruteforce::LogonBruteforceHeuristic;
pub use netconn::NetConnHeuristic;
pub use parentchild::ParentChildHeuristic;
pub use persist::PersistHeuristic;
pub use rmm::RmmHeuristic;
pub use sigma::SigmaAnalyzer;

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
