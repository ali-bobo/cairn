//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
#![forbid(unsafe_code)]

pub mod account;
pub mod byovd;
pub mod live_exec;
pub mod logon_bruteforce;
pub mod netconn;
pub mod parentchild;
pub mod persist;
pub mod score;
pub mod sigma;
pub mod temporal;
pub mod timestomp;
pub mod trust;

// Public API: the analyzers wired into the CLI live run (and reusable elsewhere).
pub use account::AccountHeuristic;
pub use byovd::ByovdHeuristic;
pub use live_exec::LiveExecHeuristic;
pub use logon_bruteforce::LogonBruteforceHeuristic;
pub use netconn::NetConnHeuristic;
pub use parentchild::ParentChildHeuristic;
pub use persist::PersistHeuristic;
pub use sigma::SigmaAnalyzer;
pub use temporal::TemporalWindowCorrelator;
pub use timestomp::TimestompHeuristic;
