//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
#![forbid(unsafe_code)]

pub mod netconn;
pub mod parentchild;
pub mod persist;
pub mod score;
pub mod timestomp;

// Public API: the analyzers wired into the CLI live run (and reusable elsewhere).
pub use netconn::NetConnHeuristic;
pub use parentchild::ParentChildHeuristic;
pub use persist::PersistHeuristic;
pub use timestomp::TimestompHeuristic;
