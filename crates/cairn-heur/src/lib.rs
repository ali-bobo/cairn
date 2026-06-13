//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
#![forbid(unsafe_code)]

pub mod netconn;
pub mod parentchild;
pub mod score;

// Re-exports enabled as the analyzers land (Task 4 / Task 6).
// pub use netconn::NetConnHeuristic;
// pub use parentchild::ParentChildHeuristic;
