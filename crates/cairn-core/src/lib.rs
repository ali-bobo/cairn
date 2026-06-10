//! cairn-core: shared contracts for the Cairn live-forensics triage engine.
//!
//! This crate defines the *typed bus* every other crate speaks:
//!   - [`Record`]   : normalized output of a Collector (raw artifact -> typed row)
//!   - [`Finding`]  : normalized output of an Analyzer (Sigma or heuristic)
//!   - [`Manifest`] : integrity + chain-of-custody record of a run
//!   - traits       : Collector, Analyzer, OutputSink (see `traits`)
//!
//! Design rule: Collectors NEVER analyze; Analyzers NEVER touch the host.
//! See ../../docs (SRS §3-§5) for the authoritative spec.
//!
//! NOTE: not yet compiled in the authoring environment. Run `cargo check` first.

#![forbid(unsafe_code)] // raw-volume/WinAPI unsafe lives only in collector crates, behind review.

pub mod record;
pub mod finding;
pub mod manifest;
pub mod traits;
pub mod config;

pub use finding::{Entity, Finding, FindingSource, Severity};
pub use manifest::{Manifest, SourceEntry};
pub use record::Record;
pub use traits::{Analyzer, Collector, CollectCtx, OutputSink};
pub use config::{Config, OutputKind, Profile, Target};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CairnError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("collector `{collector}` failed: {reason}")]
    Collector { collector: String, reason: String },
    #[error("analyzer `{analyzer}` failed: {reason}")]
    Analyzer { analyzer: String, reason: String },
    #[error("insufficient privilege for `{what}` (need: {need})")]
    Privilege { what: String, need: String },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CairnError>;

/// Schema version constants for serialized outputs.
///
/// `FINDING` and `MANIFEST` are embedded in the `schema` field of every persisted
/// Finding/Manifest. `RECORD` is the version tag for the JSONL Record interchange
/// format (SRS §7 FR1: JSONL is an accepted *input*, and Records may be dumped for
/// debug/replay). A `Record` is otherwise an INTERNAL bus type — it flows in-process
/// from Collector to Analyzer and does not itself carry a `schema` field. Use this
/// constant when wrapping Records for on-disk interchange; see record.rs.
pub mod schema {
    pub const FINDING: &str = "cairn.finding/1";
    pub const MANIFEST: &str = "cairn.manifest/1";
    pub const RECORD: &str = "cairn.record/1";
}
