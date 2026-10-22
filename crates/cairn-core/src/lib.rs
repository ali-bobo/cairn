//! cairn-core: shared contracts for the Cairn live-forensics triage engine.
//!
//! This crate defines the *typed bus* every other crate speaks:
//!   - [`Record`]    : normalized output of a Collector (raw artifact -> typed row);
//!     persistence entries carry a typed [`Mechanism`]
//!   - [`Finding`]   : normalized output of an Analyzer (Sigma or heuristic), stamped
//!     with the producing analyzer's name (`Finding.analyzer`)
//!   - [`Observation`]: inventory that did not clear an analyzer's gate
//!   - [`Manifest`]  : integrity + chain-of-custody record of a run
//!   - traits        : Collector, Analyzer, OutputSink, FileVerifier (see `traits`)
//!   - [`collectors`] / [`analyzers`]: the canonical collector / analyzer names
//!   - [`orchestrator`]: runs collectors then dependency-ordered analyzers; a failing
//!     or panicking collector/analyzer is recorded in the manifest and skipped
//!   - [`selection`] : pure profile / `--only` collector selection
//!
//! Design rule: Collectors NEVER analyze; Analyzers NEVER touch the host.
//! Authoritative spec: cairn-SRS.md at the repo root (§3-§5).

#![forbid(unsafe_code)] // raw-volume/WinAPI unsafe lives only in collector crates, behind review.

pub mod analyzers;
pub mod collectors;
pub mod config;
pub mod finding;
pub mod manifest;
pub mod observation;
pub mod orchestrator;
pub mod paths;
pub mod record;
pub mod selection;
pub mod time;
pub mod traits;

pub use config::{Config, Governance, OutputKind, Profile, Target};
pub use finding::{Entity, EntityPersistence, Finding, FindingSource, Severity};
pub use manifest::{GovernanceReport, Manifest, SourceEntry};
pub use observation::Observation;
pub use record::{Mechanism, Record};
pub use selection::{select_modules, ModuleInfo, SelectionOutcome};
pub use time::filetime_to_utc;
pub use traits::{Analyzer, CollectCtx, Collector, OutputSink};

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
    pub const OBSERVATION: &str = "cairn.observation/1";
    pub const RECORD: &str = "cairn.record/1";
}
