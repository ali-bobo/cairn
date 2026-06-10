//! Core traits: the seams Claude Code implements per stage. SRS §3-§4.
use crate::{config::Config, finding::Finding, manifest::SourceEntry, record::Record, Result};

/// Context handed to every collector: privilege state, target, output policy.
#[derive(Debug, Clone)]
pub struct CollectCtx<'a> {
    pub config: &'a Config,
    pub admin: bool,
    pub se_backup: bool,
    pub se_debug: bool,
}

impl<'a> CollectCtx<'a> {
    /// Helper for graceful-degrade (FR13): skip+record instead of hard-fail.
    pub fn require_admin(&self, what: &str) -> Result<()> {
        if self.admin {
            Ok(())
        } else {
            Err(crate::CairnError::Privilege {
                what: what.into(),
                need: "Administrator".into(),
            })
        }
    }
}

/// A Collector turns one artifact source into normalized Records.
/// MUST NOT modify the host. MUST record provenance via `sources()`.
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    /// Returns records; on missing privilege, return Err(Privilege) so the
    /// orchestrator can skip-and-log rather than abort the whole run.
    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>>;
    /// Provenance for the manifest (path/method/sha256). Empty if N/A.
    fn sources(&self) -> Vec<SourceEntry> {
        vec![]
    }
}

/// An Analyzer turns Records into Findings. MUST NOT touch the host.
/// Heuristic analyzers MUST populate `Finding.reason` (explainability).
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>>;
}

/// Where results go. Default writes OFF-TARGET; `--dry-run` writes nothing (FR16).
pub trait OutputSink: Send {
    /// Detection timeline (SRS §5.2): one row per rule hit, projected from Findings.
    /// Carries RuleTitle/RuleAuthor/MITRE/Severity — fields that live on Finding, not
    /// Record. There is no separate raw-event timeline (decided: detection-only).
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()>;
    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()>;
    fn write_manifest(&mut self, manifest: &crate::manifest::Manifest) -> Result<()>;
    /// Finalize (e.g. zip + hash). Returns output file list with hashes.
    fn finalize(&mut self) -> Result<Vec<crate::manifest::OutputEntry>>;
}
