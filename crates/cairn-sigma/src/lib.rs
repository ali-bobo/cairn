//! cairn-sigma: Sigma rule loading + matching over EventRecords. SRS §9.
//!
//! Key design decision (Hayabusa model): DO NOT resolve `logsource` at runtime.
//! Ship a precompiled mapping (LogsourceMap) that turns category/product/service
//! into concrete {Channel, EventID, field aliases}. Only run rules whose
//! Channel/EventID actually appear in the data.
//!
//! The concrete matcher is hidden behind `SigmaMatcher` so the chosen engine
//! (sigma-engine | sigmars | tau-engine) is swappable. See benchmark plan.

use cairn_core::{finding::Finding, record::EventRecord, Result};

/// Swappable engine seam. Implement once an engine is chosen in T6.
pub trait SigmaMatcher: Send + Sync {
    /// Load + compile rules from a directory of (possibly XOR-encoded) .yml.
    fn load(&mut self, rules_dir: &std::path::Path) -> Result<usize>;
    /// Match a single event; return zero or more Findings (author surfaced per DRL).
    fn match_event(&self, ev: &EventRecord) -> Result<Vec<Finding>>;
    /// Channels referenced by loaded rules (for load-optimization: skip absent channels).
    fn referenced_channels(&self) -> &[String];
}

/// Precompiled logsource de-abstraction. Built offline (T5) from SigmaHQ + config maps.
#[derive(Debug, Default, Clone)]
pub struct LogsourceMap {
    /// (category|service) -> list of (channel, event_id, field-rename table)
    pub entries: Vec<LogsourceEntry>,
}

#[derive(Debug, Clone)]
pub struct LogsourceEntry {
    pub category: Option<String>,
    pub service: Option<String>,
    pub product: Option<String>,
    pub channel: String,
    pub event_id: u32,
    /// sigma-field -> evtx EventData path (e.g. "Image" -> "NewProcessName" for 4688)
    pub field_aliases: Vec<(String, String)>,
}

/// Config files mirrored from Hayabusa concepts (SRS §9): load from rules/config/.
#[derive(Debug, Default)]
pub struct EngineConfig {
    pub channel_abbreviations: Vec<(String, String)>,
    pub eventkey_alias: Vec<(String, String)>,
    pub noisy_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
    pub level_tuning: Vec<(String, String)>,
}

// TODO(claude-code) T6: implement a concrete `EngineX` : SigmaMatcher wrapping the
// chosen crate; wire field aliasing via LogsourceMap; surface rule author into
// Finding.rule_author (DRL 1.1 hard requirement).
