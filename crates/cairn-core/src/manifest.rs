//! Manifest: integrity + chain-of-custody. SRS §5.3, §12.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String, // crate::schema::MANIFEST
    pub tool: ToolInfo,
    pub run: RunInfo,
    pub host: HostInfo,
    pub privileges: Privileges,
    pub sources: Vec<SourceEntry>,
    pub outputs: Vec<OutputEntry>,
    pub counts: Counts,
    pub integrity_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo { pub name: String, pub version: String, pub build_sha: String, pub sigma_ruleset_ver: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub started_utc: DateTime<Utc>,
    pub finished_utc: Option<DateTime<Utc>>,
    pub cmdline: String, pub operator: String, pub case_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo { pub hostname: String, pub os_build: String, pub timezone: String, pub wall_clock_utc_skew: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Privileges { pub admin: bool, pub se_backup: bool, pub se_debug: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntry {
    pub artifact: String,
    pub path: String,
    pub method: String,   // api|raw_ntfs|vss
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputEntry { pub file: String, pub sha256: String }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub records: u64,
    pub findings_by_sev: std::collections::BTreeMap<String, u64>,
}
