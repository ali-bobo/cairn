//! Findings: normalized analyzer output. SRS §5.1.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    Sigma,
    Heuristic,
}

/// The implicated entity. Only relevant sub-objects are populated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<EntityProcess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<EntityFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netconn: Option<EntityNetConn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<EntityRegistry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityProcess {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmdline: String,
    pub signed: Option<bool>,
    pub integrity: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityFile {
    pub path: String,
    pub sha256: Option<String>,
    pub mtime: Option<DateTime<Utc>>,
    pub si_btime: Option<DateTime<Utc>>,
    pub fn_btime: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityNetConn {
    pub laddr: String,
    pub lport: u16,
    pub raddr: Option<String>,
    pub rport: Option<u16>,
    pub pid: Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRegistry {
    pub hive: String,
    pub key: String,
    pub value: String,
    pub data: String,
    pub last_write: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub schema: String, // crate::schema::FINDING
    pub id: Uuid,
    pub ts: DateTime<Utc>, // event/observation time
    pub detected_at: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub source: FindingSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// DRL 1.1 REQUIRES surfacing Sigma author. Must be Some when source==Sigma.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_author: Option<String>,
    pub mitre: Vec<String>,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub artifact: String, // e.g. "evtx:Security" | "process" | "hive:..."
    pub entity: Entity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>, // sha256 of raw blob in archive | record id
    pub details: String, // technical (en)
    /// plain zh-TW, no jargon, no overstatement. Required for >= Medium at S3 (FR18).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details_client: Option<String>,
    /// explainability: heuristics MUST state why (SRS §10). Never opaque scores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, title: impl Into<String>, source: FindingSource) -> Self {
        let now = Utc::now();
        Finding {
            schema: crate::schema::FINDING.to_string(),
            id: Uuid::new_v4(),
            ts: now,
            detected_at: now,
            severity,
            title: title.into(),
            source,
            rule_id: None,
            rule_author: None,
            mitre: vec![],
            host: String::new(),
            user: None,
            artifact: String::new(),
            entity: Entity::default(),
            evidence_ref: None,
            details: String::new(),
            details_client: None,
            reason: None,
        }
    }
}
