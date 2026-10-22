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
    /// The persistence entry behind a persistence finding: its typed mechanism plus
    /// where it lives. Lets reports pick mechanism-specific wording from a typed field
    /// instead of parsing the title. Additive; absent on non-persistence findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence: Option<EntityPersistence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityPersistence {
    pub mechanism: crate::record::Mechanism,
    /// Registry key / file path / WMI binding (PersistenceRecord.location).
    pub location: String,
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

/// One corroborating source for a Finding (spec §7): which artifact saw the binary,
/// at what path, when. `path` is honest — prefetch carries only a file name and says so
/// in `detail`. Additive to the finding schema (old JSON deserializes to an empty vec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Source artifact: "run_key" | "service" | "prefetch" | "process"
    /// | "evtx:Security" | ...
    pub artifact: String,
    /// Full path as seen by that source (None when the source has no path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// That source's own timestamp (last_run / last_write / event time).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<DateTime<Utc>>,
    /// Human-readable one-liner, e.g. "prefetch: run_count=12 last_run=2026-06-27T23:31Z".
    pub detail: String,
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
    /// `Analyzer::name()` of the analyzer that produced this finding (e.g.
    /// "heur_persist", "sigma"). Typed provenance for cross-analyzer correlation and
    /// report wording; never parse `reason`/`title` for this. Additive: old JSON
    /// without the key deserializes to "".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub analyzer: String,
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
    /// Source EVTX EventID, when the finding came from an event (timeline column).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
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
    /// Corroborating sources (spec §7). Empty for findings with a single self-evident
    /// source (most Sigma hits). Old JSON without the field deserializes to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceItem>,
    /// In-memory only, never serialized (the JSON schema is unchanged): ids of earlier
    /// heuristic findings this one merged under the same-evidence rule (see
    /// `cairn_heur::dedup`). `orchestrator::run_analyzers` drops them once the analyzer
    /// that returned this finding is done. A Sigma finding is never dropped this way.
    #[serde(skip)]
    pub supersedes: Vec<Uuid>,
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
            analyzer: String::new(),
            rule_id: None,
            rule_author: None,
            mitre: vec![],
            host: String::new(),
            user: None,
            artifact: String::new(),
            event_id: None,
            entity: Entity::default(),
            evidence_ref: None,
            details: String::new(),
            details_client: None,
            reason: None,
            evidence: vec![],
            supersedes: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Sigma finding survives a JSON round-trip unchanged, and serializes with the
    /// `cairn.finding/1` schema tag (golden rule 5 / SRS §5.1).
    #[test]
    fn finding_round_trips_with_schema_and_author() {
        let mut f = Finding::new(
            Severity::High,
            "Suspicious PowerShell",
            FindingSource::Sigma,
        );
        f.rule_id = Some("abc-123".into());
        f.rule_author = Some("Florian Roth".into());
        f.mitre = vec!["T1059.001".into()];
        f.host = "WS01".into();
        f.artifact = "evtx:Security".into();
        f.entity.process = Some(EntityProcess {
            pid: 4242,
            ppid: 1000,
            image: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: "cmd /c whoami".into(),
            signed: Some(true),
            integrity: Some("Medium".into()),
        });
        f.details = "encoded command observed".into();

        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();

        // No PartialEq on Finding (chrono/uuid fields); compare canonical JSON instead.
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        assert_eq!(f.schema, crate::schema::FINDING);
        assert_eq!(back.schema, "cairn.finding/1");
        // DRL 1.1 attribution must round-trip.
        assert_eq!(back.rule_author.as_deref(), Some("Florian Roth"));
    }

    /// Severity and FindingSource serialize as lowercase strings (SRS §5.1 enum values).
    #[test]
    fn severity_and_source_serialize_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&FindingSource::Sigma).unwrap(),
            "\"sigma\""
        );
        assert_eq!(
            serde_json::to_string(&FindingSource::Heuristic).unwrap(),
            "\"heuristic\""
        );
    }

    /// Optional fields with `skip_serializing_if` are omitted when None (compact output),
    /// and a heuristic finding carries its explainability `reason` (golden rule 6).
    #[test]
    fn optional_fields_omitted_when_none_and_reason_round_trips() {
        let mut f = Finding::new(Severity::Low, "rare egress", FindingSource::Heuristic);
        f.reason = Some("connection to raw public IP with no DNS, unsigned parent".into());

        let json = serde_json::to_string(&f).unwrap();
        // rule_id/rule_author/user/details_client are None -> absent from output.
        assert!(!json.contains("rule_id"));
        assert!(!json.contains("rule_author"));
        assert!(!json.contains("details_client"));
        // reason is Some -> present and round-trips.
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.reason.as_deref(), f.reason.as_deref());
    }

    /// EntityFile JSON from older builds (which carried SI/FN timestamps and
    /// path_complete) still deserializes; the extra keys are ignored.
    #[test]
    fn entityfile_old_json_with_removed_fields_still_parses() {
        use super::EntityFile;
        let old = r#"{"path":"C:\\a.exe","sha256":null,"mtime":null,"si_btime":null,"fn_btime":null,"si_mtime":null,"fn_mtime":null,"path_complete":true}"#;
        let e: EntityFile = serde_json::from_str(old).unwrap();
        assert_eq!(e.path, "C:\\a.exe");
        let back: EntityFile = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back.path, e.path);
    }

    #[test]
    fn evidence_roundtrips_and_old_json_defaults_empty() {
        let mut f = Finding::new(Severity::High, "x", FindingSource::Heuristic);
        f.evidence.push(EvidenceItem {
            artifact: "prefetch".into(),
            path: Some("EVIL.EXE".into()),
            ts: None,
            detail: "prefetch: run_count=3".into(),
        });
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"evidence\""));
        let back: Finding = serde_json::from_str(&j).unwrap();
        assert_eq!(back.evidence.len(), 1);
        assert_eq!(back.evidence[0].artifact, "prefetch");

        // Old JSON (no evidence field) -> empty vec, and empty vec is omitted on write.
        let f2 = Finding::new(Severity::Low, "y", FindingSource::Heuristic);
        let j2 = serde_json::to_string(&f2).unwrap();
        assert!(!j2.contains("evidence"));
        let back2: Finding = serde_json::from_str(&j2).unwrap();
        assert!(back2.evidence.is_empty());
    }

    #[test]
    fn analyzer_and_persistence_entity_roundtrip_and_default_on_old_json() {
        let mut f = Finding::new(Severity::High, "x", FindingSource::Heuristic);
        f.analyzer = "heur_persist".into();
        f.entity.persistence = Some(EntityPersistence {
            mechanism: crate::record::Mechanism::Ifeo,
            location: "HKLM\\IFEO\\sethc.exe".into(),
        });
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains(r#""analyzer":"heur_persist""#), "{j}");
        assert!(j.contains(r#""mechanism":"ifeo""#), "{j}");
        let back: Finding = serde_json::from_str(&j).unwrap();
        assert_eq!(back.analyzer, "heur_persist");
        assert_eq!(
            back.entity.persistence.map(|p| p.mechanism),
            Some(crate::record::Mechanism::Ifeo)
        );

        // Old JSON: neither key present -> defaults, and empty values are not written.
        let f2 = Finding::new(Severity::Low, "y", FindingSource::Sigma);
        let j2 = serde_json::to_string(&f2).unwrap();
        assert!(!j2.contains("analyzer"));
        assert!(!j2.contains("persistence"));
        let back2: Finding = serde_json::from_str(&j2).unwrap();
        assert!(back2.analyzer.is_empty());
        assert!(back2.entity.persistence.is_none());
    }

    #[test]
    fn finding_schema_string_unchanged_by_evidence() {
        let f = Finding::new(Severity::Info, "z", FindingSource::Sigma);
        assert_eq!(f.schema, "cairn.finding/1");
    }
}
