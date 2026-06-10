//! Normalized records emitted by Collectors. SRS §4 (collector outputs).
//!
//! Contract (SRS §5): `Record` is the INTERNAL typed bus between Collectors and
//! Analyzers. Unlike [`crate::finding::Finding`] and [`crate::manifest::Manifest`],
//! a Record does NOT carry a `schema` field — it is not an independently persisted
//! artifact. The persisted outputs are the detection timeline (Findings, §5.2),
//! findings.jsonl (Findings), and the manifest. When Records ARE serialized for the
//! JSONL interchange/replay path (§7 FR1), they are versioned externally via
//! [`crate::schema::RECORD`], not by an inline field.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One normalized observation from a single artifact source.
/// `kind` tags the variant; only the matching payload is present.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Event(EventRecord),
    Process(ProcessRecord),
    NetConn(NetConnRecord),
    Persistence(PersistenceRecord),
    FileMeta(FileMetaRecord),
    UsnEvent(UsnEventRecord),
    RegValue(RegValueRecord),
    Execution(ExecutionRecord),
}

/// EVTX event normalized to JSON-ish fields (Stage 1 primary input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub ts: DateTime<Utc>,
    pub channel: String, // e.g. "Security"
    pub event_id: u32,   // e.g. 4688
    pub provider: String,
    pub computer: String,
    pub record_id: u64,
    /// Flattened EventData / System fields. Sigma matches against this map.
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmdline: String,
    pub signed: Option<bool>,
    pub integrity: Option<String>,
    pub user: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnRecord {
    pub proto: String, // tcp|udp
    pub laddr: String,
    pub lport: u16,
    pub raddr: Option<String>,
    pub rport: Option<u16>,
    pub state: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceRecord {
    pub mechanism: String, // run_key|service|scheduled_task|wmi_subscription|ifeo|startup|winlogon
    pub location: String,  // registry key / file path / wmi binding
    pub value: Option<String>,
    pub command: Option<String>,
    pub binary_path: Option<String>,
    pub binary_sha256: Option<String>,
    pub signed: Option<bool>,
    pub last_write: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetaRecord {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    // MACB; SI vs FN exposed to allow timestomp delta detection.
    pub si_btime: Option<DateTime<Utc>>,
    pub si_mtime: Option<DateTime<Utc>>,
    pub fn_btime: Option<DateTime<Utc>>,
    pub zone_identifier: Option<String>, // mark-of-the-web
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnEventRecord {
    pub ts: DateTime<Utc>,
    pub path: String,
    pub reason: String, // create|delete|rename|...
    pub mft_ref: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegValueRecord {
    pub hive: String,
    pub key: String,
    pub value: String,
    pub data: String,
    pub last_write: Option<DateTime<Utc>>,
}

/// Evidence-of-execution from Amcache/Shimcache/Prefetch/UserAssist/BAM/SRUM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub source: String, // amcache|shimcache|prefetch|userassist|bam|srum
    pub path: String,
    pub first_run: Option<DateTime<Utc>>,
    pub last_run: Option<DateTime<Utc>>,
    pub run_count: Option<u32>,
    pub sha1: Option<String>,
    pub user_sid: Option<String>,
    /// shimcache presence != execution; this flags engine-provided exec evidence.
    pub execution_confirmed: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn sample_event() -> EventRecord {
        let mut data = serde_json::Map::new();
        data.insert(
            "NewProcessName".into(),
            json!(r"C:\Windows\System32\cmd.exe"),
        );
        data.insert("ProcessId".into(), json!("0x1a2b"));
        EventRecord {
            ts: Utc.with_ymd_and_hms(2026, 6, 10, 12, 0, 0).unwrap(),
            channel: "Security".into(),
            event_id: 4688,
            provider: "Microsoft-Windows-Security-Auditing".into(),
            computer: "WS01".into(),
            record_id: 987654,
            data,
        }
    }

    /// A Record round-trips losslessly and is tagged by `kind` (internal bus type).
    #[test]
    fn event_record_round_trips_with_kind_tag() {
        let rec = Record::Event(sample_event());
        let json = serde_json::to_string(&rec).unwrap();
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        // Adjacent/internal tagging via #[serde(tag = "kind", rename_all = "snake_case")].
        assert!(json.contains("\"kind\":\"event\""));
    }

    /// Contract (SRS §5 / A2): Record is an INTERNAL bus type and carries NO inline
    /// `schema` field — unlike Finding and Manifest. This guards the decision.
    #[test]
    fn record_has_no_inline_schema_field() {
        let json = serde_json::to_string(&Record::Event(sample_event())).unwrap();
        assert!(
            !json.contains("\"schema\""),
            "Record must not carry an inline schema field: {json}"
        );
    }

    /// Each variant keeps its own snake_case kind tag.
    #[test]
    fn execution_record_kind_tag_is_snake_case() {
        let rec = Record::Execution(ExecutionRecord {
            source: "amcache".into(),
            path: r"C:\tmp\evil.exe".into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(false),
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"kind\":\"execution\""));
    }
}
