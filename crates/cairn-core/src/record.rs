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
    LogonSession(LogonSessionRecord),
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
    pub signer: Option<String>,
    pub binary_sha256: Option<String>,
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
    pub signer: Option<String>,
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
    pub fn_mtime: Option<DateTime<Utc>>,
    pub zone_identifier: Option<String>, // mark-of-the-web
    /// Path-resolution quality (path map, S2-O): Some(true) = walked clean to root
    /// (C:\); Some(false) = best-effort (orphan/truncated/cyclic — `path` is a partial
    /// REAL path fragment, never prefixed/polluted); None = resolution disabled or no
    /// path. The `path` string stays a clean filesystem path for any string consumer.
    pub path_complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub source: String, // amcache|amcache_driver|shimcache|prefetch|userassist|bam|srum
    pub path: String,
    pub first_run: Option<DateTime<Utc>>,
    pub last_run: Option<DateTime<Utc>>,
    pub run_count: Option<u32>,
    pub sha1: Option<String>,
    pub user_sid: Option<String>,
    /// shimcache presence != execution; this flags engine-provided exec evidence.
    pub execution_confirmed: Option<bool>,
}

/// A live logon session (LSA/WTS enumeration). "Who is using the host right now."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonSessionRecord {
    pub user: String,           // domain\username
    pub logon_type: String,     // Interactive|RemoteInteractive|Network|Service|...
    pub logon_time: Option<DateTime<Utc>>,
    pub source: Option<String>, // source host/IP for network/RDP sessions
    pub session_id: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn persistence_record_signer_roundtrips() {
        let mut r = PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKCU\\...\\Run".into(),
            value: Some("X".into()),
            command: Some("C:\\a.exe".into()),
            binary_path: Some("C:\\a.exe".into()),
            binary_sha256: None,
            signed: Some(true),
            signer: Some("Docker Inc".into()),
            last_write: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""signer":"Docker Inc""#));
        let back: PersistenceRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.signer.as_deref(), Some("Docker Inc"));
        r.signer = None;
        let j2 = serde_json::to_string(&r).unwrap();
        let back2: PersistenceRecord = serde_json::from_str(&j2).unwrap();
        assert_eq!(back2.signer, None);
    }

    #[test]
    fn process_record_signer_roundtrips() {
        let r = ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "C:\\a.exe".into(),
            cmdline: "C:\\a.exe".into(),
            signed: Some(true),
            signer: Some("Google LLC".into()),
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: ProcessRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.signer.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn process_record_binary_sha256_roundtrips() {
        let r = ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "C:\\a.exe".into(),
            cmdline: "C:\\a.exe".into(),
            signed: Some(true),
            signer: Some("V".into()),
            binary_sha256: Some("ba7816bf".into()),
            integrity: None,
            user: None,
            start_time: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: ProcessRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.binary_sha256.as_deref(), Some("ba7816bf"));
    }

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

    #[test]
    fn file_meta_fn_mtime_roundtrips_and_old_json_is_none() {
        let r = FileMetaRecord {
            path: r"C:\Windows\notepad.exe".into(),
            size: 0,
            sha256: None,
            si_btime: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            si_mtime: Some(Utc.with_ymd_and_hms(2026, 2, 2, 0, 0, 0).unwrap()),
            fn_btime: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            fn_mtime: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            zone_identifier: None,
            path_complete: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("fn_mtime"));
        let back: FileMetaRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.fn_mtime, r.fn_mtime);

        // Older JSONL (FR1 replay) lacking fn_mtime must deserialize to None.
        let old = r#"{"path":"x","size":0,"sha256":null,"si_btime":null,"si_mtime":null,"fn_btime":null,"zone_identifier":null}"#;
        let parsed: FileMetaRecord = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.fn_mtime, None);
    }

    #[test]
    fn file_meta_path_complete_roundtrips_and_old_json_none() {
        let r = FileMetaRecord {
            path: r"C:\Users\a\evil.exe".into(),
            size: 0,
            sha256: None,
            si_btime: None,
            si_mtime: None,
            fn_btime: None,
            fn_mtime: None,
            zone_identifier: None,
            path_complete: Some(true),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("path_complete"));
        let back: FileMetaRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.path_complete, Some(true));

        // Older JSONL (FR1 replay) lacking path_complete must deserialize to None.
        let old = r#"{"path":"x","size":0,"sha256":null,"si_btime":null,"si_mtime":null,"fn_btime":null,"fn_mtime":null,"zone_identifier":null}"#;
        let parsed: FileMetaRecord = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.path_complete, None);
    }

    #[test]
    fn logon_session_record_kind_tag() {
        let rec = Record::LogonSession(LogonSessionRecord {
            user: r"DOMAIN\alice".into(),
            logon_type: "RemoteInteractive".into(),
            logon_time: None,
            source: Some("10.0.0.5".into()),
            session_id: Some(2),
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"kind\":\"logon_session\""));
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }
}
