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

/// Every persistence mechanism cairn collects. Serializes as the snake_case string
/// the collectors have always written (`"run_key"`, `"ifeo"`, ...), so JSON output is
/// unchanged; in code it is a closed set analyzers and reports can `match` on instead of
/// comparing free strings. An unknown string read back from old/foreign JSON becomes
/// [`Mechanism::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    RunKey,
    Service,
    ScheduledTask,
    WmiSubscription,
    Ifeo,
    Startup,
    Winlogon,
    ExplorerPolicyRun,
    BootExecute,
    LsaAuthPackage,
    LsaSecurityPackage,
    LsaNotificationPackage,
    TimeProvider,
    WinlogonNotify,
    WinlogonMpnotify,
    PrintMonitor,
    ActiveSetup,
    Screensaver,
    NetshHelper,
    AppcertDlls,
    AppinitDlls,
    SilentExitMonitor,
    ComHijack,
    CmdAutorun,
    OfficeTest,
    LogonScript,
    PsProfile,
    /// A mechanism string this build does not know (deserialization fallback only).
    #[serde(other)]
    Other,
}

impl Mechanism {
    /// Every known mechanism (excludes [`Mechanism::Other`]), in declaration order.
    pub const ALL: &'static [Mechanism] = &[
        Mechanism::RunKey,
        Mechanism::Service,
        Mechanism::ScheduledTask,
        Mechanism::WmiSubscription,
        Mechanism::Ifeo,
        Mechanism::Startup,
        Mechanism::Winlogon,
        Mechanism::ExplorerPolicyRun,
        Mechanism::BootExecute,
        Mechanism::LsaAuthPackage,
        Mechanism::LsaSecurityPackage,
        Mechanism::LsaNotificationPackage,
        Mechanism::TimeProvider,
        Mechanism::WinlogonNotify,
        Mechanism::WinlogonMpnotify,
        Mechanism::PrintMonitor,
        Mechanism::ActiveSetup,
        Mechanism::Screensaver,
        Mechanism::NetshHelper,
        Mechanism::AppcertDlls,
        Mechanism::AppinitDlls,
        Mechanism::SilentExitMonitor,
        Mechanism::ComHijack,
        Mechanism::CmdAutorun,
        Mechanism::OfficeTest,
        Mechanism::LogonScript,
        Mechanism::PsProfile,
    ];

    /// The serialized snake_case name (`"run_key"`, ...). Same string serde writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::RunKey => "run_key",
            Mechanism::Service => "service",
            Mechanism::ScheduledTask => "scheduled_task",
            Mechanism::WmiSubscription => "wmi_subscription",
            Mechanism::Ifeo => "ifeo",
            Mechanism::Startup => "startup",
            Mechanism::Winlogon => "winlogon",
            Mechanism::ExplorerPolicyRun => "explorer_policy_run",
            Mechanism::BootExecute => "boot_execute",
            Mechanism::LsaAuthPackage => "lsa_auth_package",
            Mechanism::LsaSecurityPackage => "lsa_security_package",
            Mechanism::LsaNotificationPackage => "lsa_notification_package",
            Mechanism::TimeProvider => "time_provider",
            Mechanism::WinlogonNotify => "winlogon_notify",
            Mechanism::WinlogonMpnotify => "winlogon_mpnotify",
            Mechanism::PrintMonitor => "print_monitor",
            Mechanism::ActiveSetup => "active_setup",
            Mechanism::Screensaver => "screensaver",
            Mechanism::NetshHelper => "netsh_helper",
            Mechanism::AppcertDlls => "appcert_dlls",
            Mechanism::AppinitDlls => "appinit_dlls",
            Mechanism::SilentExitMonitor => "silent_exit_monitor",
            Mechanism::ComHijack => "com_hijack",
            Mechanism::CmdAutorun => "cmd_autorun",
            Mechanism::OfficeTest => "office_test",
            Mechanism::LogonScript => "logon_script",
            Mechanism::PsProfile => "ps_profile",
            Mechanism::Other => "other",
        }
    }

    /// File-backed mechanisms: the persistence entry is a file (Startup folder item,
    /// PowerShell profile), not a registry value.
    pub fn is_file_backed(self) -> bool {
        matches!(self, Mechanism::Startup | Mechanism::PsProfile)
    }
}

impl std::fmt::Display for Mechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceRecord {
    pub mechanism: Mechanism,
    pub location: String, // registry key / file path / wmi binding
    pub value: Option<String>,
    pub command: Option<String>,
    pub binary_path: Option<String>,
    pub binary_sha256: Option<String>,
    pub signed: Option<bool>,
    pub signer: Option<String>,
    pub last_write: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegValueRecord {
    pub hive: String,
    pub key: String,
    pub value: String,
    pub data: String,
    pub last_write: Option<DateTime<Utc>>,
    /// Position in the key's most-recently-used order (RunMRU / TypedPaths), 0 = most
    /// recent. The key's LastWrite time dates only the rank-0 entry. None = unknown /
    /// not an MRU list. Additive field: absent in older JSONL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mru_rank: Option<u32>,
}

/// Evidence-of-execution (currently Prefetch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub source: String, // prefetch
    pub path: String,
    pub first_run: Option<DateTime<Utc>>,
    pub last_run: Option<DateTime<Utc>>,
    pub run_count: Option<u32>,
    pub sha1: Option<String>,
    pub user_sid: Option<String>,
    /// Whether the source proves execution (not just presence).
    pub execution_confirmed: Option<bool>,
}

/// A live logon session (LSA/WTS enumeration). "Who is using the host right now."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonSessionRecord {
    pub user: String,       // domain\username
    pub logon_type: String, // Interactive|RemoteInteractive|Network|Service|...
    pub logon_time: Option<DateTime<Utc>>,
    pub source: Option<String>, // source host/IP for network/RDP sessions
    pub session_id: Option<u32>,
    /// Whether the collector observed this session as currently active (HTML
    /// report filtering, additive schema field). `#[serde(default)]` keeps old
    /// JSONL (pre-field replay) deserializable: missing key -> `false`, i.e.
    /// "unknown" is conservatively treated as "not active" rather than assumed true.
    #[serde(default)]
    pub state_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn persistence_record_signer_roundtrips() {
        let mut r = PersistenceRecord {
            mechanism: Mechanism::RunKey,
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
            source: "prefetch".into(),
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
    fn mechanism_serializes_as_legacy_snake_case_strings() {
        for m in Mechanism::ALL {
            let j = serde_json::to_string(m).unwrap();
            assert_eq!(j, format!("\"{}\"", m.as_str()), "{m:?}");
            let back: Mechanism = serde_json::from_str(&j).unwrap();
            assert_eq!(back, *m);
        }
        assert_eq!(
            serde_json::to_string(&Mechanism::WinlogonMpnotify).unwrap(),
            "\"winlogon_mpnotify\""
        );
        let unknown: Mechanism = serde_json::from_str("\"brand_new_thing\"").unwrap();
        assert_eq!(unknown, Mechanism::Other);
    }

    #[test]
    fn logon_session_record_kind_tag() {
        let rec = Record::LogonSession(LogonSessionRecord {
            user: r"DOMAIN\alice".into(),
            logon_type: "RemoteInteractive".into(),
            logon_time: None,
            source: Some("10.0.0.5".into()),
            session_id: Some(2),
            state_active: true,
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"kind\":\"logon_session\""));
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn logon_session_state_active_defaults_false_on_old_json_and_roundtrips() {
        // Older JSONL (pre-state_active field) must deserialize with state_active = false.
        let old = r#"{"kind":"logon_session","user":"DOMAIN\\alice","logon_type":"Interactive","logon_time":null,"source":null,"session_id":1}"#;
        let parsed: Record = serde_json::from_str(old).unwrap();
        match parsed {
            Record::LogonSession(rec) => assert!(!rec.state_active),
            other => panic!("expected LogonSession, got {other:?}"),
        }

        // New record with state_active: true round-trips through serialize/deserialize.
        let rec = Record::LogonSession(LogonSessionRecord {
            user: r"DOMAIN\bob".into(),
            logon_type: "Interactive".into(),
            logon_time: None,
            source: None,
            session_id: Some(3),
            state_active: true,
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains(r#""state_active":true"#));
        let back: Record = serde_json::from_str(&json).unwrap();
        match back {
            Record::LogonSession(back_rec) => assert!(back_rec.state_active),
            other => panic!("expected LogonSession, got {other:?}"),
        }
    }
}
