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
    /// Resource-governance report (NFR9/NFR10). Additive; defaults on old JSON.
    #[serde(default)]
    pub governance: GovernanceReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub build_sha: String,
    pub sigma_ruleset_ver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub started_utc: DateTime<Utc>,
    pub finished_utc: Option<DateTime<Utc>>,
    pub cmdline: String,
    pub operator: String,
    pub case_id: String,
    /// The active run profile (minimal|standard) — transparency (FR6).
    /// Additive (S2-L); `#[serde(default)]` keeps pre-S2-L manifests parseable.
    #[serde(default)]
    pub profile: String,
    /// The collector modules actually selected for this run (S2-L). Empty is honest:
    /// e.g. `--only nonexistent` ran no collectors. Additive; defaults on old JSON.
    #[serde(default)]
    pub selected_modules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_build: String,
    pub timezone: String,
    /// Host clock vs true UTC. Without a reference this is [`SKEW_NOT_MEASURED`]: a
    /// user-space tool with no network time source cannot measure it. With an
    /// operator-supplied reference time it is `"+Ns"` / `"-Ns"` (host ahead / behind).
    pub wall_clock_utc_skew: String,
    /// Host UTC offset in seconds at run start (e.g. 28800 for UTC+08:00). Additive;
    /// absent on old manifests and on offline runs (the analysed host is not this one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset_seconds: Option<i32>,
    /// The operator-supplied true UTC time at run start (`--reference-time`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_time_utc: Option<DateTime<Utc>>,
    /// `run.started_utc - reference_time_utc` in whole seconds: positive means the
    /// host clock is ahead. Present only when `reference_time_utc` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skew_seconds: Option<i64>,
}

/// `wall_clock_utc_skew` when no reference time was supplied.
pub const SKEW_NOT_MEASURED: &str = "not measured (no network time source)";

/// Host-clock skew in whole seconds against an operator reference: positive means the
/// host clock is ahead of the reference.
pub fn skew_seconds(host_utc: DateTime<Utc>, reference_utc: DateTime<Utc>) -> i64 {
    (host_utc - reference_utc).num_seconds()
}

/// The `wall_clock_utc_skew` string for a measured skew, e.g. `"+12s"` / `"-3s"`.
pub fn format_skew(seconds: i64) -> String {
    format!("{seconds:+}s")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Privileges {
    pub admin: bool,
    pub se_backup: bool,
    pub se_debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntry {
    /// Canonical `Collector::name()` of the collector that produced this entry (see
    /// [`crate::collectors`]), stamped by the orchestrator; or `analyzer:<name>` for an
    /// analyzer failure entry. Lets reports tie a source to a collector without guessing
    /// from `artifact`. Additive; old manifests default to "".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub collector: String,
    pub artifact: String,
    pub path: String,
    pub method: String, // e.g. api|fs|file_api|com|toolhelp
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputEntry {
    /// Path relative to the output root (the manifest's directory, or the zip root),
    /// `/`-separated, e.g. `timeline.csv` or `evidence/evtx/Security.evtx`.
    pub file: String,
    pub sha256: String,
    /// Byte length of the file. Additive; old manifests default to 0 (unknown).
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub records: u64,
    pub findings_by_sev: std::collections::BTreeMap<String, u64>,
    /// Inventory items written to observations.jsonl (spec §6). Additive.
    #[serde(default)]
    pub observations: u64,
}

/// Resource-governance report (NFR9): how the run was throttled.
/// Additive; `#[serde(default)]` on the `Manifest` field keeps pre-governance
/// manifests parseable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceReport {
    /// True if the process priority was successfully lowered (live + not --full-speed).
    #[serde(default)]
    pub low_priority_applied: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_manifest() -> Manifest {
        let mut by_sev = std::collections::BTreeMap::new();
        by_sev.insert("high".to_string(), 2u64);
        by_sev.insert("critical".to_string(), 1u64);
        Manifest {
            schema: crate::schema::MANIFEST.to_string(),
            tool: ToolInfo {
                name: "cairn".into(),
                version: "0.1.0".into(),
                build_sha: "a0ed50a".into(),
                sigma_ruleset_ver: "deadbeef+0123abcd".into(),
            },
            run: RunInfo {
                started_utc: Utc.with_ymd_and_hms(2026, 6, 10, 12, 0, 0).unwrap(),
                finished_utc: Some(Utc.with_ymd_and_hms(2026, 6, 10, 12, 5, 0).unwrap()),
                cmdline: "cairn evtx Security.evtx --rules ./rules".into(),
                operator: "analyst".into(),
                case_id: "IR-2026-001".into(),
                profile: "standard".into(),
                selected_modules: vec!["evtx".into()],
            },
            host: HostInfo {
                hostname: "WS01".into(),
                os_build: "Windows 11 26200".into(),
                timezone: "Asia/Taipei".into(),
                wall_clock_utc_skew: "+0s".into(),
                utc_offset_seconds: Some(28800),
                reference_time_utc: None,
                skew_seconds: None,
            },
            privileges: Privileges {
                admin: false,
                se_backup: false,
                se_debug: false,
            },
            sources: vec![SourceEntry {
                collector: String::new(),
                artifact: "evtx:Security".into(),
                path: r"C:\evidence\Security.evtx".into(),
                method: "api".into(),
                size: 1048576,
                sha256: "0".repeat(64),
                errors: vec![],
            }],
            outputs: vec![OutputEntry {
                file: "timeline.csv".into(),
                sha256: "f".repeat(64),
                size: 42,
            }],
            counts: Counts {
                records: 5000,
                findings_by_sev: by_sev,
                observations: 0,
            },
            integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
            governance: GovernanceReport::default(),
        }
    }

    /// Manifest round-trips losslessly and carries the `cairn.manifest/1` schema tag.
    #[test]
    fn manifest_round_trips_with_schema() {
        let m = sample_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        assert_eq!(back.schema, "cairn.manifest/1");
        assert_eq!(back.tool.build_sha, "a0ed50a");
        assert_eq!(back.counts.findings_by_sev.get("critical"), Some(&1));
    }

    /// RunInfo round-trips the new profile + selected_modules fields through serde.
    #[test]
    fn run_info_round_trips_profile_and_modules() {
        let ri = RunInfo {
            started_utc: chrono::Utc::now(),
            finished_utc: None,
            cmdline: "cairn run --profile minimal --only persist".into(),
            operator: String::new(),
            case_id: String::new(),
            profile: "minimal".into(),
            selected_modules: vec!["persist".into()],
        };
        let json = serde_json::to_string(&ri).unwrap();
        let back: RunInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.profile, "minimal");
        assert_eq!(back.selected_modules, vec!["persist".to_string()]);
    }

    /// `SourceEntry.errors` defaults to empty when absent from JSON, so a manifest
    /// written without errors still parses (forward/back compatibility).
    #[test]
    fn source_entry_errors_defaults_when_absent() {
        let json = r#"{
            "artifact":"evtx:Security","path":"x","method":"api",
            "size":0,"sha256":"0"
        }"#;
        let se: SourceEntry = serde_json::from_str(json).unwrap();
        assert!(se.errors.is_empty());
    }

    #[test]
    fn governance_report_round_trips_and_old_json_defaults() {
        let r = GovernanceReport {
            low_priority_applied: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: GovernanceReport = serde_json::from_str(&json).unwrap();
        assert!(back.low_priority_applied);

        // An empty object (pre-governance) defaults every field.
        let empty: GovernanceReport = serde_json::from_str("{}").unwrap();
        assert!(!empty.low_priority_applied);
    }

    #[test]
    fn manifest_without_governance_field_deserializes() {
        // Pre-governance manifest JSON lacks the `governance` field → defaults.
        let m = sample_manifest();
        let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
        v.as_object_mut().unwrap().remove("governance");
        let back: Manifest = serde_json::from_value(v).unwrap();
        assert!(!back.governance.low_priority_applied);
    }

    /// Old manifests (no output `size`, no host offset/reference/skew) still parse.
    #[test]
    fn old_output_and_host_json_defaults_new_fields() {
        let o: OutputEntry = serde_json::from_str(r#"{"file":"a","sha256":"b"}"#).unwrap();
        assert_eq!(o.size, 0);
        let h: HostInfo = serde_json::from_str(
            r#"{"hostname":"h","os_build":"","timezone":"UTC","wall_clock_utc_skew":"unknown"}"#,
        )
        .unwrap();
        assert!(h.utc_offset_seconds.is_none());
        assert!(h.reference_time_utc.is_none() && h.skew_seconds.is_none());
    }

    /// Skew is host minus reference: a host 90s fast reports +90s.
    #[test]
    fn skew_is_host_minus_reference() {
        let reference = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let host = reference + chrono::Duration::seconds(90);
        assert_eq!(skew_seconds(host, reference), 90);
        assert_eq!(skew_seconds(reference, host), -90);
        assert_eq!(format_skew(90), "+90s");
        assert_eq!(format_skew(-3), "-3s");
        assert_eq!(format_skew(0), "+0s");
    }

    #[test]
    fn run_info_missing_profile_and_modules_defaults_on_old_json() {
        // Pre-S2-L manifest JSON lacks `profile`/`selected_modules` (added in S2-L).
        let json = r#"{
            "started_utc":"2026-06-10T12:00:00Z",
            "finished_utc":null,
            "cmdline":"cairn evtx Security.evtx",
            "operator":"",
            "case_id":""
        }"#;
        let ri: RunInfo = serde_json::from_str(json).unwrap();
        assert_eq!(ri.profile, "");
        assert!(ri.selected_modules.is_empty());
    }

    #[test]
    fn manifest_missing_run_profile_field_deserializes() {
        // Full pre-S2-L manifest: `run.profile`/`run.selected_modules` absent entirely.
        let m = sample_manifest();
        let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
        v["run"].as_object_mut().unwrap().remove("profile");
        v["run"].as_object_mut().unwrap().remove("selected_modules");
        let back: Manifest = serde_json::from_value(v).unwrap();
        assert_eq!(back.run.profile, "");
        assert!(back.run.selected_modules.is_empty());
    }
}
