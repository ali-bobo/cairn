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
    /// The active run profile (minimal|standard|verbose) — transparency (FR6).
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
    pub wall_clock_utc_skew: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Privileges {
    pub admin: bool,
    pub se_backup: bool,
    pub se_debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntry {
    pub artifact: String,
    pub path: String,
    pub method: String, // api|raw_ntfs|vss
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputEntry {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub records: u64,
    pub findings_by_sev: std::collections::BTreeMap<String, u64>,
    /// Inventory items written to observations.jsonl (spec §6). Additive.
    #[serde(default)]
    pub observations: u64,
}

/// Resource-governance report (NFR9/NFR10): what the run throttled or truncated.
/// Additive; `#[serde(default)]` on the `Manifest` field keeps pre-governance
/// manifests parseable.
/// Truncations here are the structured form; the same event is also recorded as a
/// string in `manifest.sources[].errors` for SRS NFR10 compatibility.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceReport {
    /// Effective rayon thread count used this run.
    #[serde(default)]
    pub effective_threads: usize,
    /// True if the process priority was successfully lowered (live + not --full-speed).
    #[serde(default)]
    pub low_priority_applied: bool,
    /// One entry per collector that hit a record cap / circuit breaker.
    #[serde(default)]
    pub truncations: Vec<Truncation>,
}

/// A single circuit-breaker / cap hit, recorded for transparency (NFR10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Truncation {
    /// The collector module that was truncated, e.g. `"mft"`.
    pub collector: String,
    /// The cap value that fired, in the collector's natural unit (e.g. a record
    /// count for `max_mft_records`); see `reason` for the unit context.
    pub cap: u64,
    /// Human-readable explanation, e.g. `"max_mft_records reached"`.
    pub reason: String,
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
            },
            privileges: Privileges {
                admin: false,
                se_backup: false,
                se_debug: false,
            },
            sources: vec![SourceEntry {
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
            effective_threads: 8,
            low_priority_applied: true,
            truncations: vec![Truncation {
                collector: "mft".into(),
                cap: 1_000_000,
                reason: "max_mft_records reached".into(),
            }],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: GovernanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.effective_threads, 8);
        assert!(back.low_priority_applied);
        assert_eq!(back.truncations.len(), 1);
        assert_eq!(back.truncations[0].collector, "mft");
        assert_eq!(back.truncations[0].cap, 1_000_000);
        assert_eq!(back.truncations[0].reason, "max_mft_records reached");

        // A GovernanceReport with no truncations omits/defaults the vec.
        let empty: GovernanceReport = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.effective_threads, 0);
        assert!(!empty.low_priority_applied);
        assert!(empty.truncations.is_empty());
    }

    #[test]
    fn manifest_without_governance_field_deserializes() {
        // Pre-governance manifest JSON lacks the `governance` field → defaults.
        let m = sample_manifest();
        let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
        v.as_object_mut().unwrap().remove("governance");
        let back: Manifest = serde_json::from_value(v).unwrap();
        assert_eq!(back.governance.effective_threads, 0);
        assert!(back.governance.truncations.is_empty());
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
