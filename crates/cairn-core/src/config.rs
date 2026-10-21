//! Run configuration. Mirrors the CLI surface (SRS §6).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default live-EVTX look-back, in hours (30 days), when `--since` is not given. Shared
/// by the CLI default and the launcher's double-click scan so the two cannot drift.
/// Incidents are routinely found weeks after initial access, and EVTX logs are
/// size-bounded, so a month costs little.
pub const DEFAULT_SINCE_HOURS: i64 = 720;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Target {
    /// Analyze an explicit list of files (the `cairn evtx <files...>` entry, SRS §6).
    Files(Vec<PathBuf>),
    /// Collect from the live running host.
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Minimal,
    Standard,
}

impl std::str::FromStr for Profile {
    /// A human-readable message (the bad value + the valid set), surfaced to the
    /// CLI user. `cairn-core` libs use `CairnError`, but `--profile` parsing is a
    /// pure string→enum mapping with no I/O; a `String` message keeps it dependency-
    /// free and lets the CLI present it directly.
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "minimal" => Ok(Profile::Minimal),
            "standard" => Ok(Profile::Standard),
            other => Err(format!(
                "unknown profile '{other}'; valid profiles: minimal, standard"
            )),
        }
    }
}

/// Resource-governance knobs (NFR9). Grouped so the resource posture is one object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Governance {
    /// Whether to lower CPU + IO priority (NFR9). `Governance::default()` is false;
    /// the CLI sets this true for a live target unless `--full-speed`. Offline
    /// analysis stays false.
    pub low_priority: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputKind {
    Dir(PathBuf),
    Zip(PathBuf),
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target: Target,
    pub output: OutputKind,
    pub profile: Profile,
    pub rules_dir: Option<PathBuf>,
    /// module allow-list (e.g. ["evtx","process","persist"]); empty == default set.
    pub only: Vec<String>,
    pub case_id: String,
    pub operator: String,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Time window (minutes) for grouping repeated failed logons (EID 4625) from the
    /// same (TargetUserName, IpAddress) pair before flagging bruteforce (segment 4-C).
    /// Fixed default; no CLI flag.
    pub logon_bruteforce_window_minutes: i64,
    /// Failure count within `logon_bruteforce_window_minutes` that triggers a
    /// bruteforce Finding for a single (TargetUserName, IpAddress) group.
    pub logon_bruteforce_threshold: u32,
    /// Time window (minutes) for grouping distinct-account logon attempts from the
    /// same source (IpAddress or WorkstationName) before flagging password spraying.
    /// Fixed default; no CLI flag.
    pub password_spraying_window_minutes: i64,
    /// Distinct TargetUserName count within `password_spraying_window_minutes` from
    /// the same source that triggers a spraying Finding.
    pub password_spraying_threshold: u32,
    /// Resource governance (NFR9): priority posture.
    pub governance: Governance,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            target: Target::Live,
            output: OutputKind::Dir(PathBuf::from("./out")),
            profile: Profile::Standard,
            rules_dir: None,
            only: vec![],
            case_id: String::new(),
            operator: String::new(),
            since: None,
            logon_bruteforce_window_minutes: 5,
            logon_bruteforce_threshold: 5,
            password_spraying_window_minutes: 1,
            password_spraying_threshold: 10,
            governance: Governance::default(),
        }
    }
}

impl Config {
    /// Build the Stage-1 `cairn evtx <files> --rules <dir>` run config: analyze an
    /// explicit file list, output off-target by default, no live/admin collection.
    pub fn for_evtx(files: Vec<PathBuf>, rules_dir: Option<PathBuf>) -> Self {
        Config {
            target: Target::Files(files),
            rules_dir,
            ..Config::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_defaults_to_normal_priority() {
        let cfg = Config::default();
        assert!(!cfg.governance.low_priority);
    }

    #[test]
    fn for_evtx_maps_files_rules_and_default_output() {
        let files = vec![PathBuf::from("Security.evtx"), PathBuf::from("System.evtx")];
        let cfg = Config::for_evtx(files.clone(), Some(PathBuf::from("./rules")));

        match &cfg.target {
            Target::Files(fs) => assert_eq!(fs, &files),
            other => panic!("expected Target::Files, got {other:?}"),
        }
        assert_eq!(cfg.rules_dir, Some(PathBuf::from("./rules")));
        // Output defaults off-target (a dir), never DryRun unless asked.
        assert!(matches!(cfg.output, OutputKind::Dir(_)));
    }

    /// Rules dir is optional; absent means "use bundled rules" (resolved later).
    #[test]
    fn for_evtx_allows_no_rules_dir() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert_eq!(cfg.rules_dir, None);
    }

    #[test]
    fn profile_from_str_parses_known_values_case_insensitively() {
        assert_eq!("minimal".parse::<Profile>().unwrap(), Profile::Minimal);
        assert_eq!("standard".parse::<Profile>().unwrap(), Profile::Standard);
        assert!("verbose".parse::<Profile>().is_err(), "verbose was removed");
        // case-insensitive: an analyst typing --profile MINIMAL still works.
        assert_eq!("MINIMAL".parse::<Profile>().unwrap(), Profile::Minimal);
        assert_eq!("Standard".parse::<Profile>().unwrap(), Profile::Standard);
    }

    #[test]
    fn profile_from_str_rejects_unknown_value() {
        let err = "bogus".parse::<Profile>().unwrap_err();
        // The error names the bad value AND the valid set (a usable CLI error).
        assert!(
            err.contains("bogus"),
            "error should echo the bad value: {err}"
        );
        assert!(
            err.contains("minimal") && err.contains("standard"),
            "error should list valid profiles: {err}"
        );
    }
}
