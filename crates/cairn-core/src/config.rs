//! Run configuration. Mirrors the CLI surface (SRS §6).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Target {
    /// Analyze artifacts already on disk (EVTX dir/files, mounted image).
    Dir(PathBuf),
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
    Verbose,
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
            "verbose" => Ok(Profile::Verbose),
            other => Err(format!(
                "unknown profile '{other}'; valid profiles: minimal, standard, verbose"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputKind {
    Dir(PathBuf),
    Zip(PathBuf),
    EncryptedZip { path: PathBuf, pubkey: PathBuf },
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target: Target,
    pub output: OutputKind,
    pub profile: Profile,
    pub rules_dir: Option<PathBuf>,
    /// Load rules as un-encoded `.yml` (the `--rules-plain` SOC-audit bypass, ADR-0002).
    /// Default false: bundled rules are XOR-encoded and decoded on load.
    pub rules_plain: bool,
    /// module allow-list (e.g. ["evtx","process","persist"]); empty == default set.
    pub only: Vec<String>,
    pub admin_features: bool,
    pub case_id: String,
    pub operator: String,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub use_vss: bool,
    /// Hard cap on $MFT records scanned by the mft collector (NFR10). Default 1_000_000.
    /// Hitting it records a truncation note in the manifest and stops the scan
    /// (never OOM / never an unbounded loop on a lied-about volume capacity).
    pub max_mft_records: u64,
    /// Min FN−SI delta (hours), either axis, before a timestomp Finding fires (S2-N′).
    /// Below this, sub-day SI/FN drift from legit ops (unzip/copy/install) is ignored.
    /// Fixed default; no CLI flag — banding (Medium/High/Critical) carries severity.
    pub timestomp_threshold_hours: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            target: Target::Live,
            output: OutputKind::Dir(PathBuf::from("./out")),
            profile: Profile::Standard,
            rules_dir: None,
            rules_plain: false,
            only: vec![],
            admin_features: false,
            case_id: String::new(),
            operator: String::new(),
            since: None,
            use_vss: false,
            max_mft_records: 1_000_000,
            timestomp_threshold_hours: 24,
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

    /// Builder: set the `--rules-plain` bypass (load un-encoded `.yml`, ADR-0002).
    pub fn with_rules_plain(mut self, plain: bool) -> Self {
        self.rules_plain = plain;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cairn evtx <files> --rules <dir>` maps to a Config whose target is the file
    /// list, rules_dir is set, and output stays off-target by default (golden rule 4).
    #[test]
    fn for_evtx_maps_files_rules_and_default_output() {
        let files = vec![PathBuf::from("Security.evtx"), PathBuf::from("System.evtx")];
        let cfg = Config::for_evtx(files.clone(), Some(PathBuf::from("./rules")));

        match &cfg.target {
            Target::Files(fs) => assert_eq!(fs, &files),
            other => panic!("expected Target::Files, got {other:?}"),
        }
        assert_eq!(cfg.rules_dir, Some(PathBuf::from("./rules")));
        // Stage-1 evtx run is file analysis, not live; no admin features.
        assert!(!cfg.admin_features);
        // Output defaults off-target (a dir), never DryRun unless asked.
        assert!(matches!(cfg.output, OutputKind::Dir(_)));
    }

    /// Rules dir is optional; absent means "use bundled rules" (resolved later).
    #[test]
    fn for_evtx_allows_no_rules_dir() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert_eq!(cfg.rules_dir, None);
    }

    /// `--rules-plain` (ADR-0002 SOC-audit bypass) defaults OFF: bundled rules are
    /// XOR-encoded, so the default run decodes. `with_rules_plain(true)` flips it.
    #[test]
    fn rules_plain_defaults_off_and_is_settable() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert!(
            !cfg.rules_plain,
            "default must decode (encoded bundled rules)"
        );
        let cfg = cfg.with_rules_plain(true);
        assert!(cfg.rules_plain);
    }

    #[test]
    fn profile_from_str_parses_known_values_case_insensitively() {
        assert_eq!("minimal".parse::<Profile>().unwrap(), Profile::Minimal);
        assert_eq!("standard".parse::<Profile>().unwrap(), Profile::Standard);
        assert_eq!("verbose".parse::<Profile>().unwrap(), Profile::Verbose);
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
            err.contains("minimal") && err.contains("standard") && err.contains("verbose"),
            "error should list valid profiles: {err}"
        );
    }

    #[test]
    fn max_mft_records_defaults_to_one_million() {
        let cfg = Config::default();
        assert_eq!(cfg.max_mft_records, 1_000_000);
    }

    #[test]
    fn timestomp_threshold_defaults_to_24_hours() {
        let cfg = Config::default();
        assert_eq!(cfg.timestomp_threshold_hours, 24);
    }
}
