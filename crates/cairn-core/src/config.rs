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

/// Resource-governance knobs (NFR9). Grouped so the resource posture is one object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Governance {
    /// rayon global pool ceiling. None = default min(cores, MAX_THREADS_CEILING)
    /// (NFR9: not all cores). Some(n>0) = explicit `--max-threads N` (clamped to
    /// real cores by `resolve_max_threads`). Some(0) is treated as None.
    pub max_threads: Option<usize>,
    /// Whether to lower CPU + IO priority (NFR9). `Governance::default()` is false;
    /// the CLI sets this true for a live target unless `--full-speed`. Offline
    /// analysis stays false.
    pub low_priority: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for Governance {
    fn default() -> Self {
        // Default serves the offline/evtx path: uncapped (resolver picks the
        // ceiling) and normal priority. The live run path flips low_priority true.
        Governance {
            max_threads: None,
            low_priority: false,
        }
    }
}

/// NFR9 "sane ceiling, not all cores": the default rayon pool size is capped here
/// even on a many-core box, leaving headroom for the production workload.
pub const MAX_THREADS_CEILING: usize = 8;

/// Effective rayon thread count. Pure; no global state, so it is unit-testable.
///
/// - None / Some(0) → min(available, MAX_THREADS_CEILING)
/// - Some(n>0)      → min(n, available)  (never exceed real cores)
/// - Always returns >= 1 (a 0 `available` is clamped up so rayon gets a valid count).
pub fn resolve_max_threads(requested: Option<usize>, available: usize) -> usize {
    let avail = available.max(1);
    match requested {
        None | Some(0) => avail.min(MAX_THREADS_CEILING),
        Some(n) => n.min(avail),
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
    /// Reconstruct full file paths from $MFT parent references (path map, S2-O).
    /// false → fall back to S2-N bare-filename behaviour (path_complete = None),
    /// the first optional enhancement to drop under a future minimal profile.
    pub resolve_mft_paths: bool,
    /// Resource governance (NFR9): thread cap + priority posture.
    pub governance: Governance,
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
            resolve_mft_paths: true,
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

    /// Builder: set the `--rules-plain` bypass (load un-encoded `.yml`, ADR-0002).
    pub fn with_rules_plain(mut self, plain: bool) -> Self {
        self.rules_plain = plain;
        self
    }

    /// Apply profile-implied light-mode overrides. Call once after CLI parsing,
    /// before the run. Currently: `minimal` disables full-path reconstruction
    /// (path map is the first enhancement dropped in light mode). Idempotent.
    pub fn normalize_for_profile(&mut self) {
        if self.profile == Profile::Minimal {
            self.resolve_mft_paths = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_defaults_are_uncapped_and_normal_priority() {
        let cfg = Config::default();
        assert_eq!(cfg.governance.max_threads, None);
        assert!(!cfg.governance.low_priority);
    }

    #[test]
    fn resolve_max_threads_none_uses_min_cores_ceiling() {
        // None → min(available, 8). available=4 → 4; available=32 → 8 (ceiling).
        assert_eq!(resolve_max_threads(None, 4), 4);
        assert_eq!(resolve_max_threads(None, 32), 8);
        assert_eq!(resolve_max_threads(None, 8), 8);
    }

    #[test]
    fn resolve_max_threads_zero_is_treated_as_default() {
        // Some(0) is meaningless; fall back to the None default.
        assert_eq!(resolve_max_threads(Some(0), 16), 8);
    }

    #[test]
    fn resolve_max_threads_explicit_never_exceeds_available() {
        assert_eq!(resolve_max_threads(Some(2), 16), 2);
        assert_eq!(resolve_max_threads(Some(1000), 16), 16); // clamped to cores
        assert_eq!(resolve_max_threads(Some(4), 4), 4);
    }

    #[test]
    fn resolve_max_threads_never_returns_zero() {
        // available could be reported as 0 in pathological cases; result must be >= 1.
        assert!(resolve_max_threads(None, 0) >= 1);
        assert!(resolve_max_threads(Some(0), 0) >= 1);
        assert!(resolve_max_threads(Some(1), 0) >= 1); // Some(n) arm, pathological available=0
    }

    #[test]
    fn normalize_for_profile_minimal_disables_path_resolution() {
        let mut cfg = Config {
            profile: Profile::Minimal,
            ..Config::default()
        };
        assert!(cfg.resolve_mft_paths, "default starts true");
        cfg.normalize_for_profile();
        assert!(!cfg.resolve_mft_paths, "minimal must force false");
        // idempotent
        cfg.normalize_for_profile();
        assert!(!cfg.resolve_mft_paths);
    }

    #[test]
    fn normalize_for_profile_standard_and_verbose_leave_path_resolution() {
        for p in [Profile::Standard, Profile::Verbose] {
            let mut cfg = Config {
                profile: p,
                resolve_mft_paths: true,
                ..Config::default()
            };
            cfg.normalize_for_profile();
            assert!(cfg.resolve_mft_paths, "{p:?} must not disable resolution");
        }
    }

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

    #[test]
    fn resolve_mft_paths_defaults_to_true() {
        let cfg = Config::default();
        assert!(cfg.resolve_mft_paths);
    }
}
