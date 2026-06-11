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
}
