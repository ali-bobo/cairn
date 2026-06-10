//! Run configuration. Mirrors the CLI surface (SRS §6).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Target {
    /// Analyze artifacts already on disk (EVTX dir/files, mounted image).
    Dir(PathBuf),
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
            only: vec![],
            admin_features: false,
            case_id: String::new(),
            operator: String::new(),
            since: None,
            use_vss: false,
        }
    }
}
