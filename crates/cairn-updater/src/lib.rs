#![forbid(unsafe_code)]

pub mod config;
pub mod encode;
pub mod fetch;

pub use cairn_core::Result;

pub fn run(
    _pin_override: Option<&str>,
    _rules_dir: &std::path::Path,
    _ruleset_toml: &std::path::Path,
) -> Result<()> {
    unimplemented!("cairn-updater: run() not yet wired")
}
