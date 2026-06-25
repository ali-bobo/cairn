#![forbid(unsafe_code)]

use cairn_core::{CairnError, Result};
use std::path::Path;

#[derive(serde::Deserialize, Debug)]
pub struct RulesetConfig {
    pub sigma: SigmaSection,
    pub rules: Vec<RuleEntry>,
}

#[derive(serde::Deserialize, Debug)]
pub struct SigmaSection {
    pub pin: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct RuleEntry {
    pub path: String,
}

pub fn load(toml_path: &Path) -> Result<RulesetConfig> {
    let text = std::fs::read_to_string(toml_path)
        .map_err(|e| CairnError::Other(format!("ruleset.toml read: {e}")))?;
    toml::from_str(&text).map_err(|e| CairnError::Other(format!("ruleset.toml parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_toml(dir: &std::path::Path, content: &str) -> std::path::PathBuf {
        let p = dir.join("ruleset.toml");
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn parse_ruleset_toml() {
        let dir = std::env::temp_dir().join("cairn_config_test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_toml(
            &dir,
            r#"
[sigma]
pin = "98781da19cf60c48ce6e7f2d3ad11c9ba389191a"

[[rules]]
path = "windows/process_creation/rule_a.yml"

[[rules]]
path = "windows/process_creation/rule_b.yml"
"#,
        );
        let cfg = load(&p).unwrap();
        assert_eq!(cfg.sigma.pin, "98781da19cf60c48ce6e7f2d3ad11c9ba389191a");
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].path, "windows/process_creation/rule_a.yml");
        assert_eq!(cfg.rules[1].path, "windows/process_creation/rule_b.yml");
    }

    #[test]
    fn missing_toml_returns_err() {
        let p = std::path::Path::new("/nonexistent/ruleset.toml");
        assert!(load(p).is_err());
    }
}
