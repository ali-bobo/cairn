//! cairn-sigma: Sigma rule loading + matching over EventRecords. SRS §9.
//!
//! Key design decision (Hayabusa model): DO NOT resolve `logsource` at runtime.
//! Ship a precompiled mapping (LogsourceMap) that turns category/product/service
//! into concrete {Channel, EventID, field aliases}. Only run rules whose
//! Channel/EventID actually appear in the data.
//!
//! The concrete matcher is hidden behind `SigmaMatcher` so the chosen engine
//! (sigma-engine | sigmars | tau-engine) is swappable. See benchmark plan.
#![forbid(unsafe_code)] // pure rule logic; no raw-volume/WinAPI here (CLAUDE.md convention).

use cairn_core::{finding::Finding, record::EventRecord, Result};

pub mod codec;
pub mod engine;
pub mod ruleset;

/// Swappable engine seam. Implement once an engine is chosen in T6.
pub trait SigmaMatcher: Send + Sync {
    /// Load + compile rules from a directory of `.yml`. `plain = false` XOR-decodes the
    /// bundled rules (ADR-0002); `plain = true` reads un-encoded `.yml` as-is, the
    /// `--rules-plain` bypass a SOC uses to audit exactly what runs.
    fn load(&mut self, rules_dir: &std::path::Path, plain: bool) -> Result<usize>;
    /// Match a single event; return zero or more Findings (author surfaced per DRL).
    fn match_event(&self, ev: &EventRecord) -> Result<Vec<Finding>>;
    /// Channels referenced by loaded rules (for load-optimization: skip absent channels).
    fn referenced_channels(&self) -> &[String];
}

/// Precompiled logsource de-abstraction. Built offline (T5) from SigmaHQ + config maps.
#[derive(Debug, Default, Clone)]
pub struct LogsourceMap {
    /// (category|service) -> list of (channel, event_id, field-rename table)
    pub entries: Vec<LogsourceEntry>,
}

#[derive(Debug, Clone)]
pub struct LogsourceEntry {
    pub category: Option<String>,
    pub service: Option<String>,
    pub product: Option<String>,
    pub channel: String,
    pub event_id: u32,
    /// sigma-field -> evtx EventData path (e.g. "Image" -> "NewProcessName" for 4688)
    pub field_aliases: Vec<(String, String)>,
}

impl LogsourceMap {
    /// Resolve a Sigma `logsource` triple to the concrete EVTX entries it maps to.
    /// Returns every entry that matches all the *given* (Some) selectors; `None`
    /// selectors are wildcards. A single logsource may map to multiple entries
    /// (e.g. process_creation -> Security 4688 AND Sysmon EID 1).
    pub fn resolve(
        &self,
        category: Option<&str>,
        product: Option<&str>,
        service: Option<&str>,
    ) -> Vec<&LogsourceEntry> {
        let want = |sel: Option<&str>, have: &Option<String>| match sel {
            None => true,
            Some(s) => have.as_deref() == Some(s),
        };
        self.entries
            .iter()
            .filter(|e| {
                // At least one selector must be provided and all provided ones match.
                (category.is_some() || product.is_some() || service.is_some())
                    && want(category, &e.category)
                    && want(product, &e.product)
                    && want(service, &e.service)
            })
            .collect()
    }

    /// Built-in de-abstraction map for the common Windows logsources (Hayabusa model).
    /// Covers the top ~20 categories/services analysts hit in Stage-1 EVTX triage.
    pub fn windows_builtin() -> Self {
        // (category, service, channel, event_id, field_aliases)
        type Seed = (
            Option<&'static str>,
            Option<&'static str>,
            &'static str,
            u32,
            &'static [(&'static str, &'static str)],
        );
        const SEEDS: &[Seed] = &[
            // process_creation -> Security 4688 + Sysmon EID 1
            (
                Some("process_creation"),
                None,
                "Security",
                4688,
                &[
                    ("Image", "NewProcessName"),
                    ("ParentImage", "ParentProcessName"),
                ],
            ),
            (
                Some("process_creation"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                1,
                &[],
            ),
            // network_connection -> Sysmon EID 3
            (
                Some("network_connection"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                3,
                &[],
            ),
            // image_load -> Sysmon EID 7
            (
                Some("image_load"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                7,
                &[],
            ),
            // dns_query -> Sysmon EID 22
            (
                Some("dns_query"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                22,
                &[],
            ),
            // file_event -> Sysmon EID 11
            (
                Some("file_event"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                11,
                &[],
            ),
            // file_delete -> Sysmon EID 23
            (
                Some("file_delete"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                23,
                &[],
            ),
            // registry_event / registry_set -> Sysmon EID 13
            (
                Some("registry_event"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                13,
                &[],
            ),
            (
                Some("registry_set"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                13,
                &[],
            ),
            // registry_add -> Sysmon EID 12
            (
                Some("registry_add"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                12,
                &[],
            ),
            // process_access -> Sysmon EID 10
            (
                Some("process_access"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                10,
                &[],
            ),
            // pipe_created -> Sysmon EID 17
            (
                Some("pipe_created"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                17,
                &[],
            ),
            // wmi_event -> Sysmon EID 19
            (
                Some("wmi_event"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                19,
                &[],
            ),
            // process_termination -> Sysmon EID 5
            (
                Some("process_termination"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                5,
                &[],
            ),
            // create_remote_thread -> Sysmon EID 8
            (
                Some("create_remote_thread"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                8,
                &[],
            ),
            // driver_load -> Sysmon EID 6
            (
                Some("driver_load"),
                None,
                "Microsoft-Windows-Sysmon/Operational",
                6,
                &[],
            ),
            // Services by channel (service selector -> whole channel; event_id 0 = any)
            (None, Some("security"), "Security", 0, &[]),
            (None, Some("system"), "System", 0, &[]),
            (None, Some("application"), "Application", 0, &[]),
            (
                None,
                Some("sysmon"),
                "Microsoft-Windows-Sysmon/Operational",
                0,
                &[],
            ),
            (
                None,
                Some("powershell"),
                "Microsoft-Windows-PowerShell/Operational",
                0,
                &[],
            ),
            (
                None,
                Some("powershell-classic"),
                "Windows PowerShell",
                0,
                &[],
            ),
            (
                None,
                Some("windefend"),
                "Microsoft-Windows-Windows Defender/Operational",
                0,
                &[],
            ),
            (
                None,
                Some("taskscheduler"),
                "Microsoft-Windows-TaskScheduler/Operational",
                0,
                &[],
            ),
            (
                None,
                Some("wmi"),
                "Microsoft-Windows-WMI-Activity/Operational",
                0,
                &[],
            ),
            (
                None,
                Some("ntlm"),
                "Microsoft-Windows-NTLM/Operational",
                0,
                &[],
            ),
        ];

        let entries = SEEDS
            .iter()
            .map(|(cat, svc, channel, eid, aliases)| LogsourceEntry {
                category: cat.map(str::to_owned),
                service: svc.map(str::to_owned),
                product: Some("windows".to_owned()),
                channel: (*channel).to_owned(),
                event_id: *eid,
                field_aliases: aliases
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            })
            .collect();

        LogsourceMap { entries }
    }
}

/// Config files mirrored from Hayabusa concepts (SRS §9): load from rules/config/.
#[derive(Debug, Default)]
pub struct EngineConfig {
    pub channel_abbreviations: Vec<(String, String)>,
    pub eventkey_alias: Vec<(String, String)>,
    pub noisy_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
    pub level_tuning: Vec<(String, String)>,
}

/// Parse tab-separated `key<TAB>value` config lines; skip blank lines and `#` comments,
/// trim surrounding whitespace. Lines without a tab are ignored.
fn parse_kv_lines(input: &str) -> Vec<(String, String)> {
    input
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Parse one-value-per-line config lines (e.g. rule id lists); skip blanks/comments.
fn parse_list_lines(input: &str) -> Vec<String> {
    input
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

impl EngineConfig {
    /// Load the config maps from a `rules/config/` directory. A missing file yields an
    /// empty section (a partial config dir is valid); only a real read error fails.
    pub fn load(dir: &std::path::Path) -> Result<Self> {
        let read_kv = |name: &str| -> Result<Vec<(String, String)>> {
            match std::fs::read_to_string(dir.join(name)) {
                Ok(s) => Ok(parse_kv_lines(&s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
                Err(e) => Err(e.into()),
            }
        };
        let read_list = |name: &str| -> Result<Vec<String>> {
            match std::fs::read_to_string(dir.join(name)) {
                Ok(s) => Ok(parse_list_lines(&s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
                Err(e) => Err(e.into()),
            }
        };
        Ok(EngineConfig {
            channel_abbreviations: read_kv("channel_abbreviations.txt")?,
            eventkey_alias: read_kv("eventkey_alias.txt")?,
            noisy_rules: read_list("noisy_rules.txt")?,
            exclude_rules: read_list("exclude_rules.txt")?,
            level_tuning: read_kv("level_tuning.txt")?,
        })
    }
}

// TODO(claude-code) T6: implement a concrete `EngineX` : SigmaMatcher wrapping the
// chosen crate; wire field aliasing via LogsourceMap; surface rule author into
// Finding.rule_author (DRL 1.1 hard requirement).

#[cfg(test)]
mod tests {
    use super::*;

    /// process_creation resolves to BOTH Security 4688 and Sysmon EID 1 (Hayabusa
    /// de-abstraction model). The 4688 entry aliases Sigma's `Image` field to the
    /// EVTX field `NewProcessName`.
    #[test]
    fn resolves_process_creation_to_security_and_sysmon() {
        let map = LogsourceMap::windows_builtin();
        let hits = map.resolve(Some("process_creation"), None, None);

        let channels: Vec<&str> = hits.iter().map(|e| e.channel.as_str()).collect();
        assert!(
            channels.contains(&"Security"),
            "expected Security channel, got {channels:?}"
        );
        assert!(
            channels.iter().any(|c| c.contains("Sysmon")),
            "expected a Sysmon channel, got {channels:?}"
        );

        let sec = hits
            .iter()
            .find(|e| e.channel == "Security")
            .expect("Security entry");
        assert_eq!(sec.event_id, 4688);
        let image_alias = sec
            .field_aliases
            .iter()
            .find(|(k, _)| k == "Image")
            .map(|(_, v)| v.as_str());
        assert_eq!(image_alias, Some("NewProcessName"));

        let sysmon = hits
            .iter()
            .find(|e| e.channel.contains("Sysmon"))
            .expect("Sysmon entry");
        assert_eq!(sysmon.event_id, 1);
    }

    /// A `service` logsource (e.g. `security`) resolves to its channel.
    #[test]
    fn resolves_service_security_to_channel() {
        let map = LogsourceMap::windows_builtin();
        let hits = map.resolve(None, None, Some("security"));
        assert!(hits.iter().any(|e| e.channel == "Security"));
    }

    /// The built-in map covers at least the top ~20 Windows logsources (T5 acceptance).
    #[test]
    fn builtin_covers_top_windows_logsources() {
        let map = LogsourceMap::windows_builtin();
        assert!(
            map.entries.len() >= 20,
            "expected >= 20 entries, got {}",
            map.entries.len()
        );
    }

    /// An unknown logsource resolves to nothing (no panic, empty result).
    #[test]
    fn unknown_logsource_resolves_empty() {
        let map = LogsourceMap::windows_builtin();
        assert!(map
            .resolve(Some("definitely_not_a_category"), None, None)
            .is_empty());
    }

    /// Key/value config lines parse as TSV; `#` comments and blank lines are skipped,
    /// surrounding whitespace trimmed.
    #[test]
    fn parses_kv_config_lines() {
        let input = "\
# channel abbreviations
Security\tSec
Microsoft-Windows-Sysmon/Operational\tSysmon

  Application  \t  App  \n";
        let kv = parse_kv_lines(input);
        assert_eq!(kv.len(), 3);
        assert_eq!(kv[0], ("Security".to_string(), "Sec".to_string()));
        assert_eq!(
            kv[1],
            (
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Sysmon".to_string()
            )
        );
        // trimmed
        assert_eq!(kv[2], ("Application".to_string(), "App".to_string()));
    }

    /// Single-value config lines (rule id lists) parse one per line, comments skipped.
    #[test]
    fn parses_list_config_lines() {
        let input = "# noisy rules\nrule-aaa\n\n  rule-bbb  \n# trailing comment\n";
        let list = parse_list_lines(input);
        assert_eq!(list, vec!["rule-aaa".to_string(), "rule-bbb".to_string()]);
    }

    /// EngineConfig loads the config files present in a dir; missing files are simply
    /// empty (graceful — a partial config dir is valid).
    #[test]
    fn engine_config_loads_present_files_and_tolerates_missing() {
        let dir = std::env::temp_dir().join("cairn_engine_config_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("channel_abbreviations.txt"), "Security\tSec\n").unwrap();
        std::fs::write(
            dir.join("eventkey_alias.txt"),
            "Image\tEvent.EventData.NewProcessName\n",
        )
        .unwrap();
        // noisy_rules.txt intentionally absent.

        let cfg = EngineConfig::load(&dir).unwrap();
        assert_eq!(
            cfg.channel_abbreviations,
            vec![("Security".into(), "Sec".into())]
        );
        assert_eq!(
            cfg.eventkey_alias,
            vec![("Image".into(), "Event.EventData.NewProcessName".into())]
        );
        assert!(cfg.noisy_rules.is_empty());
    }

    /// The bundled rules/config/ seed files load and contain the expected core mappings
    /// (T5 acceptance: seed config maps exist in rules/config/).
    #[test]
    fn loads_bundled_seed_config() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/config");
        let cfg = EngineConfig::load(&dir).unwrap();
        assert!(
            cfg.channel_abbreviations
                .iter()
                .any(|(k, v)| k == "Security" && v == "Sec"),
            "channel_abbreviations should map Security->Sec"
        );
        assert!(
            cfg.eventkey_alias
                .iter()
                .any(|(k, v)| k == "Image" && v == "NewProcessName"),
            "eventkey_alias should map Image->NewProcessName"
        );
    }
}
