//! Observations: host-inventory items that carry investigative value but are NOT
//! detections (spec §6). Persistence entries that fail the dispositive-signal gate
//! land here instead of findings — every machine has services and autoruns; listing
//! them is inventory, alarming on them is noise.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub schema: String, // crate::schema::OBSERVATION
    /// The item's own time (e.g. registry last_write); run time when unknown.
    pub ts: DateTime<Utc>,
    pub host: String,
    /// "service" | "run_key" | "scheduled_task" | "startup" | "winlogon_default"
    pub category: String,
    /// e.g. "服務 AsusAppService → AsusAppService.exe"
    pub title: String,
    /// Binary full path when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Location (registry key / folder), signature status, last_write.
    pub details: String,
    pub source_artifact: String, // "persistence"
    /// Typed status of one Sigma rule for this run (category [`CATEGORY_SIGMA_RULE`]):
    /// could it fire given the host's logging? Additive; absent on every other
    /// observation, and old JSON without the key deserializes to None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigma_rule: Option<SigmaRuleStatus>,
}

/// `Observation.category` of a per-rule Sigma viability observation.
pub const CATEGORY_SIGMA_RULE: &str = "sigma_rule";

/// A logging setting a Sigma rule needs before it can ever match on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggingRequirement {
    /// Advanced audit "Process Creation" (Security 4688). Off by default.
    ProcessCreationAudit,
    /// `ProcessCreationIncludeCmdLine_Enabled`: 4688 carries the command line. Off by default.
    CommandLineIn4688,
    /// PowerShell script block logging (4104). Off by default (Windows still logs
    /// blocks it considers suspicious).
    ScriptBlockLogging,
    /// PowerShell module logging (4103). Off by default.
    ModuleLogging,
    /// Sysmon installed: the rule needs fields only Sysmon records (OriginalFileName,
    /// Hashes, ParentCommandLine, ...) or a Sysmon-only event type.
    Sysmon,
    /// Audit "Logon" (4624/4625/4648). On by default.
    LogonAudit,
    /// Audit "User Account Management" (4720/4722/4738...). On by default.
    UserAccountManagementAudit,
    /// Audit "Security Group Management" (4728/4732/4756...). On by default.
    SecurityGroupManagementAudit,
    /// Audit "Other Object Access Events" (4698-4702 scheduled tasks). Off by default.
    OtherObjectAccessAudit,
    /// Audit "Security System Extension" (4697 service installed). Off by default.
    SecuritySystemExtensionAudit,
    /// Audit "File Share" (5140). Off by default.
    FileShareAudit,
    /// Audit "Detailed File Share" (5145). Off by default.
    DetailedFileShareAudit,
    /// Object access auditing plus a SACL on the target (4656/4663). Off by default.
    ObjectAccessSacl,
    /// NTLM operational auditing (Microsoft-Windows-NTLM/Operational). Off by default.
    NtlmAudit,
    /// The event is only written on a domain controller (Kerberos 4768/4769, AD 4662/5136).
    DomainController,
    /// Task Scheduler operational log. Disabled by default on client Windows.
    TaskSchedulerLog,
    /// A Security event whose audit subcategory cairn does not map: only seeing such an
    /// event proves it is logged.
    OtherAuditPolicy,
    /// The rule's logsource maps to no known channel: the engine runs it fail-open on
    /// every event, but whether anything could match is unknown.
    UnmappedLogsource,
}

impl LoggingRequirement {
    /// True for settings a default Windows install already has on.
    pub fn default_on(self) -> bool {
        matches!(
            self,
            LoggingRequirement::LogonAudit
                | LoggingRequirement::UserAccountManagementAudit
                | LoggingRequirement::SecurityGroupManagementAudit
        )
    }
}

/// Whether a Sigma rule could fire on this run's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleViability {
    /// Every setting the rule needs is known to be on (or its events were seen).
    Runnable,
    /// At least one needed setting is known to be off: the rule cannot fire here.
    MissingLogging,
    /// Nothing known to be off, but at least one needed setting could not be checked.
    Unknown,
}

/// Typed payload of a [`CATEGORY_SIGMA_RULE`] observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaRuleStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Sigma `level` (lowercase), when the rule has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    pub viability: RuleViability,
    /// Everything the rule needs (for the alternative that decided `viability`).
    #[serde(default)]
    pub requirements: Vec<LoggingRequirement>,
    /// Needed settings known to be off.
    #[serde(default)]
    pub missing: Vec<LoggingRequirement>,
    /// Needed settings that could not be checked.
    #[serde(default)]
    pub unknown: Vec<LoggingRequirement>,
}

impl Observation {
    pub fn new(category: impl Into<String>, title: impl Into<String>) -> Self {
        Observation {
            schema: crate::schema::OBSERVATION.to_string(),
            ts: Utc::now(),
            host: String::new(),
            category: category.into(),
            title: title.into(),
            path: None,
            details: String::new(),
            source_artifact: String::new(),
            sigma_rule: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_roundtrips_with_schema_tag() {
        let mut o = Observation::new("service", "服務 X → x.exe");
        o.path = Some(r"C:\Program Files\X\x.exe".into());
        o.source_artifact = "persistence".into();
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains("cairn.observation/1"));
        let back: Observation = serde_json::from_str(&j).unwrap();
        assert_eq!(back.category, "service");
        assert_eq!(back.path.as_deref(), Some(r"C:\Program Files\X\x.exe"));
        assert!(back.sigma_rule.is_none());
        assert!(!j.contains("sigma_rule"), "absent status is not serialized");
    }

    #[test]
    fn sigma_rule_status_roundtrips_snake_case() {
        let mut o = Observation::new(CATEGORY_SIGMA_RULE, "Rule");
        o.sigma_rule = Some(SigmaRuleStatus {
            rule_id: Some("r1".into()),
            level: Some("high".into()),
            viability: RuleViability::MissingLogging,
            requirements: vec![
                LoggingRequirement::ProcessCreationAudit,
                LoggingRequirement::CommandLineIn4688,
            ],
            missing: vec![LoggingRequirement::ProcessCreationAudit],
            unknown: vec![LoggingRequirement::CommandLineIn4688],
        });
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains("\"missing_logging\""), "{j}");
        assert!(j.contains("\"process_creation_audit\""), "{j}");
        let back: Observation = serde_json::from_str(&j).unwrap();
        assert_eq!(back.sigma_rule, o.sigma_rule);
    }
}
