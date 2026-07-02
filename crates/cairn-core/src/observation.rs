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
    }
}
