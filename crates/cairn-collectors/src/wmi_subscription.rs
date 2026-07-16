//! Converts raw WMI subscription data (cairn-collectors-win::wmi) into
//! PersistenceRecord entries with mechanism="wmi_subscription".
#![forbid(unsafe_code)]

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{PersistenceRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;

/// Extracts a plausible executable path from a CommandLineEventConsumer's
/// CommandLineTemplate (e.g. `C:\Windows\System32\cmd.exe /c ...` -> the exe
/// part). Returns None for ActiveScriptEventConsumer entries (ScriptText has
/// no invoked executable — this is the exact gap this segment exists to
/// surface, not paper over with a guess).
fn extract_binary_path(consumer_type: &str, command: &str) -> Option<String> {
    if consumer_type != "CommandLineEventConsumer" {
        return None;
    }
    // Best-effort: first whitespace-delimited token, stripped of quotes.
    command
        .split_whitespace()
        .next()
        .map(|s| s.trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
}

pub struct WmiSubscriptionCollector;

impl Collector for WmiSubscriptionCollector {
    fn name(&self) -> &str {
        "wmi_subscription"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        #[cfg(windows)]
        let raw = cairn_collectors_win::wmi::enumerate_subscriptions()?;
        #[cfg(not(windows))]
        let raw: Vec<cairn_collectors_win::wmi::RawWmiSubscription> = vec![];

        let records: Vec<PersistenceRecord> = raw
            .into_iter()
            .map(|sub| {
                let binary_path = sub
                    .command
                    .as_deref()
                    .and_then(|c| extract_binary_path(&sub.consumer_type, c));
                PersistenceRecord {
                    mechanism: "wmi_subscription".to_string(),
                    location: format!("{} -> {}", sub.filter_name, sub.consumer_name),
                    value: Some(sub.consumer_name.clone()),
                    command: sub.command,
                    binary_path,
                    // Signature verification is left None here (not backfilled) because
                    // persist.rs's `apply_signatures`/`resolve_relative_binary_paths` are
                    // module-private helpers scoped to PersistCollector's own record batch
                    // (see crates/cairn-collectors/src/persist.rs:782,815) — reusing them
                    // would require either making them pub(crate) and threading a second
                    // FileVerifier instance through this independent collector, or merging
                    // WMI records into PersistCollector's batch (rejected by the plan: WMI's
                    // unsafe COM lifecycle warrants its own collector, see plan Task 1).
                    // Deferred rather than solved here; tracked as a known gap.
                    binary_sha256: None,
                    signed: None,
                    signer: None,
                    last_write: None,
                }
            })
            .collect();

        Ok(records.into_iter().map(Record::Persistence).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "wmi_subscription".into(),
            path: r"live:root\subscription".into(),
            method: "com".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_consumer_extracts_binary_path() {
        let path = extract_binary_path(
            "CommandLineEventConsumer",
            r#"C:\Windows\System32\cmd.exe /c whoami"#,
        );
        assert_eq!(path, Some(r"C:\Windows\System32\cmd.exe".to_string()));
    }

    #[test]
    fn active_script_consumer_never_gets_binary_path() {
        // This is the exact case S9 gate cannot see: no invoked executable.
        let path = extract_binary_path(
            "ActiveScriptEventConsumer",
            r#"CreateObject("WScript.Shell").Run("cmd.exe")"#,
        );
        assert_eq!(path, None);
    }

    #[test]
    fn empty_command_line_yields_no_binary_path() {
        let path = extract_binary_path("CommandLineEventConsumer", "");
        assert_eq!(path, None);
    }
}
