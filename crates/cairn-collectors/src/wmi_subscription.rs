//! Converts raw WMI subscription data (cairn-collectors-win::wmi) into
//! PersistenceRecord entries with mechanism="wmi_subscription".
#![forbid(unsafe_code)]

use cairn_collectors_win::wmi::RawWmiSubscription;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{Mechanism, PersistenceRecord, Record};
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

/// `location` for one entry: `filter -> consumer` for a bound pair, otherwise which half
/// exists, marked unbound.
fn location_of(sub: &RawWmiSubscription) -> String {
    match (
        sub.bound,
        sub.filter_name.is_empty(),
        sub.consumer_name.is_empty(),
    ) {
        (true, _, _) => format!("{} -> {}", sub.filter_name, sub.consumer_name),
        (false, false, _) => format!("filter:{} (unbound)", sub.filter_name),
        (false, true, _) => format!("consumer:{} (unbound)", sub.consumer_name),
    }
}

/// Map raw WMI entries to Persistence records (mechanism wmi_subscription). Pure.
/// `bound` is carried into `PersistenceRecord.bound`; an unbound filter has no command;
/// its `value` is the filter name, otherwise the consumer name.
pub fn build_wmi_records(raw: Vec<RawWmiSubscription>) -> Vec<Record> {
    raw.into_iter()
        .map(|sub| {
            let binary_path = sub
                .command
                .as_deref()
                .and_then(|c| extract_binary_path(&sub.consumer_type, c));
            let location = location_of(&sub);
            let value = if sub.consumer_name.is_empty() {
                sub.filter_name.clone()
            } else {
                sub.consumer_name.clone()
            };
            Record::Persistence(PersistenceRecord {
                mechanism: Mechanism::WmiSubscription,
                location,
                value: Some(value),
                command: sub.command,
                binary_path,
                // Signature verification is left None here (not backfilled): the
                // persist collector's signing helpers are scoped to its own batch.
                // Tracked as a known gap.
                binary_sha256: None,
                signed: None,
                signer: None,
                last_write: None,
                bound: Some(sub.bound),
                signer_source: None,
                service_start: None,
            })
        })
        .collect()
}

pub struct WmiSubscriptionCollector;

impl Collector for WmiSubscriptionCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::WMI_SUBSCRIPTION
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // enumerate_subscriptions() is cross-platform on its own (empty vec on
        // non-Windows) and returns Err (step + HRESULT) on any COM failure, which the
        // orchestrator records in the manifest.
        let raw = cairn_collectors_win::wmi::enumerate_subscriptions()?;
        Ok(build_wmi_records(raw))
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            collector: String::new(),
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

    fn sub(f: &str, c: &str, ctype: &str, cmd: Option<&str>, bound: bool) -> RawWmiSubscription {
        RawWmiSubscription {
            filter_name: f.into(),
            filter_query: String::new(),
            consumer_name: c.into(),
            consumer_type: ctype.into(),
            command: cmd.map(Into::into),
            bound,
        }
    }

    #[test]
    fn maps_bound_and_unbound_entries() {
        let recs = build_wmi_records(vec![
            sub(
                "F",
                "C",
                "CommandLineEventConsumer",
                Some(r"C:\x.exe /q"),
                true,
            ),
            sub("Orphan", "", "", None, false),
            sub("", "Lone", "ActiveScriptEventConsumer", Some("x"), false),
        ]);
        let p: Vec<&PersistenceRecord> = recs
            .iter()
            .map(|r| match r {
                Record::Persistence(p) => p,
                _ => panic!("persistence"),
            })
            .collect();
        assert_eq!(p[0].location, "F -> C");
        assert_eq!(p[0].bound, Some(true));
        assert_eq!(p[0].binary_path.as_deref(), Some(r"C:\x.exe"));
        assert_eq!(p[1].location, "filter:Orphan (unbound)");
        assert_eq!(p[1].bound, Some(false));
        assert_eq!(p[1].value.as_deref(), Some("Orphan"));
        assert_eq!(p[1].command, None);
        assert_eq!(p[2].location, "consumer:Lone (unbound)");
        assert_eq!(p[2].bound, Some(false));
        assert_eq!(p[2].binary_path, None);
        assert!(p.iter().all(|r| r.mechanism == Mechanism::WmiSubscription));
    }
}
