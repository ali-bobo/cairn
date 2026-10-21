//! Command lines seen this run, from live processes and from Security 4688 events,
//! in one shape, so the analyzers that judge command lines (`heur_cred_dump`,
//! `heur_ransom`) read both sources the same way.

use cairn_core::finding::{EntityProcess, Finding};
use cairn_core::record::{EventRecord, Record};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

/// A string field of an event's flattened data (numbers as their decimal text).
pub(crate) fn event_str(data: &Map<String, Value>, key: &str) -> Option<String> {
    match data.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// One command line and where it was seen.
#[derive(Debug, Clone)]
pub(crate) struct CommandLine<'a> {
    pub cmd: String,
    pub image: String,
    pub user: Option<String>,
    /// Process start / event time, when known.
    pub ts: Option<DateTime<Utc>>,
    /// `process` or `evtx:Security`.
    pub artifact: &'static str,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub event: Option<&'a EventRecord>,
}

impl CommandLine<'_> {
    /// Lowercase command line with runs of whitespace collapsed to one space.
    pub fn normalized(&self) -> String {
        self.cmd
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Stamp time, artifact, event id / record and process entity onto `f`.
    pub fn apply_to(&self, f: &mut Finding) {
        if let Some(t) = self.ts {
            f.ts = t;
        }
        f.artifact = self.artifact.into();
        f.user = self.user.clone();
        if let Some(ev) = self.event {
            f.event_id = Some(ev.event_id);
            f.evidence_ref = Some(format!("{}#{}", ev.channel, ev.record_id));
        }
        f.entity.process = Some(EntityProcess {
            pid: self.pid.unwrap_or(0),
            ppid: self.ppid.unwrap_or(0),
            image: self.image.clone(),
            cmdline: self.cmd.clone(),
            signed: None,
            integrity: None,
        });
    }
}

/// Parse a hex (`0x1a2`) or decimal process id from an event field.
fn event_pid(data: &Map<String, Value>, key: &str) -> Option<u32> {
    let s = event_str(data, key)?;
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Every non-empty command line in `records`: live processes, then 4688 events.
pub(crate) fn command_lines(records: &[Record]) -> Vec<CommandLine<'_>> {
    let mut out = Vec::new();
    for r in records {
        match r {
            Record::Process(p) if !p.cmdline.trim().is_empty() => out.push(CommandLine {
                cmd: p.cmdline.clone(),
                image: p.image.clone(),
                user: p.user.clone(),
                ts: p.start_time,
                artifact: "process",
                pid: Some(p.pid),
                ppid: Some(p.ppid),
                event: None,
            }),
            Record::Event(ev) if ev.channel == "Security" && ev.event_id == 4688 => {
                let Some(cmd) = event_str(&ev.data, "CommandLine").filter(|c| !c.trim().is_empty())
                else {
                    continue;
                };
                out.push(CommandLine {
                    cmd,
                    image: event_str(&ev.data, "NewProcessName").unwrap_or_default(),
                    user: event_str(&ev.data, "SubjectUserName"),
                    ts: Some(ev.ts),
                    artifact: "evtx:Security",
                    pid: event_pid(&ev.data, "NewProcessId"),
                    ppid: event_pid(&ev.data, "ProcessId"),
                    event: Some(ev),
                });
            }
            _ => {}
        }
    }
    out
}

/// [`crate::trust::exe_name`] of the program a command line starts, falling back to
/// the image path's file name.
pub(crate) fn program(c: &CommandLine<'_>) -> String {
    crate::trust::invoked_exe(&c.cmd)
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| crate::trust::exe_name(&c.image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::ProcessRecord;
    use serde_json::json;

    #[test]
    fn processes_and_4688_events_both_yield_command_lines() {
        let p = Record::Process(ProcessRecord {
            pid: 10,
            ppid: 4,
            image: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: "cmd.exe  /c   echo hi".into(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        });
        let Value::Object(data) = json!({
            "CommandLine": "vssadmin delete shadows /all",
            "NewProcessName": r"C:\Windows\System32\vssadmin.exe",
            "NewProcessId": "0x1f4",
        }) else {
            unreachable!()
        };
        let e = Record::Event(EventRecord {
            ts: Utc::now(),
            channel: "Security".into(),
            event_id: 4688,
            provider: String::new(),
            computer: String::new(),
            record_id: 7,
            data,
        });
        let records = [p, e];
        let cl = command_lines(&records);
        assert_eq!(cl.len(), 2);
        assert_eq!(cl[0].normalized(), "cmd.exe /c echo hi");
        assert_eq!(cl[1].pid, Some(500));
        assert_eq!(program(&cl[1]), "vssadmin");
    }
}
