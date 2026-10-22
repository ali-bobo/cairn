//! Process starts seen this run, from live processes, Security 4688 and Sysmon 1
//! events, in one shape, so the analyzers that judge command lines (`heur_cred_dump`,
//! `heur_ransom`) and parent -> child chains (`heur_parentchild`) read every source
//! the same way, live or offline.
//!
//! Field names (checked against real EVTX-ATTACK-SAMPLES logs, `tests/fixtures/`):
//!
//! | | Security 4688 | Sysmon 1 |
//! |---|---|---|
//! | image | `NewProcessName` | `Image` |
//! | command line | `CommandLine` (empty unless command-line auditing is on) | `CommandLine` |
//! | process id | `NewProcessId` (hex, `0x1f4`) | `ProcessId` (decimal) |
//! | parent id | `ProcessId` (hex) | `ParentProcessId` (decimal) |
//! | parent image | `ParentProcessName` (Windows 10 / 2016 and later only) | `ParentImage` (`?` when unknown) |
//! | parent command line | — | `ParentCommandLine` |
//! | account | `TargetUserName` when set, else `SubjectUserName` | `User` (`DOMAIN\user`) |
//! | PE name / hashes | — | `OriginalFileName`, `Hashes` |
//!
//! One execution recorded twice is reported once: a live process drops its own 4688 /
//! Sysmon 1 copy, and a 4688 drops when a Sysmon 1 for the same process (same image
//! and command line, within [`SAME_START_SECS`]) exists. When a 4688 has no
//! `ParentProcessName` (Windows 7 / 2008 R2), its parent is found by process id among
//! the other starts of this run.

use cairn_core::finding::{EntityProcess, Finding};
use cairn_core::record::{EventRecord, Record};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

/// The Sysmon operational channel.
pub(crate) const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
const SYSMON_ARTIFACT: &str = "evtx:Microsoft-Windows-Sysmon/Operational";

/// A 4688 and a Sysmon 1 for the same process are written within this many seconds
/// of each other (both are logged as the process starts).
pub(crate) const SAME_START_SECS: i64 = 2;

/// A string field of an event's flattened data (numbers as their decimal text).
pub(crate) fn event_str(data: &Map<String, Value>, key: &str) -> Option<String> {
    match data.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Like [`event_str`], but also looks one object level down: `UserData` payloads
/// (`EventXML`, `Operation_ESStoConsumerBinding`, ...) are flattened by the EVTX
/// collector as one nested object, so their fields sit one level below `data`.
pub(crate) fn event_field(data: &Map<String, Value>, key: &str) -> Option<String> {
    if let Some(v) = event_str(data, key) {
        return Some(v);
    }
    data.values()
        .filter_map(Value::as_object)
        .find_map(|o| event_str(o, key))
}

/// A field that carries a value: not empty, not Windows' `-` placeholder, not Sysmon's
/// `?` for an unknown parent.
fn present(data: &Map<String, Value>, key: &str) -> Option<String> {
    event_str(data, key).filter(|v| {
        let t = v.trim();
        !t.is_empty() && t != "-" && t != "?"
    })
}

/// One process start (a command line, its image and, when known, its parent) and
/// where it was seen.
#[derive(Debug, Clone)]
pub(crate) struct CommandLine<'a> {
    /// The command line; empty when the source did not record one (4688 without
    /// command-line auditing, or a live process whose command line was unreadable).
    pub cmd: String,
    pub image: String,
    pub user: Option<String>,
    /// Process start / event time, when known.
    pub ts: Option<DateTime<Utc>>,
    /// `process`, `evtx:Security` or `evtx:Microsoft-Windows-Sysmon/Operational`.
    pub artifact: &'static str,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub event: Option<&'a EventRecord>,
    /// Parent image path: from the event itself (Sysmon `ParentImage`, 4688
    /// `ParentProcessName`), else from the parent's own start in this run. Live
    /// processes leave it empty (`heur_parentchild` pairs them by pid).
    pub parent_image: Option<String>,
    /// Parent command line (Sysmon `ParentCommandLine`, or the parent's own start).
    pub parent_cmd: Option<String>,
    /// Sysmon `OriginalFileName` (the PE version-info name; survives a rename).
    pub original_file_name: Option<String>,
    /// Sysmon `Hashes` (`SHA1=...,MD5=...,SHA256=...,IMPHASH=...`).
    pub hashes: Option<String>,
}

impl CommandLine<'_> {
    /// Lowercase command line with cmd/PowerShell escape and quote characters removed
    /// ([`crate::trust::deobfuscated`]: `v^s^s^a^d^m^i^n`, ``vss`admin``, `"vssadmin"`)
    /// and runs of whitespace collapsed to one space.
    pub fn normalized(&self) -> String {
        crate::trust::deobfuscated(&self.cmd)
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

    /// Identity of one execution across sources: pid, program name, command line.
    fn key(&self) -> Option<(u32, String, String)> {
        Some((
            self.pid?,
            crate::trust::exe_name(&self.image),
            self.normalized(),
        ))
    }

    fn is_sysmon(&self) -> bool {
        self.event
            .is_some_and(|e| e.channel.eq_ignore_ascii_case(SYSMON_CHANNEL))
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

/// One process start from a Security 4688 or Sysmon 1 event; None for other events
/// and for a start without an image.
fn from_event(ev: &EventRecord) -> Option<CommandLine<'_>> {
    let d = &ev.data;
    let (image, cmd, user, pid, ppid, parent_image, parent_cmd, ofn, hashes, artifact) =
        if ev.channel.eq_ignore_ascii_case("Security") && ev.event_id == 4688 {
            (
                present(d, "NewProcessName")?,
                event_str(d, "CommandLine").unwrap_or_default(),
                present(d, "TargetUserName").or_else(|| present(d, "SubjectUserName")),
                event_pid(d, "NewProcessId"),
                event_pid(d, "ProcessId"),
                present(d, "ParentProcessName"),
                None,
                None,
                None,
                "evtx:Security",
            )
        } else if ev.channel.eq_ignore_ascii_case(SYSMON_CHANNEL) && ev.event_id == 1 {
            (
                present(d, "Image")?,
                event_str(d, "CommandLine").unwrap_or_default(),
                present(d, "User"),
                event_pid(d, "ProcessId"),
                event_pid(d, "ParentProcessId"),
                present(d, "ParentImage"),
                present(d, "ParentCommandLine"),
                present(d, "OriginalFileName"),
                present(d, "Hashes"),
                SYSMON_ARTIFACT,
            )
        } else {
            return None;
        };
    Some(CommandLine {
        cmd,
        image,
        user,
        ts: Some(ev.ts),
        artifact,
        pid,
        ppid,
        event: Some(ev),
        parent_image,
        parent_cmd,
        original_file_name: ofn,
        hashes,
    })
}

/// Every process start in `records`: live processes, then 4688 / Sysmon 1 events in
/// record order, one entry per execution (see the module doc for the de-duplication
/// and the parent lookup). Starts without a command line are included.
pub(crate) fn process_starts(records: &[Record]) -> Vec<CommandLine<'_>> {
    let mut out = Vec::new();
    for r in records {
        match r {
            Record::Process(p) => out.push(CommandLine {
                cmd: p.cmdline.clone(),
                image: p.image.clone(),
                user: p.user.clone(),
                ts: p.start_time,
                artifact: "process",
                pid: Some(p.pid),
                ppid: Some(p.ppid),
                event: None,
                parent_image: None,
                parent_cmd: None,
                original_file_name: None,
                hashes: None,
            }),
            Record::Event(ev) => out.extend(from_event(ev)),
            _ => {}
        }
    }
    dedup(&mut out);
    resolve_parents(&mut out);
    out
}

/// Drop the second copy of one execution (module doc).
fn dedup(out: &mut Vec<CommandLine<'_>>) {
    // A process that is still running also has its creation event: keep the live
    // record and drop the event copy, so one execution is not reported twice.
    let live: BTreeSet<(u32, String, String)> = out
        .iter()
        .filter(|c| c.event.is_none())
        .filter_map(CommandLine::key)
        .collect();
    out.retain(|c| c.event.is_none() || c.key().is_none_or(|k| !live.contains(&k)));

    // A 4688 next to the Sysmon 1 of the same start: keep Sysmon (parent command line,
    // hashes), taking the 4688's parent image if Sysmon had none.
    let sysmon: Vec<usize> = (0..out.len()).filter(|&i| out[i].is_sysmon()).collect();
    if sysmon.is_empty() {
        return;
    }
    let mut drop = vec![false; out.len()];
    let mut inherit: Vec<(usize, String)> = Vec::new();
    for (i, c) in out.iter().enumerate() {
        if c.event.is_none() || c.is_sysmon() {
            continue;
        }
        let twin = sysmon.iter().copied().find(|&s| same_start(&out[s], c));
        if let Some(s) = twin {
            drop[i] = true;
            if out[s].parent_image.is_none() {
                if let Some(p) = &c.parent_image {
                    inherit.push((s, p.clone()));
                }
            }
        }
    }
    for (s, p) in inherit {
        out[s].parent_image = Some(p);
    }
    let mut i = 0;
    out.retain(|_| {
        let keep = !drop[i];
        i += 1;
        keep
    });
}

/// A Sysmon 1 and a 4688 describe the same start: same program and command line,
/// same pid when both are known, logged within [`SAME_START_SECS`].
fn same_start(sysmon: &CommandLine<'_>, sec: &CommandLine<'_>) -> bool {
    let (Some(a), Some(b)) = (sysmon.ts, sec.ts) else {
        return false;
    };
    if (a - b).num_seconds().abs() > SAME_START_SECS {
        return false;
    }
    if let (Some(x), Some(y)) = (sysmon.pid, sec.pid) {
        if x != y {
            return false;
        }
    }
    crate::trust::exe_name(&sysmon.image) == crate::trust::exe_name(&sec.image)
        && sysmon.normalized() == sec.normalized()
}

/// Fill the parent image / command line of an event start that lacks them from the
/// most recent start of its parent pid at or before it (Windows reuses pids, so a
/// start after the child is never its parent).
fn resolve_parents(out: &mut [CommandLine<'_>]) {
    let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, c) in out.iter().enumerate() {
        if let Some(pid) = c.pid {
            by_pid.entry(pid).or_default().push(i);
        }
    }
    let mut fills: Vec<(usize, String, Option<String>)> = Vec::new();
    for (i, c) in out.iter().enumerate() {
        if c.event.is_none() || (c.parent_image.is_some() && c.parent_cmd.is_some()) {
            continue;
        }
        let Some(ppid) = c.ppid else { continue };
        let parent = by_pid.get(&ppid).and_then(|cands| {
            cands
                .iter()
                .copied()
                .filter(|&j| j != i)
                .filter(|&j| match (out[j].ts, c.ts) {
                    (Some(pt), Some(ct)) => pt <= ct,
                    _ => true,
                })
                .max_by_key(|&j| out[j].ts)
        });
        let Some(j) = parent else { continue };
        let p = &out[j];
        // A parent image from the event itself wins; only fill what is missing, and
        // only from a start of the same program when the event already names it.
        if let Some(named) = &c.parent_image {
            if crate::trust::exe_name(named) != crate::trust::exe_name(&p.image) {
                continue;
            }
        }
        let cmd = (!p.cmd.trim().is_empty()).then(|| p.cmd.clone());
        fills.push((i, p.image.clone(), cmd));
    }
    for (i, image, cmd) in fills {
        let c = &mut out[i];
        if c.parent_image.is_none() {
            c.parent_image = Some(image);
        }
        if c.parent_cmd.is_none() {
            c.parent_cmd = cmd;
        }
    }
}

/// Every process start with a non-empty command line ([`process_starts`]).
pub(crate) fn command_lines(records: &[Record]) -> Vec<CommandLine<'_>> {
    let mut out = process_starts(records);
    out.retain(|c| !c.cmd.trim().is_empty());
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

    fn ev4688(pid: &str, cmd: &str) -> Record {
        let Value::Object(data) = json!({
            "CommandLine": cmd,
            "NewProcessName": r"C:\Windows\System32\cmd.exe",
            "NewProcessId": pid,
        }) else {
            unreachable!()
        };
        Record::Event(EventRecord {
            ts: Utc::now(),
            channel: "Security".into(),
            event_id: 4688,
            provider: String::new(),
            computer: String::new(),
            record_id: 9,
            data,
        })
    }

    fn live(pid: u32, cmd: &str) -> Record {
        Record::Process(ProcessRecord {
            pid,
            ppid: 4,
            image: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: cmd.into(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        })
    }

    #[test]
    fn normalized_removes_caret_and_quote_obfuscation() {
        let records = [live(1, r#"c^m^d /c "v^ssad""min" delete  shadows /all"#)];
        let cl = command_lines(&records);
        assert_eq!(cl[0].normalized(), "cmd /c vssadmin delete shadows /all");
    }

    #[test]
    fn a_running_process_and_its_4688_event_are_one_command_line() {
        // The event comes first in record order; the live copy is still the one kept.
        let records = [
            ev4688("0x1f4", "cmd.exe /c whoami"),
            live(500, "cmd.exe  /c whoami"),
            // Same pid, different command (pid reused): both kept.
            ev4688("0x1f4", "cmd.exe /c ipconfig"),
            // Same command, different pid: both kept.
            ev4688("0x1f5", "cmd.exe /c whoami"),
        ];
        let cl = command_lines(&records);
        assert_eq!(cl.len(), 3, "{cl:?}");
        assert!(cl.iter().any(|c| c.event.is_none() && c.pid == Some(500)));
        assert!(!cl
            .iter()
            .any(|c| c.event.is_some() && c.pid == Some(500) && c.cmd.contains("whoami")));
    }

    fn event(channel: &str, id: u32, record_id: u64, ts: &str, v: Value) -> Record {
        let Value::Object(data) = v else {
            unreachable!()
        };
        Record::Event(EventRecord {
            ts: ts.parse().unwrap(),
            channel: channel.into(),
            event_id: id,
            provider: String::new(),
            computer: String::new(),
            record_id,
            data,
        })
    }

    /// A real Sysmon 1 (EVTX-ATTACK-SAMPLES `LM_wmiexec_impacket_sysmon_whoami.evtx`).
    fn sysmon_wmiexec(ts: &str) -> Record {
        event(
            SYSMON_CHANNEL,
            1,
            20,
            ts,
            json!({
                "ProcessId": "2828",
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r"cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1",
                "User": r"IEWIN7\IEUser",
                "ParentProcessId": "836",
                "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                "ParentCommandLine": r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
                "OriginalFileName": "Cmd.Exe",
                "Hashes": "SHA1=0123,MD5=4567",
            }),
        )
    }

    #[test]
    fn sysmon_1_yields_image_parent_user_and_hashes() {
        let records = [sysmon_wmiexec("2019-04-30T20:26:51Z")];
        let cl = command_lines(&records);
        assert_eq!(cl.len(), 1);
        let c = &cl[0];
        assert_eq!(c.artifact, "evtx:Microsoft-Windows-Sysmon/Operational");
        assert_eq!((c.pid, c.ppid), (Some(2828), Some(836)));
        assert_eq!(c.user.as_deref(), Some(r"IEWIN7\IEUser"));
        assert!(c.parent_image.as_deref().unwrap().ends_with("WmiPrvSE.exe"));
        assert!(c.parent_cmd.as_deref().unwrap().contains("-Embedding"));
        assert_eq!(c.original_file_name.as_deref(), Some("Cmd.Exe"));
        assert!(c.hashes.as_deref().unwrap().starts_with("SHA1="));
        assert_eq!(program(c), "cmd");
    }

    fn sec4688(record_id: u64, ts: &str, pid: &str, ppid: &str, image: &str, cmd: &str) -> Record {
        event(
            "Security",
            4688,
            record_id,
            ts,
            json!({
                "SubjectUserName": "WIN-77LTAPHIQ1R$",
                "TargetUserName": "-",
                "NewProcessId": pid,
                "NewProcessName": image,
                "ProcessId": ppid,
                "CommandLine": cmd,
            }),
        )
    }

    #[test]
    fn a_4688_and_the_sysmon_1_of_the_same_start_are_one() {
        let cmd = r"cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1";
        let records = [
            sec4688(
                1,
                "2019-04-30T20:26:52Z",
                "0xb0c",
                "0x344",
                r"C:\Windows\System32\cmd.exe",
                cmd,
            ),
            sysmon_wmiexec("2019-04-30T20:26:51Z"),
            // The same command run again a minute later is a second execution.
            sec4688(
                2,
                "2019-04-30T20:27:52Z",
                "0xb10",
                "0x344",
                r"C:\Windows\System32\cmd.exe",
                cmd,
            ),
        ];
        let cl = command_lines(&records);
        assert_eq!(cl.len(), 2, "{cl:?}");
        assert!(cl[0].artifact.contains("Sysmon"));
        assert_eq!(cl[1].event.unwrap().record_id, 2);
        // A different pid (0xb0d) for the same second is a different process.
        let records = [
            sec4688(
                1,
                "2019-04-30T20:26:51Z",
                "0xb0d",
                "0x344",
                r"C:\Windows\System32\cmd.exe",
                cmd,
            ),
            sysmon_wmiexec("2019-04-30T20:26:51Z"),
        ];
        assert_eq!(command_lines(&records).len(), 2);
    }

    /// Windows 7 4688 has no ParentProcessName and, without command-line auditing, an
    /// empty CommandLine (real `LM_WMI_4624_4688_TargetHost.evtx`): the parent comes
    /// from the WmiPrvSE start whose NewProcessId is the child's creator ProcessId.
    #[test]
    fn a_4688_without_parent_name_finds_its_parent_by_pid() {
        let records = [
            sec4688(
                1,
                "2019-03-19T23:40:10Z",
                "0xae8",
                "0x248",
                r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                "",
            ),
            sec4688(
                2,
                "2019-03-19T23:40:12Z",
                "0x424",
                "0xae8",
                r"C:\Windows\System32\calc.exe",
                "",
            ),
            // pid 0xae8 reused after the child started: not its parent.
            sec4688(
                3,
                "2019-03-19T23:50:00Z",
                "0xae8",
                "0x248",
                r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                "",
            ),
        ];
        let starts = process_starts(&records);
        assert_eq!(starts.len(), 3);
        let calc = starts
            .iter()
            .find(|c| c.image.ends_with("calc.exe"))
            .unwrap();
        assert!(calc
            .parent_image
            .as_deref()
            .unwrap()
            .ends_with("WmiPrvSE.exe"));
        assert_eq!(calc.user.as_deref(), Some("WIN-77LTAPHIQ1R$"));
        // Empty command lines are process starts, not command lines.
        assert!(command_lines(&records).is_empty());
    }

    #[test]
    fn sysmon_unknown_parent_is_none() {
        let records = [event(
            SYSMON_CHANNEL,
            1,
            1,
            "2019-04-30T20:26:51Z",
            json!({
                "ProcessId": "6020",
                "Image": r"C:\Windows\explorer.exe",
                "CommandLine": r"C:\Windows\explorer.exe /factory,{75dff2b7} -Embedding",
                "ParentProcessId": "752",
                "ParentImage": "?",
                "ParentCommandLine": "?",
            }),
        )];
        let starts = process_starts(&records);
        assert!(starts[0].parent_image.is_none());
        assert!(starts[0].parent_cmd.is_none());
    }
}
