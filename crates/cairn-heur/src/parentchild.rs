//! heur_parentchild (FR10, SRS §10): anomalous parent->child, encoded PowerShell,
//! suspicious exec path, unsigned + integrity weighting, built-in LOLBAS-flavored list.
// Task 3: pure scoring only. Task 4 will add the Analyzer impl that consumes these items;
// until then, suppress dead_code for the staging items.
#![allow(dead_code)]
use crate::score::{is_suspicious_path, Score};
use cairn_core::record::ProcessRecord;

// --- Named rule tables (config-loader seam; see spec) -------------------------

/// Parent images whose spawning of a shell is anomalous (Office apps).
pub(crate) const OFFICE_PARENTS: &[&str] =
    &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
/// Script-host parents.
pub(crate) const SCRIPT_PARENTS: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe"];
/// Shell/child images that are suspicious when spawned by the above.
pub(crate) const SHELL_CHILDREN: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
];
/// PowerShell binaries (for the `-e ` disambiguation).
pub(crate) const PS_BINARIES: &[&str] = &["powershell.exe", "pwsh.exe"];
/// Built-in LOLBAS-flavored watchlist (NOT the full external dataset; see spec scope).
pub(crate) const LOLBAS_WATCH: &[&str] = &[
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "cscript.exe",
    "wscript.exe",
];

/// Lowercased file name (last path segment) of an image path.
pub(crate) fn file_name(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

/// True if cmdline shows an encoded-command flag with a base64-looking token.
/// `-e ` only counts when the image is a PowerShell binary (avoids unrelated -e flags).
pub(crate) fn has_encoded_powershell(image_name: &str, cmdline: &str) -> bool {
    let lc = cmdline.to_ascii_lowercase();
    let flag = lc.contains("-enc")
        || lc.contains("-encodedcommand")
        || (lc.contains("-e ") && PS_BINARIES.contains(&image_name));
    flag && has_base64_token(cmdline)
}

/// A run of >= 16 chars from the base64 alphabet.
pub(crate) fn has_base64_token(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            if run >= 16 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Score one process against its (optional) parent. Returns a Score (may be empty).
pub(crate) fn score_process(p: &ProcessRecord, parent: Option<&ProcessRecord>) -> Score {
    let mut s = Score::default();
    let child_name = file_name(&p.image);
    let parent_name = parent.map(|pp| file_name(&pp.image));

    if let Some(pn) = &parent_name {
        if OFFICE_PARENTS.contains(&pn.as_str()) && SHELL_CHILDREN.contains(&child_name.as_str()) {
            s.add(
                50,
                format!("Office app {pn} spawned shell {child_name}"),
                &["T1059"],
            );
        }
        if SCRIPT_PARENTS.contains(&pn.as_str())
            && ["cmd.exe", "powershell.exe", "pwsh.exe"].contains(&child_name.as_str())
        {
            s.add(
                30,
                format!("script host {pn} spawned {child_name}"),
                &["T1059"],
            );
        }
    }
    if has_encoded_powershell(&child_name, &p.cmdline) {
        s.add(40, "encoded PowerShell command", &["T1059.001"]);
    }
    if is_suspicious_path(&p.image) {
        s.add(
            25,
            format!("executes from a suspicious path: {}", p.image),
            &["T1036"],
        );
    }
    if p.signed == Some(false) {
        s.add(20, "binary is unsigned", &[]);
    }
    if p.signed == Some(false) && matches!(p.integrity.as_deref(), Some("high") | Some("system")) {
        s.add(15, "unsigned binary running at high integrity", &["T1068"]);
    }
    if LOLBAS_WATCH.contains(&child_name.as_str()) && lolbas_suspicious(&p.cmdline) {
        s.add(
            30,
            format!("LOLBAS {child_name} with suspicious arguments"),
            &["T1218"],
        );
    }
    s
}

/// Suspicious argument patterns for a watchlisted LOLBAS binary.
pub(crate) fn lolbas_suspicious(cmdline: &str) -> bool {
    let lc = cmdline.to_ascii_lowercase();
    lc.contains("http") || lc.contains("scrobj") || lc.contains("/i:") || has_base64_token(cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, ppid: u32, image: &str, cmdline: &str) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid,
            image: image.into(),
            cmdline: cmdline.into(),
            signed: None,
            integrity: None,
            user: None,
            start_time: None,
        }
    }

    /// Office -> encoded PowerShell scores high+ and tags T1059.001.
    #[test]
    fn office_encoded_powershell_scores_high() {
        let parent = proc(100, 4, r"C:\Program Files\Microsoft Office\winword.exe", "");
        let child = proc(
            200,
            100,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let s = score_process(&child, Some(&parent));
        assert!(s.weight >= 50, "weight {} should be high+", s.weight);
        assert!(s.mitre.contains(&"T1059.001".to_string()));
        assert!(s.reasons.iter().any(|r| r.contains("winword.exe")));
    }

    /// A benign explorer -> notepad (signed, normal path) scores 0.
    #[test]
    fn benign_explorer_notepad_scores_zero() {
        let parent = proc(50, 4, r"C:\Windows\explorer.exe", "");
        let mut child = proc(60, 50, r"C:\Windows\System32\notepad.exe", "notepad.exe");
        child.signed = Some(true);
        let s = score_process(&child, Some(&parent));
        assert_eq!(s.weight, 0);
    }

    /// Unsigned binary from Temp still scores even with NO parent (self-signals only).
    #[test]
    fn unsigned_from_temp_no_parent_scores() {
        let mut p = proc(70, 0, r"C:\Users\a\AppData\Local\Temp\evil.exe", "evil.exe");
        p.signed = Some(false);
        let s = score_process(&p, None);
        // suspicious path (25) + unsigned (20) = 45 -> at least medium, no panic
        assert!(s.weight >= 45);
    }
}
