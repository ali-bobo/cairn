//! `cairn coverage`: which ATT&CK techniques this build can detect — the built-in
//! heuristics plus the loaded Sigma rules' technique tags — so a clean result is read
//! with its blind spots in mind.
use cairn_sigma::{engine::Engine, SigmaMatcher};
use std::fmt::Write as _;
use std::path::PathBuf;

/// Coverage text: one line per built-in technique (with the Sigma rule count when
/// rules are loaded), then the techniques only Sigma covers. Pure for testing.
pub fn coverage_report(sigma: Option<&std::collections::BTreeMap<String, usize>>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Built-in detections (heuristics over live state and EVTX):"
    );
    let _ = writeln!(
        out,
        "{:<11} {:<5} {:<40} WHAT IS CHECKED",
        "TECHNIQUE", "SIGMA", "NAME"
    );
    for c in cairn_heur::coverage::BUILTIN {
        let n = sigma
            .and_then(|m| m.get(c.technique))
            .map_or("-".to_string(), |n| n.to_string());
        let _ = writeln!(
            out,
            "{:<11} {:<5} {:<40} {}",
            c.technique, n, c.name, c.what
        );
    }
    match sigma {
        Some(map) => {
            let extra: Vec<_> = map
                .iter()
                .filter(|(t, _)| {
                    !cairn_heur::coverage::BUILTIN
                        .iter()
                        .any(|c| c.technique == *t)
                })
                .collect();
            let _ = writeln!(
                out,
                "\nSigma-only techniques (need the matching event log enabled):"
            );
            for (t, n) in extra {
                let _ = writeln!(out, "{t:<11} {n} rule(s)");
            }
        }
        None => {
            let _ = writeln!(out, "\nNo Sigma rules loaded; Sigma coverage not shown.");
        }
    }
    let _ = writeln!(
        out,
        "\nVerify a technique on a lab VM with Atomic Red Team, e.g.\n  Invoke-AtomicTest T1547.001 -ShowDetailsBrief\n\
         then run cairn and confirm a finding tagged with that technique (docs/COVERAGE.md)."
    );
    out
}

/// Print the coverage report for `rules` (default: the bundled rules).
pub fn run(rules: Option<PathBuf>) {
    let sigma = match rules.or_else(crate::output::default_rules_dir) {
        Some(dir) => {
            let mut engine = Engine::default();
            match engine.load(&dir) {
                Ok(_) => Some(engine.technique_counts()),
                Err(e) => {
                    tracing::warn!(error = %e, dir = %dir.display(), "rule load failed");
                    None
                }
            }
        }
        None => None,
    };
    print!("{}", coverage_report(sigma.as_ref()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_report_lists_builtin_and_sigma_only_techniques() {
        let mut sigma = std::collections::BTreeMap::new();
        sigma.insert("T1547.001".to_string(), 3);
        sigma.insert("T1112".to_string(), 2);
        let text = coverage_report(Some(&sigma));
        let run_line = text.lines().find(|l| l.starts_with("T1547.001")).unwrap();
        assert!(run_line.contains(" 3 "), "{run_line}");
        assert!(text.contains("T1112       2 rule(s)"), "{text}");
        assert!(coverage_report(None).contains("No Sigma rules loaded"));
    }
}
