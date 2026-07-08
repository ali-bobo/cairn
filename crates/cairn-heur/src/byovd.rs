#![forbid(unsafe_code)]

use std::collections::HashSet;

/// The default known-vulnerable/malicious driver SHA1 list, embedded at compile time.
/// Pure data (a text list), not hardcoded logic — see spec §4.3.
pub const BUNDLED_DRIVER_LIST: &str = include_str!("known-vulnerable-drivers.txt");

/// Parse a driver-hash list into a set of lowercase 40-hex SHA1 strings.
/// Tolerates blank lines, `#` comment lines, and inline `# ...` annotations.
/// A malformed line (not exactly 40 ASCII hex chars after normalization) is skipped,
/// never fatal — one bad line must not discard the whole list (golden rule 8).
pub fn parse_driver_hashes(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in text.lines() {
        // Strip an inline comment: keep everything before the first '#'.
        let body = line
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if body.is_empty() {
            continue;
        }
        if body.len() == 40 && body.chars().all(|c| c.is_ascii_hexdigit()) {
            set.insert(body);
        }
        // else: skip silently — malformed entry, not fatal.
    }
    set
}

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::Record;
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::Utc;

/// Analyzer: flags any loaded driver whose SHA1 matches the known-vulnerable/malicious
/// list. Carries the hash set as state (injected at construction — the CLI parses the
/// bundled or --driver-list file once and hands it in).
pub struct ByovdHeuristic {
    hashes: HashSet<String>,
}

impl ByovdHeuristic {
    pub fn new(hashes: HashSet<String>) -> Self {
        ByovdHeuristic { hashes }
    }
}

impl Analyzer for ByovdHeuristic {
    fn name(&self) -> &str {
        "heur_byovd"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut findings = Vec::new();
        for r in records {
            let Record::Execution(e) = r else { continue };
            if e.source != "amcache_driver" {
                continue;
            }
            // Only compare when the collector produced a real SHA1 (None = malformed
            // DriverId, honestly skipped per NFR12 — never a false match).
            let Some(sha1) = e.sha1.as_deref() else {
                continue;
            };
            if !self.hashes.contains(sha1) {
                continue;
            }
            let basename = e
                .path
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(e.path.as_str());
            let mut f = Finding::new(
                Severity::High,
                format!("已知漏洞/惡意驅動: {basename}"),
                FindingSource::Heuristic,
            );
            f.artifact = "byovd".into();
            f.mitre = vec!["T1068".into(), "T1211".into()];
            f.reason = Some(format!(
                "driver SHA1 {sha1} matches the known-vulnerable/malicious driver list (BYOVD)"
            ));
            f.ts = e.last_run.or(e.first_run).unwrap_or(now);
            f.evidence = vec![EvidenceItem {
                artifact: "amcache_driver".into(),
                path: Some(e.path.clone()),
                ts: e.last_run.or(e.first_run),
                detail: format!("SHA1={sha1}"),
            }];
            findings.push(f);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parses_valid_lowercases_and_dedups() {
        let text = "\
# header comment
AABBCCDDEEFF00112233445566778899AABBCCDD  # RTCore64.sys
aabbccddeeff00112233445566778899aabbccdd  # duplicate (diff case) -> deduped

  0011223344556677889900112233445566778899  # indented, valid
";
        let set = parse_driver_hashes(text);
        assert_eq!(set.len(), 2, "dup collapses, 2 distinct hashes");
        assert!(set.contains("aabbccddeeff00112233445566778899aabbccdd"));
        assert!(set.contains("0011223344556677889900112233445566778899"));
    }

    #[test]
    fn skips_malformed_lines_without_dropping_good_ones() {
        let text = "\
zzzz  # not hex
0123  # too short
0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5  # 64-hex SHA256, wrong length
0011223344556677889900112233445566778899  # the one good line
this line has spaces in the middle 00112233
";
        let set = parse_driver_hashes(text);
        assert_eq!(set.len(), 1);
        assert!(set.contains("0011223344556677889900112233445566778899"));
    }

    #[test]
    fn empty_and_comment_only_yields_empty_set() {
        assert!(parse_driver_hashes("").is_empty());
        assert!(parse_driver_hashes("# just a comment\n\n   \n").is_empty());
    }

    #[test]
    fn bundled_list_parses_and_is_nonempty() {
        // The shipped list must contain at least one valid SHA1 (else the whole
        // feature is a no-op). Guards against an accidentally-empty/all-malformed file.
        let set = parse_driver_hashes(BUNDLED_DRIVER_LIST);
        assert!(
            !set.is_empty(),
            "bundled driver list must have >=1 valid SHA1"
        );
    }
}

#[cfg(test)]
mod analyze_tests {
    use super::*;
    use cairn_core::record::ExecutionRecord;

    fn driver_exec(source: &str, path: &str, sha1: Option<&str>) -> Record {
        Record::Execution(ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: sha1.map(String::from),
            user_sid: None,
            execution_confirmed: Some(true),
        })
    }

    fn heur_with(hashes: &[&str]) -> ByovdHeuristic {
        ByovdHeuristic::new(hashes.iter().map(|h| h.to_string()).collect())
    }

    const KNOWN: &str = "aabbccddeeff00112233445566778899aabbccdd";

    #[test]
    fn known_driver_hash_is_high_with_mitre_and_evidence() {
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec(
            "amcache_driver",
            r"C:\Windows\System32\drivers\rtcore64.sys",
            Some(KNOWN),
        )];
        let findings = heur.analyze(&recs).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].artifact, "byovd");
        assert!(findings[0].mitre.contains(&"T1068".to_string()));
        assert!(findings[0].title.contains("rtcore64.sys"));
        assert!(findings[0].reason.as_deref().unwrap().contains(KNOWN));
        assert_eq!(findings[0].evidence[0].artifact, "amcache_driver");
        assert!(findings[0].evidence[0].detail.contains(KNOWN));
    }

    #[test]
    fn unknown_hash_yields_nothing() {
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec(
            "amcache_driver",
            r"C:\x\clean.sys",
            Some("0000000000000000000000000000000000000000"),
        )];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }

    #[test]
    fn none_sha1_is_skipped_not_matched() {
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec("amcache_driver", r"C:\x\d.sys", None)];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }

    #[test]
    fn non_amcache_driver_source_ignored() {
        // Same hash, but from a non-driver execution source -> not our concern.
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec("prefetch", r"C:\x\app.exe", Some(KNOWN))];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }

    #[test]
    fn empty_list_never_matches() {
        let heur = heur_with(&[]);
        let recs = vec![driver_exec("amcache_driver", r"C:\x\d.sys", Some(KNOWN))];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }
}
