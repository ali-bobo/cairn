//! `cairn verify <manifest.json | archive.zip> [--rules <dir>]`: re-hash a run's
//! outputs (and sources) against its manifest, and optionally the ruleset against
//! `tool.sigma_ruleset_ver`. For a `--zip` archive the manifest is read from inside it
//! and the archive is also checked against its `<zip>.sha256` sidecar.
use std::path::{Path, PathBuf};

/// True when `path` is a zip archive (by its `PK` magic), not a manifest.json.
fn is_zip(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && &magic == b"PK"
}

/// Re-hash the outputs (and sources) the manifest lists, and — if a rules dir is given —
/// recompute the ADR-0003 ruleset aggregate and compare it to `tool.sigma_ruleset_ver`.
/// Logs every check and returns `true` only if all pass. A tampered output byte, a
/// manifest that lists no outputs at all, OR a modified rule fails it.
pub fn run_verify(manifest_path: &Path, rules: Option<PathBuf>) -> anyhow::Result<bool> {
    let (manifest, report) = if is_zip(manifest_path) {
        let (m, r) = cairn_report::verify_zip(manifest_path)?;
        match &r.archive {
            None => tracing::warn!(
                "no {}.sha256 sidecar beside the archive; archive hash not checked \
                 (members are still verified against the manifest inside it)",
                manifest_path.display()
            ),
            Some(c) if c.status == cairn_report::CheckStatus::Ok => {
                tracing::info!(file = %c.file, "archive matches its .sha256 sidecar")
            }
            Some(_) => {}
        }
        (m, r)
    } else {
        let manifest = cairn_report::read_manifest(manifest_path)?;
        let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        let report = cairn_report::verify_manifest(&manifest, base_dir);
        (manifest, report)
    };
    if report.no_outputs {
        tracing::error!(
            "manifest lists NO outputs: nothing to verify, so integrity cannot be \
             established (a real run always records its outputs)"
        );
    }
    for c in &report.sources {
        match &c.status {
            cairn_report::CheckStatus::Ok => tracing::info!(file = %c.file, "source unchanged"),
            _ => tracing::warn!(
                file = %c.file,
                "source changed or not reachable here since collection (expected for a \
                 live log, or when verifying off the target); not an output-integrity failure"
            ),
        }
    }
    for c in report
        .outputs
        .iter()
        .chain(report.archive.iter())
        .chain(report.extra.iter())
    {
        match &c.status {
            cairn_report::CheckStatus::Ok => tracing::info!(file = %c.file, "verify ok"),
            cairn_report::CheckStatus::Mismatch { expected, actual } => {
                tracing::error!(file = %c.file, %expected, %actual, "HASH MISMATCH")
            }
            cairn_report::CheckStatus::Missing => {
                tracing::error!(file = %c.file, "MISSING (listed in manifest, not on disk)")
            }
            cairn_report::CheckStatus::Unexpected => {
                tracing::error!(file = %c.file, "UNEXPECTED (present, not listed in manifest)")
            }
        }
    }
    let mut all_ok = report.ok();

    // ADR-0003 ruleset integrity: recompute "<pin>+<aggregate>" over the given rules dir
    // and compare to what the manifest recorded. Only when --rules is supplied; a manifest
    // with no recorded ruleset version (parse-only run) has nothing to check.
    match (rules, manifest.tool.sigma_ruleset_ver.as_str()) {
        (Some(dir), recorded) if !recorded.is_empty() => {
            let computed = cairn_sigma::ruleset::ruleset_version(&dir)?;
            if computed == recorded {
                tracing::info!("ruleset ok ({recorded})");
            } else {
                tracing::error!(%recorded, %computed, "RULESET MISMATCH (ADR-0003)");
                all_ok = false;
            }
        }
        (Some(_), "") => {
            tracing::warn!("manifest has no sigma_ruleset_ver; skipping ruleset check")
        }
        (None, recorded) if !recorded.is_empty() => {
            tracing::warn!("ruleset recorded but no --rules given; skipping ruleset check")
        }
        _ => {}
    }

    if all_ok {
        tracing::info!("VERIFY OK");
    } else {
        tracing::error!(failures = report.failures().len(), "VERIFY FAILED");
    }
    Ok(all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::base_manifest;
    use cairn_core::finding::{Finding, FindingSource, Severity};
    use cairn_core::traits::OutputSink;
    use cairn_core::Config;
    use cairn_report::DirSink;

    /// Write timeline + findings + manifest the way the evtx run does.
    fn write_run(dir: &Path, cfg: &Config, findings: &[Finding]) {
        let mut manifest = base_manifest(cfg, "WS01", 1, findings, 0, chrono::Utc::now());
        let mut sink = DirSink::new(dir.to_path_buf());
        sink.write_timeline_csv(findings).unwrap();
        sink.write_findings_jsonl(findings).unwrap();
        manifest.outputs = sink.outputs_so_far();
        sink.write_manifest(&manifest).unwrap();
        let _ = sink.finalize().unwrap();
    }

    fn sigma_finding() -> Finding {
        let mut f = Finding::new(Severity::High, "t", FindingSource::Sigma);
        f.rule_author = Some("A".into());
        f
    }

    /// verify passes on an untouched run (T9 happy path): all output hashes match.
    #[test]
    fn run_verify_passes_on_clean_run() {
        let dir = std::env::temp_dir().join("cairn_run_verify_clean");
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        write_run(&dir, &cfg, &[sigma_finding()]);
        let ok = run_verify(&dir.join("manifest.json"), None).unwrap();
        assert!(ok, "clean run must verify");
    }

    /// verify fails on a tampered output byte (T9 acceptance).
    #[test]
    fn run_verify_fails_on_tampered_output() {
        let dir = std::env::temp_dir().join("cairn_run_verify_tamper");
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        write_run(&dir, &cfg, &[sigma_finding()]);
        // Flip a byte in findings.jsonl after the manifest recorded its hash.
        let p = dir.join("findings.jsonl");
        let mut c = std::fs::read(&p).unwrap();
        c.push(b' ');
        std::fs::write(&p, &c).unwrap();
        let ok = run_verify(&dir.join("manifest.json"), None).unwrap();
        assert!(!ok, "tampered output must fail verify");
    }

    /// verify fails on a missing output and on an extra (unlisted) file, and passes
    /// again once the extra is gone; run.log beside the manifest is fine.
    #[test]
    fn run_verify_fails_on_missing_and_extra_files() {
        let dir = std::env::temp_dir().join("cairn_run_verify_missing_extra");
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        write_run(&dir, &cfg, &[sigma_finding()]);
        std::fs::write(dir.join("run.log"), b"log").unwrap();
        assert!(run_verify(&dir.join("manifest.json"), None).unwrap());

        std::fs::write(dir.join("extra.csv"), b"planted").unwrap();
        assert!(
            !run_verify(&dir.join("manifest.json"), None).unwrap(),
            "extra file"
        );
        std::fs::remove_file(dir.join("extra.csv")).unwrap();
        assert!(run_verify(&dir.join("manifest.json"), None).unwrap());

        std::fs::remove_file(dir.join("timeline.csv")).unwrap();
        assert!(
            !run_verify(&dir.join("manifest.json"), None).unwrap(),
            "missing file"
        );
    }

    /// verify fails when the ruleset is modified vs the manifest's sigma_ruleset_ver
    /// (ADR-0003 / T9 acceptance: a swapped/edited rule is caught).
    #[test]
    fn run_verify_fails_on_modified_ruleset() {
        let dir = std::env::temp_dir().join("cairn_run_verify_rules");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A run whose manifest pins a ruleset_ver computed over an original rules dir.
        let rules = dir.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("r.yml"), b"title: original\n").unwrap();
        let cfg = Config::for_evtx(vec![], Some(rules.clone()));
        write_run(
            &dir,
            &cfg,
            &[Finding::new(Severity::Low, "t", FindingSource::Sigma)],
        );

        // Now modify a rule and verify against the modified dir: ruleset check must fail.
        std::fs::write(rules.join("r.yml"), b"title: TAMPERED\n").unwrap();
        let ok = run_verify(&dir.join("manifest.json"), Some(rules)).unwrap();
        assert!(!ok, "modified ruleset must fail verify");
    }
}
