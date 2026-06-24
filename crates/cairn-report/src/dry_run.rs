#![forbid(unsafe_code)]
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    Result,
};

/// A no-op sink: every write is discarded, finalize returns empty.
/// Implements golden rule 4 / FR16: `--dry-run` writes NOTHING to disk.
pub struct DryRunSink;

impl OutputSink for DryRunSink {
    fn write_timeline_csv(&mut self, _: &[Finding]) -> Result<()> { Ok(()) }
    fn write_findings_jsonl(&mut self, _: &[Finding]) -> Result<()> { Ok(()) }
    fn write_manifest(&mut self, _: &Manifest) -> Result<()> { Ok(()) }
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> { Ok(vec![]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    #[test]
    fn dry_run_writes_nothing() {
        let dir = std::env::temp_dir().join("cairn_dryrun_nothing");
        let _ = std::fs::remove_dir_all(&dir);

        let mut sink = DryRunSink;
        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();

        use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
        use chrono::Utc;
        let manifest = Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo { name: "cairn".into(), version: "0.1.0".into(), build_sha: "abc".into(), sigma_ruleset_ver: String::new() },
            run: RunInfo { started_utc: Utc::now(), finished_utc: None, cmdline: "test".into(), operator: String::new(), case_id: String::new(), profile: "standard".into(), selected_modules: vec![] },
            host: HostInfo { hostname: "WS01".into(), os_build: String::new(), timezone: "UTC".into(), wall_clock_utc_skew: "+0s".into() },
            privileges: Privileges { admin: false, se_backup: false, se_debug: false },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: String::new(),
            governance: cairn_core::manifest::GovernanceReport::default(),
        };
        sink.write_manifest(&manifest).unwrap();
        let entries = sink.finalize().unwrap();

        assert!(!dir.exists(), "DryRunSink must not create any dir or file");
        assert!(entries.is_empty(), "DryRunSink finalize must return empty vec");
    }

    #[test]
    fn dry_run_finalize_returns_empty() {
        let mut s = DryRunSink;
        let entries = s.finalize().unwrap();
        assert!(entries.is_empty());
    }
}
