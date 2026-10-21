//! [`Sink`]: the one output sink a run writes through, chosen from `OutputKind`.
//!
//! Wraps the three concrete sinks so a run can use the operations that go beyond the
//! `OutputSink` trait — records.jsonl, evidence files written by an external API, and a
//! non-consuming view of the hashes so far — the same way for a directory and a zip.
//! `--dry-run` (golden rule 4) makes every one of them a no-op.
#![forbid(unsafe_code)]
use crate::{output_path, DirSink, DryRunSink, ZipSink};
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    Observation, OutputKind, Record, Result,
};
use std::path::{Path, PathBuf};

pub enum Sink {
    Dir(DirSink),
    Zip(ZipSink),
    DryRun(DryRunSink),
}

impl Sink {
    pub fn new(output: &OutputKind) -> Self {
        match output {
            OutputKind::Dir(p) => Sink::Dir(DirSink::new(p)),
            OutputKind::Zip(p) => Sink::Zip(ZipSink::new(p)),
            OutputKind::DryRun => Sink::DryRun(DryRunSink),
        }
    }

    /// True for `--dry-run`: nothing may be written, so callers skip work whose only
    /// purpose is producing a file (e.g. EVTX export).
    pub fn is_dry_run(&self) -> bool {
        matches!(self, Sink::DryRun(_))
    }

    /// Write records.jsonl (included in both dir and zip output; report.html links it).
    pub fn write_records_jsonl(&mut self, records: &[Record]) -> Result<()> {
        match self {
            Sink::Dir(s) => s.write_records_jsonl(records),
            Sink::Zip(s) => s.write_records_jsonl(records),
            Sink::DryRun(_) => Ok(()),
        }
    }

    /// Where an external writer (the EVTX export API) must put the evidence file named
    /// `name` (`/`-separated, e.g. `evidence/evtx/Security.evtx`) before
    /// [`Sink::add_evidence_file`] records it. Dir: its final place in the output dir.
    /// Zip: the same layout under the `<zip>.staging` dir beside the archive (removed
    /// after archiving). Dry-run: None — nothing may be written. Always inside the
    /// operator-chosen output location, never on a source path (golden rule 4).
    pub fn evidence_path(&self, name: &str) -> Option<PathBuf> {
        match self {
            Sink::Dir(s) => Some(output_path(s.dir(), name)),
            Sink::Zip(s) => Some(output_path(&s.staging_dir(), name)),
            Sink::DryRun(_) => None,
        }
    }

    /// Record the evidence file that was written at `evidence_path(name)`: hash it into
    /// the outputs (dir), or queue it as archive member `name` (zip).
    pub fn add_evidence_file(&mut self, name: &str, written_at: &Path) -> Result<()> {
        match self {
            Sink::Dir(s) => s.register_existing(name),
            Sink::Zip(s) => s.add_file(name, written_at),
            Sink::DryRun(_) => Ok(()),
        }
    }

    /// Output entries recorded so far (for the manifest's `outputs`), not consumed.
    pub fn outputs_so_far(&self) -> Vec<OutputEntry> {
        match self {
            Sink::Dir(s) => s.outputs_so_far(),
            Sink::Zip(s) => s.outputs_so_far(),
            Sink::DryRun(_) => vec![],
        }
    }

    fn inner(&mut self) -> &mut dyn OutputSink {
        match self {
            Sink::Dir(s) => s,
            Sink::Zip(s) => s,
            Sink::DryRun(s) => s,
        }
    }
}

impl OutputSink for Sink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        self.inner().write_timeline_csv(findings)
    }
    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> {
        self.inner().write_findings_jsonl(findings)
    }
    fn write_observations(&mut self, observations: &[Observation]) -> Result<()> {
        self.inner().write_observations(observations)
    }
    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> {
        self.inner().write_manifest(manifest)
    }
    fn write_html_report(
        &mut self,
        findings: &[Finding],
        observations: &[Observation],
        records: &[Record],
        manifest: &Manifest,
    ) -> Result<()> {
        self.inner()
            .write_html_report(findings, observations, records, manifest)
    }
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        self.inner().finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// --dry-run: no evidence location, every extra write is a no-op, nothing on disk.
    #[test]
    fn dry_run_sink_offers_no_evidence_path_and_writes_nothing() {
        let mut s = Sink::new(&OutputKind::DryRun);
        assert!(s.is_dry_run());
        assert!(s.evidence_path("evidence/evtx/Security.evtx").is_none());
        s.write_records_jsonl(&[]).unwrap();
        assert!(s.outputs_so_far().is_empty());
        assert!(s.finalize().unwrap().is_empty());
    }

    /// Dir evidence goes to its final place; zip evidence is staged beside the archive.
    #[test]
    fn evidence_paths_stay_in_the_output_location() {
        let d = Sink::new(&OutputKind::Dir(PathBuf::from("out")));
        assert_eq!(
            d.evidence_path("evidence/evtx/A.evtx").unwrap(),
            Path::new("out")
                .join("evidence")
                .join("evtx")
                .join("A.evtx")
        );
        let z = Sink::new(&OutputKind::Zip(PathBuf::from("o").join("c.zip")));
        assert_eq!(
            z.evidence_path("evidence/evtx/A.evtx").unwrap(),
            Path::new("o")
                .join("c.zip.staging")
                .join("evidence")
                .join("evtx")
                .join("A.evtx")
        );
    }
}
