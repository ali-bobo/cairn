#![forbid(unsafe_code)]
use crate::{sha256_hex, write_output_safe};
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    Result,
};
use std::{io::Write, path::PathBuf};

pub struct ZipSink {
    path: PathBuf,
    files: Vec<(String, Vec<u8>)>,
}

impl ZipSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ZipSink { path: path.into(), files: Vec::new() }
    }


}

pub(crate) fn build_zip(files: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>> {
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
    let mut buf = Vec::new();
    let cursor = std::io::Cursor::new(&mut buf);
    let mut zip = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, bytes) in files {
        zip.start_file(&name, opts)
            .map_err(|e| cairn_core::CairnError::Other(e.to_string()))?;
        zip.write_all(&bytes)
            .map_err(|e| cairn_core::CairnError::Other(e.to_string()))?;
    }
    zip.finish().map_err(|e| cairn_core::CairnError::Other(e.to_string()))?;
    Ok(buf)
}

impl OutputSink for ZipSink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        let bytes = crate::timeline_csv(findings).into_bytes();
        self.files.push(("timeline.csv".into(), bytes));
        Ok(())
    }

    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> {
        let mut buf = String::new();
        for f in findings {
            buf.push_str(&serde_json::to_string(f)?);
            buf.push('\n');
        }
        self.files.push(("findings.jsonl".into(), buf.into_bytes()));
        Ok(())
    }

    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec_pretty(manifest)?;
        self.files.push(("manifest.json".into(), json));
        Ok(())
    }

    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        let files = std::mem::take(&mut self.files);
        let zip_bytes = build_zip(files)?;
        write_output_safe(&self.path, &zip_bytes)?;
        Ok(vec![OutputEntry {
            file: self.path.display().to_string(),
            sha256: sha256_hex(&zip_bytes),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_zip_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn zip_sink_produces_valid_zip() {
        let dir = mk_dir("valid");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);

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

        let bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(&bytes[..2], b"PK", "must be valid zip");

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "timeline.csv"), "timeline.csv: {names:?}");
        assert!(names.iter().any(|n| n == "findings.jsonl"), "findings.jsonl: {names:?}");
        assert!(names.iter().any(|n| n == "manifest.json"), "manifest.json: {names:?}");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sha256, crate::sha256_hex(&bytes));
    }

    #[test]
    fn zip_sink_hashes_match_disk() {
        let dir = mk_dir("hash");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();
        let disk_bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(entries[0].sha256, crate::sha256_hex(&disk_bytes));
    }

    #[cfg(windows)]
    #[test]
    fn zip_sink_refuses_symlink_output() {
        let dir = mk_dir("symlink");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"do not touch").unwrap();
        let link = dir.join("out.zip");
        if std::os::windows::fs::symlink_file(&victim, &link).is_err() {
            if std::env::var_os("CAIRN_REQUIRE_SYMLINK_TESTS").is_some() {
                panic!("CAIRN_REQUIRE_SYMLINK_TESTS set but symlink creation failed");
            }
            eprintln!("skipping: no symlink privilege");
            return;
        }
        let mut sink = ZipSink::new(&link);
        sink.write_timeline_csv(&[]).unwrap();
        let res = sink.finalize();
        assert!(res.is_err(), "must refuse symlink");
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
    }
}
