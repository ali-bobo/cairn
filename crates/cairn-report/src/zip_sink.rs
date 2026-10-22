//! `--zip` output: every output file becomes a member of one archive (FR15).
//!
//! Chain of custody (SRS §12): the `manifest.json` member lists every OTHER member with
//! its SHA-256 + size (a manifest cannot hash itself), and the archive's own SHA-256 is
//! written to a `<zip>.sha256` sidecar next to it (a zip cannot contain its own hash).
//! `verify_zip` checks both.
#![forbid(unsafe_code)]
use crate::{
    check_hash, findings_jsonl, output_entry, records_jsonl, sha256_file, sha256_reader,
    verify_sources, write_output_safe, CheckResult, VerifyReport,
};
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    CairnError, Observation, Result,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// One archive member: bytes built in memory, or a file on disk streamed in at
/// finalize (large evidence such as exported EVTX is never held in memory).
enum Member {
    Bytes(Vec<u8>),
    File(PathBuf),
}

pub struct ZipSink {
    path: PathBuf,
    members: Vec<(String, Member)>,
    outputs: Vec<OutputEntry>,
}

fn zip_err(e: impl std::fmt::Display) -> CairnError {
    CairnError::Other(format!("zip: {e}"))
}

/// `<zip>.sha256` next to the archive.
pub fn sidecar_path(zip_path: &Path) -> PathBuf {
    let mut s = zip_path.as_os_str().to_os_string();
    s.push(".sha256");
    PathBuf::from(s)
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

impl ZipSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ZipSink {
            path: path.into(),
            members: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Scratch directory beside the archive (`<zip>.staging`) for evidence that an
    /// external API must write to a real file (EVTX export) before it is archived. It
    /// lives in the operator-chosen output location, never on a source path, and is
    /// removed by `finalize` once the archive is written.
    pub fn staging_dir(&self) -> PathBuf {
        let mut s = self.path.as_os_str().to_os_string();
        s.push(".staging");
        PathBuf::from(s)
    }

    /// The member entries recorded so far (name + SHA-256 + size), without consuming
    /// them, so the caller can embed them in the manifest before writing it.
    pub fn outputs_so_far(&self) -> Vec<OutputEntry> {
        self.outputs.clone()
    }

    fn add_bytes(&mut self, name: &str, bytes: Vec<u8>) {
        self.outputs.push(output_entry(name, &bytes));
        self.members.push((name.to_string(), Member::Bytes(bytes)));
    }

    /// Add records.jsonl as a member.
    pub fn write_records_jsonl(&mut self, records: &[cairn_core::Record]) -> Result<()> {
        self.add_bytes("records.jsonl", records_jsonl(records)?.into_bytes());
        Ok(())
    }

    /// Add the file at `src` as member `name`. It is hashed now (streaming) and copied
    /// into the archive at finalize.
    pub fn add_file(&mut self, name: &str, src: &Path) -> Result<()> {
        let (sha256, size) = sha256_file(src)?;
        self.outputs.push(OutputEntry {
            file: name.to_string(),
            sha256,
            size,
        });
        self.members
            .push((name.to_string(), Member::File(src.to_path_buf())));
        Ok(())
    }
}

fn write_zip(out: std::fs::File, members: Vec<(String, Member)>) -> Result<()> {
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
    let mut zip = ZipWriter::new(out);
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);
    for (name, member) in members {
        zip.start_file(&name, opts).map_err(zip_err)?;
        match member {
            Member::Bytes(b) => zip.write_all(&b)?,
            Member::File(p) => {
                std::io::copy(&mut std::fs::File::open(&p)?, &mut zip)?;
            }
        }
    }
    zip.finish().map_err(zip_err)?;
    Ok(())
}

impl OutputSink for ZipSink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        self.add_bytes("timeline.csv", crate::timeline_csv(findings).into_bytes());
        Ok(())
    }

    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> {
        self.add_bytes("findings.jsonl", findings_jsonl(findings)?.into_bytes());
        Ok(())
    }

    fn write_observations(&mut self, observations: &[Observation]) -> Result<()> {
        let buf = crate::observations_jsonl(observations)?;
        self.add_bytes("observations.jsonl", buf.into_bytes());
        Ok(())
    }

    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> {
        self.add_bytes("manifest.json", serde_json::to_vec_pretty(manifest)?);
        Ok(())
    }

    fn write_html_report(
        &mut self,
        findings: &[Finding],
        observations: &[Observation],
        records: &[cairn_core::Record],
        manifest: &Manifest,
    ) -> Result<()> {
        let html = crate::html::html_report(findings, observations, records, manifest);
        self.add_bytes("report.html", html.into_bytes());
        Ok(())
    }

    /// Write the archive (refusing a symlinked path, threat-model #3), hash it, write
    /// the `<zip>.sha256` sidecar, and remove the staging dir. Returns the member
    /// entries plus one entry for the archive itself.
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        // Reuse the symlink guard + parent creation, then stream the real archive over
        // the placeholder.
        write_output_safe(&self.path, b"")?;
        write_zip(
            std::fs::File::create(&self.path)?,
            std::mem::take(&mut self.members),
        )?;
        let (sha256, size) = sha256_file(&self.path)?;
        let zip_name = file_name(&self.path);
        write_output_safe(
            &sidecar_path(&self.path),
            format!("{sha256}  {zip_name}\n").as_bytes(),
        )?;
        let staging = self.staging_dir();
        if staging.is_dir() {
            if let Err(e) = std::fs::remove_dir_all(&staging) {
                tracing_free_warn(&staging, &e);
            }
        }
        let mut out = std::mem::take(&mut self.outputs);
        out.push(OutputEntry {
            file: zip_name,
            sha256,
            size,
        });
        Ok(out)
    }
}

/// The report crate carries no logger; a leftover staging dir is harmless (it is in
/// the operator's output location), so it is reported on stderr and the run goes on.
fn tracing_free_warn(path: &Path, e: &std::io::Error) {
    eprintln!(
        "warning: could not remove staging dir {}: {e}",
        path.display()
    );
}

/// Verify a `--zip` archive: read `manifest.json` from inside it, re-hash every member
/// it lists (and the file-backed sources), and check the archive against its
/// `<zip>.sha256` sidecar when one is present. Returns the manifest too, so the caller
/// can run the ruleset check.
pub fn verify_zip(zip_path: &Path) -> Result<(Manifest, VerifyReport)> {
    let mut ar = zip::ZipArchive::new(std::fs::File::open(zip_path)?).map_err(zip_err)?;
    let manifest: Manifest = {
        let mut text = String::new();
        ar.by_name("manifest.json")
            .map_err(zip_err)?
            .read_to_string(&mut text)?;
        serde_json::from_str(&text)?
    };
    let mut outputs = Vec::with_capacity(manifest.outputs.len());
    for o in &manifest.outputs {
        let actual = match ar.by_name(&o.file) {
            Ok(mut member) => sha256_reader(&mut member),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        };
        outputs.push(check_hash(&o.file, &o.sha256, actual));
    }
    let sidecar = sidecar_path(zip_path);
    let archive: Option<CheckResult> = std::fs::read_to_string(&sidecar).ok().map(|s| {
        let expected = s.split_whitespace().next().unwrap_or_default().to_string();
        check_hash(&file_name(zip_path), &expected, sha256_file(zip_path))
    });
    // Directory entries are structure, not files; every other member must be listed.
    let members: Vec<String> = ar
        .file_names()
        .map(|n| n.map_or_else(|_| "<undecodable member name>".into(), |c| c.into_owned()))
        .filter(|n| !n.ends_with('/'))
        .collect();
    let report = VerifyReport {
        outputs,
        sources: verify_sources(&manifest),
        no_outputs: manifest.outputs.is_empty(),
        archive,
        extra: crate::unexpected(&manifest, members),
    };
    Ok((manifest, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckStatus;
    use cairn_core::traits::OutputSink;

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_zip_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn manifest() -> Manifest {
        use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
        use chrono::Utc;
        Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo {
                name: "cairn".into(),
                version: "0.1.0".into(),
                build_sha: "abc".into(),
                sigma_ruleset_ver: String::new(),
            },
            run: RunInfo {
                started_utc: Utc::now(),
                finished_utc: None,
                cmdline: "test".into(),
                operator: String::new(),
                case_id: String::new(),
                profile: "standard".into(),
                selected_modules: vec![],
            },
            host: HostInfo {
                hostname: "WS01".into(),
                os_build: String::new(),
                timezone: "UTC".into(),
                wall_clock_utc_skew: "+0s".into(),
                utc_offset_seconds: None,
                reference_time_utc: None,
                skew_seconds: None,
            },
            privileges: Privileges {
                admin: false,
                se_backup: false,
                se_debug: false,
            },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: String::new(),
            governance: cairn_core::manifest::GovernanceReport::default(),
        }
    }

    fn member_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().unwrap().to_string())
            .collect()
    }

    /// Build a full archive the way the live run does: data members (incl. records and
    /// the report), a staged evidence file, then a manifest listing them.
    fn full_zip(dir: &Path) -> PathBuf {
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);
        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();
        sink.write_observations(&[]).unwrap();
        sink.write_records_jsonl(&[]).unwrap();
        sink.write_html_report(&[], &[], &[], &manifest()).unwrap();
        let staged = crate::output_path(&sink.staging_dir(), "evidence/evtx/System.evtx");
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"ElfFile\0x").unwrap();
        sink.add_file("evidence/evtx/System.evtx", &staged).unwrap();
        let mut m = manifest();
        m.outputs = sink.outputs_so_far();
        sink.write_manifest(&m).unwrap();
        sink.finalize().unwrap();
        zip_path
    }

    #[test]
    fn zip_sink_produces_valid_zip_with_every_output() {
        let dir = mk_dir("valid");
        let zip_path = full_zip(&dir);
        let bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(&bytes[..2], b"PK", "must be valid zip");
        let names = member_names(&bytes);
        for want in [
            "timeline.csv",
            "findings.jsonl",
            "observations.jsonl",
            "records.jsonl",
            "report.html",
            "evidence/evtx/System.evtx",
            "manifest.json",
        ] {
            assert!(names.iter().any(|n| n == want), "{want}: {names:?}");
        }
        assert!(
            !dir.join("out.zip.staging").exists(),
            "staging dir removed after archiving"
        );
    }

    /// The sidecar holds the archive's hash; the manifest member lists every other
    /// member with hash + size; verify_zip passes on the untouched archive.
    #[test]
    fn zip_sidecar_and_member_hashes_verify() {
        let dir = mk_dir("sidecar");
        let zip_path = full_zip(&dir);
        let bytes = std::fs::read(&zip_path).unwrap();
        let sidecar = std::fs::read_to_string(sidecar_path(&zip_path)).unwrap();
        assert_eq!(sidecar, format!("{}  out.zip\n", crate::sha256_hex(&bytes)));

        let (m, report) = verify_zip(&zip_path).unwrap();
        assert_eq!(m.outputs.len(), 6, "every member but the manifest itself");
        let ev = m
            .outputs
            .iter()
            .find(|o| o.file == "evidence/evtx/System.evtx")
            .unwrap();
        assert_eq!(ev.size, 9);
        assert!(report.ok(), "{:?}", report.failures());
        assert_eq!(report.archive.as_ref().unwrap().status, CheckStatus::Ok);
    }

    /// A member the manifest does not list (added to the archive after the run) fails
    /// verify as Unexpected even when there is no sidecar to catch the change.
    #[test]
    fn verify_zip_reports_unlisted_members() {
        let dir = mk_dir("extra");
        let zip_path = dir.join("x.zip");
        let mut sink = ZipSink::new(&zip_path);
        sink.write_timeline_csv(&[]).unwrap();
        let mut m = manifest();
        m.outputs = sink.outputs_so_far();
        sink.write_manifest(&m).unwrap();
        // A member slipped in that the manifest never listed.
        sink.members
            .push(("evidence/planted.txt".into(), Member::Bytes(b"x".to_vec())));
        sink.finalize().unwrap();
        std::fs::remove_file(sidecar_path(&zip_path)).unwrap();
        let (_, report) = verify_zip(&zip_path).unwrap();
        assert!(!report.ok());
        assert_eq!(report.extra.len(), 1, "{:?}", report.extra);
        assert_eq!(report.extra[0].file, "evidence/planted.txt");
        assert_eq!(report.extra[0].status, CheckStatus::Unexpected);
    }

    /// Tampering with the archive breaks the sidecar check; a member whose bytes no
    /// longer match the manifest is a mismatch.
    #[test]
    fn verify_zip_fails_on_tampered_archive_and_member() {
        let dir = mk_dir("tamper");
        let zip_path = full_zip(&dir);

        // 1. Archive bytes changed (appended junk keeps it readable): sidecar mismatch.
        let mut bytes = std::fs::read(&zip_path).unwrap();
        bytes.extend_from_slice(b"junk");
        std::fs::write(&zip_path, &bytes).unwrap();
        let (_, report) = verify_zip(&zip_path).unwrap();
        assert!(!report.ok());
        assert!(matches!(
            report.archive.unwrap().status,
            CheckStatus::Mismatch { .. }
        ));

        // 2. Rebuild with a manifest whose recorded member hash is wrong.
        let zip2 = dir.join("bad.zip");
        let mut sink = ZipSink::new(&zip2);
        sink.write_timeline_csv(&[]).unwrap();
        let mut m = manifest();
        m.outputs = sink.outputs_so_far();
        m.outputs[0].sha256 = "0".repeat(64);
        sink.write_manifest(&m).unwrap();
        sink.finalize().unwrap();
        let (_, report) = verify_zip(&zip2).unwrap();
        assert!(!report.ok());
        assert!(matches!(
            report.outputs[0].status,
            CheckStatus::Mismatch { .. }
        ));
    }

    #[test]
    fn zip_sink_hashes_match_disk() {
        let dir = mk_dir("hash");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();
        let disk_bytes = std::fs::read(&zip_path).unwrap();
        let zip_entry = entries.iter().find(|e| e.file == "out.zip").unwrap();
        assert_eq!(zip_entry.sha256, crate::sha256_hex(&disk_bytes));
        assert_eq!(zip_entry.size, disk_bytes.len() as u64);
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
