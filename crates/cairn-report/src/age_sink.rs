#![forbid(unsafe_code)]
use crate::{sha256_hex, write_output_safe, zip_sink::build_zip};
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    CairnError, Observation, Result,
};
use std::path::PathBuf;

pub struct AgeSink {
    age_path: PathBuf,
    pubkey: age::x25519::Recipient,
    files: Vec<(String, Vec<u8>)>,
}

impl AgeSink {
    /// `zip_path` is the user-specified base path (e.g. `cairn_out.zip`);
    /// the actual output is `<zip_path>.age` (e.g. `cairn_out.zip.age`).
    /// Returns Err if `pubkey_str` is not a valid age X25519 bech32 public key.
    pub fn new(zip_path: impl Into<PathBuf>, pubkey_str: &str) -> Result<Self> {
        let zip_path = zip_path.into();
        let age_path = {
            let mut p = zip_path.as_os_str().to_owned();
            p.push(".age");
            PathBuf::from(p)
        };
        let pubkey: age::x25519::Recipient = pubkey_str
            .parse()
            .map_err(|e: &str| CairnError::Other(format!("invalid age public key: {e}")))?;
        Ok(AgeSink {
            age_path,
            pubkey,
            files: Vec::new(),
        })
    }
}

/// Encrypt `data` to the given X25519 recipient using the age binary format.
/// Module-private; callers use AgeSink which handles the OutputSink protocol.
fn age_encrypt(recipient: &age::x25519::Recipient, data: &[u8]) -> Result<Vec<u8>> {
    age::encrypt(recipient, data).map_err(|e| CairnError::Other(format!("age encrypt: {e}")))
}

impl OutputSink for AgeSink {
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

    fn write_observations(&mut self, observations: &[Observation]) -> Result<()> {
        let buf = crate::observations_jsonl(observations)?;
        self.files.push(("observations.jsonl".into(), buf.into_bytes()));
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
        let age_bytes = age_encrypt(&self.pubkey, &zip_bytes)?;
        write_output_safe(&self.age_path, &age_bytes)?;
        Ok(vec![OutputEntry {
            file: self.age_path.display().to_string(),
            sha256: sha256_hex(&age_bytes),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    // 測試專用 X25519 keypair（公開已知，無敏感資料）
    const TEST_PUBKEY: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_age_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn age_sink_output_has_age_header() {
        let dir = mk_dir("header");
        let zip_path = dir.join("out.zip");
        let mut sink = AgeSink::new(&zip_path, TEST_PUBKEY).unwrap();
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();

        let age_path = dir.join("out.zip.age");
        assert!(age_path.exists(), ".zip.age must exist");
        let bytes = std::fs::read(&age_path).unwrap();
        // age binary format starts with "age-encryption.org/v1\n"
        assert!(
            bytes.starts_with(b"age-encryption.org/v1"),
            "expected age header, got: {:?}",
            &bytes[..22.min(bytes.len())]
        );
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].file.ends_with(".zip.age"),
            "file entry: {}",
            entries[0].file
        );
        assert_eq!(entries[0].sha256, crate::sha256_hex(&bytes));
    }

    #[test]
    fn age_sink_bad_pubkey_returns_err() {
        let dir = mk_dir("badkey");
        let zip_path = dir.join("out.zip");
        // An obviously invalid pubkey must produce Err at construction time, not panic.
        let result = AgeSink::new(&zip_path, "not-an-age-pubkey");
        assert!(result.is_err(), "bad pubkey must return Err");
    }
}
