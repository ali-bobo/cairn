//! On-disk rule encoding (ADR-0002).
//!
//! Bundled Sigma `.yml` rules may be XOR-encoded on disk SOLELY to stop byte-pattern
//! AV from false-positiving on the malicious strings inside detection rules. This is
//! NOT a security control and provides NO confidentiality. Specifically:
//!
//! - the key is a public constant in this open-source file;
//! - decoded bytes are parsed as DATA only and are NEVER executed;
//! - `--rules-plain` loads un-encoded `.yml` so a SOC can audit exactly what runs.
//!
//! See docs/adr/adr-0002-rule-encoding.md and docs/threat-model.md.

use cairn_core::Result;
use std::path::Path;

/// PUBLIC, non-secret XOR key. Its only job is to keep verbatim malicious strings out
/// of the on-disk `.yml` so byte-pattern AV doesn't false-positive. Published here on
/// purpose — anyone (incl. a reviewing SOC) can decode the rules. NOT confidentiality.
pub const KEY: &[u8] = b"cairn-rules-v1-not-a-secret";

/// XOR a buffer against the repeating public key. Symmetric: `xor(xor(x)) == x`.
pub fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .zip(KEY.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

/// Read rule bytes from disk. With `plain = true`, return the file as-is (the
/// `--rules-plain` bypass — un-encoded `.yml` a SOC can audit). With `plain = false`,
/// XOR-decode the file (the bundled, AV-FP-avoiding form). Decoded bytes are returned
/// for parsing as data only; nothing here executes them (ADR-0002).
pub fn load_rule_bytes(path: &Path, plain: bool) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)?;
    Ok(if plain { raw } else { xor(&raw) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XOR is symmetric: decoding an encoded buffer returns the original bytes.
    #[test]
    fn xor_round_trips() {
        let original = b"title: Suspicious PowerShell\ndetection:\n  selection:\n";
        let encoded = xor(original);
        let decoded = xor(&encoded);
        assert_eq!(decoded, original);
    }

    /// Encoding actually changes the bytes — the plaintext detection strings are not
    /// left verbatim on disk (the whole point: avoid AV FP on `.yml`).
    #[test]
    fn xor_obscures_plaintext_on_disk() {
        let original = b"detection: selection";
        let encoded = xor(original);
        assert_ne!(encoded.as_slice(), original.as_slice());
        // The literal "detection" substring must not survive verbatim.
        assert!(
            !encoded.windows(9).any(|w| w == b"detection"),
            "plaintext leaked into encoded bytes"
        );
    }

    /// `load_rule_bytes` reads plain `.yml` as-is when `plain = true`, and decodes an
    /// encoded file when `plain = false` (the `--rules-plain` bypass, ADR-0002).
    #[test]
    fn load_rule_bytes_honors_plain_and_encoded() {
        let dir = std::env::temp_dir().join("cairn_codec_test");
        std::fs::create_dir_all(&dir).unwrap();
        let yml = b"title: t\ndetection:\n";

        let plain_path = dir.join("rule_plain.yml");
        std::fs::write(&plain_path, yml).unwrap();
        assert_eq!(load_rule_bytes(&plain_path, true).unwrap(), yml);

        let enc_path = dir.join("rule_encoded.yml");
        std::fs::write(&enc_path, xor(yml)).unwrap();
        assert_eq!(load_rule_bytes(&enc_path, false).unwrap(), yml);
    }
}
