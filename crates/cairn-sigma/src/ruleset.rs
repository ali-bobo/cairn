//! Ruleset supply-chain integrity (ADR-0003).
//!
//! Cairn's detections are only as trustworthy as its rules, which come from an
//! external mutable source (SigmaHQ). To prove a run used an un-tampered set, we
//! compute an **aggregate SHA-256** over the canonicalized rule directory and record
//! it in the manifest as part of `tool.sigma_ruleset_ver` ("<commit-sha>+<aggregate>").
//! `cairn verify` (T9) recomputes it to catch a swapped/edited rule.
//!
//! Canonicalization (must be reproducible across machines, ADR-0003):
//!   1. enumerate every `.yml`/`.yaml` file under the dir (recursively),
//!   2. compute each file's SHA-256 over its **decoded plain YAML** bytes, so the
//!      §ADR-0002 XOR codec does not change the hash (encoded and `--rules-plain`
//!      trees of the same rules hash identically),
//!   3. sort by relative path (lexicographic, `/`-separated, stable across OSes),
//!   4. feed `"<relpath>\n<hex-file-hash>\n"` for each file, in order, into a final
//!      SHA-256. That digest is the aggregate.

use cairn_core::Result;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Hex-encode a byte slice (lowercase), matching the manifest's hash format.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Recursively collect `(relative_path, absolute_path)` for every Sigma rule file
/// (`.yml`/`.yaml`) under `dir`. Relative paths use `/` separators so the canonical
/// ordering and bytes are identical on Windows and Unix (ADR-0003 reproducibility).
fn collect_rule_files(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    fn walk(base: &Path, cur: &Path, out: &mut Vec<(String, std::path::PathBuf)>) -> Result<()> {
        for entry in std::fs::read_dir(cur)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(base, &path, out)?;
            } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, path));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

/// Compute the ADR-0003 aggregate SHA-256 (hex) over the rule set in `dir`.
///
/// `plain` mirrors `codec::load_rule_bytes`: `false` decodes XOR-encoded bundled
/// rules, `true` reads plain `.yml` as-is (`--rules-plain`). Either way the per-file
/// hash is over the *decoded* YAML, so the two trees of the same rules agree.
///
/// An empty (or rule-free) directory hashes to the SHA-256 of the empty input — a
/// stable, well-defined value, not an error.
pub fn aggregate_hash(dir: &Path, plain: bool) -> Result<String> {
    let mut files = collect_rule_files(dir)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut agg = Sha256::new();
    for (rel, path) in &files {
        let bytes = crate::codec::load_rule_bytes(path, plain)?;
        let file_hash = hex(&Sha256::digest(&bytes));
        agg.update(rel.as_bytes());
        agg.update(b"\n");
        agg.update(file_hash.as_bytes());
        agg.update(b"\n");
    }
    Ok(hex(&agg.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::xor;

    fn write(dir: &Path, name: &str, bytes: &[u8]) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
    }

    /// The aggregate hash is identical whether the rules are XOR-encoded on disk
    /// (loaded with plain=false) or stored as plain `.yml` (loaded with plain=true).
    /// This is the ADR-0003 invariant: the hash is over decoded YAML, so the XOR
    /// codec layer cannot change it.
    #[test]
    fn aggregate_hash_is_stable_under_xor_codec() {
        let root = std::env::temp_dir().join("cairn_ruleset_xor_test");
        let _ = std::fs::remove_dir_all(&root);
        let enc = root.join("encoded");
        let plain = root.join("plain");

        let rule_a = b"title: A\nid: a\ndetection:\n  selection:\n  condition: selection\n";
        let rule_b = b"title: B\nid: b\ndetection:\n  selection:\n  condition: selection\n";

        // Encoded tree: XOR-encoded bytes, loaded with plain=false (decoded).
        write(&enc, "a.yml", &xor(rule_a));
        write(&enc, "b.yml", &xor(rule_b));
        // Plain tree: same YAML verbatim, loaded with plain=true.
        write(&plain, "a.yml", rule_a);
        write(&plain, "b.yml", rule_b);

        let h_enc = aggregate_hash(&enc, false).unwrap();
        let h_plain = aggregate_hash(&plain, true).unwrap();
        assert_eq!(
            h_enc, h_plain,
            "XOR codec must not change the aggregate hash"
        );
    }

    /// The hash is deterministic regardless of filesystem enumeration order: two
    /// directories with the same files in the same relative layout hash equal, and the
    /// result is a 64-char lowercase hex SHA-256.
    #[test]
    fn aggregate_hash_is_deterministic_and_order_independent() {
        let root = std::env::temp_dir().join("cairn_ruleset_order_test");
        let _ = std::fs::remove_dir_all(&root);
        let one = root.join("one");
        let two = root.join("two");

        let r1 = b"title: one\nid: 1\n";
        let r2 = b"title: two\nid: 2\n";
        // Write in different creation orders into the two dirs.
        write(&one, "windows/exec.yml", r1);
        write(&one, "linux/persist.yml", r2);
        write(&two, "linux/persist.yml", r2);
        write(&two, "windows/exec.yml", r1);

        let h1 = aggregate_hash(&one, true).unwrap();
        let h2 = aggregate_hash(&two, true).unwrap();
        assert_eq!(h1, h2, "hash must be independent of enumeration order");
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
        assert!(h1.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    /// Changing one rule's bytes changes the aggregate hash (tamper-evidence — the
    /// whole point per ADR-0003 / threat-model untrusted-input #2).
    #[test]
    fn aggregate_hash_changes_when_a_rule_changes() {
        let root = std::env::temp_dir().join("cairn_ruleset_tamper_test");
        let _ = std::fs::remove_dir_all(&root);
        let clean = root.join("clean");
        let tampered = root.join("tampered");

        write(&clean, "a.yml", b"title: clean\n");
        write(&tampered, "a.yml", b"title: tampered\n");

        let h_clean = aggregate_hash(&clean, true).unwrap();
        let h_tampered = aggregate_hash(&tampered, true).unwrap();
        assert_ne!(
            h_clean, h_tampered,
            "a changed rule must change the aggregate"
        );
    }

    /// An empty rules dir hashes to a stable, well-defined value (SHA-256 of empty
    /// input), not an error — verify can still run against a no-rules manifest.
    #[test]
    fn empty_ruleset_hashes_to_stable_value() {
        let dir = std::env::temp_dir().join("cairn_ruleset_empty_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let h = aggregate_hash(&dir, true).unwrap();
        // SHA-256 of the empty byte string.
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
