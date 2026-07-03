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
        let body = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
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
        assert!(!set.is_empty(), "bundled driver list must have >=1 valid SHA1");
    }
}
