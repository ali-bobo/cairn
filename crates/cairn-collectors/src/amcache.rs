//! AmcacheCollector: parse Amcache.hve InventoryApplicationFile entries into
//! Record::Execution (path + SHA1 + first-exec approximation).
//!
//! Amcache.hve is a structured registry hive (unlike shimcache's single blob). Each
//! file under InventoryApplicationFile is a subkey whose named values carry the path
//! (LowerCaseLongPath / Name) and a SHA1 (FileId). first_run is approximated by the
//! subkey's last-write time (the industry-accepted Amcache first-seen). On an absent
//! key or unrecognised structure it ABSTAINS (records the reason in the manifest)
//! rather than guess — misreading a forensic artifact is worse than abstaining (NFR12).
//! This segment parses InventoryApplicationFile only.

/// Parse the SHA1 out of an Amcache FileId value.
///
/// FileId format is the string "0000" + 40 lowercase hex (44 chars total). A
/// non-conforming value yields None (the entry is still emitted with sha1=None —
/// NFR12 honesty: never write a malformed value into a SHA1 field).
#[allow(dead_code)]
fn parse_sha1_from_fileid(field: &str) -> Option<String> {
    // Operate on chars, not bytes, so multibyte input can never panic on slicing.
    let chars: Vec<char> = field.chars().collect();
    if chars.len() != 44 {
        return None;
    }
    // First 4 chars must be the literal "0000" (ASCII digits; no case applies).
    if chars[0..4] != ['0', '0', '0', '0'] {
        return None;
    }
    let body: String = chars[4..].iter().collect();
    if !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(body.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conforming_fileid_yields_lowercase_sha1() {
        let id = "0000aabbccddeeff00112233445566778899aabbccdd";
        assert_eq!(id.len() - 4, 40); // sanity on the fixture
        let full = format!("0000{}", &id[4..]);
        let got = parse_sha1_from_fileid(&full);
        assert_eq!(got.as_deref(), Some(&id[4..]));
    }

    #[test]
    fn uppercase_hex_is_normalised_to_lowercase() {
        let full = "0000AABBCCDDEEFF00112233445566778899AABBCCDD".to_string();
        // 4 + 40 = 44 chars; build exactly 44.
        assert_eq!(full.len(), 44);
        let got = parse_sha1_from_fileid(&full).unwrap();
        assert_eq!(got, got.to_ascii_lowercase());
        assert_eq!(got.len(), 40);
    }

    #[test]
    fn wrong_length_is_none() {
        assert_eq!(parse_sha1_from_fileid(""), None);
        assert_eq!(parse_sha1_from_fileid("0000"), None);
        assert_eq!(parse_sha1_from_fileid("0000abcd"), None); // too short
        let too_long = format!("0000{}", "a".repeat(41));
        assert_eq!(parse_sha1_from_fileid(&too_long), None);
    }

    #[test]
    fn wrong_prefix_is_none() {
        // 44 chars, valid hex, but prefix is not 0000.
        let full = format!("1234{}", "a".repeat(40));
        assert_eq!(full.len(), 44);
        assert_eq!(parse_sha1_from_fileid(&full), None);
    }

    #[test]
    fn non_hex_body_is_none() {
        // 44 chars, 0000 prefix, but body has a non-hex char ('g').
        let full = format!("0000{}", "g".repeat(40));
        assert_eq!(full.len(), 44);
        assert_eq!(parse_sha1_from_fileid(&full), None);
    }

    #[test]
    fn no_panic_on_multibyte_input() {
        // Multibyte chars: len() is byte length. A 44-BYTE string that is not 44
        // ASCII chars must not panic on slicing. "é" is 2 bytes.
        let s = "é".repeat(22); // 44 bytes, 22 chars
        let _ = parse_sha1_from_fileid(&s); // must not panic
    }
}
