#![forbid(unsafe_code)]

use cairn_core::{CairnError, Result};

const BASE: &str = "https://raw.githubusercontent.com/SigmaHQ/sigma/";

/// Validate that `pin` is exactly 40 lowercase hex characters.
fn validate_pin(pin: &str) -> Result<()> {
    if pin.len() == 40 && pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(CairnError::Other(format!(
            "invalid pin `{pin}`: must be exactly 40 lowercase hex characters"
        )))
    }
}

/// Construct the full raw-content URL for a rule at a pinned commit.
///
/// Defensive SSRF gate: asserts the constructed URL starts with `BASE`.
fn build_url(pin: &str, rule_path: &str) -> Result<String> {
    validate_pin(pin)?;
    let url = format!("{BASE}{pin}/rules/{rule_path}");
    // Defensive assertion — validate_pin already ensures no injection via `pin`,
    // but we assert the prefix here as a belt-and-suspenders SSRF gate.
    assert!(
        url.starts_with(BASE),
        "BUG: constructed URL does not start with BASE: {url}"
    );
    Ok(url)
}

/// Check that at least one line in `bytes` starts with `b"author:"` (byte-level).
///
/// This enforces the DRL 1.1 requirement that every bundled Sigma rule carries
/// an `author:` field (CLAUDE.md golden rule #5).
fn check_drl11(bytes: &[u8], rule_path: &str) -> Result<()> {
    let has_author = bytes
        .split(|&b| b == b'\n')
        .any(|line| line.starts_with(b"author:"));
    if has_author {
        Ok(())
    } else {
        Err(CairnError::Other(format!(
            "DRL 1.1 violation: {rule_path} has no `author:` field"
        )))
    }
}

/// Fetch a single Sigma rule from SigmaHQ at the given pinned commit.
///
/// Steps:
/// 1. Build and validate the URL (SSRF whitelist + pin validation).
/// 2. Perform a blocking HTTP GET.
/// 3. Assert HTTP 2xx status.
/// 4. Read the response body.
/// 5. Enforce DRL 1.1 (`author:` line present).
/// 6. Return raw bytes.
pub fn fetch_rule(pin: &str, rule_path: &str) -> Result<Vec<u8>> {
    let url = build_url(pin, rule_path)?;
    let response = reqwest::blocking::get(&url)
        .map_err(|e| CairnError::Other(format!("HTTP request failed for `{url}`: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(CairnError::Other(format!("HTTP {status} fetching `{url}`")));
    }
    let bytes = response.bytes().map_err(|e| {
        CairnError::Other(format!("failed to read response body from `{url}`: {e}"))
    })?;
    let bytes = bytes.to_vec();
    check_drl11(&bytes, rule_path)?;
    Ok(bytes)
}

/// Public wrapper around `validate_pin` (used by lib.rs in T5).
pub fn validate_pin_pub(pin: &str) -> Result<()> {
    validate_pin(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_pin_accepts_40hex() {
        assert!(validate_pin("98781da19cf60c48ce6e7f2d3ad11c9ba389191a").is_ok());
        assert!(validate_pin("0000000000000000000000000000000000000000").is_ok());
        assert!(validate_pin("ffffffffffffffffffffffffffffffffffffffff").is_ok());
    }

    #[test]
    fn validate_pin_rejects_short() {
        assert!(validate_pin("98781da19cf60c48ce6e7f2d3ad11c9ba38919").is_err()); // 39 chars
        assert!(validate_pin("").is_err());
    }

    #[test]
    fn validate_pin_rejects_nonhex() {
        assert!(validate_pin("98781da19cf60c48ce6e7f2d3ad11c9ba389191g").is_err()); // 'g'
        assert!(validate_pin("98781da19cf60c48ce6e7f2d3AD11c9ba389191a").is_err());
        // uppercase
    }

    #[test]
    fn build_url_contains_base_and_pin() {
        let url = build_url(
            "98781da19cf60c48ce6e7f2d3ad11c9ba389191a",
            "windows/process_creation/rule.yml",
        )
        .unwrap();
        assert!(url.starts_with(BASE), "URL must start with BASE: {url}");
        assert!(url.contains("98781da19cf60c48ce6e7f2d3ad11c9ba389191a"));
        assert!(url.contains("windows/process_creation/rule.yml"));
    }

    #[test]
    fn drl11_check_rejects_no_author() {
        let bytes = b"title: Test\ndetection:\n  selection:\n  condition: selection\n";
        assert!(check_drl11(bytes, "test.yml").is_err());
    }

    #[test]
    fn drl11_check_accepts_author_line() {
        let bytes =
            b"title: Test\nauthor: Alice\ndetection:\n  selection:\n  condition: selection\n";
        assert!(check_drl11(bytes, "test.yml").is_ok());
    }

    #[test]
    #[ignore = "requires network — run manually: cargo test -p cairn-updater -- --ignored"]
    fn fetch_real_rule_from_sigmahq() {
        let bytes = fetch_rule(
            "98781da19cf60c48ce6e7f2d3ad11c9ba389191a",
            "windows/process_creation/proc_creation_win_msxsl_execution.yml",
        )
        .unwrap();
        assert!(!bytes.is_empty());
        assert!(
            bytes.windows(7).any(|w| w == b"author:"),
            "fetched rule must have author: field"
        );
    }
}
