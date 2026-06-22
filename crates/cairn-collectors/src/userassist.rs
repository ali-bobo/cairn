//! UserAssistCollector: parse each user's NTUSER.DAT UserAssist into Record::Execution
//! with a real GUI launch count + last-execution time.
//!
//! UserAssist (Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\
//! Count) records Explorer-launched programs per user. Each value's NAME is the
//! executable path ROT13-encoded; its DATA is a 72-byte struct with run_count at
//! offset 4 and a last-run FILETIME at offset 60. Reached via a raw \\.\C: read of each
//! C:\Users\<name>\NTUSER.DAT (the live hive is locked). user_sid is resolved by
//! reverse-lookup against the SOFTWARE hive's ProfileList. On an absent key or
//! unrecognised structure it ABSTAINS (records the reason) rather than guess (NFR12).

/// Decode a ROT13-encoded ASCII string (UserAssist value names are ROT13). Pure: each
/// ASCII letter is rotated 13 places; every non-alphabetic byte (digits, braces, path
/// separators, dots) passes through unchanged. Never panics. Self-inverse.
#[allow(dead_code)] // wired by UserAssistCollector in T6
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_decodes_ueme_marker() {
        // The well-known UserAssist session marker, verified on-host.
        assert_eq!(rot13("HRZR_PGYFRFFVBA"), "UEME_CTLSESSION");
    }

    #[test]
    fn rot13_is_self_inverse() {
        let s = "UEME_RUNPATH:C:\\Windows\\notepad.exe";
        assert_eq!(rot13(&rot13(s)), s);
    }

    #[test]
    fn rot13_passes_non_alpha_through_unchanged() {
        // Digits, braces, backslash, colon, dot must be untouched (GUID + path chars).
        let s = "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\\1.2_3";
        // Only the letters rotate; the structure (digits/braces/sep) is preserved.
        let decoded = rot13(s);
        assert_eq!(decoded.len(), s.len());
        assert!(decoded.contains('{') && decoded.contains('}') && decoded.contains('\\'));
        assert!(decoded.contains("1.2_3")); // digits + dot + underscore unchanged
    }

    #[test]
    fn rot13_empty_string() {
        assert_eq!(rot13(""), "");
    }

    #[test]
    fn rot13_mixed_case_preserves_case() {
        assert_eq!(rot13("AbZz"), "NoMm");
    }
}
