//! PersistCollector (FR9 subset, SRS §4): reads high-value live persistence mechanisms
//! (Run/RunOnce, Services, Winlogon, IFEO, Startup folders) via the safe `winreg` wrapper
//! and std::fs, mapping each to a PersistenceRecord. Read-only; never modifies the host.
//! `signed`/`binary_sha256` are left None (S2-D / FR14).
#![allow(dead_code)] // Task 4: pure helper only; readers + Collector land in Tasks 5-8.

/// Extract the executable path from a command line. Handles a quoted first token
/// (`"C:\p a\app.exe" -x` -> `C:\p a\app.exe`) and a bare first token
/// (`C:\p\app.exe -x` -> `C:\p\app.exe`), then expands %ENV% variables. Returns None
/// if the input is empty or yields nothing usable (never panics).
pub(crate) fn extract_binary_path(cmdline: &str) -> Option<String> {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw = if let Some(rest) = trimmed.strip_prefix('"') {
        // quoted: take up to the closing quote
        rest.split('"').next().unwrap_or("")
    } else {
        // unquoted: first whitespace-delimited token
        trimmed.split_whitespace().next().unwrap_or("")
    };
    if raw.is_empty() {
        return None;
    }
    Some(expand_env_vars(raw))
}

/// Expand %VAR% occurrences using the process environment; unknown vars are left as-is.
fn expand_env_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(val) => out.push_str(&val),
                Err(_) => {
                    // leave the literal %NAME% in place
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            // no closing %: emit the rest verbatim and stop
            out.push('%');
            out.push_str(after);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_path_with_args() {
        assert_eq!(
            extract_binary_path(r#""C:\Program Files\App\app.exe" -silent"#).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }

    #[test]
    fn unquoted_path_with_args() {
        assert_eq!(
            extract_binary_path(r"C:\Windows\system32\rundll32.exe shell32.dll,Control").as_deref(),
            Some(r"C:\Windows\system32\rundll32.exe")
        );
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(extract_binary_path("   "), None);
        assert_eq!(extract_binary_path(""), None);
    }

    #[test]
    fn expands_known_env_and_keeps_unknown() {
        // Set a known var for the test, reference an unknown one.
        std::env::set_var("CAIRN_TEST_ROOT", r"C:\testroot");
        assert_eq!(
            extract_binary_path(r"%CAIRN_TEST_ROOT%\a.exe").as_deref(),
            Some(r"C:\testroot\a.exe")
        );
        assert_eq!(
            extract_binary_path(r"%CAIRN_DOES_NOT_EXIST%\a.exe").as_deref(),
            Some(r"%CAIRN_DOES_NOT_EXIST%\a.exe")
        );
    }
}
