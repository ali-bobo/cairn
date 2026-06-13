//! PersistCollector (FR9 subset, SRS §4): reads high-value live persistence mechanisms
//! (Run/RunOnce, Services, Winlogon, IFEO, Startup folders) via the safe `winreg` wrapper
//! and std::fs, mapping each to a PersistenceRecord. Read-only; never modifies the host.
//! `signed`/`binary_sha256` are left None (S2-D / FR14).
#![allow(dead_code)] // Task 4: pure helper only; readers + Collector land in Tasks 5-8.

/// Extract the executable path from a command line. Handles a quoted first token
/// (`"C:\p a\app.exe" -x` -> `C:\p a\app.exe`) and a bare first token
/// (`C:\p\app.exe -x` -> `C:\p\app.exe`), then expands %ENV% variables using the process
/// environment. Returns None if the input is empty or yields nothing usable (never panics).
pub(crate) fn extract_binary_path(cmdline: &str) -> Option<String> {
    extract_binary_path_with(cmdline, |name| std::env::var(name).ok())
}

/// Pure core: like `extract_binary_path` but the env lookup is injected, so it is
/// deterministic and testable without mutating the process environment. `lookup` returns
/// the value for an env var name, or None if undefined.
fn extract_binary_path_with(
    cmdline: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<String> {
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
    Some(expand_env_vars(raw, &lookup))
}

/// Expand %VAR% occurrences using the injected `lookup`; unknown vars (lookup returns None)
/// are left as the literal `%NAME%`. An unterminated `%` emits the rest verbatim. An empty
/// var name (`%%`) is treated as unknown and kept literal. Never panics (the `%` byte is
/// ASCII, so all slice indices are char-boundary-safe).
fn expand_env_vars(s: &str, lookup: &impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match lookup(name) {
                Some(val) => out.push_str(&val),
                None => {
                    // unknown (or empty) var name: keep the literal %NAME%
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
    use std::collections::HashMap;

    /// Build an env-lookup closure from a fixed map (no process env, no set_var).
    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn quoted_path_with_args() {
        let env = fake_env(&[]);
        assert_eq!(
            extract_binary_path_with(r#""C:\Program Files\App\app.exe" -silent"#, &env).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }

    #[test]
    fn unquoted_path_with_args() {
        let env = fake_env(&[]);
        assert_eq!(
            extract_binary_path_with(
                r"C:\Windows\system32\rundll32.exe shell32.dll,Control",
                &env
            )
            .as_deref(),
            Some(r"C:\Windows\system32\rundll32.exe")
        );
    }

    #[test]
    fn empty_is_none() {
        let env = fake_env(&[]);
        assert_eq!(extract_binary_path_with("   ", &env), None);
        assert_eq!(extract_binary_path_with("", &env), None);
    }

    #[test]
    fn expands_known_env_and_keeps_unknown() {
        let env = fake_env(&[("CAIRN_TEST_ROOT", r"C:\testroot")]);
        assert_eq!(
            extract_binary_path_with(r"%CAIRN_TEST_ROOT%\a.exe", &env).as_deref(),
            Some(r"C:\testroot\a.exe")
        );
        assert_eq!(
            extract_binary_path_with(r"%CAIRN_DOES_NOT_EXIST%\a.exe", &env).as_deref(),
            Some(r"%CAIRN_DOES_NOT_EXIST%\a.exe")
        );
    }

    /// Adversarial: lone %, %%, and an unterminated quote must not panic.
    #[test]
    fn adversarial_inputs_do_not_panic() {
        let env = fake_env(&[]);
        assert_eq!(expand_env_vars("%", &env), "%");
        assert_eq!(expand_env_vars("%%", &env), "%%"); // empty name -> kept literal
                                                       // unterminated quote: the whole remainder becomes the path
        assert_eq!(
            extract_binary_path_with(r#""C:\unterminated args"#, &env).as_deref(),
            Some(r"C:\unterminated args")
        );
    }

    /// The public wrapper still works against the real process env without panicking.
    #[test]
    fn public_wrapper_uses_process_env() {
        // PATH is essentially always set; we only assert no panic + Some for a bare path.
        assert_eq!(
            extract_binary_path(r"C:\Windows\notepad.exe").as_deref(),
            Some(r"C:\Windows\notepad.exe")
        );
    }
}
