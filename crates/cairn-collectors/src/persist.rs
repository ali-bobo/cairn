//! PersistCollector (FR9 subset, SRS §4): reads high-value live persistence mechanisms
//! (Run/RunOnce, Services, Winlogon, IFEO, Startup folders) via the safe `winreg` wrapper
//! and std::fs, mapping each to a PersistenceRecord. Read-only; never modifies the host.
//! `signed`/`binary_sha256` are left None (S2-D / FR14).
#![allow(dead_code)] // Task 4: pure helper only; readers + Collector land in Tasks 5-8.

use cairn_core::record::PersistenceRecord;
use chrono::{DateTime, Utc};

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

/// Build a PersistenceRecord with the deferred fields (signed/sha256) as None.
fn make_record(
    mechanism: &str,
    location: String,
    value: Option<String>,
    command: Option<String>,
    last_write: Option<DateTime<Utc>>,
) -> PersistenceRecord {
    let binary_path = command.as_deref().and_then(extract_binary_path);
    PersistenceRecord {
        mechanism: mechanism.to_string(),
        location,
        value,
        command,
        binary_path,
        binary_sha256: None,
        signed: None,
        last_write,
    }
}

/// Non-Windows: persistence reads are Windows-only; return empty so the workspace builds.
#[cfg(not(windows))]
fn read_run_keys() -> Vec<PersistenceRecord> {
    vec![]
}
#[cfg(not(windows))]
fn read_winlogon() -> Vec<PersistenceRecord> {
    vec![]
}
#[cfg(not(windows))]
fn read_ifeo() -> Vec<PersistenceRecord> {
    vec![]
}

#[cfg(windows)]
fn read_run_keys() -> Vec<PersistenceRecord> {
    win::read_run_keys()
}
#[cfg(windows)]
fn read_winlogon() -> Vec<PersistenceRecord> {
    win::read_winlogon()
}
#[cfg(windows)]
fn read_ifeo() -> Vec<PersistenceRecord> {
    win::read_ifeo()
}

/// Non-Windows stub for services reader.
#[cfg(not(windows))]
fn read_services() -> Vec<PersistenceRecord> {
    vec![]
}
#[cfg(windows)]
fn read_services() -> Vec<PersistenceRecord> {
    win::read_services()
}

/// Windows registry readers for persistence mechanisms.
///
/// winreg 0.56.0 API used:
///   - `RegKey::predef(HKEY)` — open a root hive handle (const fn, no allocation)
///   - `regkey.open_subkey(path)` — read-only open; returns `io::Result<RegKey>`
///   - `regkey.enum_values()` — yields `io::Result<(String, RegValue)>`; `RegValue` impls
///     `Display` so `val.to_string()` produces the human-readable data string
///   - `regkey.enum_keys()` — yields `io::Result<String>`
///   - `regkey.get_value::<String, _>(name)` — typed single-value read
///   - `regkey.query_info()` — returns `io::Result<RegKeyMetadata>`
///   - `RegKeyMetadata::get_last_write_time_system()` — returns `SYSTEMTIME` (wYear/wMonth/
///     wDay/wHour/wMinute/wSecond all as u16; no expect/panic). We convert via
///     `Utc.with_ymd_and_hms(...).single()` — NOT the chrono feature helper which calls
///     `.expect()` internally and would panic on a malformed timestamp.
#[cfg(windows)]
mod win {
    use super::{make_record, PersistenceRecord};
    use chrono::{DateTime, TimeZone, Utc};
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    /// Best-effort last-write of a key as UTC; None if unavailable or out of range.
    /// PANIC-FREE: uses with_ymd_and_hms(...).single(), not winreg's expect()-based helper.
    fn key_last_write(key: &RegKey) -> Option<DateTime<Utc>> {
        let info = key.query_info().ok()?;
        let st = info.get_last_write_time_system();
        Utc.with_ymd_and_hms(
            st.wYear as i32,
            st.wMonth as u32,
            st.wDay as u32,
            st.wHour as u32,
            st.wMinute as u32,
            st.wSecond as u32,
        )
        .single()
    }

    /// Run + RunOnce under both HKLM and HKCU.
    pub fn read_run_keys() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let bases = [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")];
        let subs = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ];
        for (hkey, hname) in bases {
            for sub in subs {
                let root = RegKey::predef(hkey);
                let Ok(key) = root.open_subkey(sub) else {
                    continue;
                };
                let lw = key_last_write(&key);
                let location = format!("{hname}\\{sub}");
                for item in key.enum_values() {
                    let Ok((name, val)) = item else {
                        continue;
                    };
                    // RegValue implements Display; to_string() yields the human-readable
                    // data (REG_SZ/REG_EXPAND_SZ/REG_MULTI_SZ as string, DWORD/QWORD as
                    // decimal, binary as debug byte array).
                    let data = val.to_string();
                    out.push(make_record(
                        "run_key",
                        location.clone(),
                        Some(name),
                        Some(data),
                        lw,
                    ));
                }
            }
        }
        out
    }

    /// Winlogon Shell + Userinit (HKLM).
    pub fn read_winlogon() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let sub = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(key) = root.open_subkey(sub) else {
            return out;
        };
        let lw = key_last_write(&key);
        let location = format!("HKLM\\{sub}");
        for name in ["Shell", "Userinit"] {
            if let Ok(data) = key.get_value::<String, _>(name) {
                out.push(make_record(
                    "winlogon",
                    location.clone(),
                    Some(name.to_string()),
                    Some(data),
                    lw,
                ));
            }
        }
        out
    }

    /// IFEO subkeys that carry a Debugger value (the hijack vector).
    pub fn read_ifeo() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let sub = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(ifeo) = root.open_subkey(sub) else {
            return out;
        };
        for name in ifeo.enum_keys().flatten() {
            let Ok(img) = ifeo.open_subkey(&name) else {
                continue;
            };
            if let Ok(dbg) = img.get_value::<String, _>("Debugger") {
                let lw = key_last_write(&img);
                let location = format!("HKLM\\{sub}\\{name}");
                out.push(make_record(
                    "ifeo",
                    location,
                    Some(name.clone()),
                    Some(dbg),
                    lw,
                ));
            }
        }
        out
    }

    /// Autostart services: HKLM\SYSTEM\CurrentControlSet\Services\* with Start in {0,1,2}
    /// (boot/system/auto) and an ImagePath. Manual/disabled services (Start 3/4) are skipped
    /// (not a persistence focus). Best-effort: unreadable subkeys are skipped (non-admin).
    pub fn read_services() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let sub = r"SYSTEM\CurrentControlSet\Services";
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(services) = root.open_subkey(sub) else {
            return out;
        };
        for name in services.enum_keys().flatten() {
            let Ok(svc) = services.open_subkey(&name) else {
                continue;
            };
            // Start is a REG_DWORD; only 0/1/2 are autostart.
            let start: u32 = match svc.get_value::<u32, _>("Start") {
                Ok(v) => v,
                Err(_) => continue,
            };
            if start > 2 {
                continue;
            }
            let Ok(image) = svc.get_value::<String, _>("ImagePath") else {
                continue;
            };
            let lw = key_last_write(&svc);
            let location = format!("HKLM\\{sub}\\{name}");
            out.push(make_record(
                "service",
                location,
                Some(name.clone()),
                Some(image),
                lw,
            ));
        }
        out
    }
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
