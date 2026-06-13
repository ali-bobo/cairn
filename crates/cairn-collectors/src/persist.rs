//! PersistCollector (FR9 subset, SRS §4): reads high-value live persistence mechanisms
//! (Run/RunOnce, Services, Winlogon, IFEO, Startup folders) via the safe `winreg` wrapper
//! and std::fs, mapping each to a PersistenceRecord. Read-only; never modifies the host.
//! `binary_sha256` is left None (FR14 deferred); `signed` is backfilled by `apply_signatures`
//! via the injected `FileVerifier` (S2-D, WinVerifyTrust behind the cairn-collectors-win seam).

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{PersistenceRecord, Record};
use cairn_core::traits::{CollectCtx, Collector, FileVerifier};
use cairn_core::Result;
use chrono::{DateTime, Utc};

/// Extract the executable path from a command line. Handles a quoted first token
/// (`"C:\p a\app.exe" -x` -> `C:\p a\app.exe`) and a bare first token
/// (`C:\p\app.exe -x` -> `C:\p\app.exe`), then expands %ENV% variables using the process
/// environment. Returns None if the input is empty or yields nothing usable (never panics).
#[allow(dead_code)]
pub(crate) fn extract_binary_path(cmdline: &str) -> Option<String> {
    extract_binary_path_with(cmdline, |name| std::env::var(name).ok())
}

/// Pure core: like `extract_binary_path` but the env lookup is injected, so it is
/// deterministic and testable without mutating the process environment. `lookup` returns
/// the value for an env var name, or None if undefined.
#[allow(dead_code)]
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
#[allow(dead_code)]
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

/// Normalize a Windows service binary path to an absolute drive path so it can be located
/// on disk for signature verification. Handles the non-absolute ImagePath formats that
/// Windows services use:
/// - `\SystemRoot\system32\x.sys`  -> `<windir>\system32\x.sys`
/// - `System32\drivers\x.sys`      -> `<windir>\System32\drivers\x.sys` (relative to windir)
/// - `\??\C:\Windows\...\x.sys`    -> `C:\Windows\...\x.sys` (strip the NT object-manager prefix)
/// - `C:\already\absolute.exe`     -> unchanged
///
/// `windir` is injected (e.g. `C:\Windows`) so this is deterministic and Linux-testable.
/// Matching is case-insensitive for the known prefixes. Never panics.
#[allow(dead_code)]
fn normalize_service_path(path: &str, windir: &str) -> String {
    let windir = windir.trim_end_matches(['\\', '/']);
    // \??\  NT object path prefix -> strip it (rest is already an absolute drive path)
    if let Some(rest) = strip_prefix_ci(path, r"\??\") {
        return rest.to_string();
    }
    // \SystemRoot\...  -> <windir>\...
    if let Some(rest) = strip_prefix_ci(path, r"\SystemRoot\") {
        return format!(r"{windir}\{rest}");
    }
    // %SystemRoot%\... (occasionally seen) -> <windir>\...
    if let Some(rest) = strip_prefix_ci(path, r"%SystemRoot%\") {
        return format!(r"{windir}\{rest}");
    }
    // Already absolute (drive letter like C:\ or a UNC \\server\) -> unchanged
    let is_drive_abs = path.len() >= 2 && path.as_bytes()[1] == b':';
    let is_unc = path.starts_with(r"\\");
    if is_drive_abs || is_unc {
        return path.to_string();
    }
    // Otherwise treat as relative to windir (e.g. System32\drivers\x.sys).
    // Strip any leading backslash so we don't produce a double backslash.
    let rel = path.trim_start_matches(['\\', '/']);
    format!(r"{windir}\{rel}")
}

/// Case-insensitive prefix strip: if `s` starts with `prefix` ignoring ASCII case, return
/// the remainder; else None.
#[allow(dead_code)]
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Build a PersistenceRecord with the deferred fields (signed/sha256) as None.
#[allow(dead_code)]
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

/// Startup folders: per-user (%APPDATA%) and All Users (%PROGRAMDATA%) Startup dirs.
/// Reads the real process env; delegates to the testable core. Read-only.
fn read_startup_folders() -> Vec<PersistenceRecord> {
    let rel = r"Microsoft\Windows\Start Menu\Programs\Startup";
    let dirs: Vec<String> = ["APPDATA", "PROGRAMDATA"]
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .map(|base| format!(r"{base}\{rel}"))
        .collect();
    read_startup_dirs(&dirs)
}

/// Pure core: scan the given Startup directories for files, each -> a `startup`
/// PersistenceRecord. Injectable for testing (no env, no fixed paths). Best-effort:
/// an unreadable dir is skipped; `desktop.ini` (folder metadata) is ignored. Never panics.
fn read_startup_dirs(dirs: &[String]) -> Vec<PersistenceRecord> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // is_file() follows symlinks: a shortcut to a real file counts; a broken
            // symlink (missing target) returns false and is skipped — correct, since a
            // dangling shortcut cannot execute as persistence.
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let last_write = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(chrono::DateTime::<chrono::Utc>::from);
            let full = path.to_string_lossy().to_string();
            // A startup item's path is a FILE path (often a .lnk), not a command line, so
            // we do NOT run it through extract_binary_path (which would clip at the first
            // space in "Start Menu"). binary_path is the file path verbatim; resolving a
            // .lnk to its real target is deferred (S2-D shortcut parsing).
            out.push(PersistenceRecord {
                mechanism: "startup".to_string(),
                location: dir.clone(),
                value: Some(name),
                command: Some(full.clone()),
                binary_path: Some(full),
                binary_sha256: None,
                signed: None,
                last_write,
            });
        }
    }
    out
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
    use super::{extract_binary_path, make_record, normalize_service_path, PersistenceRecord};
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
                out.push(make_record("ifeo", location, Some(name), Some(dbg), lw));
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
            // Preserve the raw ImagePath as `command` (forensic fidelity); derive a normalized
            // binary_path so service paths like `System32\drivers\x.sys` or `\SystemRoot\...`
            // resolve to a real file for signature verification.
            let windir = std::env::var("SystemRoot")
                .or_else(|_| std::env::var("windir"))
                .unwrap_or_else(|_| r"C:\Windows".to_string());
            let bin = extract_binary_path(&image)
                .map(|p| normalize_service_path(&p, &windir));
            out.push(PersistenceRecord {
                mechanism: "service".to_string(),
                location,
                value: Some(name),
                command: Some(image),
                binary_path: bin,
                binary_sha256: None,
                signed: None,
                last_write: lw,
            });
        }
        out
    }
}

/// A verifier that never verifies (always None). Cross-platform default + test default; on
/// non-Windows it is also what the real collector uses (no WinTrust off-Windows).
#[allow(dead_code)]
pub struct NoopVerifier;
impl FileVerifier for NoopVerifier {
    fn verify(&self, _path: &str) -> Option<bool> {
        None
    }
}

/// Fill each record's `signed` from the verifier, for records that have a binary_path.
/// Pure wiring (no OS code); the verifier abstracts the platform. A binary_path of None is
/// left untouched (signed stays None).
fn apply_signatures(records: &mut [PersistenceRecord], verifier: &dyn FileVerifier) {
    for r in records.iter_mut() {
        if let Some(p) = r.binary_path.as_deref() {
            r.signed = verifier.verify(p);
        }
    }
}

/// Collector for live persistence mechanisms (SRS §4 persist_collector). Read-only.
/// Fans in the five mechanism readers; each is best-effort. Fills `signed` via the
/// injected verifier (the WinTrust seam stays in cairn-collectors-win).
pub struct PersistCollector {
    verifier: Box<dyn FileVerifier + Send + Sync>,
}

impl Default for PersistCollector {
    fn default() -> Self {
        #[cfg(windows)]
        let verifier: Box<dyn FileVerifier + Send + Sync> =
            Box::new(cairn_collectors_win::signature::WinSigVerifier);
        #[cfg(not(windows))]
        let verifier: Box<dyn FileVerifier + Send + Sync> = Box::new(NoopVerifier);
        Self { verifier }
    }
}

impl PersistCollector {
    /// Construct with a specific verifier (tests inject a fake; non-default callers).
    pub fn with_verifier(verifier: Box<dyn FileVerifier + Send + Sync>) -> Self {
        Self { verifier }
    }
}

impl Collector for PersistCollector {
    fn name(&self) -> &str {
        "persist"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let mut records: Vec<PersistenceRecord> = Vec::new();
        records.extend(read_run_keys());
        records.extend(read_services());
        records.extend(read_winlogon());
        records.extend(read_ifeo());
        records.extend(read_startup_folders());
        apply_signatures(&mut records, self.verifier.as_ref());
        Ok(records.into_iter().map(Record::Persistence).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "persistence".into(),
            path: "live:registry+startup".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(), // a live registry/folder read is not a byte stream (spec §5)
            errors: vec![],
        }]
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

    #[test]
    fn startup_dirs_reads_files_and_skips_desktop_ini() {
        // Lay out a temp dir like a Startup folder; pass it explicitly (no env mutation).
        let tmp = std::env::temp_dir().join(format!("cairn_s2c_startup_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("evil.lnk"), b"x").unwrap();
        std::fs::write(tmp.join("desktop.ini"), b"x").unwrap();

        let dirs = vec![tmp.to_string_lossy().to_string()];
        let recs = read_startup_dirs(&dirs);

        let _ = std::fs::remove_dir_all(&tmp);

        assert!(
            recs.iter()
                .any(|r| r.value.as_deref() == Some("evil.lnk") && r.mechanism == "startup"),
            "evil.lnk should be a startup record"
        );
        assert!(
            !recs
                .iter()
                .any(|r| r.value.as_deref() == Some("desktop.ini")),
            "desktop.ini must be skipped"
        );
        // a nonexistent dir is best-effort skipped, no panic
        assert!(read_startup_dirs(&["C:\\does\\not\\exist\\cairn".into()]).is_empty());
    }

    #[test]
    fn startup_binary_path_not_clipped_on_spaces() {
        // A startup dir whose path contains spaces (like the real "Start Menu" path) must
        // yield a binary_path equal to the full file path, not a clipped first-token.
        let tmp = std::env::temp_dir().join(format!("cairn_s2c_spaces_{} dir", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("app.lnk"), b"x").unwrap();
        let dirs = vec![tmp.to_string_lossy().to_string()];
        let recs = read_startup_dirs(&dirs);
        let _ = std::fs::remove_dir_all(&tmp);
        let r = recs
            .iter()
            .find(|r| r.value.as_deref() == Some("app.lnk"))
            .expect("record");
        let bp = r.binary_path.as_deref().expect("binary_path");
        assert!(
            bp.ends_with("app.lnk"),
            "binary_path must be the full path, got {bp}"
        );
        assert!(
            bp.contains(' '),
            "the space in the dir name must be preserved, got {bp}"
        );
    }

    use cairn_core::record::Record;
    use cairn_core::traits::{CollectCtx, Collector, FileVerifier};
    use cairn_core::Config;

    /// A verifier that maps known paths to a fixed result; unknown -> None.
    struct FakeVerifier(std::collections::HashMap<String, bool>);
    impl FileVerifier for FakeVerifier {
        fn verify(&self, path: &str) -> Option<bool> {
            self.0.get(path).copied()
        }
    }

    /// apply_signatures fills `signed` from the verifier for records that have a binary_path.
    #[test]
    fn collect_fills_signed_from_verifier() {
        let mut map = std::collections::HashMap::new();
        map.insert(r"C:\trusted\a.exe".to_string(), true);
        map.insert(r"C:\evil\b.exe".to_string(), false);
        let verifier = FakeVerifier(map);

        let mk = |name: &str, bin: Option<&str>| PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKLM\\...\\Run".into(),
            value: Some(name.into()),
            command: bin.map(|b| b.to_string()),
            binary_path: bin.map(|b| b.to_string()),
            binary_sha256: None,
            signed: None,
            last_write: None,
        };
        let mut records = vec![
            mk("a", Some(r"C:\trusted\a.exe")),
            mk("b", Some(r"C:\evil\b.exe")),
            mk("c", Some(r"C:\unknown\c.exe")),
            mk("d", None),
        ];
        apply_signatures(&mut records, &verifier);
        assert_eq!(records[0].signed, Some(true));
        assert_eq!(records[1].signed, Some(false));
        assert_eq!(records[2].signed, None); // verifier didn't know it
        assert_eq!(records[3].signed, None); // no binary_path -> not queried
    }

    #[test]
    fn normalize_service_path_handles_all_formats() {
        let windir = r"C:\Windows";
        // already absolute -> unchanged
        assert_eq!(
            normalize_service_path(r"C:\Program Files\App\app.exe", windir),
            r"C:\Program Files\App\app.exe"
        );
        // relative to windir
        assert_eq!(
            normalize_service_path(r"System32\drivers\3ware.sys", windir),
            r"C:\Windows\System32\drivers\3ware.sys"
        );
        // \SystemRoot\ prefix (case-insensitive)
        assert_eq!(
            normalize_service_path(r"\SystemRoot\system32\DRIVERS\aehd.sys", windir),
            r"C:\Windows\system32\DRIVERS\aehd.sys"
        );
        assert_eq!(
            normalize_service_path(r"\systemroot\System32\x.sys", windir),
            r"C:\Windows\System32\x.sys"
        );
        // \??\ NT path prefix -> stripped
        assert_eq!(
            normalize_service_path(r"\??\C:\WINDOWS\system32\drivers\AsIO3.sys", windir),
            r"C:\WINDOWS\system32\drivers\AsIO3.sys"
        );
        // %SystemRoot% variable form
        assert_eq!(
            normalize_service_path(r"%SystemRoot%\system32\svc.exe", windir),
            r"C:\Windows\system32\svc.exe"
        );
        // windir with trailing slash is handled (no double slash)
        assert_eq!(
            normalize_service_path(r"System32\x.sys", r"C:\Windows\"),
            r"C:\Windows\System32\x.sys"
        );
    }

    #[test]
    fn normalize_service_path_never_panics_on_edge_cases() {
        let windir = r"C:\Windows";
        assert_eq!(normalize_service_path("", windir), r"C:\Windows\");
        assert_eq!(normalize_service_path(r"\??\", windir), "");
        // a lone backslash-prefixed relative path
        assert_eq!(normalize_service_path(r"\System32\x.sys", windir), r"C:\Windows\System32\x.sys");
    }

    /// PersistCollector.collect returns only Persistence records, never panics, name="persist".
    /// On Windows it exercises the real readers; on non-Windows it gets the startup reader +
    /// empty registry stubs. Either way every record is a Persistence variant.
    #[test]
    fn persist_collector_collects_without_panicking() {
        let c = PersistCollector::default();
        assert_eq!(c.name(), "persist");
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let recs = c.collect(&ctx).expect("collect");
        assert!(recs.iter().all(|r| matches!(r, Record::Persistence(_))));
        assert_eq!(c.sources().len(), 1);
        assert_eq!(c.sources()[0].artifact, "persistence");
        assert_eq!(c.sources()[0].method, "api");
    }
}
