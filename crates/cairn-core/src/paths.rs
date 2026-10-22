//! Pure Windows-path classification shared by every crate that opens or stats a path
//! taken from host data (registry values, task XML, process images, LNK targets).
//!
//! Paths in persistence entries and command lines are attacker-controlled. Opening,
//! hashing or even `exists()`-probing a UNC path (`\\server\share\x.exe`) makes an
//! outbound SMB connection: it can stall a collector for minutes, and Windows answers
//! the server's challenge with this host's NTLM credentials, so a planted entry could
//! harvest the operator's (often admin) hash. Device-namespace paths (`\\.\pipe\x`,
//! `\\.\PhysicalDrive0`) are not files at all, and opening one can block. Neither is
//! ever probed: callers check [`must_not_probe`] first and treat such a path as
//! "could not verify" (None), which is what an unreachable file already yields.

/// True when `path` names a network location: a UNC path (`\\server\share\...`,
/// `//server/share/...`) or its verbatim form (`\\?\UNC\server\share\...`).
pub fn is_remote_path(path: &str) -> bool {
    let p = path.trim_start_matches(['"', ' ']);
    if let Some(rest) = strip_prefix_ci(p, r"\\?\UNC\") {
        return !rest.is_empty();
    }
    let b = p.as_bytes();
    let sep = |c: u8| c == b'\\' || c == b'/';
    if b.len() < 3 || !sep(b[0]) || !sep(b[1]) {
        return false;
    }
    // `\\?\` (verbatim) and `\\.\` (device) are local namespaces, not servers.
    !(matches!(b[2], b'?' | b'.') && b.get(3).is_some_and(|c| sep(*c)))
}

/// True when `path` is in the Win32 device namespace (`\\.\...`) or the NT object
/// namespace (`\\?\GLOBALROOT\...`, `\??\...`): pipes, raw disks and other devices that
/// must never be opened as if they were files.
pub fn is_device_path(path: &str) -> bool {
    let p = path.trim_start_matches(['"', ' ']);
    p.starts_with(r"\\.\")
        || p.starts_with("//./")
        || p.starts_with(r"\??\")
        || strip_prefix_ci(p, r"\\?\GLOBALROOT").is_some()
}

/// True when a collector must not open, stat or hash `path`: it is remote or a device.
/// A drive letter mapped to a network share (`Z:\x.exe` after `net use Z: \\srv\s`)
/// is remote too, but only the host knows which letters are mapped: collectors use
/// [`must_not_probe_with`] with the host's drive-type check
/// (`cairn_collectors_win::drive::must_not_probe`).
pub fn must_not_probe(path: &str) -> bool {
    is_remote_path(path) || is_device_path(path)
}

/// [`must_not_probe`], plus: the path's drive letter is one `remote_drive` reports as
/// a network drive. `remote_drive` is asked only for a drive-letter path.
pub fn must_not_probe_with(path: &str, remote_drive: impl Fn(char) -> bool) -> bool {
    must_not_probe(path) || drive_letter(path).is_some_and(remote_drive)
}

/// The drive letter (upper-cased) of a drive path: `C:\x`, `c:/x`, `C:x`, `C:`, a
/// quoted `"C:\x" -arg`, or the verbatim `\\?\C:\x`. None for UNC, device, relative
/// and empty paths.
pub fn drive_letter(path: &str) -> Option<char> {
    let p = path.trim_start_matches(['"', ' ']);
    let p = strip_prefix_ci(p, r"\\?\")
        .or_else(|| p.strip_prefix("//?/"))
        .unwrap_or(p);
    let b = p.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        .then(|| char::from(b[0].to_ascii_uppercase()))
}

/// The volume a Windows path lives on: `C:` (upper-cased) for a drive path, or
/// `\\SERVER\SHARE` for a UNC path; the `\\?\` / `\\?\UNC\` verbatim prefixes are
/// understood. None when the path names no volume (relative). Pure string logic so it
/// is testable off Windows.
pub fn volume_of(path: &str) -> Option<String> {
    let p = path.trim();
    let (p, unc) = if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        (rest, true)
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        (rest, false)
    } else if let Some(rest) = p.strip_prefix(r"\\") {
        (rest, true)
    } else {
        (p, false)
    };
    if unc {
        let mut parts = p.split(['\\', '/']).filter(|s| !s.is_empty());
        let server = parts.next()?;
        let share = parts.next()?;
        return Some(format!(r"\\{}\{}", server, share).to_uppercase());
    }
    let b = p.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        .then(|| p[..2].to_ascii_uppercase())
}

/// True when `output` is on the same volume as `system_root` (%SystemRoot%), i.e.
/// evidence would be written onto the disk under investigation.
pub fn on_system_drive(output: &std::path::Path, system_root: &str) -> bool {
    match (
        volume_of(&output.display().to_string()),
        volume_of(system_root),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unc_paths_are_remote() {
        for p in [
            r"\\attacker\share\evil.exe",
            r"\\10.0.0.5\c$\x.dll",
            "//server/share/x.exe",
            r"\\?\UNC\srv\share\x.exe",
            r"\\?\unc\srv\share\x.exe",
            r#""\\srv\share\x.exe" -arg"#,
            r"\\srv@SSL\DavWWWRoot\x.exe",
        ] {
            assert!(is_remote_path(p), "{p}");
            assert!(must_not_probe(p), "{p}");
        }
    }

    #[test]
    fn drive_letters_of_every_spelling() {
        for (p, want) in [
            (r"C:\Windows\x.exe", Some('C')),
            ("z:/share/x.exe", Some('Z')),
            (r#""Z:\Tools\x.exe" -a"#, Some('Z')),
            (r"\\?\Z:\x.exe", Some('Z')),
            ("Y:", Some('Y')),
            (r"\\srv\share\x.exe", None),
            (r"\\.\pipe\x", None),
            (r"\??\C:\x", None),
            ("relative.exe", None),
            ("", None),
            ("1:\\x", None),
            ("é:", None),
        ] {
            assert_eq!(drive_letter(p), want, "{p}");
        }
    }

    /// A mapped network drive is never probed; a local drive letter, or a host that
    /// reports no remote drives, changes nothing.
    #[test]
    fn mapped_network_drive_is_not_probed() {
        let z_is_remote = |c: char| c == 'Z';
        assert!(must_not_probe_with(r"Z:\Tools\evil.exe", z_is_remote));
        assert!(must_not_probe_with(r#""z:\x.dll",Entry"#, z_is_remote));
        assert!(!must_not_probe_with(r"C:\Windows\x.exe", z_is_remote));
        assert!(!must_not_probe_with(r"Z:\x.exe", |_| false));
        // UNC / device paths stay blocked whatever the drive check says.
        assert!(must_not_probe_with(r"\\srv\s\x.exe", |_| false));
        assert!(must_not_probe_with(r"\\.\pipe\x", |_| false));
        // The drive check is not consulted for a path without a drive letter.
        assert!(!must_not_probe_with("relative.exe", |_| panic!("asked")));
    }

    #[test]
    fn local_paths_are_not_remote() {
        for p in [
            r"C:\Windows\System32\svchost.exe",
            r"\\?\C:\Windows\x.exe",
            "relative.exe",
            "",
            r"\\",
            r"\",
            "C:",
        ] {
            assert!(!is_remote_path(p), "{p}");
        }
        assert!(!must_not_probe(r"C:\x.exe"));
        assert!(!must_not_probe(r"\\?\C:\x.exe"));
    }

    #[test]
    fn device_paths_are_never_probed() {
        for p in [
            r"\\.\pipe\evil",
            r"\\.\PhysicalDrive0",
            "//./pipe/x",
            r"\??\C:\x.exe",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\x",
        ] {
            assert!(is_device_path(p), "{p}");
            assert!(!is_remote_path(p), "{p}");
            assert!(must_not_probe(p), "{p}");
        }
    }

    #[test]
    fn volume_of_drive_unc_and_verbatim_paths() {
        assert_eq!(volume_of(r"c:\Tools\cairn\output"), Some("C:".into()));
        assert_eq!(volume_of(r"\\?\D:\cairn\output"), Some("D:".into()));
        assert_eq!(volume_of(r"\\srv\share\cairn"), Some(r"\\SRV\SHARE".into()));
        assert_eq!(
            volume_of(r"\\?\UNC\srv\share\x"),
            Some(r"\\SRV\SHARE".into())
        );
        assert_eq!(volume_of("output"), None);
    }

    #[test]
    fn system_drive_detection() {
        assert!(on_system_drive(
            std::path::Path::new(r"C:\Users\a\Desktop\cairn\output"),
            r"C:\WINDOWS"
        ));
        assert!(!on_system_drive(
            std::path::Path::new(r"E:\cairn\output"),
            r"C:\Windows"
        ));
        assert!(!on_system_drive(
            std::path::Path::new("relative"),
            r"C:\Windows"
        ));
    }

    /// Never panics on odd input (multi-byte chars at the prefix boundary).
    #[test]
    fn odd_input_does_not_panic() {
        for p in [
            "\\\\?\\UN文",
            "文字",
            "\\\\文\\x",
            "\\\\?",
            "\u{0}\u{0}\u{0}",
        ] {
            let _ = must_not_probe(p);
            let _ = volume_of(p);
        }
    }
}
