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
pub fn must_not_probe(path: &str) -> bool {
    is_remote_path(path) || is_device_path(path)
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
        }
    }
}
