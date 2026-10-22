//! Is a drive letter a network drive? The host half of the "never probe a remote
//! path" guard (`cairn_core::paths::must_not_probe`).
//!
//! A UNC path is recognisable from its text, a mapped drive is not: after
//! `net use Z: \\attacker\share`, a persistence entry naming `Z:\x.exe` looks local.
//! Opening, hashing or `exists()`-probing it makes the same SMB connection a UNC path
//! would (a stall of minutes, and this host's NTLM response sent to that server). So
//! every probe of a path from host data goes through [`must_not_probe`], which adds
//! this check to the pure one.
//!
//! The check is `GetDriveTypeW` on the bare drive root (`Z:\`): read-only, no handle
//! to keep, and it reports `DRIVE_REMOTE` for a mapped drive whether or not the share
//! is reachable (Explorer shows disconnected mapped drives from it). Off Windows there
//! are no drive letters to map: always false.

/// True when `letter` (any case) is a network (mapped / redirected) drive on this host.
/// False for local drives, unknown letters, non-ASCII-letter input, and off Windows.
pub fn is_remote_drive(letter: char) -> bool {
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    imp::is_remote_drive(letter.to_ascii_uppercase())
}

/// `cairn_core::paths::must_not_probe` plus the mapped-drive check: true when a
/// collector must not open, stat or hash `path` (UNC, device namespace, or a drive
/// letter mapped to a network share).
pub fn must_not_probe(path: &str) -> bool {
    cairn_core::paths::must_not_probe_with(path, is_remote_drive)
}

#[cfg(windows)]
mod imp {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;

    /// `DRIVE_REMOTE` from WinBase.h (`Win32::System::WindowsProgramming` in the
    /// `windows` crate, a feature this crate does not otherwise need).
    const DRIVE_REMOTE: u32 = 4;

    pub(super) fn is_remote_drive(letter: char) -> bool {
        // "Z:\" as a NUL-terminated UTF-16 string, built on the stack.
        let root: [u16; 4] = [letter as u16, u16::from(b':'), u16::from(b'\\'), 0];
        // SAFETY: `root` is a valid, NUL-terminated UTF-16 buffer that outlives the
        // call (it is a local array borrowed for the call only); GetDriveTypeW only
        // reads it and returns a plain integer. No handle or memory is handed back,
        // so there is nothing to release, and any failure is a return code
        // (DRIVE_UNKNOWN / DRIVE_NO_ROOT_DIR), never undefined behavior.
        let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
        kind == DRIVE_REMOTE
    }
}

#[cfg(not(windows))]
mod imp {
    pub(super) fn is_remote_drive(_letter: char) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_letters_are_never_remote() {
        for c in ['1', ':', '\\', 'é', ' '] {
            assert!(!is_remote_drive(c), "{c:?}");
        }
    }

    /// The pure guard still applies through the host wrapper on every platform.
    #[test]
    fn wrapper_keeps_the_pure_guard() {
        assert!(must_not_probe(r"\\attacker\share\x.exe"));
        assert!(must_not_probe(r"\\.\pipe\x"));
        assert!(!must_not_probe("relative.exe"));
    }

    /// Off Windows no drive letter is mapped, so a drive path is never blocked here.
    #[cfg(not(windows))]
    #[test]
    fn no_mapped_drives_off_windows() {
        assert!(!is_remote_drive('Z'));
        assert!(!must_not_probe(r"Z:\x.exe"));
    }
}
