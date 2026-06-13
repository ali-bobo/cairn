//! Authenticode signature verification via WinTrust (WinVerifyTrust). Read-only: opens the
//! file only to verify its embedded signature; never writes. This is a NORMAL call to the
//! public verification API — not signing, hooking, or trust-provider patching (golden rule 1).
//!
//! `verify_file` is total (never panics, never errors): an unverifiable file yields None.
//! Mirrors the host.rs FFI pattern (non-Windows stub + cfg(windows) mod win + SAFETY notes).
use cairn_core::traits::FileVerifier;

/// Verify a file's embedded Authenticode signature.
/// - `Some(true)`  = WinVerifyTrust returned ERROR_SUCCESS (trusted).
/// - `Some(false)` = unsigned or untrusted (any non-zero status).
/// - `None`        = file missing / path unconvertible / off-platform (cannot verify).
#[cfg(not(windows))]
pub fn verify_file(_path: &str) -> Option<bool> {
    None
}

#[cfg(windows)]
pub fn verify_file(path: &str) -> Option<bool> {
    win::verify_file(path)
}

/// A `FileVerifier` backed by `verify_file`. The real default used on Windows.
pub struct WinSigVerifier;

impl FileVerifier for WinSigVerifier {
    fn verify(&self, path: &str) -> Option<bool> {
        verify_file(path)
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    /// Encode a path to a NUL-terminated wide string (UTF-16).
    fn wide_nul(path: &str) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn verify_file(path: &str) -> Option<bool> {
        if path.is_empty() || !std::path::Path::new(path).exists() {
            return None;
        }
        let wide = wide_nul(path);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut wtd = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        // SAFETY: Assigning a union variant is safe in Rust (only reading union fields is unsafe).
        // pFile points to `file_info` which lives for the duration of this function.
        wtd.Anonymous.pFile = &mut file_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: wtd/file_info/wide all outlive this call; pcwszFilePath points into the
        // still-owned `wide`; pFile points at the live `file_info`. Null HWND = no UI.
        let status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                std::ptr::addr_of_mut!(wtd).cast(),
            )
        };

        // MUST free the provider state (CLOSE) regardless of the status above.
        // No fallible or panicking steps between VERIFY and CLOSE, so straight-line is correct.
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut close_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: same wtd opened by VERIFY; CLOSE frees its provider state data (hWVTStateData).
        unsafe {
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut close_action,
                std::ptr::addr_of_mut!(wtd).cast(),
            );
        }

        Some(status == 0) // 0 == ERROR_SUCCESS == trusted
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_none() {
        assert_eq!(verify_file(r"C:\does\not\exist\nope.exe"), None);
    }

    #[test]
    fn unsigned_junk_is_false() {
        let p = std::env::temp_dir().join(format!("cairn_s2d_unsigned_{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ not a real signed PE, just junk bytes").unwrap();
        let got = verify_file(&p.to_string_lossy());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, Some(false), "unsigned junk must verify as not-trusted");
    }

    #[test]
    fn known_os_binary_does_not_panic() {
        let candidates = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\notepad.exe"];
        for c in candidates {
            if std::path::Path::new(c).exists() {
                let _ = verify_file(c);
                return;
            }
        }
    }

    #[test]
    fn win_verifier_delegates() {
        assert_eq!(WinSigVerifier.verify(r"C:\does\not\exist\nope.exe"), None);
    }
}
