//! Privilege probe: which rights does this process hold? (manifest.privileges, SRS §11)
use cairn_core::manifest::Privileges;

/// Probe the current process token for the rights the collectors care about.
/// Non-Windows: no Windows privileges exist, so everything is false (graceful).
#[cfg(not(windows))]
pub fn probe() -> Privileges {
    Privileges {
        admin: false,
        se_backup: false,
        se_debug: false,
    }
}

/// Windows: query the process token. Any failure degrades to false rather than
/// panicking — a probe that can't read its own token still lets the run continue.
#[cfg(windows)]
pub fn probe() -> Privileges {
    Privileges {
        admin: win::is_elevated().unwrap_or(false),
        se_backup: win::has_privilege("SeBackupPrivilege").unwrap_or(false),
        se_debug: win::has_privilege("SeDebugPrivilege").unwrap_or(false),
    }
}

#[cfg(windows)]
mod win {
    use cairn_core::{CairnError, Result};
    use windows::core::{BOOL, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        GetTokenInformation, LookupPrivilegeValueW, PrivilegeCheck, TokenElevation,
        LUID_AND_ATTRIBUTES, PRIVILEGE_SET, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// PRIVILEGE_SET_ALL_NECESSARY (winnt.h) — inlined to avoid pulling the whole
    /// Win32_System_SystemServices feature for one constant. Value is stable (== 1).
    const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;

    /// RAII guard: a token HANDLE that is always closed on drop.
    /// INVARIANT: `0` holds a valid, open token handle obtained from OpenProcessToken;
    /// Drop closes it exactly once. Never construct with an invalid handle.
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is a valid handle opened in `open_token`; closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn open_token() -> Result<TokenHandle> {
        let mut handle = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; we request TOKEN_QUERY and
        // receive an owned token handle in `handle`, wrapped immediately in the guard.
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle).map_err(|e| {
                CairnError::Collector {
                    collector: "privilege".into(),
                    reason: format!("OpenProcessToken: {e}"),
                }
            })?;
        }
        Ok(TokenHandle(handle))
    }

    /// True if the process token is elevated (admin).
    pub fn is_elevated() -> Result<bool> {
        let token = open_token()?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        // SAFETY: token.0 is valid; we pass a correctly sized TOKEN_ELEVATION buffer and
        // its byte length; GetTokenInformation fills it.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            )
            .map_err(|e| CairnError::Collector {
                collector: "privilege".into(),
                reason: format!("GetTokenInformation(elevation): {e}"),
            })?;
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    /// True if the named privilege (e.g. "SeBackupPrivilege") is present+enabled.
    pub fn has_privilege(name: &str) -> Result<bool> {
        let token = open_token()?;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = LUID::default();
        // SAFETY: wide is a valid NUL-terminated UTF-16 string; LookupPrivilegeValueW
        // writes the LUID for a known privilege name.
        unsafe {
            LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid).map_err(
                |e| CairnError::Collector {
                    collector: "privilege".into(),
                    reason: format!("LookupPrivilegeValueW({name}): {e}"),
                },
            )?;
        }
        let mut set = PRIVILEGE_SET {
            PrivilegeCount: 1,
            Control: PRIVILEGE_SET_ALL_NECESSARY,
            Privilege: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: Default::default(),
            }],
        };
        let mut result = BOOL::default();
        // SAFETY: token.0 valid; set is a correctly initialized single-entry set.
        unsafe {
            PrivilegeCheck(token.0, &mut set, &mut result).map_err(|e| CairnError::Collector {
                collector: "privilege".into(),
                reason: format!("PrivilegeCheck({name}): {e}"),
            })?;
        }
        Ok(result.as_bool())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// probe() never panics and returns a Privileges struct on any platform.
    #[test]
    fn probe_returns_without_panicking() {
        let p = probe();
        // On a non-elevated CI/dev run these are typically false; we only assert the
        // call is total (no panic) and yields the three fields.
        let _ = (p.admin, p.se_backup, p.se_debug);
    }
}
