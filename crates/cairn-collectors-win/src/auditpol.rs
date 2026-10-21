//! Advanced audit policy query (`AuditQuerySystemPolicy`), read-only.
//!
//! This reads the effective system audit policy for a few subcategories, the same data
//! `auditpol /get` prints, without spawning a process. The call needs
//! `SeSecurityPrivilege` enabled in the caller's token (an elevated admin holds it,
//! disabled). When the first call fails with `ERROR_PRIVILEGE_NOT_HELD`, the privilege
//! is enabled on THIS process's own token and the query is retried once. That changes
//! nothing on the host: it is the same step `auditpol.exe` takes, and the token dies
//! with the process. Nothing is ever set (`AuditSetSystemPolicy` is never called).
//!
//! Off Windows, [`query`] returns an "unsupported platform" error.

/// Subcategory GUIDs (`auditpol /list /subcategory:* /v`), as `u128`.
pub mod subcategory {
    /// Detailed Tracking \ Process Creation (Security 4688).
    pub const PROCESS_CREATION: u128 = 0x0CCE922B_69AE_11D9_BED3_505054503030;
    /// Logon/Logoff \ Logon (4624, 4625).
    pub const LOGON: u128 = 0x0CCE9215_69AE_11D9_BED3_505054503030;
    /// Object Access \ Other Object Access Events (4698 scheduled task created).
    pub const OTHER_OBJECT_ACCESS: u128 = 0x0CCE9227_69AE_11D9_BED3_505054503030;
    /// Account Management \ User Account Management (4720, 4722, 4724, 4726, 4738).
    pub const USER_ACCOUNT_MANAGEMENT: u128 = 0x0CCE9235_69AE_11D9_BED3_505054503030;
    /// Account Management \ Security Group Management (4728, 4732, 4756).
    pub const SECURITY_GROUP_MANAGEMENT: u128 = 0x0CCE9237_69AE_11D9_BED3_505054503030;
}

/// What one subcategory audits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditSetting {
    pub success: bool,
    pub failure: bool,
}

/// Decode `AUDIT_POLICY_INFORMATION.AuditingInformation`
/// (`POLICY_AUDIT_EVENT_SUCCESS` = 1, `POLICY_AUDIT_EVENT_FAILURE` = 2).
pub fn decode(auditing_information: u32) -> AuditSetting {
    AuditSetting {
        success: auditing_information & 1 != 0,
        failure: auditing_information & 2 != 0,
    }
}

/// The setting of each subcategory, in input order. Err carries the Win32 failure.
#[cfg(not(windows))]
pub fn query(_subcategories: &[u128]) -> Result<Vec<AuditSetting>, String> {
    Err("AuditQuerySystemPolicy: unsupported platform".into())
}

/// The setting of each subcategory, in input order. Err carries the Win32 failure.
#[cfg(windows)]
pub fn query(subcategories: &[u128]) -> Result<Vec<AuditSetting>, String> {
    if subcategories.is_empty() {
        return Ok(Vec::new());
    }
    match win::query_once(subcategories) {
        Err(code) if code == win::ERROR_PRIVILEGE_NOT_HELD => {
            win::enable_security_privilege()?;
            win::query_once(subcategories).map_err(win::describe)
        }
        other => other.map_err(win::describe),
    }
}

#[cfg(windows)]
mod win {
    use super::{decode, AuditSetting};
    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
    use windows::Win32::Security::Authentication::Identity::{
        AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION,
    };
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;

    pub fn describe(code: u32) -> String {
        match code {
            5 => "AuditQuerySystemPolicy: access denied (Win32 error 5)".into(),
            ERROR_PRIVILEGE_NOT_HELD => {
                "AuditQuerySystemPolicy: SeSecurityPrivilege not held (Win32 error 1314)".into()
            }
            c => format!("AuditQuerySystemPolicy failed (Win32 error {c})"),
        }
    }

    /// RAII guard over the AuditQuerySystemPolicy output buffer.
    /// INVARIANT: `0` is the non-null pointer the API returned; freed once with AuditFree.
    struct AuditBuf(*mut AUDIT_POLICY_INFORMATION);
    impl Drop for AuditBuf {
        fn drop(&mut self) {
            // SAFETY: self.0 was allocated by AuditQuerySystemPolicy and is freed once.
            unsafe { AuditFree(self.0 as *const core::ffi::c_void) }
        }
    }

    /// One query; Err(win32 error code) on failure.
    pub fn query_once(subcategories: &[u128]) -> Result<Vec<AuditSetting>, u32> {
        let guids: Vec<GUID> = subcategories.iter().map(|g| GUID::from_u128(*g)).collect();
        let mut out: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
        // SAFETY: `guids` is a valid slice for the call's duration; on success the API
        // writes a pointer to `guids.len()` AUDIT_POLICY_INFORMATION entries into `out`.
        let ok = unsafe { AuditQuerySystemPolicy(&guids, &mut out) };
        if !ok || out.is_null() {
            // SAFETY: plain thread-local error read right after the failing call.
            return Err(unsafe { GetLastError() }.0);
        }
        let buf = AuditBuf(out);
        // SAFETY: on success `buf.0` points to exactly `guids.len()` initialized entries,
        // valid until AuditFree (the guard outlives this slice).
        let entries = unsafe { std::slice::from_raw_parts(buf.0, guids.len()) };
        Ok(entries
            .iter()
            .map(|e| decode(e.AuditingInformation))
            .collect())
    }

    /// RAII guard: a token HANDLE closed on drop.
    /// INVARIANT: `0` is a valid token handle from OpenProcessToken; closed once.
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid handle opened below; closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Enable SeSecurityPrivilege on this process's own token (if the token holds it).
    pub fn enable_security_privilege() -> Result<(), String> {
        let mut handle = HANDLE::default();
        // SAFETY: pseudo-handle of the current process; the opened token handle is
        // wrapped in the guard immediately.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut handle,
            )
            .map_err(|e| format!("OpenProcessToken: {e}"))?;
        }
        let token = TokenHandle(handle);
        let name: Vec<u16> = "SeSecurityPrivilege"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut luid = LUID::default();
        // SAFETY: `name` is NUL-terminated UTF-16; the API writes the LUID.
        unsafe {
            LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &mut luid)
                .map_err(|e| format!("LookupPrivilegeValueW(SeSecurityPrivilege): {e}"))?;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: token.0 is valid and opened with TOKEN_ADJUST_PRIVILEGES; `tp` is a
        // fully initialized single-entry TOKEN_PRIVILEGES; no previous state requested.
        unsafe {
            AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None)
                .map_err(|e| format!("AdjustTokenPrivileges(SeSecurityPrivilege): {e}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_reads_success_and_failure_bits() {
        assert_eq!(decode(0), AuditSetting::default());
        assert_eq!(
            decode(1),
            AuditSetting {
                success: true,
                failure: false
            }
        );
        assert_eq!(
            decode(3),
            AuditSetting {
                success: true,
                failure: true
            }
        );
        // POLICY_AUDIT_EVENT_NONE (4) alone: nothing audited.
        assert_eq!(decode(4), AuditSetting::default());
    }

    #[test]
    fn process_creation_guid_is_the_documented_one() {
        assert_eq!(
            format!("{:032X}", subcategory::PROCESS_CREATION),
            "0CCE922B69AE11D9BED3505054503030"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn query_off_windows_is_an_error_not_a_panic() {
        assert!(query(&[subcategory::PROCESS_CREATION]).is_err());
    }
}
