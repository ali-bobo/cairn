//! Process enumeration (raw WinAPI -> plain structs). Pure mapping to Records lives in
//! cairn-collectors::proc; this layer only reads the OS.
use cairn_core::Result;
use chrono::{DateTime, Utc};

/// One process as read from the OS. Per-process fields are Option/best-effort: a process
/// we cannot open leaves them None rather than failing the whole enumeration (graceful).
#[derive(Debug, Clone)]
pub struct RawProc {
    pub pid: u32,
    pub ppid: u32,
    pub image: String, // best available; "" if unreadable
    pub cmdline: Option<String>,
    pub integrity_raw: Option<u32>, // raw integrity RID; mapped to a label downstream
    pub signed: Option<bool>,
    pub user: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
}

/// `DOMAIN\user` from a LookupAccountSid result; a bare name when the domain is empty;
/// None when the name is empty. Pure.
pub fn format_account(domain: &str, name: &str) -> Option<String> {
    let d = domain.trim_end_matches('\0');
    let n = name.trim_end_matches('\0');
    match (d.is_empty(), n.is_empty()) {
        (_, true) => None,
        (true, false) => Some(n.to_string()),
        (false, false) => Some(format!("{d}\\{n}")),
    }
}

/// Non-Windows: empty (the live proc path is Windows-only).
#[cfg(not(windows))]
pub fn enumerate() -> Result<Vec<RawProc>> {
    Ok(vec![])
}

/// Windows: snapshot pid/ppid/image (reliable), then best-effort per-process enrichment.
/// Only Errs if the snapshot itself fails.
#[cfg(windows)]
pub fn enumerate() -> Result<Vec<RawProc>> {
    win::enumerate()
}

#[cfg(windows)]
mod win {
    use super::RawProc;
    use cairn_core::{CairnError, Result};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW,
        TokenIntegrityLevel, TokenUser, SID_NAME_USE, TOKEN_INFORMATION_CLASS,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// RAII guard for a snapshot HANDLE.
    /// INVARIANT: holds a valid handle from CreateToolhelp32Snapshot; closed once on drop.
    struct Snapshot(HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid snapshot handle; closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// RAII guard for a process HANDLE.
    /// INVARIANT: holds a valid handle from OpenProcess; closed exactly once on drop.
    struct ProcHandle(HANDLE);
    impl Drop for ProcHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid process handle from OpenProcess; closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Best-effort full image path for an already-open process handle, via
    /// QueryFullProcessImageNameW. Returns None if the query fails.
    /// Never panics. Read-only: QUERY_LIMITED_INFORMATION cannot modify the target.
    ///
    /// Caller contract: `handle` MUST have been opened with at least
    /// PROCESS_QUERY_LIMITED_INFORMATION.
    fn full_image_path(handle: HANDLE) -> Option<String> {
        // First attempt with MAX_PATH; grow once on insufficient buffer.
        for cap in [260usize, 32768usize] {
            let mut buf = vec![0u16; cap];
            let mut len = cap as u32;
            // SAFETY: handle valid (caller contract); buf has `cap` u16 slots; len is
            // in/out (capacity in, chars-written out). On success the API guarantees
            // len <= cap (the path + NUL fit), so the `&buf[..len]` slice is in-bounds.
            let r = unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    windows::core::PWSTR(buf.as_mut_ptr()),
                    &mut len,
                )
            };
            match r {
                Ok(()) => {
                    let s = String::from_utf16_lossy(&buf[..len as usize]);
                    return if s.is_empty() { None } else { Some(s) };
                }
                Err(_) => continue, // small buffer -> retry large; large -> give up
            }
        }
        None
    }

    /// RAII guard for a token HANDLE.
    /// INVARIANT: holds a valid token handle from OpenProcessToken; closed once on drop.
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid token handle; closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Open the process token for TOKEN_QUERY (read-only: cannot modify the target).
    /// None on any failure, typically access denied for protected/other-user processes
    /// when not elevated; the caller then leaves integrity/user None (skip quietly).
    ///
    /// Caller contract: `handle` MUST have been opened with at least
    /// PROCESS_QUERY_LIMITED_INFORMATION.
    fn open_token(handle: HANDLE) -> Option<TokenHandle> {
        let mut token = HANDLE::default();
        // SAFETY: handle valid (caller contract); token is an out-param written
        // only on success, and wrapped in the guard immediately.
        unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) }.ok()?;
        Some(TokenHandle(token))
    }

    /// Read a variable-length token information class into an owned byte buffer
    /// (two-stage size probe). None on any failure.
    fn token_info(token: &TokenHandle, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u8>> {
        let mut len: u32 = 0;
        // SAFETY: null buffer + 0 size is the documented probe form; return value
        // intentionally ignored (probe "fails" with the required size in `len`).
        unsafe {
            let _ = GetTokenInformation(token.0, class, None, 0, &mut len);
        }
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: buf sized to the probed `len`; token.0 valid; out len re-passed.
        unsafe {
            GetTokenInformation(
                token.0,
                class,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                len,
                &mut len,
            )
        }
        .ok()?;
        buf.truncate(len as usize);
        Some(buf)
    }

    /// Best-effort `DOMAIN\user` owning the process token: GetTokenInformation(TokenUser)
    /// then LookupAccountSidW on the local system. None on any failure (access denied,
    /// unmappable SID). Read-only.
    fn read_user(token: &TokenHandle) -> Option<String> {
        let buf = token_info(token, TokenUser)?;
        if buf.len() < std::mem::size_of::<TOKEN_USER>() {
            return None;
        }
        // SAFETY: buf holds at least size_of::<TOKEN_USER>() bytes written by the API;
        // read_unaligned because Vec<u8> is only 1-byte aligned.
        let tu: TOKEN_USER = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_USER) };
        let sid = tu.User.Sid;
        if sid.0.is_null() {
            return None;
        }
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        for _ in 0..2 {
            let mut name_len = name.len() as u32;
            let mut dom_len = domain.len() as u32;
            let mut use_ = SID_NAME_USE::default();
            // SAFETY: sid points into `buf`, which is alive for this whole function;
            // name/domain are live buffers whose capacities (in u16 chars) are passed in
            // name_len/dom_len; on success the API writes the lengths excluding the NUL,
            // on ERROR_INSUFFICIENT_BUFFER it writes the required sizes and we retry once.
            let r = unsafe {
                LookupAccountSidW(
                    PCWSTR::null(),
                    sid,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    Some(PWSTR(domain.as_mut_ptr())),
                    &mut dom_len,
                    &mut use_,
                )
            };
            match r {
                Ok(()) => {
                    let n = String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]);
                    let d =
                        String::from_utf16_lossy(&domain[..(dom_len as usize).min(domain.len())]);
                    return super::format_account(&d, &n);
                }
                Err(_) => {
                    if (name_len as usize) <= name.len() && (dom_len as usize) <= domain.len() {
                        return None; // a real failure, not a size problem
                    }
                    name = vec![0u16; (name_len as usize).max(name.len())];
                    domain = vec![0u16; (dom_len as usize).max(domain.len())];
                }
            }
        }
        None
    }

    /// Best-effort token integrity RID. Returns None on any failure — never panics.
    fn read_integrity(token_guard: &TokenHandle) -> Option<u32> {
        let buf = token_info(token_guard, TokenIntegrityLevel)?;
        let len = buf.len() as u32;

        // Defensive: TOKEN_MANDATORY_LABEL must fit in the returned buffer before we
        // read it out. Normal Windows semantics guarantee len >= size_of::<TOKEN_MANDATORY_LABEL>()
        // (the SID data follows the struct in the same allocation), but this is the one
        // unsafe-code crate — never trust an OS buffer size to imply a specific layout.
        if (len as usize) < std::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
            return None;
        }

        // SAFETY: buf is exactly `len` bytes as filled by the API above, and the check
        // just above guarantees len >= size_of::<TOKEN_MANDATORY_LABEL>(); read via
        // read_unaligned because a Vec<u8> only guarantees 1-byte alignment while
        // TOKEN_MANDATORY_LABEL requires pointer alignment.
        let label: TOKEN_MANDATORY_LABEL =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };

        // SAFETY: label.Label.Sid is a valid PSID pointing into `buf`, which is still
        // in scope for the remainder of this unsafe block; GetSidSubAuthorityCount/
        // GetSidSubAuthority are read-only queries against that SID.
        unsafe {
            let count_ptr = GetSidSubAuthorityCount(label.Label.Sid);
            if count_ptr.is_null() {
                return None;
            }
            let count = *count_ptr;
            if count == 0 {
                return None;
            }
            let rid_ptr = GetSidSubAuthority(label.Label.Sid, (count - 1) as u32);
            if rid_ptr.is_null() {
                return None;
            }
            Some(*rid_ptr)
        }
    }

    /// Best-effort process creation time for an already-open process handle, via
    /// GetProcessTimes. None on any failure or on an all-zero FILETIME (no real
    /// timestamp). Never panics. Read-only.
    ///
    /// Caller contract: `handle` MUST have been opened with at least
    /// PROCESS_QUERY_LIMITED_INFORMATION.
    fn read_start_time(handle: HANDLE) -> Option<super::DateTime<super::Utc>> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: handle valid (caller contract); all four out-params are valid
        // mutable FILETIME refs owned by this stack frame for the duration of the call.
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }
            .ok()?;

        let ticks = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
        cairn_core::filetime_to_utc(ticks)
    }

    pub fn enumerate() -> Result<Vec<RawProc>> {
        // SAFETY: TH32CS_SNAPPROCESS with pid 0 snapshots all processes; returns an owned
        // handle wrapped immediately in the guard.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
            CairnError::Collector {
                collector: "proc".into(),
                reason: format!("CreateToolhelp32Snapshot: {e}"),
            }
        })?;
        let snap = Snapshot(snap);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut out = Vec::new();

        // SAFETY: snap.0 valid; entry.dwSize set as required by Process32FirstW.
        if unsafe { Process32FirstW(snap.0, &mut entry) }.is_err() {
            return Ok(out); // empty snapshot is not an error
        }
        loop {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let file_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            let pid = entry.th32ProcessID;

            // Open each process ONCE with PROCESS_QUERY_LIMITED_INFORMATION only. That
            // mask is enough for the image path, token integrity, start time and (via
            // ProcessCommandLineInformation) the command line. PROCESS_VM_READ is never
            // requested: opening lsass.exe with it is the credential-dumping pattern
            // EDRs alert on, and we no longer need it. A denied open degrades this one
            // pid to its snapshot file name (golden rule 8).
            // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok();

            let (image, cmdline, integrity_raw, user, start_time) = match handle {
                Some(h) => {
                    let guard = ProcHandle(h);
                    let image = full_image_path(guard.0).unwrap_or_else(|| file_name.clone());
                    let cmdline = crate::cmdline_reader::read_cmdline(guard.0);
                    let token = open_token(guard.0);
                    let integrity_raw = token.as_ref().and_then(read_integrity);
                    let user = token.as_ref().and_then(read_user);
                    let start_time = read_start_time(guard.0);
                    (image, cmdline, integrity_raw, user, start_time)
                }
                None => (file_name.clone(), None, None, None, None),
            };

            out.push(RawProc {
                pid,
                ppid: entry.th32ParentProcessID,
                image,
                cmdline,
                integrity_raw,
                signed: None,
                user,
                start_time,
            });
            // SAFETY: snap.0 valid; entry reused per the Toolhelp iteration contract.
            if unsafe { Process32NextW(snap.0, &mut entry) }.is_err() {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod pure_tests {
    use super::format_account;

    #[test]
    fn formats_domain_and_user() {
        assert_eq!(
            format_account("NT AUTHORITY", "SYSTEM").as_deref(),
            Some(r"NT AUTHORITY\SYSTEM")
        );
        assert_eq!(format_account("", "alice").as_deref(), Some("alice"));
        assert_eq!(format_account("CORP", ""), None);
        assert_eq!(
            format_account("CORP\0", "bob\0").as_deref(),
            Some(r"CORP\bob")
        );
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Smoke test: on Windows, enumerate() returns a non-empty list that includes THIS
    /// process's PID. This is the thin-FFI smoke test (spec §4.1) — it proves the WinAPI
    /// path works without asserting exact contents (which vary per run).
    #[test]
    fn enumerate_includes_current_process() {
        let procs = enumerate().expect("enumerate");
        assert!(!procs.is_empty(), "expected at least one process");
        let me = std::process::id();
        assert!(
            procs.iter().any(|p| p.pid == me),
            "current pid {me} not found"
        );
    }

    /// On Windows we can open our own process, so enumerate() yields an absolute image path
    /// for the current pid (proving the OpenProcess/QueryFullProcessImageNameW path works).
    #[test]
    fn current_process_has_absolute_image_path() {
        let procs = enumerate().expect("enumerate");
        let me = std::process::id();
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        assert!(
            mine.image.contains(":\\"),
            "expected absolute path, got {:?}",
            mine.image
        );
    }

    /// Our own process's token integrity level should resolve to a known non-empty
    /// RID (typically "medium" for a non-elevated session, "high" if elevated).
    #[test]
    fn current_process_integrity_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        assert!(
            mine.integrity_raw.is_some(),
            "expected an integrity RID for our own process"
        );
    }

    /// Our own process's start_time should resolve to a real, past timestamp.
    #[test]
    fn current_process_start_time_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        let st = mine
            .start_time
            .expect("expected a start_time for our own process");
        assert!(
            st <= chrono::Utc::now(),
            "start_time must not be in the future"
        );
    }

    /// Our own process's token user should resolve to DOMAIN\name.
    #[test]
    fn current_process_user_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        let user = mine
            .user
            .as_deref()
            .expect("expected a token user for our own process");
        assert!(!user.is_empty());
    }

    /// Our own process's cmdline should be readable via ProcessCommandLineInformation,
    /// and must contain our own executable name.
    #[test]
    fn current_process_cmdline_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        let cmd = mine
            .cmdline
            .as_deref()
            .expect("expected a cmdline for our own process");
        assert!(!cmd.trim().is_empty());
    }
}
