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
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
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

    /// Best-effort full image path for a pid via OpenProcess + QueryFullProcessImageNameW.
    /// Returns None if the process cannot be opened (privilege / exited / pid 0 = System
    /// Idle, which always fails OpenProcess — expected and handled) or the query fails.
    /// Never panics. Read-only: QUERY_LIMITED_INFORMATION cannot modify the target.
    fn full_image_path(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately in the
        // guard. bInheritHandle=false; QUERY_LIMITED_INFORMATION is read-only.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let guard = ProcHandle(handle);

        // First attempt with MAX_PATH; grow once on insufficient buffer.
        for cap in [260usize, 32768usize] {
            let mut buf = vec![0u16; cap];
            let mut len = cap as u32;
            // SAFETY: guard.0 is a valid handle; buf has `cap` u16 slots; len is in/out
            // (capacity in, chars-written out). On success the API guarantees len <= cap
            // (the path + NUL fit), so the `&buf[..len]` slice below is always in-bounds.
            let r = unsafe {
                QueryFullProcessImageNameW(
                    guard.0,
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

    /// Best-effort token integrity RID for a pid. Returns None on any failure
    /// (privilege / pid 0 / exited process) — never panics. Read-only: TOKEN_QUERY
    /// cannot modify the target.
    fn read_integrity(pid: u32) -> Option<u32> {
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
        // QUERY_LIMITED_INFORMATION is sufficient to open a token for TOKEN_QUERY.
        let proc_handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let proc_guard = ProcHandle(proc_handle);

        let mut token = HANDLE::default();
        // SAFETY: proc_guard.0 valid; token is an out-param written only on success.
        unsafe { OpenProcessToken(proc_guard.0, TOKEN_QUERY, &mut token) }.ok()?;
        let token_guard = TokenHandle(token);

        // Two-stage size probe: first call with a null buffer to learn the required
        // size, which GetTokenInformation always reports via the out-param even
        // though the probe call itself returns an error.
        let mut len: u32 = 0;
        // SAFETY: null buffer + 0 size is the documented probe form; return value
        // intentionally ignored (probe always "fails" with the required size in `len`).
        unsafe {
            let _ = GetTokenInformation(token_guard.0, TokenIntegrityLevel, None, 0, &mut len);
        }
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: buf sized to the probed `len`; token_guard.0 valid; out len re-passed.
        unsafe {
            GetTokenInformation(
                token_guard.0,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                len,
                &mut len,
            )
        }
        .ok()?;

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

    /// Best-effort process creation time via GetProcessTimes. None on any failure
    /// (privilege / exited process) or on an all-zero FILETIME (no real timestamp).
    /// Never panics. Read-only: QUERY_LIMITED_INFORMATION cannot modify the target.
    fn read_start_time(pid: u32) -> Option<super::DateTime<super::Utc>> {
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let guard = ProcHandle(handle);

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: guard.0 valid; all four out-params are valid mutable FILETIME refs
        // owned by this stack frame for the duration of the call.
        unsafe { GetProcessTimes(guard.0, &mut creation, &mut exit, &mut kernel, &mut user) }
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
            // Prefer the full image path (for signature verification downstream); fall back
            // to the Toolhelp file name when the process can't be opened (privilege/exited).
            let image = full_image_path(entry.th32ProcessID).unwrap_or(file_name);
            out.push(RawProc {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                image,
                cmdline: None,
                integrity_raw: read_integrity(entry.th32ProcessID),
                signed: None,
                user: None,
                start_time: read_start_time(entry.th32ProcessID),
            });
            // SAFETY: snap.0 valid; entry reused per the Toolhelp iteration contract.
            if unsafe { Process32NextW(snap.0, &mut entry) }.is_err() {
                break;
            }
        }
        Ok(out)
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
}
