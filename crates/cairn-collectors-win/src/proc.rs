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
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
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
                integrity_raw: None,
                signed: None,
                user: None,
                start_time: None,
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
}
