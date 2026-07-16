//! Reads a target process's full command line via its PEB (Process Environment
//! Block), using OpenProcess(PROCESS_VM_READ) + ReadProcessMemory.
//!
//! Why: DFIR triage needs the exact command line an attacker invoked (e.g. full
//! PowerShell -EncodedCommand payload), not just the process image name — this is
//! the single largest source of parentchild/persist heuristic signal (see
//! crates/cairn-heur/src/parentchild.rs).
//!
//! Guarantee: read-only. PROCESS_VM_READ carries no write capability; this module
//! never calls WriteProcessMemory or any handle-modifying API. Failures abstain
//! (return None) rather than guess (NFR12) — see cairn/CLAUDE.md golden rule 8.

use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessBasicInformation, ProcessWow64Information,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

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

/// Upper bound on a UNICODE_STRING.Length we will trust before allocating a
/// read buffer — the value lives in the target's (potentially adversarial)
/// memory, so it must be capped before use (mirrors volume.rs::MAX_READ).
const MAX_CMDLINE_BYTES: usize = 32 * 1024;

/// True if `pid` is a WOW64 (32-bit-on-64-bit) process. On query failure,
/// conservatively returns `true` (abstain) rather than risk misreading a
/// 32-bit PEB layout as a 64-bit one.
fn is_wow64(handle: HANDLE) -> bool {
    let mut wow64_peb: usize = 0;
    // SAFETY: handle valid; wow64_peb is a valid out-param; ProcessWow64Information
    // on a 64-bit build returns the WOW64 PEB address (non-zero) or 0 if native.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessWow64Information,
            &mut wow64_peb as *mut usize as *mut core::ffi::c_void,
            std::mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status.is_err() {
        return true; // abstain-safe default
    }
    wow64_peb != 0
}

/// Read an entire `T` from `pid`'s address space at `addr` via a single
/// ReadProcessMemory call. Returns None on any failure or short read — never
/// interprets a partial/uninitialized `T`.
fn read_remote_struct<T: Default>(handle: HANDLE, addr: *const core::ffi::c_void) -> Option<T> {
    let mut out = T::default();
    let mut bytes_read: usize = 0;
    let size = std::mem::size_of::<T>();
    // SAFETY: handle valid; `out` is a local T with `size` bytes reserved;
    // bytes_read out-param checked below for a partial-read short-circuit.
    unsafe {
        ReadProcessMemory(
            handle,
            addr,
            &mut out as *mut T as *mut core::ffi::c_void,
            size,
            Some(&mut bytes_read as *mut usize),
        )
    }
    .ok()?;
    if bytes_read != size {
        return None;
    }
    Some(out)
}

/// Best-effort full command line for `pid`, via PEB -> RTL_USER_PROCESS_PARAMETERS
/// -> CommandLine (three chained ReadProcessMemory calls into the target's address
/// space). None on ANY failure at ANY step (target exited mid-read, WOW64 mismatch,
/// oversized/corrupt UNICODE_STRING.Length, partial read) — never guesses from a
/// partial result. Read-only: PROCESS_VM_READ cannot modify the target (rule 1).
pub(crate) fn read_cmdline(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    }
    .ok()?;
    let guard = ProcHandle(handle);

    if is_wow64(guard.0) {
        return None; // native-width only; abstain on bitness mismatch (NFR12)
    }

    let pbi: PROCESS_BASIC_INFORMATION = {
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        // SAFETY: guard.0 valid; pbi is a valid out-param sized correctly.
        let status = unsafe {
            NtQueryInformationProcess(
                guard.0,
                ProcessBasicInformation,
                &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut core::ffi::c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status.is_err() {
            return None;
        }
        pbi
    };
    if pbi.PebBaseAddress.is_null() {
        return None;
    }

    // Step 1: read the entire PEB struct (not a hand-computed offset) so
    // ProcessParameters is accessed via the crate's own field layout.
    let peb: windows::Win32::System::Threading::PEB =
        read_remote_struct(guard.0, pbi.PebBaseAddress as *const core::ffi::c_void)?;
    let params_ptr = peb.ProcessParameters;
    if params_ptr.is_null() {
        return None;
    }

    // Step 2: read the entire RTL_USER_PROCESS_PARAMETERS struct, then take
    // its CommandLine field (a UNICODE_STRING: Length in bytes + a remote pointer).
    let params: windows::Win32::System::Threading::RTL_USER_PROCESS_PARAMETERS =
        read_remote_struct(guard.0, params_ptr as *const core::ffi::c_void)?;
    let cmdline_us = params.CommandLine;

    if cmdline_us.Length as usize > MAX_CMDLINE_BYTES {
        return None; // adversarial/corrupt Length; abstain rather than OOM (NFR9)
    }
    if cmdline_us.Length == 0 || cmdline_us.Buffer.is_null() {
        return None;
    }

    // Step 3: read the actual UTF-16LE command-line bytes.
    let byte_len = cmdline_us.Length as usize;
    let mut buf = vec![0u16; byte_len.div_ceil(2)];
    let mut bytes_read: usize = 0;
    // SAFETY: guard.0 valid; buf sized to hold byte_len bytes; bytes_read
    // out-param checked below for a partial-read short-circuit.
    unsafe {
        ReadProcessMemory(
            guard.0,
            cmdline_us.Buffer.0 as *const core::ffi::c_void,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            byte_len,
            Some(&mut bytes_read as *mut usize),
        )
    }
    .ok()?;
    if bytes_read != byte_len {
        return None; // partial read: treat as failure, never truncate-and-guess
    }

    let s = String::from_utf16_lossy(&buf);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
