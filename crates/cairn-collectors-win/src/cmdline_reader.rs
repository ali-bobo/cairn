//! Reads a target process's full command line via
//! `NtQueryInformationProcess(ProcessCommandLineInformation)`.
//!
//! Why: DFIR triage needs the exact command line an attacker invoked (e.g. full
//! PowerShell -EncodedCommand payload), not just the process image name — this is
//! the single largest source of parentchild/persist heuristic signal (see
//! crates/cairn-heur/src/parentchild.rs).
//!
//! Guarantee: no cross-process memory access. The kernel copies the command line
//! into OUR buffer; the handle only needs PROCESS_QUERY_LIMITED_INFORMATION
//! (Windows 8.1+). An earlier version opened every process — lsass.exe included —
//! with PROCESS_VM_READ and walked the PEB with ReadProcessMemory, which is the
//! textbook credential-dumping access pattern EDRs alert on (T1003.001). This
//! version never requests PROCESS_VM_READ. Failures abstain (return None) rather
//! than guess (NFR12) — see cairn/CLAUDE.md golden rule 8. This module does not
//! open or close process handles itself — see proc.rs::enumerate.

use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{HANDLE, UNICODE_STRING};

/// `ProcessCommandLineInformation` (PROCESSINFOCLASS 60, Windows 8.1+). Returns a
/// UNICODE_STRING header followed by the command-line characters, all inside the
/// caller's buffer.
const PROCESS_COMMAND_LINE_INFORMATION: PROCESSINFOCLASS = PROCESSINFOCLASS(60);

/// Upper bound on the buffer we will allocate for one command line. Windows caps a
/// command line at 32,767 UTF-16 units; anything larger is corrupt — abstain (NFR9).
const MAX_CMDLINE_BYTES: usize = 64 * 1024 + std::mem::size_of::<UNICODE_STRING>();

/// Best-effort full command line for an already-open process handle. None on any
/// failure (access denied, process exited, oversized or inconsistent result) — never
/// guesses from a partial result.
///
/// Caller contract: `handle` MUST have been opened with at least
/// PROCESS_QUERY_LIMITED_INFORMATION. This function does not open or close the
/// handle — the caller (proc.rs::enumerate) owns its lifetime.
pub(crate) fn read_cmdline(handle: HANDLE) -> Option<String> {
    // First call with an empty buffer to learn the required size.
    let mut needed: u32 = 0;
    // SAFETY: handle valid (caller contract); a null buffer with length 0 is the
    // documented size-probe form; `needed` is a valid out-param.
    let _ = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let needed = needed as usize;
    if needed < std::mem::size_of::<UNICODE_STRING>() || needed > MAX_CMDLINE_BYTES {
        return None;
    }

    // u64 backing store keeps the UNICODE_STRING header (pointer-sized field) aligned.
    let mut buf = vec![0u64; needed.div_ceil(8)];
    let buf_bytes = buf.len() * 8;
    let mut written: u32 = 0;
    // SAFETY: handle valid; buf is a writable, 8-byte-aligned allocation of buf_bytes
    // bytes that outlives the call; `written` is a valid out-param.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf_bytes as u32,
            &mut written,
        )
    };
    if status.is_err() {
        return None;
    }

    // SAFETY: on success the buffer starts with an initialized UNICODE_STRING; the
    // allocation is at least size_of::<UNICODE_STRING>() bytes (checked above) and
    // 8-byte aligned.
    let header: UNICODE_STRING = unsafe { std::ptr::read(buf.as_ptr() as *const UNICODE_STRING) };
    let len = header.Length as usize;
    if len == 0 || header.Buffer.is_null() {
        return None;
    }

    // The kernel points Buffer inside OUR allocation. Verify that before reading, so a
    // malformed result can never make us read outside memory we own.
    let base = buf.as_ptr() as usize;
    let start = header.Buffer.0 as usize;
    let end = start.checked_add(len)?;
    if start < base || end > base + buf_bytes || !len.is_multiple_of(2) || !start.is_multiple_of(2)
    {
        return None;
    }

    // SAFETY: [start, end) lies inside `buf` and `start` is 2-byte aligned (both
    // checked above), so it is a valid, initialized run of u16 units we own.
    let units = unsafe { std::slice::from_raw_parts(start as *const u16, len / 2) };
    let s = String::from_utf16_lossy(units);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
