//! Lower this process's own CPU + IO priority so Cairn yields to production
//! workloads on a live host. Best-effort and benign (golden rules 1 & 8).

use cairn_core::Result;

/// Lower the current process's CPU and IO priority (below-normal + background mode).
///
/// Best-effort: if the OS denies the call (e.g. a sandbox or restricted token),
/// returns `Err(CairnError::Collector {...})` rather than panicking. The caller
/// should log the error and continue — this is governance advisory, not a hard
/// requirement (CLAUDE.md golden rule 8: graceful degrade).
///
/// Non-Windows: no live host to yield to on an analyst's box — no-op `Ok(())`.
#[cfg(not(windows))]
pub fn lower_priority() -> Result<()> {
    // No live host to yield to on an analyst's non-Windows box. No-op success.
    Ok(())
}

/// Windows implementation: two-step priority reduction.
///
/// Step 1 (`BELOW_NORMAL_PRIORITY_CLASS`): CPU scheduling drops below normal
/// processes but above idle. Enough to avoid starving the production workload.
///
/// Step 2 (`PROCESS_MODE_BACKGROUND_BEGIN`): Windows background processing mode
/// lowers BOTH CPU priority further AND IO priority, so disk reads from raw-volume
/// collectors (`\\.\C:`) do not contend with I/O-bound production processes.
///
/// Both steps check the return value; either failure propagates as an error so the
/// caller can log it and decide whether to abort or continue at normal priority.
#[cfg(windows)]
pub fn lower_priority() -> Result<()> {
    use cairn_core::CairnError;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS,
        PROCESS_MODE_BACKGROUND_BEGIN,
    };

    // SAFETY: GetCurrentProcess() returns a kernel pseudo-handle for the calling
    // process. This pseudo-handle must NOT be passed to CloseHandle (it is not a
    // real owned handle). SetPriorityClass only reads the handle to identify the
    // target process and does not dereference it through Rust references. No memory
    // is allocated, freed, or mutated through the handle. Lowering our OWN priority
    // requires no special privilege and modifies no host artifact (golden rules 3 & 4).
    let h = unsafe { GetCurrentProcess() };

    // Step 1: Lower CPU scheduling class to below-normal.
    // SAFETY: h is the pseudo-handle from GetCurrentProcess() (see above).
    // BELOW_NORMAL_PRIORITY_CLASS is a well-known constant (PROCESS_CREATION_FLAGS
    // newtype, value 16384). SetPriorityClass returns a windows_core::Result<()>.
    unsafe { SetPriorityClass(h, BELOW_NORMAL_PRIORITY_CLASS) }.map_err(|e| {
        CairnError::Collector {
            collector: "priority".into(),
            reason: format!("SetPriorityClass(BELOW_NORMAL): {e}"),
        }
    })?;

    // Step 2: Enter background IO mode (also reduces IO priority for this process).
    // SAFETY: h is the pseudo-handle from GetCurrentProcess() (see above).
    // PROCESS_MODE_BACKGROUND_BEGIN is a well-known constant (PROCESS_CREATION_FLAGS
    // newtype, value 1048576). This call is idempotent if already in background mode.
    unsafe { SetPriorityClass(h, PROCESS_MODE_BACKGROUND_BEGIN) }.map_err(|e| {
        CairnError::Collector {
            collector: "priority".into(),
            reason: format!("SetPriorityClass(BACKGROUND_BEGIN): {e}"),
        }
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::lower_priority;

    #[test]
    fn lower_priority_succeeds_or_degrades_without_panic() {
        // On every platform the call must return without panicking. On non-Windows
        // it is a no-op Ok; on Windows it lowers the calling process's priority and
        // returns Ok on success. We assert it does not panic and yields a Result.
        let r = lower_priority();
        // We do not assert Ok unconditionally on Windows CI (a sandbox could deny
        // it); the contract is "never panic, return a Result". A non-Windows build
        // MUST be Ok.
        #[cfg(not(windows))]
        assert!(r.is_ok(), "non-Windows lower_priority must be a no-op Ok");
        #[cfg(windows)]
        let _ = r; // Windows: success not guaranteed in all sandboxes; no panic is the contract.
    }
}
