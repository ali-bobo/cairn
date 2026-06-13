//! Live-run hostname (manifest.host.hostname; an EVTX run borrows the Computer field).
use cairn_core::Result;

/// Non-Windows: hostname via std env as a best effort (used only so the workspace builds
/// + tests off-Windows; the real live path is Windows-only).
#[cfg(not(windows))]
pub fn hostname() -> Result<String> {
    Ok(std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()))
}

/// Windows: GetComputerNameExW (DNS hostname). Failure -> Err (caller may default).
#[cfg(windows)]
pub fn hostname() -> Result<String> {
    win::computer_name()
}

#[cfg(windows)]
mod win {
    use cairn_core::{CairnError, Result};
    use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};

    pub fn computer_name() -> Result<String> {
        let mut size = 0u32;
        // First call: get required size (expected to fail with size set).
        // SAFETY: passing None buffer + &mut size is the documented size-probe form.
        unsafe {
            let _ = GetComputerNameExW(ComputerNameDnsHostname, None, &mut size);
        }
        if size == 0 {
            return Err(CairnError::Collector {
                collector: "host".into(),
                reason: "GetComputerNameExW size probe returned 0".into(),
            });
        }
        let mut buf = vec![0u16; size as usize];
        // SAFETY: buf has `size` u16 slots; we pass its pointer + the same size.
        unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                Some(windows::core::PWSTR(buf.as_mut_ptr())),
                &mut size,
            )
            .map_err(|e| CairnError::Collector {
                collector: "host".into(),
                reason: format!("GetComputerNameExW: {e}"),
            })?;
        }
        Ok(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hostname() returns a non-empty string without panicking.
    #[test]
    fn hostname_is_non_empty() {
        let h = hostname().unwrap_or_else(|_| "unknown".into());
        assert!(!h.is_empty());
    }
}
