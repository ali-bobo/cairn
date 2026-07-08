//! Live logon-session enumeration via WTS (WTSEnumerateSessions). Read-only, official
//! API, EDR-visible (golden rule 1/3). The single unsafe surface stays behind a safe
//! wrapper returning owned plain data.

/// Owned, WinAPI-free view of one interactive logon session.
#[derive(Debug, Clone)]
pub struct WtsSession {
    pub session_id: u32,
    pub user: String,
    pub state_active: bool,
    /// Client IP address for network/RDP sessions, when available. Best-effort:
    /// if address parsing isn't straightforward for this session, honestly None
    /// rather than a wrong value.
    pub client_address: Option<String>,
    /// The session's WinStation name (e.g. "Console" for the local interactive
    /// session, "RDP-Tcp#N" for an RDP session). This is the reliable, officially
    /// observable way to tell local vs. remote sessions apart -- unlike
    /// `client_address` (byte layout unverifiable, see above), the station name is
    /// a plain null-terminated string with no ambiguous parsing involved.
    pub station_name: Option<String>,
}

/// Non-Windows: empty (the live WTS path is Windows-only).
#[cfg(not(windows))]
pub fn enumerate_sessions() -> Vec<WtsSession> {
    vec![]
}

/// Windows: enumerate interactive logon sessions. Best-effort: on any API failure
/// returns an empty Vec (the collector wrapper turns "no data" into a graceful skip).
/// Never panics. Sessions with no resolvable username (e.g. the services/listener
/// session-0 slot) are skipped -- they're not "someone using the host."
#[cfg(windows)]
pub fn enumerate_sessions() -> Vec<WtsSession> {
    win::enumerate_sessions()
}

#[cfg(windows)]
mod win {
    use super::WtsSession;
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
        WTS_SESSION_INFOW,
    };

    /// RAII guard for the buffer WTSEnumerateSessionsW allocates.
    /// INVARIANT: holds a non-null pointer returned by WTSEnumerateSessionsW; freed
    /// exactly once via WTSFreeMemory on drop.
    struct SessionInfoBuf(*mut WTS_SESSION_INFOW);
    impl Drop for SessionInfoBuf {
        fn drop(&mut self) {
            // SAFETY: self.0 is the exact pointer WTSEnumerateSessionsW returned; the
            // API contract requires freeing it with WTSFreeMemory exactly once.
            unsafe {
                WTSFreeMemory(self.0 as *mut core::ffi::c_void);
            }
        }
    }

    /// RAII guard for a WTSQuerySessionInformationW buffer.
    /// INVARIANT: holds a non-null pointer returned by WTSQuerySessionInformationW;
    /// freed exactly once via WTSFreeMemory on drop.
    struct QueryBuf(windows::core::PWSTR);
    impl Drop for QueryBuf {
        fn drop(&mut self) {
            // SAFETY: self.0 is the exact pointer WTSQuerySessionInformationW returned;
            // the API contract requires freeing it with WTSFreeMemory exactly once.
            unsafe {
                WTSFreeMemory(self.0.as_ptr() as *mut core::ffi::c_void);
            }
        }
    }

    /// Best-effort username for a session id via WTSQuerySessionInformationW(WTSUserName).
    /// Returns None if the query fails or the returned string is empty (e.g. session 0,
    /// the non-interactive services session, has no user).
    fn session_user(session_id: u32) -> Option<String> {
        let mut ptr = windows::core::PWSTR::null();
        let mut len: u32 = 0;
        // SAFETY: hserver=None targets the local server (documented local-server form,
        // same convention as WTSEnumerateSessionsW below); ptr/len are out-params the
        // API fills on success. On error the API does not allocate, so no free is owed.
        let ok = unsafe {
            WTSQuerySessionInformationW(None, session_id, WTSUserName, &mut ptr, &mut len)
        };
        if ok.is_err() || ptr.is_null() {
            return None;
        }
        let guard = QueryBuf(ptr);
        // SAFETY: guard.0 is non-null and was just filled by WTSQuerySessionInformationW,
        // which null-terminates the returned string.
        let s = unsafe { guard.0.to_string() }.ok()?;
        let trimmed = s.trim_end_matches('\0');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    pub fn enumerate_sessions() -> Vec<WtsSession> {
        let mut ptr: *mut WTS_SESSION_INFOW = core::ptr::null_mut();
        let mut count: u32 = 0;
        // SAFETY: hserver=None is the documented way to target the local RD Session Host
        // server; reserved=0 and version=1 are the fixed values the API requires.
        // ptr/count are out-params the API fills on success; on error it does not
        // allocate, so there is nothing to free in that branch.
        let ok = unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut ptr, &mut count) };
        if ok.is_err() || ptr.is_null() {
            return vec![];
        }
        let guard = SessionInfoBuf(ptr);

        // SAFETY: guard.0 is non-null and the API guarantees `count` contiguous
        // WTS_SESSION_INFOW entries starting there.
        let entries = unsafe { std::slice::from_raw_parts(guard.0, count as usize) };

        entries
            .iter()
            .filter_map(|e| {
                let user = session_user(e.SessionId)?;
                // pWinStationName points into the same buffer WTSEnumerateSessionsW
                // allocated (freed once by SessionInfoBuf on drop); it is not a
                // separately-allocated string, so no extra WTSFreeMemory is owed here.
                // Still null-checked before reading, matching session_user's guard --
                // WTSEnumerateSessionsW is documented to populate this field for every
                // session, but a defensive check costs nothing and avoids UB on wcslen.
                let station_name = if e.pWinStationName.is_null() {
                    None
                } else {
                    // SAFETY: just checked non-null; the API null-terminates the string.
                    unsafe { e.pWinStationName.to_string() }
                        .ok()
                        .filter(|s| !s.is_empty())
                };
                Some(WtsSession {
                    session_id: e.SessionId,
                    user,
                    state_active: e.State == WTSActive,
                    // Byte layout of WTS_CLIENT_ADDRESS.Address for IPv4 (which offset
                    // within the 20-byte field holds the address) could not be verified
                    // against an authoritative source in this environment. Guessing risks
                    // silently producing a wrong IP, so we honestly abstain (NFR12-style:
                    // never guess, abstain instead) rather than parse it.
                    client_address: None,
                    station_name,
                })
            })
            .collect()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Smoke test: enumeration runs without panicking. Contents vary per host/session
    /// (e.g. CI runners may have zero interactive users), so we only prove the FFI path
    /// is total and any returned session has sane shape.
    #[test]
    fn enumerate_sessions_without_panicking() {
        let sessions = enumerate_sessions();
        for s in sessions.iter() {
            assert!(!s.user.is_empty());
            let _: u32 = s.session_id;
        }
    }
}
