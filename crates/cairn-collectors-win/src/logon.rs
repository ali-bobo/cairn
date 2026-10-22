//! Live logon-session enumeration: WTS (WTSEnumerateSessions: who sits at which
//! session, connection state, RDP client address) and LSA (LsaEnumerateLogonSessions +
//! LsaGetLogonSessionData: logon type, logon time, logon server, for interactive,
//! RDP, network and service logons). Read-only, official APIs, EDR-visible (golden
//! rule 1/3). The unsafe surface stays behind safe wrappers returning owned plain data;
//! the joining of the two views lives in cairn-collectors::logon_session (pure).

/// Owned, WinAPI-free view of one WTS session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtsSession {
    pub session_id: u32,
    pub user: String,
    pub state_active: bool,
    /// Raw WTS_CONNECTSTATE_CLASS value; see [`wts_state_label`].
    pub state_raw: i32,
    /// Client IP address for RDP sessions (WTSClientAddress), when the session has one.
    pub client_address: Option<String>,
    /// The session's WinStation name (e.g. "Console", "RDP-Tcp#N"). A DISCONNECTED RDP
    /// session loses its "RDP-Tcp#N" station name, so this alone cannot identify it as
    /// remote; see `protocol_type`.
    pub station_name: Option<String>,
    /// WTSClientProtocolType: 0 = console, 1 = ICA, 2 = RDP. Kept for disconnected
    /// sessions, so it is the reliable "was this an RDP session" signal.
    pub protocol_type: Option<u16>,
}

/// Owned view of one LSA logon session (SECURITY_LOGON_SESSION_DATA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaSession {
    /// LUID as `(HighPart << 32) | LowPart`.
    pub logon_id: u64,
    /// The WTS session id this logon belongs to (0 for services / network logons).
    pub session_id: u32,
    pub user: String,
    pub domain: String,
    /// Raw SECURITY_LOGON_TYPE; see [`logon_type_label`].
    pub logon_type_raw: u32,
    /// LogonTime as a FILETIME (100 ns since 1601); 0 / negative when unknown.
    pub logon_time_raw: i64,
    pub logon_server: Option<String>,
    pub auth_package: Option<String>,
}

/// WTS_CONNECTSTATE_CLASS -> lowercase label. Pure.
pub fn wts_state_label(state: i32) -> &'static str {
    match state {
        0 => "active",
        1 => "connected",
        2 => "connect_query",
        3 => "shadow",
        4 => "disconnected",
        5 => "idle",
        6 => "listen",
        7 => "reset",
        8 => "down",
        9 => "init",
        _ => "unknown",
    }
}

/// WTS_CONNECTSTATE_CLASS value of WTSDisconnected.
pub const WTS_DISCONNECTED: i32 = 4;

/// SECURITY_LOGON_TYPE -> the label used in `LogonSessionRecord.logon_type`. Pure.
pub fn logon_type_label(t: u32) -> String {
    match t {
        2 => "Interactive".into(),
        3 => "Network".into(),
        4 => "Batch".into(),
        5 => "Service".into(),
        6 => "Proxy".into(),
        7 => "Unlock".into(),
        8 => "NetworkCleartext".into(),
        9 => "NewCredentials".into(),
        10 => "RemoteInteractive".into(),
        11 => "CachedInteractive".into(),
        12 => "CachedRemoteInteractive".into(),
        13 => "CachedUnlock".into(),
        other => format!("LogonType{other}"),
    }
}

/// Parse a WTS_CLIENT_ADDRESS. Per the WTS_CLIENT_ADDRESS documentation the IP address
/// starts at offset 2 of `Address` (AF_INET: bytes 2..6, AF_INET6: bytes 2..18). None for
/// other families or an all-zero address. Pure.
pub fn parse_wts_client_address(family: u32, address: &[u8; 20]) -> Option<String> {
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    match family {
        AF_INET => {
            let b = &address[2..6];
            if b.iter().all(|&x| x == 0) {
                return None;
            }
            Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
        }
        AF_INET6 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&address[2..18]);
            if a.iter().all(|&x| x == 0) {
                return None;
            }
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}

/// Non-Windows: empty (the live WTS path is Windows-only).
#[cfg(not(windows))]
pub fn enumerate_sessions() -> Vec<WtsSession> {
    vec![]
}

/// Windows: enumerate WTS sessions. Best-effort: on any API failure returns an empty Vec.
/// Never panics. Sessions with no resolvable username (e.g. the services/listener
/// session-0 slot) are skipped -- they're not "someone using the host."
#[cfg(windows)]
pub fn enumerate_sessions() -> Vec<WtsSession> {
    win::enumerate_sessions()
}

/// Non-Windows: no LSA; reported as an error so the caller falls back to WTS only.
#[cfg(not(windows))]
pub fn enumerate_lsa_sessions() -> Result<Vec<LsaSession>, String> {
    Err("LSA logon sessions: unsupported platform".into())
}

/// Windows: enumerate LSA logon sessions. Err (with the NTSTATUS) only when the session
/// list itself cannot be read; a session whose data cannot be read (access denied for
/// another user's logon when not elevated, or a logon that ended mid-enumeration) is
/// skipped. Never panics.
#[cfg(windows)]
pub fn enumerate_lsa_sessions() -> Result<Vec<LsaSession>, String> {
    win::enumerate_lsa_sessions()
}

#[cfg(windows)]
mod win {
    use super::{parse_wts_client_address, LsaSession, WtsSession};
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Security::Authentication::Identity::{
        LsaEnumerateLogonSessions, LsaFreeReturnBuffer, LsaGetLogonSessionData, LSA_UNICODE_STRING,
        SECURITY_LOGON_SESSION_DATA,
    };
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSClientAddress, WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName, WTS_CLIENT_ADDRESS, WTS_INFO_CLASS,
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

    /// RAII guard for an LSA-allocated buffer.
    /// INVARIANT: holds a non-null pointer returned by LsaEnumerateLogonSessions or
    /// LsaGetLogonSessionData; freed exactly once via LsaFreeReturnBuffer on drop.
    struct LsaBuf(*const core::ffi::c_void);
    impl Drop for LsaBuf {
        fn drop(&mut self) {
            // SAFETY: self.0 is the exact LSA-allocated pointer (see invariant).
            unsafe {
                let _ = LsaFreeReturnBuffer(self.0);
            }
        }
    }

    /// One WTSQuerySessionInformationW call. Returns the owned buffer guard and its byte
    /// length, or None on failure / null buffer.
    fn query(session_id: u32, class: WTS_INFO_CLASS) -> Option<(QueryBuf, u32)> {
        let mut ptr = windows::core::PWSTR::null();
        let mut len: u32 = 0;
        // SAFETY: hserver=None targets the local server; ptr/len are out-params the API
        // fills on success. On error the API does not allocate, so no free is owed.
        let ok =
            unsafe { WTSQuerySessionInformationW(None, session_id, class, &mut ptr, &mut len) };
        if ok.is_err() || ptr.is_null() {
            return None;
        }
        Some((QueryBuf(ptr), len))
    }

    /// Best-effort username for a session id (WTSUserName). None if empty (session 0).
    fn session_user(session_id: u32) -> Option<String> {
        let (guard, _) = query(session_id, WTSUserName)?;
        // SAFETY: guard.0 is non-null and NUL-terminated by WTSQuerySessionInformationW.
        let s = unsafe { guard.0.to_string() }.ok()?;
        let trimmed = s.trim_end_matches('\0');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// WTSClientProtocolType (a USHORT).
    fn session_protocol(session_id: u32) -> Option<u16> {
        let (guard, len) = query(session_id, WTSClientProtocolType)?;
        if (len as usize) < std::mem::size_of::<u16>() {
            return None;
        }
        // SAFETY: the buffer holds at least 2 bytes (checked); read_unaligned avoids any
        // alignment assumption about the API allocation.
        Some(unsafe { std::ptr::read_unaligned(guard.0.as_ptr() as *const u16) })
    }

    /// WTSClientAddress, parsed by the pure `parse_wts_client_address`.
    fn session_client_address(session_id: u32) -> Option<String> {
        let (guard, len) = query(session_id, WTSClientAddress)?;
        if (len as usize) < std::mem::size_of::<WTS_CLIENT_ADDRESS>() {
            return None;
        }
        // SAFETY: the buffer holds a full WTS_CLIENT_ADDRESS (size checked above);
        // read_unaligned copies it out without alignment assumptions.
        let a: WTS_CLIENT_ADDRESS =
            unsafe { std::ptr::read_unaligned(guard.0.as_ptr() as *const WTS_CLIENT_ADDRESS) };
        parse_wts_client_address(a.AddressFamily, &a.Address)
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
                // allocated (freed once by SessionInfoBuf on drop); null-checked first.
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
                    state_raw: e.State.0,
                    client_address: session_client_address(e.SessionId),
                    station_name,
                    protocol_type: session_protocol(e.SessionId),
                })
            })
            .collect()
    }

    /// Owned copy of an LSA_UNICODE_STRING (Length is in BYTES). None if empty/null.
    fn lsa_string(s: &LSA_UNICODE_STRING) -> Option<String> {
        if s.Buffer.is_null() || s.Length == 0 {
            return None;
        }
        // SAFETY: Buffer is non-null and points at Length bytes (Length/2 UTF-16 units)
        // inside the LSA buffer, which the caller keeps alive (LsaBuf) during this call.
        let units = unsafe { std::slice::from_raw_parts(s.Buffer.0, (s.Length / 2) as usize) };
        let out = String::from_utf16_lossy(units);
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    pub fn enumerate_lsa_sessions() -> Result<Vec<LsaSession>, String> {
        let mut count: u32 = 0;
        let mut list: *mut LUID = core::ptr::null_mut();
        // SAFETY: count/list are valid out-params; on success list points at `count`
        // LUIDs allocated by LSA (freed by the guard below).
        let st = unsafe { LsaEnumerateLogonSessions(&mut count, &mut list) };
        if st.is_err() {
            return Err(format!(
                "LsaEnumerateLogonSessions NTSTATUS=0x{:08X}",
                st.0 as u32
            ));
        }
        if list.is_null() {
            return Ok(vec![]);
        }
        let list_guard = LsaBuf(list as *const core::ffi::c_void);
        // SAFETY: list is non-null and holds `count` contiguous LUIDs (API contract).
        let luids =
            unsafe { std::slice::from_raw_parts(list_guard.0 as *const LUID, count as usize) };

        let mut out = Vec::with_capacity(luids.len());
        for luid in luids {
            let mut data: *mut SECURITY_LOGON_SESSION_DATA = core::ptr::null_mut();
            // SAFETY: luid points into the live LSA list; data is a valid out-param.
            let st = unsafe { LsaGetLogonSessionData(luid, &mut data) };
            if st.is_err() || data.is_null() {
                continue; // access denied / session ended: skip this one quietly
            }
            let data_guard = LsaBuf(data as *const core::ffi::c_void);
            // SAFETY: data is non-null and points at a SECURITY_LOGON_SESSION_DATA that
            // stays valid until data_guard drops at the end of this iteration.
            let d = unsafe { &*(data_guard.0 as *const SECURITY_LOGON_SESSION_DATA) };
            let Some(user) = lsa_string(&d.UserName) else {
                continue;
            };
            out.push(LsaSession {
                logon_id: ((d.LogonId.HighPart as u32 as u64) << 32) | d.LogonId.LowPart as u64,
                session_id: d.Session,
                user,
                domain: lsa_string(&d.LogonDomain).unwrap_or_default(),
                logon_type_raw: d.LogonType,
                logon_time_raw: d.LogonTime,
                logon_server: lsa_string(&d.LogonServer),
                auth_package: lsa_string(&d.AuthenticationPackage),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_wts_states() {
        assert_eq!(wts_state_label(0), "active");
        assert_eq!(wts_state_label(WTS_DISCONNECTED), "disconnected");
        assert_eq!(wts_state_label(99), "unknown");
    }

    #[test]
    fn labels_logon_types() {
        assert_eq!(logon_type_label(2), "Interactive");
        assert_eq!(logon_type_label(3), "Network");
        assert_eq!(logon_type_label(5), "Service");
        assert_eq!(logon_type_label(10), "RemoteInteractive");
        assert_eq!(logon_type_label(42), "LogonType42");
    }

    #[test]
    fn parses_wts_client_addresses() {
        let mut a = [0u8; 20];
        a[2..6].copy_from_slice(&[10, 0, 0, 5]);
        assert_eq!(parse_wts_client_address(2, &a).as_deref(), Some("10.0.0.5"));
        let mut b = [0u8; 20];
        b[2] = 0x20;
        b[3] = 0x01;
        b[4] = 0x0d;
        b[5] = 0xb8;
        b[17] = 1;
        assert_eq!(
            parse_wts_client_address(23, &b).as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_wts_client_address(2, &[0u8; 20]), None);
        assert_eq!(parse_wts_client_address(0, &a), None);
    }
}

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;

    /// Smoke test: enumeration runs without panicking (contents vary per host).
    #[test]
    fn enumerate_sessions_without_panicking() {
        for s in enumerate_sessions().iter() {
            assert!(!s.user.is_empty());
        }
    }

    /// LSA enumeration works for an ordinary user (at least our own logon is visible).
    #[test]
    fn lsa_sessions_enumerate() {
        let sessions = enumerate_lsa_sessions().expect("LsaEnumerateLogonSessions");
        assert!(
            !sessions.is_empty(),
            "expected at least our own logon session"
        );
    }
}
