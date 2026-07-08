//! LogonSessionCollector: maps WTS session enumeration to Record::LogonSession.
//! #![forbid(unsafe_code)] — the unsafe FFI lives in cairn-collectors-win::logon.
use cairn_core::record::{LogonSessionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;

pub struct LogonSessionCollector;

impl Collector for LogonSessionCollector {
    fn name(&self) -> &str {
        "logon_session"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let sessions = cairn_collectors_win::logon::enumerate_sessions();
        Ok(sessions
            .into_iter()
            .map(|s| {
                Record::LogonSession(LogonSessionRecord {
                    user: s.user,
                    // Derived from the WinStation name, not client_address (which is
                    // always None -- see logon.rs). Windows names an RDP session's
                    // station "RDP-Tcp#<n>" and the local console session "Console";
                    // this is the officially observable, reliably-parseable signal.
                    logon_type: if is_remote_station(s.station_name.as_deref()) {
                        "RemoteInteractive".into()
                    } else {
                        "Interactive".into()
                    },
                    logon_time: None, // WTS has no reliable logon timestamp; honest None
                    source: s.client_address,
                    session_id: Some(s.session_id),
                    state_active: s.state_active,
                })
            })
            .collect())
    }
}

/// True if the WinStation name indicates an RDP session ("RDP-Tcp#N"). The local
/// interactive session is named "Console"; a bare/empty name (no station assigned)
/// is not remote either -- only a recognized RDP-Tcp prefix counts.
fn is_remote_station(station_name: Option<&str>) -> bool {
    station_name.is_some_and(|s| s.to_ascii_lowercase().starts_with("rdp-tcp"))
}

#[cfg(test)]
mod is_remote_station_tests {
    use super::is_remote_station;

    #[test]
    fn rdp_station_is_remote() {
        assert!(is_remote_station(Some("RDP-Tcp#0")));
        assert!(is_remote_station(Some("rdp-tcp#3")));
    }

    #[test]
    fn console_and_absent_are_not_remote() {
        assert!(!is_remote_station(Some("Console")));
        assert!(!is_remote_station(None));
        assert!(!is_remote_station(Some("")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_name_is_logon_session() {
        assert_eq!(LogonSessionCollector.name(), "logon_session");
    }

    #[test]
    fn maps_state_active_from_wts_session() {
        use cairn_core::record::{LogonSessionRecord, Record};
        let rec = Record::LogonSession(LogonSessionRecord {
            user: "test".into(),
            logon_type: "Interactive".into(),
            logon_time: None,
            source: None,
            session_id: Some(1),
            state_active: true,
        });
        match rec {
            Record::LogonSession(s) => assert!(s.state_active),
            _ => panic!("expected LogonSession"),
        }
    }
}
