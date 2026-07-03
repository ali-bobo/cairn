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
                    // WTS active/connected interactive sessions; refine type later.
                    logon_type: if s.client_address.is_some() {
                        "RemoteInteractive".into()
                    } else {
                        "Interactive".into()
                    },
                    logon_time: None, // WTS has no reliable logon timestamp; honest None
                    source: s.client_address,
                    session_id: Some(s.session_id),
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_name_is_logon_session() {
        assert_eq!(LogonSessionCollector.name(), "logon_session");
    }
}
