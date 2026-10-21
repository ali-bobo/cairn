//! LogonSessionCollector: joins LSA logon sessions (type, time, logon server) with WTS
//! sessions (connection state, RDP client address) into Record::LogonSession.
//! #![forbid(unsafe_code)] — the unsafe FFI lives in cairn-collectors-win::logon; the
//! join here is pure and unit-tested.
use cairn_collectors_win::logon::{
    logon_type_label, wts_state_label, LsaSession, WtsSession, WTS_DISCONNECTED,
};
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{LogonSessionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;
use std::collections::HashMap;
use std::sync::Mutex;

/// Collector for live logon sessions. LSA failing (e.g. off-Windows) is not fatal: it is
/// recorded in this collector's manifest source `errors` and the WTS view is used alone.
#[derive(Default)]
pub struct LogonSessionCollector {
    errors: Mutex<Vec<String>>,
}

impl Collector for LogonSessionCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::LOGON_SESSION
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let wts = cairn_collectors_win::logon::enumerate_sessions();
        let lsa = cairn_collectors_win::logon::enumerate_lsa_sessions();
        let errors = match &lsa {
            Ok(_) => vec![],
            Err(e) => vec![format!("lsa unavailable, WTS-only view: {e}")],
        };
        if let Ok(mut slot) = self.errors.lock() {
            *slot = errors;
        }
        Ok(build_logon_records(lsa.as_deref().ok(), &wts)
            .into_iter()
            .map(Record::LogonSession)
            .collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let errors = self.errors.lock().map(|e| e.clone()).unwrap_or_default();
        vec![SourceEntry {
            collector: String::new(),
            artifact: "logon_session".into(),
            path: "live:lsa+wts".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

/// True if the WinStation name indicates an RDP session ("RDP-Tcp#N"). The local
/// interactive session is named "Console"; a bare/empty name (no station assigned)
/// is not remote either -- only a recognized RDP-Tcp prefix counts.
fn is_remote_station(station_name: Option<&str>) -> bool {
    station_name.is_some_and(|s| s.to_ascii_lowercase().starts_with("rdp-tcp"))
}

/// WTS-only remoteness: an RDP station name, or protocol type 2 (RDP). The protocol
/// type survives disconnection, the station name does not.
fn wts_is_remote(s: &WtsSession) -> bool {
    is_remote_station(s.station_name.as_deref()) || s.protocol_type == Some(2)
}

/// Logon types that belong to a desktop (WTS) session.
fn is_session_logon(t: u32) -> bool {
    matches!(t, 2 | 7 | 10 | 11 | 12 | 13)
}

/// Remote-desktop logon types (RemoteInteractive, CachedRemoteInteractive).
fn is_remote_logon(t: u32) -> bool {
    matches!(t, 10 | 12)
}

/// Per-session virtual accounts that are not people: Desktop Window Manager and the
/// User-Mode Font Driver host run one interactive logon per session.
fn is_virtual_account(domain: &str) -> bool {
    domain.eq_ignore_ascii_case("Window Manager") || domain.eq_ignore_ascii_case("Font Driver Host")
}

fn qualified(domain: &str, user: &str) -> String {
    if domain.is_empty() {
        user.to_string()
    } else {
        format!("{domain}\\{user}")
    }
}

fn lsa_time(raw: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    if raw <= 0 || raw == i64::MAX {
        return None; // 0 = unset; i64::MAX = "never"
    }
    cairn_core::filetime_to_utc(raw as u64)
}

/// Join LSA and WTS views (pure). `lsa` None means LSA was unavailable.
///
/// - Every LSA logon (minus DWM/UMFD virtual accounts) becomes a record with its logon
///   type, logon time and logon server; duplicates for the same user, type and session
///   (e.g. an admin's elevated + filtered token pair) collapse to the earliest logon.
/// - Desktop logons take connection state from their WTS session (so a disconnected RDP
///   session is RemoteInteractive with session_state "disconnected"), and remote ones take
///   the RDP client address as `source`.
/// - A WTS session no LSA desktop logon covers is emitted from WTS alone; it is labelled
///   RemoteInteractive when its station or protocol type says RDP, including when
///   disconnected.
///
/// Output order is deterministic: by session id, then user, then logon type.
pub fn build_logon_records(
    lsa: Option<&[LsaSession]>,
    wts: &[WtsSession],
) -> Vec<LogonSessionRecord> {
    let wts_by_id: HashMap<u32, &WtsSession> = wts.iter().map(|s| (s.session_id, s)).collect();
    let mut covered: Vec<u32> = Vec::new();
    let mut by_key: HashMap<(String, u32, u32), LogonSessionRecord> = HashMap::new();

    for l in lsa.unwrap_or(&[]) {
        if is_virtual_account(&l.domain) {
            continue;
        }
        let desktop = is_session_logon(l.logon_type_raw) && l.session_id != 0;
        let w = if desktop {
            wts_by_id.get(&l.session_id).copied()
        } else {
            None
        };
        if desktop && w.is_some() {
            covered.push(l.session_id);
        }
        let rec = LogonSessionRecord {
            user: qualified(&l.domain, &l.user),
            logon_type: logon_type_label(l.logon_type_raw),
            logon_time: lsa_time(l.logon_time_raw),
            source: if is_remote_logon(l.logon_type_raw) {
                w.and_then(|w| w.client_address.clone())
            } else {
                None
            },
            session_id: Some(l.session_id),
            state_active: w.is_some_and(|w| w.state_active),
            session_state: w.map(|w| wts_state_label(w.state_raw).to_string()),
            logon_server: l.logon_server.clone(),
        };
        let key = (rec.user.to_lowercase(), l.logon_type_raw, l.session_id);
        match by_key.get(&key) {
            Some(prev) if prev.logon_time.is_some() && prev.logon_time <= rec.logon_time => {}
            Some(prev) if prev.logon_time.is_some() && rec.logon_time.is_none() => {}
            _ => {
                by_key.insert(key, rec);
            }
        }
    }

    let mut out: Vec<LogonSessionRecord> = by_key.into_values().collect();
    for w in wts {
        if covered.contains(&w.session_id) {
            continue;
        }
        let remote = wts_is_remote(w);
        out.push(LogonSessionRecord {
            user: w.user.clone(),
            logon_type: if remote {
                "RemoteInteractive".into()
            } else {
                "Interactive".into()
            },
            logon_time: None, // WTS has no reliable logon timestamp; honest None
            source: if remote {
                w.client_address.clone()
            } else {
                None
            },
            session_id: Some(w.session_id),
            state_active: w.state_active,
            session_state: Some(wts_state_label(w.state_raw).to_string()),
            logon_server: None,
        });
    }
    out.sort_by(|a, b| {
        (a.session_id, a.user.to_lowercase(), &a.logon_type).cmp(&(
            b.session_id,
            b.user.to_lowercase(),
            &b.logon_type,
        ))
    });
    out
}

/// Whether a WTS session is disconnected (exposed for callers that filter on it).
pub fn is_disconnected(s: &WtsSession) -> bool {
    s.state_raw == WTS_DISCONNECTED
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

    // 2026-06-10T12:00:00Z as a FILETIME.
    const T0: i64 = (1_781_092_800 + 11_644_473_600) * 10_000_000;

    fn wts(
        id: u32,
        user: &str,
        state: i32,
        station: Option<&str>,
        proto: Option<u16>,
    ) -> WtsSession {
        WtsSession {
            session_id: id,
            user: user.into(),
            state_active: state == 0,
            state_raw: state,
            client_address: if proto == Some(2) {
                Some("10.0.0.5".into())
            } else {
                None
            },
            station_name: station.map(Into::into),
            protocol_type: proto,
        }
    }
    fn lsa(session: u32, domain: &str, user: &str, ty: u32, time: i64) -> LsaSession {
        LsaSession {
            logon_id: u64::from(session) << 8 | u64::from(ty),
            session_id: session,
            user: user.into(),
            domain: domain.into(),
            logon_type_raw: ty,
            logon_time_raw: time,
            logon_server: Some("DC01".into()),
            auth_package: Some("Kerberos".into()),
        }
    }

    #[test]
    fn collector_name_is_logon_session() {
        assert_eq!(LogonSessionCollector::default().name(), "logon_session");
    }

    #[test]
    fn lsa_rdp_logon_joins_wts_state_and_address() {
        let w = [wts(2, "alice", 0, Some("RDP-Tcp#0"), Some(2))];
        let l = [lsa(2, "CORP", "alice", 10, T0)];
        let out = build_logon_records(Some(&l), &w);
        assert_eq!(out.len(), 1, "{out:?}");
        let r = &out[0];
        assert_eq!(r.user, r"CORP\alice");
        assert_eq!(r.logon_type, "RemoteInteractive");
        assert_eq!(
            r.logon_time.unwrap().to_rfc3339(),
            "2026-06-10T12:00:00+00:00"
        );
        assert_eq!(r.source.as_deref(), Some("10.0.0.5"));
        assert_eq!(r.logon_server.as_deref(), Some("DC01"));
        assert_eq!(r.session_state.as_deref(), Some("active"));
        assert!(r.state_active);
    }

    /// A disconnected RDP session (station name gone) is still RemoteInteractive.
    #[test]
    fn disconnected_rdp_is_labelled_remote() {
        let w = [wts(3, "bob", WTS_DISCONNECTED, None, Some(2))];
        // WTS-only (LSA unavailable)
        let out = build_logon_records(None, &w);
        assert_eq!(out[0].logon_type, "RemoteInteractive");
        assert_eq!(out[0].session_state.as_deref(), Some("disconnected"));
        assert!(!out[0].state_active);
        assert!(is_disconnected(&w[0]));
        // With LSA
        let l = [lsa(3, "CORP", "bob", 10, T0)];
        let out = build_logon_records(Some(&l), &w);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].logon_type, "RemoteInteractive");
        assert_eq!(out[0].session_state.as_deref(), Some("disconnected"));
        assert!(!out[0].state_active);
    }

    #[test]
    fn network_and_service_logons_are_kept_virtual_accounts_dropped() {
        let l = [
            lsa(0, "NT AUTHORITY", "SYSTEM", 5, T0),
            lsa(0, "CORP", "svc_backup", 3, T0),
            lsa(1, "Window Manager", "DWM-1", 2, T0),
            lsa(1, "Font Driver Host", "UMFD-1", 2, T0),
        ];
        let out = build_logon_records(Some(&l), &[]);
        let types: Vec<(&str, &str)> = out
            .iter()
            .map(|r| (r.user.as_str(), r.logon_type.as_str()))
            .collect();
        assert_eq!(
            types,
            vec![
                (r"CORP\svc_backup", "Network"),
                (r"NT AUTHORITY\SYSTEM", "Service")
            ]
        );
        assert!(out
            .iter()
            .all(|r| r.session_state.is_none() && !r.state_active));
    }

    /// Linked admin tokens (two LUIDs, same user/type/session) collapse to the earliest.
    #[test]
    fn duplicate_logons_collapse_to_earliest() {
        let w = [wts(1, "carol", 0, Some("Console"), Some(0))];
        let l = [
            lsa(1, "CORP", "carol", 2, T0 + 10_000_000),
            lsa(1, "CORP", "carol", 2, T0),
        ];
        let out = build_logon_records(Some(&l), &w);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].logon_type, "Interactive");
        assert_eq!(
            out[0].logon_time.unwrap().to_rfc3339(),
            "2026-06-10T12:00:00+00:00"
        );
        assert_eq!(out[0].source, None, "console logon has no source");
    }

    /// A WTS session with no LSA desktop logon is emitted from WTS alone.
    #[test]
    fn uncovered_wts_session_falls_back() {
        let w = [
            wts(1, "carol", 0, Some("Console"), Some(0)),
            wts(4, "dave", 0, Some("RDP-Tcp#1"), Some(2)),
        ];
        let l = [lsa(1, "CORP", "carol", 2, T0)];
        let out = build_logon_records(Some(&l), &w);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].user, "dave");
        assert_eq!(out[1].logon_type, "RemoteInteractive");
        assert_eq!(out[1].logon_time, None);
        assert_eq!(out[1].source.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn unset_lsa_times_are_none() {
        assert_eq!(lsa_time(0), None);
        assert_eq!(lsa_time(-1), None);
        assert_eq!(lsa_time(i64::MAX), None);
        assert!(lsa_time(T0).is_some());
    }

    /// Off Windows, LSA is unavailable: recorded in sources().errors, not fatal.
    #[cfg(not(windows))]
    #[test]
    fn lsa_unavailable_is_recorded_not_fatal() {
        use cairn_core::Config;
        let c = LogonSessionCollector::default();
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        assert!(c.collect(&ctx).expect("collect").is_empty());
        let errs = &c.sources()[0].errors;
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("lsa unavailable"), "{errs:?}");
    }
}
