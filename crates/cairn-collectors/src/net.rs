//! Pure mapping: raw TCP/UDP rows -> Record::NetConn. No OS access here.
use cairn_collectors_win::net::{NetTables, RawTcpRow, RawUdpRow};
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{NetConnRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::CairnError;
use cairn_core::Result;
use std::sync::Mutex;

/// Collector for live TCP/UDP tables (IPv4 + IPv6) with owning PID (SRS §4 net_collector).
///
/// Each of the four tables is read independently; a table that fails is recorded in this
/// collector's manifest source `errors` and the rows from the others are still returned.
/// Only when every table fails does `collect` return Err.
#[derive(Default)]
pub struct NetCollector {
    errors: Mutex<Vec<String>>,
}

impl NetCollector {
    /// Turn one read of the four tables into records, remembering per-table errors for
    /// `sources()`. Pure apart from the error stash (tests feed synthetic tables).
    fn ingest(&self, tables: NetTables) -> Result<Vec<Record>> {
        if let Ok(mut e) = self.errors.lock() {
            *e = tables.errors.clone();
        }
        if tables.all_failed() {
            return Err(CairnError::Collector {
                collector: cairn_core::collectors::NET.into(),
                reason: format!("every socket table failed: {}", tables.errors.join("; ")),
            });
        }
        Ok(build_netconn_records(&tables.tcp, &tables.udp))
    }
}

impl Collector for NetCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::NET
    }
    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        self.ingest(cairn_collectors_win::net::read_tables())
    }
    fn sources(&self) -> Vec<SourceEntry> {
        let errors = self.errors.lock().map(|e| e.clone()).unwrap_or_default();
        vec![SourceEntry {
            collector: String::new(),
            artifact: "netconn".into(),
            path: "live:net".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

/// Map raw rows to NetConn records. Pure + total. TCP carries remote addr/port + state;
/// UDP is connectionless (no remote, no state). state_raw maps to a label.
pub fn build_netconn_records(tcp: &[RawTcpRow], udp: &[RawUdpRow]) -> Vec<Record> {
    let mut out = Vec::with_capacity(tcp.len() + udp.len());
    for r in tcp {
        out.push(Record::NetConn(NetConnRecord {
            proto: "tcp".into(),
            laddr: r.laddr.clone(),
            lport: r.lport,
            raddr: Some(r.raddr.clone()),
            rport: Some(r.rport),
            state: Some(tcp_state_label(r.state_raw)),
            pid: Some(r.pid),
        }));
    }
    for r in udp {
        out.push(Record::NetConn(NetConnRecord {
            proto: "udp".into(),
            laddr: r.laddr.clone(),
            lport: r.lport,
            raddr: None,
            rport: None,
            state: None,
            pid: Some(r.pid),
        }));
    }
    out
}

/// MIB TCP state code -> label (MIB_TCP_STATE numbering). Unknown -> the numeric string.
fn tcp_state_label(state: u32) -> String {
    match state {
        1 => "closed".into(),
        2 => "listen".into(),
        3 => "syn_sent".into(),
        4 => "syn_rcvd".into(),
        5 => "established".into(),
        6 => "fin_wait1".into(),
        7 => "fin_wait2".into(),
        8 => "close_wait".into(),
        9 => "closing".into(),
        10 => "last_ack".into(),
        11 => "time_wait".into(),
        12 => "delete_tcb".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP row becomes a tcp NetConn with remote + state; a UDP row becomes a udp
    /// NetConn with no remote and no state.
    #[test]
    fn maps_tcp_and_udp_rows() {
        let tcp = vec![RawTcpRow {
            laddr: "127.0.0.1".into(),
            lport: 445,
            raddr: "10.0.0.5".into(),
            rport: 50000,
            state_raw: 5, // ESTAB per MIB
            pid: 4,
        }];
        let udp = vec![RawUdpRow {
            laddr: "0.0.0.0".into(),
            lport: 137,
            pid: 900,
        }];
        let recs = build_netconn_records(&tcp, &udp);
        assert_eq!(recs.len(), 2);

        let Record::NetConn(t) = &recs[0] else {
            panic!("tcp")
        };
        assert_eq!(t.proto, "tcp");
        assert_eq!(t.lport, 445);
        assert_eq!(t.raddr.as_deref(), Some("10.0.0.5"));
        assert_eq!(t.rport, Some(50000));
        assert_eq!(t.pid, Some(4));
        assert!(t.state.is_some());

        let Record::NetConn(u) = &recs[1] else {
            panic!("udp")
        };
        assert_eq!(u.proto, "udp");
        assert_eq!(u.lport, 137);
        assert_eq!(u.raddr, None);
        assert_eq!(u.state, None);
        assert_eq!(u.pid, Some(900));
    }

    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::Config;

    /// NetCollector.collect returns only NetConn records, never panics, name() is "net".
    #[test]
    fn net_collector_collects_without_panicking() {
        let c = NetCollector::default();
        assert_eq!(c.name(), "net");
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let recs = c.collect(&ctx).expect("collect");
        assert!(recs.iter().all(|r| matches!(r, Record::NetConn(_))));
        assert_eq!(c.sources()[0].artifact, "netconn");
    }

    /// A failed table lands in sources().errors while the other tables' rows are kept;
    /// all tables failing is a collector error.
    #[test]
    fn partial_table_failure_is_recorded_not_fatal() {
        let c = NetCollector::default();
        let tables = NetTables {
            tcp: vec![RawTcpRow {
                laddr: "::1".into(),
                lport: 443,
                raddr: "::".into(),
                rport: 0,
                state_raw: 2,
                pid: 10,
            }],
            udp: vec![],
            errors: vec!["udp6: GetExtendedUdpTable rc=50".into()],
        };
        let recs = c.ingest(tables).expect("partial failure is not fatal");
        assert_eq!(recs.len(), 1);
        let Record::NetConn(n) = &recs[0] else {
            panic!("netconn")
        };
        assert_eq!(n.laddr, "::1");
        assert_eq!(n.state.as_deref(), Some("listen"));
        assert_eq!(
            c.sources()[0].errors,
            vec!["udp6: GetExtendedUdpTable rc=50".to_string()]
        );

        let all_failed = NetTables {
            tcp: vec![],
            udp: vec![],
            errors: (0..4).map(|i| format!("t{i}")).collect(),
        };
        assert!(c.ingest(all_failed).is_err());
        assert_eq!(c.sources()[0].errors.len(), 4);
    }
}
