//! Pure mapping: raw TCP/UDP rows -> Record::NetConn. No OS access here.
use cairn_collectors_win::net::{RawTcpRow, RawUdpRow};
use cairn_core::record::{NetConnRecord, Record};

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
}
