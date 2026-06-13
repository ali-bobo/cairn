//! heur_netconn (FR11, SRS §10): bare public-IP remote, rare remote port, owning-proc
//! in temp, unsigned owner, suspicious high-port listener. Pure scoring (analyzer is Task 6).
// Task 5: pure scoring only. Task 6 adds the Analyzer impl that consumes score_conn;
// until then, suppress dead_code for the staging items.
#![allow(dead_code)]
use crate::score::{is_public_ipv4, is_rare_port, is_suspicious_path, Score};
use cairn_core::record::{NetConnRecord, ProcessRecord};

/// Score one connection against its (optional) owning process.
fn score_conn(c: &NetConnRecord, owner: Option<&ProcessRecord>) -> Score {
    let mut s = Score::default();

    // "Bare public IP" is approximated as a public destination on an uncommon port
    // (no DNS lookup at runtime, NFR6). Public IP on a common port (normal browsing)
    // stays quiet.
    let rare = c.rport.map(is_rare_port).unwrap_or(false);
    if let Some(raddr) = c.raddr.as_deref() {
        if is_public_ipv4(raddr) && rare {
            s.add(
                25,
                format!("connection to bare public IP {raddr} on an uncommon port"),
                &[],
            );
        }
    }
    if let Some(rport) = c.rport {
        if is_rare_port(rport) {
            s.add(20, format!("uncommon remote port {rport}"), &[]);
        }
    }
    if let Some(o) = owner {
        if is_suspicious_path(&o.image) {
            s.add(
                30,
                format!("owning process runs from a suspicious path: {}", o.image),
                &[],
            );
        }
        if o.signed == Some(false) {
            s.add(20, "owning process is unsigned", &[]);
        }
        if c.state.as_deref() == Some("listen") && c.lport > 1024 && o.signed == Some(false) {
            s.add(
                25,
                format!("unsigned process listening on high port {}", c.lport),
                &[],
            );
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(
        proto: &str,
        lport: u16,
        raddr: Option<&str>,
        rport: Option<u16>,
        state: Option<&str>,
        pid: Option<u32>,
    ) -> NetConnRecord {
        NetConnRecord {
            proto: proto.into(),
            laddr: "0.0.0.0".into(),
            lport,
            raddr: raddr.map(|s| s.into()),
            rport,
            state: state.map(|s| s.into()),
            pid,
        }
    }
    fn owner(image: &str, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 1,
            ppid: 0,
            image: image.into(),
            cmdline: String::new(),
            signed,
            integrity: None,
            user: None,
            start_time: None,
        }
    }

    /// Unsigned proc in Temp connecting to a public IP on a rare port scores high.
    #[test]
    fn unsigned_temp_to_public_rare_port_scores_high() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        // public ip 25 + rare port 20 + temp 30 + unsigned 20 = 95
        assert!(s.weight >= 70, "weight {}", s.weight);
        assert!(s.reasons.iter().any(|r| r.contains("104.18.0.1")));
    }

    /// A signed browser to 443 on a public IP scores 0 (rare-port absent → public-IP
    /// signal suppressed → normal browsing stays quiet).
    #[test]
    fn signed_browser_https_scores_below_floor() {
        let c = conn(
            "tcp",
            51000,
            Some("104.18.0.1"),
            Some(443),
            Some("established"),
            Some(2),
        );
        let o = owner(r"C:\Program Files\browser\b.exe", Some(true));
        let s = score_conn(&c, Some(&o));
        assert!(
            s.weight < 15,
            "normal https should be below floor, got {}",
            s.weight
        );
    }

    /// Loopback / private dest produces nothing.
    #[test]
    fn loopback_private_scores_zero() {
        let c = conn("tcp", 445, Some("127.0.0.1"), Some(445), None, Some(4));
        let o = owner(r"C:\Windows\System32\svchost.exe", Some(true));
        let s = score_conn(&c, Some(&o));
        assert_eq!(s.weight, 0);
    }

    /// Missing owner still evaluates connection-only signals without panic.
    /// public-IP (25, fires because rare port present) + rare port (20) = 45.
    #[test]
    fn missing_owner_scores_connection_signals() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(999),
        );
        let s = score_conn(&c, None);
        assert_eq!(s.weight, 45);
    }

    /// Signal 5: an unsigned process listening on a high port (>1024) fires the
    /// suspicious-listener signal. lport must be strictly > 1024.
    #[test]
    fn unsigned_high_port_listener_fires() {
        // listen, high port, unsigned owner: unsigned(20) + listener(25) = 45
        let c = conn("tcp", 4444, None, None, Some("listen"), Some(1));
        let o = owner(r"C:\Users\a\AppData\Local\Temp\svc.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        // suspicious path (30) + unsigned (20) + listener (25) = 75
        assert!(s.weight >= 70, "weight {}", s.weight);
        assert!(s
            .reasons
            .iter()
            .any(|r| r.contains("listening on high port")));

        // a signed listener on the same high port does NOT fire the listener signal
        let signed_owner = owner(r"C:\Windows\System32\svchost.exe", Some(true));
        let s2 = score_conn(&c, Some(&signed_owner));
        assert!(!s2
            .reasons
            .iter()
            .any(|r| r.contains("listening on high port")));
    }

    /// Public-IP gating is independent of the rare-port signal: a PRIVATE (RFC1918)
    /// address on a rare port fires ONLY the rare-port signal (+20), never the
    /// public-IP signal — proving the public-IP gate works on its own.
    #[test]
    fn private_ip_rare_port_fires_rare_port_only() {
        let c = conn(
            "tcp",
            50000,
            Some("10.0.0.5"),
            Some(4444),
            Some("established"),
            None,
        );
        let s = score_conn(&c, None);
        assert_eq!(
            s.weight, 20,
            "only the rare-port signal should fire for a private dest"
        );
        assert!(!s.reasons.iter().any(|r| r.contains("public IP")));
    }
}
