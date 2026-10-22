//! heur_netconn (FR11, SRS §10): bare public-IP remote, rare remote port, owning-proc
//! in temp, unsigned owner, suspicious high-port listener. Pure scoring + Analyzer impl.
use crate::score::{is_public_ipv4, is_rare_port, join_key, severity_for, Score};
use crate::trust::{exe_name, is_user_writable_path, launcher_kind};
use cairn_core::finding::{EntityNetConn, EntityProcess};
use cairn_core::record::{NetConnRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use std::collections::HashMap;

/// Gate floor (spec §4.2 S7): single weak signals (rare port 20, public+rare 45,
/// suspicious-path owner 30) are inventory-grade and never emit alone; a finding
/// requires a corroborated combo (e.g. public+rare+unsigned = 65). The one exception
/// is an unsigned owner in a drop zone (see [`owner_is_unsigned_dropzone`]), which
/// emits on its own at Medium.
const NETCONN_GATE_FLOOR: u32 = 50;

/// Weight of "owner is unsigned and runs from a user-writable folder": Medium on its
/// own (an unsigned per-user tool talking to the network is worth a look, not an
/// alarm); any further signal lifts it to High.
const UNSIGNED_DROPZONE_OWNER: u32 = 40;

/// Remote-access services whose LOCAL port is the listening port: a connection to
/// one of them from a public address is someone on the internet logged in to (or
/// knocking on) this host.
const INBOUND_REMOTE_SERVICES: &[(u16, &str, &str)] = &[
    (3389, "RDP", "T1021.001"),
    (445, "SMB", "T1021.002"),
    (22, "SSH", "T1021.004"),
];

/// True if the connection's owner is explicitly unsigned AND runs from a drop zone.
fn owner_is_unsigned_dropzone(owner: Option<&ProcessRecord>) -> bool {
    owner.is_some_and(|o| o.signed == Some(false) && is_user_writable_path(&o.image))
}

/// The remote-access service a public peer is connected to on this host, if any:
/// local port 3389/445/22, a public remote address, not a listening socket, and the
/// remote port is not itself that service port (an outbound session from here has an
/// ephemeral local port, so it never matches).
fn inbound_public_service(c: &NetConnRecord) -> Option<(&'static str, &'static str)> {
    if c.state.as_deref() == Some("listen") {
        return None;
    }
    let raddr = c.raddr.as_deref()?;
    if !is_public_ipv4(raddr) {
        return None;
    }
    let (port, name, mitre) = INBOUND_REMOTE_SERVICES
        .iter()
        .find(|(p, _, _)| *p == c.lport)?;
    (c.rport != Some(*port)).then_some((name, mitre))
}

/// Score one connection against its (optional) owning process.
fn score_conn(c: &NetConnRecord, owner: Option<&ProcessRecord>) -> Score {
    let mut s = Score::default();

    // "Bare public IP" is approximated as a public destination on an uncommon port
    // (no DNS lookup at runtime, NFR6). Public IP on a common port (normal browsing)
    // stays quiet.
    // A remote port of 0 (or None) means "no remote endpoint" — a listening socket, not
    // egress. Only a real (non-zero) remote port can be a rare-egress signal.
    // An inbound session's remote port is the client's ephemeral port, not egress, so
    // the rare-port signals do not apply to it.
    let inbound = inbound_public_service(c);
    let serving = c.state.as_deref() != Some("listen")
        && INBOUND_REMOTE_SERVICES
            .iter()
            .any(|(p, _, _)| *p == c.lport && c.rport != Some(*p));
    let rare = !serving && c.rport.is_some_and(|p| p != 0 && is_rare_port(p));
    if let Some(raddr) = c.raddr.as_deref() {
        if is_public_ipv4(raddr) && rare {
            s.add(
                25,
                format!("connection to bare public IP {raddr} on an uncommon port"),
                &[],
            );
        }
    }
    if rare {
        if let Some(rport) = c.rport {
            s.add(20, format!("uncommon remote port {rport}"), &[]);
        }
    }
    // 3389/445/22 are "common" only as REMOTE ports (this host connecting out). As the
    // LOCAL port with a public peer they mean the service is exposed to the internet
    // and someone is using it: High on its own (T1021 remote services / T1133).
    if let Some((name, mitre)) = inbound {
        s.add(
            55,
            format!(
                "inbound {name} connection from public IP {} to local port {}",
                c.raddr.as_deref().unwrap_or("-"),
                c.lport
            ),
            &[mitre, "T1133"],
        );
    }
    if let Some(o) = owner {
        let mut owner_path_suspicious = false;
        // 獨立訊號（段 11）：owner 未簽章 + 可疑路徑的組合，不需要連線本身先觸發
        // 任何訊號。與下方「可疑路徑」「unsigned 放大器」互斥——這三者若都命中會
        // 對同一個底層事實（owner 身分可疑）重複計分，所以用 if/else 讓「未簽章+
        // 可疑路徑」這個組合只走這條單一 50 分路徑，不與下方兩條疊加。真實世界
        // C2 最常見的偽裝手法正是用常見埠（443/80）混在正常流量裡——不能因為埠
        // 是常見埠就假設這是正常流量。MITRE T1036 (Masquerading)，比照
        // parentchild.rs 對同性質訊號的標籤。
        if is_user_writable_path(&o.image) && o.signed == Some(false) {
            s.add(
                UNSIGNED_DROPZONE_OWNER,
                format!(
                    "owning process is unsigned and runs from a suspicious path: {}",
                    o.image
                ),
                &["T1036"],
            );
            owner_path_suspicious = true;
        } else if is_user_writable_path(&o.image) {
            s.add(
                30,
                format!("owning process runs from a suspicious path: {}", o.image),
                &[],
            );
            owner_path_suspicious = true;
        } else if o.signed == Some(false) {
            // Unsigned owner is an amplifier: fire only if another signal (public-IP/
            // rare-port earlier) already fired. catalog-signed OS binaries report
            // unsigned via WTD_CHOICE_FILE, so an unconditional signal would flood
            // every signed-by-catalog service. Never penalize None/Some(true).
            let another_signal_fired = !s.reasons.is_empty();
            if another_signal_fired {
                s.add(20, "owning process is unsigned", &[]);
            }
        }
        // Unsigned high-port listener: keep listen + port>1024 + unsigned, but ALSO require
        // the suspicious-path signal so a catalog-signed service on an ephemeral port (every
        // svchost RPC listener) does not flag.
        if c.state.as_deref() == Some("listen")
            && c.lport > 1024
            && o.signed == Some(false)
            && owner_path_suspicious
        {
            s.add(
                25,
                format!("unsigned process listening on high port {}", c.lport),
                &[],
            );
        }
    }
    s
}

/// Analyzer: scores every connection against its owning process.
pub struct NetConnHeuristic;

impl NetConnHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::NETCONN;
}

impl Analyzer for NetConnHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn depends_on(&self) -> &[&str] {
        &[crate::persist::PersistHeuristic::NAME]
    }

    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        // Index processes by pid for owner lookup. As in parentchild: on pid reuse the
        // last Process record wins; a live-state snapshot almost never reuses pids, so
        // this only affects owner attribution accuracy, never correctness/panics.
        let by_pid: HashMap<u32, &ProcessRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Process(p) => Some((p.pid, p)),
                _ => None,
            })
            .collect();

        let own_pid = std::process::id();
        let mut out = Vec::new();
        for r in records {
            let Record::NetConn(c) = r else { continue };
            if c.pid == Some(own_pid) {
                continue; // never flag own network connections
            }
            let owner = c.pid.and_then(|pid| by_pid.get(&pid).copied());
            let mut score = score_conn(c, owner);

            // 跨 analyzer 佐證（段 11）：owner 若同時是 heur_persist 判定為落地
            // 持久化的程式，這是強烈的獨立佐證（不同資料來源、不同 analyzer
            // 各自判斷出同一個結論）。+30，與 persist.rs 內部同級跨文物佐證
            // 權重一致（那邊是直接 escalate() 一個 severity 級，這裡是分數制，
            // +30 大致對應 High(50..=69) 到 Critical(70..) 這個常見躍遷）。
            // A launcher owner (powershell, rundll32, ...) is skipped: a persistence
            // entry that runs through powershell.exe says nothing about which of the
            // host's powershell.exe processes holds this connection.
            if let Some(o) = owner.filter(|o| launcher_kind(&exe_name(&o.image)).is_none()) {
                let owner_key = join_key(&o.image);
                let corroborated = prior_findings.iter().any(|f| {
                    f.analyzer == crate::persist::PersistHeuristic::NAME
                        && f.evidence
                            .iter()
                            .filter_map(|e| e.path.as_deref())
                            .any(|p| join_key(p).same_target(&owner_key))
                });
                if corroborated {
                    score.add(
                        30,
                        format!(
                            "owning process {} also has a persistence finding (source: heur_persist)",
                            o.image
                        ),
                        &["T1547"],
                    );
                }
            }

            // Below the floor only the unsigned drop-zone owner emits (alone: Medium).
            let standalone = owner_is_unsigned_dropzone(owner);
            if score.weight < NETCONN_GATE_FLOOR && !standalone {
                continue;
            }
            let Some(severity) = severity_for(score.weight) else {
                continue;
            };

            let mut f = Finding::new(
                severity,
                format!("Suspicious {} connection", c.proto),
                FindingSource::Heuristic,
            );
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre;
            f.artifact = "netconn".into();
            // f.ts intentionally left at Finding::new's default (collection time):
            // NetConnRecord carries no connection-establishment timestamp, and the OS API
            // does not reliably expose one. (parentchild uses process start_time instead.)
            let proc_label = owner
                .map(|o| {
                    let name = o.image.rsplit(['\\', '/']).next().unwrap_or(&o.image);
                    format!("{} ({})", name, o.pid)
                })
                .or_else(|| c.pid.map(|pid| pid.to_string()))
                .unwrap_or_else(|| "unknown".into());
            f.details = if inbound_public_service(c).is_some() {
                format!(
                    "{} ← {}:{} (local port {})",
                    proc_label,
                    c.raddr.as_deref().unwrap_or("-"),
                    c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    c.lport,
                )
            } else {
                format!(
                    "{} → {}:{}",
                    proc_label,
                    c.raddr.as_deref().unwrap_or("-"),
                    c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                )
            };
            f.entity = Entity {
                netconn: Some(EntityNetConn {
                    laddr: c.laddr.clone(),
                    lport: c.lport,
                    raddr: c.raddr.clone(),
                    rport: c.rport,
                    pid: c.pid,
                }),
                process: owner.map(|o| EntityProcess {
                    pid: o.pid,
                    ppid: o.ppid,
                    image: o.image.clone(),
                    cmdline: o.cmdline.clone(),
                    signed: o.signed,
                    integrity: o.integrity.clone(),
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        Ok(crate::stamped(out, Self::NAME))
    }
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
    #[test]
    fn depends_on_returns_heur_persist() {
        assert_eq!(NetConnHeuristic.depends_on(), &["heur_persist"]);
    }

    fn owner(image: &str, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 1,
            ppid: 0,
            image: image.into(),
            cmdline: String::new(),
            signed,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        }
    }

    /// Unsigned proc in Temp connecting to a public IP on a rare port scores Critical
    /// (weight 95 = public-ip 25 + rare-port 20 + suspicious-path 30 + unsigned 20;
    /// severity_for(95) = Critical, per the 70.. band — see score.rs).
    #[test]
    fn unsigned_temp_to_public_rare_port_scores_critical() {
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

    /// An unsigned process running from a suspicious path (Temp), connecting to a
    /// public IP on port 443 (common port — the real-world C2 disguise), scores
    /// independently of port rarity: the combined unsigned+drop-zone signal (40) emits
    /// on its own, at Medium — no longer High without a second signal.
    #[test]
    fn unsigned_suspicious_path_owner_scores_independently_of_port_443() {
        let c = conn(
            "tcp",
            51000,
            Some("104.18.0.1"),
            Some(443), // common port — must NOT suppress this signal
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        assert_eq!(s.weight, UNSIGNED_DROPZONE_OWNER);
        assert!(s
            .reasons
            .iter()
            .any(|r| r.contains("unsigned") && r.contains("suspicious path")));

        let findings = NetConnHeuristic
            .analyze(&[Record::NetConn(c), Record::Process(o)], &[])
            .expect("analyze");
        assert_eq!(
            findings.len(),
            1,
            "a 443-port C2 disguise with an unsigned+suspicious-path owner must be flagged"
        );
        assert_eq!(findings[0].severity, cairn_core::Severity::Medium);
    }

    /// A signed, normal-path owner connecting on port 443 must still stay quiet —
    /// this proves the new independent signal doesn't fire on legitimate browsing.
    #[test]
    fn signed_normal_path_owner_on_443_still_scores_zero() {
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
        assert_eq!(
            s.weight, 0,
            "signed, normal-path owner on a common port must score zero"
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
        // unsigned + suspicious path (40) + listener (25) = 65 (High)
        assert_eq!(s.weight, 65);
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
    /// public-IP signal — proving the public-IP gate works on its own. At the
    /// `score_conn` level this weight (20) is below NETCONN_GATE_FLOOR (50), so
    /// `analyze()` must produce no finding at all (renamed from
    /// `private_ip_rare_port_fires_rare_port_only`, which asserted a bare score
    /// value under the pre-gate-floor model).
    #[test]
    fn private_ip_rare_port_below_gate_floor_no_finding() {
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

        let findings = NetConnHeuristic
            .analyze(&[Record::NetConn(c)], &[])
            .expect("analyze");
        assert!(
            findings.is_empty(),
            "weight 20 must not clear the gate floor (50)"
        );
    }

    /// A listening socket reports remote port 0 / no remote — it must NOT fire the
    /// rare-port signal (regression: live runs flagged every listener as rare egress).
    #[test]
    fn listening_socket_rport_zero_is_not_rare() {
        // rport = Some(0): a listener with the API's placeholder remote port
        let c0 = conn(
            "tcp",
            445,
            Some("0.0.0.0"),
            Some(0),
            Some("listen"),
            Some(4),
        );
        let s0 = score_conn(&c0, None);
        assert!(
            !s0.reasons
                .iter()
                .any(|r| r.contains("uncommon remote port")),
            "rport 0 must not be a rare-port signal"
        );

        // rport = None: same — no remote port at all
        let cn = conn("tcp", 445, None, None, Some("listen"), Some(4));
        let sn = score_conn(&cn, None);
        assert!(!sn
            .reasons
            .iter()
            .any(|r| r.contains("uncommon remote port")));
    }

    /// A public IP paired with rport 0 must NOT fire the bare-public-IP signal either
    /// (the gate requires a real rare remote port).
    #[test]
    fn public_ip_with_rport_zero_does_not_fire() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(0),
            Some("established"),
            None,
        );
        let s = score_conn(&c, None);
        assert_eq!(s.weight, 0, "public IP with rport 0 should score nothing");
    }

    /// Unsigned owner WITH another signal (public IP + rare port): amplifier fires.
    #[test]
    fn unsigned_owner_amplifies_with_connection_signal() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Windows\System32\svc.exe", Some(false)); // normal path
        let s = score_conn(&c, Some(&o));
        // public ip 25 + rare port 20 + unsigned 20 = 65
        assert_eq!(s.weight, 65);
        assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned owner, NO other signal (common port 443, normal path): amplifier does NOT fire.
    #[test]
    fn unsigned_owner_alone_does_not_amplify() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(443),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Windows\System32\svchost.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        assert_eq!(s.weight, 0);
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned high-port listener in a NORMAL path: listener compound does NOT fire.
    #[test]
    fn unsigned_listener_normal_path_does_not_fire() {
        let c = conn("tcp", 49500, None, None, Some("listen"), Some(1));
        let o = owner(r"C:\Windows\System32\svchost.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        assert_eq!(
            s.weight, 0,
            "catalog-signed service listener in System32 must stay quiet"
        );
    }

    /// Unsigned high-port listener in a SUSPICIOUS path: path + listener fire.
    #[test]
    fn unsigned_listener_suspicious_path_fires() {
        let c = conn("tcp", 4444, None, None, Some("listen"), Some(1));
        let o = owner(r"C:\Users\a\AppData\Local\Temp\svc.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        // owner is unsigned + suspicious path, so the mutually-exclusive owner-identity
        // block (score_conn) takes the single combined path: unsigned+suspicious-path
        // signal (50) — NOT suspicious-path(30) and unsigned(20) added separately, since
        // those would double-count the same underlying fact. owner_path_suspicious is
        // still set true by that branch, so the listener signal (25) still fires on top:
        // 40 + 25 = 65.
        assert_eq!(s.weight, 65);
        assert!(s
            .reasons
            .iter()
            .any(|r| r.contains("listening on high port")));
    }

    /// Inbound RDP / SMB / SSH from a public address is High on its own, even with a
    /// signed system owner; the same ports used outbound, or from a private peer, are
    /// not.
    #[test]
    fn inbound_public_remote_service_is_high() {
        let svchost = owner(r"C:\Windows\System32\svchost.exe", Some(true));
        for (lport, mitre) in [(3389, "T1021.001"), (445, "T1021.002"), (22, "T1021.004")] {
            let c = conn(
                "tcp",
                lport,
                Some("45.33.32.156"),
                Some(51234),
                Some("established"),
                Some(1),
            );
            let s = score_conn(&c, Some(&svchost));
            assert_eq!(s.weight, 55, "{lport}");
            assert!(s.mitre.contains(&mitre.to_string()));
            assert!(s.mitre.contains(&"T1133".to_string()));
            let f = NetConnHeuristic
                .analyze(&[Record::NetConn(c), Record::Process(svchost.clone())], &[])
                .unwrap();
            assert_eq!(f.len(), 1, "{lport}");
            assert_eq!(f[0].severity, cairn_core::Severity::High);
            assert!(f[0].details.contains('←'), "{}", f[0].details);
        }
        // outbound RDP from this host: ephemeral local port -> not inbound
        let out = conn(
            "tcp",
            50123,
            Some("45.33.32.156"),
            Some(3389),
            Some("established"),
            Some(1),
        );
        assert_eq!(score_conn(&out, Some(&svchost)).weight, 0);
        // inbound from a private peer -> quiet
        let lan = conn(
            "tcp",
            3389,
            Some("10.0.0.5"),
            Some(51234),
            Some("established"),
            Some(1),
        );
        assert_eq!(score_conn(&lan, Some(&svchost)).weight, 0);
        // the listening socket itself -> quiet
        let listen = conn(
            "tcp",
            3389,
            Some("0.0.0.0"),
            Some(0),
            Some("listen"),
            Some(1),
        );
        assert_eq!(score_conn(&listen, Some(&svchost)).weight, 0);
    }

    /// A dual-stack listener reports its IPv4 peers as `::ffff:a.b.c.d`; an inbound RDP
    /// session from a public address in that spelling was silently skipped.
    #[test]
    fn ipv4_mapped_peer_is_judged_as_ipv4() {
        let svchost = owner(r"C:\Windows\System32\svchost.exe", Some(true));
        let c = conn(
            "tcp6",
            3389,
            Some("::ffff:45.33.32.156"),
            Some(51234),
            Some("established"),
            Some(1),
        );
        assert_eq!(score_conn(&c, Some(&svchost)).weight, 55);
        let lan = conn(
            "tcp6",
            3389,
            Some("::ffff:10.0.0.5"),
            Some(51234),
            Some("established"),
            Some(1),
        );
        assert_eq!(score_conn(&lan, Some(&svchost)).weight, 0);
    }

    fn persist_finding(path: &str) -> Finding {
        let mut f = Finding::new(cairn_core::Severity::High, "p", FindingSource::Heuristic);
        f.analyzer = crate::persist::PersistHeuristic::NAME.into();
        f.evidence = vec![cairn_core::finding::EvidenceItem {
            artifact: "run_key".into(),
            path: Some(path.into()),
            ts: None,
            detail: String::new(),
        }];
        f
    }

    /// Corroboration needs the same binary: a persistence finding on a fake
    /// `C:\Users\a\svchost.exe` must not lift the real System32 svchost's connection,
    /// and an entry that runs through powershell.exe says nothing about which
    /// powershell process owns a connection.
    #[test]
    fn persist_corroboration_requires_the_same_binary() {
        let c = || {
            conn(
                "tcp",
                50000,
                Some("104.18.0.1"),
                Some(4444),
                Some("established"),
                Some(1),
            )
        };
        let real = owner(r"C:\Windows\System32\svchost.exe", Some(true));
        let fake = persist_finding(r"C:\Users\a\svchost.exe");
        let f = NetConnHeuristic
            .analyze(&[Record::NetConn(c()), Record::Process(real)], &[fake])
            .unwrap();
        assert!(f.is_empty(), "{f:?}");

        let ps = owner(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Some(true),
        );
        let entry = persist_finding(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        let f = NetConnHeuristic
            .analyze(&[Record::NetConn(c()), Record::Process(ps)], &[entry])
            .unwrap();
        assert!(f.is_empty(), "{f:?}");

        // Same binary spelled differently still corroborates; a bare name too.
        for ev_path in [r#""C:\TOOLS\evil.exe""#, "evil.exe"] {
            let f = NetConnHeuristic
                .analyze(
                    &[
                        Record::NetConn(c()),
                        Record::Process(owner(r"C:\Tools\evil.exe", None)),
                    ],
                    &[persist_finding(ev_path)],
                )
                .unwrap();
            assert_eq!(f.len(), 1, "{ev_path}");
        }
    }

    /// Unsigned drop-zone owner plus one more signal (rare port) is High.
    #[test]
    fn unsigned_dropzone_owner_with_another_signal_is_high() {
        let c = conn(
            "tcp",
            50000,
            Some("10.0.0.5"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Users\a\AppData\Roaming\x\x.exe", Some(false));
        let f = NetConnHeuristic
            .analyze(&[Record::NetConn(c), Record::Process(o)], &[])
            .unwrap();
        assert_eq!(f[0].severity, cairn_core::Severity::High);
    }

    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    /// Own PID connections must never produce findings.
    #[test]
    fn own_pid_netconn_not_flagged() {
        use std::process;
        let own_pid = process::id();
        let bad_conn = Record::NetConn(conn(
            "tcp",
            65146,
            Some("104.18.38.233"),
            Some(80),
            Some("established"),
            Some(own_pid),
        ));
        let findings = NetConnHeuristic.analyze(&[bad_conn], &[]).expect("analyze");
        assert!(
            findings.is_empty(),
            "own PID connections must never produce findings"
        );
    }

    #[test]
    fn entity_process_populated_when_owner_known() {
        let bad = Record::NetConn(NetConnRecord {
            proto: "tcp".into(),
            laddr: "192.168.0.1".into(),
            lport: 50000,
            raddr: Some("104.18.0.1".into()),
            rport: Some(4444),
            state: Some("established".into()),
            pid: Some(42),
        });
        let proc_rec = Record::Process(ProcessRecord {
            pid: 42,
            ppid: 4,
            image: r"C:\Users\x\AppData\Local\Temp\beacon.exe".into(),
            cmdline: String::new(),
            signed: Some(false),
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        });
        let findings = NetConnHeuristic
            .analyze(&[bad, proc_rec], &[])
            .expect("analyze");
        assert!(!findings.is_empty(), "must produce a finding");
        let f = &findings[0];
        assert!(
            f.entity.process.is_some(),
            "entity.process must be populated when owner is known"
        );
        assert_eq!(
            f.entity.process.as_ref().unwrap().pid,
            42,
            "entity.process.pid must match owner"
        );
    }

    /// A different PID on a suspicious connection (with a corroborating owner signal
    /// clearing the gate floor) must still fire.
    #[test]
    fn other_pid_netconn_still_flagged() {
        use std::process;
        let own_pid = process::id();
        let other_pid = own_pid + 9999;
        let bad_conn = Record::NetConn(conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(other_pid),
        ));
        let mut o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", Some(false));
        o.pid = other_pid;
        let proc_rec = Record::Process(o);
        let findings = NetConnHeuristic
            .analyze(&[bad_conn, proc_rec], &[])
            .expect("analyze");
        assert!(
            !findings.is_empty(),
            "other PID must still produce findings"
        );
    }

    // --- R6: human-readable details field ---

    /// details should show "<proc_name> (<pid>) → <raddr>:<rport>", not debug pid={:?} format.
    #[test]
    fn netconn_details_format() {
        let bad = Record::NetConn(NetConnRecord {
            proto: "tcp".into(),
            laddr: "192.168.0.11".into(),
            lport: 50000,
            raddr: Some("104.18.0.1".into()),
            rport: Some(4444),
            state: Some("established".into()),
            pid: Some(1234),
        });
        let proc_rec = Record::Process(ProcessRecord {
            pid: 1234,
            ppid: 4,
            image: r"C:\Users\x\AppData\Local\Temp\beacon.exe".into(),
            cmdline: String::new(),
            signed: Some(false),
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        });
        let findings = NetConnHeuristic
            .analyze(&[bad, proc_rec], &[])
            .expect("analyze");
        assert!(!findings.is_empty(), "should produce at least one finding");
        let details = &findings[0].details;
        assert!(
            details.contains("beacon.exe"),
            "process name missing: {details}"
        );
        assert!(details.contains("1234"), "pid missing: {details}");
        assert!(
            details.contains("104.18.0.1"),
            "remote addr missing: {details}"
        );
        assert!(
            !details.contains("pid=Some("),
            "must not use debug format: {details}"
        );
    }

    /// With no owning process record, connection-only signals (public-IP 25 + rare-port
    /// 20 = 45) cannot clear the NETCONN_GATE_FLOOR (50) alone — no finding is produced.
    /// (Renamed from `netconn_details_no_owner`: that test's premise — a no-owner
    /// connection still producing a finding — is no longer reachable post-gate-floor,
    /// since connection-only signals cap at 45. The pid-as-label details format for a
    /// known owner is already covered by `netconn_details_format`.)
    #[test]
    fn netconn_no_owner_below_gate_floor_no_finding() {
        let bad = Record::NetConn(conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(9999),
        ));
        let findings = NetConnHeuristic.analyze(&[bad], &[]).expect("analyze");
        assert!(
            findings.is_empty(),
            "connection-only signals (45) must not clear the gate floor (50)"
        );
    }

    /// The analyzer emits one Heuristic NetConn finding for the malicious conn, with
    /// reason + netconn entity, and nothing for loopback.
    #[test]
    fn analyzer_emits_finding_for_malicious_conn() {
        let bad = Record::NetConn(conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        ));
        let good = Record::NetConn(conn(
            "tcp",
            445,
            Some("127.0.0.1"),
            Some(445),
            None,
            Some(4),
        ));
        let proc = Record::Process(owner(
            r"C:\Users\a\AppData\Local\Temp\evil.exe",
            Some(false),
        ));
        // owner pid must match the bad conn's pid (1); the owner() helper sets pid=1
        let recs = vec![bad, good, proc];

        let findings = NetConnHeuristic.analyze(&recs, &[]).expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert!(f.entity.netconn.is_some());
    }

    /// public+rare (25+20=45) + unsigned amplifier (20) = 65, clearing the gate floor
    /// (50). severity_for(65) = High (the 50..=69 band).
    #[test]
    fn public_rare_plus_unsigned_owner_clears_gate() {
        let bad = Record::NetConn(conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        ));
        let proc = Record::Process(owner(r"C:\Windows\System32\svc.exe", Some(false)));
        let findings = NetConnHeuristic
            .analyze(&[bad, proc], &[])
            .expect("analyze");
        assert_eq!(findings.len(), 1, "combo (65) must clear the gate floor");
        assert_eq!(findings[0].severity, cairn_core::Severity::High);
    }

    /// public+rare alone (25+20=45) stays below the gate floor (50) with no owning
    /// process to supply the unsigned amplifier: analyze() must return nothing.
    #[test]
    fn public_rare_alone_is_dropped_by_gate() {
        let bad = Record::NetConn(conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            None,
        ));
        let findings = NetConnHeuristic.analyze(&[bad], &[]).expect("analyze");
        assert!(
            findings.is_empty(),
            "weight 45 must not clear the gate floor (50)"
        );
    }

    /// A connection whose owner also has a heur_persist finding (same image path)
    /// gets a +30 corroboration bonus, which pushes a below-floor connection over the
    /// gate. The prior finding comes from the real PersistHeuristic, and the match is
    /// on the typed `Finding.analyzer`, not on reason text.
    #[test]
    fn netconn_corroborated_by_persist_finding_clears_gate() {
        use crate::persist::PersistHeuristic;
        use cairn_core::record::{Mechanism, PersistenceRecord};
        // Connection alone: public+rare (25+20=45) — below the 50 gate floor, and the
        // owner is outside every drop zone so no owner-path signal adds weight.
        let image = r"C:\Tools\evil.exe";
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let records = vec![Record::NetConn(c), Record::Process(owner(image, None))];
        assert!(NetConnHeuristic.analyze(&records, &[]).unwrap().is_empty());

        // Recent, unverifiable, non-system run key -> persist S4 finding on evil.exe.
        let persist_rec = Record::Persistence(PersistenceRecord {
            mechanism: Mechanism::RunKey,
            location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value: Some("evil".into()),
            command: Some(image.into()),
            binary_path: Some(image.into()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: Some(chrono::Utc::now()),
            bound: None,
            signer_source: None,
            service_start: None,
        });
        let prior = PersistHeuristic.analyze(&[persist_rec], &[]).unwrap();
        assert_eq!(prior.len(), 1);
        assert_eq!(prior[0].analyzer, PersistHeuristic::NAME);

        let findings = NetConnHeuristic.analyze(&records, &prior).expect("analyze");
        assert_eq!(
            findings.len(),
            1,
            "45 (connection-only) + 30 (corroboration) = 75 must clear the gate floor"
        );
        assert!(
            findings[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("heur_persist")),
            "reason must mention the corroborating source: {:?}",
            findings[0].reason
        );
    }

    /// Only a finding whose `analyzer` is heur_persist corroborates; reason text
    /// that merely mentions it (the old string-marker contract) does not.
    #[test]
    fn netconn_corroboration_keys_on_analyzer_field_not_reason_text() {
        let image = r"C:\Tools\evil.exe";
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let mut other = Finding::new(cairn_core::Severity::High, "x", FindingSource::Heuristic);
        other.analyzer = "heur_eventlog".into();
        other.reason = Some("source: heur_persist".into());
        other.evidence = vec![cairn_core::finding::EvidenceItem {
            artifact: "run_key".into(),
            path: Some(image.into()),
            ts: None,
            detail: String::new(),
        }];
        let findings = NetConnHeuristic
            .analyze(
                &[Record::NetConn(c), Record::Process(owner(image, None))],
                &[other],
            )
            .unwrap();
        assert!(findings.is_empty());
    }

    /// Without a matching prior_findings entry, the connection's score is unaffected
    /// (regression: corroboration logic must not fire spuriously). Uses a
    /// non-suspicious-path owner (unlike the sibling test above) so the score stays
    /// at connection-only signals (45): a suspicious-path owner (e.g. Temp) would
    /// independently add 30 via score_conn's own owner-identity signal and clear the
    /// gate on its own, which would defeat the purpose of this regression test.
    #[test]
    fn netconn_without_persist_corroboration_unaffected() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Windows\System32\svc.exe", None);
        let proc_rec = Record::Process(o);

        let findings = NetConnHeuristic
            .analyze(&[Record::NetConn(c), proc_rec], &[])
            .expect("analyze");
        assert!(
            findings.is_empty(),
            "45 (connection-only, no corroboration) must stay below the gate floor"
        );
    }
}
