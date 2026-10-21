//! Inbound lateral movement seen from the target host's Security and System logs
//! (ATT&CK T1021.002 SMB/Admin Shares, T1569.002 Service Execution, T1550.002
//! Pass the Hash). Reads only `Record::Event`, so it also runs on offline EVTX.
//!
//! - **Admin-share access** (Security 5140 / 5145 on `ADMIN$` or a drive share `C$`)
//!   from a remote address, grouped per (source, account): Medium. High when a
//!   service was installed (System 7045) within [`CORRELATION_WINDOW_MINUTES`] after
//!   it, the PsExec / Impacket pattern of copying a binary and starting it as a
//!   service.
//! - **Remote-execution service** (7045 whose name or ImagePath is PsExec's
//!   `PSEXESVC`, points into `ADMIN$` / `\\127.0.0.1\`, or runs `%COMSPEC%` /
//!   `cmd.exe /c` as the service binary, as smbexec does): High, with the network
//!   logon (4624 type 3) or admin-share access that preceded it within the window
//!   named as the likely source.
//! - **NewCredentials logons** (4624 type 9, logon process `seclogo`), grouped per
//!   (account, process): Low. `runas /netonly` and Mimikatz `sekurlsa::pth` both
//!   produce it, so it is context for the other findings, not a verdict.
//!
//! The 5140 / 5145 events need "Audit File Share" auditing, which is off by default;
//! without it only the 7045 path fires.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

use crate::cmdline::event_str;

/// How long after a remote logon / share access a service install is tied to it.
pub const CORRELATION_WINDOW_MINUTES: i64 = 10;

const ADMIN_SHARES: &str = "T1021.002";
const SERVICE_EXEC: &str = "T1569.002";
const PASS_THE_HASH: &str = "T1550.002";

fn s(ev: &EventRecord, key: &str) -> String {
    event_str(&ev.data, key).unwrap_or_default()
}

/// Remote source address, None for local / loopback / missing ("-").
fn remote_ip(ev: &EventRecord) -> Option<String> {
    let ip = s(ev, "IpAddress");
    let ip = ip.trim().trim_start_matches("::ffff:");
    let local = ip.is_empty() || ip == "-" || ip == "::1" || ip.starts_with("127.");
    (!local).then(|| ip.to_string())
}

/// True for `ADMIN$` and single-letter drive shares (`C$`), any `\\host\` prefix.
pub fn is_admin_share(share: &str) -> bool {
    let name = share
        .rsplit('\\')
        .next()
        .unwrap_or(share)
        .to_ascii_uppercase();
    name == "ADMIN$"
        || (name.len() == 2 && name.ends_with('$') && name.as_bytes()[0].is_ascii_alphabetic())
}

/// Why a 7045 service looks like remote execution, if it does.
pub fn remote_exec_service(name: &str, image: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    let i = image.to_ascii_lowercase();
    if n.contains("psexesvc") || i.contains("psexesvc") {
        return Some("PsExec service (PSEXESVC)");
    }
    if i.contains(r"\\127.0.0.1\") || i.contains(r"\admin$\") {
        return Some(r"service binary runs from ADMIN$ / \\127.0.0.1\ (Impacket)");
    }
    let i = i.split_whitespace().collect::<Vec<_>>().join(" ");
    if i.starts_with("%comspec%") || i.contains("cmd.exe /c") || i.contains("cmd.exe /q /c") {
        return Some("service binary is a cmd /c one-liner (smbexec-style)");
    }
    None
}

/// A remote access this host recorded: who, from where, when.
#[derive(Debug, Clone)]
struct Access<'a> {
    ev: &'a EventRecord,
    ip: String,
    account: String,
    /// Share name for 5140/5145; None for a 4624 network logon.
    share: Option<String>,
}

fn account(ev: &EventRecord, user_key: &str, domain_key: &str) -> String {
    let user = s(ev, user_key);
    let domain = s(ev, domain_key);
    if domain.is_empty() || domain == "-" {
        user
    } else {
        format!(r"{domain}\{user}")
    }
}

fn evidence(ev: &EventRecord, detail: String) -> EvidenceItem {
    EvidenceItem {
        artifact: format!("evtx:{}", ev.channel),
        path: None,
        ts: Some(ev.ts),
        detail,
    }
}

fn base(ev: &EventRecord, severity: Severity, title: String, mitre: &[&str]) -> Finding {
    let mut f = Finding::new(severity, title, FindingSource::Heuristic);
    f.ts = ev.ts;
    f.artifact = format!("evtx:{}", ev.channel);
    f.event_id = Some(ev.event_id);
    f.evidence_ref = Some(format!("{}#{}", ev.channel, ev.record_id));
    f.mitre = mitre.iter().map(|m| m.to_string()).collect();
    f
}

fn fmt_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Inbound lateral movement (see module docs).
pub struct LateralHeuristic;

impl LateralHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::LATERAL;
}

impl Analyzer for LateralHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut events: Vec<&EventRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Event(e) => Some(e),
                _ => None,
            })
            .collect();
        events.sort_by_key(|e| (e.ts, e.record_id));

        let mut accesses: Vec<Access> = Vec::new();
        let mut services: Vec<&EventRecord> = Vec::new();
        let mut newcreds: BTreeMap<(String, String), Vec<&EventRecord>> = BTreeMap::new();
        for ev in &events {
            match (ev.channel.as_str(), ev.event_id) {
                ("Security", 4624) => {
                    let logon_type = s(ev, "LogonType");
                    if logon_type.trim() == "3" {
                        if let Some(ip) = remote_ip(ev) {
                            accesses.push(Access {
                                ev,
                                ip,
                                account: account(ev, "TargetUserName", "TargetDomainName"),
                                share: None,
                            });
                        }
                    } else if logon_type.trim() == "9"
                        && s(ev, "LogonProcessName")
                            .trim()
                            .eq_ignore_ascii_case("seclogo")
                    {
                        let who = account(ev, "SubjectUserName", "SubjectDomainName");
                        newcreds
                            .entry((who, s(ev, "ProcessName")))
                            .or_default()
                            .push(ev);
                    }
                }
                ("Security", 5140 | 5145) => {
                    let share = s(ev, "ShareName");
                    if is_admin_share(&share) {
                        if let Some(ip) = remote_ip(ev) {
                            accesses.push(Access {
                                ev,
                                ip,
                                account: account(ev, "SubjectUserName", "SubjectDomainName"),
                                share: Some(share),
                            });
                        }
                    }
                }
                ("System", 7045) => services.push(ev),
                _ => {}
            }
        }

        let window = Duration::minutes(CORRELATION_WINDOW_MINUTES);
        let service_after = |t: DateTime<Utc>| {
            services
                .iter()
                .find(|sv| sv.ts >= t && sv.ts - t <= window)
                .copied()
        };
        let mut out = Vec::new();

        // Admin-share access per (source, account).
        let mut groups: BTreeMap<(String, String), Vec<&Access>> = BTreeMap::new();
        for a in accesses.iter().filter(|a| a.share.is_some()) {
            groups
                .entry((a.ip.clone(), a.account.clone()))
                .or_default()
                .push(a);
        }
        for ((ip, acct), list) in &groups {
            let first = list[0].ev;
            let last = list[list.len() - 1].ev;
            let mut shares: Vec<&str> = list.iter().filter_map(|a| a.share.as_deref()).collect();
            shares.sort_unstable();
            shares.dedup();
            let svc = list.iter().find_map(|a| service_after(a.ev.ts));
            let (severity, mitre): (Severity, &[&str]) = match svc {
                Some(_) => (Severity::High, &[ADMIN_SHARES, SERVICE_EXEC]),
                None => (Severity::Medium, &[ADMIN_SHARES]),
            };
            let mut f = base(
                first,
                severity,
                format!("遠端存取系統管理共用：{ip}"),
                mitre,
            );
            f.user = Some(acct.clone());
            f.details = format!(
                "{} admin-share access event(s) from {ip} as {acct} to {} between {} and {}",
                list.len(),
                shares.join(", "),
                fmt_ts(first.ts),
                fmt_ts(last.ts)
            );
            let mut reason = format!(
                "{ip} reached the administrative share(s) {} as {acct} ({} event(s)); \
                 admin shares are how PsExec-style tools copy their payload",
                shares.join(", "),
                list.len()
            );
            for a in list.iter().take(5) {
                f.evidence.push(evidence(
                    a.ev,
                    format!(
                        "EID {}: {} {} from {ip}",
                        a.ev.event_id,
                        a.share.as_deref().unwrap_or("-"),
                        s(a.ev, "RelativeTargetName")
                    ),
                ));
            }
            if let Some(sv) = svc {
                reason.push_str(&format!(
                    "; service {} ({}) installed at {}, within {CORRELATION_WINDOW_MINUTES} min",
                    s(sv, "ServiceName"),
                    s(sv, "ImagePath"),
                    fmt_ts(sv.ts)
                ));
                f.evidence.push(evidence(
                    sv,
                    format!(
                        "EID 7045: {} ImagePath={}",
                        s(sv, "ServiceName"),
                        s(sv, "ImagePath")
                    ),
                ));
            }
            f.reason = Some(reason);
            f.details_client = Some(format!(
                "來自 {ip} 的電腦以帳號 {acct} 存取了這台主機的系統管理共用資料夾（{}）。\
                 攻擊者常用這種方式把程式複製到其他電腦再遠端執行；請確認 {ip} 是不是\
                 IT 管理用的電腦、這個帳號當時是否在做維護工作。",
                shares.join("、")
            ));
            out.push(f);
        }

        // Remote-execution services.
        for sv in &services {
            let name = s(sv, "ServiceName");
            let image = s(sv, "ImagePath");
            let Some(why) = remote_exec_service(&name, &image) else {
                continue;
            };
            let source = accesses
                .iter()
                .rev()
                .find(|a| a.ev.ts <= sv.ts && sv.ts - a.ev.ts <= window);
            let mut f = base(
                sv,
                Severity::High,
                format!("遠端建立服務執行指令：{name}"),
                &[SERVICE_EXEC, ADMIN_SHARES],
            );
            f.details = format!("EID 7045: service {name} installed, ImagePath={image}");
            let from = match source {
                Some(a) => {
                    f.user = Some(a.account.clone());
                    f.evidence.push(evidence(
                        a.ev,
                        format!("EID {}: {} from {}", a.ev.event_id, a.account, a.ip),
                    ));
                    format!(
                        "; preceded at {} by {} from {} as {}",
                        fmt_ts(a.ev.ts),
                        if a.share.is_some() {
                            "admin-share access"
                        } else {
                            "a network logon"
                        },
                        a.ip,
                        a.account
                    )
                }
                None => {
                    "; no remote logon or share access within the window is in the log".to_string()
                }
            };
            f.reason = Some(format!("{why}{from}"));
            let origin = source
                .map(|a| format!("，來源可能是 {}", a.ip))
                .unwrap_or_default();
            f.details_client = Some(format!(
                "{} 這台主機被建立了一個名為「{name}」的服務來執行指令（{image}）{origin}。\
                 這是遠端控制工具（如 PsExec）或攻擊工具在其他電腦上執行指令的典型做法；\
                 請確認是否為 IT 人員的遠端管理作業。",
                sv.ts.format("%Y-%m-%d %H:%M UTC")
            ));
            out.push(f);
        }

        // NewCredentials logons per (account, process).
        for ((who, process), list) in &newcreds {
            let first = list[0];
            let mut f = base(
                first,
                Severity::Low,
                format!("以其他憑證建立網路登入（logon type 9）：{who}"),
                &[PASS_THE_HASH],
            );
            f.user = Some(who.clone());
            let process = if process.is_empty() {
                "-"
            } else {
                process.as_str()
            };
            f.details = format!(
                "{} NewCredentials (type 9, seclogo) logon(s) by {who} via {process}, first {}",
                list.len(),
                fmt_ts(first.ts)
            );
            f.reason = Some(format!(
                "{who} started {} logon(s) with separate network credentials (type 9, seclogo) \
                 via {process}; runas /netonly and pass-the-hash (sekurlsa::pth) both look like this",
                list.len()
            ));
            out.push(f);
        }

        Ok(crate::stamped(out, Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::{Map, Value};

    fn t(min: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap() + Duration::minutes(min)
    }

    fn ev(channel: &str, id: u32, min: i64, fields: &[(&str, &str)]) -> Record {
        let mut data = Map::new();
        for (k, v) in fields {
            data.insert((*k).into(), Value::String((*v).into()));
        }
        Record::Event(EventRecord {
            ts: t(min),
            channel: channel.into(),
            event_id: id,
            provider: String::new(),
            computer: "WS1".into(),
            record_id: (min as u64) * 10 + u64::from(id % 10),
            data,
        })
    }

    fn share(min: i64, ip: &str, name: &str) -> Record {
        ev(
            "Security",
            5145,
            min,
            &[
                ("ShareName", name),
                ("IpAddress", ip),
                ("SubjectUserName", "admin"),
                ("SubjectDomainName", "CORP"),
                ("RelativeTargetName", "x.exe"),
            ],
        )
    }

    fn service(min: i64, name: &str, image: &str) -> Record {
        ev(
            "System",
            7045,
            min,
            &[("ServiceName", name), ("ImagePath", image)],
        )
    }

    fn run(r: &[Record]) -> Vec<Finding> {
        LateralHeuristic.analyze(r, &[]).unwrap()
    }

    #[test]
    fn admin_share_names() {
        assert!(is_admin_share(r"\\*\ADMIN$"));
        assert!(is_admin_share(r"\\*\c$"));
        assert!(!is_admin_share(r"\\*\IPC$"));
        assert!(!is_admin_share(r"\\*\Finance$"));
        assert!(!is_admin_share(r"\\*\SYSVOL"));
    }

    #[test]
    fn admin_share_access_alone_is_medium_and_grouped() {
        let f = run(&[
            share(0, "10.0.0.9", r"\\*\ADMIN$"),
            share(1, "10.0.0.9", r"\\*\C$"),
            share(2, "127.0.0.1", r"\\*\ADMIN$"),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].mitre, vec!["T1021.002"]);
        assert_eq!(f[0].user.as_deref(), Some(r"CORP\admin"));
        assert_eq!(f[0].evidence.len(), 2);
        assert_eq!(f[0].analyzer, cairn_core::analyzers::LATERAL);
    }

    #[test]
    fn share_access_then_service_install_is_high() {
        let f = run(&[
            share(0, "10.0.0.9", r"\\*\ADMIN$"),
            service(3, "updsvc", r"C:\Windows\updsvc.exe"),
        ]);
        assert_eq!(f.len(), 1, "plain service: only the share finding");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].reason.as_deref().unwrap().contains("updsvc"));
        // Outside the window: stays Medium.
        let f = run(&[
            share(0, "10.0.0.9", r"\\*\ADMIN$"),
            service(30, "updsvc", r"C:\Windows\updsvc.exe"),
        ]);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn psexec_and_smbexec_services_name_the_preceding_logon() {
        let logon = ev(
            "Security",
            4624,
            0,
            &[
                ("LogonType", "3"),
                ("IpAddress", "::ffff:10.0.0.7"),
                ("TargetUserName", "svc"),
                ("TargetDomainName", "CORP"),
            ],
        );
        let f = run(&[logon, service(1, "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1569.002", "T1021.002"]);
        assert!(f[0].reason.as_deref().unwrap().contains("10.0.0.7"));
        assert_eq!(f[0].user.as_deref(), Some(r"CORP\svc"));

        let f = run(&[service(
            5,
            "BTOBTO",
            r"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat",
        )]);
        assert_eq!(f.len(), 1);
        assert!(f[0].reason.as_deref().unwrap().contains("no remote logon"));
    }

    #[test]
    fn ordinary_services_and_logons_are_quiet() {
        let f = run(&[
            service(0, "Spooler", r"C:\Windows\System32\spoolsv.exe"),
            ev(
                "Security",
                4624,
                1,
                &[("LogonType", "3"), ("IpAddress", "10.0.0.2")],
            ),
            ev(
                "Security",
                4624,
                2,
                &[("LogonType", "2"), ("IpAddress", "-")],
            ),
        ]);
        assert!(f.is_empty());
    }

    #[test]
    fn newcredentials_logons_are_low_and_grouped() {
        let pth = |min| {
            ev(
                "Security",
                4624,
                min,
                &[
                    ("LogonType", "9"),
                    ("LogonProcessName", "seclogo  "),
                    ("SubjectUserName", "bob"),
                    ("SubjectDomainName", "CORP"),
                    ("ProcessName", r"C:\Users\bob\m.exe"),
                ],
            )
        };
        let f = run(&[pth(0), pth(1)]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].mitre, vec!["T1550.002"]);
        assert!(f[0].reason.as_deref().unwrap().contains("2 logon"));
    }
}
