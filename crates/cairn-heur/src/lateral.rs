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
//!   `PSEXESVC`, points into `ADMIN$` / `\\127.0.0.1\`, runs `%COMSPEC%` /
//!   `cmd.exe /c` as the service binary, as smbexec does, or is an exe directly in
//!   the Windows folder, where Metasploit psexec / PAExec / RemCom copy it): High, with the network
//!   logon (4624 type 3) or admin-share access that preceded it within the window
//!   named as the likely source.
//! - **NewCredentials logons** (4624 type 9, logon process `seclogo`), grouped per
//!   (account, process): Low. `runas /netonly` and Mimikatz `sekurlsa::pth` both
//!   produce it, so it is context for the other findings, not a verdict.
//!
//! - **Remote Desktop logons** (Security 4624 type 10, type 7 with a remote address,
//!   4778 session reconnect; TerminalServices-RemoteConnectionManager 1149;
//!   TerminalServices-LocalSessionManager 21 / 24 / 25), grouped per (source address,
//!   account), T1021.001. From a public address: High. Through a local tunnel (4624
//!   type 10 from loopback, or a LocalSessionManager address carrying the
//!   `%16777216` zone that ngrok-style forwarding leaves): High. From a private
//!   address: Low context, Medium when the same source also failed to log on as that
//!   account (4625) or it is the account's first logon in a window that covers at
//!   least [`NEW_ACCOUNT_LOOKBACK_HOURS`] of earlier Security log. Console / loopback
//!   / empty sources are ignored.
//! - **Explicit-credential logons to another host** (Security 4648 whose
//!   TargetServerName is neither localhost nor this computer — or names this computer
//!   while `IpAddress` is remote, see below — and whose target account differs from
//!   the caller), grouped per (caller, server, process) with the target accounts
//!   listed: Medium, T1021 / T1550 context; High with T1110.003 when one group used
//!   at least [`EXPLICIT_SPRAY_ACCOUNTS`] different accounts (password spraying over
//!   SMB). Same-account 4648s (lsass / svchost re-using the caller's own
//!   credentials) are the noise and are skipped.
//! - **WMI-Activity** (`Microsoft-Windows-WMI-Activity/Operational`): 5861 permanent
//!   consumer bound (T1546.003): High for CommandLine / ActiveScript consumers, Medium
//!   for other consumer types, the stock BVTConsumer / SCM Event Log Consumer skipped.
//!   5860 temporary consumer registered (T1047): Medium, skipped when a system
//!   account registered it from this computer. 5857 provider loaded (T1047): Medium
//!   only when the provider DLL is in a user-writable folder.
//!
//! Field names checked against real logs (`tests/fixtures/README.md` names the files):
//! - 5140 / 5145: `ShareName` (`\\*\ADMIN$`), `RelativeTargetName` (5145),
//!   `IpAddress`, `IpPort`, `SubjectUserName`, `SubjectDomainName`. Confirmed.
//! - 7045: `ServiceName`, `ImagePath`, `AccountName`. Confirmed (Metasploit psexec
//!   puts its exe directly in `%SYSTEMROOT%\`, the ADMIN$ root: flagged too).
//! - 4624: `LogonType` (a number), `IpAddress` (`::ffff:` prefix seen),
//!   `LogonProcessName` (`seclogo` for type 9), `TargetUserName`. Confirmed.
//! - 4648: `SubjectUserName`, `TargetUserName`, `TargetServerName`, `TargetInfo`,
//!   `ProcessId`, `ProcessName`, `IpAddress`, `IpPort`. Confirmed, with a correction:
//!   an SMB logon to a remote IP is logged with TargetServerName = this computer's
//!   own name and the remote end only in `IpAddress` (port 445, ProcessName empty,
//!   PID 4), so that address is the target. Winlogon / lsass 4648s for this host
//!   (`localhost`, machine-account caller) stay skipped.
//! - RemoteConnectionManager 1149: UserData `EventXML` { `Param1` user, `Param2`
//!   domain, `Param3` source address }. Confirmed.
//! - WMI-Activity 5857: `Operation_StartedOperational` { `ProviderName`, `Code`,
//!   `HostProcess`, `ProcessID`, `ProviderPath` }. 5860: `Operation_TemporaryEssStarted`
//!   { `NamespaceName` (not `Namespace`), `Query`, `User`, `Processid`, `ClientMachine`,
//!   `PossibleCause` }; ClientMachine is the NetBIOS name, cut to 15 characters, so it
//!   is compared to the computer name with that cut. 5861: `Operation_ESStoConsumerBinding`
//!   { `Namespace`, `ESS`, `CONSUMER`, `PossibleCause` }. Confirmed.
//! - NOT yet checked against a real log (no public sample found): LocalSessionManager
//!   21 / 24 / 25 (`User`, `SessionID`, `Address` in UserData `EventXML`) and 4778
//!   (`AccountName`, `AccountDomain`, `ClientAddress`).
//!
//! The 5140 / 5145 events need "Audit File Share" auditing, which is off by default;
//! without it only the 7045 path fires. 4778 needs "Other Logon/Logoff Events"
//! auditing (off by default); the TerminalServices and WMI-Activity channels and
//! 4624 / 4625 / 4648 are written by default.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::{EventRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

use crate::cmdline::{event_field, event_str};
use crate::rmm::is_public_ip;
use crate::trust::{is_user_writable_path, is_windows_root_exe};

/// How long after a remote logon / share access a service install is tied to it.
pub const CORRELATION_WINDOW_MINUTES: i64 = 10;

/// A private-address RDP logon is "the account's first" only when the Security log
/// already covered at least this many hours before it without a logon by that account.
pub const NEW_ACCOUNT_LOOKBACK_HOURS: i64 = 24;

/// TerminalServices-RemoteConnectionManager: 1149 (RDP network authentication
/// succeeded; user, domain and source address in `Param1..3`).
pub const RCM_CHANNEL: &str =
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
/// TerminalServices-LocalSessionManager: 21 logon, 24 disconnect, 25 reconnect
/// (`User`, `SessionID`, `Address`).
pub const LSM_CHANNEL: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
/// WMI-Activity operational log: 5857 provider loaded, 5860 temporary and 5861
/// permanent event consumers.
pub const WMI_CHANNEL: &str = "Microsoft-Windows-WMI-Activity/Operational";

/// Channels this analyzer reads (all written by default). The live EVTX collector
/// reads them even when no Sigma rules are loaded.
pub const CHANNELS: &[&str] = &["Security", "System", RCM_CHANNEL, LSM_CHANNEL, WMI_CHANNEL];

const ADMIN_SHARES: &str = "T1021.002";
const SERVICE_EXEC: &str = "T1569.002";
const PASS_THE_HASH: &str = "T1550.002";
const RDP: &str = "T1021.001";
const REMOTE_SERVICES: &str = "T1021";
const ALT_AUTH: &str = "T1550";
const WMI: &str = "T1047";
const WMI_SUBSCRIPTION: &str = "T1546.003";

/// The channel constant `raw` names (any case), else `raw` itself: modern channel
/// names are compared case-insensitively.
fn canonical_channel(raw: &str) -> &str {
    CHANNELS
        .iter()
        .find(|c| c.eq_ignore_ascii_case(raw))
        .copied()
        .unwrap_or(raw)
}

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
    if is_windows_root_exe(&i) {
        return Some(
            "service binary sits directly in the Windows folder, the ADMIN$ share root where \
             PsExec-style tools (Metasploit psexec, PAExec, RemCom) copy their service exe",
        );
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

// ---------------------------------------------------------------------------
// Remote Desktop
// ---------------------------------------------------------------------------

/// Where an RDP client connected from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RdpSource {
    /// A private / link-local / CGNAT address, or a client name that is not an IP.
    Private,
    /// A routable public address.
    Public,
    /// Loopback reached through a local port forward (ngrok, plink, chisel, ...).
    Tunneled,
}

/// Classify an RDP client address. None for the console and for sources that are
/// not a remote client: empty, `-`, `LOCAL`, `UNKNOWN`, loopback, unspecified. A
/// LocalSessionManager address with the `%16777216` zone (what an ngrok-style forward
/// to the local RDP port leaves, per the Sigma rule "Ngrok Usage with Remote Desktop
/// Service") is [`RdpSource::Tunneled`].
pub fn rdp_source(raw: &str) -> Option<(String, RdpSource)> {
    let a = raw.trim();
    if a.contains("%16777216") {
        return Some((a.to_string(), RdpSource::Tunneled));
    }
    let a = a.trim_start_matches("::ffff:");
    if is_not_remote(a) {
        return None;
    }
    let kind = if is_public_ip(a) {
        RdpSource::Public
    } else {
        RdpSource::Private
    };
    Some((a.to_string(), kind))
}

fn is_loopback(a: &str) -> bool {
    a == "::1" || a.starts_with("127.")
}

fn is_not_remote(a: &str) -> bool {
    a.is_empty()
        || a == "-"
        || a == "::"
        || a == "0.0.0.0"
        || a.eq_ignore_ascii_case("local")
        || a.eq_ignore_ascii_case("unknown")
        || is_loopback(a)
}

/// Lowercase user part of `DOMAIN\user` / `user@domain`: the grouping key, so the
/// same account matches across events that spell its domain differently.
fn account_key(acct: &str) -> String {
    let u = acct.rsplit('\\').next().unwrap_or(acct);
    let u = u.split('@').next().unwrap_or(u);
    u.trim().to_ascii_lowercase()
}

/// Built-in principals that never stand for a person.
fn is_system_account(acct: &str) -> bool {
    let k = account_key(acct);
    k.is_empty()
        || k == "-"
        || k.ends_with('$')
        || matches!(
            k.as_str(),
            "system" | "local service" | "network service" | "anonymous logon"
        )
        || k.starts_with("dwm-")
        || k.starts_with("umfd-")
        || matches!(acct.trim(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
}

/// First DNS label, lowercase (`WS1.corp.local` -> `ws1`).
fn host_label(h: &str) -> String {
    h.trim()
        .trim_start_matches(r"\\")
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// One RDP-related event, normalized.
struct RdpEvent<'a> {
    ev: &'a EventRecord,
    ip: String,
    kind: RdpSource,
    account: String,
    what: &'static str,
    /// A logon or reconnect (not a disconnect).
    logon: bool,
}

/// What the RDP part gathers in the single pass over the events.
#[derive(Default)]
struct RdpInput<'a> {
    events: Vec<RdpEvent<'a>>,
    /// 4625 failures per (source, account key).
    failures: BTreeMap<(String, String), usize>,
    /// Earliest 4624 per account key, any logon type.
    first_logon: BTreeMap<String, DateTime<Utc>>,
    /// Earliest Security event seen: how far back the log reaches.
    security_start: Option<DateTime<Utc>>,
}

impl<'a> RdpInput<'a> {
    fn push(
        &mut self,
        ev: &'a EventRecord,
        raw: &str,
        account: String,
        what: &'static str,
        logon: bool,
        loopback_is_tunnel: bool,
    ) {
        let src = rdp_source(raw).or_else(|| {
            (loopback_is_tunnel && is_loopback(raw.trim()))
                .then(|| (raw.trim().to_string(), RdpSource::Tunneled))
        });
        if let Some((ip, kind)) = src {
            self.events.push(RdpEvent {
                ev,
                ip,
                kind,
                account,
                what,
                logon,
            });
        }
    }

    fn observe(&mut self, channel: &str, ev: &'a EventRecord) {
        match (channel, ev.event_id) {
            ("Security", id) => {
                self.security_start = Some(self.security_start.map_or(ev.ts, |t| t.min(ev.ts)));
                match id {
                    4624 => {
                        let acct = account(ev, "TargetUserName", "TargetDomainName");
                        if !is_system_account(&acct) {
                            let first = self.first_logon.entry(account_key(&acct)).or_insert(ev.ts);
                            *first = (*first).min(ev.ts);
                        }
                        let ip = s(ev, "IpAddress");
                        match s(ev, "LogonType").trim() {
                            "10" => self.push(
                                ev,
                                &ip,
                                acct,
                                "4624 type 10 (RemoteInteractive) logon",
                                true,
                                true,
                            ),
                            "7" => self.push(
                                ev,
                                &ip,
                                acct,
                                "4624 type 7 (unlock / reconnect) from a remote address",
                                true,
                                false,
                            ),
                            _ => {}
                        }
                    }
                    4625 => {
                        let ip = s(ev, "IpAddress");
                        let ip = ip.trim().trim_start_matches("::ffff:");
                        if !is_not_remote(ip) {
                            let k = account_key(&s(ev, "TargetUserName"));
                            *self
                                .failures
                                .entry((ip.to_ascii_lowercase(), k))
                                .or_default() += 1;
                        }
                    }
                    4778 => self.push(
                        ev,
                        &s(ev, "ClientAddress"),
                        account(ev, "AccountName", "AccountDomain"),
                        "4778 session reconnected",
                        true,
                        false,
                    ),
                    _ => {}
                }
            }
            (RCM_CHANNEL, 1149) => {
                let f = |k| event_field(&ev.data, k).unwrap_or_default();
                let (user, domain) = (f("Param1"), f("Param2"));
                let acct = if domain.trim().is_empty() {
                    user.trim().to_string()
                } else {
                    format!(r"{}\{}", domain.trim(), user.trim())
                };
                self.push(
                    ev,
                    &f("Param3"),
                    acct,
                    "RemoteConnectionManager 1149 RDP authentication succeeded",
                    true,
                    false,
                );
            }
            (LSM_CHANNEL, id @ (21 | 24 | 25)) => {
                let f = |k| event_field(&ev.data, k).unwrap_or_default();
                let (what, logon) = match id {
                    21 => ("LocalSessionManager 21 session logon", true),
                    24 => ("LocalSessionManager 24 session disconnected", false),
                    _ => ("LocalSessionManager 25 session reconnected", true),
                };
                self.push(ev, &f("Address"), f("User"), what, logon, false);
            }
            _ => {}
        }
    }

    fn findings(&self) -> Vec<Finding> {
        let mut groups: BTreeMap<(String, String), Vec<&RdpEvent>> = BTreeMap::new();
        for e in &self.events {
            groups
                .entry((e.ip.to_ascii_lowercase(), account_key(&e.account)))
                .or_default()
                .push(e);
        }
        let lookback = Duration::hours(NEW_ACCOUNT_LOOKBACK_HOURS);
        let mut out = Vec::new();
        for ((ip_key, acct_key), list) in &groups {
            let first = list[0];
            let last = list[list.len() - 1];
            let ip = first.ip.clone();
            let acct = list
                .iter()
                .map(|e| e.account.trim())
                .find(|a| a.contains('\\'))
                .or_else(|| {
                    list.iter()
                        .map(|e| e.account.trim())
                        .find(|a| !a.is_empty())
                })
                .unwrap_or("-")
                .to_string();
            let kind = list.iter().map(|e| e.kind).max().unwrap_or(first.kind);
            let failures = self
                .failures
                .get(&(ip_key.clone(), acct_key.clone()))
                .copied()
                .unwrap_or(0);
            let has_4624 = list
                .iter()
                .any(|e| e.ev.event_id == 4624 && canonical_channel(&e.ev.channel) == "Security");
            let new_account = has_4624
                && !acct_key.is_empty()
                && self
                    .first_logon
                    .get(acct_key)
                    .is_some_and(|t| *t >= first.ev.ts)
                && self
                    .security_start
                    .is_some_and(|t| t + lookback <= first.ev.ts);
            let mut why: Vec<String> = Vec::new();
            let severity = match kind {
                RdpSource::Public => {
                    why.push(format!("{ip} is a public address"));
                    Severity::High
                }
                RdpSource::Tunneled => {
                    why.push(format!(
                        "the client address {ip} is the local machine: the session came \
                         through a local port forward / tunnel (ngrok, plink, chisel, ...)"
                    ));
                    Severity::High
                }
                RdpSource::Private => {
                    why.push(format!("{ip} is a private address"));
                    if failures > 0 || new_account {
                        Severity::Medium
                    } else {
                        Severity::Low
                    }
                }
            };
            if failures > 0 {
                why.push(format!(
                    "{failures} failed logon(s) (4625) as this account from the same source"
                ));
            }
            if new_account {
                why.push(format!(
                    "first logon of this account in the collected Security log, which reaches \
                     at least {NEW_ACCOUNT_LOOKBACK_HOURS} h further back"
                ));
            }
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for e in list {
                *counts.entry(e.what).or_default() += 1;
            }
            let summary: Vec<String> = counts.iter().map(|(w, n)| format!("{w} x{n}")).collect();
            let logons = list.iter().filter(|e| e.logon).count();
            let mut f = base(
                first.ev,
                severity,
                format!("遠端桌面（RDP）連入：{ip}"),
                &[RDP],
            );
            f.user = (acct != "-").then(|| acct.clone());
            f.details = format!(
                "{} RDP event(s) from {ip} as {acct} between {} and {}: {}",
                list.len(),
                fmt_ts(first.ev.ts),
                fmt_ts(last.ev.ts),
                summary.join(", ")
            );
            f.reason = Some(format!(
                "remote desktop from {ip} as {acct}: {logons} logon / reconnect event(s) ({}); {}",
                summary.join(", "),
                why.join("; ")
            ));
            for e in list.iter().take(8) {
                f.evidence.push(evidence(
                    e.ev,
                    format!(
                        "EID {}: {} from {} as {}",
                        e.ev.event_id, e.what, e.ip, e.account
                    ),
                ));
            }
            let extra = match kind {
                RdpSource::Public => {
                    "這個位址在網際網路上，代表遠端桌面直接開放到外部，或有人從外部連進來；"
                }
                RdpSource::Tunneled => {
                    "連線來源顯示為本機，代表有人透過通道程式（例如 ngrok）把遠端桌面轉到外部；"
                }
                RdpSource::Private => "",
            };
            f.details_client = Some(format!(
                "{} 起，有人從 {ip} 以帳號 {acct} 用遠端桌面連入這台主機（共 {} 筆紀錄）。{extra}\
                 請確認這個帳號當時是否由本人或 IT 人員使用，來源電腦是否為公司設備。",
                first.ev.ts.format("%Y-%m-%d %H:%M UTC"),
                list.len()
            ));
            out.push(f);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Explicit credentials (4648)
// ---------------------------------------------------------------------------

/// Longest NetBIOS computer name. Windows logs the NetBIOS form in some fields
/// (WMI-Activity 5860 `ClientMachine`), so a 16+ character DNS host name shows up cut
/// to its first 15 characters (real log: Computer `DESKTOP-BZCP2020`, ClientMachine
/// `DESKTOP-BZCP202`).
const NETBIOS_NAME_MAX: usize = 15;

/// True when two host names name the same computer: same first DNS label, or one is
/// the other's NetBIOS form (the label cut to [`NETBIOS_NAME_MAX`] characters).
fn same_host(a: &str, b: &str) -> bool {
    let (a, b) = (host_label(a), host_label(b));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let (short, long) = if a.chars().count() <= b.chars().count() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    a == b
        || (short.chars().count() == NETBIOS_NAME_MAX
            && long.chars().take(NETBIOS_NAME_MAX).eq(short.chars()))
}

/// True when a host name names this computer or the loopback (or is empty).
fn is_local_target(server: &str, computer: &str) -> bool {
    let srv = server.trim();
    srv.is_empty()
        || srv == "-"
        || srv == "."
        || srv.eq_ignore_ascii_case("localhost")
        || is_loopback(srv)
        || same_host(srv, computer)
}

/// Distinct target accounts one caller tried against one server (one process) at or
/// above which the 4648 group reads as password spraying rather than one admin task.
pub const EXPLICIT_SPRAY_ACCOUNTS: usize = 5;
const PASSWORD_SPRAYING: &str = "T1110.003";

/// Where a 4648 logon went, or None when it stayed on this computer.
///
/// `TargetServerName` is the primary answer. Real logs also show an SMB logon to a
/// remote IP (`net use \\10.0.0.5 /user:...`) recorded with `TargetServerName` /
/// `TargetInfo` = this computer's own name, the remote end only in `IpAddress` (with
/// `IpPort` 445) — DeepBlueCLI `password-spray.evtx`. So a local-looking server name
/// with a remote `IpAddress` counts as that address, unless the caller is the machine
/// account: winlogon's 4648 for an incoming RDP / console logon also carries the
/// client's address there.
fn explicit_target(ev: &EventRecord, subject: &str) -> Option<String> {
    let server = s(ev, "TargetServerName").trim().to_string();
    if !is_local_target(&server, &ev.computer) {
        return Some(server);
    }
    if is_system_account(subject) {
        return None;
    }
    let ip = s(ev, "IpAddress");
    let ip = ip.trim().trim_start_matches("::ffff:");
    (!is_not_remote(ip)).then(|| ip.to_string())
}

/// 4648 logons with another account's credentials to another host, grouped per
/// (caller, server, process); the target accounts are listed in the finding.
fn explicit_credential_findings(events: &[&EventRecord]) -> Vec<Finding> {
    type Key = (String, String, String);
    let mut groups: BTreeMap<Key, Vec<(&EventRecord, String)>> = BTreeMap::new();
    for ev in events {
        let subject = account(ev, "SubjectUserName", "SubjectDomainName");
        let Some(server) = explicit_target(ev, &subject) else {
            continue;
        };
        let target = account(ev, "TargetUserName", "TargetDomainName");
        let (sk, tk) = (account_key(&subject), account_key(&target));
        // Same account: the caller re-using its own credentials (the lsass / svchost
        // noise). Machine account to machine account: Kerberos housekeeping.
        if sk == tk || tk.is_empty() || (sk.ends_with('$') && tk.ends_with('$')) {
            continue;
        }
        groups
            .entry((
                sk,
                server.to_ascii_lowercase(),
                s(ev, "ProcessName").trim().to_ascii_lowercase(),
            ))
            .or_default()
            .push((ev, server));
    }
    let mut out = Vec::new();
    for list in groups.values() {
        let (first, server) = (list[0].0, list[0].1.clone());
        let subject = account(first, "SubjectUserName", "SubjectDomainName");
        let mut targets: Vec<String> = Vec::new();
        for (ev, _) in list {
            let t = account(ev, "TargetUserName", "TargetDomainName");
            if !targets.iter().any(|x| account_key(x) == account_key(&t)) {
                targets.push(t);
            }
        }
        // An SMB logon is made by the kernel's SMB client: ProcessName empty, PID 4.
        let process = match (s(first, "ProcessName").trim(), s(first, "ProcessId").trim()) {
            ("" | "-", "0x4" | "4") => "System (kernel SMB client, PID 4)".to_string(),
            ("" | "-", _) => "-".to_string(),
            (p, _) => p.to_string(),
        };
        let spray = targets.len() >= EXPLICIT_SPRAY_ACCOUNTS;
        let shown: Vec<&str> = targets.iter().take(10).map(String::as_str).collect();
        let more = targets.len() - shown.len();
        let target_list = if more > 0 {
            format!("{} (+{more} more)", shown.join(", "))
        } else {
            shown.join(", ")
        };
        let mut f = if spray {
            base(
                first,
                Severity::High,
                format!("以多個帳號憑證嘗試登入其他主機：{server}"),
                &[REMOTE_SERVICES, ALT_AUTH, PASSWORD_SPRAYING],
            )
        } else {
            base(
                first,
                Severity::Medium,
                format!("以其他帳號憑證連到其他主機：{server}"),
                &[REMOTE_SERVICES, ALT_AUTH],
            )
        };
        f.user = Some(subject.clone());
        f.details = format!(
            "{} explicit-credential logon(s) (4648) by {subject} to {server} via {process} \
             with {} account(s): {target_list}; first {}",
            list.len(),
            targets.len(),
            fmt_ts(first.ts)
        );
        f.reason = Some(if spray {
            format!(
                "{process} running as {subject} supplied the credentials of {} different \
                 accounts to log on to {server} ({} time(s), 4648): {target_list}; one caller \
                 cycling through many accounts against one host is password spraying / \
                 credential stuffing",
                targets.len(),
                list.len()
            )
        } else {
            format!(
                "{process} running as {subject} supplied the credentials of {target_list} to \
                 log on to {server} ({} time(s), 4648); another account's credentials used \
                 against another host is what runas / net use / PsExec -u and \
                 stolen-credential lateral movement look like",
                list.len()
            )
        });
        for (ev, _) in list.iter().take(5) {
            f.evidence.push(evidence(
                ev,
                format!(
                    "EID 4648: {subject} -> {} on {server} via {process} \
                     (TargetServerName={}, TargetInfo={}, IpAddress={}, IpPort={})",
                    account(ev, "TargetUserName", "TargetDomainName"),
                    s(ev, "TargetServerName"),
                    s(ev, "TargetInfo"),
                    s(ev, "IpAddress"),
                    s(ev, "IpPort")
                ),
            ));
        }
        f.details_client = Some(if spray {
            format!(
                "帳號 {subject} 在這台主機上，用 {} 個不同帳號的密碼嘗試登入另一台電腦 {server}。\
                 這是攻擊者猜測或試用竊得密碼（密碼噴灑）的典型行為；請確認這台主機是否遭到入侵。",
                targets.len()
            )
        } else {
            format!(
                "帳號 {subject} 在這台主機上透過 {process}，改用另一個帳號 {target_list} 的密碼登入另一台電腦 {server}。\
                 IT 人員做維護時會這樣做，但攻擊者拿到密碼後橫向移動也會留下同樣的紀錄；\
                 請確認當時是否有人在做這項工作。"
            )
        });
        out.push(f);
    }
    out
}

// ---------------------------------------------------------------------------
// WMI-Activity
// ---------------------------------------------------------------------------

/// Consumers Windows itself registers (NTEventLogEventConsumer instances).
const STOCK_WMI_CONSUMERS: &[&str] = &["bvtconsumer", "scm event log consumer"];

fn wf(ev: &EventRecord, key: &str) -> String {
    event_field(&ev.data, key).unwrap_or_default()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push_str("...");
        out
    }
}

fn or_dash(s: &str) -> &str {
    match s.trim() {
        "" => "-",
        t => t,
    }
}

/// WMI-Activity 5857 / 5860 / 5861 findings (see module docs).
fn wmi_findings(events: &[&EventRecord]) -> Vec<Finding> {
    type TempKey = (String, String, String);
    let mut permanent: BTreeMap<(String, String), Vec<&EventRecord>> = BTreeMap::new();
    let mut temporary: BTreeMap<TempKey, Vec<&EventRecord>> = BTreeMap::new();
    let mut providers: BTreeMap<String, Vec<&EventRecord>> = BTreeMap::new();
    for ev in events {
        match ev.event_id {
            5861 => {
                let lc = wf(ev, "CONSUMER").to_ascii_lowercase();
                if STOCK_WMI_CONSUMERS.iter().any(|c| lc.contains(c)) {
                    continue;
                }
                permanent
                    .entry((wf(ev, "ESS").to_ascii_lowercase(), lc))
                    .or_default()
                    .push(ev);
            }
            5860 => {
                let user = wf(ev, "User");
                let client = wf(ev, "ClientMachine");
                if is_local_target(&client, &ev.computer) && is_system_account(&user) {
                    continue;
                }
                temporary
                    .entry((
                        user.to_ascii_lowercase(),
                        client.to_ascii_lowercase(),
                        wf(ev, "Query").to_ascii_lowercase(),
                    ))
                    .or_default()
                    .push(ev);
            }
            5857 => {
                let path = wf(ev, "ProviderPath");
                if is_user_writable_path(&path) {
                    providers
                        .entry(path.to_ascii_lowercase())
                        .or_default()
                        .push(ev);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for list in permanent.values() {
        let ev = list[0];
        let (ess, consumer, cause) = (wf(ev, "ESS"), wf(ev, "CONSUMER"), wf(ev, "PossibleCause"));
        let text = format!("{consumer} {cause}").to_ascii_lowercase();
        let scripted = ["commandlineeventconsumer", "activescripteventconsumer"]
            .iter()
            .any(|c| text.contains(c));
        let severity = if scripted {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut f = base(
            ev,
            severity,
            format!("WMI 永久事件訂閱：{}", or_dash(&consumer)),
            &[WMI_SUBSCRIPTION],
        );
        f.details = format!(
            "EID 5861 x{}: filter {ess} bound to {consumer} in {}; {}",
            list.len(),
            wf(ev, "Namespace"),
            clip(&cause, 600)
        );
        f.reason = Some(format!(
            "a permanent WMI event consumer was bound (5861): filter {} -> {}{}; permanent \
             subscriptions survive reboots and run as SYSTEM, a known fileless persistence \
             method",
            or_dash(&ess),
            or_dash(&consumer),
            if scripted {
                " (runs a command line or script)"
            } else {
                ""
            }
        ));
        for e in list.iter().take(5) {
            f.evidence.push(evidence(
                e,
                format!("EID 5861: {} -> {}", wf(e, "ESS"), wf(e, "CONSUMER")),
            ));
        }
        f.details_client = Some(format!(
            "這台主機在 {} 新增了一個 WMI 永久事件訂閱（{}）。這種設定會在特定事件發生時自動執行程式，\
             重開機後仍然有效，是攻擊者常用的隱藏常駐手法；請確認是否為已知的管理軟體所建立。",
            ev.ts.format("%Y-%m-%d %H:%M UTC"),
            or_dash(&consumer)
        ));
        out.push(f);
    }
    for list in temporary.values() {
        let ev = list[0];
        let (user, client, query) = (wf(ev, "User"), wf(ev, "ClientMachine"), wf(ev, "Query"));
        let remote = !is_local_target(&client, &ev.computer);
        let user_d = or_dash(&user).to_string();
        let mut f = base(
            ev,
            Severity::Medium,
            format!("WMI 暫時事件訂閱：{user_d}"),
            &[WMI],
        );
        f.user = Some(user_d.clone());
        f.details = format!(
            "EID 5860 x{}: {user_d} from {} registered a temporary consumer in {}: {}",
            list.len(),
            or_dash(&client),
            // 5860 names it `NamespaceName` (5861 uses `Namespace`); real-log verified.
            or_dash(&wf(ev, "NamespaceName")),
            clip(&query, 400)
        );
        f.reason = Some(format!(
            "{user_d} registered a temporary WMI event consumer ({} time(s), 5860){} for query \
             {}; scripts use this to watch for events (process starts, logons) while they run",
            list.len(),
            if remote {
                format!(" from the remote machine {}", client.trim())
            } else {
                String::new()
            },
            clip(&query, 200)
        ));
        for e in list.iter().take(5) {
            f.evidence.push(evidence(
                e,
                format!(
                    "EID 5860: user={} client={} pid={} query={}",
                    wf(e, "User"),
                    wf(e, "ClientMachine"),
                    wf(e, "Processid"),
                    clip(&wf(e, "Query"), 200)
                ),
            ));
        }
        f.details_client = Some(format!(
            "帳號 {user_d} 在這台主機上建立了 WMI 暫時事件監看（{}）。管理工具偶爾會這樣做，\
             攻擊腳本也會用它來監看系統活動；請確認是否為已知的管理或監控軟體。",
            clip(&query, 120)
        ));
        out.push(f);
    }
    for list in providers.values() {
        let ev = list[0];
        let (name, path, host) = (
            wf(ev, "ProviderName"),
            wf(ev, "ProviderPath"),
            wf(ev, "HostProcess"),
        );
        let mut f = base(
            ev,
            Severity::Medium,
            format!("WMI provider 從使用者可寫入路徑載入：{}", or_dash(&name)),
            &[WMI],
        );
        f.entity.file = Some(cairn_core::finding::EntityFile {
            path: path.clone(),
            sha256: None,
            mtime: None,
        });
        f.details = format!(
            "EID 5857 x{}: provider {name} loaded from {path} by {host}",
            list.len()
        );
        f.reason = Some(format!(
            "WMI loaded provider {} from {path}, a user-writable folder ({} time(s), 5857); \
             stock providers live under System32\\wbem or Program Files, and a provider DLL in \
             a user folder runs its code inside the WMI host",
            or_dash(&name),
            list.len()
        ));
        for e in list.iter().take(5) {
            f.evidence.push(evidence(
                e,
                format!(
                    "EID 5857: {} from {} host={} pid={}",
                    wf(e, "ProviderName"),
                    wf(e, "ProviderPath"),
                    wf(e, "HostProcess"),
                    wf(e, "ProcessID")
                ),
            ));
        }
        f.details_client = Some(format!(
            "WMI 服務從使用者可以寫入的資料夾載入了元件 {path}。正常的 WMI 元件都在系統資料夾或 Program Files 裡；\
             請確認這個檔案是否為已知軟體所安裝。"
        ));
        out.push(f);
    }
    out
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
        let mut rdp = RdpInput::default();
        let mut explicit: Vec<&EventRecord> = Vec::new();
        let mut wmi: Vec<&EventRecord> = Vec::new();
        for ev in &events {
            let channel = canonical_channel(&ev.channel);
            rdp.observe(channel, ev);
            match (channel, ev.event_id) {
                ("Security", 4648) => explicit.push(ev),
                (WMI_CHANNEL, 5857 | 5860 | 5861) => wmi.push(ev),
                _ => {}
            }
            match (channel, ev.event_id) {
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

        out.extend(rdp.findings());
        out.extend(explicit_credential_findings(&explicit));
        out.extend(wmi_findings(&wmi));
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
            record_id: min.unsigned_abs() * 10 + u64::from(id % 10),
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
            service(3, "updsvc", r"C:\Program Files\Upd\updsvc.exe"),
        ]);
        assert_eq!(f.len(), 1, "plain service: only the share finding");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].reason.as_deref().unwrap().contains("updsvc"));
        // Outside the window: stays Medium.
        let f = run(&[
            share(0, "10.0.0.9", r"\\*\ADMIN$"),
            service(30, "updsvc", r"C:\Program Files\Upd\updsvc.exe"),
        ]);
        assert_eq!(f[0].severity, Severity::Medium);
        // The same exe copied to the ADMIN$ root (C:\Windows) is itself the remote-exec
        // pattern (real Metasploit psexec: %SYSTEMROOT%\duKhLYUX.exe).
        let f = run(&[service(3, "updsvc", r"%SYSTEMROOT%\updsvc.exe")]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].mitre, vec!["T1569.002", "T1021.002"]);
        assert!(f[0].reason.as_deref().unwrap().contains("Windows folder"));
        let f = run(&[service(3, "w", r"%SystemRoot%\System32\w.exe")]);
        assert!(f.is_empty(), "{f:?}");
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

    /// An event whose payload is a UserData element (`<UserData><EventXML>...`), as the
    /// EVTX collector flattens it: one nested object under the element's name.
    fn ud(channel: &str, id: u32, min: i64, element: &str, fields: &[(&str, &str)]) -> Record {
        let mut inner = Map::new();
        inner.insert(
            "#attributes".into(),
            serde_json::json!({ "xmlns": "Event_NS" }),
        );
        for (k, v) in fields {
            inner.insert((*k).into(), Value::String((*v).into()));
        }
        let mut data = Map::new();
        data.insert(element.into(), Value::Object(inner));
        Record::Event(EventRecord {
            ts: t(min),
            channel: channel.into(),
            event_id: id,
            provider: String::new(),
            computer: "WS1.corp.local".into(),
            record_id: (min.unsigned_abs()) * 10 + u64::from(id % 10),
            data,
        })
    }

    fn logon(min: i64, logon_type: &str, ip: &str, user: &str) -> Record {
        ev(
            "Security",
            4624,
            min,
            &[
                ("LogonType", logon_type),
                ("IpAddress", ip),
                ("TargetUserName", user),
                ("TargetDomainName", "CORP"),
            ],
        )
    }

    fn failed(min: i64, ip: &str, user: &str) -> Record {
        ev(
            "Security",
            4625,
            min,
            &[("IpAddress", ip), ("TargetUserName", user)],
        )
    }

    fn lsm(id: u32, min: i64, address: &str, user: &str) -> Record {
        ud(
            LSM_CHANNEL,
            id,
            min,
            "EventXML",
            &[("User", user), ("SessionID", "2"), ("Address", address)],
        )
    }

    fn rcm(min: i64, user: &str, domain: &str, ip: &str) -> Record {
        ud(
            RCM_CHANNEL,
            1149,
            min,
            "EventXML",
            &[("Param1", user), ("Param2", domain), ("Param3", ip)],
        )
    }

    fn rdp_only(f: Vec<Finding>) -> Vec<Finding> {
        f.into_iter().filter(|f| f.mitre == vec![RDP]).collect()
    }

    #[test]
    fn rdp_source_classification() {
        assert_eq!(
            rdp_source("203.0.113.9").map(|s| s.1),
            Some(RdpSource::Private),
            "documentation range is not public"
        );
        assert_eq!(rdp_source("8.8.8.8").unwrap().1, RdpSource::Public);
        assert_eq!(rdp_source("::ffff:8.8.8.8").unwrap().0, "8.8.8.8");
        assert_eq!(rdp_source("10.1.2.3").unwrap().1, RdpSource::Private);
        assert_eq!(rdp_source("::%16777216").unwrap().1, RdpSource::Tunneled);
        for local in ["", "-", "LOCAL", "127.0.0.1", "::1", "0.0.0.0"] {
            assert!(rdp_source(local).is_none(), "{local:?}");
        }
    }

    #[test]
    fn rdp_from_public_ip_is_high_and_grouped_across_channels() {
        let f = run(&[
            rcm(0, "bob", "CORP", "8.8.8.8"),
            logon(1, "10", "8.8.8.8", "bob"),
            lsm(21, 1, "8.8.8.8", r"CORP\bob"),
            lsm(24, 30, "8.8.8.8", r"CORP\bob"),
            lsm(25, 40, "8.8.8.8", r"CORP\bob"),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1021.001"]);
        assert_eq!(f[0].user.as_deref(), Some(r"CORP\bob"));
        assert_eq!(f[0].evidence.len(), 5);
        let r = f[0].reason.as_deref().unwrap();
        assert!(r.contains("public address") && r.contains("4 logon"), "{r}");
        assert!(f[0].details_client.as_deref().unwrap().contains("8.8.8.8"));
    }

    #[test]
    fn rdp_from_private_ip_is_low_context() {
        let f = rdp_only(run(&[
            logon(0, "10", "10.0.0.5", "alice"),
            lsm(21, 0, "10.0.0.5", r"CORP\alice"),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].reason.as_deref().unwrap().contains("private address"));
        // 4778 reconnect alone is RDP context too.
        let f = run(&[ev(
            "Security",
            4778,
            0,
            &[
                ("AccountName", "alice"),
                ("AccountDomain", "CORP"),
                ("ClientAddress", "10.0.0.5"),
                ("ClientName", "LAPTOP7"),
            ],
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn rdp_from_private_ip_with_failures_is_medium() {
        let f = rdp_only(run(&[
            failed(0, "10.0.0.5", "alice"),
            failed(1, "10.0.0.5", "alice"),
            logon(2, "10", "10.0.0.5", "alice"),
        ]));
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("2 failed logon(s)"));
        // Failures for another account from that source do not count.
        let f = rdp_only(run(&[
            failed(0, "10.0.0.5", "admin"),
            logon(2, "10", "10.0.0.5", "alice"),
        ]));
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn rdp_first_logon_of_an_account_is_medium_only_with_log_history() {
        let day = 24 * 60;
        // The log reaches two days back, alice never logged on before: Medium.
        let f = rdp_only(run(&[
            logon(-2 * day, "2", "-", "carol"),
            logon(0, "10", "10.0.0.5", "alice"),
        ]));
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].reason.as_deref().unwrap().contains("first logon"));
        // alice logged on interactively the day before: Low.
        let f = rdp_only(run(&[
            logon(-2 * day, "2", "-", "carol"),
            logon(-day, "2", "-", "alice"),
            logon(0, "10", "10.0.0.5", "alice"),
        ]));
        assert_eq!(f[0].severity, Severity::Low);
        // The log only starts with this logon: nothing to compare against, Low.
        let f = rdp_only(run(&[logon(0, "10", "10.0.0.5", "alice")]));
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn rdp_through_a_local_tunnel_is_high() {
        let f = run(&[logon(0, "10", "127.0.0.1", "bob")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].reason.as_deref().unwrap().contains("tunnel"));
        let f = run(&[lsm(21, 0, "::%16777216", r"CORP\bob")]);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn console_and_local_rdp_sources_are_ignored() {
        let f = run(&[
            lsm(21, 0, "LOCAL", r"CORP\bob"),
            lsm(24, 1, "", r"CORP\bob"),
            logon(2, "7", "127.0.0.1", "bob"),
            logon(3, "7", "-", "bob"),
            logon(4, "10", "-", "bob"),
            rcm(5, "", "", ""),
            ev(
                "Security",
                4778,
                6,
                &[("AccountName", "bob"), ("ClientAddress", "LOCAL")],
            ),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    fn explicit(min: i64, subject: &str, target: &str, server: &str, process: &str) -> Record {
        ev(
            "Security",
            4648,
            min,
            &[
                ("SubjectUserName", subject),
                ("SubjectDomainName", "CORP"),
                ("TargetUserName", target),
                ("TargetDomainName", "CORP"),
                ("TargetServerName", server),
                ("TargetInfo", server),
                ("ProcessName", process),
                ("IpAddress", "-"),
            ],
        )
    }

    #[test]
    fn explicit_credentials_to_another_host_are_medium() {
        let f = run(&[
            explicit(0, "bob", "da_admin", "FS01", r"C:\Windows\System32\net.exe"),
            explicit(1, "bob", "da_admin", "fs01", r"C:\Windows\System32\net.exe"),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].mitre, vec!["T1021", "T1550"]);
        let r = f[0].reason.as_deref().unwrap();
        assert!(
            r.contains("net.exe") && r.contains("FS01") && r.contains(r"CORP\da_admin"),
            "{r}"
        );
        assert_eq!(f[0].evidence.len(), 2);
    }

    /// Real shape (DeepBlueCLI password-spray.evtx): an SMB logon to a remote IP logs
    /// this computer's own name as TargetServerName / TargetInfo, an empty
    /// ProcessName, and the remote end only in IpAddress / IpPort 445.
    fn smb_explicit(min: i64, target: &str, ip: &str) -> Record {
        ev(
            "Security",
            4648,
            min,
            &[
                ("SubjectUserName", "jwrig"),
                ("SubjectDomainName", "WS1"),
                ("TargetUserName", target),
                ("TargetDomainName", "DOMAIN"),
                ("TargetServerName", "WS1"),
                ("TargetInfo", "WS1"),
                ("ProcessId", "0x4"),
                ("ProcessName", ""),
                ("IpAddress", ip),
                ("IpPort", "445"),
            ],
        )
    }

    #[test]
    fn explicit_credentials_to_a_remote_address_under_the_local_name() {
        let f = run(&[smb_explicit(0, "Administrator", "172.16.144.128")]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].title.contains("172.16.144.128"), "{}", f[0].title);
        // Loopback / no address under the local name stays local.
        let f = run(&[
            smb_explicit(0, "Administrator", "127.0.0.1"),
            smb_explicit(1, "Administrator", "-"),
        ]);
        assert!(f.is_empty(), "{f:?}");
        // winlogon's 4648 for an incoming logon: machine account caller, client IP.
        let Record::Event(mut e) = smb_explicit(0, "bob", "10.0.0.9") else {
            unreachable!()
        };
        e.data.insert("SubjectUserName".into(), "WS1$".into());
        assert!(run(&[Record::Event(e)]).is_empty());
    }

    #[test]
    fn explicit_credentials_for_many_accounts_are_one_spraying_finding() {
        let names = [
            "Administrator",
            "jwright",
            "bob",
            "alice",
            "svc_sql",
            "carol",
        ];
        let recs: Vec<Record> = names
            .iter()
            .enumerate()
            .map(|(i, n)| smb_explicit(i as i64, n, "172.16.144.128"))
            .collect();
        let f = run(&recs);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1021", "T1550", "T1110.003"]);
        let r = f[0].reason.as_deref().unwrap();
        assert!(r.contains("6 different accounts"), "{r}");
        // Below the account threshold: Medium, one finding listing the accounts.
        let f = run(&recs[..EXPLICIT_SPRAY_ACCOUNTS - 1]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn explicit_credential_noise_is_quiet() {
        let lsass = r"C:\Windows\System32\lsass.exe";
        let svchost = r"C:\Windows\System32\svchost.exe";
        let f = run(&[
            // runas / scheduled tasks against this machine.
            explicit(
                0,
                "bob",
                "admin",
                "localhost",
                r"C:\Windows\System32\runas.exe",
            ),
            explicit(
                1,
                "bob",
                "admin",
                "127.0.0.1",
                r"C:\Windows\System32\runas.exe",
            ),
            // This computer by short name and FQDN.
            explicit(2, "bob", "admin", "WS1", lsass),
            // ev() events carry computer "WS1".
            explicit(3, "bob", "admin", "ws1.corp.local", lsass),
            // The caller's own credentials (lsass / svchost noise).
            explicit(4, "bob", "bob", "FS01", lsass),
            explicit(5, "WS1$", "WS1$", "DC01.corp.local", svchost),
            // Machine account to machine account.
            explicit(6, "WS1$", "DC01$", "DC01", svchost),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    fn wmi(id: u32, min: i64, element: &str, fields: &[(&str, &str)]) -> Record {
        ud(WMI_CHANNEL, id, min, element, fields)
    }

    fn binding(min: i64, filter: &str, consumer: &str, cause: &str) -> Record {
        wmi(
            5861,
            min,
            "Operation_ESStoConsumerBinding",
            &[
                ("Namespace", "//./root/subscription"),
                ("ESS", filter),
                ("CONSUMER", consumer),
                ("PossibleCause", cause),
            ],
        )
    }

    #[test]
    fn wmi_permanent_consumers() {
        let f = run(&[binding(
            0,
            "Updater",
            "CommandLineEventConsumer=\"Updater\"",
            "Binding EventFilter: instance of __EventFilter { Name = \"Updater\"; Query = \
             \"SELECT * FROM __InstanceModificationEvent WITHIN 60\"; }; Perm. Consumer: \
             instance of CommandLineEventConsumer { CommandLineTemplate = \
             \"powershell -nop -w hidden -enc SQBFAFgA\"; Name = \"Updater\"; };",
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].mitre, vec!["T1546.003"]);
        assert!(f[0].details.contains("CommandLineTemplate"));
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("runs a command line"));
        // Other consumer types: Medium.
        let f = run(&[binding(
            0,
            "Watch",
            "LogFileEventConsumer=\"Watch\"",
            "Perm. Consumer: instance of LogFileEventConsumer { Filename = \"c:\\\\x.log\"; };",
        )]);
        assert_eq!(f[0].severity, Severity::Medium);
        // Stock Windows bindings: quiet.
        let f = run(&[
            binding(
                0,
                "BVTFilter",
                "NTEventLogEventConsumer=\"BVTConsumer\"",
                "Perm. Consumer: instance of NTEventLogEventConsumer { Name = \"BVTConsumer\"; };",
            ),
            binding(
                1,
                "SCM Event Log Filter",
                "NTEventLogEventConsumer=\"SCM Event Log Consumer\"",
                "",
            ),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    fn temp_consumer(min: i64, user: &str, client: &str, query: &str) -> Record {
        wmi(
            5860,
            min,
            "Operation_TemporaryEssStarted",
            &[
                ("NamespaceName", r"ROOT\CIMV2"),
                ("Query", query),
                ("User", user),
                ("Processid", "4242"),
                ("ClientMachine", client),
                ("PossibleCause", "Temporary"),
            ],
        )
    }

    #[test]
    fn wmi_temporary_consumers() {
        let q = "SELECT * FROM Win32_ProcessStartTrace";
        let f = run(&[
            temp_consumer(0, r"CORP\bob", "WS1", q),
            temp_consumer(1, r"CORP\bob", "WS1", q),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].mitre, vec!["T1047"]);
        assert!(f[0].reason.as_deref().unwrap().contains("2 time(s)"));
        // From another machine: the reason names it, even for SYSTEM.
        let f = run(&[temp_consumer(0, r"NT AUTHORITY\SYSTEM", "ADMINPC", q)]);
        assert_eq!(f.len(), 1);
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("remote machine ADMINPC"));
        assert!(f[0].details.contains(r"ROOT\CIMV2"), "{}", f[0].details);
        // Local system agents: quiet. ClientMachine is the NetBIOS name, cut to 15
        // characters when the host name is longer (real WMI-Activity log).
        let long = |min, user: &str, client: &str| {
            let Record::Event(mut e) = temp_consumer(min, user, client, q) else {
                unreachable!()
            };
            e.computer = "DESKTOP-BZCP2020".into();
            Record::Event(e)
        };
        let f = run(&[long(0, r"NT AUTHORITY\LOCAL SERVICE", "DESKTOP-BZCP202")]);
        assert!(f.is_empty(), "{f:?}");
        let f = run(&[long(0, r"NT AUTHORITY\LOCAL SERVICE", "DESKTOP-BZCP")]);
        assert_eq!(f.len(), 1, "a shorter, different name is another machine");
        let f = run(&[
            temp_consumer(0, r"NT AUTHORITY\SYSTEM", "WS1", q),
            temp_consumer(1, "S-1-5-18", "", q),
            temp_consumer(2, r"NT AUTHORITY\NETWORK SERVICE", "localhost", q),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    fn provider(min: i64, path: &str) -> Record {
        wmi(
            5857,
            min,
            "Operation_StartedOperational",
            &[
                ("ProviderName", "EvilProv"),
                ("Code", "0x0"),
                ("HostProcess", "wmiprvse.exe"),
                ("ProcessID", "3100"),
                ("ProviderPath", path),
            ],
        )
    }

    #[test]
    fn wmi_provider_load_only_from_user_writable_paths() {
        let f = run(&[provider(0, r"C:\Users\bob\AppData\Roaming\prov.dll")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].mitre, vec!["T1047"]);
        assert_eq!(
            f[0].entity.file.as_ref().unwrap().path,
            r"C:\Users\bob\AppData\Roaming\prov.dll"
        );
        let f = run(&[
            provider(0, r"%SystemRoot%\system32\wbem\wmiprov.dll"),
            provider(1, r"C:\Program Files\Vendor\vprov.dll"),
            provider(2, ""),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn channel_names_match_case_insensitively() {
        let mut r = lsm(21, 0, "8.8.8.8", r"CORP\bob");
        if let Record::Event(e) = &mut r {
            e.channel = LSM_CHANNEL.to_ascii_lowercase();
        }
        assert_eq!(run(&[r]).len(), 1);
    }
}
