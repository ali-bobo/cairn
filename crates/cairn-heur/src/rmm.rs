//! Remote-access / RMM tool inventory (ATT&CK T1219, phase 3E `heur_rmm`).
//!
//! Intruders install the same remote-support tools IT uses (AnyDesk, ScreenConnect,
//! Atera, ...), plus tunnels (ngrok, cloudflared). [`RMM_TOOLS`] describes each tool
//! once, as data: process exe names, service names, install-path fragments and signer
//! substrings. A tool is found from running processes, services (persistence records)
//! and the install folders the `posture` collector lists.
//!
//! Severity, one finding per tool:
//! - Low: present. RMM tools are usually legitimate; the reason says to verify it is
//!   sanctioned.
//! - Medium: installed recently (an install folder's or the service key's last_write
//!   within [`RECENT_DAYS`] of the run start).
//! - High: it runs from a user-writable folder, is unsigned, is renamed (the signer is
//!   the tool's but the exe name is not, or the exe name is the tool's but a valid
//!   signature names someone else), or has an established connection to a public IP.
//!
//! Two or more distinct tools on one host add one Medium finding.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use cairn_core::finding::{EntityFile, EntityProcess, EvidenceItem, FindingSource, Severity};
use cairn_core::record::{
    Mechanism, NetConnRecord, PersistenceRecord, ProcessRecord, ProgramDir, Record,
};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::{DateTime, Duration, Utc};

use crate::score::{is_public_ipv4, is_trusted_appdata_location};
use crate::trust::{exe_name, is_user_writable_path};

/// "Recently installed" window, in days before the run start.
pub const RECENT_DAYS: i64 = 30;

/// One remote-access tool. All strings lowercase; exe names without `.exe`; path
/// fragments are `\`-delimited folder names (`\anydesk\`).
#[derive(Debug, Clone, Copy)]
pub struct RmmTool {
    pub name: &'static str,
    pub exes: &'static [&'static str],
    pub services: &'static [&'static str],
    pub paths: &'static [&'static str],
    pub signers: &'static [&'static str],
    /// The signer also signs unrelated software (Google, GoTo/LogMeIn): a signer match
    /// alone does not identify this tool.
    pub shared_signer: bool,
}

const fn t(
    name: &'static str,
    exes: &'static [&'static str],
    services: &'static [&'static str],
    paths: &'static [&'static str],
    signers: &'static [&'static str],
    shared_signer: bool,
) -> RmmTool {
    RmmTool {
        name,
        exes,
        services,
        paths,
        signers,
        shared_signer,
    }
}

/// The tool table.
pub const RMM_TOOLS: &[RmmTool] = &[
    t(
        "AnyDesk",
        &["anydesk"],
        &["anydesk"],
        &[r"\anydesk\"],
        &["anydesk", "philandro"],
        false,
    ),
    t(
        "ScreenConnect / ConnectWise Control",
        &[
            "screenconnect.clientservice",
            "screenconnect.windowsclient",
            "screenconnect.windowsbackstageshell",
            "connectwisecontrol.client",
        ],
        &["screenconnect client", "connectwise control client"],
        &[r"\screenconnect client", r"\connectwise control client"],
        &["connectwise", "screenconnect"],
        false,
    ),
    t(
        "TeamViewer",
        &[
            "teamviewer",
            "teamviewer_service",
            "tv_w32",
            "tv_x64",
            "teamviewer_desktop",
        ],
        &["teamviewer"],
        &[r"\teamviewer\"],
        &["teamviewer"],
        false,
    ),
    t(
        "Atera",
        &["ateraagent", "atera.agentpackagerunner"],
        &["ateraagent"],
        &[r"\atera networks\", r"\ateraagent\"],
        &["atera networks"],
        false,
    ),
    t(
        "Splashtop",
        &[
            "srservice",
            "srmanager",
            "srapp",
            "srfeature",
            "strwinclt",
            "splashtop",
        ],
        &["splashtopremoteservice", "splashtop"],
        &[r"\splashtop\"],
        &["splashtop"],
        false,
    ),
    t(
        "NetSupport",
        &["client32", "pcictlui"],
        &["client32"],
        &[r"\netsupport\"],
        &["netsupport"],
        false,
    ),
    t(
        "RustDesk",
        &["rustdesk"],
        &["rustdesk"],
        &[r"\rustdesk\"],
        &["rustdesk", "purslane"],
        false,
    ),
    t(
        "Supremo",
        &["supremo", "supremohelper", "supremoservice"],
        &["supremoservice"],
        &[r"\supremo\"],
        &["nanosystems"],
        false,
    ),
    t(
        "LogMeIn",
        &["logmein", "lmiguardiansvc", "logmeinsystray", "ramaint"],
        &["logmein", "lmiguardian"],
        &[r"\logmein\"],
        &["logmein"],
        true,
    ),
    t(
        "GoTo / LogMeIn Rescue",
        &[
            "lmi_rescue",
            "lmi_rescue_srv",
            "lmi_rescuerc",
            "gotoassist",
            "gotoresolveservice",
            "gotoresolveprocesschecker",
        ],
        &["lmirescue", "gotoresolveservice", "gotoassist"],
        &[r"\logmein rescue", r"\goto resolve", r"\gotoassist"],
        &["goto technologies", "logmein"],
        true,
    ),
    t(
        "Action1",
        &["action1_agent", "action1_remote"],
        &["a1agent"],
        &[r"\action1\"],
        &["action1"],
        false,
    ),
    t(
        "MeshAgent",
        &["meshagent"],
        &["mesh agent", "meshagent"],
        &[r"\mesh agent\"],
        &[],
        false,
    ),
    t(
        "ngrok",
        &["ngrok"],
        &["ngrok"],
        &[r"\ngrok\"],
        &["ngrok"],
        false,
    ),
    t(
        "cloudflared",
        &["cloudflared"],
        &["cloudflared"],
        &[r"\cloudflared\"],
        &["cloudflare"],
        false,
    ),
    t(
        "Tailscale",
        &["tailscale", "tailscaled", "tailscale-ipn"],
        &["tailscale"],
        &[r"\tailscale\"],
        &["tailscale"],
        false,
    ),
    t(
        "ZeroTier",
        &[
            "zerotier-one_x64",
            "zerotier-one_x86",
            "zerotier_desktop_ui",
            "zerotier-one",
        ],
        &["zerotieroneservice"],
        &[r"\zerotier\"],
        &["zerotier"],
        false,
    ),
    t(
        "Radmin",
        &["rserver3", "radmin"],
        &["rserver3"],
        &[r"\radmin\"],
        &["famatech"],
        false,
    ),
    t(
        "UltraVNC",
        &["winvnc"],
        &["uvnc_service"],
        &[r"\uvnc bvba\", r"\ultravnc\"],
        &["uvnc"],
        false,
    ),
    t(
        "TightVNC",
        &["tvnserver"],
        &["tvnserver"],
        &[r"\tightvnc\"],
        &["glavsoft"],
        false,
    ),
    t(
        "RealVNC",
        &["vncserver", "vncserverui", "vncagent"],
        &["vncserver"],
        &[r"\realvnc\"],
        &["realvnc"],
        false,
    ),
    t(
        "Chrome Remote Desktop",
        &[
            "remoting_host",
            "remoting_desktop",
            "remoting_native_messaging_host",
        ],
        &["chromoting"],
        &[r"\chrome remote desktop\"],
        &["google"],
        true,
    ),
    t(
        "Level",
        &["level"],
        &["level"],
        &[r"\level\"],
        &["level software"],
        false,
    ),
    t(
        "SimpleHelp",
        &[
            "simpleservice",
            "simplegatewayservice",
            "remote access",
            "simplehelp",
        ],
        &["simplehelp", "simplegateway"],
        &[r"\jwrapper-remote access\", r"\simplehelp\"],
        &["simplehelp"],
        false,
    ),
    t(
        "Tactical RMM",
        &["tacticalrmm"],
        &["tacticalrmm"],
        &[r"\tacticalagent\"],
        &["amidaware"],
        false,
    ),
];

fn by_exe(exe: &str) -> Option<&'static RmmTool> {
    RMM_TOOLS.iter().find(|t| t.exes.contains(&exe))
}

fn by_path(path: &str) -> Option<&'static RmmTool> {
    let lower = format!("{}\\", path.to_ascii_lowercase());
    RMM_TOOLS
        .iter()
        .find(|t| t.paths.iter().any(|p| lower.contains(p)))
}

fn signer_matches(t: &RmmTool, signer: &str) -> bool {
    let s = signer.to_ascii_lowercase();
    t.signers.iter().any(|x| s.contains(x))
}

/// A tool whose signer uniquely identifies it.
fn by_signer(signer: &str) -> Option<&'static RmmTool> {
    RMM_TOOLS
        .iter()
        .find(|t| !t.shared_signer && signer_matches(t, signer))
}

/// Service name match: exact, or the listed name followed by a non-letter
/// (`ScreenConnect Client (1a2b)`, `TeamViewer9`).
fn by_service(name: &str) -> Option<&'static RmmTool> {
    let n = name.to_ascii_lowercase();
    RMM_TOOLS.iter().find(|t| {
        t.services.iter().any(|s| {
            n.strip_prefix(s)
                .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphabetic()))
        })
    })
}

/// A routable public address (IPv4 via the shared check; IPv6 global unicast).
pub(crate) fn is_public_ip(addr: &str) -> bool {
    match addr.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => is_public_ipv4(addr),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_ipv4(&v4.to_string()),
            None => is_global_v6(v6),
        },
        Err(_) => false,
    }
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // 2000::/3 global unicast, minus documentation 2001:db8::/32.
    (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
}

/// Runs from a drop zone (a signed per-user install under AppData\Local\Programs is
/// the vendor's normal layout, not a drop).
fn user_writable(path: &str, signed: Option<bool>) -> bool {
    is_user_writable_path(path) && !(signed == Some(true) && is_trusted_appdata_location(path))
}

/// Everything seen for one tool.
#[derive(Default)]
struct Hits {
    seen: Vec<String>,
    high: Vec<String>,
    recent: Vec<String>,
    evidence: Vec<EvidenceItem>,
    process: Option<EntityProcess>,
    file: Option<EntityFile>,
    latest: Option<DateTime<Utc>>,
}

impl Hits {
    fn stamp(&mut self, ts: Option<DateTime<Utc>>) {
        if let Some(ts) = ts {
            self.latest = Some(self.latest.map_or(ts, |l| l.max(ts)));
        }
    }
}

struct Ctx {
    now: DateTime<Utc>,
}

impl Ctx {
    fn recent(&self, ts: Option<DateTime<Utc>>) -> bool {
        ts.is_some_and(|t| {
            t <= self.now + Duration::days(1) && self.now - t <= Duration::days(RECENT_DAYS)
        })
    }
}

fn fmt_ts(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn on_process(
    p: &ProcessRecord,
    hits: &mut BTreeMap<&'static str, Hits>,
    pids: &mut BTreeMap<u32, &'static str>,
) {
    let exe = exe_name(&p.image);
    let mut renamed: Option<String> = None;
    let tool = match by_exe(&exe).or_else(|| by_path(&p.image)) {
        Some(t) => {
            // The tool's exe name, validly signed by someone else.
            if let (Some(true), Some(signer)) = (p.signed, p.signer.as_deref()) {
                if !t.signers.is_empty()
                    && !signer_matches(t, signer)
                    && by_path(&p.image).is_none()
                {
                    renamed = Some(format!(
                        "process.image name {exe}.exe is {}'s but process.signer is {signer:?}",
                        t.name
                    ));
                }
            }
            t
        }
        None => {
            let Some(t) = p.signer.as_deref().and_then(by_signer) else {
                return;
            };
            renamed = Some(format!(
                "process.signer {:?} is {}'s but process.image is named {exe}.exe",
                p.signer.as_deref().unwrap_or_default(),
                t.name
            ));
            t
        }
    };
    pids.insert(p.pid, t_name(tool));
    let h = hits.entry(t_name(tool)).or_default();
    h.seen
        .push(format!("process.image={} (pid {})", p.image, p.pid));
    if let Some(r) = renamed {
        h.high.push(format!("renamed: {r}"));
    }
    if p.signed == Some(false) {
        h.high.push(format!("process.signed=false for {}", p.image));
    }
    if user_writable(&p.image, p.signed) {
        h.high.push(format!(
            "process.image {} is in a user-writable folder",
            p.image
        ));
    }
    h.evidence.push(EvidenceItem {
        artifact: "process".into(),
        path: Some(p.image.clone()),
        ts: p.start_time,
        detail: format!(
            "process: pid={} signed={:?} signer={:?} cmdline={}",
            p.pid, p.signed, p.signer, p.cmdline
        ),
    });
    h.stamp(p.start_time);
    if h.process.is_none() {
        h.process = Some(EntityProcess {
            pid: p.pid,
            ppid: p.ppid,
            image: p.image.clone(),
            cmdline: p.cmdline.clone(),
            signed: p.signed,
            integrity: p.integrity.clone(),
        });
    }
}

fn t_name(t: &'static RmmTool) -> &'static str {
    t.name
}

fn on_service(s: &PersistenceRecord, ctx: &Ctx, hits: &mut BTreeMap<&'static str, Hits>) {
    let name = s.value.as_deref().unwrap_or_default();
    let bin = s.binary_path.as_deref();
    let Some(tool) = by_service(name)
        .or_else(|| bin.and_then(|b| by_exe(&exe_name(b))))
        .or_else(|| bin.and_then(by_path))
    else {
        return;
    };
    let h = hits.entry(tool.name).or_default();
    h.seen.push(format!(
        "service.name={name}{}",
        bin.map(|b| format!(" (binary_path={b})"))
            .unwrap_or_default()
    ));
    if ctx.recent(s.last_write) {
        h.recent.push(format!(
            "service key last_write {} is within {RECENT_DAYS} days",
            s.last_write.map(fmt_ts).unwrap_or_default()
        ));
    }
    if let Some(b) = bin {
        if s.signed == Some(false) {
            h.high.push(format!("service binary_path {b} signed=false"));
        }
        if user_writable(b, s.signed) {
            h.high.push(format!(
                "service binary_path {b} is in a user-writable folder"
            ));
        }
        if h.file.is_none() {
            h.file = Some(EntityFile {
                path: b.to_string(),
                sha256: s.binary_sha256.clone(),
                mtime: None,
            });
        }
    }
    h.evidence.push(EvidenceItem {
        artifact: "service".into(),
        path: bin.map(str::to_string),
        ts: s.last_write,
        detail: format!(
            "service {name} at {}: signed={:?} signer={:?} start={:?}",
            s.location, s.signed, s.signer, s.service_start
        ),
    });
    h.stamp(s.last_write);
}

fn on_dir(d: &ProgramDir, ctx: &Ctx, hits: &mut BTreeMap<&'static str, Hits>) {
    let Some(tool) = by_path(&d.path) else {
        return;
    };
    let h = hits.entry(tool.name).or_default();
    h.seen.push(format!("program_dirs.path={}", d.path));
    if ctx.recent(d.last_write) {
        h.recent.push(format!(
            "folder {} last_write {} is within {RECENT_DAYS} days",
            d.path,
            d.last_write.map(fmt_ts).unwrap_or_default()
        ));
    }
    h.evidence.push(EvidenceItem {
        artifact: "program_dir".into(),
        path: Some(d.path.clone()),
        ts: d.last_write,
        detail: format!(
            "install folder {} (last_write {})",
            d.path,
            d.last_write.map(fmt_ts).unwrap_or_else(|| "unknown".into())
        ),
    });
    h.stamp(d.last_write);
}

fn on_conn(
    c: &NetConnRecord,
    pids: &BTreeMap<u32, &'static str>,
    hits: &mut BTreeMap<&'static str, Hits>,
) {
    let Some(&tool) = c.pid.and_then(|p| pids.get(&p)) else {
        return;
    };
    let Some(raddr) = c.raddr.as_deref().filter(|r| is_public_ip(r)) else {
        return;
    };
    let state = c.state.as_deref().unwrap_or("").to_ascii_lowercase();
    if !(state == "established" || state == "syn_sent") {
        return;
    }
    let h = hits.entry(tool).or_default();
    let remote = format!(
        "{raddr}:{}",
        c.rport.map(|p| p.to_string()).unwrap_or_default()
    );
    h.high.push(format!(
        "netconn {state} from pid {} to public {remote}",
        c.pid.unwrap_or_default()
    ));
    h.evidence.push(EvidenceItem {
        artifact: "netconn".into(),
        path: None,
        ts: None,
        detail: format!("{} {}:{} -> {remote} ({state})", c.proto, c.laddr, c.lport),
    });
}

/// Remote-access tool inventory and risk.
pub struct RmmHeuristic;

impl RmmHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::RMM;
}

impl Analyzer for RmmHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let now = records
            .iter()
            .find_map(|r| match r {
                Record::Posture(p) => p.collected_at,
                _ => None,
            })
            .unwrap_or_else(Utc::now);
        let ctx = Ctx { now };
        let mut hits: BTreeMap<&'static str, Hits> = BTreeMap::new();
        let mut pids: BTreeMap<u32, &'static str> = BTreeMap::new();
        for r in records {
            match r {
                Record::Process(p) => on_process(p, &mut hits, &mut pids),
                Record::Persistence(s) if s.mechanism == Mechanism::Service => {
                    on_service(s, &ctx, &mut hits)
                }
                Record::Posture(p) => {
                    for d in &p.program_dirs {
                        on_dir(d, &ctx, &mut hits);
                    }
                }
                _ => {}
            }
        }
        for r in records {
            if let Record::NetConn(c) = r {
                on_conn(c, &pids, &mut hits);
            }
        }

        let mut out = Vec::new();
        for (tool, h) in &hits {
            let (severity, why) = if !h.high.is_empty() {
                (Severity::High, h.high.join("; "))
            } else if !h.recent.is_empty() {
                (
                    Severity::Medium,
                    format!("recently installed: {}", h.recent.join("; ")),
                )
            } else {
                (Severity::Low, "present; no risk signal".to_string())
            };
            let mut f = Finding::new(
                severity,
                format!("遠端控制工具：{tool}"),
                FindingSource::Heuristic,
            );
            f.mitre = vec!["T1219".into()];
            f.ts = h.latest.unwrap_or(now);
            f.artifact = "rmm".into();
            f.reason = Some(format!(
                "{tool} found via {}; {why}; verify it is sanctioned (remote-access tools are \
                 often legitimate IT software, and equally often installed by intruders)",
                h.seen.join(", ")
            ));
            f.details = h.seen.join("\n");
            f.details_client = Some(format!(
                "這台主機上有遠端控制軟體 {tool}。這類軟體常是資訊人員或廠商合法使用的，但攻擊者也常安裝它來\
                 遠端操控電腦；請向資訊人員確認是否為公司核准安裝，不是的話應立即移除並更換密碼。"
            ));
            f.entity.process = h.process.clone();
            f.entity.file = h.file.clone();
            f.evidence = h.evidence.clone();
            out.push(f);
        }
        if hits.len() >= 2 {
            let names: Vec<&str> = hits.keys().copied().collect();
            let mut f = Finding::new(
                Severity::Medium,
                format!("多個遠端控制工具：{}", names.join("、")),
                FindingSource::Heuristic,
            );
            f.mitre = vec!["T1219".into()];
            f.ts = now;
            f.artifact = "rmm".into();
            f.reason = Some(format!(
                "{} distinct remote-access tools on one host ({}); intruders often add a second \
                 tool as a fallback; verify each is sanctioned",
                names.len(),
                names.join(", ")
            ));
            f.details = names.join("\n");
            f.details_client = Some(format!(
                "這台主機同時裝了 {} 種遠端控制軟體（{}）。一般公司只會用一種；攻擊者常多裝一個當備用入口，\
                 請逐一確認是否都經過核准。",
                names.len(),
                names.join("、")
            ));
            out.push(f);
        }
        Ok(crate::stamped(out, Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::PostureRecord;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 21, 0, 0, 0).unwrap()
    }

    fn posture(dirs: &[(&str, Option<DateTime<Utc>>)]) -> Record {
        Record::Posture(PostureRecord {
            collected_at: Some(now()),
            program_dirs: dirs
                .iter()
                .map(|(p, lw)| ProgramDir {
                    path: (*p).into(),
                    last_write: *lw,
                })
                .collect(),
            ..PostureRecord::default()
        })
    }

    fn proc(pid: u32, image: &str, signed: Option<bool>, signer: Option<&str>) -> Record {
        Record::Process(ProcessRecord {
            pid,
            ppid: 1,
            image: image.into(),
            cmdline: format!("\"{image}\""),
            signed,
            signer: signer.map(str::to_string),
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        })
    }

    fn service(name: &str, bin: &str, signed: Option<bool>, lw: Option<DateTime<Utc>>) -> Record {
        Record::Persistence(PersistenceRecord {
            mechanism: Mechanism::Service,
            location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
            value: Some(name.into()),
            command: Some(format!("\"{bin}\" --service")),
            binary_path: Some(bin.into()),
            binary_sha256: None,
            signed,
            signer: None,
            last_write: lw,
            signer_source: None,
            bound: None,
            service_start: Some(2),
        })
    }

    fn conn(pid: u32, raddr: &str, state: &str) -> Record {
        Record::NetConn(NetConnRecord {
            proto: "tcp".into(),
            laddr: "192.168.1.5".into(),
            lport: 50000,
            raddr: Some(raddr.into()),
            rport: Some(443),
            state: Some(state.into()),
            pid: Some(pid),
        })
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        RmmHeuristic.analyze(records, &[]).unwrap()
    }

    const ANYDESK: &str = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe";

    #[test]
    fn every_tool_has_an_exe_and_lowercase_data() {
        for t in RMM_TOOLS {
            assert!(!t.exes.is_empty(), "{}", t.name);
            for s in t
                .exes
                .iter()
                .chain(t.services)
                .chain(t.paths)
                .chain(t.signers)
            {
                assert_eq!(*s, s.to_ascii_lowercase(), "{}: {s}", t.name);
            }
        }
    }

    #[test]
    fn signed_installed_tool_alone_is_low_and_says_verify() {
        let f = run(&[
            posture(&[(r"C:\Program Files (x86)\AnyDesk", None)]),
            proc(10, ANYDESK, Some(true), Some("AnyDesk Software GmbH")),
            service("AnyDesk", ANYDESK, Some(true), None),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].mitre, vec!["T1219"]);
        assert_eq!(f[0].analyzer, RmmHeuristic::NAME);
        let r = f[0].reason.as_deref().unwrap();
        assert!(r.contains("verify it is sanctioned"), "{r}");
        assert!(
            r.contains("process.image=") && r.contains("service.name=AnyDesk"),
            "{r}"
        );
        assert_eq!(f[0].evidence.len(), 3);
    }

    #[test]
    fn recent_install_is_medium() {
        let f = run(&[
            posture(&[(
                r"C:\Program Files\TeamViewer",
                Some(now() - Duration::days(3)),
            )]),
            service(
                "TeamViewer",
                r"C:\Program Files\TeamViewer\TeamViewer_Service.exe",
                Some(true),
                Some(now() - Duration::days(400)),
            ),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("recently installed"));
        // Old install: Low.
        let old = run(&[posture(&[(
            r"C:\Program Files\TeamViewer",
            Some(now() - Duration::days(90)),
        )])]);
        assert_eq!(old[0].severity, Severity::Low);
    }

    #[test]
    fn portable_unsigned_or_connected_is_high() {
        let dl = run(&[proc(
            7,
            r"C:\Users\bob\Downloads\AnyDesk.exe",
            Some(true),
            Some("AnyDesk Software GmbH"),
        )]);
        assert_eq!(dl[0].severity, Severity::High);
        assert!(dl[0].reason.as_deref().unwrap().contains("user-writable"));

        let unsigned = run(&[service(
            "ScreenConnect Client (1a2b3c)",
            r"C:\Program Files (x86)\ScreenConnect Client (1a2b3c)\ScreenConnect.ClientService.exe",
            Some(false),
            None,
        )]);
        assert_eq!(unsigned[0].severity, Severity::High);
        assert!(unsigned[0].title.contains("ScreenConnect"));

        let connected = run(&[
            proc(10, ANYDESK, Some(true), Some("AnyDesk Software GmbH")),
            conn(10, "8.8.4.4", "established"),
        ]);
        assert_eq!(connected[0].severity, Severity::High);
        assert!(connected[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("public 8.8.4.4:443"));
        // A LAN peer or a listening socket is not an external connection.
        let lan = run(&[
            proc(10, ANYDESK, Some(true), Some("AnyDesk Software GmbH")),
            conn(10, "10.0.0.9", "established"),
            conn(10, "0.0.0.0", "listen"),
        ]);
        assert_eq!(lan[0].severity, Severity::Low);
    }

    #[test]
    fn renamed_binaries_are_high() {
        // NetSupport RAT renamed: the signer gives it away.
        let f = run(&[proc(
            5,
            r"C:\Program Files\Common\svchelper.exe",
            Some(true),
            Some("NetSupport Ltd"),
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "遠端控制工具：NetSupport");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].reason.as_deref().unwrap().contains("renamed"));
        // A tool's exe name signed by someone else.
        let g = run(&[proc(
            6,
            r"C:\Tools\rustdesk.exe",
            Some(true),
            Some("Evil Corp"),
        )]);
        assert_eq!(g[0].severity, Severity::High);
        // A shared signer alone (Google) is not Chrome Remote Desktop.
        assert!(run(&[proc(
            8,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            Some(true),
            Some("Google LLC"),
        )])
        .is_empty());
    }

    #[test]
    fn several_tools_add_one_medium() {
        let f = run(&[posture(&[
            (r"C:\Program Files (x86)\AnyDesk", None),
            (r"C:\Program Files\RustDesk", None),
            (r"C:\Users\bob\AppData\Local\ngrok", None),
        ])]);
        assert_eq!(f.len(), 4, "{f:?}");
        let multi: Vec<_> = f.iter().filter(|f| f.title.starts_with("多個")).collect();
        assert_eq!(multi.len(), 1);
        assert_eq!(multi[0].severity, Severity::Medium);
        assert!(multi[0].reason.as_deref().unwrap().contains("3 distinct"));
    }

    #[test]
    fn unrelated_software_is_ignored() {
        assert!(run(&[
            posture(&[
                (r"C:\Program Files\Mozilla Firefox", None),
                (r"C:\Program Files\Levels", None)
            ]),
            proc(
                1,
                r"C:\Windows\explorer.exe",
                Some(true),
                Some("Microsoft Windows")
            ),
            service(
                "Spooler",
                r"C:\Windows\System32\spoolsv.exe",
                Some(true),
                None
            ),
        ])
        .is_empty());
        assert!(by_service("TeamViewer15").is_some());
        assert!(by_service("TeamViewerX").is_none());
    }

    #[test]
    fn public_ip_check_covers_v6() {
        assert!(is_public_ip("2606:4700::1111"));
        assert!(!is_public_ip("fe80::1"));
        assert!(!is_public_ip("::1"));
        assert!(!is_public_ip("2001:db8::1"));
        assert!(is_public_ip("::ffff:8.8.8.8"));
        assert!(!is_public_ip("192.168.0.1"));
    }
}
