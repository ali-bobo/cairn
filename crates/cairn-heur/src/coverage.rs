//! What cairn's built-in (non-Sigma) detections cover, as ATT&CK techniques, and how
//! to verify each one on a lab VM. `cairn coverage` prints this table merged with the
//! loaded Sigma rules' technique tags, so an analyst can see — before trusting a clean
//! result — which techniques this build can and cannot see.

/// One technique covered by a built-in collector + heuristic.
#[derive(Debug, Clone, Copy)]
pub struct Coverage {
    /// ATT&CK technique ID.
    pub technique: &'static str,
    /// ATT&CK technique name.
    pub name: &'static str,
    /// What cairn inspects for it.
    pub what: &'static str,
    /// Analyzer that raises the finding.
    pub analyzer: &'static str,
}

const fn c(
    technique: &'static str,
    name: &'static str,
    what: &'static str,
    analyzer: &'static str,
) -> Coverage {
    Coverage {
        technique,
        name,
        what,
        analyzer,
    }
}

/// Built-in coverage, ordered by technique ID. Every persistence row's technique is
/// what `asep::mechanism_mitre` emits for that mechanism (checked by a test).
pub const BUILTIN: &[Coverage] = &[
    c(
        "T1036",
        "Masquerading",
        "unsigned binaries in user-writable paths behind persistence or network connections",
        "heur_persist, heur_netconn",
    ),
    c(
        "T1036.005",
        "Match Legitimate Name or Location",
        "system binary names outside C:\\Windows",
        "heur_persist, heur_parentchild",
    ),
    c(
        "T1037.001",
        "Logon Script (Windows)",
        "HKCU\\Environment UserInitMprLogonScript",
        "heur_persist",
    ),
    c(
        "T1053.005",
        "Scheduled Task",
        "task XML under System32\\Tasks",
        "heur_persist",
    ),
    c(
        "T1059",
        "Command and Scripting Interpreter",
        "Office apps / script hosts spawning shells; persistence launching interpreters",
        "heur_persist, heur_parentchild",
    ),
    c(
        "T1059.001",
        "PowerShell",
        "encoded / download-cradle PowerShell command lines",
        "heur_parentchild",
    ),
    c(
        "T1098.007",
        "Additional Local or Domain Groups",
        "Security 4728/4732 member added to group",
        "heur_account",
    ),
    c(
        "T1110.001",
        "Password Guessing",
        "Security 4625 bursts against one account",
        "heur_logon_bruteforce",
    ),
    c(
        "T1110.003",
        "Password Spraying",
        "Security 4625 across many accounts from one source",
        "heur_logon_bruteforce",
    ),
    c(
        "T1136.001",
        "Local Account",
        "Security 4720 account created",
        "heur_account",
    ),
    c(
        "T1137.002",
        "Office Test",
        "Office test\\Special\\Perf default value",
        "heur_persist",
    ),
    c(
        "T1218",
        "System Binary Proxy Execution",
        "LOLBins (rundll32, certutil, ...) run with suspicious arguments",
        "heur_parentchild",
    ),
    c(
        "T1531",
        "Account Access Removal",
        "Security 4726 account deleted",
        "heur_account",
    ),
    c(
        "T1543.003",
        "Windows Service",
        "auto-start services' ImagePath + signature",
        "heur_persist",
    ),
    c(
        "T1546",
        "Event Triggered Execution",
        "cmd.exe Command Processor AutoRun",
        "heur_persist",
    ),
    c(
        "T1546.002",
        "Screensaver",
        "HKCU Control Panel\\Desktop SCRNSAVE.EXE",
        "heur_persist",
    ),
    c(
        "T1546.003",
        "WMI Event Subscription",
        "root\\subscription filter/consumer bindings",
        "heur_persist",
    ),
    c(
        "T1546.007",
        "Netsh Helper DLL",
        "HKLM\\SOFTWARE\\Microsoft\\NetSh non-stock DLLs",
        "heur_persist",
    ),
    c(
        "T1546.008",
        "Accessibility Features",
        "IFEO Debugger on sethc/utilman/osk/magnify/narrator",
        "heur_persist",
    ),
    c(
        "T1546.009",
        "AppCert DLLs",
        "Session Manager\\AppCertDlls",
        "heur_persist",
    ),
    c(
        "T1546.010",
        "AppInit DLLs",
        "AppInit_DLLs (both bitnesses)",
        "heur_persist",
    ),
    c(
        "T1546.012",
        "Image File Execution Options Injection",
        "IFEO Debugger, SilentProcessExit MonitorProcess",
        "heur_persist",
    ),
    c(
        "T1546.013",
        "PowerShell Profile",
        "all-users and current-user profile.ps1 content",
        "heur_persist",
    ),
    c(
        "T1546.015",
        "Component Object Model Hijacking",
        "HKCU CLSID InprocServer32 to untrusted DLLs",
        "heur_persist",
    ),
    c(
        "T1547.001",
        "Registry Run Keys / Startup Folder",
        "Run/RunOnce (incl. WOW64, policy), Startup folders, BootExecute",
        "heur_persist",
    ),
    c(
        "T1547.002",
        "Authentication Package",
        "LSA Authentication Packages non-stock entries",
        "heur_persist",
    ),
    c(
        "T1547.003",
        "Time Providers",
        "W32Time TimeProviders DllName",
        "heur_persist",
    ),
    c(
        "T1547.004",
        "Winlogon Helper DLL",
        "Winlogon Shell/Userinit/Notify/MPNotify",
        "heur_persist",
    ),
    c(
        "T1547.005",
        "Security Support Provider",
        "LSA Security Packages non-stock entries",
        "heur_persist",
    ),
    c(
        "T1547.010",
        "Port Monitors",
        "Print\\Monitors Driver DLLs",
        "heur_persist",
    ),
    c(
        "T1547.014",
        "Active Setup",
        "Installed Components StubPath to untrusted binaries",
        "heur_persist",
    ),
    c(
        "T1556.002",
        "Password Filter DLL",
        "LSA Notification Packages non-stock entries",
        "heur_persist",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_sorted_and_unique() {
        for w in BUILTIN.windows(2) {
            assert!(
                w[0].technique < w[1].technique,
                "{} / {}",
                w[0].technique,
                w[1].technique
            );
        }
    }

    /// Every technique a persistence mechanism is tagged with appears in the table,
    /// so the coverage report never under-states what a run can find.
    #[test]
    fn every_persistence_technique_is_listed() {
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
            let t = crate::asep::mechanism_mitre(m);
            assert!(
                BUILTIN.iter().any(|c| c.technique == t),
                "{m} -> {t} missing from coverage table"
            );
        }
    }
}
