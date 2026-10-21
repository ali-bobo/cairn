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
        "T1021.001",
        "Remote Desktop Protocol",
        "inbound RDP (local port 3389) connection from a public IP",
        "heur_netconn",
    ),
    c(
        "T1021.002",
        "SMB/Windows Admin Shares",
        "inbound SMB (local port 445) from a public IP; loopback ADMIN$ output of wmiexec/smbexec",
        "heur_netconn, heur_parentchild",
    ),
    c(
        "T1021.004",
        "SSH",
        "inbound SSH (local port 22) connection from a public IP",
        "heur_netconn",
    ),
    c(
        "T1036",
        "Masquerading",
        "unsigned binaries in user-writable paths behind persistence or network connections",
        "heur_persist, heur_netconn",
    ),
    c(
        "T1036.005",
        "Match Legitimate Name or Location",
        "system binary names outside their canonical directory (also inside C:\\Windows)",
        "heur_persist, heur_parentchild",
    ),
    c(
        "T1037.001",
        "Logon Script (Windows)",
        "HKCU\\Environment UserInitMprLogonScript",
        "heur_persist",
    ),
    c(
        "T1047",
        "Windows Management Instrumentation",
        "wmiprvse.exe spawning cmd/PowerShell (wmiexec output to ADMIN$ escalates)",
        "heur_parentchild",
    ),
    c(
        "T1053.005",
        "Scheduled Task",
        "task XML under System32\\Tasks; Security 4698 task created; hidden TaskCache\\Tree tasks (SD value deleted or no task file: Tarrask)",
        "heur_persist, heur_eventlog, heur_defense",
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
        "T1059.003",
        "Windows Command Shell",
        "persistence running cmd.exe on a user-writable or remote script",
        "heur_persist",
    ),
    c(
        "T1059.005",
        "Visual Basic",
        "persistence running wscript/cscript on a user-writable or remote script",
        "heur_persist",
    ),
    c(
        "T1070.001",
        "Clear Windows Event Logs",
        "Security 1102 / System 104 log cleared",
        "heur_eventlog",
    ),
    c(
        "T1098",
        "Account Manipulation",
        "Security 4722 account enabled, 4724 password reset by another account, 4738 risky UAC flag turned on",
        "heur_account",
    ),
    c(
        "T1098.007",
        "Additional Local or Domain Groups",
        "Security 4728/4732/4756 member added to group (High for admin/RDP/backup groups)",
        "heur_account",
    ),
    c(
        "T1110.001",
        "Password Guessing",
        "Security 4625/4771/4776 guessing failures against one account",
        "heur_logon_bruteforce",
    ),
    c(
        "T1110.003",
        "Password Spraying",
        "Security 4625/4771/4776 failures across many accounts from one source",
        "heur_logon_bruteforce",
    ),
    c(
        "T1133",
        "External Remote Services",
        "inbound RDP/SMB/SSH session from a public IP",
        "heur_netconn",
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
        "T1204.004",
        "Malicious Copy and Paste (ClickFix)",
        "Run dialog RunMRU and Explorer address bar TypedPaths of every loaded user; explorer.exe -> mshta.exe",
        "heur_clickfix, heur_parentchild",
    ),
    c(
        "T1218",
        "System Binary Proxy Execution",
        "LOLBins (rundll32, certutil, ...) run with suspicious arguments",
        "heur_parentchild",
    ),
    c(
        "T1218.005",
        "Mshta",
        "persistence running mshta on remote/user-writable content; explorer.exe -> mshta.exe",
        "heur_persist, heur_parentchild",
    ),
    c(
        "T1218.007",
        "Msiexec",
        "persistence running msiexec on a URL or user-writable package",
        "heur_persist",
    ),
    c(
        "T1218.010",
        "Regsvr32",
        "persistence running regsvr32 on a URL/scriptlet or user-writable DLL",
        "heur_persist",
    ),
    c(
        "T1218.011",
        "Rundll32",
        "persistence running rundll32 on a user-writable or remote DLL",
        "heur_persist",
    ),
    c(
        "T1219",
        "Remote Access Tools",
        "RMM / remote-access tools (AnyDesk, ScreenConnect, TeamViewer, Atera, ngrok, ...) from processes, services and install folders",
        "heur_rmm",
    ),
    c(
        "T1505.003",
        "Web Shell",
        "w3wp/sqlservr/httpd/nginx/Tomcat spawning cmd, PowerShell or whoami",
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
        "auto-start services' ImagePath + signature; System 7045 service installed",
        "heur_persist, heur_eventlog",
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
        "IFEO Debugger on sethc/utilman/osk/magnify/narrator; System32 accessibility binaries whose OriginalFilename is cmd/PowerShell/explorer or that are unsigned",
        "heur_persist, heur_defense",
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
    c(
        "T1562.001",
        "Disable or Modify Tools",
        "Defender 5001 real-time protection off, 5007 exclusion added; Defender exclusions (paths, extensions, processes, IPs), Defender disabled by policy, Tamper Protection off",
        "heur_eventlog, heur_defense",
    ),
    c(
        "T1569.002",
        "Service Execution",
        "services.exe -> cmd.exe writing to \\\\127.0.0.1\\ADMIN$, PSEXESVC (PsExec / Impacket)",
        "heur_parentchild",
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
        for m in cairn_core::Mechanism::ALL {
            let t = crate::asep::mechanism_mitre(*m);
            assert!(
                BUILTIN.iter().any(|c| c.technique == t),
                "{m} -> {t} missing from coverage table"
            );
        }
    }
}
