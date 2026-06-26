//! Shared scoring primitives for the heuristics (SRS §10). Named-constant rule tables
//! live here so a config loader can later replace them without touching matching logic.
use cairn_core::Severity;
use std::net::Ipv4Addr;

/// Directories whose presence in an image path is a suspicious-execution signal.
/// Matched case-insensitively as a substring of the path.
pub const SUSPICIOUS_DIRS: &[&str] = &[
    r"\temp\",
    r"\appdata\",
    r"\programdata\",
    r"\downloads\",
    r"\public\", // matches C:\Users\Public (world-readable shared dir) too
];

/// The canonical install subpath for modern signed per-user apps (Notion, Warp, VS Code, …).
/// Matched case-insensitively as a substring. Only THIS AppData subpath earns suspicious-path
/// suppression; Temp/Roaming/other AppData subpaths stay suspicious (droppers favor them).
pub const TRUSTED_APPDATA_SUBPATH: &str = r"\appdata\local\programs\";

/// Remote ports considered ordinary egress; anything else is the "rare port" signal.
// Tunable allowlist; ports outside this set raise the "rare port" signal. Tune per environment (e.g. 8080/636 may be common internally).
pub const COMMON_PORTS: &[u16] = &[
    80, 443, 53, 22, 3389, 445, 135, 139, 21, 25, 587, 993, 143, 110,
];

/// Stock Winlogon `Shell` value on a default Windows install (post-normalization, lowercased).
pub const WINLOGON_SHELL_DEFAULT: &str = "explorer.exe";

/// Stock Winlogon `Userinit` values (post-normalization: lowercased, trailing comma stripped,
/// %SystemRoot%/%windir% expanded to c:\windows). Both the absolute and bare-name forms occur.
///
/// The `c:\windows` drive is assumed DELIBERATELY. On a host with Windows on another volume
/// (e.g. `D:\Windows`), a genuinely stock Userinit would fail to match and stay High — a
/// false POSITIVE (the safe direction for a forensic tool). Do NOT "fix" this by loosening the
/// match to ignore the drive: that would let an attacker plant `X:\...\userinit.exe` and earn
/// suppression. Fail-loud is intentional.
pub const WINLOGON_USERINIT_DEFAULTS: &[&str] =
    &[r"c:\windows\system32\userinit.exe", "userinit.exe"];

/// True if `path` (any case) contains one of the suspicious directory segments.
pub fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SUSPICIOUS_DIRS.iter().any(|d| lower.contains(d))
}

/// True if `path` (any case) is under the trusted per-user app install directory
/// (`\AppData\Local\Programs\`). Used only in combination with `signed==Some(true)`.
pub fn is_trusted_appdata_location(path: &str) -> bool {
    path.to_ascii_lowercase().contains(TRUSTED_APPDATA_SUBPATH)
}

/// True if `port` is NOT in the common-egress set.
pub fn is_rare_port(port: u16) -> bool {
    !COMMON_PORTS.contains(&port)
}

/// True if `addr` is a routable public IPv4 (not RFC1918/loopback/link-local/unspecified,
/// nor CGNAT/benchmarking/IETF-protocol/reserved). A string that does not parse as IPv4
/// returns false (the signal simply does not fire).
///
/// FUTURE: replace the manual reserved-range guards with `Ipv4Addr::is_global()` once that
/// method stabilises (currently nightly-only behind `feature(ip)`).
pub fn is_public_ipv4(addr: &str) -> bool {
    match addr.parse::<Ipv4Addr>() {
        Ok(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_multicast()
                && !is_reserved_nonpublic(ip)
        }
        Err(_) => false,
    }
}

/// Ranges that std's `is_private`/etc. do not cover but are still non-routable:
/// CGNAT (100.64.0.0/10), IETF protocol assignments (192.0.0.0/24),
/// benchmarking (198.18.0.0/15), reserved class E (240.0.0.0/4).
fn is_reserved_nonpublic(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let cgnat = o[0] == 100 && (o[1] & 0xC0) == 64; // 100.64.0.0/10
    let ietf_protocol = o[0] == 192 && o[1] == 0 && o[2] == 0; // 192.0.0.0/24
    let benchmarking = o[0] == 198 && (o[1] & 0xFE) == 18; // 198.18.0.0/15
    let class_e = o[0] >= 240; // 240.0.0.0/4
    cgnat || ietf_protocol || benchmarking || class_e
}

/// True if a Winlogon registry value carries its stock default (i.e. NOT attacker-modified).
/// `value_name` is the registry value ("Shell"/"Userinit"); `command` is its data.
/// Normalization tolerates case, surrounding whitespace, a single trailing comma (Windows
/// writes `userinit.exe,`), and a leading %SystemRoot%/%windir% (expanded to c:\windows).
/// Any appended payload, replacement, or wrong value name fails to match (fail-loud).
pub fn winlogon_value_is_default(value_name: &str, command: &str) -> bool {
    let norm = normalize_winlogon_command(command);
    match value_name {
        "Shell" => norm == WINLOGON_SHELL_DEFAULT,
        "Userinit" => WINLOGON_USERINIT_DEFAULTS.contains(&norm.as_str()),
        _ => false,
    }
}

/// Lowercase, trim, strip a single trailing comma, expand a leading %SystemRoot%/%windir%.
fn normalize_winlogon_command(command: &str) -> String {
    let mut s = command.trim().to_ascii_lowercase();
    if let Some(stripped) = s.strip_suffix(',') {
        s = stripped.to_string();
    }
    for var in ["%systemroot%", "%windir%"] {
        if let Some(rest) = s.strip_prefix(var) {
            s = format!(r"c:\windows{rest}");
            break;
        }
    }
    s
}

/// Collapses Windows env-var / path-root prefixes to a canonical `<win>\` prefix
/// (case-insensitive), so the inbox-pattern check only needs one code path.
fn normalise_service_cmd(cmd: &str) -> String {
    let lower = cmd.trim().to_ascii_lowercase();
    for prefix in [r"%systemroot%\", r"%windir%\"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return format!(r"<win>\{rest}");
        }
    }
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        return format!(r"<win>\{rest}");
    }
    // Drive-letter form: exactly one letter + ":\windows\" (11 chars total)
    if lower.len() > 11 {
        let (head, rest) = lower.split_at(11);
        let chars: Vec<char> = head.chars().collect();
        if chars[0].is_ascii_alphabetic()
            && chars[1] == ':'
            && &head[2..] == r"\windows\"
        {
            return format!(r"<win>\{rest}");
        }
    }
    lower
}

/// Returns `true` when `cmd` is a Windows inbox service binary (System32 / SysWOW64),
/// excluding DriverStore paths (OEM drivers are not suppressed).
pub fn is_inbox_service_command(cmd: &str) -> bool {
    if cmd.trim().is_empty() {
        return false;
    }
    let norm = normalise_service_cmd(cmd);
    // DriverStore OEM drivers are NOT suppressed even if under System32
    if norm.contains(r"\driverstore\") {
        return false;
    }
    // Absolute canonical form
    if norm.starts_with(r"<win>\system32\") || norm.starts_with(r"<win>\syswow64\") {
        return true;
    }
    // Relative bare form (may have a leading quote from registry ImagePath)
    let stripped = norm.strip_prefix('"').unwrap_or(&norm);
    if stripped.starts_with(r"system32\") || stripped.starts_with(r"syswow64\") {
        return true;
    }
    false
}

/// Accumulates weighted signals + human-readable reasons + ATT&CK tags for one finding.
#[derive(Debug, Default)]
pub struct Score {
    pub weight: u32,
    /// Reasons are appended in signal-fire order (do not reorder; preserves the narrative).
    pub reasons: Vec<String>,
    pub mitre: Vec<String>,
}

impl Score {
    /// Add a signal: its weight, a plain-English reason, and optional ATT&CK ids.
    pub fn add(&mut self, weight: u32, reason: impl Into<String>, mitre: &[&str]) {
        // saturating: a finding's weight must never panic on overflow (clamps at Critical)
        self.weight = self.weight.saturating_add(weight);
        self.reasons.push(reason.into());
        for m in mitre {
            let m = m.to_string();
            if !self.mitre.contains(&m) {
                self.mitre.push(m);
            }
        }
    }
}

/// Map an accumulated weight to a Severity. Returns None below the noise floor (<15),
/// meaning "do not emit a finding".
pub fn severity_for(weight: u32) -> Option<Severity> {
    match weight {
        70.. => Some(Severity::Critical),
        50..=69 => Some(Severity::High),
        30..=49 => Some(Severity::Medium),
        15..=29 => Some(Severity::Low),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_path_matches_each_dir_case_insensitively() {
        assert!(is_suspicious_path(r"C:\Users\a\AppData\Local\Temp\x.exe"));
        assert!(is_suspicious_path(r"c:\users\a\downloads\y.exe"));
        assert!(is_suspicious_path(r"C:\ProgramData\z.exe"));
        // a normal system path is not suspicious
        assert!(!is_suspicious_path(r"C:\Windows\System32\cmd.exe"));
    }

    #[test]
    fn rare_port_excludes_common_ports() {
        assert!(!is_rare_port(443));
        assert!(!is_rare_port(53));
        assert!(is_rare_port(4444));
        assert!(is_rare_port(8081));
    }

    #[test]
    fn public_ipv4_excludes_private_and_garbage() {
        assert!(is_public_ipv4("8.8.8.8"));
        assert!(is_public_ipv4("104.18.0.1"));
        assert!(!is_public_ipv4("10.0.0.5")); // RFC1918
        assert!(!is_public_ipv4("192.168.1.1")); // RFC1918
        assert!(!is_public_ipv4("172.16.0.1")); // RFC1918
        assert!(!is_public_ipv4("127.0.0.1")); // loopback
        assert!(!is_public_ipv4("169.254.1.1")); // link-local
        assert!(!is_public_ipv4("0.0.0.0")); // unspecified
        assert!(!is_public_ipv4("not-an-ip")); // unparseable -> false
        assert!(!is_public_ipv4("100.64.0.1")); // CGNAT (RFC6598)
        assert!(!is_public_ipv4("198.18.0.1")); // benchmarking (RFC2544)
        assert!(!is_public_ipv4("240.0.0.1")); // reserved class E
        assert!(!is_public_ipv4("192.0.0.1")); // IETF protocol (RFC6890)
    }

    #[test]
    fn severity_boundaries() {
        assert_eq!(severity_for(70), Some(Severity::Critical));
        assert_eq!(severity_for(69), Some(Severity::High));
        assert_eq!(severity_for(50), Some(Severity::High));
        assert_eq!(severity_for(49), Some(Severity::Medium));
        assert_eq!(severity_for(30), Some(Severity::Medium));
        assert_eq!(severity_for(29), Some(Severity::Low));
        assert_eq!(severity_for(15), Some(Severity::Low));
        assert_eq!(severity_for(14), None); // below noise floor
        assert_eq!(severity_for(0), None);
    }

    #[test]
    fn score_accumulates_weight_reasons_and_dedups_mitre() {
        let mut s = Score::default();
        s.add(50, "office spawned shell", &["T1059"]);
        s.add(40, "encoded powershell", &["T1059.001", "T1059"]);
        assert_eq!(s.weight, 90);
        assert_eq!(s.reasons.len(), 2);
        assert_eq!(s.mitre, vec!["T1059", "T1059.001"]); // deduped, insertion order
    }

    #[test]
    fn winlogon_default_shell_matches() {
        assert!(winlogon_value_is_default("Shell", "explorer.exe"));
        assert!(winlogon_value_is_default("Shell", "  explorer.exe  ")); // trimmed
        assert!(winlogon_value_is_default("Shell", "EXPLORER.EXE")); // case-insensitive
    }

    #[test]
    fn winlogon_default_userinit_matches_variants() {
        // trailing comma (Windows writes "userinit.exe,") + case
        assert!(winlogon_value_is_default(
            "Userinit",
            r"C:\WINDOWS\system32\userinit.exe,"
        ));
        // env-var form expands to C:\Windows
        assert!(winlogon_value_is_default(
            "Userinit",
            r"%SystemRoot%\system32\userinit.exe"
        ));
        // bare-name form
        assert!(winlogon_value_is_default("Userinit", "userinit.exe"));
    }

    #[test]
    fn trusted_appdata_location_is_local_programs_only() {
        assert!(is_trusted_appdata_location(
            r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"
        ));
        assert!(is_trusted_appdata_location(
            r"c:\users\x\appdata\local\programs\warp\warp.exe"
        )); // case-insensitive
            // NOT trusted: droppers favor Temp / Roaming / other AppData subpaths
        assert!(!is_trusted_appdata_location(
            r"C:\Users\x\AppData\Local\Temp\e.exe"
        ));
        assert!(!is_trusted_appdata_location(
            r"C:\Users\x\AppData\Roaming\e.exe"
        ));
        assert!(!is_trusted_appdata_location(r"C:\Program Files\App\a.exe"));
    }

    #[test]
    fn winlogon_tampered_values_do_not_match() {
        // appended payload (the classic attack) — must NOT match
        assert!(!winlogon_value_is_default("Shell", "explorer.exe,evil.exe"));
        assert!(!winlogon_value_is_default(
            "Userinit",
            r"C:\WINDOWS\system32\userinit.exe,evil.exe"
        ));
        // replaced shell
        assert!(!winlogon_value_is_default("Shell", r"C:\Temp\x.exe"));
        // wrong value name (a userinit string under the Shell name)
        assert!(!winlogon_value_is_default("Shell", "userinit.exe"));
        // unknown value name
        assert!(!winlogon_value_is_default("Notify", "explorer.exe"));
    }

    #[test]
    fn inbox_svchost_pct_systemroot_suppressed() {
        assert!(is_inbox_service_command(
            r"%SystemRoot%\system32\svchost.exe -k DcomLaunch -p"
        ));
    }

    #[test]
    fn inbox_svchost_pct_windir_suppressed() {
        assert!(is_inbox_service_command(
            r"%windir%\system32\svchost.exe -k netsvcs"
        ));
    }

    #[test]
    fn inbox_backslash_systemroot_suppressed() {
        assert!(is_inbox_service_command(
            r"\SystemRoot\system32\lsass.exe"
        ));
    }

    #[test]
    fn inbox_absolute_cwindows_suppressed() {
        assert!(is_inbox_service_command(
            r"C:\Windows\system32\SearchIndexer.exe /Embedding"
        ));
    }

    #[test]
    fn inbox_relative_system32_suppressed() {
        assert!(is_inbox_service_command(r"System32\drivers\tcpip.sys"));
    }

    #[test]
    fn inbox_relative_syswow64_suppressed() {
        assert!(is_inbox_service_command(r"SysWOW64\some32bitbin.exe"));
    }

    #[test]
    fn inbox_case_insensitive() {
        assert!(is_inbox_service_command(r"SYSTEM32\DRIVERS\WDF01000.SYS"));
        assert!(is_inbox_service_command(
            r"%SYSTEMROOT%\SYSTEM32\SVCHOST.EXE -k LocalService"
        ));
    }

    #[test]
    fn driverstore_not_suppressed_abs() {
        assert!(!is_inbox_service_command(
            r"%SystemRoot%\System32\DriverStore\FileRepository\asusptpfilter.inf_amd64_e109\AsusPTPService.exe"
        ));
    }

    #[test]
    fn driverstore_not_suppressed_rel() {
        assert!(!is_inbox_service_command(
            r"System32\DriverStore\FileRepository\genpass.inf_amd64_0c82d80c\genpass.sys"
        ));
    }

    #[test]
    fn program_files_not_suppressed() {
        assert!(!is_inbox_service_command(
            r#""C:\Program Files\Trend Micro\AMSP\coreServiceShell.exe""#
        ));
    }

    #[test]
    fn windowsapps_not_suppressed() {
        assert!(!is_inbox_service_command(
            r#""C:\Program Files\WindowsApps\Claude_1.15\app\resources\cowork-svc.exe""#
        ));
    }

    #[test]
    fn empty_command_not_suppressed() {
        assert!(!is_inbox_service_command(""));
    }
}
