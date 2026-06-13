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
    r"\public\",
];

/// Remote ports considered ordinary egress; anything else is the "rare port" signal.
pub const COMMON_PORTS: &[u16] = &[
    80, 443, 53, 22, 3389, 445, 135, 139, 21, 25, 587, 993, 143, 110,
];

/// True if `path` (any case) contains one of the suspicious directory segments.
pub fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SUSPICIOUS_DIRS.iter().any(|d| lower.contains(d))
}

/// True if `port` is NOT in the common-egress set.
pub fn is_rare_port(port: u16) -> bool {
    !COMMON_PORTS.contains(&port)
}

/// True if `addr` is a routable public IPv4 (not RFC1918/loopback/link-local/unspecified).
/// A string that does not parse as IPv4 returns false (signal simply does not fire).
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
        }
        Err(_) => false,
    }
}

/// Accumulates weighted signals + human-readable reasons + ATT&CK tags for one finding.
#[derive(Debug, Default)]
pub struct Score {
    pub weight: u32,
    pub reasons: Vec<String>,
    pub mitre: Vec<String>,
}

impl Score {
    /// Add a signal: its weight, a plain-English reason, and optional ATT&CK ids.
    pub fn add(&mut self, weight: u32, reason: impl Into<String>, mitre: &[&str]) {
        self.weight += weight;
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
}
