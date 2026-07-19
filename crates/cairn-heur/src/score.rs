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
        if chars[0].is_ascii_alphabetic() && chars[1] == ':' && &head[2..] == r"\windows\" {
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

/// 跨文物比對鍵：有完整路徑（含目錄分隔符）就用正規化後的完整路徑比對；
/// 只有檔名（來源本身缺路徑資訊，如多數 prefetch 條目、srum 的 "id:<n>" 回退）
/// 就降級成純檔名比對。降級佐證的信心度低於完整路徑相符，呼叫端在組
/// finding reason 時必須標註「降級佐證」。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JoinKey {
    /// 正規化（trim + 去引號 + 小寫）後的完整路徑，含目錄。
    Path(String),
    /// 僅檔名（去 `.exe` 尾綴），來源缺路徑資訊。
    Name(String),
}

impl JoinKey {
    /// 兩個 JoinKey 是否應視為同一佐證目標：Path 對 Path 要求完全相同；
    /// 任一方是 Name（降級）就退回比對雙方的 basename。
    pub fn degraded_key(&self) -> String {
        match self {
            JoinKey::Path(p) => basename_from_normalized(p),
            JoinKey::Name(n) => n.clone(),
        }
    }
}

/// 從一個原始路徑/檔名字串建立 JoinKey：trim + 去引號 + 小寫，再判斷是否含
/// 目錄分隔符（`\` 或 `/`）。不含分隔符（如純檔名、或 srum 的 "id:42" 回退）
/// 一律視為 Name（降級）鍵。
pub fn join_key(raw: &str) -> JoinKey {
    let normalized = raw.trim().trim_matches('"').to_ascii_lowercase();
    if normalized.contains('\\') || normalized.contains('/') {
        JoinKey::Path(normalized)
    } else {
        JoinKey::Name(strip_exe_suffix(&normalized))
    }
}

/// 從一個已正規化（小寫、trim 過）的完整路徑取出檔名（去 `.exe` 尾綴）。
fn basename_from_normalized(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    strip_exe_suffix(base)
}

/// 去掉 `.exe` 尾綴（若有）。
fn strip_exe_suffix(s: &str) -> String {
    s.strip_suffix(".exe")
        .map(String::from)
        .unwrap_or_else(|| s.to_string())
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

/// Bump one severity band (multi-signal / execution-corroboration escalation).
/// Caps at Critical.
pub fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// Index execution + process records for corroboration lookups. Two-layer index:
/// exact (JoinKey equality — Path==Path or Name==Name with identical string) built
/// for **all** records; degraded (basename-only) built **only** from records whose
/// source itself lacks path information (`JoinKey::Name`, e.g. prefetch filenames,
/// srum's `id:<n>` fallback) — records with a full path (`JoinKey::Path`) are never
/// inserted into the degraded index. On lookup, exact is tried first regardless of
/// the query's own key kind; degraded is only consulted on an exact miss. Because
/// the degraded index only ever holds path-less records, two records that both carry
/// full paths (but disagree on directory) can never collide there.
pub struct CrossIndex<'a> {
    exec_exact: std::collections::HashMap<JoinKey, Vec<&'a cairn_core::record::ExecutionRecord>>,
    exec_degraded: std::collections::HashMap<String, Vec<&'a cairn_core::record::ExecutionRecord>>,
    proc_exact: std::collections::HashMap<JoinKey, Vec<&'a cairn_core::record::ProcessRecord>>,
    proc_degraded: std::collections::HashMap<String, Vec<&'a cairn_core::record::ProcessRecord>>,
}

impl<'a> CrossIndex<'a> {
    /// Look up execution-artifact corroboration: exact key first, falling back to
    /// the degraded (filename-only) index on a miss. Returns (hits, was_degraded).
    pub fn lookup_exec(
        &self,
        key: &JoinKey,
    ) -> (Vec<&'a cairn_core::record::ExecutionRecord>, bool) {
        if let Some(hits) = self.exec_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        match self.exec_degraded.get(&key.degraded_key()) {
            Some(hits) if !hits.is_empty() => (hits.clone(), true),
            _ => (Vec::new(), false),
        }
    }

    /// Same as `lookup_exec`, on the process side.
    pub fn lookup_proc(&self, key: &JoinKey) -> (Vec<&'a cairn_core::record::ProcessRecord>, bool) {
        if let Some(hits) = self.proc_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        match self.proc_degraded.get(&key.degraded_key()) {
            Some(hits) if !hits.is_empty() => (hits.clone(), true),
            _ => (Vec::new(), false),
        }
    }
}

/// Build a `CrossIndex` over every `Record::Execution`/`Record::Process` entry in
/// `records`.
pub fn build_cross_index(records: &[cairn_core::record::Record]) -> CrossIndex<'_> {
    use cairn_core::record::Record;
    let mut exec_exact: std::collections::HashMap<JoinKey, Vec<&cairn_core::record::ExecutionRecord>> =
        std::collections::HashMap::new();
    let mut exec_degraded: std::collections::HashMap<String, Vec<&cairn_core::record::ExecutionRecord>> =
        std::collections::HashMap::new();
    let mut proc_exact: std::collections::HashMap<JoinKey, Vec<&cairn_core::record::ProcessRecord>> =
        std::collections::HashMap::new();
    let mut proc_degraded: std::collections::HashMap<String, Vec<&cairn_core::record::ProcessRecord>> =
        std::collections::HashMap::new();
    for r in records {
        match r {
            Record::Execution(e) => {
                let k = join_key(&e.path);
                if !k.degraded_key().is_empty() {
                    if let JoinKey::Name(n) = &k {
                        exec_degraded.entry(n.clone()).or_default().push(e);
                    }
                    exec_exact.entry(k).or_default().push(e);
                }
            }
            Record::Process(p) => {
                let k = join_key(&p.image);
                if !k.degraded_key().is_empty() {
                    if let JoinKey::Name(n) = &k {
                        proc_degraded.entry(n.clone()).or_default().push(p);
                    }
                    proc_exact.entry(k).or_default().push(p);
                }
            }
            _ => {}
        }
    }
    CrossIndex {
        exec_exact,
        exec_degraded,
        proc_exact,
        proc_degraded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_key_full_path_requires_path_match_not_just_basename() {
        // Two ProcessRecords with the same basename but different directories must
        // NOT be treated as the same join key when both sides have full paths.
        let a = join_key(r"C:\Windows\System32\evil.exe");
        let b = join_key(r"C:\Users\x\AppData\Local\Temp\evil.exe");
        assert_ne!(a, b, "same basename, different full paths must not collide");
    }

    #[test]
    fn join_key_full_path_matches_identical_path_case_insensitive() {
        let a = join_key(r"C:\Windows\System32\evil.exe");
        let b = join_key(r"c:\windows\system32\EVIL.EXE");
        assert_eq!(a, b, "identical path differing only by case must match");
    }

    #[test]
    fn join_key_name_only_source_degrades_to_basename_match() {
        // prefetch-style source: bare filename, no directory component.
        let prefetch_side = join_key("NOTEPAD.EXE");
        let live_side = join_key(r"C:\Windows\System32\notepad.exe");
        // Degraded match: both reduce to the same basename-level key.
        assert_eq!(
            prefetch_side.degraded_key(),
            live_side.degraded_key(),
            "basename-only source must still corroborate via degraded match"
        );
    }

    #[test]
    fn join_key_srum_id_fallback_is_name_only() {
        // srum's resolve_app_name falls back to "id:<n>" when unmapped — must be
        // treated as a Name key (no directory component), not misparsed as a path.
        let k = join_key("id:42");
        assert!(
            matches!(k, JoinKey::Name(_)),
            "id: fallback must be a Name key"
        );
    }

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
        assert!(is_inbox_service_command(r"\SystemRoot\system32\lsass.exe"));
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

    #[test]
    fn escalate_caps_at_critical() {
        assert_eq!(escalate(Severity::Low), Severity::Medium);
        assert_eq!(escalate(Severity::Medium), Severity::High);
        assert_eq!(escalate(Severity::High), Severity::Critical);
        assert_eq!(escalate(Severity::Critical), Severity::Critical);
    }

    #[test]
    fn cross_index_full_paths_with_same_basename_never_collide_via_degraded() {
        use cairn_core::record::{ExecutionRecord, Record};
        // Regression for F-2 resurfacing: two ExecutionRecords both carry full paths
        // (e.g. shimcache/userassist) with the same basename but different directories.
        // Looking up one path must NOT return the other via the degraded (basename-only)
        // fallback — degraded matching is reserved for sources that never had a path
        // to begin with (JoinKey::Name), not for two full paths that merely disagree.
        let sys32 = ExecutionRecord {
            source: "shimcache".into(),
            path: r"C:\Windows\System32\evil.exe".into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        };
        let temp = ExecutionRecord {
            source: "shimcache".into(),
            path: r"C:\Users\alice\AppData\Local\Temp\evil.exe".into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        };
        let records = vec![
            Record::Execution(sys32.clone()),
            Record::Execution(temp.clone()),
        ];
        let idx = build_cross_index(&records);

        let (hits, degraded) = idx.lookup_exec(&join_key(r"C:\Windows\System32\evil.exe"));
        assert_eq!(
            hits.len(),
            1,
            "must match only the exact path, not the temp twin"
        );
        assert_eq!(hits[0].path, sys32.path);
        assert!(
            !degraded,
            "exact path match must not be flagged as degraded"
        );

        let (hits, degraded) =
            idx.lookup_exec(&join_key(r"C:\Users\alice\AppData\Local\Temp\evil.exe"));
        assert_eq!(
            hits.len(),
            1,
            "must match only the exact path, not the system32 twin"
        );
        assert_eq!(hits[0].path, temp.path);
        assert!(!degraded);

        // A path with no exact match at all must return empty, not fall back to
        // basename-guessing against either full-path record above.
        let (hits, degraded) = idx.lookup_exec(&join_key(r"D:\Other\evil.exe"));
        assert!(
            hits.is_empty(),
            "unmatched full path must not degrade to basename guess"
        );
        assert!(!degraded);
    }
}
