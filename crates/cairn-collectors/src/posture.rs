//! Defense and logging posture (phase 3E `posture` collector), read-only.
//!
//! One [`PostureRecord`] per live run: audit policy (via the read-only
//! `AuditQuerySystemPolicy` wrapper in cairn-collectors-win), 4688 command-line and
//! PowerShell logging policy, Sysmon presence, Defender policy / tamper state /
//! exclusions, the scheduled-task TaskCache tree (for hidden "Tarrask" tasks), the
//! accessibility binaries in System32 (sticky-keys replacement) and the top-level
//! folders of the program-install roots (RMM inventory).
//!
//! Every host read goes through the [`PostureHost`] seam, so [`snapshot`] is unit-tested
//! off-Windows with a fake host. Nothing is judged here (that is `cairn-heur::defense`
//! and `cairn-heur::rmm`); nothing is written. A key that exists but cannot be read is
//! an error in the manifest source entry, and the matching field stays `None` (or the
//! key is listed in `exclusions_unreadable`): unreadable is never reported as clean.

use cairn_collectors_win::auditpol::{self, AuditSetting};
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{
    AccessibilityBinary, DefenderExclusion, DefenderPolicy, ExclusionKind, PostureRecord,
    ProgramDir, Record, TaskCacheEntry,
};
use cairn_core::traits::{CollectCtx, Collector, FileVerifier};
use cairn_core::Result;
use chrono::{DateTime, Utc};

/// One registry value's data, reduced to what posture reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegVal {
    Dword(u32),
    /// REG_SZ / REG_EXPAND_SZ.
    Str(String),
    Other,
}

/// A registry key: its values (default value under `""`), child key names, LastWrite.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegKeyData {
    pub values: Vec<(String, RegVal)>,
    pub subkeys: Vec<String>,
    pub last_write: Option<DateTime<Utc>>,
}

impl RegKeyData {
    fn get(&self, name: &str) -> Option<&RegVal> {
        self.values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// A DWORD value (a decimal REG_SZ is accepted too: some GPO tools write strings).
    pub fn dword(&self, name: &str) -> Option<u32> {
        match self.get(name)? {
            RegVal::Dword(d) => Some(*d),
            RegVal::Str(s) => s.trim().parse().ok(),
            RegVal::Other => None,
        }
    }

    pub fn string(&self, name: &str) -> Option<&str> {
        match self.get(name)? {
            RegVal::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

/// Child directories as (full path, mtime); `None` when the parent is absent.
pub type DirList = Option<Vec<(String, Option<DateTime<Utc>>)>>;

/// Read-only host access used by [`snapshot`]. Paths are Windows paths.
pub trait PostureHost {
    /// An HKLM-relative key. `Ok(None)` = absent; `Err(reason)` = present but unreadable.
    fn hklm(&self, key: &str) -> std::result::Result<Option<RegKeyData>, String>;
    /// Advanced audit policy of each subcategory GUID, in input order.
    fn audit_policy(
        &self,
        subcategories: &[u128],
    ) -> std::result::Result<Vec<AuditSetting>, String>;
    /// `Some(true)` exists, `Some(false)` does not, `None` cannot tell (access denied).
    fn exists(&self, path: &str) -> Option<bool>;
    /// Child directories of `dir` as (full path, mtime). `Ok(None)` when `dir` is absent.
    fn subdirs(&self, dir: &str) -> std::result::Result<DirList, String>;
    /// Up to `cap` bytes of a file (None when unreadable).
    fn read_head(&self, path: &str, cap: u64) -> Option<Vec<u8>>;
    fn mtime(&self, path: &str) -> Option<DateTime<Utc>>;
    fn sha256(&self, path: &str) -> Option<String>;
    fn env(&self, var: &str) -> Option<String>;
}

/// Advanced audit subcategories read, in [`PostureRecord`] field order.
const AUDIT_SUBCATEGORIES: [u128; 5] = [
    auditpol::subcategory::PROCESS_CREATION,
    auditpol::subcategory::LOGON,
    auditpol::subcategory::OTHER_OBJECT_ACCESS,
    auditpol::subcategory::USER_ACCOUNT_MANAGEMENT,
    auditpol::subcategory::SECURITY_GROUP_MANAGEMENT,
];

const AUDIT_SYSTEM_POLICY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
const PS_SCRIPTBLOCK: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
const PS_MODULE: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";
const SYSMON_SERVICES: &[&str] = &["SysmonDrv", "Sysmon64", "Sysmon"];
const SYSMON_CHANNEL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational";
const DEFENDER_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";
const DEFENDER_POLICY_RTP: &str =
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
const DEFENDER_FEATURES: &str = r"SOFTWARE\Microsoft\Windows Defender\Features";
/// (exclusions root, is the Group Policy key).
const EXCLUSION_ROOTS: &[(&str, bool)] = &[
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions", false),
    (
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
        true,
    ),
];
const EXCLUSION_LISTS: &[(&str, ExclusionKind)] = &[
    ("Paths", ExclusionKind::Path),
    ("Extensions", ExclusionKind::Extension),
    ("Processes", ExclusionKind::Process),
    ("IpAddresses", ExclusionKind::IpAddress),
];
const TASKCACHE_TREE: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
/// Bounds on the TaskCache walk (a normal host has a few hundred tasks).
const TASKCACHE_MAX_DEPTH: usize = 32;
const TASKCACHE_MAX_ENTRIES: usize = 10_000;

/// The Windows accessibility binaries reachable from the logon screen.
pub const ACCESSIBILITY_BINARIES: &[&str] = &[
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
    "displayswitch.exe",
    "atbroker.exe",
];
/// Read cap for the version-resource scan (explorer.exe, the largest likely stand-in,
/// is ~5 MiB).
const VERSION_SCAN_CAP: u64 = 64 * 1024 * 1024;
/// Bound on recorded program folders (all roots together).
const MAX_PROGRAM_DIRS: usize = 5_000;
/// Profile folders under `C:\Users` that are not user profiles.
const NON_PROFILE_DIRS: &[&str] = &["public", "default", "default user", "all users"];

/// Take the posture snapshot. Returns the record and the source errors to put in the
/// manifest (one line per unreadable location).
pub fn snapshot(
    host: &dyn PostureHost,
    verifier: &dyn FileVerifier,
    now: DateTime<Utc>,
) -> (PostureRecord, Vec<String>) {
    let mut errs = Vec::new();
    let mut p = PostureRecord {
        collected_at: Some(now),
        ..PostureRecord::default()
    };

    match host.audit_policy(&AUDIT_SUBCATEGORIES) {
        Ok(s) if s.len() == AUDIT_SUBCATEGORIES.len() => {
            p.audit_process_creation = Some(s[0].success);
            p.audit_logon = Some(s[1].success || s[1].failure);
            p.audit_other_object_access = Some(s[2].success);
            p.audit_user_account_management = Some(s[3].success);
            p.audit_security_group_management = Some(s[4].success);
        }
        Ok(s) => errs.push(format!(
            "audit policy: {} settings returned for {} subcategories",
            s.len(),
            AUDIT_SUBCATEGORIES.len()
        )),
        Err(e) => errs.push(format!("audit policy: {e}")),
    }

    p.cmdline_in_4688 = policy_flag(
        host,
        AUDIT_SYSTEM_POLICY,
        "ProcessCreationIncludeCmdLine_Enabled",
        &mut errs,
    );
    p.ps_scriptblock = policy_flag(host, PS_SCRIPTBLOCK, "EnableScriptBlockLogging", &mut errs);
    p.ps_module_logging = policy_flag(host, PS_MODULE, "EnableModuleLogging", &mut errs);

    p.sysmon_present = any_key_present(
        host,
        SYSMON_SERVICES
            .iter()
            .map(|s| format!(r"SYSTEM\CurrentControlSet\Services\{s}")),
        &mut errs,
    );
    p.sysmon_channel =
        any_key_present(host, std::iter::once(SYSMON_CHANNEL.to_string()), &mut errs);

    p.defender_policy = DefenderPolicy {
        disable_antispyware: dword(host, DEFENDER_POLICY, "DisableAntiSpyware", &mut errs),
        disable_realtime_monitoring: dword(
            host,
            DEFENDER_POLICY_RTP,
            "DisableRealtimeMonitoring",
            &mut errs,
        ),
        disable_behavior_monitoring: dword(
            host,
            DEFENDER_POLICY_RTP,
            "DisableBehaviorMonitoring",
            &mut errs,
        ),
    };
    p.tamper_protection = dword(host, DEFENDER_FEATURES, "TamperProtection", &mut errs);

    read_exclusions(host, &mut p, &mut errs);

    let system_root = host
        .env("SystemRoot")
        .or_else(|| host.env("windir"))
        .unwrap_or_else(|| r"C:\Windows".to_string());
    let system_root = system_root.trim_end_matches('\\').to_string();
    p.task_cache = read_task_cache(host, &system_root, &mut errs);
    p.accessibility_binaries = read_accessibility(host, verifier, &system_root, &mut errs);
    p.program_dirs = read_program_dirs(host, &mut errs);
    (p, errs)
}

fn read_key(
    host: &dyn PostureHost,
    key: &str,
    errs: &mut Vec<String>,
) -> Option<Option<RegKeyData>> {
    match host.hklm(key) {
        Ok(k) => Some(k),
        Err(e) => {
            errs.push(format!(r"HKLM\{key}: {e}"));
            None
        }
    }
}

/// A policy switch that is on only when the value is 1. An absent key or value is the
/// documented default (off); an unreadable key is unknown.
fn policy_flag(
    host: &dyn PostureHost,
    key: &str,
    value: &str,
    errs: &mut Vec<String>,
) -> Option<bool> {
    let k = read_key(host, key, errs)?;
    Some(k.and_then(|k| k.dword(value)) == Some(1))
}

fn dword(host: &dyn PostureHost, key: &str, value: &str, errs: &mut Vec<String>) -> Option<u32> {
    read_key(host, key, errs)?.and_then(|k| k.dword(value))
}

/// True when any key exists; false when every key is absent; None when none exists
/// and at least one could not be read.
fn any_key_present(
    host: &dyn PostureHost,
    keys: impl Iterator<Item = String>,
    errs: &mut Vec<String>,
) -> Option<bool> {
    let mut unknown = false;
    for key in keys {
        match read_key(host, &key, errs) {
            Some(Some(_)) => return Some(true),
            Some(None) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(false)
}

fn read_exclusions(host: &dyn PostureHost, p: &mut PostureRecord, errs: &mut Vec<String>) {
    for (root, policy) in EXCLUSION_ROOTS {
        for (list, kind) in EXCLUSION_LISTS {
            let key = format!(r"{root}\{list}");
            match host.hklm(&key) {
                Ok(None) => {}
                Ok(Some(k)) => {
                    for (name, _) in &k.values {
                        if name.is_empty() {
                            continue;
                        }
                        p.defender_exclusions.push(DefenderExclusion {
                            kind: *kind,
                            value: name.clone(),
                            policy: *policy,
                            key: format!(r"HKLM\{key}"),
                            last_write: k.last_write,
                        });
                    }
                }
                Err(e) => {
                    errs.push(format!(
                        r"HKLM\{key}: {e} (Defender exclusion list unreadable; not treated as empty)"
                    ));
                    p.exclusions_unreadable.push(format!(r"HKLM\{key}"));
                }
            }
        }
    }
}

fn read_task_cache(
    host: &dyn PostureHost,
    system_root: &str,
    errs: &mut Vec<String>,
) -> Vec<TaskCacheEntry> {
    let mut out = Vec::new();
    let Some(Some(root)) = read_key(host, TASKCACHE_TREE, errs) else {
        return out;
    };
    let tasks_dir = format!(r"{system_root}\System32\Tasks");
    let tasks_readable = host.exists(&tasks_dir) == Some(true);
    if !tasks_readable {
        errs.push(format!(
            "{tasks_dir}: not readable; TaskCache entries not checked for a task file"
        ));
    }
    // Depth-first walk: (relative path, child names, depth).
    let mut stack: Vec<(String, Vec<String>, usize)> = vec![(String::new(), root.subkeys, 0)];
    while let Some((parent, children, depth)) = stack.pop() {
        for child in children.into_iter().rev() {
            if out.len() >= TASKCACHE_MAX_ENTRIES {
                errs.push(format!(
                    "TaskCache: stopped after {TASKCACHE_MAX_ENTRIES} entries"
                ));
                return out;
            }
            let rel = format!(r"{parent}\{child}");
            let key = format!("{TASKCACHE_TREE}{rel}");
            let Some(Some(k)) = read_key(host, &key, errs) else {
                continue;
            };
            if k.has("Id") {
                let file_present = if tasks_readable {
                    host.exists(&format!("{tasks_dir}{rel}"))
                } else {
                    None
                };
                out.push(TaskCacheEntry {
                    path: rel.clone(),
                    key: format!(r"HKLM\{key}"),
                    id: k.string("Id").map(str::to_string),
                    sd_present: k.has("SD"),
                    file_present,
                    last_write: k.last_write,
                });
            }
            if !k.subkeys.is_empty() && depth + 1 < TASKCACHE_MAX_DEPTH {
                stack.push((rel, k.subkeys, depth + 1));
            }
        }
    }
    out.sort_by_key(|t| t.path.to_ascii_lowercase());
    out
}

fn read_accessibility(
    host: &dyn PostureHost,
    verifier: &dyn FileVerifier,
    system_root: &str,
    errs: &mut Vec<String>,
) -> Vec<AccessibilityBinary> {
    ACCESSIBILITY_BINARIES
        .iter()
        .map(|name| {
            let path = format!(r"{system_root}\System32\{name}");
            let exists = host.exists(&path);
            if exists.is_none() {
                errs.push(format!("{path}: cannot tell whether it exists"));
            }
            if exists != Some(true) {
                return AccessibilityBinary {
                    name: (*name).to_string(),
                    path,
                    exists: false,
                    original_filename: None,
                    signed: None,
                    signer: None,
                    sha256: None,
                    last_write: None,
                };
            }
            let original_filename = host
                .read_head(&path, VERSION_SCAN_CAP)
                .as_deref()
                .and_then(original_filename);
            AccessibilityBinary {
                name: (*name).to_string(),
                original_filename,
                signed: verifier.verify(&path),
                signer: verifier.signer(&path),
                sha256: host.sha256(&path),
                last_write: host.mtime(&path),
                exists: true,
                path,
            }
        })
        .collect()
}

/// The install roots: Program Files (both), ProgramData, and per user AppData\Local,
/// AppData\Roaming and AppData\Local\Programs.
fn program_roots(host: &dyn PostureHost, errs: &mut Vec<String>) -> Vec<String> {
    let drive = host.env("SystemDrive").unwrap_or_else(|| "C:".to_string());
    let drive = drive.trim_end_matches('\\').to_string();
    let mut roots: Vec<String> = Vec::new();
    let mut push = |r: String| {
        let r = r.trim_end_matches('\\').to_string();
        if !roots.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
            roots.push(r);
        }
    };
    for (var, default) in [
        ("ProgramFiles", r"\Program Files"),
        ("ProgramFiles(x86)", r"\Program Files (x86)"),
        ("ProgramData", r"\ProgramData"),
    ] {
        push(host.env(var).unwrap_or_else(|| format!("{drive}{default}")));
    }
    let users = format!(r"{drive}\Users");
    match host.subdirs(&users) {
        Ok(Some(homes)) => {
            let mut homes: Vec<String> = homes
                .into_iter()
                .map(|(p, _)| p)
                .filter(|p| {
                    let leaf = p.rsplit('\\').next().unwrap_or(p).to_ascii_lowercase();
                    !NON_PROFILE_DIRS.contains(&leaf.as_str())
                })
                .collect();
            homes.sort();
            for h in homes {
                for sub in [
                    r"AppData\Local",
                    r"AppData\Roaming",
                    r"AppData\Local\Programs",
                ] {
                    push(format!(r"{h}\{sub}"));
                }
            }
        }
        Ok(None) => {}
        Err(e) => errs.push(format!("{users}: {e}")),
    }
    roots
}

fn read_program_dirs(host: &dyn PostureHost, errs: &mut Vec<String>) -> Vec<ProgramDir> {
    let mut out = Vec::new();
    for root in program_roots(host, errs) {
        match host.subdirs(&root) {
            Ok(Some(dirs)) => {
                let mut dirs = dirs;
                dirs.sort_by(|a, b| a.0.cmp(&b.0));
                for (path, last_write) in dirs {
                    if out.len() >= MAX_PROGRAM_DIRS {
                        errs.push(format!("program folders: stopped after {MAX_PROGRAM_DIRS}"));
                        return out;
                    }
                    out.push(ProgramDir { path, last_write });
                }
            }
            Ok(None) => {}
            Err(e) => errs.push(format!("{root}: {e}")),
        }
    }
    out
}

/// UTF-16LE bytes of `s` followed by a NUL terminator.
fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// The version resource's `OriginalFilename` string, found by scanning the file for the
/// `StringFileInfo` `String` entry (wLength, wValueLength, wType, szKey, padding to a
/// 32-bit boundary, Value). Pure and total: None when there is none or it is malformed.
pub fn original_filename(bytes: &[u8]) -> Option<String> {
    let key = utf16z("OriginalFilename");
    let mut from = 0;
    while let Some(off) = find(&bytes[from..], &key) {
        let pos = from + off;
        from = pos + 2;
        let Some(header) = pos.checked_sub(6) else {
            continue;
        };
        let Some(words) = u16_at(bytes, pos - 4).map(usize::from) else {
            continue;
        };
        if words == 0 || words > 260 {
            continue;
        }
        let after_key = pos + key.len();
        let start = header + (after_key - header).div_ceil(4) * 4;
        let units: Vec<u16> = (0..words)
            .map_while(|i| u16_at(bytes, start + 2 * i))
            .take_while(|u| *u != 0)
            .collect();
        let s = String::from_utf16(&units).ok()?;
        let s = s.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The real host: registry via winreg (read-only opens, 64-bit view), files via std.
pub struct LiveHost;

fn fs_mtime(path: &str) -> Option<DateTime<Utc>> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
}

impl PostureHost for LiveHost {
    #[cfg(windows)]
    fn hklm(&self, key: &str) -> std::result::Result<Option<RegKeyData>, String> {
        use winreg::enums::{RegType, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        let root = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
        let k = match root.open_subkey_with_flags(key, KEY_READ | KEY_WOW64_64KEY) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let last_write = k.query_info().ok().and_then(|info| {
            let st = info.get_last_write_time_system();
            {
                use chrono::TimeZone;
                Utc.with_ymd_and_hms(
                    i32::from(st.wYear),
                    u32::from(st.wMonth),
                    u32::from(st.wDay),
                    u32::from(st.wHour),
                    u32::from(st.wMinute),
                    u32::from(st.wSecond),
                )
                .single()
            }
        });
        let mut values = Vec::new();
        for (name, raw) in k.enum_values().flatten() {
            let v = match raw.vtype {
                RegType::REG_DWORD if raw.bytes.len() >= 4 => RegVal::Dword(u32::from_le_bytes([
                    raw.bytes[0],
                    raw.bytes[1],
                    raw.bytes[2],
                    raw.bytes[3],
                ])),
                RegType::REG_SZ | RegType::REG_EXPAND_SZ => k
                    .get_value::<String, _>(&name)
                    .map(RegVal::Str)
                    .unwrap_or(RegVal::Other),
                _ => RegVal::Other,
            };
            values.push((name, v));
        }
        let subkeys = k.enum_keys().flatten().collect();
        Ok(Some(RegKeyData {
            values,
            subkeys,
            last_write,
        }))
    }

    #[cfg(not(windows))]
    fn hklm(&self, _key: &str) -> std::result::Result<Option<RegKeyData>, String> {
        Err("registry: unsupported platform".into())
    }

    fn audit_policy(
        &self,
        subcategories: &[u128],
    ) -> std::result::Result<Vec<AuditSetting>, String> {
        auditpol::query(subcategories)
    }

    fn exists(&self, path: &str) -> Option<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Some(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    }

    fn subdirs(&self, dir: &str) -> std::result::Result<DirList, String> {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if !md.is_dir() {
                continue;
            }
            let mtime = md.modified().ok().map(DateTime::<Utc>::from);
            out.push((e.path().display().to_string(), mtime));
        }
        Ok(Some(out))
    }

    fn read_head(&self, path: &str, cap: u64) -> Option<Vec<u8>> {
        use std::io::Read;
        let f = std::fs::File::open(path).ok()?;
        let mut buf = Vec::new();
        f.take(cap).read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    fn mtime(&self, path: &str) -> Option<DateTime<Utc>> {
        fs_mtime(path)
    }

    fn sha256(&self, path: &str) -> Option<String> {
        crate::hash::hash_file_capped(path)
    }

    fn env(&self, var: &str) -> Option<String> {
        std::env::var(var).ok().filter(|v| !v.is_empty())
    }
}

/// The `posture` collector. Read-only; runs without elevation (reads that need it fail
/// into the manifest source errors).
pub struct PostureCollector {
    verifier: Box<dyn FileVerifier + Send + Sync>,
    sources: std::sync::Mutex<Vec<SourceEntry>>,
}

impl Default for PostureCollector {
    fn default() -> Self {
        #[cfg(windows)]
        let verifier: Box<dyn FileVerifier + Send + Sync> =
            Box::new(cairn_collectors_win::signature::WinSigVerifier);
        #[cfg(not(windows))]
        let verifier: Box<dyn FileVerifier + Send + Sync> = Box::new(crate::persist::NoopVerifier);
        Self {
            verifier,
            sources: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Collector for PostureCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::POSTURE
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let now = Utc::now();
        #[cfg(windows)]
        let (rec, errors) = snapshot(&LiveHost, self.verifier.as_ref(), now);
        #[cfg(not(windows))]
        let (rec, errors) = {
            let _ = &self.verifier;
            (
                PostureRecord {
                    collected_at: Some(now),
                    ..PostureRecord::default()
                },
                vec!["posture: unsupported platform".to_string()],
            )
        };
        for e in &errors {
            tracing::warn!(collector = "posture", "{e}");
        }
        *self.sources.lock().unwrap_or_else(|e| e.into_inner()) = vec![SourceEntry {
            collector: String::new(),
            artifact: "posture".into(),
            path:
                r"HKLM (Defender, audit, PowerShell, Sysmon, TaskCache); System32; program folders"
                    .into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }];
        Ok(vec![Record::Posture(rec)])
    }

    fn sources(&self) -> Vec<SourceEntry> {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::{HashMap, HashSet};

    #[derive(Default)]
    struct FakeHost {
        keys: HashMap<String, RegKeyData>,
        denied: HashSet<String>,
        audit: Option<Vec<AuditSetting>>,
        files: HashMap<String, Vec<u8>>,
        dirs: HashMap<String, Vec<String>>,
        env: HashMap<String, String>,
    }

    fn lc(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    impl FakeHost {
        fn key(&mut self, key: &str, values: &[(&str, RegVal)]) -> &mut Self {
            let e = self.keys.entry(lc(key)).or_default();
            for (n, v) in values {
                e.values.push(((*n).to_string(), v.clone()));
            }
            // Register the key as a child of its parent.
            if let Some((parent, leaf)) = key.rsplit_once('\\') {
                let p = self.keys.entry(lc(parent)).or_default();
                if !p.subkeys.iter().any(|s| s.eq_ignore_ascii_case(leaf)) {
                    p.subkeys.push(leaf.to_string());
                }
            }
            self
        }
        fn file(&mut self, path: &str, bytes: Vec<u8>) -> &mut Self {
            self.files.insert(lc(path), bytes);
            self
        }
        fn dir(&mut self, dir: &str, children: &[&str]) -> &mut Self {
            self.dirs.insert(
                lc(dir),
                children.iter().map(|c| format!(r"{dir}\{c}")).collect(),
            );
            self
        }
    }

    impl PostureHost for FakeHost {
        fn hklm(&self, key: &str) -> std::result::Result<Option<RegKeyData>, String> {
            if self.denied.contains(&lc(key)) {
                return Err("Access is denied. (os error 5)".into());
            }
            Ok(self.keys.get(&lc(key)).cloned())
        }
        fn audit_policy(&self, s: &[u128]) -> std::result::Result<Vec<AuditSetting>, String> {
            match &self.audit {
                Some(v) => Ok(v.iter().take(s.len()).copied().collect()),
                None => Err("SeSecurityPrivilege not held".into()),
            }
        }
        fn exists(&self, path: &str) -> Option<bool> {
            Some(self.files.contains_key(&lc(path)) || self.dirs.contains_key(&lc(path)))
        }
        fn subdirs(&self, dir: &str) -> std::result::Result<DirList, String> {
            Ok(self
                .dirs
                .get(&lc(dir))
                .map(|v| v.iter().map(|p| (p.clone(), None)).collect()))
        }
        fn read_head(&self, path: &str, _cap: u64) -> Option<Vec<u8>> {
            self.files.get(&lc(path)).cloned()
        }
        fn mtime(&self, _path: &str) -> Option<DateTime<Utc>> {
            None
        }
        fn sha256(&self, _path: &str) -> Option<String> {
            Some("ab".into())
        }
        fn env(&self, var: &str) -> Option<String> {
            self.env.get(var).cloned()
        }
    }

    struct SignedAll;
    impl FileVerifier for SignedAll {
        fn verify(&self, _p: &str) -> Option<bool> {
            Some(true)
        }
    }

    /// A minimal version-resource `String` entry for OriginalFilename.
    fn version_string(value: &str) -> Vec<u8> {
        let key = utf16z("OriginalFilename");
        let val = utf16z(value);
        let mut v = Vec::new();
        v.extend_from_slice(&[0u8; 3]); // unaligned junk before the struct
        let header_at = v.len();
        v.extend_from_slice(&0u16.to_le_bytes()); // wLength (unused by the parser)
        v.extend_from_slice(&((val.len() / 2) as u16).to_le_bytes()); // wValueLength
        v.extend_from_slice(&1u16.to_le_bytes()); // wType = text
        v.extend_from_slice(&key);
        while (v.len() - header_at) % 4 != 0 {
            v.push(0);
        }
        v.extend_from_slice(&val);
        v
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 21, 0, 0, 0).unwrap()
    }

    #[test]
    fn original_filename_reads_the_version_string() {
        let mut bytes = b"MZ....".to_vec();
        bytes.extend(version_string("cmd.exe"));
        bytes.extend_from_slice(b"tail");
        assert_eq!(original_filename(&bytes).as_deref(), Some("cmd.exe"));
        assert_eq!(original_filename(b"MZ no resource"), None);
        // Truncated right after the key: no panic, no value.
        let mut cut = version_string("sethc.exe");
        cut.truncate(cut.len() - 20);
        assert_eq!(original_filename(&cut), None);
    }

    #[test]
    fn empty_host_reads_defaults_and_absent_values_as_off() {
        let mut h = FakeHost::default();
        h.audit = Some(vec![AuditSetting::default(); 5]);
        let (p, errs) = snapshot(&h, &SignedAll, now());
        assert_eq!(p.collected_at, Some(now()));
        assert_eq!(p.audit_process_creation, Some(false));
        assert_eq!(p.cmdline_in_4688, Some(false));
        assert_eq!(p.ps_scriptblock, Some(false));
        assert_eq!(p.sysmon_present, Some(false));
        assert_eq!(p.sysmon_channel, Some(false));
        assert_eq!(p.defender_policy, DefenderPolicy::default());
        assert!(p.defender_exclusions.is_empty() && p.exclusions_unreadable.is_empty());
        assert_eq!(p.accessibility_binaries.len(), ACCESSIBILITY_BINARIES.len());
        assert!(p.accessibility_binaries.iter().all(|a| !a.exists));
        // Only the unreadable Tasks folder is reported (TaskCache root absent => nothing).
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn logging_and_defender_values_are_read() {
        let mut h = FakeHost::default();
        h.audit = Some(vec![
            AuditSetting {
                success: true,
                failure: false,
            },
            AuditSetting {
                success: false,
                failure: true,
            },
            AuditSetting::default(),
            AuditSetting::default(),
            AuditSetting::default(),
        ]);
        h.key(
            AUDIT_SYSTEM_POLICY,
            &[("ProcessCreationIncludeCmdLine_Enabled", RegVal::Dword(1))],
        )
        .key(
            PS_SCRIPTBLOCK,
            &[("EnableScriptBlockLogging", RegVal::Str("1".into()))],
        )
        .key(r"SYSTEM\CurrentControlSet\Services\Sysmon64", &[])
        .key(DEFENDER_POLICY, &[("DisableAntiSpyware", RegVal::Dword(1))])
        .key(
            DEFENDER_POLICY_RTP,
            &[("DisableRealtimeMonitoring", RegVal::Dword(1))],
        )
        .key(DEFENDER_FEATURES, &[("TamperProtection", RegVal::Dword(4))]);
        let (p, _) = snapshot(&h, &SignedAll, now());
        assert_eq!(p.audit_process_creation, Some(true));
        assert_eq!(p.audit_logon, Some(true));
        assert_eq!(p.audit_other_object_access, Some(false));
        assert_eq!(p.cmdline_in_4688, Some(true));
        assert_eq!(p.ps_scriptblock, Some(true));
        assert_eq!(p.ps_module_logging, Some(false));
        assert_eq!(p.sysmon_present, Some(true));
        assert_eq!(p.defender_policy.disable_antispyware, Some(1));
        assert_eq!(p.defender_policy.disable_realtime_monitoring, Some(1));
        assert_eq!(p.defender_policy.disable_behavior_monitoring, None);
        assert_eq!(p.tamper_protection, Some(4));
    }

    #[test]
    fn unreadable_locations_are_unknown_and_reported() {
        let mut h = FakeHost::default(); // audit query fails
        h.denied.insert(lc(PS_SCRIPTBLOCK));
        h.denied
            .insert(lc(r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"));
        h.denied
            .insert(lc(r"SYSTEM\CurrentControlSet\Services\SysmonDrv"));
        let (p, errs) = snapshot(&h, &SignedAll, now());
        assert_eq!(p.audit_process_creation, None);
        assert_eq!(p.ps_scriptblock, None);
        assert_eq!(p.sysmon_present, None, "one unreadable, none present");
        assert_eq!(
            p.exclusions_unreadable,
            vec![r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths".to_string()]
        );
        assert!(errs.iter().any(|e| e.starts_with("audit policy:")));
        assert!(errs
            .iter()
            .any(|e| e.contains(r"Exclusions\Paths") && e.contains("not treated as empty")));
        assert!(errs.iter().any(|e| e.contains("ScriptBlockLogging")));
    }

    #[test]
    fn exclusions_from_both_keys_are_listed() {
        let mut h = FakeHost::default();
        h.key(
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            &[(r"C:\Users\Public", RegVal::Dword(0))],
        )
        .key(
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
            &[("ps1", RegVal::Str("0".into()))],
        );
        let (p, _) = snapshot(&h, &SignedAll, now());
        assert_eq!(p.defender_exclusions.len(), 2);
        let path = &p.defender_exclusions[0];
        assert_eq!(
            (path.kind, path.value.as_str(), path.policy),
            (ExclusionKind::Path, r"C:\Users\Public", false)
        );
        let ext = &p.defender_exclusions[1];
        assert_eq!((ext.kind, ext.policy), (ExclusionKind::Extension, true));
        assert!(ext.key.starts_with(r"HKLM\SOFTWARE\Policies\"));
    }

    #[test]
    fn task_cache_records_sd_and_task_file() {
        let mut h = FakeHost::default();
        h.env.insert("SystemRoot".into(), r"C:\Windows".into());
        let tree = TASKCACHE_TREE;
        h.key(&format!(r"{tree}\Microsoft"), &[("SD", RegVal::Other)])
            .key(
                &format!(r"{tree}\Microsoft\Good"),
                &[("Id", RegVal::Str("{1}".into())), ("SD", RegVal::Other)],
            )
            .key(
                &format!(r"{tree}\Hidden"),
                &[("Id", RegVal::Str("{2}".into()))],
            );
        h.dir(r"C:\Windows\System32\Tasks", &[])
            .file(r"C:\Windows\System32\Tasks\Microsoft\Good", vec![]);
        h.audit = Some(vec![AuditSetting::default(); 5]);
        let (p, errs) = snapshot(&h, &SignedAll, now());
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(p.task_cache.len(), 2, "folders without Id are not tasks");
        let hidden = p.task_cache.iter().find(|t| t.path == r"\Hidden").unwrap();
        assert!(!hidden.sd_present);
        assert_eq!(hidden.file_present, Some(false));
        assert_eq!(hidden.id.as_deref(), Some("{2}"));
        let good = p
            .task_cache
            .iter()
            .find(|t| t.path == r"\Microsoft\Good")
            .unwrap();
        assert!(good.sd_present);
        assert_eq!(good.file_present, Some(true));
        assert!(good.key.ends_with(r"TaskCache\Tree\Microsoft\Good"));
    }

    #[test]
    fn task_file_presence_is_unknown_when_tasks_folder_unreadable() {
        let mut h = FakeHost::default();
        h.key(
            &format!(r"{TASKCACHE_TREE}\T"),
            &[("Id", RegVal::Str("{3}".into())), ("SD", RegVal::Other)],
        );
        let (p, errs) = snapshot(&h, &SignedAll, now());
        assert_eq!(p.task_cache[0].file_present, None);
        assert!(errs.iter().any(|e| e.contains(r"System32\Tasks")));
    }

    #[test]
    fn accessibility_binary_original_filename_and_signature() {
        let mut h = FakeHost::default();
        h.env.insert("SystemRoot".into(), r"C:\Windows".into());
        h.file(r"C:\Windows\System32\sethc.exe", version_string("cmd.exe"));
        let (p, _) = snapshot(&h, &SignedAll, now());
        let s = &p.accessibility_binaries[0];
        assert_eq!(s.name, "sethc.exe");
        assert!(s.exists);
        assert_eq!(s.original_filename.as_deref(), Some("cmd.exe"));
        assert_eq!(s.signed, Some(true));
        assert_eq!(s.sha256.as_deref(), Some("ab"));
        assert!(!p.accessibility_binaries[1].exists);
    }

    #[test]
    fn program_dirs_cover_install_roots_and_user_appdata() {
        let mut h = FakeHost::default();
        h.env.insert("SystemDrive".into(), "C:".into());
        h.env
            .insert("ProgramFiles".into(), r"C:\Program Files".into());
        h.dir(r"C:\Program Files", &["AnyDesk", "Common Files"])
            .dir(r"C:\ProgramData", &["chocolatey"])
            .dir(r"C:\Users", &["alice", "Public", "Default"])
            .dir(r"C:\Users\alice\AppData\Roaming", &["AnyDesk"])
            .dir(r"C:\Users\Public\AppData\Roaming", &["Hidden"]);
        let (p, _) = snapshot(&h, &SignedAll, now());
        let paths: Vec<&str> = p.program_dirs.iter().map(|d| d.path.as_str()).collect();
        assert!(paths.contains(&r"C:\Program Files\AnyDesk"), "{paths:?}");
        assert!(paths.contains(&r"C:\ProgramData\chocolatey"), "{paths:?}");
        assert!(
            paths.contains(&r"C:\Users\alice\AppData\Roaming\AnyDesk"),
            "{paths:?}"
        );
        assert!(!paths.iter().any(|p| p.contains("Public")), "{paths:?}");
    }

    #[test]
    fn collector_emits_one_posture_record_and_a_source_entry() {
        let c = PostureCollector::default();
        let cfg = cairn_core::Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let recs = c.collect(&ctx).unwrap();
        assert_eq!(recs.len(), 1);
        assert!(matches!(recs[0], Record::Posture(_)));
        let src = c.sources();
        assert_eq!(src.len(), 1);
        assert_eq!(src[0].artifact, "posture");
        #[cfg(not(windows))]
        assert_eq!(src[0].errors, vec!["posture: unsupported platform"]);
    }
}
