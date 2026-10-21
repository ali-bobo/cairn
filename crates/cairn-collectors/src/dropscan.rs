//! Drop-zone listing for credential-dump and ransomware-precursor triage.
//!
//! Three read-only parts, each best-effort (a failure is recorded in the manifest and
//! the other parts still run):
//!
//! 1. **Drop-zone files** ([`Record::FileListing`]): files with a dump or archive
//!    extension ([`EXTENSIONS`]) created or modified inside the `--since` window, in
//!    the folders attackers stage tools and loot in: every user's Desktop, Downloads
//!    and `AppData\Local\Temp`, `%SystemRoot%\Temp`, `C:\Users\Public`, the
//!    `C:\ProgramData` root and `C:\PerfLogs`. Metadata only (path, size, times); the
//!    only content read is the first 8 bytes, for the signature (`MDMP` minidump, zip,
//!    7z, rar). Depth is capped at [`MAX_DEPTH`] and the listing at [`MAX_ENTRIES`];
//!    symbolic links and junctions are not followed. LSASS is never opened: a dump
//!    that is already on disk is found by its name, size and signature.
//! 2. **WER LocalDumps for lsass.exe** ([`Record::RegValue`]): the presence of
//!    `HKLM\` [`WER_LSASS_LOCALDUMPS_KEY`] makes Windows Error Reporting write a full
//!    LSASS dump on the next crash.
//! 3. **Shadow copies** ([`Record::ShadowCopies`]): the `Win32_ShadowCopy` count
//!    (cairn-collectors-win `vss`), whether this is a client edition, and whether
//!    System Restore is on.
//!
//! Judging any of this is left to `cairn-heur` (`heur_cred_dump`, `heur_ransom`).

use crate::asep::{Hive, RegData, RegRead};
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{
    FileListingRecord, Record, RegValueRecord, ShadowCopyRecord, MAGIC_MINIDUMP,
    WER_LSASS_LOCALDUMPS_KEY,
};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;
use chrono::{DateTime, Utc};
use std::io::Read;
use std::path::{Path, PathBuf};

/// File extensions listed (lowercase, no dot): memory dumps and the archives they are
/// packed into for exfiltration.
pub const EXTENSIONS: &[&str] = &["dmp", "mdmp", "bin", "zip", "7z", "rar"];
/// Most files listed per run; the rest are dropped and the truncation recorded.
pub const MAX_ENTRIES: usize = 5_000;
/// Directory levels scanned in a zone (1 = only the zone's own files).
pub const MAX_DEPTH: usize = 3;
/// Directory entries examined per run, listed or not: bounds the cost of a huge Temp.
pub const MAX_VISITED: usize = 200_000;

/// `SourceEntry.method` of the listing.
pub const LISTING_METHOD: &str = "fs:metadata_listing+magic8";

/// A folder to list and how deep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropZone {
    pub path: String,
    /// Levels scanned: 1 = files directly in `path`.
    pub depth: usize,
}

/// The drop zones for these profile folders and environment, without duplicates
/// (case-insensitive). `SystemRoot` / `SystemDrive` / `ProgramData` fall back to the
/// `C:` defaults when unset.
pub fn drop_zones(env: impl Fn(&str) -> Option<String>, homes: &[String]) -> Vec<DropZone> {
    let trim = |s: String| s.trim_end_matches(['\\', '/']).to_string();
    let drive = env("SystemDrive").map(trim).unwrap_or_else(|| "C:".into());
    let root = env("SystemRoot")
        .or_else(|| env("windir"))
        .map(trim)
        .unwrap_or_else(|| format!(r"{drive}\Windows"));
    let program_data = env("ProgramData")
        .map(trim)
        .unwrap_or_else(|| format!(r"{drive}\ProgramData"));
    let mut zones: Vec<DropZone> = Vec::new();
    let mut add = |path: String, depth: usize| {
        if !zones.iter().any(|z| z.path.eq_ignore_ascii_case(&path)) {
            zones.push(DropZone { path, depth });
        }
    };
    for home in homes {
        let home = home.trim_end_matches(['\\', '/']);
        for rel in ["Desktop", "Downloads", r"AppData\Local\Temp"] {
            add(format!(r"{home}\{rel}"), MAX_DEPTH);
        }
    }
    add(format!(r"{root}\Temp"), MAX_DEPTH);
    add(format!(r"{drive}\Users\Public"), MAX_DEPTH);
    add(program_data, 1);
    add(format!(r"{drive}\PerfLogs"), MAX_DEPTH);
    zones
}

/// Profile folders of real users: the subfolders of the folder holding
/// `%USERPROFILE%` (normally `C:\Users`), minus the shared/template ones (Public is
/// its own zone).
fn user_profile_dirs() -> Vec<String> {
    let Some(root) = std::env::var("USERPROFILE")
        .ok()
        .and_then(|p| Path::new(&p).parent().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            !matches!(
                n.as_str(),
                "public" | "default" | "default user" | "all users"
            )
        })
        .map(|e| e.path().display().to_string())
        .collect();
    out.sort();
    out
}

/// True if the file name has one of [`EXTENSIONS`].
fn listed_extension(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| EXTENSIONS.iter().any(|e| ext.eq_ignore_ascii_case(e)))
}

/// Signature label of a file's first bytes: [`MAGIC_MINIDUMP`], `PK`, `7z`, `Rar!`,
/// else lowercase hex of what was read. None for an empty read.
pub fn magic_label(head: &[u8]) -> Option<String> {
    if head.is_empty() {
        return None;
    }
    let label = if head.starts_with(MAGIC_MINIDUMP.as_bytes()) {
        MAGIC_MINIDUMP.to_string()
    } else if head.starts_with(b"PK\x03\x04") {
        "PK".to_string()
    } else if head.starts_with(b"7z\xBC\xAF\x27\x1C") {
        "7z".to_string()
    } else if head.starts_with(b"Rar!") {
        "Rar!".to_string()
    } else {
        head.iter().map(|b| format!("{b:02x}")).collect()
    };
    Some(label)
}

/// The first 8 bytes of `path`, opened read-only. None if it cannot be read.
fn read_magic(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 8];
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    magic_label(&buf[..n])
}

/// What one zone's scan saw.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ZoneStats {
    pub listed: usize,
    pub unreadable_dirs: usize,
}

/// Limits shared by every zone of one run.
#[derive(Debug)]
pub struct Budget {
    pub max_entries: usize,
    pub max_visited: usize,
    listed: usize,
    visited: usize,
    /// Set once either limit was hit.
    pub truncated: bool,
}

impl Budget {
    pub fn new(max_entries: usize, max_visited: usize) -> Self {
        Budget {
            max_entries,
            max_visited,
            listed: 0,
            visited: 0,
            truncated: false,
        }
    }
}

/// List one zone (breadth-first, up to `zone.depth` levels), keeping files with a
/// listed extension whose creation or modification time is at or after `since`
/// (a file with neither time is kept). Never follows symbolic links or junctions.
pub fn scan_zone(
    zone: &DropZone,
    since: DateTime<Utc>,
    budget: &mut Budget,
    out: &mut Vec<FileListingRecord>,
) -> ZoneStats {
    let mut stats = ZoneStats::default();
    let mut queue: std::collections::VecDeque<(PathBuf, usize)> =
        std::collections::VecDeque::from([(PathBuf::from(&zone.path), 1)]);
    while let Some((dir, level)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            stats.unreadable_dirs += 1;
            continue;
        };
        for entry in entries.flatten() {
            if budget.visited >= budget.max_visited || budget.listed >= budget.max_entries {
                budget.truncated = true;
                return stats;
            }
            budget.visited += 1;
            // DirEntry::file_type does not follow links; on Windows a junction or
            // symlink reports is_symlink and is skipped.
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                if level < zone.depth {
                    queue.push_back((path, level + 1));
                }
                continue;
            }
            if !ft.is_file() || !listed_extension(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let modified = meta.modified().ok().map(DateTime::<Utc>::from);
            let created = meta.created().ok().map(DateTime::<Utc>::from);
            let newest = modified.max(created);
            if newest.is_some_and(|t| t < since) {
                continue;
            }
            out.push(FileListingRecord {
                path: path.display().to_string(),
                size: meta.len(),
                modified,
                magic: read_magic(&path),
                created,
            });
            budget.listed += 1;
            stats.listed += 1;
        }
    }
    stats
}

/// The WER LocalDumps entry for lsass.exe, if that key exists: one RegValue record
/// whose `data` lists the key's string values (e.g. `DumpFolder=C:\dumps`).
pub fn read_wer_lsass(reg: &dyn RegRead) -> Option<RegValueRecord> {
    let (values, last_write) = reg.values(Hive::Hklm, WER_LSASS_LOCALDUMPS_KEY)?;
    let data: Vec<String> = values
        .iter()
        .filter_map(|(n, d)| match d {
            RegData::Str(s) => Some(format!("{n}={s}")),
            _ => None,
        })
        .collect();
    Some(RegValueRecord {
        hive: "HKLM".into(),
        key: WER_LSASS_LOCALDUMPS_KEY.into(),
        value: String::new(),
        data: data.join("; "),
        last_write,
        mru_rank: None,
    })
}

/// Workstation edition marker of `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions`
/// `ProductType` (`ServerNT` / `LanmanNT` are servers / DCs).
const PRODUCT_OPTIONS_KEY: &str = r"SYSTEM\CurrentControlSet\Control\ProductOptions";

/// `ProductType` string, if readable.
fn product_type(reg: &dyn RegRead) -> Option<String> {
    let (values, _) = reg.values(Hive::Hklm, PRODUCT_OPTIONS_KEY)?;
    values.into_iter().find_map(|(n, d)| match d {
        RegData::Str(s) if n.eq_ignore_ascii_case("ProductType") => Some(s),
        _ => None,
    })
}

/// Combine what was read into the shadow-copy record. Pure.
///
/// - `client_os`: ProductType `WinNT`.
/// - `system_restore_enabled`: the `DisableSR` policy (1 = off) wins; otherwise
///   `SystemRestore\RPSessionInterval` (0 = System Protection off, non-zero = on).
///   Best knowledge of these values, not verified on a host here.
pub fn shadow_state(
    product_type: Option<&str>,
    rp_session_interval: Option<u32>,
    disable_sr_policy: Option<u32>,
    count: Option<u32>,
) -> ShadowCopyRecord {
    let system_restore_enabled = if disable_sr_policy == Some(1) {
        Some(false)
    } else {
        rp_session_interval.map(|v| v != 0)
    };
    ShadowCopyRecord {
        count,
        client_os: product_type.map(|p| p.trim().eq_ignore_ascii_case("WinNT")),
        system_restore_enabled,
    }
}

/// `SystemRestore\RPSessionInterval` and the `DisableSR` policy (REG_DWORD values,
/// which the [`RegRead`] seam does not carry).
#[cfg(windows)]
fn system_restore_dwords() -> (Option<u32>, Option<u32>) {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let read = |key: &str, value: &str| -> Option<u32> {
        hklm.open_subkey(key).ok()?.get_value::<u32, _>(value).ok()
    };
    (
        read(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore",
            "RPSessionInterval",
        ),
        read(
            r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore",
            "DisableSR",
        ),
    )
}

#[cfg(not(windows))]
fn system_restore_dwords() -> (Option<u32>, Option<u32>) {
    (None, None)
}

/// Empty registry stand-in off Windows.
#[cfg(not(windows))]
struct NoReg;
#[cfg(not(windows))]
impl RegRead for NoReg {
    fn values(&self, _hive: Hive, _key: &str) -> Option<crate::asep::KeyValues> {
        None
    }
    fn subkeys(&self, _hive: Hive, _key: &str) -> Vec<String> {
        Vec::new()
    }
}

/// List the zones under one budget; one SourceEntry per zone that exists.
pub fn scan_zones(
    zones: &[DropZone],
    since: DateTime<Utc>,
    budget: &mut Budget,
    sources: &mut Vec<SourceEntry>,
) -> Vec<FileListingRecord> {
    let mut out = Vec::new();
    for zone in zones {
        if !Path::new(&zone.path).is_dir() {
            continue;
        }
        let stats = scan_zone(zone, since, budget, &mut out);
        let mut errors = Vec::new();
        if stats.unreadable_dirs > 0 {
            errors.push(format!("{} folder(s) unreadable", stats.unreadable_dirs));
        }
        sources.push(SourceEntry {
            collector: String::new(),
            artifact: "dropscan:listing".into(),
            path: zone.path.clone(),
            method: LISTING_METHOD.into(),
            size: stats.listed as u64,
            sha256: String::new(),
            errors,
        });
        if budget.truncated {
            break;
        }
    }
    if budget.truncated {
        let msg = format!(
            "listing truncated at {} files / {} entries examined",
            budget.max_entries, budget.max_visited
        );
        tracing::warn!("dropscan: {msg}");
        if let Some(last) = sources.last_mut() {
            last.errors.push(msg);
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Drop-zone listing + WER LocalDumps + shadow-copy state (see module docs).
pub struct DropScanCollector {
    since: DateTime<Utc>,
    sources: std::sync::Mutex<Vec<SourceEntry>>,
}

impl DropScanCollector {
    /// Files created or modified at or after `since` are listed.
    pub fn new(since: DateTime<Utc>) -> Self {
        DropScanCollector {
            since,
            sources: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Collector for DropScanCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::DROPSCAN
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let mut sources = Vec::new();
        let zones = drop_zones(|v| std::env::var(v).ok(), &user_profile_dirs());
        let mut budget = Budget::new(MAX_ENTRIES, MAX_VISITED);
        let mut records: Vec<Record> = scan_zones(&zones, self.since, &mut budget, &mut sources)
            .into_iter()
            .map(Record::FileListing)
            .collect();

        #[cfg(windows)]
        let reg = crate::asep::WinReg;
        #[cfg(not(windows))]
        let reg = NoReg;
        let wer = read_wer_lsass(&reg);
        sources.push(SourceEntry {
            collector: String::new(),
            artifact: "dropscan:wer_localdumps".into(),
            path: format!(r"HKLM\{WER_LSASS_LOCALDUMPS_KEY}"),
            method: "registry".into(),
            size: u64::from(wer.is_some()),
            sha256: String::new(),
            errors: Vec::new(),
        });
        records.extend(wer.map(Record::RegValue));

        let (count, err) = match cairn_collectors_win::vss::shadow_copy_count() {
            Ok(n) => (Some(n), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let (rp, disable_sr) = system_restore_dwords();
        let state = shadow_state(product_type(&reg).as_deref(), rp, disable_sr, count);
        sources.push(SourceEntry {
            collector: String::new(),
            artifact: "dropscan:shadow_copies".into(),
            path: r"root\cimv2:Win32_ShadowCopy".into(),
            method: "wmi".into(),
            size: u64::from(count.unwrap_or(0)),
            sha256: String::new(),
            errors: err.into_iter().collect(),
        });
        records.push(Record::ShadowCopies(state));

        *self.sources.lock().unwrap_or_else(|e| e.into_inner()) = sources;
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asep::KeyValues;
    use std::collections::HashMap;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_dropscan_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn zone(p: &Path, depth: usize) -> DropZone {
        DropZone {
            path: p.display().to_string(),
            depth,
        }
    }

    #[test]
    fn zones_cover_every_profile_and_the_machine_folders() {
        let env = |v: &str| match v {
            "SystemDrive" => Some("C:".to_string()),
            "SystemRoot" => Some(r"C:\Windows\".to_string()),
            _ => None,
        };
        let homes = vec![r"C:\Users\alice".to_string(), r"C:\Users\ALICE".to_string()];
        let z = drop_zones(env, &homes);
        let paths: Vec<&str> = z.iter().map(|z| z.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                r"C:\Users\alice\Desktop",
                r"C:\Users\alice\Downloads",
                r"C:\Users\alice\AppData\Local\Temp",
                r"C:\Windows\Temp",
                r"C:\Users\Public",
                r"C:\ProgramData",
                r"C:\PerfLogs",
            ],
            "duplicate profile (case) collapsed"
        );
        assert_eq!(z[5].depth, 1, "ProgramData root only");
        assert!(z
            .iter()
            .filter(|z| z.path != r"C:\ProgramData")
            .all(|z| z.depth == MAX_DEPTH));
    }

    #[test]
    fn magic_labels() {
        assert_eq!(magic_label(b"MDMP\x93\xa7\0\0").as_deref(), Some("MDMP"));
        assert_eq!(magic_label(b"PK\x03\x04abcd").as_deref(), Some("PK"));
        assert_eq!(
            magic_label(b"7z\xBC\xAF\x27\x1C\0\x04").as_deref(),
            Some("7z")
        );
        assert_eq!(magic_label(b"Rar!\x1a\x07\x01\0").as_deref(), Some("Rar!"));
        assert_eq!(magic_label(b"\x01\x02").as_deref(), Some("0102"));
        assert_eq!(magic_label(b""), None);
    }

    #[test]
    fn scan_lists_dump_extensions_with_magic_and_respects_depth() {
        let d = tmp("depth");
        std::fs::write(d.join("lsass.DMP"), b"MDMP\x93\xa7\0\0rest-is-not-read").unwrap();
        std::fs::write(d.join("notes.txt"), b"x").unwrap();
        std::fs::create_dir_all(d.join("a/b/c")).unwrap();
        std::fs::write(d.join("a/loot.zip"), b"PK\x03\x04").unwrap();
        std::fs::write(d.join("a/b/deep.7z"), b"7z\xBC\xAF\x27\x1C").unwrap();
        std::fs::write(d.join("a/b/c/too_deep.rar"), b"Rar!").unwrap();
        let mut budget = Budget::new(MAX_ENTRIES, MAX_VISITED);
        let mut out = Vec::new();
        let stats = scan_zone(&zone(&d, 3), DateTime::UNIX_EPOCH, &mut budget, &mut out);
        let _ = std::fs::remove_dir_all(&d);
        let mut names: Vec<(String, Option<String>)> = out
            .iter()
            .map(|r| {
                (
                    Path::new(&r.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    r.magic.clone(),
                )
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("deep.7z".to_string(), Some("7z".to_string())),
                ("loot.zip".to_string(), Some("PK".to_string())),
                ("lsass.DMP".to_string(), Some("MDMP".to_string())),
            ]
        );
        assert_eq!(stats.listed, 3);
        assert!(!budget.truncated);
        let dump = out.iter().find(|r| r.path.ends_with("lsass.DMP")).unwrap();
        assert_eq!(dump.size, 24);
        assert!(dump.modified.is_some());
    }

    #[test]
    fn files_older_than_since_are_skipped() {
        let d = tmp("since");
        std::fs::write(d.join("old.dmp"), b"MDMP").unwrap();
        let mut out = Vec::new();
        let future = Utc::now() + chrono::Duration::days(1);
        scan_zone(&zone(&d, 1), future, &mut Budget::new(10, 100), &mut out);
        let _ = std::fs::remove_dir_all(&d);
        assert!(out.is_empty());
    }

    #[test]
    fn listing_cap_truncates_and_is_recorded() {
        let d = tmp("cap");
        for i in 0..5 {
            std::fs::write(d.join(format!("f{i}.bin")), b"\0").unwrap();
        }
        let mut budget = Budget::new(2, MAX_VISITED);
        let mut sources = Vec::new();
        let out = scan_zones(
            &[zone(&d, 1)],
            DateTime::UNIX_EPOCH,
            &mut budget,
            &mut sources,
        );
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(out.len(), 2);
        assert!(budget.truncated);
        assert_eq!(sources.len(), 1);
        assert!(sources[0].errors.iter().any(|e| e.contains("truncated")));
        assert_eq!(sources[0].method, LISTING_METHOD);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directories_are_not_followed() {
        let d = tmp("link");
        let outside = tmp("link_target");
        std::fs::write(outside.join("x.dmp"), b"MDMP").unwrap();
        std::os::unix::fs::symlink(&outside, d.join("j")).unwrap();
        let mut out = Vec::new();
        scan_zone(
            &zone(&d, 3),
            DateTime::UNIX_EPOCH,
            &mut Budget::new(10, 100),
            &mut out,
        );
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
        assert!(out.is_empty());
    }

    #[test]
    fn missing_zones_are_skipped_without_a_source_entry() {
        let mut sources = Vec::new();
        let out = scan_zones(
            &[DropZone {
                path: "/definitely/not/here".into(),
                depth: 3,
            }],
            DateTime::UNIX_EPOCH,
            &mut Budget::new(10, 100),
            &mut sources,
        );
        assert!(out.is_empty() && sources.is_empty());
    }

    struct FakeReg(HashMap<String, Vec<(String, RegData)>>);
    impl RegRead for FakeReg {
        fn values(&self, hive: Hive, key: &str) -> Option<KeyValues> {
            if hive != Hive::Hklm {
                return None;
            }
            self.0
                .get(&key.to_ascii_lowercase())
                .map(|v| (v.clone(), None))
        }
        fn subkeys(&self, _hive: Hive, _key: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn wer_lsass_key_presence_yields_one_record() {
        let empty = FakeReg(HashMap::new());
        assert!(read_wer_lsass(&empty).is_none());
        let reg = FakeReg(HashMap::from([(
            WER_LSASS_LOCALDUMPS_KEY.to_ascii_lowercase(),
            vec![
                ("DumpFolder".to_string(), RegData::Str(r"C:\tmp".into())),
                ("DumpType".to_string(), RegData::Other),
            ],
        )]));
        let r = read_wer_lsass(&reg).unwrap();
        assert_eq!(r.hive, "HKLM");
        assert_eq!(r.key, WER_LSASS_LOCALDUMPS_KEY);
        assert_eq!(r.data, r"DumpFolder=C:\tmp");
    }

    #[test]
    fn product_type_and_shadow_state() {
        let reg = FakeReg(HashMap::from([(
            PRODUCT_OPTIONS_KEY.to_ascii_lowercase(),
            vec![("ProductType".to_string(), RegData::Str("WinNT".into()))],
        )]));
        assert_eq!(product_type(&reg).as_deref(), Some("WinNT"));
        let s = shadow_state(Some("WinNT"), Some(1), None, Some(0));
        assert_eq!(
            (s.count, s.client_os, s.system_restore_enabled),
            (Some(0), Some(true), Some(true))
        );
        let s = shadow_state(Some("ServerNT"), Some(1), Some(1), None);
        assert_eq!(
            (s.count, s.client_os, s.system_restore_enabled),
            (None, Some(false), Some(false)),
            "DisableSR policy wins"
        );
        let s = shadow_state(None, Some(0), None, Some(3));
        assert_eq!((s.client_os, s.system_restore_enabled), (None, Some(false)));
    }

    /// Off Windows: no zones exist, no registry, shadow count is an error recorded in
    /// the manifest; still Ok with exactly one ShadowCopies record of unknowns.
    #[cfg(not(windows))]
    #[test]
    fn collect_off_windows_degrades_gracefully() {
        let cfg = cairn_core::Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let c = DropScanCollector::new(Utc::now());
        let recs = c.collect(&ctx).unwrap();
        let shadows: Vec<&ShadowCopyRecord> = recs
            .iter()
            .filter_map(|r| match r {
                Record::ShadowCopies(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(shadows.len(), 1);
        assert_eq!(shadows[0].count, None);
        let src = c.sources();
        let vss = src
            .iter()
            .find(|s| s.artifact == "dropscan:shadow_copies")
            .unwrap();
        assert!(!vss.errors.is_empty());
    }
}
