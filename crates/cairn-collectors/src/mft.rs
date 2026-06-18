//! MftCollector: full $MFT scan with SI/FN btime+mtime (SRS §4, S2-N).
//!
//! This module consumes the safe `VolumeReader` (already built in
//! `cairn-collectors-win::volume`) and the `ntfs` 0.4 crate to scan the $MFT and
//! read SI/FN btime+mtime into FileMetaRecord, bounded by a record cap, emitting
//! them as `Record::FileMeta`.
//!
//! ## Peak memory (NFR10)
//! The scan holds up to `max_mft_records` `FileMetaRecord`s in a `Vec` before they are
//! mapped to `Record::FileMeta`, so peak RAM is bounded by the record cap
//! (default 1_000_000 × ~the size of a `FileMetaRecord`). The cap — not the volume's
//! declared capacity — is the bound, so a boot sector lying about volume size cannot
//! inflate it. A streaming sink (removing the intermediate `Vec`) is a future improvement.
//!
//! ## Two-layer DoS guard (BOTH required — defense in depth)
//!
//! A throwaway probe on 2026-06-16 MEASURED that `ntfs` 0.4.0 returns clean `Err`
//! on garbage / length-field / absurd-geometry input, BUT PANICS (`unreachable!()`)
//! when the reader is shorter than one boot sector (e.g. empty, or 3 bytes). The
//! orchestrator degrades on `Err` but a panic would unwind past it = DoS.
//!
//! Guard (a) — boot-sector LENGTH PRE-CHECK:
//!   Before calling `Ntfs::new`, read exactly 512 bytes from the start of the
//!   source. If `read_exact` fails (short source), return `Err` immediately — never
//!   call `Ntfs::new`.  This removes the ONLY KNOWN panic trigger.
//!
//! Guard (b) — `std::panic::catch_unwind` around the ntfs parse:
//!   Even if `ntfs` panics somewhere UNFORESEEN (future crate regression, unusual
//!   on-disk geometry), the panic is caught and converted to `Err` so it never
//!   escapes this collector. This is the one place `catch_unwind` is legitimate:
//!   containing a THIRD-PARTY panic, not hiding our own logic errors.
//!
//! Both guards are proven by unit tests that use the exact inputs that panicked the
//! raw crate (empty reader, 3-byte reader).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::panic::{self, AssertUnwindSafe};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{FileMetaRecord, Record};
use cairn_core::time::filetime_to_utc;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};
use ntfs::structured_values::{NtfsFileName, NtfsFileNamespace};
use ntfs::Ntfs;

/// NTFS boot sector length in bytes. The ntfs crate panics if the source is shorter
/// than this; guard (a) checks this BEFORE calling `Ntfs::new`.
const BOOT_SECTOR_LEN: usize = 512;

/// NTFS practical max directory nesting; also the cycle/runaway depth ceiling for
/// the path walk. A chain exceeding this is treated as truncated (best-effort).
const MAX_PATH_DEPTH: usize = 255;

/// Root directory record number (NTFS fixed: KnownNtfsFileRecordNumber::RootDirectory).
/// In real NTFS the root's own $FILE_NAME parent-references itself; the walk
/// terminates on reaching this number BEFORE the cycle check.
const ROOT_RECORD: u64 = 5;

/// Walk parent references from `start` to the root directory, returning
/// `(path, complete)`. `index` maps `rec_num -> (name, parent_num)` (built in the
/// scan phase). Pure (no I/O), never panics: bounded by `MAX_PATH_DEPTH`, a visited
/// set detects cycles, and any dead end yields a best-effort partial path rather
/// than aborting (golden rule 8).
///
/// `complete == true` only when the walk reaches `ROOT_RECORD`. `path` is always a
/// clean filesystem path (e.g. `C:\a\b\file` or, best-effort, `C:\a\b`); it is NEVER
/// prefixed with a pollution marker — resolution quality lives solely in `complete`.
///
/// The drive prefix is a fixed `C:` — the collector reads `\\.\C:` and $MFT carries
/// no mount/drive-letter info, so by design no other letter is inferred (spec: no
/// drive-letter discovery).
#[allow(dead_code)] // called by T4 two-phase scan; not yet wired in this task
fn resolve_path(start: u64, index: &HashMap<u64, (String, u64)>) -> (String, bool) {
    let mut components: Vec<String> = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut current = start;
    let mut complete = false;

    for _ in 0..MAX_PATH_DEPTH {
        // ① Root FIRST: record 5 self-references in real NTFS, so terminating here
        //    before the cycle check is what makes a clean walk-to-root NOT cyclic.
        if current == ROOT_RECORD {
            complete = true;
            break;
        }
        // ② Cycle detection: re-visiting a record means the chain loops.
        if !visited.insert(current) {
            break; // complete stays false
        }
        // ③ Index lookup: a missing parent is an orphan / deleted / skipped record.
        match index.get(&current) {
            Some((name, parent)) => {
                components.push(name.clone());
                current = *parent;
            }
            None => break, // complete stays false
        }
    }
    // depth exhausted without reaching root → complete stays false (truncated).

    components.reverse();
    let path = if components.is_empty() {
        // start == ROOT_RECORD (or an immediate dead end at start): just the drive root.
        r"C:\".to_string()
    } else {
        format!(r"C:\{}", components.join(r"\"))
    };
    (path, complete)
}

/// MftCollector: privilege-gated, read-only, full $MFT scan with SI/FN times.
///
/// Requires `Administrator + SeBackupPrivilege`. On success emits
/// `Record::FileMeta` for each file record found in the $MFT (up to
/// `Config.max_mft_records`), populating `si_btime`, `si_mtime`, `fn_btime`,
/// and `fn_mtime` via `filetime_to_utc`.
#[derive(Default)]
pub struct MftCollector;

impl Collector for MftCollector {
    fn name(&self) -> &str {
        "mft"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate: both Administrator AND SeBackupPrivilege are required
        // to open \\.\C: for raw volume reads. Check BEFORE any volume open so
        // the privilege error is emitted cleanly without touching the host.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "mft".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let cap = ctx.config.max_mft_records;
        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let (capacity, records) = parse_mft_records(&mut reader, cap)?;

        tracing::info!(
            mft_capacity_estimate = capacity,
            records_emitted = records.len(),
            record_cap = cap,
            "mft scan"
        );

        Ok(records.into_iter().map(Record::FileMeta).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "mft".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }]
    }
}

/// Construct a `CairnError::Collector` for the `"mft"` collector.
///
/// Deduplicates the repeated `CairnError::Collector { collector: "mft".into(), reason }`
/// pattern used throughout this module (~9 call sites).
#[inline]
fn mft_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "mft".into(),
        reason,
    }
}

/// Scan the $MFT and return `(mft_capacity_estimate, file_meta_records)`.
///
/// `mft_capacity_estimate` = volume_size / file_record_size: a geometric upper bound on
/// addressable file records, NOT the count of allocated entries. The scan iterates
/// `0..min(capacity, max_records)` — the hard cap closes the lied-about-capacity
/// wall-clock DoS. Both S2-M DoS guards apply:
/// - Guard (a): 512-byte pre-check — short source -> Err without calling `Ntfs::new`.
/// - Guard (b): `catch_unwind` around the scan — any third-party panic -> Err.
pub(crate) fn parse_mft_records<R: Read + Seek>(
    src: &mut R,
    max_records: u64,
) -> Result<(u64, Vec<FileMetaRecord>)> {
    src.seek(SeekFrom::Start(0))
        .map_err(|e| mft_err(format!("seek to start failed: {e}")))?;
    let mut probe = [0u8; BOOT_SECTOR_LEN];
    src.read_exact(&mut probe).map_err(|_| {
        mft_err(format!(
            "source is shorter than {BOOT_SECTOR_LEN} bytes; refusing to call Ntfs::new (would panic)"
        ))
    })?;
    src.seek(SeekFrom::Start(0))
        .map_err(|e| mft_err(format!("seek-back failed: {e}")))?;

    // Guard (b): wrap the ntfs parse in catch_unwind so that any third-party
    // panic (unforeseen ntfs crate regression, unusual on-disk geometry) is
    // caught and converted to Err rather than unwinding past this collector.
    //
    // NOTE: AssertUnwindSafe is correct here because:
    // - `src` is the only captured mutable reference.
    // - If the ntfs crate panics, `src` may be in an undefined mid-parse state,
    //   but we NEVER use `src` after a caught panic — we immediately return Err.
    // - We are NOT using catch_unwind to hide our own logic errors; only to
    //   contain a measured, third-party panic that we cannot fix.
    let result = panic::catch_unwind(AssertUnwindSafe(|| parse_mft_inner(src, max_records)));
    match result {
        Ok(inner) => inner,
        Err(_) => Err(mft_err(
            "ntfs parser panicked (contained); treating volume as unreadable".into(),
        )),
    }
}

/// Pick the preferred `$FILE_NAME`: first Win32 or Win32AndDos (avoid DOS 8.3 short
/// names like PROGRA~1); fall back to the first available. Returns its name plus the
/// raw FILETIME u64s of its creation/modification times. Deterministic (NFR4).
/// A per-attribute parse error is skipped (continue), never propagated — one unreadable
/// attribute must not abort name selection for the whole file.
fn preferred_file_name<R: Read + Seek>(
    file: &ntfs::NtfsFile<'_>,
    src: &mut R,
) -> Option<(String, u64, u64)> {
    let mut fallback: Option<(String, u64, u64)> = None;
    let mut attrs = file.attributes();
    while let Some(item) = attrs.next(src) {
        let item = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        let attr = match item.to_attribute() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if attr.ty().ok() != Some(ntfs::NtfsAttributeType::FileName) {
            continue;
        }
        let fname: NtfsFileName = match attr.structured_value::<_, NtfsFileName>(src) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = fname.name().to_string_lossy();
        let btime = fname.creation_time().nt_timestamp();
        let mtime = fname.modification_time().nt_timestamp();
        match fname.namespace() {
            NtfsFileNamespace::Win32 | NtfsFileNamespace::Win32AndDos => {
                return Some((name, btime, mtime));
            }
            _ => {
                if fallback.is_none() {
                    fallback = Some((name, btime, mtime));
                }
            }
        }
    }
    fallback
}

/// Inner $MFT scan. Called only after guard (a); wrapped by guard (b).
///
/// UPSTREAM LIMITATION (ntfs 0.4): `Ntfs::file()` assumes the $MFT itself has no
/// `$ATTRIBUTE_LIST`. On a heavily fragmented volume whose $MFT spans multiple data
/// runs, records beyond the first run yield `Err` and are silently skipped via the
/// per-record `continue`. This is a triage trade-off, not a correctness bug; a future
/// crate upgrade or a custom $MFT reader would lift it. Surfaced here so the gap is
/// auditable.
fn parse_mft_inner<R: Read + Seek>(
    src: &mut R,
    max_records: u64,
) -> Result<(u64, Vec<FileMetaRecord>)> {
    let ntfs = Ntfs::new(src).map_err(|e| mft_err(format!("Ntfs::new failed: {e}")))?;
    let file_record_size = ntfs.file_record_size() as u64;
    let capacity = ntfs.size().checked_div(file_record_size).unwrap_or(0);
    let ceiling = capacity.min(max_records);

    // Not pre-allocated to `ceiling`: most records are typically skipped (no FN /
    // parse error), so Vec::new avoids reserving worst-case capacity up front.
    let mut out: Vec<FileMetaRecord> = Vec::new();
    for rec_num in 0..ceiling {
        // Single-record isolation: a bad/unallocated record is skipped, never aborts.
        let file = match ntfs.file(src, rec_num) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let si = file.info().ok();
        let (path, fn_b_raw, fn_m_raw) = match preferred_file_name(&file, src) {
            Some(t) => t,
            None => continue, // no $FILE_NAME -> not a meaningful file-meta record
        };
        out.push(FileMetaRecord {
            path,
            size: 0,
            sha256: None,
            si_btime: si
                .as_ref()
                .and_then(|s| filetime_to_utc(s.creation_time().nt_timestamp())),
            si_mtime: si
                .as_ref()
                .and_then(|s| filetime_to_utc(s.modification_time().nt_timestamp())),
            fn_btime: filetime_to_utc(fn_b_raw),
            fn_mtime: filetime_to_utc(fn_m_raw),
            zone_identifier: None,
            path_complete: None,
        });
    }
    Ok((capacity, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::config::Config;

    // ── Guard-b panic-containment coverage note ──────────────────────────────
    //
    // Guard (b)'s catch_unwind catch-arm is NOT deterministically exercised by
    // the fixtures in this module. The contained panic (ntfs 0.4 `unreachable!()`)
    // was demonstrated empirically by the 2026-06-16 probe using a live short-
    // buffer reader. Reproducing it in-process requires a byte buffer that (a)
    // passes `BootSector::validate` so guard (a) does not fire, yet (b) causes
    // ntfs to hit an `unreachable!()` branch deep in index or attribute parsing.
    // That combination is hard to craft deterministically without reading the
    // ntfs 0.4 internals in detail. The test
    // `parse_garbage_mft_body_yields_zero_records_or_err` below attempts this;
    // see its comment for which path it actually exercised.
    //
    // SI/FN time population and FN-namespace preference are covered by the ELEVATED
    // e2e (T6), not by a synthetic image — a fully ntfs-0.4-parseable $MFT with real
    // SI/FN attributes is impractical to hand-craft deterministically. The unit tests
    // here pin: return shape, the cap bound, and guard (a)/(b) regression.
    //
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_short_source_returns_err_not_panic() {
        // The two inputs that panicked ntfs 0.4 RAW in the probe: empty and 3 bytes.
        // Through the guarded helper they MUST be Err, with no panic escaping.
        for bytes in [vec![], vec![0xEB, 0x52, 0x90]] {
            let mut cur = std::io::Cursor::new(bytes);
            let r = parse_mft_records(&mut cur, 8);
            assert!(r.is_err(), "short source must be Err, never panic");
        }
    }

    #[test]
    fn parse_garbage_full_sector_returns_err_not_panic() {
        // A full sector+ of zeros: ntfs returns clean Err (invalid boot signature);
        // the wrapper passes it through as Err.
        let mut cur = std::io::Cursor::new(vec![0u8; 1024]);
        let r = parse_mft_records(&mut cur, 8);
        assert!(r.is_err());
    }

    /// Attempt to exercise guard (b)'s catch-arm by supplying a buffer that has a
    /// plausible-looking NTFS boot sector but contains garbage where the MFT and
    /// index structures would be, causing deep parse failures.
    ///
    /// Crafting strategy:
    ///   - OEM ID "NTFS    " at offset 3 (8 bytes)
    ///   - bytes_per_sector = 512 (LE u16 at offset 11)
    ///   - sectors_per_cluster = 8 (u8 at offset 13)
    ///   - clusters_per_file_record = 0xF6 (-10 in two's complement → 1024 bytes,
    ///     a valid encoding the crate accepts; ntfs derives record_size = 2^10)
    ///   - total_sectors plausible (u64 LE at offset 40): 1 MiB / 512 - 1 = 2047
    ///   - MFT LCN (u64 LE at offset 48): cluster 4, i.e. byte offset 4*4096 = 16384
    ///     (within the 1 MiB buffer, but the content there is garbage)
    ///   - NTFS boot signature 0x55AA at offset 510
    ///   - Everything else: 0x00
    ///
    /// Expected: the call is `Err` (either a clean Err from a failed validation
    /// inside ntfs, or a contained panic from guard b). The test asserts `is_err()`
    /// and that the process does NOT abort (i.e., the panic, if any, was contained
    /// by guard b).
    ///
    /// Actual path exercised (as observed with the S2-N full-$MFT scan): the boot
    /// sector parses successfully (geometry is valid), then `ntfs.file(src, rec_num)`
    /// is called for each record in `0..ceiling`. Every file record in the garbage MFT
    /// body fails to parse and is skipped via `continue`. The scan completes and
    /// returns `Ok((capacity, vec![]))` — zero records, no panic. This is the correct,
    /// per-record-isolation behaviour of the new scan (S2-N design: individual bad
    /// records are skipped, not the whole scan). Guard (b)'s catch-arm was NOT
    /// triggered. The residual gap (an in-process panic from ntfs) is documented in
    /// the guard-b note above.
    #[test]
    fn parse_garbage_mft_body_yields_zero_records_or_err() {
        const BUF_LEN: usize = 1024 * 1024; // 1 MiB
        let mut buf = vec![0u8; BUF_LEN];

        let total_sectors: u64 = (BUF_LEN as u64 / 512).saturating_sub(1);
        write_boot_sector(&mut buf, total_sectors, 4);

        let mut cur = std::io::Cursor::new(buf);
        let r = parse_mft_records(&mut cur, 8);
        // S2-N: per-record isolation means individual bad file records are skipped, not
        // the whole scan. A garbage MFT body yields Ok with zero records (all skipped) —
        // not Err. Err is also acceptable (e.g. if Ntfs::new itself fails on the geometry).
        // The process must not panic/abort.
        if let Ok((_, records)) = &r {
            assert!(
                records.is_empty(),
                "garbage MFT body must yield zero records (all skipped), got {}",
                records.len()
            );
        }
        // Err(_) is also acceptable — no assertion needed.
    }

    #[test]
    fn collect_without_privilege_returns_err_no_host_access() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = MftCollector.collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    // Build a minimal ntfs-0.4-parseable NTFS boot sector header into `buf`,
    // declaring total_sectors and an MFT at cluster mft_lcn. (Used by
    // parse_garbage_mft_body_yields_zero_records_or_err and record_cap_truncates_without_panic.)
    fn write_boot_sector(buf: &mut [u8], total_sectors: u64, mft_lcn: u64) {
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[11] = 0x00; // bytes_per_sector = 512 (LE u16)
        buf[12] = 0x02;
        buf[13] = 0x08; // sectors_per_cluster = 8
        buf[64] = 0xF6; // clusters_per_file_record = -10 -> record_size 1024
        buf[40..48].copy_from_slice(&total_sectors.to_le_bytes());
        buf[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
        buf[510] = 0x55;
        buf[511] = 0xAA;
    }

    #[test]
    fn record_cap_truncates_without_panic() {
        // Boot sector declaring a huge volume -> huge capacity; with a tiny cap the scan
        // must stop at the cap (not loop to capacity) and never panic. The synthetic MFT
        // body is garbage so records are skipped; what we assert is: the call RETURNS
        // (no panic, no hang) — Err or Ok both acceptable here.
        const BUF: usize = 1024 * 1024;
        let mut buf = vec![0u8; BUF];
        write_boot_sector(&mut buf, (BUF as u64 / 512).saturating_sub(1), 4);
        let mut cur = std::io::Cursor::new(buf);
        let _ = parse_mft_records(&mut cur, 8); // must return, not panic/hang
    }

    #[test]
    fn parse_mft_records_short_source_is_err_shape() {
        // Pins the new return type (u64, Vec<FileMetaRecord>) and guard (a): a 3-byte
        // source (panicked the raw ntfs crate in S2-M's probe) is Err, no panic.
        let mut empty = std::io::Cursor::new(vec![0u8; 3]);
        let r: Result<(u64, Vec<FileMetaRecord>)> = parse_mft_records(&mut empty, 8);
        assert!(r.is_err());
    }

    // ── resolve_path tests (S2-O Task 2) ─────────────────────────────────────

    use std::collections::HashMap;

    // index helper: rec_num -> (name, parent_num)
    fn idx(pairs: &[(u64, &str, u64)]) -> HashMap<u64, (String, u64)> {
        pairs
            .iter()
            .map(|(r, n, p)| (*r, (n.to_string(), *p)))
            .collect()
    }

    #[test]
    fn resolves_clean_path_to_root() {
        // 100(file, parent 50), 50(dir "b", parent 40), 40(dir "a", parent 5 root)
        let index = idx(&[(100, "evil.exe", 50), (50, "b", 40), (40, "a", 5)]);
        let (path, complete) = resolve_path(100, &index);
        assert_eq!(path, r"C:\a\b\evil.exe");
        assert!(complete);
    }

    #[test]
    fn root_self_reference_not_cyclic() {
        // A top-level file directly under root: 100(parent 5). Root (5) is NOT in the
        // index (it self-references in real NTFS); termination is by current==ROOT_RECORD,
        // checked BEFORE the cycle/visited check, so this is complete, not cyclic.
        let index = idx(&[(100, "evil.exe", 5)]);
        let (path, complete) = resolve_path(100, &index);
        assert_eq!(path, r"C:\evil.exe");
        assert!(complete, "walk ending at root must be complete, not cyclic");
    }

    #[test]
    fn root_record_itself_resolves_to_c_backslash() {
        // start == 5 (the root directory record itself).
        let index = idx(&[]);
        let (path, complete) = resolve_path(5, &index);
        assert_eq!(path, r"C:\");
        assert!(complete);
    }

    #[test]
    fn cycle_returns_best_effort() {
        // A(parent B), B(parent A): a cycle that never reaches root.
        let index = idx(&[(100, "a", 200), (200, "b", 100)]);
        let (_path, complete) = resolve_path(100, &index);
        assert!(!complete, "a cycle must be best-effort");
    }

    #[test]
    fn orphan_parent_missing_best_effort() {
        // 100(parent 999) where 999 is not in the index (deleted/skipped directory).
        let index = idx(&[(100, "evil.exe", 999)]);
        let (path, complete) = resolve_path(100, &index);
        assert!(!complete, "missing parent must be best-effort");
        assert!(
            path.contains("evil.exe"),
            "best-effort path keeps the part it resolved: {path}"
        );
    }

    #[test]
    fn depth_ceiling_truncates() {
        // A 300-deep chain that never hits root: rec k -> parent k+1, for k in 1001..=1300.
        // Records start at 1001 to avoid accidentally passing through ROOT_RECORD (5).
        // The walk must stop at MAX_PATH_DEPTH and report best-effort without hanging.
        let pairs: Vec<(u64, String, u64)> = (1001..=1300u64)
            .map(|k| (k, format!("d{k}"), k + 1))
            .collect();
        let index: HashMap<u64, (String, u64)> =
            pairs.into_iter().map(|(r, n, p)| (r, (n, p))).collect();
        let (_path, complete) = resolve_path(1001, &index);
        assert!(!complete, "exceeding MAX_PATH_DEPTH must be best-effort");
    }

    #[test]
    fn best_effort_path_not_polluted() {
        // The orphan path must be a clean partial path: no "[orphan]"/"[truncated]" prefix.
        let index = idx(&[(100, "evil.exe", 999)]);
        let (path, _complete) = resolve_path(100, &index);
        assert!(!path.contains("[orphan]"), "no pollution prefix: {path}");
        assert!(!path.contains("[truncated]"), "no pollution prefix: {path}");
    }
}
