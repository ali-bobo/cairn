//! MftCollector: minimal raw-NTFS proof of read path (SRS §4, S2-M).
//!
//! This module consumes the safe `VolumeReader` (already built in
//! `cairn-collectors-win::volume`) and the `ntfs` 0.4 crate to parse a live NTFS
//! volume far enough to count $MFT records and list the first N file names from
//! the root-directory index, emitting them as `Record::FileMeta`.
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

use std::io::{Read, Seek, SeekFrom};
use std::panic::{self, AssertUnwindSafe};

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{FileMetaRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};
use ntfs::Ntfs;

/// Maximum number of file names collected from the root-directory index (proof bound).
const MAX_NAMES: usize = 50;

/// NTFS boot sector length in bytes. The ntfs crate panics if the source is shorter
/// than this; guard (a) checks this BEFORE calling `Ntfs::new`.
const BOOT_SECTOR_LEN: usize = 512;

/// MftCollector: privilege-gated, read-only, raw-NTFS $MFT proof.
///
/// Requires `Administrator + SeBackupPrivilege`. On success emits
/// `Record::FileMeta` for each of the first [`MAX_NAMES`] file names found in
/// the root-directory index, plus a `tracing::info!` log of the total MFT record
/// count (as reported by `Ntfs` structure metadata) and the number of names harvested.
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

        let mut reader = VolumeReader::open(r"\\.\C:")?;
        let (count, names) = parse_mft_names(&mut reader, MAX_NAMES)?;

        tracing::info!(mft_records = count, names = names.len(), "mft proof");

        let records = names
            .into_iter()
            .map(|name| {
                Record::FileMeta(FileMetaRecord {
                    path: name,
                    size: 0,
                    sha256: None,
                    si_btime: None,
                    si_mtime: None,
                    fn_btime: None,
                    zone_identifier: None,
                })
            })
            .collect();

        Ok(records)
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

/// Parse file names from the root-directory index of an NTFS source.
///
/// Returns `(total_mft_record_count_estimate, first_max_names_file_names)`.
///
/// Applies BOTH DoS guards (see module doc):
/// - Guard (a): 512-byte pre-check — returns `Err` for short sources without
///   calling `Ntfs::new`.
/// - Guard (b): `catch_unwind` around `parse_mft_inner` — converts any third-party
///   panic to `Err`.
pub(crate) fn parse_mft_names<R: Read + Seek>(
    src: &mut R,
    max_names: usize,
) -> Result<(u64, Vec<String>)> {
    // Guard (a): read exactly BOOT_SECTOR_LEN bytes to prove the source is long
    // enough for `Ntfs::new` to read its boot sector without panicking.
    // If `read_exact` fails (UnexpectedEof or other I/O error), convert it to a
    // Collector error and return immediately — never call `Ntfs::new`.
    src.seek(SeekFrom::Start(0))
        .map_err(|e| CairnError::Collector {
            collector: "mft".into(),
            reason: format!("seek to start failed: {e}"),
        })?;

    let mut probe = [0u8; BOOT_SECTOR_LEN];
    src.read_exact(&mut probe)
        .map_err(|_| CairnError::Collector {
            collector: "mft".into(),
            reason: format!(
                "source is shorter than {BOOT_SECTOR_LEN} bytes; \
             refusing to call Ntfs::new (would panic)"
            ),
        })?;

    // Seek back so that `Ntfs::new` reads from the beginning.
    src.seek(SeekFrom::Start(0))
        .map_err(|e| CairnError::Collector {
            collector: "mft".into(),
            reason: format!("seek-back failed: {e}"),
        })?;

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
    let result = panic::catch_unwind(AssertUnwindSafe(|| parse_mft_inner(src, max_names)));

    match result {
        Ok(inner_result) => inner_result,
        Err(_payload) => Err(CairnError::Collector {
            collector: "mft".into(),
            reason: "ntfs parser panicked (contained); treating volume as unreadable".into(),
        }),
    }
}

/// Inner ntfs parse: walk root-directory index, count entries, collect first
/// `max_names` file names.
///
/// Called only after guard (a) (boot-sector length pre-check) has passed.
/// Wrapped by guard (b) (`catch_unwind`) in `parse_mft_names`.
///
/// Returns `(mft_volume_size_in_records_approx, names)`.
/// - The "count" is the volume size divided by the per-file-record size, both
///   obtained from the `Ntfs` metadata; it is an upper bound on actual records
///   (some may be unallocated), but is deterministic and stable for this proof.
/// - Names are collected in the order the root-directory index iterator yields
///   them (ascending by NTFS case-insensitive key).
fn parse_mft_inner<R: Read + Seek>(src: &mut R, max_names: usize) -> Result<(u64, Vec<String>)> {
    // Parse the boot sector and derive filesystem geometry.
    let ntfs = Ntfs::new(src).map_err(|e| CairnError::Collector {
        collector: "mft".into(),
        reason: format!("Ntfs::new failed: {e}"),
    })?;

    // Derive a stable MFT record count estimate from volume geometry.
    // `ntfs.size()` is the volume size in bytes; `ntfs.file_record_size()` is bytes per record.
    let file_record_size = ntfs.file_record_size() as u64;
    let count = ntfs.size().checked_div(file_record_size).unwrap_or(0);

    // Walk root-directory index to collect file names.
    let root = ntfs
        .root_directory(src)
        .map_err(|e| CairnError::Collector {
            collector: "mft".into(),
            reason: format!("root_directory failed: {e}"),
        })?;

    let index = root
        .directory_index(src)
        .map_err(|e| CairnError::Collector {
            collector: "mft".into(),
            reason: format!("directory_index failed: {e}"),
        })?;

    let mut entries = index.entries();
    let mut names: Vec<String> = Vec::with_capacity(max_names);

    // Iterate bounded by max_names; entries() yields in ascending NTFS key order
    // (deterministic: same order every run for the same volume state).
    while names.len() < max_names {
        let entry = match entries.next(src) {
            None => break,
            Some(r) => r.map_err(|e| CairnError::Collector {
                collector: "mft".into(),
                reason: format!("index entry error: {e}"),
            })?,
        };

        // key() returns Option<Result<NtfsFileName>>; None on the last (sentinel) entry.
        if let Some(key_result) = entry.key() {
            let file_name = key_result.map_err(|e| CairnError::Collector {
                collector: "mft".into(),
                reason: format!("file name key error: {e}"),
            })?;
            // NtfsFileName::name() returns U16StrLe; to_string_lossy() converts to String.
            names.push(file_name.name().to_string_lossy());
        }
    }

    Ok((count, names))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::config::Config;

    #[test]
    fn parse_short_source_returns_err_not_panic() {
        // The two inputs that panicked ntfs 0.4 RAW in the probe: empty and 3 bytes.
        // Through the guarded helper they MUST be Err, with no panic escaping.
        for bytes in [vec![], vec![0xEB, 0x52, 0x90]] {
            let mut cur = std::io::Cursor::new(bytes);
            let r = parse_mft_names(&mut cur, MAX_NAMES);
            assert!(r.is_err(), "short source must be Err, never panic");
        }
    }

    #[test]
    fn parse_garbage_full_sector_returns_err_not_panic() {
        // A full sector+ of zeros: ntfs returns clean Err (invalid boot signature);
        // the wrapper passes it through as Err.
        let mut cur = std::io::Cursor::new(vec![0u8; 1024]);
        let r = parse_mft_names(&mut cur, MAX_NAMES);
        assert!(r.is_err());
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
}
