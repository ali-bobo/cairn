//! HiveReader: raw-locate a locked hive, read its bytes (+ .LOG1/.LOG2) entirely in
//! memory, and parse it with notatin. Reusable primitive for hive-backed collectors
//! (shimcache now; amcache/userassist later). Mirrors usn.rs: same VolumeReader +
//! ntfs find_child navigation, same catch_unwind third-party-panic containment, same
//! read_value_capped memory ceiling. No temp files (notatin from_file takes a reader).

use chrono::{DateTime, Utc};
use cairn_core::{CairnError, Result};

/// A locked hive's on-volume location. Drive prefix is fixed C: (reads \\.\C:),
/// matching mft/usn — $MFT carries no drive-letter info.
#[allow(dead_code)]
pub(crate) struct HivePath {
    /// Volume-relative path components, last element is the hive filename.
    pub components: &'static [&'static str],
}

/// SYSTEM hive — the only path wired this segment.
#[allow(dead_code)]
pub(crate) const SYSTEM_HIVE: HivePath = HivePath {
    components: &["Windows", "System32", "config", "SYSTEM"],
};

/// 512 MiB hard ceiling on a single hive's in-memory size (NFR10). A boot sector or
/// attribute length lying about size cannot force a larger allocation than this.
#[allow(dead_code)]
pub(crate) const HIVE_HARD_CEILING: u64 = 512 * 1024 * 1024;

/// Outcome of attempting transaction-log replay. Recorded in the manifest.
#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub(crate) enum LogStatus {
    /// At least one of .LOG1/.LOG2 was found and handed to notatin.
    Applied,
    /// Neither log file was present (clean shutdown or logs absent) — primary only.
    NotFound,
    /// A log existed but reading it failed; primary-only parse proceeded.
    Failed(String),
}

/// Result of open_hive.
#[allow(dead_code)]
pub(crate) struct OpenedHive {
    pub parser: notatin::parser::Parser,
    pub log_status: LogStatus,
    /// True if the primary hive read hit HIVE_HARD_CEILING (abstain signal).
    pub truncated: bool,
}

/// Build a Collector-variant CairnError (mirrors usn_err/mft_err).
#[inline]
#[allow(dead_code)]
fn hive_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "hive".into(),
        reason,
    }
}

/// Locate, read (in memory), and notatin-parse a hive from a raw volume reader.
///
/// Wrapped in catch_unwind (mirroring usn.rs read_usn_journal / mft.rs guard b): the
/// ntfs crate panics on some inputs (named-stream lookup panics without
/// read_upcase_table; short sources panic in Ntfs::new) and notatin is third-party
/// too. Contain any panic and convert to Err so it never escapes this collector.
#[allow(dead_code)] // called by shimcache collector (next task)
pub(crate) fn open_hive<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    hive: &HivePath,
) -> Result<OpenedHive> {
    use std::panic::{self, AssertUnwindSafe};
    // NOTE: AssertUnwindSafe is correct here because:
    // - `reader` is the only captured mutable reference.
    // - If ntfs/notatin panic, `reader` may be in an undefined mid-parse state, but we
    //   NEVER use `reader` after a caught panic — we immediately return Err.
    // - We are NOT using catch_unwind to hide our own logic errors; only to contain a
    //   third-party panic (ntfs short-source / named-lookup; notatin regressions).
    let result = panic::catch_unwind(AssertUnwindSafe(|| open_hive_inner(reader, hive)));
    match result {
        Ok(inner) => inner,
        Err(_) => Err(hive_err(
            "ntfs/notatin panicked (contained); treating hive as unreadable".into(),
        )),
    }
}

/// Inner open: navigate to the hive file, read primary + .LOG1/.LOG2 into memory,
/// build the notatin Parser. Only called inside catch_unwind.
#[allow(dead_code)]
fn open_hive_inner<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    hive: &HivePath,
) -> Result<OpenedHive> {
    use ntfs::Ntfs;

    let mut ntfs = Ntfs::new(reader).map_err(|e| hive_err(format!("Ntfs::new failed: {e}")))?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| hive_err(format!("read_upcase_table failed: {e}")))?;
    let root = ntfs
        .root_directory(reader)
        .map_err(|e| hive_err(format!("root_directory failed: {e}")))?;

    // Walk components: dirs are intermediate, last is the hive file.
    // split_last() returns Option<(&last, &[rest])>.
    let (file_name, dir_components) = hive
        .components
        .split_last()
        .ok_or_else(|| hive_err("empty HivePath".into()))?;

    let mut cur = root;
    for comp in dir_components {
        cur = find_child_dir(&ntfs, reader, &cur, comp)?;
    }
    // Read primary hive via the DEFAULT (unnamed, empty-string) data stream.
    // ntfs::NtfsFile::data(reader, "") uses a simple is_empty() check and does NOT
    // require read_upcase_table (only non-empty names need the upcase table).
    let (primary, truncated) = read_default_stream(&ntfs, reader, &cur, file_name)?;

    // Read .LOG1/.LOG2 best-effort (graceful: absent -> NotFound).
    let log1_name = format!("{file_name}.LOG1");
    let log2_name = format!("{file_name}.LOG2");
    let log1 = read_default_stream(&ntfs, reader, &cur, &log1_name);
    let log2 = read_default_stream(&ntfs, reader, &cur, &log2_name);

    let log_status = derive_log_status(&log1, &log2);
    let parser = build_parser(
        primary,
        log1.ok().map(|(b, _)| b),
        log2.ok().map(|(b, _)| b),
    )?;

    Ok(OpenedHive {
        parser,
        log_status,
        truncated,
    })
}

/// Read a named child file's DEFAULT (unnamed, "") data stream into a memory-capped Vec.
/// Returns (bytes, truncated). truncated == true if HIVE_HARD_CEILING was hit.
#[allow(dead_code)]
fn read_default_stream<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<(Vec<u8>, bool)> {
    use std::io::Read as _;
    let file = find_child_dir(ntfs, reader, dir, name)?;
    // Empty string selects the unnamed (default) $DATA attribute.
    // ntfs confirms: is_empty() == true path skips the upcase-table lookup.
    let data_item = file
        .data(reader, "")
        .ok_or_else(|| hive_err(format!("{name}: no default data stream")))?
        .map_err(|e| hive_err(format!("{name} data attribute error: {e}")))?;
    let attr = data_item
        .to_attribute()
        .map_err(|e| hive_err(format!("{name} to_attribute failed: {e}")))?;
    let value = attr
        .value(reader)
        .map_err(|e| hive_err(format!("{name} value failed: {e}")))?;
    let mut attached = value.attach(reader);
    let mut buf = Vec::new();
    let n = attached
        .by_ref()
        .take(HIVE_HARD_CEILING)
        .read_to_end(&mut buf)
        .map_err(|e| hive_err(format!("reading {name} failed: {e}")))?;
    let truncated = n as u64 == HIVE_HARD_CEILING;
    Ok((buf, truncated))
}

/// Look up a child entry by name in a directory, returning the NtfsFile.
/// read_upcase_table MUST already have been called on `ntfs` (find() panics otherwise).
/// Named find_child_dir to avoid collision with usn::find_child (both are pub(crate) in
/// separate modules; this name is local to hive_reader).
#[allow(dead_code)]
fn find_child_dir<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    use ntfs::indexes::NtfsFileNameIndex;
    let index = dir
        .directory_index(reader)
        .map_err(|e| hive_err(format!("directory_index for {name} failed: {e}")))?;
    let mut finder = index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, ntfs, reader, name)
        .ok_or_else(|| hive_err(format!("{name} not found in directory")))?
        .map_err(|e| hive_err(format!("find {name} failed: {e}")))?;
    entry
        .to_file(ntfs, reader)
        .map_err(|e| hive_err(format!("to_file for {name} failed: {e}")))
}

/// Derive LogStatus from the two log read results.
#[allow(dead_code)]
fn derive_log_status(log1: &Result<(Vec<u8>, bool)>, log2: &Result<(Vec<u8>, bool)>) -> LogStatus {
    match (log1.is_ok(), log2.is_ok()) {
        (false, false) => LogStatus::NotFound,
        _ => LogStatus::Applied,
    }
}

/// Build a notatin Parser from in-memory primary + optional log bytes.
///
/// notatin 1.0.1 API (confirmed from parser_builder.rs source):
/// - `ParserBuilder::from_file(primary)` returns `ParserBuilderFromFile` (distinct type).
/// - Chain methods `recover_deleted(&mut self, bool) -> &mut Self` and
///   `with_transaction_log<T: ReadSeek + 'static>(&mut self, log: T) -> &mut Self`
///   both take `&mut self` and return `&mut Self` — statement-style mutation works.
/// - `build(self)` on `ParserBuilderFromFile` consumes the builder by value (not `&self`).
/// - notatin `ReadSeek` is a blanket impl over all `T: Read + Seek`, so
///   `std::io::Cursor<Vec<u8>>` satisfies it automatically.
#[allow(dead_code)]
fn build_parser(
    primary: Vec<u8>,
    log1: Option<Vec<u8>>,
    log2: Option<Vec<u8>>,
) -> Result<notatin::parser::Parser> {
    use notatin::parser_builder::ParserBuilder;
    use std::io::Cursor;

    let mut builder = ParserBuilder::from_file(Cursor::new(primary));
    builder.recover_deleted(false);
    if let Some(b) = log1 {
        builder.with_transaction_log(Cursor::new(b));
    }
    if let Some(b) = log2 {
        builder.with_transaction_log(Cursor::new(b));
    }
    // build(self) consumes the ParserBuilderFromFile by value.
    builder
        .build()
        .map_err(|e| hive_err(format!("notatin build failed: {e}")))
}

/// Fetch a single value's raw bytes + the owning key's last-write time.
/// Returns Ok(None) when the key or value is absent (graceful — golden rule 8).
///
/// key_path uses notatin's path syntax WITHOUT the root prefix (key_path_has_root =
/// false), e.g. r"ControlSet001\Control\Session Manager\AppCompatCache".
///
/// Only REG_BINARY values are returned; other value types yield Ok(None). Suitable
/// for binary-format artifacts (AppCompatCache, Amcache hashes, ...). Callers
/// needing string values (REG_SZ) must use a different accessor.
///
/// Note: `parser` must be `&mut` because notatin's `Parser::get_key` traverses the
/// hive lazily via an internal cursor — it mutates state on every lookup.
#[allow(dead_code)]
pub(crate) fn get_value_bytes(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Result<Option<(Vec<u8>, DateTime<Utc>)>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(None),
    };
    let last_write = key.last_key_written_date_and_time();
    let value = match key.get_value(value_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    // Confirmed from notatin 1.0.1 source (cell_value.rs):
    //   CellValue::Binary(Vec<u8>) — NOT ValueBinary.
    // get_content() returns (CellValue, Option<Logs>); .0 gives the CellValue.
    let bytes = match value.get_content().0 {
        notatin::cell_value::CellValue::Binary(b) => b,
        _ => return Ok(None),
    };
    Ok(Some((bytes, last_write)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn open_hive_short_reader_is_err_not_panic() {
        // A reader far shorter than a boot sector: ntfs cannot parse a volume.
        // Must return Err (contained), never panic (golden rule 8).
        let mut reader = Cursor::new(vec![0u8; 16]);
        let r = open_hive(&mut reader, &SYSTEM_HIVE);
        assert!(r.is_err(), "short reader must yield Err, got Ok");
    }

    #[test]
    fn system_hive_path_joins_to_config_system() {
        let joined = SYSTEM_HIVE.components.join("\\");
        assert_eq!(joined, r"Windows\System32\config\SYSTEM");
    }

    #[test]
    fn hive_err_is_collector_variant() {
        let e = hive_err("boom".into());
        assert!(matches!(e, cairn_core::CairnError::Collector { .. }));
    }

    #[test]
    fn log_status_variants_are_distinct() {
        assert_ne!(LogStatus::Applied, LogStatus::NotFound);
        assert_ne!(LogStatus::NotFound, LogStatus::Failed("x".into()));
        assert_eq!(LogStatus::Failed("y".into()), LogStatus::Failed("y".into()));
    }
}
