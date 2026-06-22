//! HiveReader: raw-locate a locked hive, read its bytes (+ .LOG1/.LOG2) entirely in
//! memory, and parse it with notatin. Reusable primitive for hive-backed collectors
//! (shimcache now; amcache/userassist later). Mirrors usn.rs: same VolumeReader +
//! ntfs find_child navigation, same catch_unwind third-party-panic containment, same
//! read_value_capped memory ceiling. No temp files (notatin from_file takes a reader).

use cairn_core::{CairnError, Result};
use chrono::{DateTime, Utc};

/// A locked hive's on-volume location. Drive prefix is fixed C: (reads \\.\C:),
/// matching mft/usn — $MFT carries no drive-letter info.
///
/// `components` is an OWNED Vec<String> (not &'static) so per-user paths (e.g.
/// Users\<name>\NTUSER.DAT) can be built at runtime. The well-known hives expose
/// builder fns (SYSTEM_HIVE()/AMCACHE_HIVE()) rather than consts because a const
/// cannot hold an owned Vec.
pub(crate) struct HivePath {
    /// Volume-relative path components, last element is the hive filename.
    pub components: Vec<String>,
}

impl HivePath {
    /// Build the per-user NTUSER.DAT path: Users\<user_dir_name>\NTUSER.DAT.
    // allow(dead_code): first used in T6 userassist collector; remove when wired.
    #[allow(dead_code)]
    pub(crate) fn user_ntuser(user_dir_name: &str) -> HivePath {
        HivePath {
            components: vec![
                "Users".to_string(),
                user_dir_name.to_string(),
                "NTUSER.DAT".to_string(),
            ],
        }
    }
}

/// SYSTEM hive (Windows\System32\config\SYSTEM). A fn (not const) because HivePath
/// now holds an owned Vec.
#[allow(non_snake_case)]
pub(crate) fn SYSTEM_HIVE() -> HivePath {
    HivePath {
        components: ["Windows", "System32", "config", "SYSTEM"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

/// Amcache.hve — programs/files inventory (FR12 amcache_collector). A fn (not const)
/// because HivePath now holds an owned Vec.
#[allow(non_snake_case)]
pub(crate) fn AMCACHE_HIVE() -> HivePath {
    HivePath {
        components: ["Windows", "AppCompat", "Programs", "Amcache.hve"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

/// 512 MiB hard ceiling on a single hive's in-memory size (NFR10). A boot sector or
/// attribute length lying about size cannot force a larger allocation than this.
pub(crate) const HIVE_HARD_CEILING: u64 = 512 * 1024 * 1024;

/// Outcome of attempting transaction-log replay. Recorded in the manifest.
#[derive(Debug, PartialEq)]
pub(crate) enum LogStatus {
    /// At least one of .LOG1/.LOG2 was found and handed to notatin.
    Applied,
    /// Neither log file was present (clean shutdown or logs absent) — primary only.
    NotFound,
    /// A log existed but reading it failed; primary-only parse proceeded.
    Failed(String),
}

/// Result of open_hive.
pub(crate) struct OpenedHive {
    pub parser: notatin::parser::Parser,
    pub log_status: LogStatus,
    /// True if the primary hive read hit HIVE_HARD_CEILING (abstain signal).
    pub truncated: bool,
}

/// One enumerated subkey: its name and last-write time. hive_reader's OWN pure type —
/// it deliberately does NOT expose notatin's CellKeyNode, so a notatin upgrade cannot
/// break consumers (same encapsulation as get_value_bytes returning (Vec<u8>, DateTime)).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SubKey {
    pub name: String,
    pub last_write: DateTime<Utc>,
}

/// One enumerated value: its name and raw REG_BINARY bytes. hive_reader's OWN pure type
/// (mirrors SubKey) — it deliberately does NOT expose notatin's CellKeyValue, so a
/// notatin upgrade cannot break consumers. Non-binary values are not represented here
/// (list_values skips them).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeyValue {
    pub name: String,
    pub data: Vec<u8>,
}

/// Build a Collector-variant CairnError (mirrors usn_err/mft_err).
#[inline]
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
        cur = find_child_dir(&ntfs, reader, &cur, comp.as_str())?;
    }
    // Read primary hive via the DEFAULT (unnamed, empty-string) data stream.
    // ntfs::NtfsFile::data(reader, "") uses a simple is_empty() check and does NOT
    // require read_upcase_table (only non-empty names need the upcase table).
    let (primary, truncated) = read_default_stream(&ntfs, reader, &cur, file_name)?;

    // Read .LOG1/.LOG2 best-effort via tri-state: Ok(None)=absent, Ok(Some)=present+read,
    // Err=present but read failed. derive_log_status must be called BEFORE .ok() consumption.
    let log1_name = format!("{file_name}.LOG1");
    let log2_name = format!("{file_name}.LOG2");
    let log1 = read_log_stream(&ntfs, reader, &cur, &log1_name);
    let log2 = read_log_stream(&ntfs, reader, &cur, &log2_name);

    let log_status = derive_log_status(&log1, &log2);
    // Extract bytes only when Ok(Some(_)); Err and Ok(None) both yield None here.
    let log1_bytes = log1.ok().flatten();
    let log2_bytes = log2.ok().flatten();
    let parser = build_parser(primary, log1_bytes, log2_bytes)?;

    Ok(OpenedHive {
        parser,
        log_status,
        truncated,
    })
}

/// Read an already-located file's DEFAULT (unnamed) $DATA stream into a memory-capped
/// Vec. Returns (bytes, truncated); truncated == (n == HIVE_HARD_CEILING).
/// A lying $DATA attribute length cannot force a larger allocation than this ceiling
/// (NFR10); see HIVE_HARD_CEILING.
fn read_stream_bytes<'n, R: std::io::Read + std::io::Seek>(
    _ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    file: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<Vec<u8>> {
    use std::io::Read as _;
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
    attached
        .by_ref()
        .take(HIVE_HARD_CEILING)
        .read_to_end(&mut buf)
        .map_err(|e| hive_err(format!("reading {name} failed: {e}")))?;
    Ok(buf)
}

/// Read a named child file's DEFAULT (unnamed, "") data stream into a memory-capped Vec.
/// Returns (bytes, truncated). truncated == true if HIVE_HARD_CEILING was hit.
fn read_default_stream<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<(Vec<u8>, bool)> {
    let file = find_child_dir(ntfs, reader, dir, name)?;
    let bytes = read_stream_bytes(ntfs, reader, &file, name)?;
    // Conservative: a hive exactly == ceiling reports truncated (a false positive that
    // is impossible in practice — real hives are far below 512 MiB). Do NOT relax to
    // `>`; hitting the cap means we may have cut data, which must abstain (NFR10/NFR12).
    let truncated = bytes.len() as u64 == HIVE_HARD_CEILING;
    Ok((bytes, truncated))
}

/// Read a log file's default stream as a tri-state:
/// - Ok(None)        => the log file is ABSENT (graceful: clean shutdown / no logs)
/// - Ok(Some(bytes)) => present and read OK
/// - Err(reason)     => the log file EXISTS but reading it FAILED (genuine error)
///
/// This separation lets derive_log_status report LogStatus::Failed honestly instead
/// of silently claiming replay succeeded (NFR12 — the manifest must not lie about
/// whether transaction logs were applied).
fn read_log_stream<'n, R: std::io::Read + std::io::Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'n>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    // First locate the file. "Not found in directory" => absent => Ok(None).
    // find_child_dir builds its not-found message as "<name> not found in directory".
    // We treat THAT specific case as absent. Any other error (directory_index/find/
    // to_file failure, or the subsequent read failure) is a genuine Err.
    match find_child_dir(ntfs, reader, dir, name) {
        Err(e) => {
            // Distinguish "not found" (absent) from a real navigation error.
            let msg = e.to_string();
            if msg.contains("not found in directory") {
                Ok(None) // absent — graceful
            } else {
                Err(e) // genuine navigation error
            }
        }
        Ok(file) => {
            // File exists: read its default stream. A failure here is genuine.
            let bytes = read_stream_bytes(ntfs, reader, &file, name)?;
            Ok(Some(bytes))
        }
    }
}

/// Look up a child entry by name in a directory, returning the NtfsFile.
/// read_upcase_table MUST already have been called on `ntfs` (find() panics otherwise).
/// Named find_child_dir to avoid collision with usn::find_child (both are pub(crate) in
/// separate modules; this name is local to hive_reader).
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

/// Enumerate the immediate SUBDIRECTORY names of an on-volume directory (e.g. the user
/// folders under C:\Users). Returns hive_reader-owned Vec<String> — no ntfs type leaks
/// to callers. This walks the NTFS $I30 directory index, NOT a registry hive (contrast
/// list_subkeys, which enumerates keys inside a parsed hive).
///
/// Wrapped in catch_unwind (mirroring open_hive): ntfs panics on some inputs
/// (short sources in Ntfs::new, named lookups without read_upcase_table). Contain any
/// third-party panic and convert to Err so it never escapes the collector.
///
/// Only directories are returned (files skipped via NtfsFileName::is_directory). The
/// "." / ".." self/parent entries are dropped. NTFS short-name (8.3) duplicate index
/// entries (Dos namespace, e.g. "DEFAUL~1" alongside "DefaultUser") are SKIPPED via a
/// namespace filter — only Win32, Win32AndDos, and Posix entries are kept. (Win32AndDos
/// is the single-record case where long == short, so it represents one real entry.)
/// The result is sorted for determinism.
// allow(dead_code): first used in T6 userassist collector; remove when wired.
#[allow(dead_code)]
pub(crate) fn list_dir_names<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    dir_path: &HivePath,
) -> Result<Vec<String>> {
    use std::panic::{self, AssertUnwindSafe};
    // Same AssertUnwindSafe rationale as open_hive: `reader` is the only captured mut
    // ref; on a caught panic we never reuse it, we return Err immediately.
    let result = panic::catch_unwind(AssertUnwindSafe(|| list_dir_names_inner(reader, dir_path)));
    match result {
        Ok(inner) => inner,
        Err(_) => Err(hive_err(
            "ntfs panicked during directory enumeration (contained)".into(),
        )),
    }
}

/// Inner enumeration (only called inside catch_unwind).
fn list_dir_names_inner<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    dir_path: &HivePath,
) -> Result<Vec<String>> {
    use ntfs::structured_values::NtfsFileNamespace;
    use ntfs::Ntfs;

    let mut ntfs = Ntfs::new(reader).map_err(|e| hive_err(format!("Ntfs::new failed: {e}")))?;
    ntfs.read_upcase_table(reader)
        .map_err(|e| hive_err(format!("read_upcase_table failed: {e}")))?;
    let root = ntfs
        .root_directory(reader)
        .map_err(|e| hive_err(format!("root_directory failed: {e}")))?;

    // Navigate to the target directory (all components are directories here).
    let mut cur = root;
    for comp in &dir_path.components {
        cur = find_child_dir(&ntfs, reader, &cur, comp.as_str())?;
    }

    // Stream the directory index. directory_index() returns Err if `cur` is not a
    // directory (NtfsError::NotADirectory) — surfaced as Err (caller abstains).
    let index = cur
        .directory_index(reader)
        .map_err(|e| hive_err(format!("directory_index failed: {e}")))?;
    let mut entries = index.entries();
    let mut out: Vec<String> = Vec::new();
    while let Some(entry) = entries.next(reader) {
        // A corrupt index entry is skipped, not fatal — one bad $I30 node must not lose
        // the entire user listing (golden rule 8: graceful degrade).
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        // key() is Option<Result<NtfsFileName>>: None = no $FILE_NAME key on this entry
        // (skip); Err = a corrupt entry (skip it, do not abort the whole listing).
        let file_name = match entry.key() {
            Some(Ok(fnm)) => fnm,
            Some(Err(_)) | None => continue,
        };
        if !file_name.is_directory() {
            continue; // files are not user folders
        }
        // Skip the MS-DOS 8.3 short-name index entry. A directory with a long name has
        // TWO $FILE_NAME entries (Win32 long + Dos 8.3, e.g. "DefaultUser" + "DEFAUL~1");
        // keeping both would make the caller open NTUSER.DAT under a bogus short name.
        // Win32AndDos is the single-record case (long == short) — keep it.
        if file_name.namespace() == NtfsFileNamespace::Dos {
            continue;
        }
        let name = file_name.name().to_string_lossy();
        if name == "." || name == ".." {
            continue; // self / parent
        }
        out.push(name);
    }

    // Sort for deterministic output. dedup() is a cheap belt-and-suspenders guard
    // against any exact-duplicate that slips through (the Dos namespace filter above
    // is the primary mechanism for removing 8.3 short-name entries).
    out.sort();
    out.dedup();
    Ok(out)
}

/// Honest LogStatus from the two tri-state log reads:
/// - any genuine read error (Err) => Failed (a log existed but couldn't be read)
/// - both absent (Ok(None), Ok(None)) => NotFound
/// - at least one present (Ok(Some)) => Applied
fn derive_log_status(log1: &Result<Option<Vec<u8>>>, log2: &Result<Option<Vec<u8>>>) -> LogStatus {
    // A genuine failure on EITHER log is the most important signal to surface.
    for log in [log1, log2] {
        if let Err(e) = log {
            return LogStatus::Failed(e.to_string());
        }
    }
    let any_present = matches!(log1, Ok(Some(_))) || matches!(log2, Ok(Some(_)));
    if any_present {
        LogStatus::Applied
    } else {
        LogStatus::NotFound
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
fn build_parser(
    primary: Vec<u8>,
    log1: Option<Vec<u8>>,
    log2: Option<Vec<u8>>,
) -> Result<notatin::parser::Parser> {
    use notatin::parser_builder::ParserBuilder;
    use std::io::Cursor;

    let mut builder = ParserBuilder::from_file(Cursor::new(primary));
    builder.recover_deleted(false);
    // YAGNI: deleted-key recovery isn't needed for shimcache/amcache (they read live
    // keys). Enable in a later task only if a consumer (e.g. userassist) needs it.
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

/// Enumerate the direct child keys of `key_path`, returning each child's name and
/// last-write time. Absent key => Ok(vec![]) (graceful — golden rule 8).
///
/// Index-based enumeration (get_sub_key_by_index over 0..number_of_sub_keys). Order
/// is the hive's physical order, NOT sorted — the CALLER sorts for determinism.
/// `parser` is &mut because notatin traverses lazily (mutates state per lookup).
///
pub(crate) fn list_subkeys(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
) -> Result<Vec<SubKey>> {
    let mut parent = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let n = parent.detail.number_of_sub_keys() as usize;
    // NFR10 / never-panic: number_of_sub_keys is a u32 read straight from the hive and
    // could be adversarially huge (e.g. 0xFFFFFFFF on a corrupt/hostile hive). Do NOT
    // pre-allocate `n` elements — a lying count would trigger a multi-GB allocation
    // (OOM) BEFORE the loop discovers the real subkeys don't exist. Cap the *initial
    // capacity* only; the loop still runs the full 0..n and the Vec grows as needed for
    // a genuinely large (but real) key. notatin guards its own iter path with the same
    // 1<<20 limit ("Sanity check to prevent OOM with recovered data", cell_key_node.rs).
    let prealloc = n.min(SUBKEY_PREALLOC_CAP);
    let mut out = Vec::with_capacity(prealloc);
    for i in 0..n {
        if let Some(child) = parent.get_sub_key_by_index(parser, i) {
            out.push(SubKey {
                name: child.key_name.clone(),
                last_write: child.last_key_written_date_and_time(),
            });
        }
    }
    Ok(out)
}

/// Upper bound on the initial `Vec` capacity when enumerating subkeys, so a lying
/// `number_of_sub_keys` cannot force a huge pre-allocation. Mirrors notatin's own
/// 1<<20 OOM guard. The loop still honours the real count; this only bounds the
/// up-front reservation.
const SUBKEY_PREALLOC_CAP: usize = 1 << 20;

/// Enumerate ALL values of `key_path`, returning each value's name and raw REG_BINARY
/// bytes. Non-binary values (REG_SZ etc.) are skipped — bam/userassist values are all
/// REG_BINARY. Absent key => Ok(vec![]) (graceful — golden rule 8).
///
/// Order is the hive's physical value order, NOT sorted — the CALLER sorts for
/// determinism. `parser` is &mut because notatin traverses lazily (mutates state per
/// lookup). notatin guards its own value vector against a lying number_of_key_values
/// (> 1<<20 OOM guard, cell_key_node.rs), so no manual pre-alloc cap is needed here.
/// Caveat: when that guard fires, notatin silently leaves sub_values empty, so
/// list_values returns Ok(vec![]) — indistinguishable from a legitimately empty key.
/// Acceptable here: real bam keys hold O(10) values, nowhere near the cap.
pub(crate) fn list_values(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
) -> Result<Vec<KeyValue>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for value in key.value_iter() {
        // get_content().0 is the CellValue; only REG_BINARY is kept (bam data is binary).
        if let notatin::cell_value::CellValue::Binary(data) = value.get_content().0 {
            // detail.value_name() is the macro-generated accessor; unnamed values return "".
            out.push(KeyValue {
                name: value.detail.value_name(),
                data,
            });
        }
    }
    Ok(out)
}

/// Fetch a single REG_SZ value as a String. Returns Ok(None) when the key or value is
/// absent, or when the value is not a string type (graceful — golden rule 8).
///
/// Companion to get_value_bytes (which handles REG_BINARY). `parser` is &mut for the
/// same lazy-cursor reason.
///
/// Note: notatin maps REG_SZ, REG_EXPAND_SZ and REG_LINK all to `CellValue::String`,
/// so this accessor does NOT distinguish those three. That is fine for amcache's
/// target values (all plain REG_SZ); a future consumer needing a strict REG_SZ-only
/// read must inspect `CellKeyValue.data_type` instead.
///
pub(crate) fn get_value_string(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Result<Option<String>> {
    let key = match parser
        .get_key(key_path, false)
        .map_err(|e| hive_err(format!("get_key({key_path}) failed: {e}")))?
    {
        Some(k) => k,
        None => return Ok(None),
    };
    let value = match key.get_value(value_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    match value.get_content().0 {
        notatin::cell_value::CellValue::String(s) => Ok(Some(s)),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn amcache_hive_path_joins_to_appcompat_programs() {
        let joined = AMCACHE_HIVE().components.join("\\");
        assert_eq!(joined, r"Windows\AppCompat\Programs\Amcache.hve");
    }

    #[test]
    fn user_ntuser_builds_users_name_ntuser_dat() {
        let p = HivePath::user_ntuser("alice");
        assert_eq!(p.components, vec!["Users", "alice", "NTUSER.DAT"]);
    }

    #[test]
    fn user_ntuser_handles_names_with_spaces() {
        let p = HivePath::user_ntuser("John Doe");
        assert_eq!(p.components, vec!["Users", "John Doe", "NTUSER.DAT"]);
    }

    #[test]
    fn subkey_holds_name_and_time() {
        let t = chrono::Utc::now();
        let sk = SubKey {
            name: "0006...".into(),
            last_write: t,
        };
        assert_eq!(sk.name, "0006...");
        assert_eq!(sk.last_write, t);
    }

    #[test]
    fn subkey_prealloc_is_capped_against_lying_count() {
        // A corrupt/hostile hive can claim number_of_sub_keys == u32::MAX. list_subkeys
        // pre-allocates n.min(SUBKEY_PREALLOC_CAP), NOT n, so a lying count cannot force
        // a multi-GB Vec reservation (NFR10 / never-panic). Prove the clamp arithmetic.
        let lying = u32::MAX as usize;
        assert_eq!(lying.min(SUBKEY_PREALLOC_CAP), SUBKEY_PREALLOC_CAP);
        // A real, small count is unaffected.
        assert_eq!(7usize.min(SUBKEY_PREALLOC_CAP), 7);
    }

    #[test]
    fn open_hive_short_reader_is_err_not_panic() {
        // A reader far shorter than a boot sector: ntfs cannot parse a volume.
        // Must return Err (contained), never panic (golden rule 8).
        let mut reader = Cursor::new(vec![0u8; 16]);
        let r = open_hive(&mut reader, &SYSTEM_HIVE());
        assert!(r.is_err(), "short reader must yield Err, got Ok");
    }

    #[test]
    fn list_dir_names_on_short_reader_is_err_not_panic() {
        // A reader too short to be a volume must yield Err (contained), never panic.
        let mut reader = Cursor::new(vec![0u8; 16]);
        let users = HivePath {
            components: vec!["Users".to_string()],
        };
        let r = list_dir_names(&mut reader, &users);
        assert!(r.is_err(), "short reader must yield Err, got Ok");
    }

    #[test]
    fn system_hive_path_joins_to_config_system() {
        let joined = SYSTEM_HIVE().components.join("\\");
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

    #[test]
    fn keyvalue_holds_name_and_data() {
        let kv = KeyValue {
            name: r"\Device\HarddiskVolume3\Windows\notepad.exe".into(),
            data: vec![1u8, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(kv.name, r"\Device\HarddiskVolume3\Windows\notepad.exe");
        assert_eq!(kv.data.len(), 8);
    }
}
