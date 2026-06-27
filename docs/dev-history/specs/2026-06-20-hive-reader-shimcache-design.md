# Hive-Reader Primitive + Shimcache Collector — Design

**Date:** 2026-06-20
**Segment:** FR12 raw-NTFS, third piece (after $MFT, $J/USN). First hive-backed collector.
**Status:** Approved (brainstorm complete, 2026-06-20).

---

## 1. Goal & Scope

Read a **locked** SYSTEM hive from a live host via raw `\\.\C:`, parse it with
`notatin` (including `.LOG1`/`.LOG2` transaction-log replay), extract the
AppCompatCache (shimcache) binary blob, version-aware-parse it, and emit
`Record::Execution`. Entirely in-memory, **zero temp files, zero new `unsafe`**.

This segment delivers **two new files** in `cairn-collectors`:

1. `hive_reader.rs` — the **reusable hive-reading primitive** (raw locate + read
   hive bytes + `.LOG1`/`.LOG2` → `notatin::Parser` → safe value-fetch API).
   Future `amcache_collector` / `userassist_collector` consume this same
   primitive.
2. `shimcache.rs` — the **first consumer**: AppCompatCache → version-aware pure
   parser → `Record::Execution`.

### Out of scope (YAGNI — deferred to their own segments)
- `amcache_collector` (Amcache.hve: sha1, first-exec) — next segment.
- `userassist`/`bam` (NTUSER per-SID enumeration) — Stage 3.
- Recovering deleted/modified registry keys (`recover_deleted(false)`).
- Hives other than SYSTEM. The primitive is generic (takes a `HivePath`), but
  this segment only wires `SYSTEM_HIVE`.
- Win7/Win8 AppCompatCache formats — modern hosts only; old/unknown formats
  **abstain** (NFR12), never guess.
- A CLI flag for the hive RAM cap (fixed 512 MiB hard ceiling instead).

---

## 2. Dependency decision (verified during brainstorm)

**`notatin` v1.0.1** — chosen offline-hive parser.

| Property | Finding | Source |
|---|---|---|
| License | **Apache-2.0** (does NOT infect the signed binary) | crates.io metadata + LICENSE file |
| Safety | 100% safe Rust | crate README |
| Maintenance | Last release **2023-08-18** — mature but not actively maintained | crates.io |
| Downloads | ~45k | crates.io |
| `from_file<R: ReadSeek>` | **accepts an in-memory reader** (not just a path) | docs.rs ParserBuilder |
| `with_transaction_log<T: ReadSeek>` | **accepts a reader** for `.LOG1`/`.LOG2` | docs.rs ParserBuilderFromFile |

**Key correction during brainstorm:** an earlier assumption held that notatin
"only accepts `from_path()`", which would have forced a raw-bytes → off-target
temp file → parse architecture. **This is false.** `from_file` and
`with_transaction_log` both take `R: ReadSeek`, so the entire chain runs on
`Cursor<Vec<u8>>` readers in memory — **no temp file**, avoiding the whole
`--dry-run` / off-target / cleanup / host-footprint problem (golden rule 4).

**Rejected alternative:** `nt_hive2` is **GPL-3.0** → would infect the signed
binary → rejected. (Already recorded in prior memory.)

**Residual risk (accepted):** notatin is 2 years stale. Mitigation: `cargo audit`
gate in CI catches any future advisory; NFR12 abstain handles parse anomalies;
the version-aware shimcache parser is OURS (notatin only supplies raw value
bytes), so format drift is isolated in our code.

**Zero new transitive `unsafe`:** notatin is 100% safe Rust. The only `unsafe`
on the whole path is inside the existing `VolumeReader` (already isolated in
`cairn-collectors-win`); `cairn-collectors` keeps `#![forbid(unsafe_code)]`.

---

## 3. Architecture

Three layers, responsibilities physically separated; all inside
`cairn-collectors` (`#![forbid(unsafe_code)]` preserved).

```
cairn-collectors  (#![forbid(unsafe_code)])

  hive_reader.rs  ── primitive (reusable by amcache/userassist)
    input: a HivePath (volume-relative components → hive file)
    1. VolumeReader::open(r"\\.\C:")          ← existing; unsafe isolated in win crate
    2. ntfs crate: Ntfs::new → read_upcase_table → find_child chain
       (Windows → System32 → config → SYSTEM)  ← same nav as usn.rs find_child
    3. read primary default data stream → Vec<u8> via read_value_capped pattern
       (512 MiB HARD_CEILING, NFR10); same for SYSTEM.LOG1 / SYSTEM.LOG2 (graceful)
    4. Cursor::new(primary) → notatin from_file
         .with_transaction_log(Cursor::new(log1))
         .with_transaction_log(Cursor::new(log2))
         .recover_deleted(false).build() → notatin::Parser
    all of 2–4 wrapped in catch_unwind(AssertUnwindSafe) — contain ntfs+notatin panic
    5. safe API: get_value_bytes(key_path, value_name) -> Option<(Vec<u8>, last_write)>
                          │
                          ▼ raw bytes of AppCompatCache value
  shimcache.rs  ── consumer (pure parser + Collector)
    parse_appcompatcache(buf) -> (ShimVersion, Vec<ShimEntry>)
       version-aware (header magic), NO I/O, never-panic (bounds-checked readers,
       same style as parse_usn_record); Unknown version → abstain (empty)
    ShimCollector: privilege gate (admin && se_backup, BEFORE open) → VolumeReader
       → open_hive(SYSTEM) → get_value_bytes(AppCompatCache) → parse → Record::Execution
```

### Golden-rule binding
1. **No evasion** — read-only `GENERIC_READ`+`OPEN_EXISTING`; tool stays benign.
2. **Zero new unsafe** — primitive uses VolumeReader's safe `Read+Seek` only.
3. **Collectors never modify host** — no writes, no temp files, in-memory only.
4. **`--dry-run` writes nothing** — trivially satisfied (collector never writes).
7. **UTC RFC3339** — all timestamps via existing `filetime_to_utc`.
8. **Graceful degrade** — every failure mode skips/abstains + records reason,
   never aborts the run; never panics.

---

## 4. Components (precise interfaces)

### 4.1 `hive_reader.rs`

```rust
/// A locked hive's on-volume location. Drive prefix is fixed C: (reads \\.\C:).
pub(crate) struct HivePath { pub components: &'static [&'static str] }

/// SYSTEM hive — the only path wired this segment.
pub(crate) const SYSTEM_HIVE: HivePath =
    HivePath { components: &["Windows", "System32", "config", "SYSTEM"] };

/// 512 MiB hard ceiling on a single hive's in-memory size (NFR10).
const HIVE_HARD_CEILING: u64 = 512 * 1024 * 1024;

pub(crate) enum LogStatus { Applied, NotFound, Failed(String) }

pub(crate) struct OpenedHive {
    pub parser: notatin::parser::Parser,
    pub log_status: LogStatus,
    pub truncated: bool,   // primary hive exceeded the ceiling → abstain signal
}

/// Locate, read, and notatin-parse a hive from a raw volume reader.
/// catch_unwind-wrapped (contains ntfs + notatin third-party panics).
pub(crate) fn open_hive<R: Read + Seek>(
    reader: &mut R,
    hive: &HivePath,
) -> Result<OpenedHive>;

/// Fetch a single value's raw bytes + last-write from an opened Parser.
/// Returns Ok(None) when the key/value is absent (graceful).
pub(crate) fn get_value_bytes(
    parser: &notatin::parser::Parser,
    key_path: &str,
    value_name: &str,
) -> Result<Option<(Vec<u8>, Option<DateTime<Utc>>)>>;
```

**Internal flow** mirrors `usn.rs::read_usn_inner` (Ntfs::new → read_upcase_table
→ find_child chain), but the terminal read is the hive file's **default** data
stream `file.data(reader, "")` (not an ADS), and the bytes feed notatin instead
of a hand-rolled scanner. `read_value_capped`-style read with `HIVE_HARD_CEILING`.

**Deferred-to-implementer (NOT guessed in this design):** the exact notatin
method chain for `get_value_bytes` (e.g. `parser.get_key()` → `key.get_value()`
→ extracting raw bytes from the `CellValue` type). The implementer verifies the
real method names against the **installed notatin source** (same discipline the
usn implementer used for the ntfs crate). The interface contract
(key_path+value_name → raw bytes + last_write) is stable.

### 4.2 `shimcache.rs`

```rust
const SHIMCACHE_KEY: &str =
    r"ControlSet001\Control\Session Manager\AppCompatCache";  // not CurrentControlSet (symlink absent offline)
const SHIMCACHE_VALUE: &str = "AppCompatCache";

#[derive(Debug, PartialEq)]
pub(crate) struct ShimEntry {
    pub path: String,
    pub last_modified: Option<DateTime<Utc>>,  // file mtime from cache, NOT exec time
    pub executed: bool,                        // best-effort data-flag (drives execution_confirmed)
}

#[derive(Debug, PartialEq)]
pub(crate) enum ShimVersion { Win10Plus, Unknown(u32) }

/// Version-aware AppCompatCache parser. NO I/O, never-panic (bounds-checked
/// readers, same style as parse_usn_record). Unknown version → (Unknown, vec![]).
pub(crate) fn parse_appcompatcache(buf: &[u8]) -> (ShimVersion, Vec<ShimEntry>);

#[derive(Default)]
pub struct ShimCollector { /* AtomicU64 abstain/truncation flags, like usn */ }
```

`ShimCollector::collect`: privilege gate (admin && se_backup, before volume open)
→ VolumeReader → open_hive(SYSTEM) → get_value_bytes(AppCompatCache) →
parse_appcompatcache → map to `Record::Execution { source:"shimcache", path,
first_run:None, last_run:None, run_count:None, sha1:None, user_sid:None,
execution_confirmed:Some(false) }`. `sources()`: artifact `"shimcache"`, method
`"raw_ntfs_hive"`, errors carry log_status / abstain / truncation notes.

**Win10Plus, not Win10-vs-Win11:** AppCompatCache's on-disk format has been
stable since Win10 1607 — Win10 and Win11 share the same layout, so they collapse
into one parse path (`ShimVersion::Win10Plus`). A separate `Win11` variant would
falsely imply a format difference. If the implementer's format-reference check
finds Win11 genuinely differs, split then; the design assumes one path.

**Deferred-to-implementer (NOT guessed):** the exact AppCompatCache header magic
/ signature that identifies the Win10Plus format. The plan task cites an
authoritative format reference (Mandiant/SANS AppCompatCache spec); the
implementer confirms the magic value against it. This segment recognises the
**Win10Plus format only**; everything else abstains (NFR12).

---

## 5. Data flow

```
ShimCollector::collect(ctx)
 ① ctx.admin && ctx.se_backup ?  no → Err(Privilege) → orchestrator skips, records reason
 ② VolumeReader::open(\\.\C:)    fail → Err(Collector) → graceful degrade
 ③ open_hive(reader, SYSTEM)     [catch_unwind] panic/Err → graceful degrade
                                 truncated(>ceiling) → abstain + manifest note
 ④ get_value_bytes(AppCompatCache)  None → empty + "shimcache absent" note → Ok(vec![])
 ⑤ parse_appcompatcache(bytes)   Unknown ver → abstain + note → Ok(vec![])
 ⑥ entries → Record::Execution { source:"shimcache", path, last_run:None,
                                 execution_confirmed:Some(false), .. }
              sort by (ts, path) → Record bus → timeline/findings
```

**Timestamp semantics (NFR12 honesty):** a shimcache entry carries the file's
**last-modified** time, NOT an execution time. `last_run`/`first_run` are `None`
(never lie). `execution_confirmed` reflects the entry's data-flag (best-effort:
`Some(true)` iff the flag indicates execution, else `Some(false)`).

**last_modified has no Record-layer home (known limitation):** `ExecutionRecord`
has no "file mtime" field, and putting the mtime in `last_run` would be a lie.
So `last_modified` is parsed (it's real evidence) but **dropped at the Record
layer** this segment. The timeline ts is projected from `Finding`, not `Record`
(see `cairn-report::timeline_row`), so surfacing the mtime is a downstream
Finding/analyzer concern or a future schema field — out of scope here. Collector
output is therefore sorted by **path** (the only stable key a shimcache Record
carries), not (ts, path); the (ts, record_id) ordering applies at the Finding/
timeline layer.

---

## 6. Error handling → golden-rule map

| Failure | Handling | Rule |
|---|---|---|
| not admin / no SeBackup | Err(Privilege) BEFORE volume open; skip + record | GR8 |
| VolumeReader open fails | Err(Collector); skip + record | GR8 |
| ntfs/notatin **panic** | catch_unwind → Err; never escapes | GR8 + never-panic |
| hive primary > ceiling | truncate read, truncated=true, **abstain** (no half record) + note | NFR10 + NFR12 |
| .LOG1/.LOG2 missing/corrupt | fallback to primary-only, LogStatus::NotFound/Failed + note | GR8 + NFR12 |
| AppCompatCache key/value absent | empty result + "shimcache absent" note | GR8 |
| unknown format version | **abstain**: empty + "version unrecognised" note; never guess | NFR12 |
| AppCompatCache blob corrupt/OOB | bounds-checked reader stops; best-effort partial + note | never-panic |
| bad UTF-16 path | from_utf16_lossy replacement chars, best-effort | never-panic |

**Error type:** `cairn_core::CairnError` (`Privilege`/`Collector`) + `Result`;
new `hive_err(reason)` helper mirroring `usn_err`/`mft_err`.

**never-modify-host:** only `GENERIC_READ`+`OPEN_EXISTING` raw read + in-memory
notatin parse. No write, no temp file, no `--dry-run` conflict. GR3 + GR4.

**determinism:** collector output sorted by **path** (shimcache Records carry no
native ts/record_id). The (ts, record_id) timeline ordering applies downstream at
the Finding layer, same as all other Record sources.

---

## 7. Testing strategy

CI cannot run real locked-hive reads (need admin+SeBackup), so **correctness
lives in pure-function unit tests**; e2e is an `#[ignore]` smoke test.

### 7.1 Pure unit tests (primary, CI-run)
- `parse_appcompatcache`: synthetic Win10Plus header with N entries → correct
  paths/mtimes/count; Unknown magic → `(Unknown, vec![])`; empty / short / count
  field lying huge / truncated body / bad-UTF-16 path → never-panic, best-effort.
  Synthetic builder `build_shim_win10plus(entries)` in test mod (mirrors `build_usn_v2`).
- Constants: SYSTEM_HIVE components, SHIMCACHE_KEY/VALUE (typo regression guard).
- ShimCollector no-I/O: no-priv → Err(Privilege); name()=="shimcache";
  sources() clean vs abstain/truncated errors.

### 7.2 open_hive / get_value_bytes test boundary (honest)
Synthesising a mini NTFS volume + mini hive that satisfies both ntfs nav AND
notatin parse is prohibitively expensive/brittle (= hand-coding two on-disk
formats). usn/mft set the precedent: the ntfs navigation layer is NOT unit-tested
with a synthetic volume — it is covered by e2e. We follow that boundary.
**Testable error branch:** a <512-byte reader → ntfs short-source →
catch_unwind/length-guard → Err (same as mft guard a/b, using real panic-trigger
inputs). notatin build success + get_value_bytes correctness → e2e.

### 7.3 `#[ignore]` elevated e2e (manual, real host)
`cargo test -- --ignored` on real Windows with admin+SeBackup: ShimCollector
against real `\\.\C:` → real SYSTEM AppCompatCache → > 0 Execution records, each
path non-empty, source=="shimcache", execution_confirmed==Some(false); log
replay non-fatal (LogStatus Applied or NotFound, not panic). Mirrors usn
`elevated_e2e_real_j`.

### 7.4 Integration wiring (CI-run, no I/O)
- `select_modules`: RAW_NTFS contains "shimcache"; `--profile minimal` excludes it
  (`minimal_excludes_shimcache`, mirrors `minimal_excludes_usn`).
- CLI: AVAILABLE contains "shimcache"; `built_collector_names` / exact-vector +
  contains assertions updated (mirror the usn change).

### 7.5 CI discipline (lessons carried from governance/usn)
- local clippy MUST include `--all-targets` (else lib-test lints only fail in CI).
- run `cargo test --workspace` (not `-p`) to catch cross-crate breakage.

---

## 8. Schema impact

**None.** `Record::RegValue(RegValueRecord)` and `Record::Execution(ExecutionRecord)`
already exist in `cairn-core::record`. No manifest/Finding schema change.
(`RegValueRecord` is reserved for a future generic hive dump; this segment emits
only `Execution` via shimcache.)

---

## 9. Decomposition note (the brainstorm's primary output)

The four SRS hive collectors (hive_collector, amcache, shimcache,
userassist/bam) share one hard core: raw-locate a locked hive → read its bytes
(+logs) → notatin-parse. That core is **hive_reader.rs**, built once here. The
remaining collectors become thin consumers: walk specific keys, map values to
Records. This segment ships the primitive + shimcache (single SYSTEM hive,
Execution evidence, schema ready, classic high-value DFIR artifact) to de-risk
the primitive before the more complex amcache (sha1/first-exec) and the
per-SID-enumerating userassist/bam.
