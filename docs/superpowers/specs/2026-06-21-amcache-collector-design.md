# Amcache Collector — Design

> FR12 raw-NTFS fourth piece. Reuses the `hive_reader` primitive (built in PR #20)
> to parse `Amcache.hve` → `Record::Execution`. Scope this segment:
> **InventoryApplicationFile only** (path + SHA1 + first-exec approximation).

**Date:** 2026-06-21
**Status:** approved (design), pending plan
**Authoritative spec:** `cairn-SRS.md` §4 (amcache_collector row 65), NFR12, FR12
**Predecessor:** `2026-06-20-hive-reader-shimcache-design.md`

---

## 1. Architecture & layering

Two layers, both in `cairn-collectors` (`#![forbid(unsafe_code)]` maintained; the
only raw read reuses the existing `cairn-collectors-win::volume::VolumeReader`).
Mirrors the proven hive/shimcache split.

### Foundation layer — `hive_reader.rs` (extend with two reusable primitives)

The shimcache segment left `hive_reader` with `open_hive`, `get_value_bytes`
(REG_BINARY only), `HivePath`, `LogStatus`, `OpenedHive`, and the `catch_unwind`
third-party-panic containment around `open_hive`. Amcache needs two capabilities
that hive_reader does not yet have: **subkey enumeration** and **string-value
reads**. Per the chosen layering decision, both go into `hive_reader` as generic
primitives (not into `amcache.rs`), so `userassist`/`bam` can reuse them later.

- **`AMCACHE_HIVE: HivePath`** — new const, volume-relative components
  `&["Windows", "AppCompat", "Programs", "Amcache.hve"]` (same style/const as
  `SYSTEM_HIVE`). Drive prefix fixed C: (reads `\\.\C:`), matching mft/usn/shimcache.

- **`struct SubKey { name: String, last_write: DateTime<Utc> }`** — hive_reader's
  OWN pure type. Does NOT leak notatin's `CellKeyNode`. This is the same
  encapsulation discipline as `get_value_bytes` returning `(Vec<u8>, DateTime)`
  rather than a notatin value type: third-party types stay contained inside the
  primitive so a notatin upgrade cannot break consumers.

- **`list_subkeys(parser: &mut Parser, key_path: &str) -> Result<Vec<SubKey>>`** —
  index-based enumeration (approach A, chosen):
  1. `parser.get_key(key_path, false)` → parent `CellKeyNode`. Key absent ⇒
     `Ok(vec![])` (graceful — golden rule 8).
  2. read child count from the node's detail (`number_of_sub_keys()`).
  3. `for i in 0..n { node.get_sub_key_by_index(parser, i) }`, taking each child's
     `key_name` (pub field) + `last_key_written_date_and_time()`.
  Determinism: index order is the hive's physical order, NOT lexicographic — the
  CONSUMER sorts (amcache sorts emitted records by path, mirroring shimcache).

- **`get_value_string(parser, key_path, value_name) -> Result<Option<String>>`** —
  `CellValue::String(s)` ⇒ `Some(s)`; any other variant (incl. Binary) ⇒ `None`.
  Same layer / `hive_err` / graceful semantics as `get_value_bytes`.

### Harvest layer — `amcache.rs` (new file; InventoryApplicationFile mapping only)

`AmcacheCollector` (`#[derive(Default)]`, the shimcache AtomicBool-flag pattern):
privilege gate → `VolumeReader::open(r"\\.\C:")` → `open_hive(&AMCACHE_HIVE)` →
truncated / `LogStatus::Failed` handling (copied from shimcache) →
`list_subkeys(INVENTORY_APP_FILE_KEY)` → per subkey, `get_value_string` for the
fields + the pure `parse_sha1_from_fileid` → map to `Record::Execution`.

`OpenedHive.parser` is borrowed `&mut` repeatedly (once by `list_subkeys`, then
once per subkey by `get_value_string`); all sequential, single-threaded — no
borrow conflict. notatin's lazy cursor mutates on every lookup, which is why the
primitives take `&mut Parser`.

## 2. Data flow & field/SHA1 parsing

InventoryApplicationFile values used this segment (cross-checked against KAPE's
AmcacheParser field names — not guessed):

| value name          | type   | use                              | when absent                         |
|---------------------|--------|----------------------------------|-------------------------------------|
| `LowerCaseLongPath` | REG_SZ | full path (primary path source)  | fall back to `Name`                 |
| `Name`              | REG_SZ | file name (path fallback)        | None                                |
| `FileId`            | REG_SZ | `0000` + 40-hex SHA1             | sha1 = None                         |

If BOTH `LowerCaseLongPath` and `Name` are absent, the entry is DROPPED (an
execution-evidence record with no path is meaningless). This is a local
best-effort drop — it does NOT set an abstain flag.

`first_run` ← the subkey's `last_write` (from `list_subkeys`, i.e.
`last_key_written_date_and_time`) — the industry-accepted Amcache first-seen /
first-exec approximation. `last_run` = None. `run_count` = None. `user_sid` = None.
`execution_confirmed` = `Some(true)` — an Amcache InventoryApplicationFile entry
means the OS registered the file as an executable (distinct from shimcache's
"presence != execution", which sets `execution_confirmed` from a data flag).

`source` = `"amcache"`. ExecutionRecord already has every field — **schema unchanged**.

### `parse_sha1_from_fileid(field: &str) -> Option<String>` (pure, never-panic)

1. `field.len() == 44` (else None — also guards short-string slicing).
2. first 4 chars == `"0000"` (literal ASCII digits; no case applies).
3. take `[4..]` (40 chars; safe because len is already known == 44).
4. all 40 chars `is_ascii_hexdigit()` (accepts both `a-f` and `A-F`).
5. pass ⇒ `Some` of the 40-char hex lowercased; any failure ⇒ `None`.

Decision (NFR12 honesty): a non-conforming FileId yields `sha1 = None` but the
entry is STILL emitted (the path is itself execution evidence). We never write a
malformed value into `sha1` — an analyst pasting a wrong "SHA1" into VirusTotal
would get false misses; abstaining on the hash is the honest choice.

### Determinism (NFR4)

`get_sub_key_by_index` order is physical, not sorted. After mapping to records,
amcache sorts by path (mirrors shimcache). Cost: one `Vec` held fully in memory;
entry count (a few thousand) is far below the memory ceiling. Acceptable.

## 3. Error handling & NFR12 abstain matrix

Reuses shimcache's three-AtomicBool pattern, but the third trigger differs:
Amcache is a STRUCTURED hive, not a single versioned blob, so it has no
"unknown format magic". Its build-variance signal is instead "the key is absent".

| situation                              | handling                                   | manifest message                                                        |
|----------------------------------------|--------------------------------------------|------------------------------------------------------------------------|
| no admin / se_backup                   | privilege gate → Err BEFORE any volume open | upper layer records skip reason                                         |
| hive exceeds memory ceiling            | `abstained_truncated`=true, return empty   | `abstained: Amcache.hve exceeded memory ceiling (NFR10); not parsed`    |
| .LOG1/.LOG2 present but unreadable      | `log_replay_failed`=true, primary-only      | `log_replay_failed: transaction log present but unreadable; primary-only parse` |
| InventoryApplicationFile key absent    | `key_absent`=true, return empty (NOT error) | `abstained: InventoryApplicationFile key absent (build variance/NFR12)` |
| individual subkey missing path         | drop that entry, NO flag (local best-effort) | (none — normal)                                                       |

Rationale for the `key_absent` flag: NFR12 names Amcache as build-volatile. The
InventoryApplicationFile key may be genuinely absent on very old Win10 (<1607) or
trimmed images. The manifest MUST distinguish "enumerated to empty" from "key not
present" so an analyst can tell "no programs" from "this host's Amcache structure
is unsupported here". This closes the NFR12 honesty loop, reusing the proven
flag→manifest surfacing mechanism.

### Never-panic, both layers

`list_subkeys` / `get_value_string` run AFTER `open_hive` returns, i.e. OUTSIDE
its `catch_unwind` umbrella — identical to how shimcache's `get_value_bytes` is
called (also outside, also relying on notatin not to panic). For consistency we
keep the same handling. This is a documented accepted residual: a notatin panic
on the subkey-enumeration path is not currently caught. Risk is LOWER than blob
parsing — `get_sub_key_by_index` returns `Option` (out-of-range ⇒ None, no panic)
and the `0..n` bound is strict. The elevated e2e exercises the real path.

## 4. Testing boundary (mirrors shimcache)

- **Pure unit tests (cross-platform):** `parse_sha1_from_fileid` — conforming /
  wrong length / wrong prefix / non-hex / uppercase-normalised cases; the record
  mapping path-fallback logic (LowerCaseLongPath → Name → drop).
- **Foundation primitives:** `list_subkeys` / `get_value_string` are the ntfs+notatin
  navigation layer — like `open_hive`, verified via e2e (cannot unit-test without a
  real hive). Add a short-reader → Err no-panic guard for the AMCACHE_HIVE path.
- **Collector surface (no I/O):** no-privilege → Err; `name()` == "amcache";
  `sources()` surfaces each of the three flags (mirror shimcache's surface tests).
- **`#[ignore]` elevated e2e:** real admin + SeBackup, full chain raw `\\.\C:` →
  Amcache.hve → notatin (+ log replay) → InventoryApplicationFile → Record.
  Asserts ≥1 entry, every entry has a path, `source == "amcache"`,
  `last_run.is_none()`. Mirrors `shimcache_e2e_real_system_hive`.

## 5. selection / CLI wiring (mechanical, mirrors shimcache)

- `selection.rs`: add `"amcache"` to `RAW_NTFS` + a minimal-excludes-amcache
  symmetry test.
- `main.rs`: AVAILABLE (run block + test) gains `"amcache"`; `built_collector_names`
  becomes 7 elements + doc "six" → "seven"; a selection-gated push block after
  shimcache (mirror usn/shimcache); extend `selected_collector_names_follow_selection`.

## 6. Error → golden-rule matrix

| golden rule | how amcache honors it |
|---|---|
| #1 no evasion | read-only hive parse; no injection/patching; EDR sees a normal read |
| #3 collectors don't modify host | `VolumeReader` is GENERIC_READ + OPEN_EXISTING; never writes |
| #4 off-target output, --dry-run writes nothing, no temp files | in-memory Cursor parse (notatin ReadSeek); no temp file |
| #7 UTC RFC3339 | `last_key_written_date_and_time()` is `DateTime<Utc>`; reused directly |
| #8 graceful degrade | missing privilege/key/value → skip+record reason, never abort the run |
| forbid(unsafe) outside collectors-win | amcache.rs + hive_reader.rs add zero unsafe; raw read reuses VolumeReader |

## 7. Decomposition note (what this segment is NOT)

Out of scope this segment (each its own future segment, reusing these primitives):
InventoryApplication (installed programs), InventoryDriverBinary (BYOVD / driver
SHA1), the legacy `File` key, Programs. Also out of scope: userassist/bam
(NTUSER per-SID enumeration, Stage 3). This segment is the smallest valuable
slice that proves the extended primitives (`list_subkeys` / `get_value_string`)
and delivers the single highest-value Amcache artifact for IR.
