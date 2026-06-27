# Amcache InventoryDriverBinary Collector — Design

> FR12 raw-NTFS. Extends the existing `AmcacheCollector` to ALSO parse
> `Amcache.hve` **InventoryDriverBinary** entries (driver path + SHA1) into
> `Record::Execution` with `source="amcache_driver"` — BYOVD evidence. Reuses the
> hive_reader primitive and the existing amcache plumbing.

**Date:** 2026-06-21
**Status:** approved (design), pending plan
**Authoritative spec:** `cairn-SRS.md` §4 (amcache_collector row), NFR12, FR12
**Predecessor:** `2026-06-21-amcache-collector-design.md` (InventoryApplicationFile)

---

## 0. Scope & non-goals

In scope: add InventoryDriverBinary parsing to the EXISTING `AmcacheCollector`, via
a spec-driven shared helper that also serves the existing InventoryApplicationFile
path. One collector, one `open_hive`, two inventory keys.

Out of scope (each a future segment): InventoryApplication (installed programs), the
legacy `File` key; userassist/bam (NTUSER per-SID). Also out of scope: driver
signature fields (see §2 — schema stays unchanged; BYOVD detection is delegated to
downstream SHA1 ↔ LOLDrivers matching, which is more precise than "unsigned").

Note on golden rules: SRS §13's "kernel driver" hard-exclusion forbids CAIRN from
BEING or installing a kernel driver. READING the host's existing
driver-execution evidence is pure read-only forensics — exactly the BYOVD use case —
and violates nothing.

## 1. Architecture & layering

All changes in `crates/cairn-collectors/src/amcache.rs` (no new file).
`#![forbid(unsafe_code)]` maintained; raw read reuses `VolumeReader`; hive parse
reuses `open_hive` / `list_subkeys` / `get_value_string`. The work refactors the
current hard-coded-InventoryApplicationFile `collect` into a **spec-driven helper
called twice**.

### New data layer — `InventorySpec`

```rust
struct InventorySpec {
    /// notatin key path (key_path_has_root = false), e.g. "Root\\InventoryApplicationFile".
    key_path: &'static str,
    /// ExecutionRecord.source tag for entries from this key.
    source: &'static str,
    /// REG_SZ value holding the "0000"+40hex SHA1 (FileId / DriverId).
    sha1_value: &'static str,
    /// Path candidates, tried in order; first non-empty wins, else the entry is dropped.
    path_values: &'static [&'static str],
}

const APP_FILE_SPEC: InventorySpec = InventorySpec {
    key_path: "Root\\InventoryApplicationFile",
    source: "amcache",
    sha1_value: "FileId",
    path_values: &["LowerCaseLongPath", "Name"],
};

const DRIVER_SPEC: InventorySpec = InventorySpec {
    key_path: "Root\\InventoryDriverBinary",
    source: "amcache_driver",
    sha1_value: "DriverId",
    path_values: &["DriverName"],
};
```

Two inventory keys differ ONLY as data (two consts). The helper logic is single.
This is the chosen "extract a shared helper" approach (A), with two integrations:
- **C's testability:** the path-selection logic is a small pure function
  `extract_path` (unit-testable), not buried in the collect loop.
- **B's flexibility, deferred (YAGNI):** `path_values: &[&str]` covers both keys
  today (and most regular future keys). IF a future key's path is irregular (in the
  subkey name, or a composite), `path_values` can later grow into an enum
  `PathSource { Values(&[&str]), SubkeyName, ... }`. NOT done now — both current
  keys are "try these value names". The shape is reserved, the complexity is not paid.

### Shared helper

`collect_inventory(parser, spec, flags) -> Vec<Record>`: list_subkeys(spec.key_path)
→ per subkey graceful read → `extract_path(spec.path_values, read)` (drop if all
empty) → SHA1 from `spec.sha1_value` via the existing `parse_sha1_from_fileid` →
`Record::Execution { source: spec.source, … }`. The `flags` struct carries the
AtomicBool abstain/partial flags (`&self`), surfaced in `sources()`.

### Pure function

`extract_path(values: &[&str], read: impl FnMut(&str) -> ...) -> Option<String>`:
try each value name in order; first non-empty → Some; all empty → None. Pure
(no hive I/O of its own beyond the injected read), unit-testable.

### collect body

privilege gate → open_hive (ONCE) → truncated / log abstain (shared) →
`collect_inventory(APP_FILE_SPEC)` then `collect_inventory(DRIVER_SPEC)` → concat →
sort by path → return.

## 2. Field mapping & driver SHA1

Per-driver-subkey mapping (KAPE AmcacheParser field names; confidence note below):

| ExecutionRecord field | source |
|---|---|
| `source` | `"amcache_driver"` |
| `path` | `DriverName` (drop entry if empty) |
| `sha1` | `DriverId` via `parse_sha1_from_fileid` (same `0000`+40hex) |
| `first_run` | subkey last_write (documented first-seen approximation) |
| `last_run` / `run_count` / `user_sid` | None |
| `execution_confirmed` | `Some(true)` (OS registered the driver as a loaded image) |

**Confidence statement (honest):** `DriverId` = `0000`+40hex is high-confidence (same
origin as FileId; reuses the same parser). `DriverName` as the path value and
`Root\InventoryDriverBinary` as the key path are MEDIUM-confidence — this is Amcache
format knowledge, not a notatin API. Mitigation: every key/value name is isolated in
the single `DRIVER_SPEC` const; the elevated e2e is the final verification; if the
real hive shows the path lives in the subkey name, the fix is one const line (the
reserved-flexibility point from §1).

**Why no signature field (per the approved decision):** ExecutionRecord has no
`signed`/`signer`; adding it would change the schema (affecting all Execution sources)
and the signature value names are build-volatile (NFR12 misread risk). BYOVD detection
is delegated downstream: an analyst matches the emitted SHA1 against LOLDrivers /
loldrivers.io, which precisely identifies known-malicious drivers — stronger than an
"unsigned" heuristic (many unsigned drivers are legitimate).

## 3. Error handling & abstain matrix

Reuses the existing flag pattern, with `key_absent` SPLIT into two per-key flags so
the manifest distinguishes which inventory key is unsupported (NFR12 honesty).

| situation | handling | manifest message |
|---|---|---|
| no admin / se_backup | gate → Err before any volume open | upper layer records skip |
| hive exceeds ceiling | `abstained_truncated` + return empty | (existing message) |
| .LOG1/.LOG2 unreadable | `log_replay_failed` + continue | (existing message) |
| InventoryApplicationFile absent/empty | `app_key_absent`; app section empty, **driver section still runs** | `abstained: InventoryApplicationFile key absent (build variance/NFR12)` |
| InventoryDriverBinary absent/empty | `driver_key_absent`; driver section empty, **app section still runs** | `abstained: InventoryDriverBinary key absent (build variance/NFR12)` |
| individual subkey missing path / read Err | drop / skip; read Err sets `entry_read_errors` | (existing "partial" message) |

**Independent per-key degrade:** one key absent does NOT suppress the other (a key
that early-returns empty must not abort the whole collect — the current code's single
`return Ok(vec![])` on empty becomes "this spec yields empty, continue to the next
spec"). This is a strict improvement over the current single-key early return, fully
aligned with golden rule 8.

**Never-panic / DoS:** helper reuses `list_subkeys` (with its `SUBKEY_PREALLOC_CAP`
guard) + the graceful read closure; never-panic unchanged. `extract_path` is pure
string ops.

## 4. Testing boundary

- **Pure unit tests (cross-platform):** `extract_path` (in-order try, all-empty →
  None, first-non-empty wins). Driver SHA1 reuses the existing
  `parse_sha1_from_fileid` tests (same function).
- **Collector surface (no I/O):** existing surface tests extended — `app_key_absent`
  and `driver_key_absent` each surface their own message (replacing the single
  `key_absent` test); `name()` still "amcache" (one collector).
- **No regression:** existing app-section behaviour (source="amcache", field mapping)
  must be preserved — keep the existing app assertions.
- **`#[ignore]` elevated e2e:** extend the existing e2e. Assert the overall collect
  is non-empty (app chain always populated on a real host). For EVERY emitted record,
  validate the contract (source ∈ {amcache, amcache_driver}, non-empty path, last_run
  None, SHA1 when present is 40 lowercase hex, execution_confirmed Some(true)). Do NOT
  hard-require ≥1 driver entry (a freshly-imaged VM may have few), but if any
  `amcache_driver` record IS present, it must pass the same per-record contract —
  which the loop already enforces. This keeps the assertion precise without depending
  on a specific host's driver count.

## 5. selection / CLI wiring

**Near-zero wiring** — the payoff of "one collector emits two kinds".
`AmcacheCollector` is already registered in `AVAILABLE` / `RAW_NTFS` / the run-arm
push block. The driver records are just an additional output of the same collector:
**no change to `selection.rs` or `main.rs` wiring**. The only thing to check during
the refactor: any test asserting amcache emits a single source — update if present.

This confirms the merge-into-existing-collector choice: zero wiring change, one
`open_hive` (vs a separate collector needing 3 wiring sites and a second hive open).

## 6. Golden-rule matrix

| golden rule | how this honors it |
|---|---|
| #1 no evasion | read-only hive parse; no driver loading/injection; EDR sees a normal read |
| #3 collectors don't modify host | VolumeReader is GENERIC_READ + OPEN_EXISTING |
| #4 off-target / no temp files | in-memory Cursor parse; no temp file |
| #7 UTC RFC3339 | `last_key_written_date_and_time()` is `DateTime<Utc>` |
| #8 graceful degrade | per-key + per-subkey degrade; never abort the run |
| forbid(unsafe) outside collectors-win | zero new unsafe; raw read reuses VolumeReader |

## 7. Decomposition note

This segment delivers BYOVD execution evidence (driver path + SHA1) by extending the
amcache collector with a second inventory key, proving the spec-driven helper. The
spec-driven shape makes the NEXT amcache key (InventoryApplication, etc.) a one-const
addition. Driver signature data, userassist/bam, and other Amcache namespaces remain
future segments.
