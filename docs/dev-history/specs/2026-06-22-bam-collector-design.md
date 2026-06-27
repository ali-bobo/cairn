# BAM Collector — Design

> FR12 / SRS Stage 2 (the `userassist/bam_collector` row). Parse the SYSTEM hive's
> Background Activity Moderator (bam) UserSettings into `Record::Execution` with a real
> per-SID last-execution time. Reuses the hive_reader foundation; adds one small,
> reusable hive_reader primitive (`list_values`). First half of the S2-closeout pair
> (bam light, userassist heavy).

**Date:** 2026-06-22
**Status:** approved (design), pending plan
**Authoritative spec:** `cairn-SRS.md` §4 (userassist/bam_collector row), FR12, NFR12
**New dependency:** none (reuses notatin + VolumeReader)
**Schema change:** none (Record::Execution unchanged)

---

## 0. Scope & non-goals

In scope: from the SYSTEM hive, read `Select\Current` to pick the active ControlSet,
enumerate `{ControlSet}\Services\bam\State\UserSettings\<SID>`, and for each value emit
ONE `Record::Execution` per (SID, executable) with the last-execution FILETIME. bam
records the last background-activity time per program per user — an independent
execution-evidence source.

Out of scope: DOS-path translation of the NT device path (YAGNI — see §2 honesty note);
any bam data beyond the leading 8-byte FILETIME (the trailing bytes are
padding/sequence with no documented forensic value); userassist (the heavy half of the
S2 pair — its own segment, needs hive_reader directory enumeration + dynamic HivePath,
explicitly NOT bundled here).

## 1. Architecture & layering

Two change points, both in `crates/cairn-collectors` (`#![forbid(unsafe_code)]` kept;
reuses `cairn-collectors-win::volume::VolumeReader`; zero new dependency; zero schema
change). bam reaches a SYSTEM-only ACL-protected key (`reg query` as a normal user
returns empty — verified during brainstorm) precisely because the raw `\\.\C:` hive
read bypasses registry ACLs, reading bytes the live registry API would deny.

### 1a. hive_reader foundation extension — `list_values`

The one foundation gap. hive_reader today has `get_value_bytes`/`get_value_string`
(single known value name) and `list_subkeys` (child keys), but NO "enumerate ALL values
of a key". Add:

```rust
/// One enumerated value: its name and raw REG_BINARY bytes. hive_reader's OWN pure type
/// (mirrors SubKey) — does NOT expose notatin's CellKeyValue, so a notatin upgrade
/// cannot break consumers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeyValue {
    pub name: String,
    pub data: Vec<u8>,
}

/// Enumerate ALL values of `key_path`, returning each value's name + REG_BINARY bytes.
/// Non-binary values are skipped. Absent key => Ok(vec![]) (graceful, golden rule 8).
/// Order is the hive's physical order; the CALLER sorts for determinism.
pub(crate) fn list_values(
    parser: &mut notatin::parser::Parser,
    key_path: &str,
) -> Result<Vec<KeyValue>>;
```

**Verified notatin 1.0.1 API (read from cell_key_node.rs / cell_key_value.rs source):**
- `CellKeyNode::value_iter() -> CellKeyNodeValueIterator` (line 231); its
  `Iterator::Item = CellKeyValue` (owned, no lifetime — line 797).
- `CellKeyValue` has public `value_name: String` and `get_content() -> (CellValue, _)`;
  take `.0`, match `CellValue::Binary(b)` (same access pattern as get_value_bytes).
- notatin guards its own value vector against `number_of_key_values > 1<<20` (OOM guard,
  line 656), so the enumeration is bounded without us pre-allocating.

`get_key` is `&mut` (notatin's lazy cursor mutates on lookup), same as list_subkeys.
Absent key (get_key → None) returns `Ok(vec![])`. This primitive is reusable by future
value-enumerating consumers (userassist's Count key is the next).

### 1b. bam.rs — the collector

`BamCollector` (`#[derive(Default)]` + 4 AtomicBool flags). Privilege gate → raw read →
ControlSet resolution → per-SID enumeration → mapping. Mirrors AmcacheCollector's shape.

## 2. Data flow & mapping

```
admin+SeBackup gate → VolumeReader::open(\\.\C:) → open_hive(SYSTEM_HIVE)
  → resolve_controlset(parser)        # read Select\Current → "ControlSet001" (etc.)
  → list_subkeys({CS}\Services\bam\State\UserSettings)   # the <SID> children
  → per SID: list_values({...}\UserSettings\{SID})       # (exe NT path, data) pairs
  → per value: parse_bam_value(data) → Record::Execution
```

bam key path (notatin key_path syntax, key_path_has_root = false):
`{ControlSet}\Services\bam\State\UserSettings\{SID}`.

**ControlSet resolution** (forensic-correct, the KAPE/forensics convention): in a raw
hive there is no `CurrentControlSet` (that name is a live-registry symlink). Read the
`Select` key's `Current` value (REG_DWORD, e.g. 1) and format `ControlSet{:03}`
(→ `ControlSet001`). If `Select\Current` is unreadable/absent, fall back to
`ControlSet001` (the overwhelmingly common case) and proceed — do NOT abstain the whole
collect for a missing Select value.

Each value → one `Record::Execution`:

| field | source |
|---|---|
| `source` | `"bam"` |
| `path` | value name — the executable's NT device path (`\Device\HarddiskVolumeN\...`), kept VERBATIM |
| `last_run` | leading 8 bytes of value data, LE FILETIME, via `filetime_to_utc` |
| `user_sid` | the `<SID>` subkey name |
| `execution_confirmed` | `Some(true)` |
| `first_run` / `run_count` / `sha1` | `None` (bam carries only the last-activity time) |

Determinism (NFR4): sort emitted records by (user_sid, path).

**Honesty note (NFR12):** the bam value name is an NT device path, NOT a DOS path
(`C:\...`). We write it verbatim and do not guess the volume-letter mapping — disguising
an NT path as a DOS path would be a lie. Downstream may cross-reference `\Device\
HarddiskVolumeN` → drive letter if needed. This is a bam-format reality, documented, not
a defect.

## 3. Error handling & abstain matrix

Four separated AtomicBool flags (aligned with amcache), one manifest message each.
Every SID and every value degrades independently — a bad value/SID skips only itself and
never aborts the collect (golden rule 8).

| situation | handling | manifest message |
|---|---|---|
| no admin / no SeBackup | gate → Err before any volume open | upper layer records skip |
| SYSTEM hive > ceiling | `truncated` + return empty | `abstained: SYSTEM hive exceeded memory ceiling (NFR10); not parsed` |
| UserSettings key absent/empty | `bam_key_absent` + return empty | `abstained: bam UserSettings key absent (build variance/NFR12)` |
| .LOG1/.LOG2 present but unreadable | `log_replay_failed` | `log_replay_failed: transaction log present but unreadable; primary-only parse` |
| one value/SID read fails, OR value non-binary / data<8 | skip that value + `entry_read_errors` | `partial: one or more entries skipped (result incomplete)` |

**FILETIME==0 special case (NOT an error):** a value whose leading 8 bytes are zero
yields `filetime_to_utc(0) → None`; that value is skipped but does NOT set
`entry_read_errors`. Zero is a legitimate "no time" padding, not a malformed entry —
flagging it as `partial` would be a false alarm. Only a genuine read error or a
structurally-impossible value (non-binary / data<8) sets `entry_read_errors`.

**Never-panic:** all byte access via `data.get(0..8)` (Option, never slice-index panic);
`filetime_to_utc` has its own ft==0 guard. catch_unwind already wraps `open_hive`
internally (third-party ntfs/notatin panic containment); bam needs no extra wrapping.

## 4. Testing boundary

- **Pure unit tests (cross-platform):**
  - `parse_bam_value(data: &[u8]) -> Option<DateTime<Utc>>` — the testable core. Assert:
    a valid 8-byte LE FILETIME → Some(expected); data shorter than 8 → None (no panic);
    all-zero 8 bytes → None; trailing padding beyond 8 bytes is ignored (same result as
    exactly 8 bytes); a value with extra bytes does not panic. Use the project's
    FT_2021 = 132_539_328_000_000_000 convention for a known-value assertion.
  - `resolve_controlset` formatting — Current=1 → "ControlSet001", Current=2 →
    "ControlSet002", Current=10 → "ControlSet010" (zero-pad to 3). (Pure formatting test;
    the actual Select read is exercised by e2e.)
  - `list_values` — structural only at the primitive layer (KeyValue holds name/data);
    real enumeration needs a live hive, deferred to e2e (same policy list_subkeys used).
- **Collector surface (no I/O):** no-privilege → `Err(Privilege)`; `name()` == "bam";
  each of the four flags surfaces its own message in `sources()`.
- **`#[ignore]` elevated e2e:** real admin + SeBackup host, full chain. Assert: ≥1 record
  (an active host always has bam entries), source == "bam", last_run.is_some(),
  user_sid matches `S-1-5-...`, path non-empty, execution_confirmed == Some(true), and
  first_run / run_count / sha1 are all None (NFR12: bam never fabricates these fields).

Extracting `parse_bam_value` as a pure function is the segment's main testability lever:
FILETIME parsing is fully verified without a hive; e2e only proves the enumeration chain
+ real SID structure.

## 5. selection / CLI wiring

- `selection.rs`: add `"bam"` to `HEAVY_OFFLINE` (the existing minimal-excluded heavy set
  — bam reads the whole SYSTEM hive, belongs with the other heavy offline collectors).
- `main.rs`: AVAILABLE (run block + test) gains `"bam"`; `built_collector_names` gains it
  (+ count/doc update); a selection-gated push block constructing `BamCollector`; extend
  the selection test. Mirrors exactly how amcache/prefetch were wired.

bam joins via the SAME open_hive(SYSTEM_HIVE) path that shimcache already uses, so the
only genuinely new code is `list_values` + `parse_bam_value` + the SID enumeration loop.

## 6. Golden-rule matrix

| golden rule | how this honors it |
|---|---|
| #1 no evasion | read-only raw hive parse; no injection; EDR sees a normal volume read |
| #3 collectors don't modify host | VolumeReader is read-only; notatin parses in memory |
| #4 off-target / no temp files | in-memory hive read + parse (open_hive uses Cursor, no temp file) |
| #7 UTC RFC3339 | last_run via `filetime_to_utc` → `DateTime<Utc>` |
| #8 graceful degrade | per-SID + per-value degrade; key-absent abstains; never abort the run |
| forbid(unsafe) outside collectors-win | bam.rs + list_values add zero unsafe; reuse VolumeReader |

## 7. Decomposition (≈5 tasks)

1. **T1** hive_reader `list_values` primitive + `KeyValue` type (foundation; structural
   unit tests; verified value_iter API).
2. **T2** pure `parse_bam_value` (LE FILETIME of leading 8 bytes; never-panic unit tests).
3. **T3** `resolve_controlset` helper (read `Select\Current` → `ControlSet{:03}`; fallback
   ControlSet001; pure formatting unit tests).
4. **T4** `BamCollector` (privilege gate + enumeration chain + mapping + 4 flags +
   sources(); collector-surface unit tests).
5. **T5** selection/CLI wiring (HEAVY_OFFLINE + AVAILABLE + built_collector_names) +
   `#[ignore]` elevated e2e.

Lighter than amcache (no SHA1 parse, no spec-driven dual-key, simpler format).
