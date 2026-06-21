# Prefetch Collector — Design

> FR12 / SRS Stage 2. Parse `C:\Windows\Prefetch\*.pf` (Win10+ MAM-compressed) into
> `Record::Execution` with real run_count + first/last run times. The first collector
> that does NOT touch raw-NTFS — standard file API, admin only (no SeBackup).

**Date:** 2026-06-21
**Status:** approved (design), pending plan
**Authoritative spec:** `cairn-SRS.md` §4 (prefetch_collector row), NFR12, FR12
**New dependency:** `compcol` (MIT, 100% safe, xpress_huffman feature only)

---

## 0. Scope & non-goals

In scope: enumerate `C:\Windows\Prefetch\*.pf`, MAM-decompress (Win10+), parse the
prefetch header, emit ONE `Record::Execution` per file with run_count + first/last
run times. Recognised versions only (Win10 v30; Win11 added once verified by e2e).

Out of scope: the mapped-files / loaded-modules section (hundreds of paths per file,
no Record field, would bloat output — YAGNI); all 8 run-times as separate records
(we keep newest+oldest); driver/other artifact types. Out of scope by nature: raw
volume reads (the .pf files are NOT OS-locked — see §1).

This is the project's first NON-raw-NTFS offline collector. It uses the standard
file API (`std::fs`), needs only Administrator (NOT SeBackup), and adds zero unsafe.
SRS §4 confirms prefetch's privilege is `admin` (not `admin+SeBackup`), validating
this.

## 1. Architecture & layering

New file `crates/cairn-collectors/src/prefetch.rs` (`#![forbid(unsafe_code)]` kept;
does NOT touch VolumeReader / raw-NTFS / unsafe — the biggest simplification vs every
prior raw-NTFS collector). `compcol` is the one new dependency
(`default-features = false`, only the `xpress_huffman` feature; Cargo.lock pins the
exact version per NFR7, easing its frequent breaking releases).

Three layers:

### Decompression wrapper — `decompress_mam(raw: &[u8]) -> Result<Vec<u8>>`
Check the `MAM\x04` magic (offset 0, 4 bytes) + read the uncompressed size (offset 4,
u32) → run compcol's `xpress_huffman` decoder → return decompressed bytes. A non-MAM
file (older uncompressed Win8 .pf) is returned as-is (passthrough). Decompression
failure → Err (the caller abstains on that file).

### Pure parser — `parse_prefetch(buf: &[u8]) -> Option<PrefetchInfo>`
No I/O, never-panic (bounds-checked rd_* readers, same style as usn/shimcache). Read
the header format version (offset 0, u32): this segment hard-supports ONLY Win10
version 30 (the most widespread). Win11/24H2 may use a different version number; rather
than guess it, the e2e on a real Win11 host confirms the actual value and it is added
as a one-line const change THEN. Any unrecognised version → None (abstain). Returns a
hive_reader-style OWN pure type:
```rust
struct PrefetchInfo {
    exe_name: String,              // executable name from the header (NAME ONLY — see §2)
    run_count: u32,
    run_times: Vec<DateTime<Utc>>, // up to 8, zeros filtered out
}
```

### Collector — `PrefetchCollector`
`#[derive(Default)]` + AtomicBool flags. Flow: privilege gate (admin only) →
`std::fs::read_dir(PREFETCH_DIR)` enumerate `*.pf` → per file `std::fs::read` →
`decompress_mam` → `parse_prefetch` → map to `Record::Execution` → sort by path → return.

`PrefetchInfo` is the collector's own pure type (does not leak compcol or parser
internals), same encapsulation discipline as hive_reader's `SubKey`.

## 2. Data flow & mapping

Each .pf → one `Record::Execution`:

| field | source |
|---|---|
| `source` | `"prefetch"` |
| `path` | `exe_name` (header executable NAME — see honesty note) |
| `run_count` | header run count |
| `last_run` | newest of run_times (a REAL execution time, not an approximation) |
| `first_run` | oldest of run_times (real) |
| `execution_confirmed` | `Some(true)` (prefetch = definitely executed) |
| `sha1` / `user_sid` | None |

Prefetch is the first collector with genuine run_count + real first/last run times —
shimcache/amcache could only approximate. This is its core forensic value.

**Honesty note (NFR12):** the .pf header's executable name is a bare filename (e.g.
`NOTEPAD.EXE`), NOT a full path — the full path lives only in the mapped-files section
we deliberately don't parse. So `path` is filename-granularity, not a directory path.
We do NOT disguise a filename as a path; downstream cross-references amcache/mft by the
same exe name for the full path. This is a prefetch-format limitation, documented, not
a defect.

**run_times handling:** the 8 slots are zero-padded when fewer runs exist;
`filetime_to_utc(0)` returns None (reusing the existing helper), so zeros are filtered
out — run_times holds only real times. last_run = max, first_run = min. If run_times is
empty (all zero — anomalous), last_run/first_run = None but the record is still emitted
(run_count + path still carry value).

## 3. Error handling & abstain matrix

Four separated AtomicBool flags so the manifest distinguishes the failure mode. Every
file degrades independently — a Prefetch dir often holds hundreds of .pf files; one bad
file (read / decompress / version) skips ONLY that file and never aborts the collect
(golden rule 8, the amcache lesson).

| situation | handling | manifest message |
|---|---|---|
| no admin | gate → Err before enumeration | upper layer records skip |
| Prefetch dir absent/unreadable | `dir_unreadable` + return empty | `abstained: Prefetch directory absent or unreadable` |
| one .pf read fails (lock/IO) | skip file + `file_read_errors` | `partial: one or more .pf files unreadable` |
| one .pf decompress fails | skip file + `decompress_errors` | `partial: one or more .pf files failed MAM decompression` |
| one .pf version unrecognised | skip file + `unknown_version` | `abstained: one or more .pf files had an unrecognised format version (NFR12)` |

**Never-panic:** `parse_prefetch` is bounds-checked (the proven usn/shimcache rd_*
pattern); `decompress_mam` wraps compcol's return in Result (compcol claims panic-free,
but we Result-wrap and verify by e2e); directory enumeration uses `std::fs` Result chains.

## 4. Testing boundary

- **Pure unit tests (cross-platform):** `parse_prefetch` — build fake .pf header bytes,
  assert exe_name / run_count / run_times; unrecognised version → None; truncated / lying
  length → no panic; all-zero run_times → empty. `decompress_mam` — non-MAM magic
  passthrough; MAM magic round-trip using compcol's OWN encoder (docs confirm "full
  encoder and decoder"), so we can compress→decompress in-test without a real .pf fixture.
- **Collector surface (no I/O):** no-privilege → Err; `name()` == "prefetch"; each of the
  four flags surfaces its own message.
- **`#[ignore]` elevated e2e:** real admin host, full chain. Assert ≥1 record,
  source=="prefetch", run_count present, last_run.is_some() (a real host always has runs),
  execution_confirmed Some(true), path non-empty.

The compcol encoder making decompress round-trippable in unit tests is a real win — this
collector is MORE testable than the hive collectors (which needed a real hive for the
nav layer).

## 5. selection / CLI wiring

- `selection.rs`: rename `RAW_NTFS` → `HEAVY_OFFLINE` (semantic widening to "heavy
  offline collectors": the four raw-NTFS modules + prefetch); add `"prefetch"`. `minimal`
  excludes all of `HEAVY_OFFLINE`. This is the single place the profile→heavy-set
  knowledge lives; future srum/userassist join here too. The rename is mechanical (one
  const + its doc comment + the existing tests' references).
- `main.rs`: AVAILABLE (run block + test) gains `"prefetch"`; `built_collector_names`
  gains it (+ count/doc update); a selection-gated push block; extend the selection test.

Rationale for the rename over a parallel list: prefetch is heavy (hundreds of files +
decompression) and belongs with the other minimal-excluded heavy collectors, but it is
NOT raw-NTFS, so the const name `RAW_NTFS` would be a lie. `HEAVY_OFFLINE` states the
actual gating intent.

## 6. Golden-rule matrix

| golden rule | how this honors it |
|---|---|
| #1 no evasion | read-only file parse; no injection; EDR sees normal file reads |
| #3 collectors don't modify host | `std::fs::read` is read-only (reading a .pf does not modify it; atime is not a forensic-critical field) |
| #4 off-target / no temp files | in-memory decompress + parse; no temp file |
| #7 UTC RFC3339 | run times via `filetime_to_utc` → `DateTime<Utc>` |
| #8 graceful degrade | per-file degrade; dir-absent abstains; never abort the run |
| forbid(unsafe) outside collectors-win | prefetch.rs adds zero unsafe; compcol is 100% safe (forbid-unsafe crate-wide); no raw volume read |

## 7. Supply-chain note (compcol)

compcol: MIT (does not infect the signed binary), `unsafe_code = "forbid"` crate-wide
(100% safe), zero runtime dependencies, pure Rust (no FFI/C), `xpress_huffman` feature
provides a full MS-XCA §2.1 decoder. 20 releases / ~566 tests / cross-validated /
1.8k downloads-month / used by 25 crates as of 2026-06. Maintainer: Karpeles Lab
(Mark Karpelès) — noted for the record; the crate itself is technically sound (license,
safety, zero-deps, tested). We pin the exact version in Cargo.lock (NFR7) given its
frequent breaking releases, build with `default-features = false` + only `xpress_huffman`
to minimise compiled surface, and add it to `.cargo/audit.toml` only if cargo audit flags
a non-CVE advisory (mirroring the encoding/paste precedent). The elevated e2e verifies
real .pf decompression end-to-end.

## 8. Decomposition note

This is the first non-raw-NTFS offline collector and the first with genuine
run_count + real first/last run times. The HEAVY_OFFLINE rename sets up the gating for
future heavy offline collectors (srum, userassist/bam). Mapped-files parsing, all-8
run-times, and other .pf detail remain future work if a consumer needs them.
