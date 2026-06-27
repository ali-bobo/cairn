# S2-O — Path Map: $MFT Parent-Reference Full-Path Reconstruction (design)

> **Status:** design, approved 2026-06-18.
> **Predecessor:** S2-N ($MFT MACB + SI/FN dual-axis, main 7e1decf) + S2-N′
> (timestomp delta heuristic, main 7878799).
> **Ordering note:** The committed decomposition listed S2-O as "$J/USN". This
> sub-segment is a deliberate reorder: **path map is promoted ahead of governance
> and $J** because it completes the usability of what S2-N/N′ already produce (the
> timestomp Finding currently surfaces a bare filename, not a path). $J/USN moves
> down the queue (governance still precedes the heavier raw reads). The "S2-O"
> label here is sequential; the $J work inherits the next free label.
> **Authoritative spec:** `cairn-SRS.md` §4 (collector outputs), FR12.

## 1. Scope & intent

Upgrade `FileMetaRecord.path` from a **bare filename** (the current S2-N output —
`preferred_file_name` returns only the `$FILE_NAME` name) to a **full filesystem
path** (`C:\Users\foo\evil.exe`), reconstructed by walking the `$MFT`
parent-reference chain to the root directory (record 5).

This is a **pure-logic change** in `cairn-collectors::mft` plus an additive schema
field. It adds **zero new dependencies** — `ntfs` 0.4.0 natively exposes the parent
reference via `NtfsFileName::parent_directory_reference().file_record_number()` —
keeps `cairn-collectors`'s `#![forbid(unsafe_code)]`, and **does not touch the
`cairn-collectors-win` crate or `volume.rs`**.

### Why this matters
A timestomp Finding (S2-N′) that reads `path = "evil.exe"` forces the analyst to
guess where the file lives. `C:\Users\victim\AppData\Local\Temp\evil.exe` vs
`C:\Windows\System32\evil.exe` is the difference between a 2-second triage and a
dead end. Path is the single highest-value missing field on `FileMetaRecord`.

### In scope
- A `resolve_path` pure function (parent-chain walk over an in-memory index).
- A two-phase rewrite of `parse_mft_inner` (scan→index, then resolve→emit).
- `preferred_file_name` returns the parent reference (currently discarded).
- One additive `FileMetaRecord.path_complete` field + matching `EntityFile` field.
- A `Config.resolve_mft_paths` toggle (default `true`) for a future minimal profile.

### Out of scope (explicitly)
- **No path-string pollution.** best-effort paths are clean partial real paths,
  never prefixed with `[orphan]`/`[truncated]`. Quality lives ONLY in the
  `path_complete` flag, keeping `path` clean for any string consumer.
- **No hard-link enumeration.** A record with multiple `$FILE_NAME` attributes
  (same file in multiple directories) uses the single name `preferred_file_name`
  already selects (prefers Win32/Win32AndDos). Multi-path is future work.
- **No drive-letter discovery.** $MFT carries no mount-point info; the prefix is a
  fixed `C:` matching the opened `\\.\C:` volume. We do not pretend to know others.
- **No per-suspect lazy resolution.** Path reconstruction needs ancestor records
  that are not themselves suspects, so a full index is unavoidable when enabled.
  Memory relief is the `resolve_mft_paths` toggle, not a cleverer algorithm.

## 2. Reconstruction logic

### 2.1 `resolve_path` (pure, unit-testable)

```rust
/// NTFS practical max directory nesting; also the cycle/runaway depth ceiling.
const MAX_PATH_DEPTH: usize = 255;
/// Root directory record number (NTFS fixed: KnownNtfsFileRecordNumber::RootDirectory).
const ROOT_RECORD: u64 = 5;

/// Walk parent references from `start` to root, returning (path, complete).
/// `index`: rec_num -> (name, parent_num) built in phase 1. Pure, no I/O.
fn resolve_path(start: u64, index: &HashMap<u64, (String, u64)>) -> (String, bool)
```

**Walk algorithm — the termination ORDER is the correctness crux:**

```
components: Vec<String> = []
visited:    HashSet<u64> = {}
current = start
loop up to MAX_PATH_DEPTH times:
    // ① root FIRST — record 5's $FILE_NAME parent-references ITSELF (parent = 5);
    //    this self-reference MUST terminate before the cycle check or a clean
    //    walk to root would be misflagged cyclic.
    if current == ROOT_RECORD:        complete = true;  break
    // ② cycle detection
    if !visited.insert(current):      complete = false; break   // re-visit = cyclic
    // ③ index lookup
    match index.get(current):
        Some((name, parent)) => { components.push(name.clone()); current = parent; }
        None                 => { complete = false; break }     // orphan / deleted / skipped-fragmented
// depth exhausted without break:     complete = false           // truncated
reverse components, join with '\', prefix "C:"  ->  "C:\Users\foo\evil.exe"
```

**Path formatting:**
- Clean walk to root → `C:\a\b\file`, `complete = true`. Root itself → `C:\`.
- best-effort (`complete = false`) → the partial REAL path collected so far
  (e.g. `\Users\foo`), **no pollution prefix**. The `C:` prefix is still applied
  to whatever was collected, so a best-effort path reads `C:\Users\foo` — a clean
  (if incomplete) path. The flag, not the string, signals incompleteness.

**Edge cases (all covered by tests):**
- `start == 5` → `C:\`, complete (degenerate but valid).
- `start`'s parent == 5 → one component then root, complete.
- `start` not in index → immediate None branch → best-effort (won't happen in
  practice since pending is built from index, but defended anyway).

### 2.2 Why a HashMap index (decided in brainstorm)

Walking a chain needs the `(name, parent)` of **arbitrary ancestor records**,
which are typically not suspects. A full `rec_num -> (name, parent)` map built in a
first pass is therefore required; resolution is a deterministic second pass. The
rejected single-pass alternative (re-reading each parent via `ntfs.file(parent)` at
emit time) costs O(depth) repeated I/O per record and re-enters the ntfs parser
(another error surface) — slower and riskier on millions of records.

## 3. Schema changes (additive, backward-compatible)

serde fills a missing `Option` with `None`, so old JSONL (FR1 replay) round-trips.

### 3.1 `FileMetaRecord` (`crates/cairn-core/src/record.rs`)

```rust
/// Path-resolution quality (path map): Some(true) = walked clean to root (C:\);
/// Some(false) = best-effort (orphan/truncated/cyclic — `path` is a partial REAL
/// path fragment, never prefixed/polluted); None = resolution disabled or no path.
/// The `path` string itself stays a clean filesystem path for any string consumer.
pub path_complete: Option<bool>,
```

### 3.2 `EntityFile` (`crates/cairn-core/src/finding.rs`)

Add `pub path_complete: Option<bool>,` so a timestomp Finding carries the path
quality alongside its four-axis evidence (S2-N′ precedent). Every existing
`EntityFile { .. }` constructor adds `path_complete: None` — the compiler
enumerates the sites.

### 3.3 `Config` (`crates/cairn-core/src/config.rs`)

```rust
/// Reconstruct full file paths from $MFT parent references (path map, S2-O).
/// false → fall back to S2-N bare-filename behaviour (path_complete = None),
/// the first optional enhancement to drop under a future minimal profile.
pub resolve_mft_paths: bool,   // default true
```

Default `true` in `Config::default()`. No CLI flag yet (the future governance
`--profile minimal` will flip it; a standalone flag is YAGNI until then).

## 4. Two-phase integration (`parse_mft_inner`)

The `resolve_mft_paths` flag selects the path:

```rust
fn parse_mft_inner<R>(src, max_records, resolve_paths: bool)
    -> Result<(u64, Vec<FileMetaRecord>)>
{
    let ntfs = Ntfs::new(src)?;                 // unchanged
    let ceiling = capacity.min(max_records);    // unchanged

    if !resolve_paths {
        // `scan_bare` is a module-private helper (extracted, not inline): the exact
        // S2-N single-pass loop, emitting path = bare filename + path_complete: None.
        return scan_bare(src, ntfs, ceiling, capacity);
    }

    // ── Phase 1: scan + build index ──
    let mut index: HashMap<u64, (String, u64)> = HashMap::new();  // rec -> (name, parent)
    let mut pending: Vec<Skeleton> = Vec::new();                  // times only; NO name
    for rec_num in 0..ceiling {
        let file = match ntfs.file(src, rec_num) { Ok(f) => f, Err(_) => continue };
        let (name, parent, fn_b, fn_m) = match preferred_file_name(&file, src) {
            Some(t) => t, None => continue,
        };
        let si = file.info().ok();
        index.insert(rec_num, (name, parent));
        pending.push(Skeleton { rec_num, si_b, si_m, fn_b, fn_m });
    }

    // ── Phase 2: resolve + emit ──
    let mut out = Vec::new();
    for sk in pending {
        let (path, complete) = resolve_path(sk.rec_num, &index);
        out.push(FileMetaRecord {
            path, path_complete: Some(complete),
            si_btime: sk.si_b, si_mtime: sk.si_m, fn_btime: sk.fn_b, fn_mtime: sk.fn_m,
            size: 0, sha256: None, zone_identifier: None,
        });
    }
    Ok((capacity, out))
}
```

- `preferred_file_name` signature changes to return the parent reference:
  `Option<(String /*name*/, u64 /*parent rec*/, u64 /*fn_b raw*/, u64 /*fn_m raw*/)>`,
  obtained from `fname.parent_directory_reference().file_record_number()`.
- `Skeleton` is a module-private struct holding `rec_num` + four `Option<DateTime>`
  only — **no name** (name lives in `index`, borrowed by `resolve_path`). Memory
  adds one index map; the name is NOT stored twice.

## 5. Error handling (golden rule 8 — unchanged posture)

- Both S2-M/N DoS guards are **fully preserved**, wrapping the whole two-phase scan:
  guard (a) 512-byte boot-sector pre-check, guard (b) `catch_unwind` around the parse.
- Phase-1 per-record `continue` isolation is unchanged (bad record skipped, not aborted).
- Phase-2 `resolve_path` is pure and never-panics: depth ceiling + visited set +
  no unchecked arithmetic. Any pathological chain returns best-effort, never aborts.
- **Orphans are honest:** a parent pointing at a record skipped in phase 1 (the
  documented `$ATTRIBUTE_LIST`-fragmentation skip, or a deleted directory) yields a
  `None` branch → `path_complete = false`. This is consistent with the existing
  module-doc disclosure; the gap is now *surfaced per-record* via the flag.

## 6. Peak memory (NFR10 — honest module-doc update)

S2-N's doc says the scan "holds up to `max_mft_records` `FileMetaRecord`s in a Vec".
With path resolution ENABLED, peak adds one `HashMap<rec -> (name, parent)>` (bounded
by the same record cap; the name is stored once, not duplicated into pending). With
the toggle DISABLED, behaviour reverts exactly to S2-N's single-Vec footprint. The
module doc must be updated to state both, so the bound is auditable.

## 7. Determinism

Records emit in `pending` (i.e. `rec_num`) order; the orchestrator sorts the final
timeline by `(ts, record_id)` (CLAUDE.md). `resolve_path` is deterministic for a
fixed index. `HashMap` is used only as a lookup index, never iterated for output.

## 8. Testing strategy (TDD)

`resolve_path` pure-function tests (feed a synthetic `HashMap`; no ntfs, no volume):

- `resolves_clean_path_to_root` — 5(root), a(parent 5), b(parent a), file(parent b)
  → `C:\a\b\file`, complete=true.
- `root_self_reference_not_cyclic` — **correctness crux**: a file whose chain ends
  at record 5 resolves to `C:\…`, complete=true, NOT misflagged cyclic (proves the
  root-before-cycle termination order).
- `root_record_itself_resolves_to_c_backslash` — start==5 → `C:\`, complete=true.
- `cycle_returns_best_effort` — A(parent B), B(parent A) → complete=false, partial path.
- `orphan_parent_missing_best_effort` — parent not in index → complete=false.
- `depth_ceiling_truncates` — a 256-deep chain → stops at MAX_PATH_DEPTH, complete=false.
- `best_effort_path_not_polluted` — a best-effort path is a clean partial path with
  NO `[orphan]`/`[truncated]` prefix (only the flag signals incompleteness).
- `bare_filename_when_disabled` — `resolve_paths=false` → `scan_bare` path → `path`
  == filename, `path_complete == None` (S2-N parity, resolution off).

Schema tests:
- `filemeta_path_complete_roundtrips_and_old_json_none` — new field round-trips;
  old JSONL lacking it deserializes to `None`.
- `entityfile_path_complete_roundtrips`.
- `config_resolve_mft_paths_defaults_true`.

Existing mft.rs guard (a)/(b) and privilege tests are preserved and must not regress.

## 9. Acceptance gate (same bar as S2-N′)

- `cargo test --workspace --locked` — all green (258 current + new).
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — 0 warnings.
- `cargo fmt --check` — clean.
- `cargo audit --deny warnings` — clean.
- **`Cargo.lock` unchanged vs main** (zero new dependency).
- `#![forbid(unsafe_code)]` preserved in `cairn-collectors` and `cairn-core`.
- Non-admin smoke still degrades cleanly (mft skipped without admin → no records).
- **Elevated-e2e gap (honest):** real full-path assembly on a live volume (root
  termination, real orphans/cycles) is only verifiable under Administrator +
  SeBackupPrivilege on a real disk. The pure `resolve_path` already exhausts ALL
  chain logic on the dev box via synthetic HashMaps; the elevated e2e only confirms
  "a real volume actually assembles `C:\...`" — a thin integration check, not new logic.

## 10. Interaction with existing analyzers

S2-N′'s `TimestompHeuristic` treats `path` as a free-form evidence string (entity /
details); it does NOT parse it. A best-effort `path` therefore does not break
timestomp, and `path_complete` is **bonus context** the analyst can use. No analyzer
change is needed. (When path_complete is wired into `EntityFile`, the timestomp
analyzer may optionally copy it through — a one-line additive carry, decided in the plan.)

## 11. Threat-model note (think-like-an-attacker)

- **Input:** `parent_num` is an **attacker-controllable on-disk value**. A corrupt
  or planted $MFT can craft cycles, absurd depth, or a parent pointing at any record.
- **Mitigation:** visited set + `MAX_PATH_DEPTH` ceiling + best-effort degrade, all
  never-panic. A malformed chain costs at most MAX_PATH_DEPTH lookups (bounded), then
  returns a flagged partial path.
- **Evasion the attacker WANTS:** make a file's path resolve as best-effort to *hide*
  where it lives. Residual: they can force `path_complete=false`, but that flag
  **explicitly tells the analyst the path is untrustworthy** — loud-but-explained,
  the same triage stance as S2-N′'s known-FP disclosure. The attacker cannot make a
  WRONG path look complete without also controlling the (kernel-written) ancestor
  chain consistently up to root, a much higher bar.
- **No host effect:** pure reconstruction over already-read data; no extra host I/O
  beyond the existing capped scan; cannot modify artifacts or host (golden rule 3/4).
