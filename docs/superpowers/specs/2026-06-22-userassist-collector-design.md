# UserAssist Collector — Design

> FR12 / SRS Stage 2 (the `userassist/bam_collector` row). Parse each user's
> `C:\Users\<name>\NTUSER.DAT` UserAssist into `Record::Execution` with real GUI launch
> count + last-execution time. The LAST S2 collector — completing it closes out Stage 2.
> Heavier than bam: extends the hive_reader foundation (dynamic HivePath + directory
> enumeration) and reaches per-user hives.

**Date:** 2026-06-22
**Status:** approved (design), pending plan
**Authoritative spec:** `cairn-SRS.md` §4 (userassist/bam_collector row), FR12, NFR12
**New dependency:** none (reuses notatin + ntfs + VolumeReader)
**Schema change:** none (Record::Execution unchanged)

---

## 0. Scope & non-goals

In scope: enumerate `C:\Users\<name>` directories, open each `NTUSER.DAT`, read
`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`, ROT13-decode
each value name (the executable path), parse run_count + last-execution FILETIME from the
value data, and emit one `Record::Execution` per (user, executable). Resolve `user_sid`
by reverse-lookup against the SOFTWARE hive's ProfileList.

Out of scope: the focus-time / focus-count fields in the UserAssist struct (no Record
field; YAGNI); expanding known-folder GUIDs in the decoded path (kept verbatim, NFR12);
bam (its own already-merged segment).

## 1. Verified facts (all confirmed during brainstorm — do NOT re-litigate)

- **ntfs 0.4 directory enumeration EXISTS** (the segment's biggest risk, resolved): the
  pattern from the crate's own `ntfs-shell` example (main.rs:308-322) is
  `dir.directory_index(fs)?.entries()` → `iter.next(fs)` (streaming) →
  `entry.key()` returns `Option<Result<NtfsFileName>>` → `.name()` / `.is_directory()`.
  No hand-rolling needed.
- **UserAssist struct (verified on this Win11 host via reg query + byte analysis):**
  value name = ROT13-encoded path (`HRZR_PGYFRFFVBA` → `UEME_CTLSESSION`); value data =
  **72 bytes**; **run_count = u32 @ offset 4**; **last-run FILETIME = u64 @ offset 60**.
  Cross-checked: a Notepad entry showed run_count=4 and FILETIME = today. NO version
  drift (matches the classic Win7+ layout — unlike prefetch's v30/v31 surprise).
- **ROT13** confirmed (`HRZR`↔`UEME`).
- **HivePath const→fn refactor is feasible and bounded:** `const` cannot hold an owned
  `Vec<String>`, so `SYSTEM_HIVE`/`AMCACHE_HIVE` become fns returning an owned `HivePath`.
  This touches exactly 7 call sites (`&SYSTEM_HIVE` → `&SYSTEM_HIVE()` etc.) across
  shimcache/amcache/bam + 2 hive_reader tests. `open_hive`'s body is unchanged except
  the loop var becomes `&String` (deref-coerces to the `&str` that `find_child_dir`
  takes). Three existing tests guard against regression.

## 2. Architecture & layering

All changes in `crates/cairn-collectors` (`#![forbid(unsafe_code)]` kept; reuses
VolumeReader; zero new dependency; zero schema change).

### 2a. hive_reader foundation extension

**(i) Dynamic HivePath.** `HivePath.components` changes from `&'static [&'static str]`
to owned `Vec<String>`. `SYSTEM_HIVE`/`AMCACHE_HIVE` change from `const` to `fn`s
returning a `HivePath` (build via `.to_string()`). Add
`HivePath::user_ntuser(user_dir_name: &str) -> HivePath` building
`["Users", <name>, "NTUSER.DAT"]`. `open_hive`'s signature is unchanged (`&HivePath`);
its body's component loop yields `&String` (coerces to `&str`). The 7 call sites gain
`()`.

**(ii) Directory enumeration.** Add
`list_dir_names(reader, dir_path: &HivePath) -> Result<Vec<String>>`: navigate to
`dir_path` (reusing the same find-child chain open_hive uses for the parent dirs), then
`directory_index(reader)?.entries()` + `next(reader)` streaming, collecting
`entry.key()?.name().to_string_lossy()` for entries where `is_directory()` and the name
is not `.`/`..`. Returns hive_reader-owned `Vec<String>` (no ntfs type leakage).
NOTE: this enumerates a DIRECTORY on the volume (for `C:\Users`), distinct from
`list_subkeys` which enumerates registry KEYS inside a parsed hive. It takes the raw
`reader`, not a notatin Parser.

**(iii)** `list_values` (REG_BINARY value enumeration) already exists from the bam
segment — reused directly for the Count key.

### 2b. userassist.rs — the collector

`UserAssistCollector` (`#[derive(Default)]` + four AtomicBool flags). Mirrors bam/amcache
shape; the new shape is the per-user outer loop + the ProfileList reverse-lookup.

## 3. Data flow & mapping

```
admin+SeBackup gate → VolumeReader::open(\\.\C:)
  → open SOFTWARE hive once → read ProfileList\<SID>\ProfileImagePath
      → build { lowercased C:\Users\<name>  →  SID } reverse map
  → list_dir_names("Users")  → each <name>
      → open_hive(HivePath::user_ntuser(<name>))   [per-user; missing file = skip]
          → for each GUID subkey under
              Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist :
              list_subkeys → find the "Count" child → list_values(Count)
              → per value:
                  path  = rot13(value name)
                  (run_count, last_run) = parse_userassist(value data)
          → user_sid = reverse_map[ lowercased "C:\Users\<name>" ]  else None
  → Record::Execution
```

UserAssist key path inside a NTUSER hive (notatin key_path, key_path_has_root=false):
`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`. We
`list_subkeys` the UserAssist key to get the `<GUID>` names, then for each GUID build the
fixed path `...\UserAssist\<GUID>\Count` directly (Count is a constant child name — no
second list_subkeys needed) and `list_values` it.

Each value → one `Record::Execution`:

| field | source |
|---|---|
| `source` | `"userassist"` |
| `path` | `rot13(value name)` — the executable path, verbatim (known-folder GUID abbreviations kept; NFR12) |
| `run_count` | value data u32 @ offset 4 |
| `last_run` | value data FILETIME @ offset 60 → `filetime_to_utc` |
| `user_sid` | ProfileList reverse-lookup of `C:\Users\<name>`; `None` if not found |
| `execution_confirmed` | `Some(true)` |
| `first_run` / `sha1` | `None` |

Determinism (NFR4): sort emitted records by (user_sid, path).

Scan ALL `C:\Users\` subdirectories; a directory with no NTUSER.DAT (system accounts,
Default, Public) or no UserAssist key is skipped gracefully. We do NOT hard-code a
system-account blacklist — existence drives filtering.

**ProfileList reverse-lookup:** read each `ProfileList\<SID>` subkey's `ProfileImagePath`
(REG_SZ / REG_EXPAND_SZ, e.g. `C:\Users\alice`), keyed lowercased → SID. A user dir with
no matching ProfileList entry gets `user_sid = None` (still emits records). ProfileList
read failure does NOT set an abstain flag (it is enrichment, not core data).

**Honesty note (NFR12):** the decoded path may contain a known-folder GUID prefix (e.g.
`{F38BF404-...}\NOTEPAD.EXE` for System32). We keep it verbatim — expanding the GUID
would require a folder-id table we don't ship; downstream can resolve it. Not a defect.

## 4. Error handling & abstain matrix

Four separated AtomicBool flags (aligned with bam/amcache). Every user dir and every
value degrades independently — one bad hive/value never aborts the collect (golden rule 8).

| situation | handling | manifest message |
|---|---|---|
| no admin / no SeBackup | gate → Err before any volume open | upper layer records skip |
| `C:\Users` enumeration fails | `users_dir_unreadable` + return empty | `abstained: C:\Users enumeration failed (NFR12)` |
| no NTUSER had a UserAssist key | `no_userassist` + return empty | `abstained: no UserAssist key in any user hive (build variance/NFR12)` |
| a NTUSER's .LOG was unreadable | `log_replay_failed` | `log_replay_failed: a user hive's transaction log was unreadable; primary-only` |
| a NTUSER fails to OPEN (exists but unreadable), or a value/struct is malformed | skip that item + `entry_read_errors` | `partial: one or more user hives or entries skipped (result incomplete)` |

**Missing NTUSER.DAT is NOT an error.** Many `C:\Users` dirs (system accounts, Default,
Public) legitimately have no parseable NTUSER.DAT. "File simply not present" → graceful
skip, NO `entry_read_errors` flag. Only a NTUSER that EXISTS but fails to open/parse sets
the flag. (Same spirit as bam's "ft==0 is not partial".) Distinguishing absent-vs-broken
relies on open_hive: a navigation "not found" for NTUSER.DAT is absent (skip silently);
any other open_hive Err is a genuine read failure (skip + flag).

**ProfileList lookup failure** → `user_sid = None`, record still emitted, no flag.

**Never-panic:** `rot13` is a pure ASCII rotate (non-alpha bytes pass through, no panic);
`parse_userassist` uses `data.get(4..8)` / `data.get(60..68)` (Option, never slice-index);
`filetime_to_utc` has its own ft==0 guard. catch_unwind already wraps each `open_hive`.

## 5. Testing boundary

- **Pure unit tests (cross-platform):**
  - `rot13(s) -> String`: `UEME_CTLSESSION`↔`HRZR_PGYFRFFVBA` round-trip; non-alpha
    chars pass through unchanged; empty string; mixed case; a `{GUID}` path fragment
    round-trips (digits/braces untouched).
  - `parse_userassist(data) -> Option<(u32, Option<DateTime<Utc>>)>`: a valid 72-byte
    record (run_count @ 4, FILETIME @ 60) → Some((n, Some(dt))); data shorter than 68 →
    None (no panic); FILETIME==0 → Some((n, None)) (run_count present, last_run absent);
    a fixture built from the brainstorm-verified bytes (run_count 4, FILETIME today).
  - `HivePath::user_ntuser("alice")` → components `["Users","alice","NTUSER.DAT"]`;
    `SYSTEM_HIVE()` / `AMCACHE_HIVE()` still return the correct component paths (regression
    guard that the const→fn refactor preserved them).
  - `list_dir_names`: structural only at the primitive layer (real enumeration needs a
    volume → e2e), same policy list_subkeys/list_values used.
- **Collector surface (no I/O):** no-privilege → `Err(Privilege)`; `name()` ==
  "userassist"; each of the four flags surfaces its own message.
- **`#[ignore]` elevated e2e:** real admin+SeBackup host, full chain. Assert: ≥1 record
  (this host has at least the current user's UserAssist), source == "userassist",
  run_count present, at least one record's last_run.is_some(), path non-empty,
  execution_confirmed == Some(true), first_run/sha1 == None. Print diagnostics (record
  count + sources() errors via the SAME collector instance) so an empty result is
  explainable (not elevated vs genuinely empty).

`rot13` + `parse_userassist` as pure functions are the main testability lever: all format
parsing is verified without a hive; e2e only proves the directory-enumeration + per-user
open + ProfileList reverse-lookup integration chain.

## 6. selection / CLI wiring

- `selection.rs`: add `"userassist"` to `HEAVY_OFFLINE` (minimal-excluded) + one
  `minimal_excludes_userassist` test.
- `main.rs`: add `"userassist"` to both AVAILABLE arrays + `built_collector_names` (+
  count/doc: "nine" → "ten"); a selection-gated push block; a wiring test assertion; and
  the canonical-order assert_eq list. Mirrors exactly how bam was wired.

## 7. Golden-rule matrix

| golden rule | how this honors it |
|---|---|
| #1 no evasion | read-only raw hive + directory parse; EDR sees normal volume reads |
| #3 collectors don't modify host | VolumeReader + notatin are read-only; in-memory |
| #4 off-target / no temp files | in-memory hive read + parse (open_hive uses Cursor) |
| #7 UTC RFC3339 | last_run via `filetime_to_utc` → `DateTime<Utc>` |
| #8 graceful degrade | per-user + per-value degrade; absent NTUSER skips silently; dir-fail abstains; never abort the run |
| forbid(unsafe) outside collectors-win | userassist.rs + the two new hive_reader primitives add zero unsafe; reuse VolumeReader |

## 8. Decomposition (≈6 tasks; one more than bam due to the foundation work)

1. **T1** hive_reader: `HivePath` → owned `Vec<String>`; `SYSTEM_HIVE`/`AMCACHE_HIVE`
   const→fn; `HivePath::user_ntuser`; update the 7 call sites; regression tests that the
   existing consumers' paths are preserved.
2. **T2** hive_reader: `list_dir_names` (ntfs `entries()`/`next()` directory enumeration,
   verified API), returning owned `Vec<String>`.
3. **T3** pure `rot13`.
4. **T4** pure `parse_userassist` (run_count @ 4 + FILETIME @ 60; never-panic).
5. **T5** ProfileList reverse-lookup helper (open SOFTWARE hive → { lowercased
   ProfileImagePath → SID } map).
6. **T6** `UserAssistCollector` (gate + scan Users + per-user open + enumerate
   GUID/Count + mapping + four flags + sources()) + selection/CLI wiring + `#[ignore]`
   e2e.

T1 is the one risk-bearing step (it touches the shared foundation), so it is isolated
with its own regression tests proving the existing three consumers (shimcache/amcache/bam)
still resolve their paths.
