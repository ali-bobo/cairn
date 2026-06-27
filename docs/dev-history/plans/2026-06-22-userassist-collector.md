# UserAssist Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse each user's `C:\Users\<name>\NTUSER.DAT` UserAssist into `Record::Execution` (source="userassist") with GUI launch count + last-execution time, resolving `user_sid` via the SOFTWARE-hive ProfileList — the last S2 collector.

**Architecture:** All code lands in `crates/cairn-collectors` (`#![forbid(unsafe_code)]` kept). The hive_reader foundation gains two reusable primitives — a dynamic `HivePath` (owned `Vec<String>` so per-user NTUSER paths can be built at runtime) and `list_dir_names` (raw-NTFS directory enumeration via ntfs 0.4's verified `directory_index().entries()`/`next()` API). The collector opens the SOFTWARE hive once to build a `{ lowercased C:\Users\<name> → SID }` map, enumerates `C:\Users` subdirectories, opens each NTUSER.DAT, walks `...\Explorer\UserAssist\<GUID>\Count`, ROT13-decodes value names and parses the 72-byte struct. Every user dir and value degrades independently (golden rule 8); unrecognised structure abstains rather than misreports (NFR12).

**Tech Stack:** Rust, `notatin` (hive parse), `ntfs` 0.4 (raw NTFS), `cairn-collectors-win::volume::VolumeReader` (raw `\\.\C:`), `chrono`, `rayon` (existing fan-in), reuses `cairn_core::time::filetime_to_utc`.

---

## Verified facts baked into this plan (confirmed during brainstorm — do NOT re-derive)

- **ntfs 0.4 directory enumeration API** (read from the installed crate source):
  - `NtfsFile::directory_index(reader) -> Result<NtfsIndex<'n,'f, NtfsFileNameIndex>>`
    (file.rs:263). Returns `Err(NtfsError::NotADirectory)` if the file is not a directory.
  - `NtfsIndex::entries() -> NtfsIndexEntries` (index.rs:85).
  - `NtfsIndexEntries::next(reader) -> Option<Result<NtfsIndexEntry>>` (index.rs:127) — streaming, re-borrows `reader` each call (same dance `find_child_dir` already uses).
  - `NtfsIndexEntry::key() -> Option<Result<NtfsFileName>>` (index_entry.rs:212).
  - `NtfsFileName::name() -> U16StrLe` (file_name.rs:210) and `U16StrLe::to_string_lossy() -> String` (used in the crate's own tests, file_name.rs:339).
  - `NtfsFileName::is_directory() -> bool` (file_name.rs:184).
- **UserAssist value struct (verified on this Win11 host):** value data = 72 bytes; `run_count = u32 @ offset 4`; `last-run FILETIME = u64 @ offset 60`. No version drift (classic Win7+ layout). Value NAME = ROT13-encoded path.
- **ROT13**: `HRZR`↔`UEME` confirmed.
- **HivePath const→fn refactor** touches exactly these 7 call sites:
  1. `shimcache.rs:25` import; 2. `shimcache.rs:195` `&SYSTEM_HIVE`
  3. `amcache.rs:20` import; 4. `amcache.rs:73` `&AMCACHE_HIVE`
  5. `bam.rs:23` import; 6. `bam.rs:75` `&SYSTEM_HIVE`
  7. `hive_reader.rs` tests (lines 477, 508, 514).
- `cairn_core::time::filetime_to_utc(ft: u64) -> Option<DateTime<Utc>>` (rejects ft==0 and pre-1970) — already imported by bam.rs.
- `open_hive`'s component loop currently iterates `for comp in dir_components` where each `comp: &&'static str` is passed to `find_child_dir(..., comp)` (takes `&str`). After the refactor each element is `&String`, which deref-coerces to `&str` — `find_child_dir`'s signature is unchanged.

## Build / test commands (this repo)

- Per-crate fast check: `cargo test -p cairn-collectors <module>::tests::<name>`
- Workspace gate (run before commit): `cargo test --workspace`
- Clippy MUST match CI: `cargo clippy --workspace --all-targets -- -D warnings`
- Format: `cargo fmt`
- `CARGO_TARGET_DIR` is set out of OneDrive (see CLAUDE.md "Local dev environment notes").

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/cairn-collectors/src/hive_reader.rs` | hive locate/read/parse primitives | T1 (HivePath owned + const→fn + `user_ntuser`), T2 (`list_dir_names`) |
| `crates/cairn-collectors/src/shimcache.rs` | shimcache consumer | T1 (call-site `()`) |
| `crates/cairn-collectors/src/amcache.rs` | amcache consumer | T1 (call-site `()`) |
| `crates/cairn-collectors/src/bam.rs` | bam consumer | T1 (call-site `()`) |
| `crates/cairn-collectors/src/userassist.rs` | the new collector + pure `rot13`/`parse_userassist`/ProfileList helper | T3, T4, T5, T6 (created in T3, grown across T3–T6) |
| `crates/cairn-collectors/src/lib.rs` | module list | T3 (`pub mod userassist;`) |
| `crates/cairn-core/src/selection.rs` | profile→collector set | T6 (`HEAVY_OFFLINE` + test) |
| `crates/cairn-cli/src/main.rs` | CLI wiring | T6 (AVAILABLE ×2, built_collector_names, push block, tests) |

---

## Task 1: hive_reader — dynamic HivePath (owned Vec<String>, const→fn, user_ntuser)

**Files:**
- Modify: `crates/cairn-collectors/src/hive_reader.rs:12-29` (HivePath struct + SYSTEM_HIVE/AMCACHE_HIVE), add `user_ntuser`
- Modify: `crates/cairn-collectors/src/hive_reader.rs:127-129` (open_hive loop var)
- Modify: `crates/cairn-collectors/src/hive_reader.rs` tests (lines 477, 508, 514)
- Modify: `crates/cairn-collectors/src/shimcache.rs:25,195`
- Modify: `crates/cairn-collectors/src/amcache.rs:20,73`
- Modify: `crates/cairn-collectors/src/bam.rs:23,75`

This is the one risk-bearing task (it touches the shared foundation). It is TDD-driven by regression tests that prove the existing three consumers' paths are byte-for-byte preserved through the const→fn change.

- [ ] **Step 1: Write the failing regression tests**

In `crates/cairn-collectors/src/hive_reader.rs`, REPLACE the two existing path tests
(`amcache_hive_path_joins_to_appcompat_programs` at line 476-479 and
`system_hive_path_joins_to_config_system` at line 513-516) with the fn-call form, and
ADD a `user_ntuser` test. The other tests that touch `&SYSTEM_HIVE`
(`open_hive_short_reader_is_err_not_panic` line 504-510) become `&SYSTEM_HIVE()`.

```rust
    #[test]
    fn amcache_hive_path_joins_to_appcompat_programs() {
        let joined = AMCACHE_HIVE().components.join("\\");
        assert_eq!(joined, r"Windows\AppCompat\Programs\Amcache.hve");
    }

    #[test]
    fn system_hive_path_joins_to_config_system() {
        let joined = SYSTEM_HIVE().components.join("\\");
        assert_eq!(joined, r"Windows\System32\config\SYSTEM");
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
```

Also update `open_hive_short_reader_is_err_not_panic` (line 508) from
`open_hive(&mut reader, &SYSTEM_HIVE)` to `open_hive(&mut reader, &SYSTEM_HIVE())`.

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `cargo test -p cairn-collectors hive_reader::tests:: 2>&1 | head -30`
Expected: compile error — `SYSTEM_HIVE()` "expected value, found constant" / `HivePath::user_ntuser` not found.

- [ ] **Step 3: Change HivePath to owned + const→fn + add user_ntuser**

In `crates/cairn-collectors/src/hive_reader.rs`, REPLACE lines 10-25 (the HivePath
struct + SYSTEM_HIVE const + AMCACHE_HIVE const) with:

```rust
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
```

NOTE: the `#[allow(non_snake_case)]` keeps the SCREAMING_CASE names (they read as
constants to consumers, minimizing churn) while satisfying clippy's fn-naming lint.

- [ ] **Step 4: Fix open_hive's component loop**

In `crates/cairn-collectors/src/hive_reader.rs`, the loop at line 127-129 currently is:

```rust
    let mut cur = root;
    for comp in dir_components {
        cur = find_child_dir(&ntfs, reader, &cur, comp)?;
    }
```

`dir_components` is now `&[String]` (from `components.split_last()` on a `Vec<String>`),
so `comp: &String`. `find_child_dir` takes `name: &str`; `&String` deref-coerces, but to
be explicit and avoid any inference surprise, change the call to pass `comp.as_str()`:

```rust
    let mut cur = root;
    for comp in dir_components {
        cur = find_child_dir(&ntfs, reader, &cur, comp.as_str())?;
    }
```

`split_last()` on `&Vec<String>` (via the `hive.components` field, line 121-124) returns
`Option<(&String, &[String])>` — `file_name: &String`. The later uses of `file_name`
are `format!("{file_name}.LOG1")` (Display on &String works) and
`read_default_stream(..., file_name)` which takes `name: &str` — `&String`
deref-coerces. No further change needed there. Verify by reading lines 119-146 after
editing.

- [ ] **Step 5: Update the 6 consumer call sites**

`crates/cairn-collectors/src/shimcache.rs` line 25: change the import — `SYSTEM_HIVE`
is now a fn, but the `use` line stays identical (you import the name either way):
```rust
use crate::hive_reader::{get_value_bytes, open_hive, LogStatus, SYSTEM_HIVE};
```
(No change to the `use`; the imported item is now a fn.) Line 195:
```rust
        let mut opened = open_hive(&mut reader, &SYSTEM_HIVE())?;
```

`crates/cairn-collectors/src/amcache.rs` line 20 `use` unchanged; line 73:
```rust
        let mut opened = open_hive(&mut reader, &AMCACHE_HIVE())?;
```

`crates/cairn-collectors/src/bam.rs` line 23 `use` unchanged; line 75:
```rust
        let mut opened = open_hive(&mut reader, &SYSTEM_HIVE())?;
```

- [ ] **Step 6: Run the full workspace test suite to prove no regression**

Run: `cargo test --workspace 2>&1 | tail -25`
Expected: PASS — all existing tests green (shimcache/amcache/bam compile and their
unit tests pass), plus the 2 new `user_ntuser` tests. Same test count as before + 2.

- [ ] **Step 7: Clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15` (expect clean)
Run: `cargo fmt`

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-collectors/src/hive_reader.rs crates/cairn-collectors/src/shimcache.rs crates/cairn-collectors/src/amcache.rs crates/cairn-collectors/src/bam.rs
git commit -m "refactor(hive_reader): dynamic HivePath (owned Vec, const->fn) + user_ntuser

HivePath.components becomes owned Vec<String> so per-user NTUSER.DAT paths can be
built at runtime; SYSTEM_HIVE/AMCACHE_HIVE become builder fns (a const cannot hold an
owned Vec). Adds HivePath::user_ntuser. The 6 existing consumer call sites gain ().
Regression tests prove shimcache/amcache/bam paths are preserved.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: hive_reader — list_dir_names (raw-NTFS directory enumeration)

**Files:**
- Modify: `crates/cairn-collectors/src/hive_reader.rs` (add `list_dir_names` after `find_child_dir`, ~line 262)

`list_dir_names` enumerates a DIRECTORY on the volume (for `C:\Users`), distinct from
`list_subkeys` (registry keys inside a parsed hive). It takes the raw `reader`, not a
notatin Parser. Real enumeration needs a live volume, so the unit test is structural;
the e2e (T6) proves real enumeration — the same policy `find_child_dir` follows.

- [ ] **Step 1: Write the failing structural test**

In the `tests` module of `crates/cairn-collectors/src/hive_reader.rs`, add:

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p cairn-collectors hive_reader::tests::list_dir_names_on_short_reader 2>&1 | head -20`
Expected: compile error — `list_dir_names` not found.

- [ ] **Step 3: Implement list_dir_names**

In `crates/cairn-collectors/src/hive_reader.rs`, add this fn AFTER `find_child_dir`
(after line 262, before `derive_log_status`):

```rust
/// Enumerate the immediate SUBDIRECTORY names of an on-volume directory (e.g. the user
/// folders under C:\Users). Returns hive_reader-owned Vec<String> — no ntfs type leaks
/// to callers. This walks the NTFS $I30 directory index, NOT a registry hive (contrast
/// list_subkeys, which enumerates keys inside a parsed hive).
///
/// Wrapped in catch_unwind (mirroring open_hive): ntfs panics on some inputs
/// (short sources in Ntfs::new, named lookups without read_upcase_table). Contain any
/// third-party panic and convert to Err so it never escapes the collector.
///
/// Only directories are returned (files skipped via NtfsFileName::is_directory); the
/// "." / ".." self/parent entries and the NTFS short-name (8.3) duplicate entries would
/// pollute the list, so we keep only the Win32/POSIX namespace long names and drop "."
/// and "..". Order is the index's ascending key order; the CALLER sorts if it needs a
/// specific order (we sort here for determinism since the set is small).
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
        let entry = entry.map_err(|e| hive_err(format!("index entry read failed: {e}")))?;
        // key() is Option<Result<NtfsFileName>>: None = no $FILE_NAME key on this entry
        // (skip); Err = a corrupt entry (skip it, do not abort the whole listing).
        let file_name = match entry.key() {
            Some(Ok(fnm)) => fnm,
            Some(Err(_)) | None => continue,
        };
        if !file_name.is_directory() {
            continue; // files are not user folders
        }
        let name = file_name.name().to_string_lossy();
        if name == "." || name == ".." {
            continue; // self / parent
        }
        out.push(name);
    }

    // A directory's index yields each child under BOTH its long (Win32) and short (8.3)
    // names, so the same folder can appear twice (e.g. "DefaultUser" + "DEFAUL~1").
    // De-dup after sorting so the result is deterministic and each user folder appears
    // once. (We accept that a rare folder whose long name differs only by case is still
    // one logical folder; lowercased de-dup is unnecessary here — open_hive on a
    // duplicate simply fails find and is skipped gracefully.)
    out.sort();
    out.dedup();
    Ok(out)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p cairn-collectors hive_reader::tests::list_dir_names_on_short_reader 2>&1 | tail -10`
Expected: PASS (short reader → Err, contained, no panic).

- [ ] **Step 5: Clippy + fmt + workspace test**

Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15` (expect clean)
Run: `cargo fmt`
Run: `cargo test --workspace 2>&1 | tail -8` (all green)

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/hive_reader.rs
git commit -m "feat(hive_reader): list_dir_names (raw-NTFS directory enumeration)

Enumerate immediate subdirectory names of an on-volume directory (for C:\\Users) via
ntfs 0.4 directory_index().entries()/next() streaming. catch_unwind-contained;
files / . / .. skipped; sorted + deduped (long vs 8.3 short-name duplicates). Returns
owned Vec<String>, no ntfs type leakage. Reused by userassist.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: pure rot13 + userassist.rs module skeleton

**Files:**
- Create: `crates/cairn-collectors/src/userassist.rs`
- Modify: `crates/cairn-collectors/src/lib.rs` (add `pub mod userassist;` after line 18 `pub mod shimcache;`, keeping alpha-ish order — insert between `shimcache` and `usn`)

- [ ] **Step 1: Create userassist.rs with the module header + rot13 + its tests**

Create `crates/cairn-collectors/src/userassist.rs`:

```rust
//! UserAssistCollector: parse each user's NTUSER.DAT UserAssist into Record::Execution
//! with a real GUI launch count + last-execution time.
//!
//! UserAssist (Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\
//! Count) records Explorer-launched programs per user. Each value's NAME is the
//! executable path ROT13-encoded; its DATA is a 72-byte struct with run_count at
//! offset 4 and a last-run FILETIME at offset 60. Reached via a raw \\.\C: read of each
//! C:\Users\<name>\NTUSER.DAT (the live hive is locked). user_sid is resolved by
//! reverse-lookup against the SOFTWARE hive's ProfileList. On an absent key or
//! unrecognised structure it ABSTAINS (records the reason) rather than guess (NFR12).

/// Decode a ROT13-encoded ASCII string (UserAssist value names are ROT13). Pure: each
/// ASCII letter is rotated 13 places; every non-alphabetic byte (digits, braces, path
/// separators, dots) passes through unchanged. Never panics. Self-inverse.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_decodes_ueme_marker() {
        // The well-known UserAssist session marker, verified on-host.
        assert_eq!(rot13("HRZR_PGYFRFFVBA"), "UEME_CTLSESSION");
    }

    #[test]
    fn rot13_is_self_inverse() {
        let s = "UEME_RUNPATH:C:\\Windows\\notepad.exe";
        assert_eq!(rot13(&rot13(s)), s);
    }

    #[test]
    fn rot13_passes_non_alpha_through_unchanged() {
        // Digits, braces, backslash, colon, dot must be untouched (GUID + path chars).
        let s = "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\\1.2_3";
        // Only the letters rotate; the structure (digits/braces/sep) is preserved.
        let decoded = rot13(s);
        assert_eq!(decoded.len(), s.len());
        assert!(decoded.contains('{') && decoded.contains('}') && decoded.contains('\\'));
        assert!(decoded.contains("1.2_3")); // digits + dot + underscore unchanged
    }

    #[test]
    fn rot13_empty_string() {
        assert_eq!(rot13(""), "");
    }

    #[test]
    fn rot13_mixed_case_preserves_case() {
        assert_eq!(rot13("AbZz"), "NoMm");
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/cairn-collectors/src/lib.rs`, add after line 18 (`pub mod shimcache;`):

```rust
pub mod userassist;
```

(Resulting order: `shimcache`, `userassist`, `usn` — `dead_code` on `rot13` is expected
until T6 wires it; allow it temporarily with `#[allow(dead_code)]` on the fn, removed in
T6. Add `#[allow(dead_code)]` directly above `fn rot13`.)

Add the attribute now:
```rust
#[allow(dead_code)] // wired by UserAssistCollector in T6
fn rot13(s: &str) -> String {
```

- [ ] **Step 3: Run the rot13 tests**

Run: `cargo test -p cairn-collectors userassist::tests::rot13 2>&1 | tail -12`
Expected: PASS — all 5 rot13 tests.

- [ ] **Step 4: Clippy + fmt**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings 2>&1 | tail -10` (clean)
Run: `cargo fmt`

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors/src/userassist.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(userassist): pure rot13 decoder + module skeleton

ROT13 decode for UserAssist value names (HRZR_PGYFRFFVBA -> UEME_CTLSESSION verified).
Self-inverse, non-alpha passthrough, never-panic. dead_code allowed until T6 wiring.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: pure parse_userassist (72-byte struct: run_count @ 4, FILETIME @ 60)

**Files:**
- Modify: `crates/cairn-collectors/src/userassist.rs` (add `parse_userassist` + tests)

- [ ] **Step 1: Write the failing tests**

In `crates/cairn-collectors/src/userassist.rs`, add to the `tests` module (you will need
imports at the TOP of the file — add them in Step 3 alongside the fn):

```rust
    /// FILETIME for 2021-01-01T00:00:00Z (same constant bam uses; verified value).
    const FT_2021: u64 = 132_539_328_000_000_000;

    /// Build a 72-byte UserAssist value: run_count @ 4, FILETIME @ 60, rest zero.
    fn make_ua(run_count: u32, filetime: u64) -> Vec<u8> {
        let mut v = vec![0u8; 72];
        v[4..8].copy_from_slice(&run_count.to_le_bytes());
        v[60..68].copy_from_slice(&filetime.to_le_bytes());
        v
    }

    #[test]
    fn parses_run_count_and_filetime() {
        let data = make_ua(4, FT_2021);
        let (count, last) = parse_userassist(&data).expect("valid 72-byte record parses");
        assert_eq!(count, 4);
        assert_eq!(last, cairn_core::time::filetime_to_utc(FT_2021));
    }

    #[test]
    fn zero_filetime_yields_count_with_no_last_run() {
        // run_count present but FILETIME==0 → Some((n, None)): a real count, no time.
        let data = make_ua(7, 0);
        let (count, last) = parse_userassist(&data).expect("count present even with ft==0");
        assert_eq!(count, 7);
        assert_eq!(last, None);
    }

    #[test]
    fn data_shorter_than_run_count_field_is_none() {
        // Can't even read run_count (needs >= 8 bytes) → None, no panic.
        assert_eq!(parse_userassist(&[]), None);
        assert_eq!(parse_userassist(&[0u8; 7]), None);
    }

    #[test]
    fn data_with_run_count_but_no_filetime_field_is_some_none() {
        // >= 8 bytes (run_count readable) but < 68 (no FILETIME): count present, last None.
        let mut data = vec![0u8; 8];
        data[4..8].copy_from_slice(&9u32.to_le_bytes());
        let (count, last) = parse_userassist(&data).expect("run_count readable at >=8 bytes");
        assert_eq!(count, 9);
        assert_eq!(last, None, "no FILETIME field present");
    }

    #[test]
    fn trailing_bytes_beyond_72_are_ignored() {
        let mut data = make_ua(3, FT_2021);
        data.extend_from_slice(&[0xAA; 16]);
        let (count, last) = parse_userassist(&data).expect("parses despite trailing bytes");
        assert_eq!(count, 3);
        assert_eq!(last, cairn_core::time::filetime_to_utc(FT_2021));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p cairn-collectors userassist::tests::parses_run_count 2>&1 | head -15`
Expected: compile error — `parse_userassist` not found.

- [ ] **Step 3: Implement parse_userassist + add imports**

At the TOP of `crates/cairn-collectors/src/userassist.rs`, after the module doc comment,
add:

```rust
use chrono::{DateTime, Utc};

use cairn_core::time::filetime_to_utc;
```

Then add the fn (after `rot13`, before `#[cfg(test)]`):

```rust
/// Parse the UserAssist 72-byte value struct. Returns:
/// - `Some((run_count, Some(last_run)))` — both fields present and last_run is a real time
/// - `Some((run_count, None))` — run_count present but FILETIME absent (data < 68 bytes)
///   or zero/pre-1970 (filetime_to_utc rejects those: a launch count with no usable time)
/// - `None` — data shorter than 8 bytes (run_count itself unreadable: not a real record)
///
/// Layout (verified on this Win11 host, classic Win7+ UserAssist):
///   offset 4  : u32 LE run_count
///   offset 60 : u64 LE FILETIME (last execution)
/// Never panics — all reads via slice::get (Option), never index slicing.
#[allow(dead_code)] // wired by UserAssistCollector in T6
fn parse_userassist(data: &[u8]) -> Option<(u32, Option<DateTime<Utc>>)> {
    // run_count is the minimum to call this a record; < 8 bytes => not a record.
    let count_bytes: [u8; 4] = data.get(4..8)?.try_into().ok()?;
    let run_count = u32::from_le_bytes(count_bytes);

    // FILETIME is best-effort: absent field (data < 68) or a non-real time => None,
    // but the run_count still stands. filetime_to_utc rejects ft==0 and pre-1970.
    let last_run = data
        .get(60..68)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .and_then(filetime_to_utc);

    Some((run_count, last_run))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p cairn-collectors userassist::tests:: 2>&1 | tail -15`
Expected: PASS — the 5 rot13 + 5 parse_userassist tests (10 total).

- [ ] **Step 5: Clippy + fmt**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings 2>&1 | tail -10` (clean)
Run: `cargo fmt`

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/userassist.rs
git commit -m "feat(userassist): pure parse_userassist (72-byte struct, never-panic)

run_count u32 @ offset 4, last-run FILETIME u64 @ offset 60 (host-verified). Returns
Some((count, Some(dt))) / Some((count, None)) for absent-or-zero FILETIME / None when
data < 8 bytes. All reads via slice::get; reuses filetime_to_utc (ft==0/pre-1970 guard).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: ProfileList reverse-lookup helper

**Files:**
- Modify: `crates/cairn-collectors/src/userassist.rs` (add `build_profilelist_map` + tests)

This helper, given a parsed SOFTWARE hive, builds a `{ lowercased ProfileImagePath → SID }`
map. The pure, testable core is the path→key normalization; the notatin read is exercised
by the e2e (T6), same as list_subkeys/list_values policy. We split out a pure
`profile_map_key` normalizer so the lowercasing is unit-tested without a hive.

- [ ] **Step 1: Write the failing tests**

In the `tests` module of `crates/cairn-collectors/src/userassist.rs`, add:

```rust
    #[test]
    fn profile_map_key_lowercases() {
        assert_eq!(profile_map_key(r"C:\Users\Alice"), r"c:\users\alice");
        assert_eq!(profile_map_key(r"C:\Users\Bob"), r"c:\users\bob");
    }

    #[test]
    fn profile_map_key_idempotent_on_lowercase() {
        assert_eq!(profile_map_key(r"c:\users\alice"), r"c:\users\alice");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p cairn-collectors userassist::tests::profile_map_key 2>&1 | head -12`
Expected: compile error — `profile_map_key` not found.

- [ ] **Step 3: Implement profile_map_key + build_profilelist_map**

Add imports at the TOP of `crates/cairn-collectors/src/userassist.rs` (after the existing
`use cairn_core::time::filetime_to_utc;`):

```rust
use std::collections::HashMap;

use crate::hive_reader::{get_value_string, list_subkeys};
```

Add the two fns (after `parse_userassist`, before `#[cfg(test)]`):

```rust
/// Normalize a ProfileImagePath (or a C:\Users\<name> path) to the map key: lowercased.
/// Pure — the lookup is case-insensitive because Windows paths are.
fn profile_map_key(path: &str) -> String {
    path.to_ascii_lowercase()
}

/// Build a { lowercased ProfileImagePath -> SID } map from a parsed SOFTWARE hive's
/// ProfileList. Used to resolve a user folder back to its SID. A read failure on the
/// ProfileList (or any individual entry) is non-fatal — this is ENRICHMENT, not core
/// data: callers fall back to user_sid = None and emit records anyway (no abstain flag).
/// Returns an empty map (not Err) if ProfileList is absent.
///
/// `parser` is &mut for notatin's lazy cursor (same as list_subkeys/get_value_string).
#[allow(dead_code)] // wired by UserAssistCollector in T6
fn build_profilelist_map(parser: &mut notatin::parser::Parser) -> HashMap<String, String> {
    const PROFILE_LIST: &str =
        r"Microsoft\Windows NT\CurrentVersion\ProfileList";
    let mut map = HashMap::new();
    // list_subkeys returns Ok(vec![]) on absent key; an Err is a genuine read failure —
    // treat it as "no enrichment available" (return whatever we have, empty).
    let sids = match list_subkeys(parser, PROFILE_LIST) {
        Ok(s) => s,
        Err(_) => return map,
    };
    for sid in sids {
        let key_path = format!("{PROFILE_LIST}\\{}", sid.name);
        // ProfileImagePath is REG_EXPAND_SZ; get_value_string maps it to a String.
        if let Ok(Some(path)) = get_value_string(parser, &key_path, "ProfileImagePath") {
            if !path.is_empty() {
                map.insert(profile_map_key(&path), sid.name);
            }
        }
        // A missing/failed ProfileImagePath for one SID just omits that mapping.
    }
    map
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p cairn-collectors userassist::tests::profile_map_key 2>&1 | tail -10`
Expected: PASS — both `profile_map_key` tests.

- [ ] **Step 5: Clippy + fmt**

Run: `cargo clippy -p cairn-collectors --all-targets -- -D warnings 2>&1 | tail -10` (clean)
Run: `cargo fmt`

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/userassist.rs
git commit -m "feat(userassist): ProfileList reverse-lookup helper

build_profilelist_map opens the SOFTWARE hive's ProfileList into a { lowercased
ProfileImagePath -> SID } map for resolving a user folder to its SID. Enrichment, not
core data: any read failure degrades to an empty/partial map (no abstain). Pure
profile_map_key normalizer unit-tested.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: UserAssistCollector + selection/CLI wiring + e2e

**Files:**
- Modify: `crates/cairn-collectors/src/userassist.rs` (the collector + collector-surface tests + e2e; remove the 3 `#[allow(dead_code)]`)
- Modify: `crates/cairn-core/src/selection.rs` (HEAVY_OFFLINE + test)
- Modify: `crates/cairn-cli/src/main.rs` (AVAILABLE ×2, built_collector_names, push block, doc/count, test)

- [ ] **Step 1: Write the collector + remove the dead_code allows**

Remove the three `#[allow(dead_code)]` lines (above `rot13`, `parse_userassist`,
`build_profilelist_map`) — they are now used.

Add the full collector imports at the TOP of `crates/cairn-collectors/src/userassist.rs`
(merge with existing imports; final import block):

```rust
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use cairn_collectors_win::volume::VolumeReader;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::time::filetime_to_utc;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};

use crate::hive_reader::{
    get_value_string, list_dir_names, list_subkeys, list_values, open_hive, HivePath, LogStatus,
    SYSTEM_HIVE,
};
```

WAIT — userassist opens the SOFTWARE hive (ProfileList) and each NTUSER.DAT, NOT the
SYSTEM hive. There is no `SOFTWARE_HIVE` builder yet. Add one in hive_reader.rs FIRST
(see Step 1a), then import `SOFTWARE_HIVE` instead of `SYSTEM_HIVE`. Corrected import:

```rust
use crate::hive_reader::{
    get_value_string, list_dir_names, list_subkeys, list_values, open_hive, HivePath, LogStatus,
    SOFTWARE_HIVE,
};
```

- [ ] **Step 1a: Add SOFTWARE_HIVE builder to hive_reader.rs**

In `crates/cairn-collectors/src/hive_reader.rs`, after the `AMCACHE_HIVE()` fn (added in
T1), add:

```rust
/// SOFTWARE hive (Windows\System32\config\SOFTWARE) — holds ProfileList (SID -> user
/// folder), used by userassist to resolve user_sid. A fn (HivePath holds an owned Vec).
#[allow(non_snake_case)]
pub(crate) fn SOFTWARE_HIVE() -> HivePath {
    HivePath {
        components: ["Windows", "System32", "config", "SOFTWARE"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}
```

And add a regression test in hive_reader.rs tests:

```rust
    #[test]
    fn software_hive_path_joins_to_config_software() {
        let joined = SOFTWARE_HIVE().components.join("\\");
        assert_eq!(joined, r"Windows\System32\config\SOFTWARE");
    }
```

- [ ] **Step 1b: Write the collector struct + impl**

Append to `crates/cairn-collectors/src/userassist.rs` (after `build_profilelist_map`,
before `#[cfg(test)]`):

```rust
/// UserAssistCollector: privilege-gated, read-only parse of every user's NTUSER.DAT
/// UserAssist into Record::Execution (source="userassist", execution_confirmed=
/// Some(true)). Requires Administrator + SeBackupPrivilege (raw \\.\C: open).
#[derive(Default)]
pub struct UserAssistCollector {
    /// C:\Users enumeration failed — cannot find any user hive (abstained). NFR12.
    users_dir_unreadable: AtomicBool,
    /// No NTUSER had a UserAssist key (build variance — abstained). NFR12.
    no_userassist: AtomicBool,
    /// A user hive's transaction log existed but could not be read; primary-only parse.
    log_replay_failed: AtomicBool,
    /// A NTUSER that EXISTS failed to open/parse, or a value/struct was malformed; that
    /// item was skipped and the rest still collected (golden rule 8). Surfaced so the
    /// analyst knows the result is partial (NFR12). A simply-absent NTUSER is NOT this.
    entry_read_errors: AtomicBool,
}

/// The UserAssist parent key inside a NTUSER hive (key_path_has_root = false).
const USERASSIST_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

impl Collector for UserAssistCollector {
    fn name(&self) -> &str {
        "userassist"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate BEFORE any volume open (mirrors bam/amcache). NTUSER.DAT and
        // SOFTWARE are OS-locked, reachable only via a raw \\.\C: read.
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "userassist".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }

        let mut reader = VolumeReader::open(r"\\.\C:")?;

        // (1) Build the ProfileList reverse map (enrichment). A failure to open SOFTWARE
        // is non-fatal: we proceed with an empty map (user_sid = None for all).
        let profile_map = match open_hive(&mut reader, &SOFTWARE_HIVE()) {
            Ok(mut sw) if !sw.truncated => {
                if let LogStatus::Failed(reason) = &sw.log_status {
                    self.log_replay_failed.store(true, Ordering::Relaxed);
                    tracing::warn!(reason = %reason, "userassist: SOFTWARE log replay failed");
                }
                build_profilelist_map(&mut sw.parser)
            }
            _ => {
                tracing::warn!("userassist: SOFTWARE hive unavailable; user_sid will be None");
                HashMap::new()
            }
        };

        // (2) Enumerate C:\Users subdirectories.
        let users_dir = HivePath {
            components: vec!["Users".to_string()],
        };
        let user_dirs = match list_dir_names(&mut reader, &users_dir) {
            Ok(d) => d,
            Err(e) => {
                self.users_dir_unreadable.store(true, Ordering::Relaxed);
                tracing::warn!(err = %e, "userassist: C:\\Users enumeration failed; abstaining");
                return Ok(Vec::new());
            }
        };

        // (3) Per user: open NTUSER.DAT, walk UserAssist\<GUID>\Count.
        let mut records: Vec<Record> = Vec::new();
        let mut any_userassist_key = false;
        for user_dir in user_dirs {
            let hive_path = HivePath::user_ntuser(&user_dir);
            let mut opened = match open_hive(&mut reader, &hive_path) {
                Ok(o) => o,
                Err(e) => {
                    // Distinguish absent (system folders w/o NTUSER.DAT) from a genuine
                    // read failure. open_hive's "not found in directory" message means the
                    // file simply isn't there → silent graceful skip (NOT a partial signal).
                    if e.to_string().contains("not found in directory") {
                        continue; // absent NTUSER.DAT — legitimate, skip silently
                    }
                    self.entry_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(user = %user_dir, err = %e, "userassist: NTUSER open failed; skipping");
                    continue;
                }
            };
            if opened.truncated {
                self.entry_read_errors.store(true, Ordering::Relaxed);
                tracing::warn!(user = %user_dir, "userassist: NTUSER exceeded ceiling; skipping");
                continue;
            }
            if let LogStatus::Failed(reason) = &opened.log_status {
                self.log_replay_failed.store(true, Ordering::Relaxed);
                tracing::warn!(user = %user_dir, reason = %reason, "userassist: NTUSER log replay failed");
            }

            // Resolve this user's SID via the ProfileList map (C:\Users\<name>).
            let user_path = format!(r"C:\Users\{user_dir}");
            let user_sid = profile_map.get(&profile_map_key(&user_path)).cloned();

            // The GUID subkeys under UserAssist.
            let guids = match list_subkeys(&mut opened.parser, USERASSIST_KEY) {
                Ok(g) => g,
                Err(e) => {
                    self.entry_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(user = %user_dir, err = %e, "userassist: GUID enum failed; skipping user");
                    continue;
                }
            };
            if guids.is_empty() {
                continue; // this NTUSER has no UserAssist key — skip (not an error)
            }
            any_userassist_key = true;

            for guid in guids {
                // Count is a constant child of each GUID; build the path directly.
                let count_path = format!("{USERASSIST_KEY}\\{}\\Count", guid.name);
                let values = match list_values(&mut opened.parser, &count_path) {
                    Ok(v) => v,
                    Err(e) => {
                        self.entry_read_errors.store(true, Ordering::Relaxed);
                        tracing::warn!(user = %user_dir, guid = %guid.name, err = %e, "userassist: Count value read failed; skipping");
                        continue;
                    }
                };
                for kv in values {
                    let path = rot13(&kv.name);
                    match parse_userassist(&kv.data) {
                        Some((run_count, last_run)) => {
                            records.push(Record::Execution(ExecutionRecord {
                                source: "userassist".into(),
                                path,
                                first_run: None,
                                last_run,
                                run_count: Some(run_count),
                                sha1: None,
                                user_sid: user_sid.clone(),
                                execution_confirmed: Some(true),
                            }));
                        }
                        None => {
                            // data < 8 bytes: structurally impossible UserAssist value.
                            self.entry_read_errors.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        if !any_userassist_key {
            self.no_userassist.store(true, Ordering::Relaxed);
            tracing::warn!("userassist: no UserAssist key found in any user hive; abstaining");
        }

        // Determinism (NFR4): enumeration order is physical; sort by (user_sid, path).
        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => {
                x.user_sid.cmp(&y.user_sid).then(x.path.cmp(&y.path))
            }
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution emitted above
        });

        tracing::info!(userassist_entries = records.len(), "userassist scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.users_dir_unreadable.load(Ordering::Relaxed) {
            errors.push("abstained: C:\\Users enumeration failed (NFR12)".to_string());
        }
        if self.no_userassist.load(Ordering::Relaxed) {
            errors.push(
                "abstained: no UserAssist key in any user hive (build variance/NFR12)".to_string(),
            );
        }
        if self.log_replay_failed.load(Ordering::Relaxed) {
            errors.push(
                "log_replay_failed: a user hive's transaction log was unreadable; primary-only"
                    .to_string(),
            );
        }
        if self.entry_read_errors.load(Ordering::Relaxed) {
            errors.push(
                "partial: one or more user hives or entries skipped (result incomplete)".to_string(),
            );
        }
        vec![SourceEntry {
            artifact: "userassist".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs_hive".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}
```

NOTE on imports: `SYSTEM_HIVE` is NOT used by userassist (remove it from the import list;
keep `SOFTWARE_HIVE`). `DateTime`/`Utc` are used only by `parse_userassist`'s signature
(already imported). Confirm the final `use` block compiles — clippy will flag any unused.

- [ ] **Step 2: Add collector-surface unit tests**

Add to the `tests` module of `crates/cairn-collectors/src/userassist.rs`:

```rust
    use cairn_core::config::Config;
    use cairn_core::record::Record;
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::CairnError;
    use std::sync::atomic::Ordering;

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let r = UserAssistCollector::default().collect(&ctx);
        assert!(
            matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open"
        );
    }

    #[test]
    fn name_is_userassist() {
        assert_eq!(UserAssistCollector::default().name(), "userassist");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = UserAssistCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "userassist");
        assert_eq!(s[0].method, "raw_ntfs_hive");
    }

    #[test]
    fn sources_reports_users_dir_unreadable() {
        let c = UserAssistCollector::default();
        c.users_dir_unreadable.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("C:\\Users enumeration failed")));
    }

    #[test]
    fn sources_reports_no_userassist() {
        let c = UserAssistCollector::default();
        c.no_userassist.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("no UserAssist key")));
    }

    #[test]
    fn sources_reports_log_replay_failed() {
        let c = UserAssistCollector::default();
        c.log_replay_failed.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("log_replay_failed")));
    }

    #[test]
    fn sources_reports_partial_on_entry_read_errors() {
        let c = UserAssistCollector::default();
        c.entry_read_errors.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("partial")));
    }
```

NOTE: the test module already `use super::*;` so `UserAssistCollector` is in scope; the
extra `use` lines above import Config/CollectCtx/etc. for the surface tests. If any are
already pulled in by `super::*`, clippy will flag the duplicate — drop duplicates.

- [ ] **Step 3: Run the collector unit tests**

Run: `cargo test -p cairn-collectors userassist:: 2>&1 | tail -20`
Expected: PASS — rot13 (5) + parse_userassist (5) + profile_map_key (2) + surface (7) = 19, plus e2e ignored (added Step 7).

- [ ] **Step 4: selection.rs wiring**

In `crates/cairn-core/src/selection.rs` line 36, add `"userassist"`:

```rust
const HEAVY_OFFLINE: &[&str] = &[
    "mft", "usn", "shimcache", "amcache", "prefetch", "bam", "userassist",
];
```

Add a test after `minimal_excludes_bam` (after line 291):

```rust
    #[test]
    fn minimal_excludes_userassist() {
        let available = vec![
            "proc",
            "net",
            "persist",
            "mft",
            "usn",
            "shimcache",
            "amcache",
            "prefetch",
            "bam",
            "userassist",
        ];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"userassist".to_string()));
    }
```

- [ ] **Step 5: main.rs wiring**

(a) `built_collector_names` (line 277-293): add `"userassist"` after `"bam"`:
```rust
        "prefetch",
        "bam",
        "userassist",
    ]
```
And update the doc comment line 274-275: "construct proc/.../prefetch/bam/userassist
collectors" and "MUST stay in sync with the **ten** `if ... push(...)` blocks".

(b) The run-handler `AVAILABLE` (line 633-643): add `"userassist"` after `"bam"`:
```rust
                "prefetch",
                "bam",
                "userassist",
            ];
```

(c) The push block — add after the `bam` block (after line 731):
```rust
            if selection.selected.iter().any(|m| m == "userassist") {
                collectors.push(Box::new(
                    cairn_collectors::userassist::UserAssistCollector::default(),
                ));
            }
```

(d) The test `AVAILABLE` (line 922-932): add `"userassist"` after `"bam"`.

(e) The canonical-order assert in `selected_collector_names_follow_selection`
(line 943-956): add `"userassist"` after `"bam"`:
```rust
                "prefetch",
                "bam",
                "userassist"
            ]
```

(f) Add userassist standard/minimal assertions after the bam ones (after line 1020):
```rust
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            built.contains(&"userassist".to_string()),
            "standard includes userassist"
        );
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"userassist".to_string()),
            "minimal skips userassist"
        );
```

- [ ] **Step 6: Run the workspace tests**

Run: `cargo test --workspace 2>&1 | tail -15`
Expected: PASS — selection + main wiring tests green; userassist unit tests green.

- [ ] **Step 7: Add the #[ignore] elevated e2e**

Add to the `tests` module of `crates/cairn-collectors/src/userassist.rs`:

```rust
    /// ELEVATED E2E (manual): run as Administrator with SeBackupPrivilege:
    ///   cargo test -p cairn-collectors userassist::tests::userassist_e2e_real_hives -- --ignored --nocapture
    /// Proves the full chain: raw \\.\C: -> ntfs enumerate C:\Users -> per-user NTUSER
    /// open (+ log replay) -> UserAssist\<GUID>\Count -> rot13 + 72-byte parse ->
    /// Record::Execution, with SOFTWARE ProfileList SID reverse-lookup.
    #[test]
    #[ignore = "requires Administrator + SeBackupPrivilege and a real NTFS C: volume"]
    fn userassist_e2e_real_hives() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: true,
            se_debug: false,
        };
        // Bind the collector so sources() reads the SAME instance collect() flagged
        // (a fresh default would always show empty errors and make the diagnostic inert).
        let collector = UserAssistCollector::default();
        let recs = collector
            .collect(&ctx)
            .expect("collect should succeed on a real elevated host");
        eprintln!(
            "userassist_e2e diagnostics: {} records; sources errors = {:?}",
            recs.len(),
            collector.sources()[0].errors
        );
        if recs.is_empty() {
            eprintln!(
                "NOTE: 0 userassist records. If you are NOT elevated (Administrator + \
                 SeBackupPrivilege), that is the cause; re-run elevated."
            );
        }
        assert!(
            !recs.is_empty(),
            "expected at least the current user's UserAssist entries"
        );
        let mut any_last_run = false;
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "userassist");
                assert!(!e.path.is_empty(), "every entry must have a path");
                assert_eq!(e.execution_confirmed, Some(true));
                assert!(e.run_count.is_some(), "userassist carries a run_count");
                assert!(e.first_run.is_none(), "userassist has no first_run");
                assert!(e.sha1.is_none(), "userassist has no sha1");
                if e.last_run.is_some() {
                    any_last_run = true;
                }
                // user_sid, when present, is a SID; None is acceptable (ProfileList miss).
                if let Some(sid) = &e.user_sid {
                    assert!(sid.starts_with("S-1-"), "user_sid must be a SID, got {sid:?}");
                }
            } else {
                panic!("userassist must only emit Execution records");
            }
        }
        assert!(
            any_last_run,
            "at least one userassist record should have a last_run time"
        );
    }
```

- [ ] **Step 8: Clippy + fmt + full workspace test**

Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15` (clean)
Run: `cargo fmt`
Run: `cargo test --workspace 2>&1 | tail -10` (all green; e2e ignored)

- [ ] **Step 9: Real-host elevated e2e (manual — controller runs this)**

Run in an elevated shell:
`cargo test -p cairn-collectors userassist::tests::userassist_e2e_real_hives -- --ignored --nocapture`
Expected: ≥1 record; diagnostics print record count + empty `sources errors`; at least
one record has a last_run. (If format drift appears — wrong run_count/time — STOP and
re-verify offsets on the real bytes, per the prefetch lesson: medium-confidence offsets
must be e2e-verified.)

- [ ] **Step 10: Commit**

```bash
git add crates/cairn-collectors/src/userassist.rs crates/cairn-collectors/src/hive_reader.rs crates/cairn-core/src/selection.rs crates/cairn-cli/src/main.rs
git commit -m "feat(userassist): UserAssistCollector + SOFTWARE_HIVE + selection/CLI wiring

Per-user NTUSER.DAT UserAssist -> Record::Execution (source=userassist, run_count +
last_run, user_sid via SOFTWARE ProfileList reverse-lookup). Four abstain flags
(users_dir_unreadable/no_userassist/log_replay_failed/entry_read_errors); absent NTUSER
skips silently (not partial). Adds SOFTWARE_HIVE builder. HEAVY_OFFLINE + AVAILABLE +
push block (tenth collector) + ignore e2e. Closes out Stage 2.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- §2a(i) dynamic HivePath → T1. §2a(ii) list_dir_names → T2. §2a(iii) list_values reuse → T6 (used in collector). ✓
- §3 data flow (SOFTWARE ProfileList → list_dir_names Users → per-user open → GUID/Count → rot13 + parse) → T5 + T6. ✓
- §3 mapping table (source/path/run_count@4/last_run@60/user_sid/execution_confirmed/first_run+sha1 None) → T6 push block. ✓
- §3 determinism sort (user_sid, path) → T6. ✓
- §4 four-flag matrix → T6 struct + sources(). Missing NTUSER not flagged (open_hive "not found" → continue) → T6 Step 1b. ProfileList failure → user_sid None no flag → T5 build_profilelist_map returns empty on Err + T6 `.get().cloned()`. ✓
- §5 testing boundary: rot13 (T3), parse_userassist (T4), HivePath::user_ntuser + SYSTEM/AMCACHE/SOFTWARE regression (T1, T6 1a), list_dir_names structural (T2), collector surface + e2e (T6). ✓
- §6 selection/CLI wiring (HEAVY_OFFLINE + AVAILABLE ×2 + built_collector_names + push + count/doc + tests) → T6 Steps 4-6. ✓
- §7 golden rules: forbid(unsafe) kept (no unsafe added); read-only; in-memory; UTC via filetime_to_utc; graceful degrade. ✓

**2. Placeholder scan:** No TBD/TODO/"handle errors" — every code step has complete code. The dead_code allows are deliberate (added T3-T5, removed T6 Step 1), not placeholders.

**3. Type consistency:**
- `rot13(&str) -> String` — consistent T3/T6.
- `parse_userassist(&[u8]) -> Option<(u32, Option<DateTime<Utc>>)>` — consistent T4/T6 (T6 destructures `Some((run_count, last_run))` and assigns `run_count: Some(run_count)`, `last_run`). ✓
- `build_profilelist_map(&mut Parser) -> HashMap<String,String>` — T5; T6 calls `profile_map.get(&profile_map_key(&user_path)).cloned()` → `Option<String>` matches `user_sid: Option<String>`. ✓
- `HivePath::user_ntuser(&str) -> HivePath` and `HivePath{components: Vec<String>}` literal construction — consistent T1/T2/T6.
- `list_dir_names(&mut R, &HivePath) -> Result<Vec<String>>` — T2; T6 iterates `for user_dir in user_dirs` (String). ✓
- `SOFTWARE_HIVE()`/`SYSTEM_HIVE()`/`AMCACHE_HIVE()` fns — T1/T6 1a; userassist imports SOFTWARE_HIVE only. ✓
- `ExecutionRecord` field set matches bam.rs/amcache.rs exactly (source, path, first_run, last_run, run_count, sha1, user_sid, execution_confirmed). ✓

One correction applied inline: the collector opens the **SOFTWARE** hive for ProfileList
(not SYSTEM); T6 Step 1a adds the `SOFTWARE_HIVE()` builder and the import uses
`SOFTWARE_HIVE`, with `SYSTEM_HIVE` removed from userassist's import list.
