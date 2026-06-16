# S2-M — raw volume read primitive + $MFT minimal proof — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cairn's first `unsafe` — a minimal read-only `VolumeReader` (`\\.\C:` → `Read+Seek`)
in cairn-collectors-win — and an `MftCollector` that uses `ntfs` 0.4 over it to emit
`Record::FileMeta` ($MFT record count + first N file names), wired into profile/only selection
with `minimal` skipping raw-NTFS, and hardened so a malformed/short volume can never panic the run.

**Architecture:** unsafe is confined to `cairn-collectors-win/src/volume.rs` (CreateFileW read-only,
RAII handle, sector-aligned `Read`+`Seek`, off-platform → `Err`). The `#![forbid(unsafe_code)]`
`MftCollector` in cairn-collectors consumes the safe `VolumeReader` + `ntfs` 0.4, guarded by a
boot-sector length pre-check AND `catch_unwind`. Selection diverges so `--profile minimal` skips it.

**Tech Stack:** Rust, `ntfs` 0.4.0 (NEW dep — measured safe except short-read panic, both guards
mandated), `windows` crate (Win32 FileSystem), existing cairn traits/orchestrator.

**Spec:** `docs/superpowers/specs/2026-06-16-s2m-raw-volume-primitive-design.md`. Read §② (the
measured DoS finding) and the four locked decisions before starting.

**Branch:** `feature/s2m-raw-volume-primitive` (already created off main).

---

## File Structure

| File | Responsibility | unsafe? |
|---|---|---|
| `crates/cairn-collectors-win/Cargo.toml` | add `Win32_System_Ioctl` feature (sector-size query) | — |
| `crates/cairn-collectors-win/src/volume.rs` | NEW. `VolumeReader`: open `\\.\C:` read-only, `Read`+`Seek`, sector alignment, RAII handle. off-platform stub. | YES (the only new unsafe) |
| `crates/cairn-collectors-win/src/lib.rs` | `pub mod volume;` | — |
| `crates/cairn-core/src/selection.rs` | `profile_base` diverges: `minimal` excludes `RAW_NTFS` set | no |
| `crates/cairn-collectors/Cargo.toml` | add `ntfs = "=0.4.0"`; dep on cairn-collectors-win | — |
| `crates/cairn-collectors/src/mft.rs` | NEW. `MftCollector`: privilege gate, boot-sector pre-check, `catch_unwind`(ntfs parse), count + first-N names → `Record::FileMeta`. | no (`#![forbid(unsafe_code)]`) |
| `crates/cairn-collectors/src/lib.rs` | `pub mod mft;` | — |
| `crates/cairn-cli/src/main.rs` | `AVAILABLE` gains `"mft"`; one if-block constructs `MftCollector`; `built_collector_names` mirror | no |

**Task order (each de-risks the next):** T1 selection divergence (pure, no Windows) → T2 VolumeReader
unsafe primitive → T3 MftCollector (the DoS-guard heart) → T4 CLI wiring → T5 final integration check.

---

### Task 1: `minimal` skips raw-NTFS — selection divergence (pure, connects the S2-L hook)

**Why first:** pure, platform-independent, testable on Linux CI; establishes the classification the
collector will register into. SRS §19.1: `--profile minimal` MUST skip raw-NTFS.

**Files:**
- Modify: `crates/cairn-core/src/selection.rs` (the `profile_base` fn ~line 36, + tests ~line 101)

- [ ] **Step 1: Write the failing tests** (append to the `mod tests` in `selection.rs`)

```rust
    #[test]
    fn minimal_excludes_raw_ntfs_collectors() {
        // SRS §19.1: --profile minimal SKIPS raw-NTFS. "mft" is the first raw-NTFS module.
        let available = vec!["proc", "net", "persist", "mft"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]); // no "mft"
    }

    #[test]
    fn standard_and_verbose_include_raw_ntfs() {
        let available = vec!["proc", "net", "persist", "mft"];
        let std = select_modules(Profile::Standard, None, &available);
        assert_eq!(std.selected, vec!["proc", "net", "persist", "mft"]);
        let vb = select_modules(Profile::Verbose, None, &available);
        assert_eq!(vb.selected, vec!["proc", "net", "persist", "mft"]);
    }

    #[test]
    fn only_mft_under_minimal_still_excluded() {
        // --only cannot re-enable a module the profile base excludes (only INTERSECTS base).
        let available = vec!["proc", "net", "persist", "mft"];
        let only = vec!["mft".to_string()];
        let out = select_modules(Profile::Minimal, Some(&only), &available);
        assert!(out.selected.is_empty());
        // "mft" IS available (just not in minimal's base), so it is NOT an unknown_only warning.
        assert!(out.unknown_only.is_empty());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p cairn-core selection:: 2>&1 | tail -20`
Expected: the three new tests FAIL (minimal currently returns all available, incl. "mft").

- [ ] **Step 3: Implement the divergence** — replace the `profile_base` fn body in `selection.rs`

```rust
/// Collector names that are raw-NTFS reads (admin + heavy). `--profile minimal` skips
/// these (SRS §19.1). Grows as S2-N/O/P add modules — the single place that knowledge lives.
const RAW_NTFS: &[&str] = &["mft"];

/// Modules a profile selects from `available`, BEFORE the `--only` intersection.
/// `minimal` = the light live set (raw-NTFS excluded, SRS §19.1). `standard`/`verbose`
/// currently select everything available. The mechanism is here; profiles diverge as
/// heavier collectors register into `RAW_NTFS`.
fn profile_base<'a>(profile: Profile, available: &[&'a str]) -> Vec<&'a str> {
    match profile {
        Profile::Minimal => available
            .iter()
            .copied()
            .filter(|name| !RAW_NTFS.contains(name))
            .collect(),
        Profile::Standard | Profile::Verbose => available.to_vec(),
    }
}
```

Also update the existing `minimal_no_only_selects_the_live_light_set` test's comment if needed
(its assertion stays valid: with available `["proc","net","persist"]` and no "mft", minimal still
returns all three — raw-NTFS exclusion only bites once "mft" is present).

- [ ] **Step 4: Run to verify all selection tests pass**

Run: `cargo test -p cairn-core selection:: 2>&1 | tail -20`
Expected: PASS (all old + 3 new).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-core/src/selection.rs
git commit -m "feat(s2m): --profile minimal skips raw-NTFS (RAW_NTFS set; SRS §19.1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `VolumeReader` — the unsafe read-only volume primitive

**Why:** the single new unsafe. Read-only `\\.\C:` presented as `Read+Seek` for `ntfs` to consume.
Follows the established `cairn-collectors-win` pattern (RAII guard, cfg split, never panic).

**Files:**
- Modify: `crates/cairn-collectors-win/Cargo.toml` (add `Win32_System_Ioctl` feature)
- Create: `crates/cairn-collectors-win/src/volume.rs`
- Modify: `crates/cairn-collectors-win/src/lib.rs` (add `pub mod volume;`)

- [ ] **Step 1: Add the Ioctl feature** to `crates/cairn-collectors-win/Cargo.toml`, in the
`features = [ ... ]` list under `[target.'cfg(windows)'.dependencies.windows]`:

```toml
  "Win32_System_Ioctl",
```

- [ ] **Step 2: Write the off-platform + alignment unit tests first** — create `volume.rs` with
the tests and a not-yet-complete impl so the test target exists. Put the alignment math in a
platform-independent helper so it is testable on Linux CI.

```rust
//! VolumeReader: open a volume (`\\.\C:`) READ-ONLY and present it as std::io::Read + Seek
//! for the `ntfs` parser (which consumes a generic Read+Seek; it does not self-open volumes).
//!
//! GOLDEN RULES: read-only (GENERIC_READ + OPEN_EXISTING, no write flag — golden rules 3,4);
//! no evasion (plain documented WinAPI — rule 1). The unsafe is confined here behind a safe
//! wrapper that checks every return value and never panics (NFR3, CLAUDE.md).
//!
//! Sector alignment: raw volume reads must be aligned to the logical sector size. The
//! alignment math (`align_down`/`align_up`) is platform-independent and unit-tested; the
//! Windows ReadFile/SetFilePointerEx calls sit behind it.

/// Round `n` down to a multiple of `align` (a power of two ≥ 1).
pub(crate) fn align_down(n: u64, align: u64) -> u64 {
    n - (n % align)
}

/// Round `n` up to a multiple of `align` (a power of two ≥ 1).
pub(crate) fn align_up(n: u64, align: u64) -> u64 {
    let rem = n % align;
    if rem == 0 { n } else { n + (align - rem) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_math_rounds_to_sector_boundaries() {
        assert_eq!(align_down(0, 512), 0);
        assert_eq!(align_down(513, 512), 512);
        assert_eq!(align_down(1024, 512), 1024);
        assert_eq!(align_up(0, 512), 0);
        assert_eq!(align_up(1, 512), 512);
        assert_eq!(align_up(512, 512), 512);
        assert_eq!(align_up(513, 512), 1024);
    }

    #[cfg(not(windows))]
    #[test]
    fn open_off_platform_is_unsupported_error() {
        let r = VolumeReader::open(r"\\.\C:");
        assert!(r.is_err(), "off-platform open must return Err, not a fake reader");
    }
}
```

- [ ] **Step 3: Run the Linux-testable parts to verify they fail/compile**

Run: `cargo test -p cairn-collectors-win volume:: 2>&1 | tail -20`
Expected: FAIL/compile-error (`VolumeReader::open` not defined yet).

- [ ] **Step 4: Implement `VolumeReader`** — add to `volume.rs` (above the tests):

```rust
use cairn_core::{CairnError, Result};
use std::io::{self, Read, Seek, SeekFrom};

/// Default block size for raw reads — also the alignment fallback if sector size is
/// unavailable. 4096 is a multiple of 512, so it is valid for both common sector sizes.
const DEFAULT_BLOCK: u64 = 4096;
/// Hard cap on a single underlying ReadFile (NFR10 nod): never request an unbounded buffer.
const MAX_READ: usize = 1024 * 1024;

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub struct VolumeReader;
    impl VolumeReader {
        pub fn open(_path: &str) -> Result<Self> {
            Err(CairnError::Collector {
                collector: "volume".into(),
                reason: "raw volume read is Windows-only".into(),
            })
        }
        pub fn sector_size(&self) -> u64 { DEFAULT_BLOCK }
    }
    impl Read for VolumeReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "windows-only"))
        }
    }
    impl Seek for VolumeReader {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "windows-only"))
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, SetFilePointerEx, FILE_BEGIN, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    /// RAII: a volume HANDLE always closed on drop.
    /// INVARIANT: holds a valid open handle from CreateFileW; closed exactly once; never
    /// constructed with an invalid handle (open returns Err instead).
    struct VolumeHandle(HANDLE);
    impl Drop for VolumeHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is a valid handle opened in `open`; closed once.
            unsafe { let _ = CloseHandle(self.0); }
        }
    }

    pub struct VolumeReader {
        handle: VolumeHandle,
        pos: u64,
        sector: u64,
    }

    impl VolumeReader {
        /// Open `path` (e.g. r"\\.\C:") READ-ONLY. GENERIC_READ + OPEN_EXISTING, no write
        /// flag (golden rules 3,4). FILE_SHARE_READ|WRITE so the in-use volume isn't blocked.
        pub fn open(path: &str) -> Result<Self> {
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a valid NUL-terminated UTF-16 string; we request GENERIC_READ
            // only (no write access); the returned handle is wrapped immediately in the guard.
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    Default::default(),
                    None,
                )
            }
            .map_err(|e| CairnError::Collector {
                collector: "volume".into(),
                reason: format!("CreateFileW({path}): {e}"),
            })?;
            let guard = VolumeHandle(handle);
            // Sector size: best-effort query; fall back to DEFAULT_BLOCK (4096, a multiple of
            // 512). A read-only geometry query never modifies the host.
            let sector = query_sector_size(&guard).unwrap_or(DEFAULT_BLOCK);
            Ok(VolumeReader { handle: guard, pos: 0, sector })
        }

        pub fn sector_size(&self) -> u64 { self.sector }
    }

    /// Best-effort logical sector size via IOCTL_DISK_GET_DRIVE_GEOMETRY_EX. Any failure →
    /// None (caller falls back to DEFAULT_BLOCK). Read-only ioctl; never modifies the host.
    fn query_sector_size(_h: &VolumeHandle) -> Option<u64> {
        // The exact IOCTL plumbing (DISK_GEOMETRY_EX, DeviceIoControl) is settled in this
        // task on Windows (TASK-0 item 3). If it proves fiddly, returning None here is a
        // correct, safe fallback to 4096-aligned reads. Implement the DeviceIoControl call
        // with a // SAFETY: note, or leave as None with a comment if the fallback suffices.
        None
    }

    impl Read for VolumeReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() { return Ok(0); }
            // Cap a single read (NFR10 nod) and align length to the sector size.
            let want = buf.len().min(MAX_READ);
            let aligned_len = super::align_up(want as u64, self.sector).min(MAX_READ as u64) as u32;
            let mut tmp = vec![0u8; aligned_len as usize];
            let mut read_bytes = 0u32;
            // SAFETY: handle is valid; tmp is a valid writable buffer of aligned_len bytes;
            // read_bytes receives the count. The file pointer is positioned by seek().
            unsafe {
                ReadFile(
                    self.handle.0,
                    Some(tmp.as_mut_slice()),
                    Some(&mut read_bytes),
                    None,
                )
                .map_err(|e| io::Error::other(format!("ReadFile: {e}")))?;
            }
            let n = (read_bytes as usize).min(buf.len());
            buf[..n].copy_from_slice(&tmp[..n]);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for VolumeReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            // ntfs seeks absolutely; support Start fully, Current relatively. End is unsupported
            // (volume size not tracked) → error rather than a wrong answer.
            let target = match pos {
                SeekFrom::Start(n) => n,
                SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
                SeekFrom::End(_) => {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "seek from end unsupported"));
                }
            };
            // Align the underlying pointer DOWN to a sector; read() reads from there. We track
            // logical pos separately so callers see exact positioning.
            let aligned = super::align_down(target, self.sector) as i64;
            let mut new_ptr = 0i64;
            // SAFETY: handle is valid; new_ptr receives the resulting absolute offset.
            unsafe {
                SetFilePointerEx(self.handle.0, aligned, Some(&mut new_ptr), FILE_BEGIN)
                    .map_err(|e| io::Error::other(format!("SetFilePointerEx: {e}")))?;
            }
            self.pos = target;
            Ok(target)
        }
    }
}

pub use imp::VolumeReader;
```

> NOTE for the implementer: the `windows` 0.x API surface (exact arg types for `CreateFileW`/
> `ReadFile`/`SetFilePointerEx`, whether `GENERIC_READ.0` vs `GENERIC_READ`) may differ slightly
> by crate version — adjust to what compiles, keeping the READ-ONLY flags exact. If `read()`'s
> sector-aligned scheme conflicts with how `ntfs` issues reads (it may seek then read unaligned
> lengths), the correct fix is to buffer a full aligned sector internally and serve sub-ranges —
> do that rather than relaxing alignment. The alignment HELPERS stay as the tested core.

- [ ] **Step 5: Run tests (Linux-testable parts) + check Windows compiles**

Run: `cargo test -p cairn-collectors-win volume:: 2>&1 | tail -20`
Expected: PASS (alignment math + off-platform open Err). On Windows also: `cargo check -p cairn-collectors-win`.

- [ ] **Step 6: Add the module** to `crates/cairn-collectors-win/src/lib.rs`:

```rust
pub mod volume;
```

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors-win/
git commit -m "feat(s2m): read-only VolumeReader (\\\\.\\C: Read+Seek; the only new unsafe)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `MftCollector` — $MFT proof, with the two-layer DoS guard (the security heart)

**Why:** consumes the safe `VolumeReader` + `ntfs` 0.4 to emit `Record::FileMeta` (count + first N
names). Carries the mandated short-read defenses (spec §②): boot-sector length pre-check AND
`catch_unwind`. Privilege-gates; degrades gracefully.

**Files:**
- Modify: `crates/cairn-collectors/Cargo.toml` (add `ntfs` + cairn-collectors-win dep)
- Create: `crates/cairn-collectors/src/mft.rs`
- Modify: `crates/cairn-collectors/src/lib.rs` (add `pub mod mft;`)

- [ ] **Step 1: Add dependencies** to `crates/cairn-collectors/Cargo.toml` under `[dependencies]`:

```toml
cairn-collectors-win = { path = "../cairn-collectors-win" }
ntfs = "=0.4.0"
```

- [ ] **Step 2: Write the failing tests first** — create `mft.rs` with tests + a stub:

```rust
//! MftCollector (SRS §4 mft_collector, FR12): the minimal raw-NTFS proof. Reads $MFT via the
//! safe VolumeReader + `ntfs` 0.4, emits Record::FileMeta (record count + first N file names).
//! Does NOT do MACB/timestomp (that is S2-N). Read-only; never modifies the host.
//!
//! SECURITY (spec §②, MEASURED): `ntfs` 0.4 PANICS on a short read (reader < one boot sector).
//! Two guards: (a) a boot-sector length pre-check before Ntfs::new, (b) catch_unwind around the
//! parse. No input may make a panic escape this collector. `catch_unwind` here contains a
//! third-party panic — it does NOT hide our own logic errors (those return Err normally).
#![allow(clippy::result_large_err)]

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{FileMetaRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};
use std::io::{Read, Seek};

/// Max file names to emit (the "first N" proof). Also a small NFR10 nod (bounded output).
const MAX_NAMES: usize = 50;
/// One NTFS boot sector is 512 bytes; the measured `ntfs` 0.4 panic is a read shorter than this.
const BOOT_SECTOR_LEN: usize = 512;

#[derive(Default)]
pub struct MftCollector;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ctx_no_priv() -> () {} // placeholder; see Step 4 for the real CollectCtx fake

    #[test]
    fn parse_short_source_returns_err_not_panic() {
        // The two inputs that panicked `ntfs` 0.4 RAW in the probe: empty and 3 bytes.
        // Through our guarded helper they MUST be Err, with no panic escaping.
        for bytes in [vec![], vec![0xEB, 0x52, 0x90]] {
            let mut cur = Cursor::new(bytes);
            let r = parse_mft_names(&mut cur, MAX_NAMES);
            assert!(r.is_err(), "short source must be Err, never panic");
        }
    }

    #[test]
    fn parse_garbage_full_sector_returns_err_not_panic() {
        // A full sector of zeros: ntfs returns clean Err (boot signature); our wrapper passes it.
        let mut cur = Cursor::new(vec![0u8; 1024]);
        let r = parse_mft_names(&mut cur, MAX_NAMES);
        assert!(r.is_err());
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p cairn-collectors mft:: 2>&1 | tail -20`
Expected: FAIL (`parse_mft_names` not defined).

- [ ] **Step 4: Implement the guarded parser + collector** — add to `mft.rs` (replace the stub
`ctx_no_priv` placeholder usage by writing the real impl below; the test fake CollectCtx is in
Step 5):

```rust
/// Parse $MFT from a Read+Seek source and return (record_count, first-N file names).
/// SECURITY: guard (a) boot-sector length pre-check + guard (b) catch_unwind (spec §②).
/// Never panics out; any failure → Err. The source is read-only.
pub(crate) fn parse_mft_names<R: Read + Seek>(
    src: &mut R,
    max_names: usize,
) -> Result<(u64, Vec<String>)> {
    // Guard (a): refuse a source too short to hold a boot sector — the measured ntfs panic
    // trigger. Read the first sector; a short read → Err, never call Ntfs::new.
    let mut probe = [0u8; BOOT_SECTOR_LEN];
    use std::io::SeekFrom;
    src.seek(SeekFrom::Start(0))
        .map_err(|e| CairnError::Collector { collector: "mft".into(), reason: format!("seek: {e}") })?;
    src.read_exact(&mut probe).map_err(|e| CairnError::Collector {
        collector: "mft".into(),
        reason: format!("source shorter than one boot sector ({e})"),
    })?;
    src.seek(SeekFrom::Start(0))
        .map_err(|e| CairnError::Collector { collector: "mft".into(), reason: format!("seek: {e}") })?;

    // Guard (b): contain any third-party panic from ntfs as an Err (defense in depth).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_mft_inner(src, max_names)
    }));
    match result {
        Ok(inner) => inner,
        Err(_) => Err(CairnError::Collector {
            collector: "mft".into(),
            reason: "ntfs parser panicked (contained); treating volume as unreadable".into(),
        }),
    }
}

/// The actual ntfs walk. Separated so catch_unwind wraps exactly this. Bounded iteration.
fn parse_mft_inner<R: Read + Seek>(src: &mut R, max_names: usize) -> Result<(u64, Vec<String>)> {
    use ntfs::Ntfs;
    let ntfs = Ntfs::new(src).map_err(|e| CairnError::Collector {
        collector: "mft".into(),
        reason: format!("Ntfs::new: {e}"),
    })?;
    // Count + first-N names by walking the root directory index in deterministic order.
    // (NOTE: the EXACT ntfs 0.4 call to enumerate ALL $MFT records vs the root dir index is
    // pinned during this task — see spec TASK-0 item 1. The probe-verified path is
    // root_directory -> directory_index -> entries; if a full-$MFT iterator exists, prefer it
    // for a true "record count". Either way: bounded, deterministic, returns Result.)
    let root = ntfs.root_directory(src).map_err(|e| CairnError::Collector {
        collector: "mft".into(),
        reason: format!("root_directory: {e}"),
    })?;
    let index = root.directory_index(src).map_err(|e| CairnError::Collector {
        collector: "mft".into(),
        reason: format!("directory_index: {e}"),
    })?;
    let mut entries = index.entries();
    let mut count: u64 = 0;
    let mut names: Vec<String> = Vec::new();
    while let Some(entry) = entries.next(src) {
        let entry = entry.map_err(|e| CairnError::Collector {
            collector: "mft".into(),
            reason: format!("index entry: {e}"),
        })?;
        count += 1;
        if names.len() < max_names {
            if let Some(key) = entry.key() {
                if let Ok(name) = key {
                    names.push(name.name().to_string_lossy());
                }
            }
        }
    }
    Ok((count, names))
}

impl Collector for MftCollector {
    fn name(&self) -> &str { "mft" }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Privilege gate (golden rule 8): raw volume read needs admin + SeBackup. Missing →
        // Err(Privilege); the orchestrator records it + continues (no host access attempted).
        if !(ctx.admin && ctx.se_backup) {
            return Err(CairnError::Privilege {
                what: "mft".into(),
                need: "Administrator + SeBackupPrivilege".into(),
            });
        }
        let mut reader = cairn_collectors_win::volume::VolumeReader::open(r"\\.\C:")?;
        let (count, names) = parse_mft_names(&mut reader, MAX_NAMES)?;
        // Minimal proof: one FileMeta per name (path = name, size left 0; MACB None = S2-N).
        // Plus the record count is surfaced via the source entry / log.
        tracing::info!(mft_records = count, names = names.len(), "mft proof");
        Ok(names
            .into_iter()
            .map(|n| {
                Record::FileMeta(FileMetaRecord {
                    path: n,
                    size: 0,
                    sha256: None,
                    si_btime: None,
                    si_mtime: None,
                    fn_btime: None,
                    zone_identifier: None,
                })
            })
            .collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "mft".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }]
    }
}
```

> NOTE for the implementer: the `ntfs` 0.4 entry-key/name extraction (`entry.key()` shape, how to
> get a UTF-16 name to a String) MUST match the real 0.4 API — adjust the inner loop to what
> compiles (the probe used `entries.next(&mut cur)` returning `Option<Result<NtfsIndexEntry>>`).
> Keep it bounded + deterministic + Result-returning. Do NOT relax the two guards.

- [ ] **Step 5: Add a privilege-gate unit test** (the CollectCtx fake) to the `mod tests`:

```rust
    #[test]
    fn collect_without_privilege_returns_err_no_host_access() {
        use cairn_core::config::Config;
        let cfg = Config::default();
        let ctx = CollectCtx { config: &cfg, admin: false, se_backup: false, se_debug: false };
        let r = MftCollector.collect(&ctx);
        assert!(matches!(r, Err(CairnError::Privilege { .. })),
            "no admin/se_backup must yield Privilege err before any volume open");
    }
```

(Remove the `ctx_no_priv` placeholder from Step 2.)

- [ ] **Step 6: Run all mft tests**

Run: `cargo test -p cairn-collectors mft:: 2>&1 | tail -20`
Expected: PASS — short-source→Err (no panic), garbage→Err, no-priv→Privilege err.

- [ ] **Step 7: Register the module** in `crates/cairn-collectors/src/lib.rs`:

```rust
pub mod mft;
```

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-collectors/
git commit -m "feat(s2m): MftCollector with two-layer DoS guard (\$MFT count + first N names)

boot-sector length pre-check + catch_unwind contain the measured ntfs 0.4 short-read
panic (spec §2). Privilege-gated, read-only, emits Record::FileMeta.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: CLI wiring — register `mft` into selection + construction

**Why:** make `--only mft` / profile selection actually build the collector. Mirror the S2-L
pattern exactly (AVAILABLE + if-block + built_collector_names mirror — kept in sync, the S2-L trap).

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (AVAILABLE ~575, if-blocks ~593, mirror ~782)

- [ ] **Step 1: Add "mft" to AVAILABLE** (run arm, ~line 575):

```rust
            const AVAILABLE: &[&str] = &["proc", "net", "persist", "mft"];
```

- [ ] **Step 2: Add the construction if-block** after the `persist` block (~line 603):

```rust
            if selection.selected.iter().any(|m| m == "mft") {
                collectors.push(Box::new(cairn_collectors::mft::MftCollector));
            }
```

- [ ] **Step 3: Update the `built_collector_names` mirror** (~line 782, the test helper) to include
mft so it stays in sync with the construction blocks:

```rust
            if selected.iter().any(|m| m == "mft") {
                names.push("mft".to_string());
            }
```

- [ ] **Step 4: Add a CLI selection test** to the cli test module:

```rust
        // --profile minimal must NOT select mft (raw-NTFS); standard must.
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"mft".to_string()), "minimal skips raw-NTFS mft");

        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"mft".to_string()), "standard includes mft");
```

(Update the cli test's `AVAILABLE` const to `&["proc","net","persist","mft"]` to match the run arm.)

- [ ] **Step 5: Run cli tests + full workspace build**

Run: `cargo test -p cairn-cli 2>&1 | tail -20` then `cargo build --workspace 2>&1 | tail -5`
Expected: PASS + clean build.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(s2m): wire mft collector into run-arm selection (minimal skips it)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Final integration check (gates + honest e2e note)

**Why:** the Definition-of-Done gate for the whole sub-segment.

- [ ] **Step 1: Full gate**

Run, each must be clean:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked 2>&1 | tail -15
cargo audit --deny warnings 2>&1 | tail -15
```
Expected: fmt clean; clippy 0 warnings; all tests pass; audit clean (incl. new `ntfs` dep — if
audit flags `ntfs` or a transitive dep, STOP and report; do not silence).

- [ ] **Step 2: Verify the layering invariants** (grep, must match expectations):

```bash
grep -rn "unsafe" crates/cairn-collectors/src crates/cairn-core/src crates/cairn-cli/src
```
Expected: NO `unsafe` keyword in those three crates (only comments/strings mentioning it are ok;
no `unsafe {` blocks). The `#![forbid(unsafe_code)]` headers already enforce this at compile time.

```bash
grep -n "GENERIC_READ\|OPEN_EXISTING\|GENERIC_WRITE\|FILE_GENERIC_WRITE" crates/cairn-collectors-win/src/volume.rs
```
Expected: GENERIC_READ + OPEN_EXISTING present; NO write/append access right anywhere.

- [ ] **Step 3: Confirm Cargo.lock committed + pinned ntfs**

```bash
git status --short   # Cargo.lock should be staged/committed if changed
grep -A2 'name = "ntfs"' Cargo.lock | head -3
```
Expected: `ntfs` pinned to 0.4.0 in the lockfile.

- [ ] **Step 4: Document the manual elevated e2e** (it cannot run in CI / on this dev box as admin
automatically — record it honestly in the commit/PR body, do NOT fake-pass it):

The elevated e2e to be run by the operator on a real Windows admin shell:
```
# Elevated (Administrator) PowerShell, off-target output:
cairn run --target live --only mft --out <off-target-dir>
#   expect: records.jsonl has Record::FileMeta entries (kind=file_meta), manifest
#   SourceEntry artifact=mft method=raw_ntfs, cairn verify <manifest> => OK
# Non-elevated:
cairn run --target live --only mft --out <dir2>
#   expect: mft skipped, manifest SourceEntry mft has errors=[Privilege...], run still OK
cairn run --target live --profile minimal --out <dir3>
#   expect: selected modules do NOT include mft
```

- [ ] **Step 5: Commit any final fmt/fixups**, then the sub-segment is ready for final review +
finishing-a-development-branch.

```bash
git add -A
git commit -m "chore(s2m): final gate (fmt/clippy/test/audit) + manual elevated e2e note

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>" || echo "nothing to commit"
```

---

## Self-Review (done by plan author)

- **Spec coverage:** VolumeReader unsafe primitive (T2), ntfs 0.4 + MftCollector (T3), $MFT count +
  first N names → FileMeta (T3), minimal-skips-rawNTFS (T1), CLI wiring (T4), two-layer DoS guard
  (T3, the user directive), read-only flags (T2 + T5 grep), privilege degrade (T3), gates (T5),
  manual elevated e2e (T5). All spec sections map to a task. ✓
- **Placeholder scan:** the two `NOTE for the implementer` blocks are explicit "adjust to the real
  ntfs/windows API that compiles" guidance grounded in probe-verified call shapes — not vague TODOs.
  No "add error handling"/"TBD". ✓
- **Type consistency:** `parse_mft_names`/`parse_mft_inner` signatures match across T3 steps;
  `FileMetaRecord` fields match record.rs (path/size/sha256/si_btime/si_mtime/fn_btime/zone_identifier);
  `CollectCtx`/`CairnError::Privilege` match traits.rs/error usage; `AVAILABLE` updated consistently
  in run arm AND cli test (the S2-L sync trap addressed in T4). ✓
- **Known soft spot (flagged honestly):** the exact `ntfs` 0.4 record-enumeration + name-extraction
  calls (T3 inner loop) and the IOCTL sector-size query (T2) are the residual Windows-only API
  details; the plan tells the implementer to pin them to what compiles, keeping guards/alignment/
  determinism fixed. These can't be fully nailed on this Linux-style dev box without the elevated
  Windows path, and the plan says so rather than pretending.
