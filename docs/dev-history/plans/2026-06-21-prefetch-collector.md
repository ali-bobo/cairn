# Prefetch Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse `C:\Windows\Prefetch\*.pf` (Win10+ MAM-compressed) into `Record::Execution` with real run_count + first/last run times, using `compcol` for MAM decompression.

**Architecture:** A new `prefetch.rs` in cairn-collectors (no raw-NTFS, no unsafe, admin-only). Three layers: `decompress_mam` (compcol xpress_huffman wrapper), pure `parse_prefetch` (header → PrefetchInfo, never-panic), and `PrefetchCollector` (std::fs enumerate + per-file graceful degrade → Record). Wire into selection (RAW_NTFS renamed HEAVY_OFFLINE) and the CLI run arm.

**Tech Stack:** Rust, `compcol` (new dep, MIT, xpress_huffman feature only), `std::fs`, `cairn-collectors` (`#![forbid(unsafe_code)]`), the existing `filetime_to_utc`.

**Authoritative spec:** `docs/superpowers/specs/2026-06-21-prefetch-collector-design.md`

---

## Context for the implementer (read before Task 1)

- This is the FIRST non-raw-NTFS offline collector. NO VolumeReader, NO ntfs, NO unsafe,
  admin-only (NOT SeBackup). Compare the COLLECTOR SHAPE (flags, sources(), privilege
  gate, determinism sort, #[ignore] e2e) against `crates/cairn-collectors/src/amcache.rs`,
  but note prefetch reads via `std::fs`, not raw volume.
- `crates/cairn-core/src/record.rs` — `ExecutionRecord` (all fields exist; schema UNCHANGED).
- `crates/cairn-core/src/time.rs` — `filetime_to_utc(ft: u64) -> Option<DateTime<Utc>>`
  (REUSE for run times; ft==0 → None, which filters zero-padded slots automatically).
- `crates/cairn-core/src/selection.rs` — `RAW_NTFS` const (3 references: definition L34,
  doc comment L39, filter L45). You RENAME it to `HEAVY_OFFLINE`.
- `crates/cairn-cli/src/main.rs` — AVAILABLE arrays, `built_collector_names`, push blocks.

### compcol API (verify exactly in Task 1 — do NOT guess the signature)
Known from docs: feature flag `xpress_huffman`; module path `compcol::xpress_huffman::`;
a `vec` module exists with "one-shot Vec<u8> compress/decompress helpers". The EXACT
function name/signature for one-shot decompress is NOT yet confirmed — Task 1 confirms it
by reading the installed source (`~/.cargo/registry/src/.../compcol-*/src/`) or
`cargo doc`, and the round-trip test in Task 1 is what pins it down. Do NOT write the
signature into later tasks until Task 1 has confirmed it; Task 2 references whatever Task 1
established.

### Prefetch .pf format facts (Win10 v30, standard DFIR knowledge — e2e is the verifier)
- The .pf may be MAM-compressed: magic `MAM\x04` (4 bytes) at offset 0, uncompressed size
  as u32 at offset 4, compressed payload from offset 8. Older/uncompressed .pf start with
  the version number directly (no MAM magic).
- After decompression, the prefetch header: format version = u32 at offset 0 (Win10 = 30);
  signature "SCCA" at offset 4; the executable name is a UTF-16LE string in the header
  (Win10 v30: at offset 16, up to 60 bytes / 29 UTF-16 chars, NUL-terminated).
- Win10 v30 file-information layout: run_count and the 8 last-run FILETIME timestamps live
  in the file-information section. The exact offsets are version-specific; Task 3 documents
  the v30 offsets it uses as named consts (single fix-point), and the e2e verifies them.
- These offsets are MEDIUM-confidence; isolate them as named consts and let the e2e be the
  field verifier (same honesty posture as the amcache DRIVER_SPEC).

### Standing constraints (every task)
- `#![forbid(unsafe_code)]`. Zero unsafe.
- Never panic in non-test code (bounds-checked readers).
- Schema UNCHANGED (do not touch record.rs).
- Determinism: sort emitted records by path (NFR4).
- Commit footer EXACTLY: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Before each commit: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`. Local clippy MUST use `--all-targets` (matches CI).
- Target dir is preconfigured (.cargo/config.toml); do not change it.

---

## Task 1: Land the compcol dependency + confirm the decompress API (T0-level)

**Files:**
- Modify: `Cargo.toml` (workspace deps), `crates/cairn-collectors/Cargo.toml`
- Modify: `crates/cairn-collectors/src/lib.rs` (add `pub mod prefetch;`)
- Create: `crates/cairn-collectors/src/prefetch.rs` (module doc + the round-trip test only)
- Possibly: `.cargo/audit.toml` (only if cargo audit flags a new non-CVE advisory)

This is a dependency-resolution task like the notatin landing (hive segment). Resolve the
version, confirm it compiles, confirm cargo audit is green, and pin the exact API via a
round-trip test. Do NOT build the collector yet.

- [ ] **Step 1: Add the dependency**

Add to the workspace `[workspace.dependencies]` in root `Cargo.toml`:
```toml
compcol = { version = "0.6", default-features = false, features = ["xpress_huffman"] }
```
(Use the latest 0.6.x that resolves; `cargo add` picks it. If 0.6 does not resolve, report
the actual latest and use it — pin whatever resolves.)

Then in `crates/cairn-collectors/Cargo.toml` `[dependencies]`:
```toml
compcol = { workspace = true }
```

Run `cargo add -p cairn-collectors compcol --no-default-features --features xpress_huffman`
if you prefer the tool to wire both; verify the result matches the above (workspace dep +
member reference, default-features off, only xpress_huffman).

- [ ] **Step 2: Register the module + write the API-pinning round-trip test**

In `crates/cairn-collectors/src/lib.rs` add `pub mod prefetch;` (alphabetical — after
`pub mod persist;`/before `pub mod proc` per the existing order; check and place correctly).

Create `crates/cairn-collectors/src/prefetch.rs`:
```rust
//! PrefetchCollector: parse C:\Windows\Prefetch\*.pf (Win10+ MAM-compressed) into
//! Record::Execution with real run_count + first/last run times. The first non-raw-NTFS
//! offline collector: std::fs reads (admin only, .pf is not OS-locked), compcol decompresses
//! the MAM (Xpress-Huffman) wrapper, a pure never-panic parser reads the header. Recognised
//! format versions only (Win10 v30); an unrecognised version ABSTAINS (NFR12).

#[cfg(test)]
mod tests {
    /// Pins the compcol xpress_huffman one-shot decompress API. If this fails to COMPILE,
    /// the function path/signature below is wrong — fix it from the installed compcol source
    /// (~/.cargo/registry/src/.../compcol-*/src/) and update Task 2 to match.
    #[test]
    fn compcol_xpress_huffman_round_trips() {
        let original = b"the quick brown fox jumps over the lazy dog, repeatedly. \
                         the quick brown fox jumps over the lazy dog, repeatedly.";
        // CONFIRM these two calls against the installed compcol source. The design expects
        // a one-shot vec helper under compcol::xpress_huffman (or compcol::vec). Adjust the
        // exact path/name to what the crate actually exposes, then keep this test as the
        // canonical reference for Task 2.
        let compressed = compcol::xpress_huffman::vec::compress(original)
            .expect("xpress_huffman compress");
        let restored = compcol::xpress_huffman::vec::decompress(&compressed)
            .expect("xpress_huffman decompress");
        assert_eq!(restored, original);
    }
}
```

NOTE: the `compcol::xpress_huffman::vec::{compress,decompress}` paths are the EXPECTED
shape, not confirmed. Your job in this step is to make this test COMPILE AND PASS by using
the crate's real API. Read the installed source if the path is wrong. Whatever paths make
this pass become the API that Task 2 wraps. Report the exact confirmed signatures.

- [ ] **Step 3: Resolve, compile, test**

```
cargo update -p compcol  # if needed to resolve
cargo test -p cairn-collectors prefetch::tests::compcol_xpress_huffman_round_trips
```
Expected: PASS. If it does not COMPILE, the API path is wrong — fix from source. If compcol
itself does not compile (e.g. an edition / MSRV clash with rust-toolchain.toml 1.95.0),
STOP and report — this is a dependency blocker for the controller to resolve (mirrors the
notatin/nom pin episode).

- [ ] **Step 4: cargo audit gate**

```
cargo audit
```
Expected: clean. If compcol or a transitive dep raises a NON-CVE advisory (unmaintained,
etc.), add it to `.cargo/audit.toml` `ignore` with a full rationale comment mirroring the
existing RUSTSEC-2021-0153 (encoding) / RUSTSEC-2024-0436 (paste) entries. If it raises a
REAL CVE, STOP and report (do not ignore a CVE).

- [ ] **Step 5: Verify Cargo.lock is committed + lint + commit**

```
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/cairn-collectors/Cargo.toml crates/cairn-collectors/src/lib.rs crates/cairn-collectors/src/prefetch.rs .cargo/audit.toml
git commit -m "feat(prefetch): land compcol dep + pin xpress_huffman decompress API

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```
(Include .cargo/audit.toml in the add ONLY if you modified it.)

## Report after Task 1
Report the EXACT confirmed compcol API (module path + function names + signatures for
one-shot compress/decompress), the resolved compcol version, whether audit needed an
ignore entry, and STATUS. Task 2 depends on the confirmed API.

---

## Task 2: decompress_mam wrapper

**Files:** Modify `crates/cairn-collectors/src/prefetch.rs`

Wrap compcol behind a function that handles the MAM container (magic + size) and passes
through uncompressed .pf. Use the compcol API CONFIRMED in Task 1 — substitute the actual
`compress`/`decompress` paths Task 1 reported wherever this plan writes
`compcol::xpress_huffman::vec::{compress,decompress}`.

- [ ] **Step 1: Write the failing tests** — in `prefetch.rs` `mod tests`:

```rust
    use super::*;

    #[test]
    fn decompress_mam_passes_through_non_mam() {
        let raw = b"SCCA-ish uncompressed bytes".to_vec();
        assert_eq!(decompress_mam(&raw).expect("passthrough"), raw);
    }

    #[test]
    fn decompress_mam_decompresses_mam_container() {
        let original = b"prefetch decompressed body ".repeat(8);
        let payload = compcol::xpress_huffman::vec::compress(&original).expect("compress");
        let mut mam = Vec::new();
        mam.extend_from_slice(b"MAM\x04");
        mam.extend_from_slice(&(original.len() as u32).to_le_bytes());
        mam.extend_from_slice(&payload);
        assert_eq!(decompress_mam(&mam).expect("decompress"), original);
    }

    #[test]
    fn decompress_mam_too_short_is_err_not_panic() {
        let raw = b"MAM\x04\x01".to_vec();
        assert!(decompress_mam(&raw).is_err());
    }
```

- [ ] **Step 2: Run, confirm FAIL** — `cargo test -p cairn-collectors prefetch::tests::decompress_mam`

- [ ] **Step 3: Implement** — add to `prefetch.rs` (module level; replace compcol path with Task 1's confirmed one):

```rust
use cairn_core::{CairnError, Result};

const MAM_MAGIC: &[u8; 4] = b"MAM\x04";

#[inline]
fn prefetch_err(reason: String) -> CairnError {
    CairnError::Collector { collector: "prefetch".into(), reason }
}

/// Decompress a .pf outer container. MAM files (magic "MAM\x04", uncompressed size u32 at
/// offset 4, payload from offset 8) are Xpress-Huffman-decompressed via compcol. Files
/// without the MAM magic (older uncompressed .pf) are returned unchanged. A malformed MAM
/// container or a decompression failure yields Err (the caller abstains on that file).
fn decompress_mam(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 4 || &raw[0..4] != MAM_MAGIC {
        return Ok(raw.to_vec()); // not MAM-compressed: pass through
    }
    if raw.len() < 8 {
        return Err(prefetch_err("MAM header truncated (no uncompressed size)".into()));
    }
    let payload = &raw[8..];
    compcol::xpress_huffman::vec::decompress(payload)
        .map_err(|e| prefetch_err(format!("MAM decompression failed: {e}")))
}
```
If Task 1 reported decompress REQUIRES the uncompressed size, read
`u32::from_le_bytes(raw[4..8].try_into().unwrap())` and pass it per the confirmed signature.

- [ ] **Step 4: Run, confirm PASS** — `cargo test -p cairn-collectors prefetch::tests::decompress_mam` (3 pass)

- [ ] **Step 5: Lint + commit**

```bash
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add crates/cairn-collectors/src/prefetch.rs
git commit -m "feat(prefetch): decompress_mam wrapper (MAM container + passthrough)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: parse_prefetch pure parser

**Files:** Modify `crates/cairn-collectors/src/prefetch.rs`

Pure, never-panic parser of DECOMPRESSED prefetch bytes → PrefetchInfo. Win10 v30 only.

- [ ] **Step 1: Write the failing tests** — in `mod tests`:

```rust
    use chrono::{DateTime, Utc};

    // FILETIME for 2021-01-01T00:00:00Z (verified: 132_539_328_000_000_000).
    const FT_2021: u64 = 132_539_328_000_000_000;

    /// Build a minimal Win10 v30 body (already decompressed) using the impl's offset consts.
    fn build_v30(exe: &str, run_count: u32, run_times: &[u64]) -> Vec<u8> {
        let mut buf = vec![0u8; V30_MIN_LEN];
        buf[0..4].copy_from_slice(&30u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        let utf16: Vec<u8> = exe.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let cap = utf16.len().min(EXE_NAME_MAX_BYTES);
        buf[EXE_NAME_OFFSET..EXE_NAME_OFFSET + cap].copy_from_slice(&utf16[..cap]);
        buf[RUN_COUNT_OFFSET..RUN_COUNT_OFFSET + 4].copy_from_slice(&run_count.to_le_bytes());
        for (i, ft) in run_times.iter().take(8).enumerate() {
            let off = RUN_TIMES_OFFSET + i * 8;
            buf[off..off + 8].copy_from_slice(&ft.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parse_v30_basic() {
        let body = build_v30("NOTEPAD.EXE", 5, &[FT_2021, FT_2021 + 10_000_000]);
        let info = parse_prefetch(&body).expect("v30 parses");
        assert_eq!(info.exe_name, "NOTEPAD.EXE");
        assert_eq!(info.run_count, 5);
        assert_eq!(info.run_times.len(), 2);
    }

    #[test]
    fn parse_unknown_version_is_none() {
        let mut body = build_v30("X.EXE", 1, &[FT_2021]);
        body[0..4].copy_from_slice(&26u32.to_le_bytes()); // Win8 v26 — unrecognised
        assert!(parse_prefetch(&body).is_none());
    }

    #[test]
    fn parse_truncated_is_none_no_panic() {
        assert!(parse_prefetch(&[30u8, 0, 0, 0]).is_none());
    }

    #[test]
    fn parse_all_zero_run_times_yields_empty_vec() {
        let body = build_v30("Z.EXE", 0, &[]);
        let info = parse_prefetch(&body).expect("parses");
        assert!(info.run_times.is_empty());
    }
```

- [ ] **Step 2: Run, confirm FAIL** — `cargo test -p cairn-collectors prefetch::tests::parse_`

- [ ] **Step 3: Implement** — add to `prefetch.rs`:

```rust
use chrono::{DateTime, Utc};
use cairn_core::time::filetime_to_utc;

/// Parsed prefetch header — prefetch.rs's OWN pure type (no parser internals leak).
#[derive(Debug, PartialEq)]
struct PrefetchInfo {
    exe_name: String, // header NAME only, not a full path (design §2)
    run_count: u32,
    run_times: Vec<DateTime<Utc>>, // up to 8, zeros filtered
}

// Win10 v30 layout consts — the single fix-point for format offsets (e2e verifies them).
const PF_V30: u32 = 30;
const EXE_NAME_OFFSET: usize = 16;
const EXE_NAME_MAX_BYTES: usize = 60;
const RUN_COUNT_OFFSET: usize = 0xD0;
const RUN_TIMES_OFFSET: usize = 0x80;
const V30_MIN_LEN: usize = RUN_COUNT_OFFSET + 4;

fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)?.try_into().ok().map(u32::from_le_bytes)
}
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)?.try_into().ok().map(u64::from_le_bytes)
}

/// UTF-16LE NUL-terminated name from a capped window. Never panics; lossy on bad units.
fn read_exe_name(buf: &[u8]) -> String {
    let end = (EXE_NAME_OFFSET + EXE_NAME_MAX_BYTES).min(buf.len());
    let slice = match buf.get(EXE_NAME_OFFSET..end) {
        Some(s) => s,
        None => return String::new(),
    };
    let mut units = Vec::new();
    for pair in slice.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// Parse decompressed prefetch bytes. Win10 v30 only; unrecognised version → None (abstain).
/// Never panics (all reads bounds-checked).
fn parse_prefetch(buf: &[u8]) -> Option<PrefetchInfo> {
    let version = rd_u32(buf, 0)?;
    if version != PF_V30 {
        return None;
    }
    let run_count = rd_u32(buf, RUN_COUNT_OFFSET).unwrap_or(0);
    let exe_name = read_exe_name(buf);
    let mut run_times = Vec::new();
    for i in 0..8 {
        if let Some(ft) = rd_u64(buf, RUN_TIMES_OFFSET + i * 8) {
            if let Some(dt) = filetime_to_utc(ft) {
                run_times.push(dt);
            }
        }
    }
    Some(PrefetchInfo { exe_name, run_count, run_times })
}
```
NOTE: the v30 offsets are medium-confidence; build_v30 uses the SAME consts so unit tests
pass by construction, and the e2e (Task 6) verifies them against a real .pf. Wrong offsets =
one-line fix.

- [ ] **Step 4: Run, confirm PASS** — `cargo test -p cairn-collectors prefetch::tests::parse_` (4 pass)

- [ ] **Step 5: Lint + commit**

```bash
cargo fmt
cargo clippy -p cairn-collectors --all-targets -- -D warnings
git add crates/cairn-collectors/src/prefetch.rs
git commit -m "feat(prefetch): pure parse_prefetch (Win10 v30 header, never-panic)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: PrefetchCollector

**Files:** Modify `crates/cairn-collectors/src/prefetch.rs`

Enumerate the Prefetch dir, read each .pf via std::fs, decompress+parse, map to Record,
degrade per-file. Mirror amcache's collector shape but std::fs (not raw volume).

- [ ] **Step 1: Add imports + const + struct** — at the top of `prefetch.rs` (after module doc):

```rust
use std::sync::atomic::{AtomicBool, Ordering};

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};

const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";

/// PrefetchCollector: admin-only, read-only parse of C:\Windows\Prefetch\*.pf into
/// Record::Execution (source="prefetch") with real run_count + first/last run times.
#[derive(Default)]
pub struct PrefetchCollector {
    dir_unreadable: AtomicBool,
    file_read_errors: AtomicBool,
    decompress_errors: AtomicBool,
    unknown_version: AtomicBool,
}
```
(`Result`/`CairnError`/`prefetch_err` and `decompress_mam`/`parse_prefetch`/`PrefetchInfo`
are already in the module.)

- [ ] **Step 2: Write the surface tests** — in `mod tests`:

```rust
    use cairn_core::config::Config;
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::CairnError;
    use std::sync::atomic::Ordering;

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx { config: &cfg, admin: false, se_backup: false, se_debug: false };
        assert!(matches!(PrefetchCollector::default().collect(&ctx), Err(CairnError::Privilege { .. })));
    }

    #[test]
    fn name_is_prefetch() {
        assert_eq!(PrefetchCollector::default().name(), "prefetch");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = PrefetchCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "prefetch");
    }

    #[test]
    fn sources_reports_dir_unreadable() {
        let c = PrefetchCollector::default();
        c.dir_unreadable.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("Prefetch directory")));
    }

    #[test]
    fn sources_reports_unknown_version() {
        let c = PrefetchCollector::default();
        c.unknown_version.store(true, Ordering::Relaxed);
        assert!(c.sources()[0].errors.iter().any(|e| e.contains("unrecognised format version")));
    }

    #[test]
    fn sources_reports_partial_read_and_decompress() {
        let c = PrefetchCollector::default();
        c.file_read_errors.store(true, Ordering::Relaxed);
        c.decompress_errors.store(true, Ordering::Relaxed);
        let errs = c.sources()[0].errors.clone();
        assert!(errs.iter().any(|e| e.contains("unreadable")));
        assert!(errs.iter().any(|e| e.contains("MAM decompression")));
    }
```

- [ ] **Step 3: Run, confirm FAIL** — `cargo test -p cairn-collectors prefetch::tests` (Collector not impl'd)

- [ ] **Step 4: Implement** — add to `prefetch.rs`:

```rust
impl PrefetchCollector {
    fn to_record(info: PrefetchInfo) -> Record {
        let last_run = info.run_times.iter().max().copied();
        let first_run = info.run_times.iter().min().copied();
        Record::Execution(ExecutionRecord {
            source: "prefetch".into(),
            path: info.exe_name, // header NAME only (design §2)
            first_run,
            last_run,
            run_count: Some(info.run_count),
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        })
    }
}

impl Collector for PrefetchCollector {
    fn name(&self) -> &str {
        "prefetch"
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        if !ctx.admin {
            return Err(CairnError::Privilege {
                what: "prefetch".into(),
                need: "Administrator".into(),
            });
        }

        let entries = match std::fs::read_dir(PREFETCH_DIR) {
            Ok(rd) => rd,
            Err(e) => {
                self.dir_unreadable.store(true, Ordering::Relaxed);
                tracing::warn!(err = %e, "prefetch: dir unreadable; abstaining");
                return Ok(Vec::new());
            }
        };

        let mut records: Vec<Record> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("pf"))
                != Some(true)
            {
                continue;
            }
            let raw = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    self.file_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(file = ?path, err = %e, "prefetch: read failed; skipping");
                    continue;
                }
            };
            let decompressed = match decompress_mam(&raw) {
                Ok(b) => b,
                Err(e) => {
                    self.decompress_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(file = ?path, err = %e, "prefetch: decompress failed; skipping");
                    continue;
                }
            };
            match parse_prefetch(&decompressed) {
                Some(info) => records.push(Self::to_record(info)),
                None => {
                    self.unknown_version.store(true, Ordering::Relaxed);
                    tracing::warn!(file = ?path, "prefetch: unrecognised version; skipping");
                }
            }
        }

        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => x.path.cmp(&y.path),
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution emitted
        });

        tracing::info!(prefetch_entries = records.len(), "prefetch scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.dir_unreadable.load(Ordering::Relaxed) {
            errors.push("abstained: Prefetch directory absent or unreadable".to_string());
        }
        if self.file_read_errors.load(Ordering::Relaxed) {
            errors.push("partial: one or more .pf files unreadable".to_string());
        }
        if self.decompress_errors.load(Ordering::Relaxed) {
            errors.push("partial: one or more .pf files failed MAM decompression".to_string());
        }
        if self.unknown_version.load(Ordering::Relaxed) {
            errors.push(
                "abstained: one or more .pf files had an unrecognised format version (NFR12)"
                    .to_string(),
            );
        }
        vec![SourceEntry {
            artifact: "prefetch".into(),
            path: PREFETCH_DIR.into(),
            method: "file_api".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}
```

- [ ] **Step 5: Run, confirm PASS** — `cargo test -p cairn-collectors prefetch::tests`

- [ ] **Step 6: Workspace gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/prefetch.rs
git commit -m "feat(prefetch): PrefetchCollector (std::fs enumerate, per-file degrade)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: selection (RAW_NTFS → HEAVY_OFFLINE) + CLI wiring

**Files:** Modify `crates/cairn-core/src/selection.rs`, `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: selection test (failing) + rename + add prefetch**

In `selection.rs` `mod tests` add:
```rust
    #[test]
    fn minimal_excludes_prefetch() {
        let available = vec!["proc", "net", "persist", "mft", "usn", "shimcache", "amcache", "prefetch"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"prefetch".to_string()));
    }
```
Run `cargo test -p cairn-core selection::tests::minimal_excludes_prefetch` → FAIL.

Rename the const + 3 references (definition, doc comment, `.filter(...)`):
```rust
/// Heavy offline collectors (raw-NTFS + prefetch + future srum/userassist). `--profile
/// minimal` skips all of these (SRS §19.1). The single place the profile→heavy-set mapping lives.
const HEAVY_OFFLINE: &[&str] = &["mft", "usn", "shimcache", "amcache", "prefetch"];
```
Update the `.filter(|name| !RAW_NTFS.contains(name))` to `!HEAVY_OFFLINE.contains(name)` and
any doc comment mentioning RAW_NTFS. Run all selection tests → pass.

- [ ] **Step 2: CLI test (failing)** — in `main.rs` tests, after the `standard includes amcache`
block add:
```rust
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"prefetch".to_string()), "standard includes prefetch");
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"prefetch".to_string()), "minimal skips prefetch");
```
And append `, "prefetch"` to the standard-selects-all vec assertion. Run `cargo test -p cairn-cli` → FAIL.

- [ ] **Step 3: Add prefetch to both AVAILABLE arrays + built_collector_names** — append
`"prefetch"` last to the run-block AVAILABLE, the test AVAILABLE, and the `built_collector_names`
array; update its doc count ("seven"→"eight") and append `/prefetch` to the collector list.

- [ ] **Step 4: Add the push block** — after the amcache push block:
```rust
            if selection.selected.iter().any(|m| m == "prefetch") {
                collectors.push(Box::new(
                    cairn_collectors::prefetch::PrefetchCollector::default(),
                ));
            }
```

- [ ] **Step 5: Workspace gate + commit**

```bash
cargo test -p cairn-cli
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/cairn-core/src/selection.rs crates/cairn-cli/src/main.rs
git commit -m "feat(prefetch): wire collector + rename RAW_NTFS to HEAVY_OFFLINE

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Elevated end-to-end test (ignored by default)

**Files:** Modify `crates/cairn-collectors/src/prefetch.rs`

- [ ] **Step 1: Add the ignored e2e** — in `mod tests`:

```rust
    use cairn_core::record::Record;

    /// ELEVATED E2E (manual): run as Administrator:
    ///   cargo test -p cairn-collectors prefetch::tests::prefetch_e2e_real_dir -- --ignored --nocapture
    /// Proves the full chain: std::fs enumerate C:\Windows\Prefetch -> MAM decompress (compcol)
    /// -> parse v30 header -> Record::Execution. The any_run assertion also verifies the v30
    /// offset consts (wrong offsets → zero/garbage run_count or run times).
    #[test]
    #[ignore = "requires Administrator and a real Windows C:\\Windows\\Prefetch"]
    fn prefetch_e2e_real_dir() {
        let cfg = Config::default();
        let ctx = CollectCtx { config: &cfg, admin: true, se_backup: false, se_debug: false };
        let recs = PrefetchCollector::default().collect(&ctx).expect("collect ok");
        assert!(!recs.is_empty(), "a real host has prefetch entries");
        let mut any_run = false;
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "prefetch");
                assert!(!e.path.is_empty(), "every entry has an exe name");
                assert_eq!(e.execution_confirmed, Some(true));
                assert!(e.run_count.is_some(), "prefetch carries a run count");
                if e.last_run.is_some() {
                    any_run = true;
                }
            } else {
                panic!("prefetch must only emit Execution records");
            }
        }
        assert!(any_run, "at least one entry should have a real last_run (offset sanity)");
        eprintln!("prefetch_e2e_real_dir: parsed {} entries", recs.len());
    }
```

- [ ] **Step 2: Verify compiles + ignored** — `cargo test -p cairn-collectors prefetch`
(non-ignored pass; `prefetch_e2e_real_dir ... ignored`).

- [ ] **Step 3: Final workspace gate + commit**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git add crates/cairn-collectors/src/prefetch.rs
git commit -m "test(prefetch): ignored elevated e2e for the full real-dir chain

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final acceptance (after all tasks)

- `cargo test --workspace` green (prior count + ~17 new prefetch tests; e2e ignored).
- `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check` clean.
- `Cargo.lock` updated with compcol pinned; schema (record.rs) UNCHANGED.
- `#![forbid(unsafe_code)]` intact (zero new unsafe; compcol is 100% safe).
- `--profile minimal` excludes prefetch (via HEAVY_OFFLINE); standard/verbose include it.
- cargo audit green (or a documented non-CVE ignore).

## Known residuals (documented, not defects)

1. **v30 offset confidence** — RUN_COUNT_OFFSET / RUN_TIMES_OFFSET / EXE_NAME_OFFSET are
   medium-confidence Win10 v30 facts, isolated as consts; the e2e `any_run` assertion is the
   field verifier. Wrong offsets are a one-line fix.
2. **Win11 version** — only Win10 v30 is recognised; Win11/24H2's version is added once the
   e2e on a real Win11 host confirms it. Until then Win11 .pf abstain (unknown_version).
3. **path is the exe NAME, not a full path** — prefetch headers carry only the filename; the
   full path is in the unparsed mapped-files section. Documented honesty limit (design §2).
4. **compcol new dependency** — pinned in Cargo.lock; built with only xpress_huffman; audit-gated.
