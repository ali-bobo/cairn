//! PrefetchCollector: parse C:\Windows\Prefetch\*.pf (Win10+ MAM-compressed) into
//! Record::Execution with real run_count + first/last run times. The first non-raw-NTFS
//! offline collector: std::fs reads (admin only, .pf is not OS-locked), compcol decompresses
//! the MAM (Xpress-Huffman) wrapper, a pure never-panic parser reads the header. Recognised
//! format versions only (Win10 v30); an unrecognised version ABSTAINS (NFR12).

use std::sync::atomic::{AtomicBool, Ordering};

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::time::filetime_to_utc;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};
use chrono::{DateTime, Utc};

const MAM_MAGIC: &[u8; 4] = b"MAM\x04";

/// Hard ceiling on a single decompressed .pf (NFR10). Real prefetch files are well under
/// a few MB; 64 MiB is far above any legitimate .pf yet caps a malicious MAM size lie.
/// NOTE: compcol 0.6.5 decompress_to_vec_capped takes u64, not usize.
const PREFETCH_DECOMPRESS_CEILING: u64 = 64 * 1024 * 1024;

const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";

#[inline]
fn prefetch_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "prefetch".into(),
        reason,
    }
}

/// Decompress a .pf outer container. A MAM file is `"MAM\x04"` (4 bytes) followed by the
/// compcol-framed Xpress-Huffman stream. Crucially, compcol's own frame begins with a
/// 4-byte LE uncompressed-length header — and that is EXACTLY the u32 that sits at MAM
/// offset 4. So the bytes compcol needs are `raw[4..]` (the MAM length header IS compcol's
/// length header; the MS-XCA bitstream follows it). We must NOT strip the length u32 —
/// passing `raw[8..]` would feed compcol the bare bitstream, and its decoder would misread
/// the first 4 bitstream bytes as the length and decode from the wrong position.
///
/// Decompression is capped (NFR10 — a malicious .pf cannot force an unbounded allocation).
/// Files without the MAM magic (older uncompressed .pf) are returned unchanged. A truncated
/// MAM container or a decompression failure (incl. exceeding the ceiling) yields Err (caller
/// abstains).
fn decompress_mam(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 4 || &raw[0..4] != MAM_MAGIC {
        return Ok(raw.to_vec()); // not MAM-compressed: pass through
    }
    if raw.len() < 8 {
        return Err(prefetch_err(
            "MAM header truncated (no length header)".into(),
        ));
    }
    // Keep the offset-4 u32 length header — it IS compcol's frame header.
    let stream = &raw[4..];
    compcol::vec::decompress_to_vec_capped::<compcol::xpress_huffman::XpressHuffman>(
        stream,
        PREFETCH_DECOMPRESS_CEILING,
    )
    .map_err(|e| prefetch_err(format!("MAM decompression failed: {e}")))
}

// ── Win10 v30 prefetch header layout ─────────────────────────────────────────
// These constants are the single fix-point for format offsets; the e2e test (Task 6)
// verifies them against a real .pf file. Wrong offsets = a one-line fix here.

/// The only supported prefetch format version (Windows 10/11).
const PF_V30: u32 = 30;

/// Byte offset of the NUL-terminated UTF-16LE executable name field in the header.
const EXE_NAME_OFFSET: usize = 16;

/// Maximum byte length of the name field (60 bytes = 30 UTF-16 code units).
const EXE_NAME_MAX_BYTES: usize = 60;

/// Byte offset of the run-times array (8 × u64 FILETIME slots).
const RUN_TIMES_OFFSET: usize = 0x80;

/// Byte offset of the u32 run-count field.
const RUN_COUNT_OFFSET: usize = 0xD0;

/// Parsed prefetch header — a pure value type; no parser internals exposed.
#[derive(Debug, PartialEq)]
struct PrefetchInfo {
    /// Executable name from the header NAME field (not a full path).
    exe_name: String,
    run_count: u32,
    /// Up to 8 run timestamps; zero-padded slots are filtered (ft==0 → None in filetime_to_utc).
    run_times: Vec<DateTime<Utc>>,
}

/// Bounds-checked little-endian u32 reader (mirrors usn.rs/shimcache.rs rd_u32).
/// Returns None when `off..off+4` is out of bounds — never panics.
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// Bounds-checked little-endian u64 reader (mirrors usn.rs/shimcache.rs rd_u64).
/// Returns None when `off..off+8` is out of bounds — never panics.
#[inline]
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// Read the NUL-terminated UTF-16LE executable name from the header.
/// Stops at the first NUL code unit or at `EXE_NAME_MAX_BYTES`, whichever comes first.
/// Lossy on bad surrogate pairs. Never panics.
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

/// Parse a decompressed prefetch body into a `PrefetchInfo`.
///
/// Win10 v30 only. Unrecognised version → `None` (abstain, NFR12).
/// Never panics: all reads are bounds-checked via `rd_u32`/`rd_u64` (Option-returning);
/// a truncated buffer returns `None` rather than indexing out of range.
fn parse_prefetch(buf: &[u8]) -> Option<PrefetchInfo> {
    // Version field at offset 0; anything other than 30 → abstain.
    let version = rd_u32(buf, 0)?;
    if version != PF_V30 {
        return None;
    }
    // Buffer must reach at least RUN_COUNT_OFFSET + 4 to be a plausible v30 header.
    let run_count = rd_u32(buf, RUN_COUNT_OFFSET)?;
    let exe_name = read_exe_name(buf);
    // Read up to 8 FILETIME slots; filetime_to_utc filters ft==0 (zero-padded slots).
    let mut run_times = Vec::new();
    for i in 0..8usize {
        if let Some(ft) = rd_u64(buf, RUN_TIMES_OFFSET + i * 8) {
            if let Some(dt) = filetime_to_utc(ft) {
                run_times.push(dt);
            }
        }
    }
    Some(PrefetchInfo {
        exe_name,
        run_count,
        run_times,
    })
}

/// PrefetchCollector: admin-only, read-only parse of C:\Windows\Prefetch\*.pf into
/// Record::Execution (source="prefetch") with real run_count + first/last run times.
#[derive(Default)]
pub struct PrefetchCollector {
    dir_unreadable: AtomicBool,
    file_read_errors: AtomicBool,
    decompress_errors: AtomicBool,
    unknown_version: AtomicBool,
}

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
            if path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("pf"))
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
                    tracing::warn!(file = ?path, "prefetch: unrecognised/incomplete; skipping");
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
                "abstained: one or more .pf files had an unrecognised or incomplete format (NFR12)"
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

#[cfg(test)]
mod tests {
    use super::*;

    use cairn_core::config::Config;
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::CairnError;
    use std::sync::atomic::Ordering;

    /// Pins the compcol xpress_huffman one-shot API. If this fails to COMPILE, the function
    /// path/signature below is wrong — fix it from the installed compcol source
    /// (~/.cargo/registry/src/.../compcol-*/src/) or `cargo doc`, and report the real API.
    ///
    /// Real confirmed API (compcol 0.6.5):
    ///   compress:   compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&[u8])
    ///                 -> Result<Vec<u8>, compcol::Error>
    ///   decompress: compcol::vec::decompress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&[u8])
    ///                 -> Result<Vec<u8>, compcol::Error>
    ///
    /// The compressed stream is self-delimiting: compcol prepends a 4-byte LE
    /// uncompressed-length header so decompress does NOT require the caller to
    /// supply the uncompressed size separately.
    #[test]
    fn compcol_xpress_huffman_round_trips() {
        let original = b"the quick brown fox jumps over the lazy dog, repeatedly. \
                         the quick brown fox jumps over the lazy dog, repeatedly.";
        let compressed =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(original)
                .expect("xpress_huffman compress");
        let restored =
            compcol::vec::decompress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&compressed)
                .expect("xpress_huffman decompress");
        assert_eq!(restored, original);
    }

    #[test]
    fn decompress_mam_passes_through_non_mam() {
        let raw = b"SCCA-ish uncompressed bytes".to_vec();
        assert_eq!(decompress_mam(&raw).expect("passthrough"), raw);
    }

    #[test]
    fn decompress_mam_decompresses_mam_container() {
        // A real MAM .pf is "MAM\x04" + the compcol-framed stream. compcol's frame ALREADY
        // begins with the 4-byte LE uncompressed-length header, so the MAM container is
        // exactly MAM_MAGIC ++ compcol_output (NO extra size field — the compcol header IS
        // the offset-4 length). decompress_mam must therefore hand compcol raw[4..].
        let original = b"prefetch decompressed body ".repeat(8);
        let compcol_stream =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&original)
                .expect("compress");
        let mut mam = Vec::new();
        mam.extend_from_slice(b"MAM\x04");
        mam.extend_from_slice(&compcol_stream); // compcol_stream[0..4] = LE length header
        assert_eq!(decompress_mam(&mam).expect("decompress"), original);
    }

    #[test]
    fn decompress_mam_slices_at_offset_4_not_8() {
        // Regression guard for the framing bug caught in review: compcol's frame starts with
        // a u32 LE length header, which sits at MAM offset 4. Feeding raw[8..] (dropping that
        // header) makes compcol misread the bitstream. This test pins raw[4..] by checking
        // that the bytes AT offset 4 are what compcol round-trips — i.e. MAM_MAGIC ++ frame
        // decompresses, and a wrongly-8-sliced variant (frame with its first 4 bytes chopped)
        // does NOT yield the original.
        let original = b"the regression vector body, distinct content here".to_vec();
        let frame =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&original)
                .expect("compress");
        // Correct container: MAM + full frame. decompress_mam uses raw[4..] == frame.
        let mut correct = b"MAM\x04".to_vec();
        correct.extend_from_slice(&frame);
        assert_eq!(
            decompress_mam(&correct).expect("correct decompresses"),
            original
        );
        // If decompress_mam had used raw[8..], it would have fed compcol `frame[4..]` (the
        // frame minus its length header) — prove that bytes are NOT a valid decode of original.
        let wrong_input = &frame[4..];
        let wrong = compcol::vec::decompress_to_vec_capped::<compcol::xpress_huffman::XpressHuffman>(
            wrong_input,
            PREFETCH_DECOMPRESS_CEILING,
        );
        // Either it errors, or it decodes to something other than the original — never equal.
        assert!(
            wrong.as_deref() != Ok(original.as_slice()),
            "dropping the length header must not coincidentally yield the original"
        );
    }

    #[test]
    fn decompress_mam_too_short_is_err_not_panic() {
        let raw = b"MAM\x04\x01".to_vec();
        assert!(decompress_mam(&raw).is_err());
    }

    // ── parse_prefetch tests (Task 3) ─────────────────────────────────────────

    /// Minimum decompressed body length required to read the run-count field.
    /// Lives here because it is only needed by the `build_v30` test helper.
    const V30_MIN_LEN: usize = RUN_COUNT_OFFSET + 4;

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

    // ── PrefetchCollector unit tests (Task 4) ────────────────────────────────

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        assert!(matches!(
            PrefetchCollector::default().collect(&ctx),
            Err(CairnError::Privilege { .. })
        ));
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
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("Prefetch directory")));
    }

    #[test]
    fn sources_reports_unknown_version() {
        let c = PrefetchCollector::default();
        c.unknown_version.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("unrecognised or incomplete")));
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

    /// ELEVATED E2E (manual): run as Administrator:
    ///   cargo test -p cairn-collectors prefetch::tests::prefetch_e2e_real_dir -- --ignored --nocapture
    /// Proves the full chain: std::fs enumerate C:\Windows\Prefetch -> MAM decompress (compcol)
    /// -> parse v30 header -> Record::Execution. The any_run assertion verifies the v30 offset
    /// consts are correct (wrong offsets => zero/garbage run_count or run times).
    #[test]
    #[ignore = "requires Administrator and a real Windows C:\\Windows\\Prefetch"]
    fn prefetch_e2e_real_dir() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: false,
            se_debug: false,
        };
        let collector = PrefetchCollector::default();
        let recs = collector.collect(&ctx).expect("collect ok");
        // Diagnostic: surface WHY collect returned what it did, so a failure clearly
        // distinguishes "no real admin rights / dir unreadable" from a parse problem.
        let src = collector.sources();
        eprintln!(
            "prefetch_e2e diagnostics: {} records; sources errors = {:?}",
            recs.len(),
            src[0].errors
        );
        if recs.is_empty() {
            // The most common cause is running WITHOUT real OS Administrator rights:
            // ctx.admin=true passes the gate, but std::fs::read_dir(C:\Windows\Prefetch)
            // is still denied by the OS unless the PROCESS is elevated.
            panic!(
                "collect returned 0 records. If sources errors mention 'Prefetch directory \
                 absent or unreadable', this test was NOT run from an elevated (Administrator) \
                 terminal — re-run it as Administrator. Errors: {:?}",
                src[0].errors
            );
        }
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
        assert!(
            any_run,
            "at least one entry should have a real last_run (offset sanity)"
        );
        eprintln!("prefetch_e2e_real_dir: parsed {} entries", recs.len());
    }
}
