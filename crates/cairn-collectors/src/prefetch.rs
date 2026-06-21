//! PrefetchCollector: parse C:\Windows\Prefetch\*.pf (Win10+ MAM-compressed) into
//! Record::Execution with real run_count + first/last run times. The first non-raw-NTFS
//! offline collector: std::fs reads (admin only, .pf is not OS-locked), compcol decompresses
//! the MAM (Xpress-Huffman) wrapper, a pure never-panic parser reads the header. Recognised
//! format versions only (Win10 v30); an unrecognised version ABSTAINS (NFR12).

use cairn_core::time::filetime_to_utc;
use cairn_core::{CairnError, Result};
use chrono::{DateTime, Utc};

#[allow(dead_code)] // used by decompress_mam; PrefetchCollector wired in a later task
const MAM_MAGIC: &[u8; 4] = b"MAM\x04";

/// Hard ceiling on a single decompressed .pf (NFR10). Real prefetch files are well under
/// a few MB; 64 MiB is far above any legitimate .pf yet caps a malicious MAM size lie.
/// NOTE: compcol 0.6.5 decompress_to_vec_capped takes u64, not usize.
#[allow(dead_code)] // used by decompress_mam; PrefetchCollector wired in a later task
const PREFETCH_DECOMPRESS_CEILING: u64 = 64 * 1024 * 1024;

#[allow(dead_code)] // used by decompress_mam; PrefetchCollector wired in a later task
#[inline]
fn prefetch_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "prefetch".into(),
        reason,
    }
}

#[allow(dead_code)] // PrefetchCollector wired in a later task
/// Decompress a .pf outer container. MAM files (magic "MAM\x04", uncompressed size u32 at
/// offset 4, Xpress-Huffman payload from offset 8) are decompressed via compcol with a hard
/// memory cap (NFR10 — a malicious .pf cannot force an unbounded allocation). Files without
/// the MAM magic (older uncompressed .pf) are returned unchanged. A truncated MAM container
/// or a decompression failure (incl. exceeding the ceiling) yields Err (caller abstains).
fn decompress_mam(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 4 || &raw[0..4] != MAM_MAGIC {
        return Ok(raw.to_vec()); // not MAM-compressed: pass through
    }
    if raw.len() < 8 {
        return Err(prefetch_err(
            "MAM header truncated (no uncompressed size)".into(),
        ));
    }
    let payload = &raw[8..];
    compcol::vec::decompress_to_vec_capped::<compcol::xpress_huffman::XpressHuffman>(
        payload,
        PREFETCH_DECOMPRESS_CEILING,
    )
    .map_err(|e| prefetch_err(format!("MAM decompression failed: {e}")))
}

// ── Win10 v30 prefetch header layout ─────────────────────────────────────────
// These constants are the single fix-point for format offsets; the e2e test (Task 6)
// verifies them against a real .pf file. Wrong offsets = a one-line fix here.

/// The only supported prefetch format version (Windows 10/11).
#[allow(dead_code)] // used only inside parse_prefetch; Task 4 wires PrefetchCollector
const PF_V30: u32 = 30;

/// Byte offset of the NUL-terminated UTF-16LE executable name field in the header.
#[allow(dead_code)]
const EXE_NAME_OFFSET: usize = 16;

/// Maximum byte length of the name field (60 bytes = 30 UTF-16 code units).
#[allow(dead_code)]
const EXE_NAME_MAX_BYTES: usize = 60;

/// Byte offset of the run-times array (8 × u64 FILETIME slots).
#[allow(dead_code)]
const RUN_TIMES_OFFSET: usize = 0x80;

/// Byte offset of the u32 run-count field.
#[allow(dead_code)]
const RUN_COUNT_OFFSET: usize = 0xD0;

/// Minimum decompressed body length required to read the run-count field.
#[allow(dead_code)]
const V30_MIN_LEN: usize = RUN_COUNT_OFFSET + 4;

/// Parsed prefetch header — a pure value type; no parser internals exposed.
#[allow(dead_code)] // PrefetchCollector wired in Task 4
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
#[allow(dead_code)]
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// Bounds-checked little-endian u64 reader (mirrors usn.rs/shimcache.rs rd_u64).
/// Returns None when `off..off+8` is out of bounds — never panics.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let original = b"prefetch decompressed body ".repeat(8);
        let payload =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&original)
                .expect("compress");
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

    // ── parse_prefetch tests (Task 3) ─────────────────────────────────────────

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
}
