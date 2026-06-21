//! PrefetchCollector: parse C:\Windows\Prefetch\*.pf (Win10+ MAM-compressed) into
//! Record::Execution with real run_count + first/last run times. The first non-raw-NTFS
//! offline collector: std::fs reads (admin only, .pf is not OS-locked), compcol decompresses
//! the MAM (Xpress-Huffman) wrapper, a pure never-panic parser reads the header. Recognised
//! format versions only (Win10 v30); an unrecognised version ABSTAINS (NFR12).

use cairn_core::{CairnError, Result};

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
}
