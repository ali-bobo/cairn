//! PrefetchCollector: parse C:\Windows\Prefetch\*.pf (Win10+ MAM-compressed) into
//! Record::Execution with real run_count + first/last run times. The first non-raw-NTFS
//! offline collector: std::fs reads (admin only, .pf is not OS-locked), compcol decompresses
//! the MAM (Xpress-Huffman) wrapper, a pure never-panic parser reads the header. Recognised
//! format versions only (Win10 v30); an unrecognised version ABSTAINS (NFR12).

#[cfg(test)]
mod tests {
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
}
