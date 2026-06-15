//! Streaming, size-capped sha256 of a file (FR14 IOC hashing). PURE: the file open+length probe
//! is injected, so this is Linux-CI-testable and unsafe-free. Constant memory (one fixed
//! buffer); a file over the cap is skipped (None) so a pathological huge file cannot stall
//! triage — the first concrete NFR10 resource-governance guard (raw-NTFS will reuse the shape).
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::io::Read;

/// Default size cap: 256 MiB. Files larger than this are skipped (binary_sha256 stays None).
pub const DEFAULT_MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

const CHUNK: usize = 64 * 1024;

/// Stream-hash `path` to a lowercase sha256 hex string, or None if it cannot be opened, exceeds
/// `max_bytes`, or errors mid-read. `open(path) -> Option<(len, reader)>` returns the file length
/// AND a streaming reader (Windows: fs metadata().len() + File; tests: an in-memory (len, Cursor)).
/// Never panics.
pub fn hash_file_capped<R: Read>(
    path: &str,
    max_bytes: u64,
    open: impl Fn(&str) -> Option<(u64, R)>,
) -> Option<String> {
    let (len, mut reader) = open(path)?;
    if len > max_bytes {
        return None; // skip: don't stream a huge file
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None, // mid-read error: defensive, no panic
        }
    }
    let digest = hasher.finalize();
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mem(bytes: &'static [u8]) -> impl Fn(&str) -> Option<(u64, Cursor<&'static [u8]>)> {
        move |_p: &str| Some((bytes.len() as u64, Cursor::new(bytes)))
    }

    #[test]
    fn hashes_known_vectors() {
        assert_eq!(
            hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, mem(b"")).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, mem(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn multi_chunk_matches_one_shot() {
        let big: &'static [u8] = Box::leak(vec![0xABu8; CHUNK * 3 + 123].into_boxed_slice());
        let got = hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, mem(big)).unwrap();
        let mut h = Sha256::new();
        h.update(big);
        let want: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn over_cap_is_skipped() {
        let open = |_p: &str| Some((10u64, Cursor::new(&b"0123456789"[..])));
        assert_eq!(hash_file_capped("x", 9, open), None);
        assert!(hash_file_capped("x", 10, open).is_some());
    }

    #[test]
    fn open_failure_is_none() {
        let open = |_p: &str| -> Option<(u64, Cursor<&[u8]>)> { None };
        assert_eq!(hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, open), None);
    }
}
