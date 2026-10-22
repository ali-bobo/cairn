//! Streaming, size-capped sha256 of a file (FR14 IOC hashing). The core
//! [`hash_stream_capped`] is PURE: the file open+length probe is injected, so it is
//! Linux-CI-testable and unsafe-free. Constant memory (one fixed buffer); a file over the
//! cap is skipped (None) so a pathological huge file cannot stall triage (NFR10
//! resource-governance guard).
//!
//! [`hash_file_capped`] is the on-disk entry point used by the proc collector (process
//! images) and available to the persist collector (persistence targets): read-only open,
//! [`DEFAULT_MAX_HASH_BYTES`] cap, memoized per path for the whole run.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Mutex, OnceLock};

/// Default size cap: 256 MiB. Files larger than this are skipped (binary_sha256 stays None).
pub const DEFAULT_MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

const CHUNK: usize = 64 * 1024;

/// Stream-hash `path` to a lowercase sha256 hex string, or None if it cannot be opened, exceeds
/// `max_bytes`, or errors mid-read. `open(path) -> Option<(len, reader)>` returns the file length
/// AND a streaming reader (Windows: fs metadata().len() + File; tests: an in-memory (len, Cursor)).
/// Never panics.
pub fn hash_stream_capped<R: Read>(
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

/// Read-only opener for [`hash_stream_capped`]: file length from metadata + a `File` reader.
/// A remote (UNC) or device path is never opened (see `cairn_core::paths`).
fn open_on_disk(path: &str) -> Option<(u64, std::fs::File)> {
    if crate::must_not_probe(path) {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    Some((meta.len(), file))
}

/// Cache key: Windows paths are case-insensitive and accept `/`; elsewhere keep as is.
fn cache_key(path: &str) -> String {
    if cfg!(windows) {
        path.replace('/', "\\").to_lowercase()
    } else {
        path.to_string()
    }
}

/// Memoizing wrapper: `compute` runs outside the lock; the result (including None, i.e.
/// unreadable / over the cap) is remembered per normalized path.
fn cached(
    cache: &Mutex<HashMap<String, Option<String>>>,
    path: &str,
    compute: impl FnOnce(&str) -> Option<String>,
) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let key = cache_key(path);
    if let Ok(m) = cache.lock() {
        if let Some(hit) = m.get(&key) {
            return hit.clone();
        }
    }
    let v = compute(path);
    if let Ok(mut m) = cache.lock() {
        m.insert(key, v.clone());
    }
    v
}

/// Lowercase sha256 hex of the file at `path`, or None if it cannot be opened, is not a
/// regular file, exceeds [`DEFAULT_MAX_HASH_BYTES`] (256 MiB) or errors mid-read.
/// Read-only (golden rule 3). Memoized per path for the lifetime of the process, so the
/// same binary referenced by many processes / persistence entries is hashed once.
pub fn hash_file_capped(path: &str) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    cached(cache, path, |p| {
        hash_stream_capped(p, DEFAULT_MAX_HASH_BYTES, open_on_disk)
    })
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
            hash_stream_capped("x", DEFAULT_MAX_HASH_BYTES, mem(b"")).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_stream_capped("x", DEFAULT_MAX_HASH_BYTES, mem(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn multi_chunk_matches_one_shot() {
        let big: &'static [u8] = Box::leak(vec![0xABu8; CHUNK * 3 + 123].into_boxed_slice());
        let got = hash_stream_capped("x", DEFAULT_MAX_HASH_BYTES, mem(big)).unwrap();
        let mut h = Sha256::new();
        h.update(big);
        let want: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn over_cap_is_skipped() {
        let open = |_p: &str| Some((10u64, Cursor::new(&b"0123456789"[..])));
        assert_eq!(hash_stream_capped("x", 9, open), None);
        assert!(hash_stream_capped("x", 10, open).is_some());
    }

    #[test]
    fn on_disk_hash_matches_and_is_cached() {
        let dir = std::env::temp_dir().join(format!("cairn_hash_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("abc.bin");
        std::fs::write(&p, b"abc").unwrap();
        let ps = p.to_string_lossy().to_string();
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hash_file_capped(&ps).as_deref(), Some(want));
        // Cached: a later change on disk is not re-read within the run.
        std::fs::write(&p, b"changed").unwrap();
        assert_eq!(hash_file_capped(&ps).as_deref(), Some(want));
        assert_eq!(hash_file_capped(""), None);
        assert_eq!(hash_file_capped(&dir.to_string_lossy()), None); // a directory
        assert_eq!(hash_file_capped("/definitely/not/here.exe"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cached_computes_each_key_once() {
        let cache = Mutex::new(HashMap::new());
        let mut calls = 0;
        for _ in 0..3 {
            let v = cached(&cache, "a", |_| {
                calls += 1;
                Some("h".to_string())
            });
            assert_eq!(v.as_deref(), Some("h"));
        }
        assert_eq!(calls, 1);
        // None results are cached too.
        let mut none_calls = 0;
        for _ in 0..2 {
            assert_eq!(
                cached(&cache, "b", |_| {
                    none_calls += 1;
                    None
                }),
                None
            );
        }
        assert_eq!(none_calls, 1);
    }

    #[test]
    fn open_failure_is_none() {
        let open = |_p: &str| -> Option<(u64, Cursor<&[u8]>)> { None };
        assert_eq!(hash_stream_capped("x", DEFAULT_MAX_HASH_BYTES, open), None);
    }
}
