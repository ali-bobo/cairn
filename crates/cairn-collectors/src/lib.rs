//! cairn-collectors: raw artifact -> normalized `Record`. SRS §4.
//!
//! Collectors are read-only with respect to the host and isolate every external
//! forensic-parsing dependency (e.g. the `evtx` crate) here, keeping `cairn-core`
//! dependency-free per its contract.
#![forbid(unsafe_code)]

pub mod asep;
pub mod dropscan;
pub mod evtx;
pub mod evtx_live;
pub mod hash;
pub mod history;
pub mod host_info;
pub mod lnk;
pub mod logon_session;
pub mod net;
pub mod persist;
pub mod posture;
pub mod prefetch;
pub mod proc;
pub mod rmm_logs;
pub mod wmi_subscription;

pub use hash::hash_file_capped;

/// `exists()` for a path taken from host data, without ever touching the network or a
/// device: a remote (UNC) or device-namespace path reads as absent (see
/// `cairn_core::paths::must_not_probe` for why probing one is unsafe).
pub fn local_path_exists(path: &str) -> bool {
    !cairn_core::paths::must_not_probe(path) && std::path::Path::new(path).exists()
}

/// Up to `cap` bytes from the start of `path`, opened read-only. Never reads more than
/// `cap` however large the file is (a planted multi-GB file cannot exhaust memory).
/// None when the path is remote/device (see [`local_path_exists`]) or unreadable.
pub fn read_head_capped(path: &std::path::Path, cap: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    if cairn_core::paths::must_not_probe(&path.to_string_lossy()) {
        return None;
    }
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Text of a file's bytes, by BOM: UTF-16LE (`FF FE`), UTF-16BE (`FE FF`), UTF-8 (BOM
/// stripped), else lossy UTF-8. Windows writes Task Scheduler XML and many scripts as
/// UTF-16LE; reading those as UTF-8 fails or yields mojibake. A trailing odd byte is
/// dropped. Never fails, never panics.
pub fn decode_text(bytes: &[u8]) -> String {
    let utf16 = |body: &[u8], le: bool| {
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|p| {
                if le {
                    u16::from_le_bytes([p[0], p[1]])
                } else {
                    u16::from_be_bytes([p[0], p[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn decode_text_handles_boms_and_garbage() {
        let le: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<Task>文</Task>".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(super::decode_text(&le), "<Task>文</Task>");
        let be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain("ab".encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        assert_eq!(super::decode_text(&be), "ab");
        assert_eq!(super::decode_text(b"\xEF\xBB\xBFx"), "x");
        assert_eq!(super::decode_text(b"x\xFFy"), "x\u{FFFD}y");
        assert_eq!(
            super::decode_text(&[0xFF, 0xFE, b'a']),
            "",
            "odd tail dropped"
        );
        let mut rng = cairn_core::fuzz::Rng::new(5);
        for _ in 0..2000 {
            let _ = super::decode_text(&rng.bytes(64));
        }
    }

    #[test]
    fn read_head_capped_never_reads_past_the_cap() {
        let p = std::env::temp_dir().join(format!("cairn_head_{}", std::process::id()));
        std::fs::write(&p, vec![b'a'; 10_000]).unwrap();
        assert_eq!(super::read_head_capped(&p, 100).unwrap().len(), 100);
        assert_eq!(super::read_head_capped(&p, 1 << 20).unwrap().len(), 10_000);
        let _ = std::fs::remove_file(&p);
        assert!(super::read_head_capped(std::path::Path::new(r"\\srv\s\x"), 10).is_none());
    }

    #[test]
    fn remote_and_device_paths_never_exist() {
        assert!(!super::local_path_exists(r"\\attacker\share\evil.exe"));
        assert!(!super::local_path_exists(r"\\.\pipe\x"));
        let here = std::env::current_dir().unwrap();
        assert!(super::local_path_exists(&here.to_string_lossy()));
    }
}
