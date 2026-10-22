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

#[cfg(test)]
mod tests {
    #[test]
    fn remote_and_device_paths_never_exist() {
        assert!(!super::local_path_exists(r"\\attacker\share\evil.exe"));
        assert!(!super::local_path_exists(r"\\.\pipe\x"));
        let here = std::env::current_dir().unwrap();
        assert!(super::local_path_exists(&here.to_string_lossy()));
    }
}
