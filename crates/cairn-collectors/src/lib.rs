//! cairn-collectors: raw artifact -> normalized `Record`. SRS §4.
//!
//! Collectors are read-only with respect to the host and isolate every external
//! forensic-parsing dependency (e.g. the `evtx` crate) here, keeping `cairn-core`
//! dependency-free per its contract. Stage 1 ships only `evtx`.
#![forbid(unsafe_code)]

pub mod evtx;
pub mod hash;
pub mod mft;
pub mod net;
pub mod persist;
pub mod proc;
