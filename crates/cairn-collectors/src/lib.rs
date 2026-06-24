//! cairn-collectors: raw artifact -> normalized `Record`. SRS §4.
//!
//! Collectors are read-only with respect to the host and isolate every external
//! forensic-parsing dependency (e.g. the `evtx` crate) here, keeping `cairn-core`
//! dependency-free per its contract. Stage 1 ships only `evtx`.
#![forbid(unsafe_code)]

pub mod amcache;
pub mod bam;
pub mod evtx;
pub mod hash;
pub mod hive_reader;
pub mod mft;
pub mod net;
pub mod persist;
pub mod prefetch;
pub mod proc;
pub mod shimcache;
pub mod srum;
pub mod userassist;
pub mod usn;
