//! cairn-collectors: raw artifact -> normalized `Record`. SRS §4.
//!
//! Collectors are read-only with respect to the host and isolate every external
//! forensic-parsing dependency (e.g. the `evtx` crate) here, keeping `cairn-core`
//! dependency-free per its contract.
#![forbid(unsafe_code)]

pub mod asep;
pub mod evtx;
pub mod evtx_live;
pub mod hash;
pub mod history;
pub mod host_info;
pub mod lnk;
pub mod logon_session;
pub mod net;
pub mod persist;
pub mod prefetch;
pub mod proc;
pub mod wmi_subscription;
