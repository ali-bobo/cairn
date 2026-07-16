//! cairn-collectors-win: the ONLY crate permitted to use `unsafe` (Windows FFI).
//!
//! All raw WinAPI calls live here, behind safe wrappers that check every return value
//! and never panic. Handles are closed via RAII guards (invariant documented at each
//! guard). Everything compiles on non-Windows too, where each function returns an
//! "unsupported platform" error or empty data so the whole workspace still builds.
//!
//! See docs/superpowers/specs/2026-06-12-s2a-orchestrator-proc-net-design.md.
#![allow(unsafe_code)] // EXPECTED: this is the isolated FFI boundary (NFR3, CLAUDE.md).

#[cfg(windows)]
mod cmdline_reader;
pub mod host;
pub mod logon;
pub mod net;
pub mod priority;
pub mod privilege;
pub mod proc;
pub mod signature;
pub mod volume;
#[cfg(windows)]
pub mod wmi;
