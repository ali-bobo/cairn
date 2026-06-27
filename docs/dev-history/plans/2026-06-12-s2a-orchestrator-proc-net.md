# S2-A: Orchestrator + proc/net live collectors — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `cairn run --target live`, which scans the running Windows host for its process tree and network connections and writes a verifiable manifest.

**Architecture:** A new `cairn-collectors-win` crate isolates ALL Windows `unsafe` FFI (the single `allow(unsafe_code)` crate); `cairn-collectors` gains pure raw→Record mapping (TDD'd); `cairn-core` gains a minimal orchestrator (probe → sequence collectors → graceful degrade), tested with fake collectors; `cairn-cli` wires `cairn run --target live`. No raw-NTFS, no heuristics, no persistence.

**Tech Stack:** Rust, `windows` crate (windows-rs, native WinAPI), serde, the existing Collector/Record/Manifest contracts.

**Spec:** `docs/superpowers/specs/2026-06-12-s2a-orchestrator-proc-net-design.md`

**Standing discipline (every task):** after the task's test passes, run the full gate
`cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
(all from the repo root, `dangerouslyDisableSandbox: true` on Windows), and `cargo audit`
when deps change. Then the anti-drift check: no golden-rule violation (esp. unsafe only in
`cairn-collectors-win`, collectors read-only), no deviation from SRS §3/§4, no invention
beyond spec (YAGNI). Commit only after green. On Windows the AV may lock a build probe →
`os error 5`; just re-run the build (probes cache afterward).

---

## File Structure

- `crates/cairn-collectors-win/Cargo.toml` — new crate; `windows` dep under `cfg(windows)`.
- `crates/cairn-collectors-win/src/lib.rs` — `#![allow(unsafe_code)]`; re-exports the modules.
- `crates/cairn-collectors-win/src/privilege.rs` — `probe() -> Privileges` (FFI + stub).
- `crates/cairn-collectors-win/src/host.rs` — `hostname() -> Result<String>` (FFI + stub).
- `crates/cairn-collectors-win/src/proc.rs` — `RawProc` + `enumerate()` (FFI + stub).
- `crates/cairn-collectors-win/src/net.rs` — `RawTcpRow`/`RawUdpRow` + tables (FFI + stub).
- `crates/cairn-collectors/src/proc.rs` — `build_process_records` (pure) + `ProcCollector`.
- `crates/cairn-collectors/src/net.rs` — `build_netconn_records` (pure) + `NetCollector`.
- `crates/cairn-collectors/src/lib.rs:modify` — add `pub mod proc; pub mod net;`.
- `crates/cairn-core/src/orchestrator.rs` — `run_live` + `RunOutcome` (pure, DI).
- `crates/cairn-core/src/lib.rs:modify` — `pub mod orchestrator;`.
- `crates/cairn-cli/src/main.rs:modify` — wire `Cmd::Run` `--target live`.
- `Cargo.toml:modify` — add the new crate to workspace members; pin `windows` in workspace deps.

**Dependency direction:** `cairn-collectors` → `cairn-collectors-win` → `cairn-core`. No cycle
(`cairn-collectors-win` depends only on `cairn-core` for `Privileges`/`CairnError`).

---

## Task 1: Scaffold `cairn-collectors-win` crate (builds on all platforms)

**Files:**
- Create: `crates/cairn-collectors-win/Cargo.toml`
- Create: `crates/cairn-collectors-win/src/lib.rs`
- Modify: `Cargo.toml` (workspace members + `windows` pinned dep)

- [ ] **Step 1: Add the `windows` dep to workspace deps (pinned).** First find the exact
  current version:

Run: `cargo search windows --limit 1`
Take the exact version printed (e.g. `0.62.2`) and use it verbatim below — do NOT guess.

In root `Cargo.toml` under `[workspace.dependencies]`, add (substitute the real version):

```toml
windows = "0.62.2" # native WinAPI for live collectors (cairn-collectors-win only)
```

And add the crate to `[workspace] members`:

```toml
    "crates/cairn-collectors-win",
```

- [ ] **Step 2: Create the crate Cargo.toml.**

```toml
[package]
name = "cairn-collectors-win"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
cairn-core = { path = "../cairn-core" }

# Windows-only: native WinAPI. Minimal feature set; expand only as collectors need it.
[target.'cfg(windows)'.dependencies.windows]
workspace = true
features = [
  "Win32_Foundation",
  "Win32_System_Threading",
  "Win32_System_ProcessStatus",
  "Win32_System_Diagnostics_ToolHelp",
  "Win32_Security",
  "Win32_System_SystemInformation",
  "Win32_NetworkManagement_IpHelper",
  "Win32_Networking_WinSock",
]
```

- [ ] **Step 3: Create the lib.rs shell.**

```rust
//! cairn-collectors-win: the ONLY crate permitted to use `unsafe` (Windows FFI).
//!
//! All raw WinAPI calls live here, behind safe wrappers that check every return value
//! and never panic. Handles are closed via RAII guards (invariant documented at each
//! guard). Everything compiles on non-Windows too, where each function returns an
//! "unsupported platform" error or empty data so the whole workspace still builds.
//!
//! See docs/superpowers/specs/2026-06-12-s2a-orchestrator-proc-net-design.md.
#![allow(unsafe_code)] // EXPECTED: this is the isolated FFI boundary (NFR3, CLAUDE.md).

pub mod host;
pub mod privilege;
pub mod proc;
pub mod net;
```

- [ ] **Step 4: Create empty module files so it compiles.** Create each of
  `privilege.rs`, `host.rs`, `proc.rs`, `net.rs` in `src/` with just a doc line for now:

```rust
//! (filled in a later task)
```

- [ ] **Step 5: Verify it builds on this platform.**

Run: `cargo check -p cairn-collectors-win`
Expected: compiles (empty modules). On Windows, `windows` crate downloads + builds.

- [ ] **Step 6: Commit.**

```bash
git add Cargo.toml Cargo.lock crates/cairn-collectors-win/
git commit -m "feat(s2a): scaffold cairn-collectors-win crate (isolated unsafe FFI)"
```

---

## Task 2: Privilege probe

**Files:**
- Modify: `crates/cairn-collectors-win/src/privilege.rs`

- [ ] **Step 1: Write the cross-platform stub + the test (non-Windows path).** Replace
  `privilege.rs` with:

```rust
//! Privilege probe: which rights does this process hold? (manifest.privileges, SRS §11)
use cairn_core::manifest::Privileges;

/// Probe the current process token for the rights the collectors care about.
/// Non-Windows: no Windows privileges exist, so everything is false (graceful).
#[cfg(not(windows))]
pub fn probe() -> Privileges {
    Privileges { admin: false, se_backup: false, se_debug: false }
}

/// Windows: query the process token. Any failure degrades to false rather than
/// panicking — a probe that can't read its own token still lets the run continue.
#[cfg(windows)]
pub fn probe() -> Privileges {
    Privileges {
        admin: win::is_elevated().unwrap_or(false),
        se_backup: win::has_privilege("SeBackupPrivilege").unwrap_or(false),
        se_debug: win::has_privilege("SeDebugPrivilege").unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// probe() never panics and returns a Privileges struct on any platform.
    #[test]
    fn probe_returns_without_panicking() {
        let p = probe();
        // On a non-elevated CI/dev run these are typically false; we only assert the
        // call is total (no panic) and yields the three fields.
        let _ = (p.admin, p.se_backup, p.se_debug);
    }
}
```

- [ ] **Step 2: Run the test (it compiles + passes on non-Windows; on Windows it needs
  the `win` module).**

Run: `cargo test -p cairn-collectors-win privilege`
Expected (non-Windows): PASS. Expected (Windows): FAIL to compile — `win` not defined.
That failure is the RED for the Windows implementation in Step 3.

- [ ] **Step 3: Add the Windows `win` submodule (the actual FFI).** Append to
  `privilege.rs`:

```rust
#[cfg(windows)]
mod win {
    use cairn_core::{CairnError, Result};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        GetTokenInformation, LookupPrivilegeValueW, TokenElevation, PRIVILEGE_SET,
        PRIVILEGE_SET_ALL_NECESSARY, PrivilegeCheck, TOKEN_ELEVATION, TOKEN_QUERY,
        TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PCWSTR;

    /// RAII guard: a token HANDLE that is always closed on drop.
    /// INVARIANT: `0` holds a valid, open token handle obtained from OpenProcessToken;
    /// Drop closes it exactly once. Never construct with an invalid handle.
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is a valid handle opened in `open_token`; closed once.
            unsafe { let _ = CloseHandle(self.0); }
        }
    }

    fn open_token() -> Result<TokenHandle> {
        let mut handle = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; we request TOKEN_QUERY and
        // receive an owned token handle in `handle`, wrapped immediately in the guard.
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle)
                .map_err(|e| CairnError::Collector {
                    collector: "privilege".into(),
                    reason: format!("OpenProcessToken: {e}"),
                })?;
        }
        Ok(TokenHandle(handle))
    }

    /// True if the process token is elevated (admin).
    pub fn is_elevated() -> Result<bool> {
        let token = open_token()?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        // SAFETY: token.0 is valid; we pass a correctly sized TOKEN_ELEVATION buffer and
        // its byte length; GetTokenInformation fills it.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            )
            .map_err(|e| CairnError::Collector {
                collector: "privilege".into(),
                reason: format!("GetTokenInformation(elevation): {e}"),
            })?;
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    /// True if the named privilege (e.g. "SeBackupPrivilege") is present+enabled.
    pub fn has_privilege(name: &str) -> Result<bool> {
        let token = open_token()?;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = LUID::default();
        // SAFETY: wide is a valid NUL-terminated UTF-16 string; LookupPrivilegeValueW
        // writes the LUID for a known privilege name.
        unsafe {
            LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid)
                .map_err(|e| CairnError::Collector {
                    collector: "privilege".into(),
                    reason: format!("LookupPrivilegeValueW({name}): {e}"),
                })?;
        }
        let mut set = PRIVILEGE_SET {
            PrivilegeCount: 1,
            Control: PRIVILEGE_SET_ALL_NECESSARY,
            Privilege: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: Default::default() }],
        };
        let mut result = windows::Win32::Foundation::BOOL::default();
        // SAFETY: token.0 valid; set is a correctly initialized single-entry set.
        unsafe {
            PrivilegeCheck(token.0, &mut set, &mut result).map_err(|e| {
                CairnError::Collector {
                    collector: "privilege".into(),
                    reason: format!("PrivilegeCheck({name}): {e}"),
                }
            })?;
        }
        Ok(result.as_bool())
    }
}
```

> NOTE: exact `windows` crate type/function paths can drift between versions. If a path
> doesn't resolve, search the installed version's docs (`cargo doc -p windows --open`) and
> fix the `use` — do NOT guess. The structure (open token → query) is stable.

- [ ] **Step 4: Run the gate.**

Run: `cargo test -p cairn-collectors-win privilege` then the full gate.
Expected: PASS on this Windows host; `clippy -D warnings` clean.

- [ ] **Step 5: Self-check for errors + commit.** State in the commit body the failure
  modes considered: token open fails → `Err` → probe degrades to false (not panic);
  unknown privilege name → `Err` → false. Then:

```bash
git add crates/cairn-collectors-win/src/privilege.rs
git commit -m "feat(s2a): privilege probe (token elevation + SeBackup/SeDebug), graceful"
```

---

## Task 3: Hostname

**Files:**
- Modify: `crates/cairn-collectors-win/src/host.rs`

- [ ] **Step 1: Write the stub + test.** Replace `host.rs`:

```rust
//! Live-run hostname (manifest.host.hostname; an EVTX run borrows the Computer field).
use cairn_core::{CairnError, Result};

/// Non-Windows: hostname via std env as a best effort (used only so the workspace builds
/// + tests off-Windows; the real live path is Windows-only).
#[cfg(not(windows))]
pub fn hostname() -> Result<String> {
    Ok(std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()))
}

/// Windows: GetComputerNameExW (DNS hostname). Failure -> Err (caller may default).
#[cfg(windows)]
pub fn hostname() -> Result<String> {
    win::computer_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hostname() returns a non-empty string without panicking.
    #[test]
    fn hostname_is_non_empty() {
        let h = hostname().unwrap_or_else(|_| "unknown".into());
        assert!(!h.is_empty());
    }
}
```

- [ ] **Step 2: Run test.**

Run: `cargo test -p cairn-collectors-win host`
Expected (Windows): FAIL to compile (`win` missing) — RED. (non-Windows: PASS.)

- [ ] **Step 3: Add the Windows submodule.** Append to `host.rs`:

```rust
#[cfg(windows)]
mod win {
    use cairn_core::{CairnError, Result};
    use windows::Win32::System::SystemInformation::{
        GetComputerNameExW, ComputerNameDnsHostname,
    };

    pub fn computer_name() -> Result<String> {
        let mut size = 0u32;
        // First call: get required size (expected to fail with size set).
        // SAFETY: passing null buffer + &mut size is the documented size-probe form.
        unsafe {
            let _ = GetComputerNameExW(ComputerNameDnsHostname, None, &mut size);
        }
        if size == 0 {
            return Err(CairnError::Collector {
                collector: "host".into(),
                reason: "GetComputerNameExW size probe returned 0".into(),
            });
        }
        let mut buf = vec![0u16; size as usize];
        // SAFETY: buf has `size` u16 slots; we pass its pointer + the same size.
        unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                Some(windows::core::PWSTR(buf.as_mut_ptr())),
                &mut size,
            )
            .map_err(|e| CairnError::Collector {
                collector: "host".into(),
                reason: format!("GetComputerNameExW: {e}"),
            })?;
        }
        Ok(String::from_utf16_lossy(&buf[..size as usize]))
    }
}
```

- [ ] **Step 4: Gate + commit.**

Run: `cargo test -p cairn-collectors-win host` + full gate.

```bash
git add crates/cairn-collectors-win/src/host.rs
git commit -m "feat(s2a): live hostname via GetComputerNameExW (Windows) + portable stub"
```

---

## Task 4: proc — `RawProc` + `enumerate()` (FFI + smoke test)

**Files:**
- Modify: `crates/cairn-collectors-win/src/proc.rs`

- [ ] **Step 1: Define `RawProc` + the stub + smoke test.** Replace `proc.rs`:

```rust
//! Process enumeration (raw WinAPI -> plain structs). Pure mapping to Records lives in
//! cairn-collectors::proc; this layer only reads the OS.
use cairn_core::Result;
use chrono::{DateTime, Utc};

/// One process as read from the OS. Per-process fields are Option/best-effort: a process
/// we cannot open leaves them None rather than failing the whole enumeration (graceful).
#[derive(Debug, Clone)]
pub struct RawProc {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,                 // best available; "" if unreadable
    pub cmdline: Option<String>,
    pub integrity_raw: Option<u32>,    // raw integrity RID; mapped to a label downstream
    pub signed: Option<bool>,
    pub user: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
}

/// Non-Windows: empty (the live proc path is Windows-only).
#[cfg(not(windows))]
pub fn enumerate() -> Result<Vec<RawProc>> {
    Ok(vec![])
}

/// Windows: snapshot pid/ppid/image (reliable), then best-effort per-process enrichment.
/// Only Errs if the snapshot itself fails.
#[cfg(windows)]
pub fn enumerate() -> Result<Vec<RawProc>> {
    win::enumerate()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Smoke test: on Windows, enumerate() returns a non-empty list that includes THIS
    /// process's PID. This is the thin-FFI smoke test (spec §4.1) — it proves the WinAPI
    /// path works without asserting exact contents (which vary per run).
    #[test]
    fn enumerate_includes_current_process() {
        let procs = enumerate().expect("enumerate");
        assert!(!procs.is_empty(), "expected at least one process");
        let me = std::process::id();
        assert!(procs.iter().any(|p| p.pid == me), "current pid {me} not found");
    }
}
```

- [ ] **Step 2: Run the smoke test.**

Run (Windows): `cargo test -p cairn-collectors-win proc`
Expected: FAIL to compile (`win` missing) — RED.

- [ ] **Step 3: Implement the Windows enumeration.** Append to `proc.rs`. This uses the
  Toolhelp snapshot for the reliable pid/ppid/image core; per-process enrichment
  (cmdline/integrity/signer/user/start_time) is added incrementally and left None on any
  failure. For THIS task, implement the snapshot core and leave enrichment fields None
  (a focused, testable unit; enrichment is its own follow-up within scope).

```rust
#[cfg(windows)]
mod win {
    use super::RawProc;
    use cairn_core::{CairnError, Result};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    /// RAII guard for a snapshot HANDLE.
    /// INVARIANT: holds a valid handle from CreateToolhelp32Snapshot; closed once on drop.
    struct Snapshot(HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid snapshot handle; closed exactly once.
            unsafe { let _ = CloseHandle(self.0); }
        }
    }

    pub fn enumerate() -> Result<Vec<RawProc>> {
        // SAFETY: TH32CS_SNAPPROCESS with pid 0 snapshots all processes; returns an owned
        // handle wrapped immediately in the guard.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|e| CairnError::Collector {
                collector: "proc".into(),
                reason: format!("CreateToolhelp32Snapshot: {e}"),
            })?;
        let snap = Snapshot(snap);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut out = Vec::new();

        // SAFETY: snap.0 valid; entry.dwSize set as required by Process32FirstW.
        if unsafe { Process32FirstW(snap.0, &mut entry) }.is_err() {
            return Ok(out); // empty snapshot is not an error
        }
        loop {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let image = String::from_utf16_lossy(&entry.szExeFile[..len]);
            out.push(RawProc {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                image,
                cmdline: None,
                integrity_raw: None,
                signed: None,
                user: None,
                start_time: None,
            });
            // SAFETY: snap.0 valid; entry reused per the Toolhelp iteration contract.
            if unsafe { Process32NextW(snap.0, &mut entry) }.is_err() {
                break;
            }
        }
        Ok(out)
    }
}
```

- [ ] **Step 4: Run smoke test + gate.**

Run (Windows): `cargo test -p cairn-collectors-win proc` + full gate.
Expected: PASS — current PID is in the list.

- [ ] **Step 5: Self-check + commit.** Failure modes: snapshot fails → Err (whole-OS read
  impossible, honest); empty first entry → empty vec (not an error). Enrichment fields are
  None for now (best-effort; populated in a later in-scope step without breaking callers).

```bash
git add crates/cairn-collectors-win/src/proc.rs
git commit -m "feat(s2a): process enumeration via Toolhelp snapshot (pid/ppid/image)"
```

---

## Task 5: proc — `build_process_records` (pure, TDD)

**Files:**
- Create: `crates/cairn-collectors/src/proc.rs`
- Modify: `crates/cairn-collectors/src/lib.rs` (add `pub mod proc;`)
- Modify: `crates/cairn-collectors/Cargo.toml` (dep on `cairn-collectors-win`)

- [ ] **Step 1: Add the dep.** In `crates/cairn-collectors/Cargo.toml` `[dependencies]`:

```toml
cairn-collectors-win = { path = "../cairn-collectors-win" }
```

- [ ] **Step 2: Write the failing test first.** Create `crates/cairn-collectors/src/proc.rs`:

```rust
//! Pure mapping: RawProc -> Record::Process. No OS access here (that's cairn-collectors-win).
use cairn_collectors_win::proc::RawProc;
use cairn_core::record::{ProcessRecord, Record};

/// Map raw processes to normalized Records. Pure + total (never panics). A None cmdline
/// becomes "" (ProcessRecord.cmdline is String). integrity_raw maps to a label.
pub fn build_process_records(raw: &[RawProc]) -> Vec<Record> {
    unimplemented!()
}

/// Windows integrity RID -> label (SRS forensic field). Common RIDs only; unknown -> "".
fn integrity_label(rid: u32) -> String {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_collectors_win::proc::RawProc;

    fn raw(pid: u32, ppid: u32, image: &str) -> RawProc {
        RawProc {
            pid, ppid, image: image.into(),
            cmdline: None, integrity_raw: None, signed: None, user: None, start_time: None,
        }
    }

    /// Each RawProc becomes one Record::Process with pid/ppid/image carried through and a
    /// None cmdline normalized to "".
    #[test]
    fn maps_raw_to_process_records() {
        let recs = build_process_records(&[raw(100, 4, r"C:\Windows\explorer.exe")]);
        assert_eq!(recs.len(), 1);
        let Record::Process(p) = &recs[0] else { panic!("expected Process record") };
        assert_eq!(p.pid, 100);
        assert_eq!(p.ppid, 4);
        assert_eq!(p.image, r"C:\Windows\explorer.exe");
        assert_eq!(p.cmdline, ""); // None -> ""
    }

    /// integrity_raw maps to its label; the well-known "high" RID is 0x3000 (12288).
    #[test]
    fn maps_integrity_rid_to_label() {
        let mut r = raw(1, 0, "x.exe");
        r.integrity_raw = Some(0x3000);
        let recs = build_process_records(&[r]);
        let Record::Process(p) = &recs[0] else { panic!() };
        assert_eq!(p.integrity.as_deref(), Some("high"));
    }
}
```

- [ ] **Step 3: Add `pub mod proc;` to `crates/cairn-collectors/src/lib.rs`** (next to
  `pub mod evtx;`).

- [ ] **Step 4: Run the test, watch it fail.**

Run: `cargo test -p cairn-collectors proc::tests`
Expected: FAIL — `unimplemented!()` panics.

- [ ] **Step 5: Implement.** Replace the two `unimplemented!()` bodies:

```rust
pub fn build_process_records(raw: &[RawProc]) -> Vec<Record> {
    raw.iter()
        .map(|r| {
            Record::Process(ProcessRecord {
                pid: r.pid,
                ppid: r.ppid,
                image: r.image.clone(),
                cmdline: r.cmdline.clone().unwrap_or_default(),
                signed: r.signed,
                integrity: r.integrity_raw.map(integrity_label),
                user: r.user.clone(),
                start_time: r.start_time,
            })
        })
        .collect()
}

fn integrity_label(rid: u32) -> String {
    match rid {
        0x0000 => "untrusted",
        0x1000 => "low",
        0x2000 => "medium",
        0x3000 => "high",
        0x4000 => "system",
        _ => "",
    }
    .to_string()
}
```

- [ ] **Step 6: Run tests + gate.**

Run: `cargo test -p cairn-collectors proc` + full gate. Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add crates/cairn-collectors/src/proc.rs crates/cairn-collectors/src/lib.rs crates/cairn-collectors/Cargo.toml Cargo.lock
git commit -m "feat(s2a): pure RawProc->Record mapping + integrity-RID labels (TDD)"
```

---

## Task 6: `ProcCollector impl Collector`

**Files:**
- Modify: `crates/cairn-collectors/src/proc.rs`

- [ ] **Step 1: Write the test.** Append to `proc.rs` tests module:

```rust
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::Config;

    /// ProcCollector.collect returns Process records (>=1 on a real OS; >=0 if the
    /// platform stub returns empty) and never panics; its name() is "proc".
    #[test]
    fn proc_collector_collects_without_panicking() {
        let collector = ProcCollector;
        assert_eq!(collector.name(), "proc");
        let cfg = Config::default();
        let ctx = CollectCtx { config: &cfg, admin: false, se_backup: false, se_debug: false };
        let recs = collector.collect(&ctx).expect("collect");
        // Every record must be a Process variant.
        assert!(recs.iter().all(|r| matches!(r, Record::Process(_))));
        // sources() advertises the live process source.
        assert_eq!(collector.sources().len(), 1);
        assert_eq!(collector.sources()[0].method, "api");
    }
```

- [ ] **Step 2: Run it, watch it fail.**

Run: `cargo test -p cairn-collectors proc_collector`
Expected: FAIL — `ProcCollector` not defined.

- [ ] **Step 3: Implement.** Append to `proc.rs` (above tests):

```rust
use cairn_core::manifest::SourceEntry;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;

/// Collector that enumerates live processes (SRS §4 proc_collector).
pub struct ProcCollector;

impl Collector for ProcCollector {
    fn name(&self) -> &str {
        "proc"
    }
    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let raw = cairn_collectors_win::proc::enumerate()?;
        Ok(build_process_records(&raw))
    }
    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "process".into(),
            path: "live:process".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(), // a live table is not a byte stream (spec §5)
            errors: vec![],
        }]
    }
}
```

- [ ] **Step 4: Run + gate + commit.**

```bash
git add crates/cairn-collectors/src/proc.rs
git commit -m "feat(s2a): ProcCollector impl Collector (live process source)"
```

---

## Task 7: net — raw rows + tables (FFI + smoke test)

**Files:**
- Modify: `crates/cairn-collectors-win/src/net.rs`

- [ ] **Step 1: Define rows + stub + smoke test.** Replace `net.rs`:

```rust
//! TCP/UDP table enumeration with owning PID (raw WinAPI -> plain rows).
use cairn_core::Result;

#[derive(Debug, Clone)]
pub struct RawTcpRow {
    pub laddr: String, pub lport: u16,
    pub raddr: String, pub rport: u16,
    pub state_raw: u32, pub pid: u32,
}
#[derive(Debug, Clone)]
pub struct RawUdpRow { pub laddr: String, pub lport: u16, pub pid: u32 }

#[cfg(not(windows))]
pub fn tcp_table() -> Result<Vec<RawTcpRow>> { Ok(vec![]) }
#[cfg(not(windows))]
pub fn udp_table() -> Result<Vec<RawUdpRow>> { Ok(vec![]) }

#[cfg(windows)]
pub fn tcp_table() -> Result<Vec<RawTcpRow>> { win::tcp_table() }
#[cfg(windows)]
pub fn udp_table() -> Result<Vec<RawUdpRow>> { win::udp_table() }

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    /// Smoke test: tables enumerate without panicking and return rows with sane ports.
    /// (Exact contents vary; we only prove the FFI path works.)
    #[test]
    fn tables_enumerate_without_panicking() {
        let tcp = tcp_table().expect("tcp");
        let _udp = udp_table().expect("udp");
        // A typical host has at least one listening TCP socket, but don't hard-require it;
        // assert the call is total and any returned row has a plausible local port type.
        for r in tcp.iter().take(1) { let _: u16 = r.lport; }
    }
}
```

- [ ] **Step 2: Run smoke test.**

Run (Windows): `cargo test -p cairn-collectors-win net`
Expected: FAIL to compile (`win` missing) — RED.

- [ ] **Step 3: Implement the Windows tables.** Append to `net.rs`. Uses
  `GetExtendedTcpTable`/`GetExtendedUdpTable` with `TCP_TABLE_OWNER_PID_ALL` /
  `UDP_TABLE_OWNER_PID`. IPv4 first (the common triage case); IPv6 is an in-scope
  follow-up but not required for this task's gate.

```rust
#[cfg(windows)]
mod win {
    use super::{RawTcpRow, RawUdpRow};
    use cairn_core::{CairnError, Result};
    use std::net::Ipv4Addr;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    fn ipv4(be: u32) -> String {
        // table stores addresses in network byte order already as u32
        Ipv4Addr::from(u32::from_be(be.to_be())).to_string()
    }
    fn port(be: u32) -> u16 {
        // ports are in network byte order in the low 16 bits
        u16::from_be((be & 0xFFFF) as u16)
    }

    pub fn tcp_table() -> Result<Vec<RawTcpRow>> {
        let mut size = 0u32;
        // SAFETY: size-probe form — null buffer, &mut size; returns required bytes.
        unsafe {
            let _ = GetExtendedTcpTable(None, &mut size, false, AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL, 0);
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf has `size` bytes; we pass its pointer + the same size.
        unsafe {
            let rc = GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false,
                AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
            if rc != 0 {
                return Err(CairnError::Collector { collector: "net".into(),
                    reason: format!("GetExtendedTcpTable rc={rc}") });
            }
        }
        // SAFETY: buf begins with a MIB_TCPTABLE_OWNER_PID; dwNumEntries then the rows.
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        // SAFETY: the row array has dwNumEntries entries immediately after the count.
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), n) };
        Ok(rows.iter().map(|r| RawTcpRow {
            laddr: ipv4(r.dwLocalAddr), lport: port(r.dwLocalPort),
            raddr: ipv4(r.dwRemoteAddr), rport: port(r.dwRemotePort),
            state_raw: r.dwState, pid: r.dwOwningPid,
        }).collect())
    }

    pub fn udp_table() -> Result<Vec<RawUdpRow>> {
        let mut size = 0u32;
        // SAFETY: size-probe form.
        unsafe {
            let _ = GetExtendedUdpTable(None, &mut size, false, AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID, 0);
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf sized to `size`; pointer + same size passed.
        unsafe {
            let rc = GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false,
                AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
            if rc != 0 {
                return Err(CairnError::Collector { collector: "net".into(),
                    reason: format!("GetExtendedUdpTable rc={rc}") });
            }
        }
        // SAFETY: buf begins with a MIB_UDPTABLE_OWNER_PID.
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        // SAFETY: row array of dwNumEntries entries after the count.
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), n) };
        Ok(rows.iter().map(|r| RawUdpRow {
            laddr: ipv4(r.dwLocalAddr), lport: port(r.dwLocalPort), pid: r.dwOwningPid,
        }).collect())
    }
}
```

> NOTE: `windows` crate field/const names (e.g. `MIB_TCPTABLE_OWNER_PID`, `table` array
> field) can vary by version. If a path/field doesn't resolve, check the installed
> version's docs — do NOT guess. The call shape (size-probe → fill → cast → iterate) is stable.

- [ ] **Step 4: Smoke test + gate + commit.**

```bash
git add crates/cairn-collectors-win/src/net.rs
git commit -m "feat(s2a): TCP/UDP table enumeration with owning PID (IPv4)"
```

---

## Task 8: net — `build_netconn_records` (pure, TDD)

**Files:**
- Create: `crates/cairn-collectors/src/net.rs`
- Modify: `crates/cairn-collectors/src/lib.rs` (add `pub mod net;`)

- [ ] **Step 1: Write the failing test.** Create `crates/cairn-collectors/src/net.rs`:

```rust
//! Pure mapping: raw TCP/UDP rows -> Record::NetConn. No OS access here.
use cairn_collectors_win::net::{RawTcpRow, RawUdpRow};
use cairn_core::record::{NetConnRecord, Record};

/// Map raw rows to NetConn records. Pure + total. TCP carries remote addr/port + state;
/// UDP is connectionless (no remote, no state). state_raw maps to a label.
pub fn build_netconn_records(tcp: &[RawTcpRow], udp: &[RawUdpRow]) -> Vec<Record> {
    unimplemented!()
}

/// MIB TCP state code -> label. Common states; unknown -> the numeric string.
fn tcp_state_label(state: u32) -> String {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP row becomes a tcp NetConn with remote + state; a UDP row becomes a udp
    /// NetConn with no remote and no state.
    #[test]
    fn maps_tcp_and_udp_rows() {
        let tcp = vec![RawTcpRow {
            laddr: "127.0.0.1".into(), lport: 445,
            raddr: "10.0.0.5".into(), rport: 50000,
            state_raw: 5 /* LISTEN per MIB */, pid: 4,
        }];
        let udp = vec![RawUdpRow { laddr: "0.0.0.0".into(), lport: 137, pid: 900 }];
        let recs = build_netconn_records(&tcp, &udp);
        assert_eq!(recs.len(), 2);

        let Record::NetConn(t) = &recs[0] else { panic!("tcp") };
        assert_eq!(t.proto, "tcp");
        assert_eq!(t.lport, 445);
        assert_eq!(t.raddr.as_deref(), Some("10.0.0.5"));
        assert_eq!(t.rport, Some(50000));
        assert_eq!(t.pid, Some(4));
        assert!(t.state.is_some());

        let Record::NetConn(u) = &recs[1] else { panic!("udp") };
        assert_eq!(u.proto, "udp");
        assert_eq!(u.lport, 137);
        assert_eq!(u.raddr, None);
        assert_eq!(u.state, None);
        assert_eq!(u.pid, Some(900));
    }
}
```

- [ ] **Step 2: Add `pub mod net;` to `crates/cairn-collectors/src/lib.rs`.**

- [ ] **Step 3: Run, watch it fail.**

Run: `cargo test -p cairn-collectors net::tests`
Expected: FAIL — `unimplemented!()` panics.

- [ ] **Step 4: Implement.** Replace the two `unimplemented!()` bodies:

```rust
pub fn build_netconn_records(tcp: &[RawTcpRow], udp: &[RawUdpRow]) -> Vec<Record> {
    let mut out = Vec::with_capacity(tcp.len() + udp.len());
    for r in tcp {
        out.push(Record::NetConn(NetConnRecord {
            proto: "tcp".into(),
            laddr: r.laddr.clone(),
            lport: r.lport,
            raddr: Some(r.raddr.clone()),
            rport: Some(r.rport),
            state: Some(tcp_state_label(r.state_raw)),
            pid: Some(r.pid),
        }));
    }
    for r in udp {
        out.push(Record::NetConn(NetConnRecord {
            proto: "udp".into(),
            laddr: r.laddr.clone(),
            lport: r.lport,
            raddr: None,
            rport: None,
            state: None,
            pid: Some(r.pid),
        }));
    }
    out
}

fn tcp_state_label(state: u32) -> String {
    match state {
        1 => "closed".into(),
        2 => "listen".into(),
        3 => "syn_sent".into(),
        4 => "syn_rcvd".into(),
        5 => "established".into(),
        6 => "fin_wait1".into(),
        7 => "fin_wait2".into(),
        8 => "close_wait".into(),
        9 => "closing".into(),
        10 => "last_ack".into(),
        11 => "time_wait".into(),
        12 => "delete_tcb".into(),
        other => other.to_string(),
    }
}
```

> NOTE: the test's `state_raw: 5` asserts only `state.is_some()`, so the exact MIB→label
> table above (Microsoft's MIB_TCP_STATE numbering) does not affect the test; it is the
> real mapping used at runtime.

- [ ] **Step 5: Run + gate + commit.**

```bash
git add crates/cairn-collectors/src/net.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(s2a): pure TCP/UDP row->NetConn mapping + TCP state labels (TDD)"
```

---

## Task 9: `NetCollector impl Collector`

**Files:**
- Modify: `crates/cairn-collectors/src/net.rs`

- [ ] **Step 1: Write the test.** Append to `net.rs` tests:

```rust
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::Config;

    /// NetCollector.collect returns only NetConn records, never panics, name() is "net".
    #[test]
    fn net_collector_collects_without_panicking() {
        let c = NetCollector;
        assert_eq!(c.name(), "net");
        let cfg = Config::default();
        let ctx = CollectCtx { config: &cfg, admin: false, se_backup: false, se_debug: false };
        let recs = c.collect(&ctx).expect("collect");
        assert!(recs.iter().all(|r| matches!(r, Record::NetConn(_))));
        assert_eq!(c.sources()[0].artifact, "netconn");
    }
```

- [ ] **Step 2: Run, watch it fail.**

Run: `cargo test -p cairn-collectors net_collector`
Expected: FAIL — `NetCollector` not defined.

- [ ] **Step 3: Implement.** Append to `net.rs` (above tests):

```rust
use cairn_core::manifest::SourceEntry;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;

/// Collector for live TCP/UDP tables with owning PID (SRS §4 net_collector).
pub struct NetCollector;

impl Collector for NetCollector {
    fn name(&self) -> &str {
        "net"
    }
    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let tcp = cairn_collectors_win::net::tcp_table()?;
        let udp = cairn_collectors_win::net::udp_table()?;
        Ok(build_netconn_records(&tcp, &udp))
    }
    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "netconn".into(),
            path: "live:net".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }]
    }
}
```

- [ ] **Step 4: Run + gate + commit.**

```bash
git add crates/cairn-collectors/src/net.rs
git commit -m "feat(s2a): NetCollector impl Collector (live network source)"
```

---

## Task 10: Orchestrator `run_live` (pure, TDD with fake collectors)

**Files:**
- Create: `crates/cairn-core/src/orchestrator.rs`
- Modify: `crates/cairn-core/src/lib.rs` (add `pub mod orchestrator;`)

- [ ] **Step 1: Write the failing tests with fake collectors.** Create
  `crates/cairn-core/src/orchestrator.rs`:

```rust
//! Minimal live-run orchestrator (SRS §3): probe privileges (injected), sequence the
//! given collectors in order, accumulate Records + provenance, and degrade gracefully —
//! a failing collector is logged + recorded but never aborts the run (FR13, golden rule 8).
use crate::manifest::{Privileges, SourceEntry};
use crate::record::Record;
use crate::traits::{CollectCtx, Collector};
use crate::{Config, Result};

/// Result of a live run, ready to feed the manifest builder + reporter.
#[derive(Debug)]
pub struct RunOutcome {
    pub records: Vec<Record>,
    pub sources: Vec<SourceEntry>,
    pub privileges: Privileges,
    pub hostname: String,
}

/// Run the given collectors against the host. `privileges`/`hostname` are provided by the
/// caller (real probe in the bin; fakes in tests) so this stays pure + testable.
pub fn run_live(
    cfg: &Config,
    privileges: Privileges,
    hostname: String,
    collectors: &[Box<dyn Collector>],
) -> RunOutcome {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{NetConnRecord, ProcessRecord};
    use crate::CairnError;

    /// A test double: returns a canned result, advertises one source. Uses Mutex (not
    /// RefCell) because the Collector trait requires Send + Sync.
    struct FakeCollector {
        name: &'static str,
        result: std::sync::Mutex<Option<Result<Vec<Record>>>>,
    }
    impl FakeCollector {
        fn ok(name: &'static str, recs: Vec<Record>) -> Box<dyn Collector> {
            Box::new(FakeCollector { name, result: std::sync::Mutex::new(Some(Ok(recs))) })
        }
        fn err(name: &'static str) -> Box<dyn Collector> {
            Box::new(FakeCollector {
                name,
                result: std::sync::Mutex::new(Some(Err(CairnError::Privilege {
                    what: name.into(), need: "Administrator".into(),
                }))),
            })
        }
    }
    impl Collector for FakeCollector {
        fn name(&self) -> &str { self.name }
        fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
            self.result.lock().unwrap().take().unwrap()
        }
        fn sources(&self) -> Vec<SourceEntry> {
            vec![SourceEntry { artifact: self.name.into(), path: format!("live:{}", self.name),
                method: "api".into(), size: 0, sha256: String::new(), errors: vec![] }]
        }
    }

    fn privs() -> Privileges { Privileges { admin: true, se_backup: false, se_debug: false } }
    fn proc_rec() -> Record { Record::Process(ProcessRecord {
        pid: 1, ppid: 0, image: "a.exe".into(), cmdline: String::new(),
        signed: None, integrity: None, user: None, start_time: None }) }
    fn net_rec() -> Record { Record::NetConn(NetConnRecord {
        proto: "tcp".into(), laddr: "127.0.0.1".into(), lport: 1, raddr: None, rport: None,
        state: None, pid: Some(1) }) }

    /// All collectors succeed: records + sources accumulate in order, privileges/hostname
    /// pass through.
    #[test]
    fn accumulates_all_successful_collectors() {
        let cfg = Config::default();
        let collectors = vec![
            FakeCollector::ok("proc", vec![proc_rec()]),
            FakeCollector::ok("net", vec![net_rec()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors);
        assert_eq!(out.records.len(), 2);
        assert_eq!(out.sources.len(), 2);
        assert_eq!(out.hostname, "WS01");
        assert!(out.privileges.admin);
    }

    /// One collector erroring does NOT abort: the other still runs, and the failure is
    /// recorded as a source with a non-empty errors list (graceful degrade, FR13).
    #[test]
    fn failing_collector_is_recorded_and_run_continues() {
        let cfg = Config::default();
        let collectors = vec![
            FakeCollector::err("proc"),
            FakeCollector::ok("net", vec![net_rec()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors);
        // net still produced its record.
        assert_eq!(out.records.len(), 1);
        // proc's failure is captured as a source entry carrying the error.
        let failed = out.sources.iter().find(|s| s.artifact == "proc").expect("proc source");
        assert!(!failed.errors.is_empty(), "failure must be recorded");
    }
}
```

- [ ] **Step 2: Add `pub mod orchestrator;` to `crates/cairn-core/src/lib.rs`.**

- [ ] **Step 3: Run the tests, watch them fail.**

Run: `cargo test -p cairn-core orchestrator`
Expected: FAIL — `unimplemented!()` panics.

- [ ] **Step 4: Implement.** Replace the `run_live` body:

```rust
pub fn run_live(
    cfg: &Config,
    privileges: Privileges,
    hostname: String,
    collectors: &[Box<dyn Collector>],
) -> RunOutcome {
    let ctx = CollectCtx {
        config: cfg,
        admin: privileges.admin,
        se_backup: privileges.se_backup,
        se_debug: privileges.se_debug,
    };
    let mut records = Vec::new();
    let mut sources = Vec::new();
    for c in collectors {
        match c.collect(&ctx) {
            Ok(mut recs) => {
                records.append(&mut recs);
                sources.extend(c.sources());
            }
            Err(e) => {
                // Graceful degrade: record the failure as a source entry, keep going.
                tracing::warn!(collector = c.name(), error = %e, "collector failed; skipping");
                sources.push(SourceEntry {
                    artifact: c.name().to_string(),
                    path: format!("live:{}", c.name()),
                    method: "api".into(),
                    size: 0,
                    sha256: String::new(),
                    errors: vec![e.to_string()],
                });
            }
        }
    }
    RunOutcome { records, sources, privileges, hostname }
}
```

- [ ] **Step 5: Add `tracing` dep to cairn-core.** In `crates/cairn-core/Cargo.toml`
  `[dependencies]` add:

```toml
tracing.workspace = true
```

- [ ] **Step 6: Run tests + gate.**

Run: `cargo test -p cairn-core orchestrator` + full gate. Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add crates/cairn-core/src/orchestrator.rs crates/cairn-core/src/lib.rs crates/cairn-core/Cargo.toml Cargo.lock
git commit -m "feat(s2a): minimal live orchestrator with graceful degrade (TDD, fakes)"
```

---

## Task 11: CLI wiring `cairn run --target live` + end-to-end verification

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`
- Modify: `crates/cairn-cli/Cargo.toml` (dep on `cairn-collectors-win`)

- [ ] **Step 1: Add the dep.** In `crates/cairn-cli/Cargo.toml` `[dependencies]`:

```toml
cairn-collectors-win = { path = "../cairn-collectors-win" }
```

- [ ] **Step 2: Write a unit test for the run-plan helper.** In `main.rs` tests module, add:

```rust
    #[test]
    fn run_target_live_is_recognized() {
        assert!(is_live_target("live"));
        assert!(!is_live_target("C:\\evidence"));
    }
```

- [ ] **Step 3: Run it, watch it fail.**

Run: `cargo test -p cairn-cli run_target_live`
Expected: FAIL — `is_live_target` not defined.

- [ ] **Step 4: Implement the helper + wire `Cmd::Run`.** Add the helper near the other
  pure helpers in `main.rs`:

```rust
/// True if the run target selects the live host (vs an offline artifact dir).
fn is_live_target(target: &str) -> bool {
    target.eq_ignore_ascii_case("live")
}
```

Then replace the `Cmd::Run(_args) => { tracing::info!("TODO S2+...") }` arm. The `Run`
arm currently lives in the non-evtx `other` match which inits a stderr-only subscriber;
move `Run` OUT to the top-level match (like `Evtx`) so it gets its own run.log. Replace
the `Cmd::Run` handling with:

```rust
Cmd::Run(args) => {
    use cairn_core::orchestrator::run_live;
    use cairn_core::traits::Collector;

    if !is_live_target(&args.target) {
        // Offline-artifact orchestration is the raw-NTFS sub-segment; be honest.
        eprintln!("cairn run --target <dir> is not implemented yet (raw-NTFS sub-segment); \
                   use --target live, or `cairn evtx` for EVTX files.");
        std::process::exit(2);
    }

    let dir = args.output.clone();
    std::fs::create_dir_all(&dir)?;
    let file_appender = tracing_appender::rolling::never(&dir, "run.log");
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .with_target(false)
        .with_ansi(false)
        .with_writer(file_writer)
        .init();

    tracing::info!("cairn {} ({}) starting (live)", env!("CARGO_PKG_VERSION"), BUILD_SHA);

    let privileges = cairn_collectors_win::privilege::probe();
    tracing::info!(admin = privileges.admin, se_backup = privileges.se_backup,
        se_debug = privileges.se_debug, "privilege probe");
    let hostname = cairn_collectors_win::host::hostname().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "hostname probe failed; using 'unknown'");
        "unknown".into()
    });

    let cfg = Config::default();
    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(cairn_collectors::proc::ProcCollector),
        Box::new(cairn_collectors::net::NetCollector),
    ];
    let outcome = run_live(&cfg, privileges, hostname, &collectors);
    tracing::info!(records = outcome.records.len(), "live collection complete");

    // Reuse the manifest builder shape from the evtx path, filled from the outcome.
    let by_sev = cairn_report::Summary::from_findings(&[], outcome.records.len() as u64)
        .by_severity;
    let manifest = Manifest {
        schema: cairn_core::schema::MANIFEST.to_string(),
        tool: ToolInfo {
            name: "cairn".into(), version: env!("CARGO_PKG_VERSION").into(),
            build_sha: BUILD_SHA.into(), sigma_ruleset_ver: String::new(),
        },
        run: RunInfo {
            started_utc: chrono::Utc::now(), finished_utc: Some(chrono::Utc::now()),
            cmdline: std::env::args().collect::<Vec<_>>().join(" "),
            operator: String::new(), case_id: String::new(),
        },
        host: HostInfo {
            hostname: outcome.hostname.clone(), os_build: String::new(),
            timezone: "UTC".into(), wall_clock_utc_skew: "unknown".into(),
        },
        privileges: outcome.privileges.clone(),
        sources: outcome.sources.clone(),
        outputs: vec![],
        counts: Counts { records: outcome.records.len() as u64, findings_by_sev: by_sev },
        integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
    };

    let mut sink = DirSink::new(dir.clone());
    sink.write_timeline_csv(&[])?;       // no findings yet (no analyzers this sub-segment)
    sink.write_findings_jsonl(&[])?;
    // Also dump the collected records so the run is actually useful:
    write_records_jsonl(&dir, &outcome.records)?;
    manifest_outputs_then_write(&mut sink, manifest)?;
    tracing::info!(dir = %dir.display(), "live run complete");
    drop(_guard);
}
```

Add two small helpers in `main.rs` (records dump + manifest finalize), keeping the
manifest.outputs-before-write pattern from the evtx path:

```rust
/// Dump collected Records as JSONL so a live run produces usable data even before
/// analyzers exist. One Record per line (the internal bus type; versioned by schema::RECORD).
fn write_records_jsonl(dir: &std::path::Path, records: &[cairn_core::record::Record]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(dir.join("records.jsonl"))?;
    for r in records {
        writeln!(f, "{}", serde_json::to_string(r)?)?;
    }
    Ok(())
}

/// Set manifest.outputs from the data files written so far, then write the manifest.
fn manifest_outputs_then_write(sink: &mut DirSink, mut manifest: Manifest) -> anyhow::Result<()> {
    manifest.outputs = sink.outputs_so_far();
    sink.write_manifest(&manifest)?;
    let outputs = sink.finalize()?;
    for o in &outputs {
        tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
    }
    Ok(())
}
```

> NOTE: `records.jsonl` is written via `std::fs` directly (not DirSink) so it is not in
> the manifest's hashed outputs in THIS sub-segment — the manifest still hashes
> timeline.csv + findings.jsonl. Adding records.jsonl to the hashed set is a tiny
> follow-up (route it through DirSink) but not required for the gate. Keep it simple now.

- [ ] **Step 5: Run the unit test + full gate.**

Run: `cargo test -p cairn-cli run_target_live` then the full workspace gate.
Expected: PASS; clippy clean.

- [ ] **Step 6: END-TO-END VERIFICATION (the real usability check).** Build and run
  against this live host:

Run:
```
cargo run -q -p cairn-cli --bin cairn -- run --target live --output ./out-live
```
Then inspect (use Read, not shell cat):
- `./out-live/manifest.json` — `privileges` reflects this host; `host.hostname` is real;
  `counts.records` > 0; `sources` lists process + netconn (+ any degraded errors).
- `./out-live/records.jsonl` — contains `"kind":"process"` lines incl. this run's PID, and
  `"kind":"net_conn"` lines.
- `./out-live/run.log` — probe line + per-collector lines + completion, clean.

Then verify integrity end to end:
```
cargo run -q -p cairn-cli --bin cairn -- verify ./out-live/manifest.json
```
Expected: VERIFY OK (timeline.csv + findings.jsonl hashes match), exit 0.

- [ ] **Step 7: Commit.**

```bash
git add crates/cairn-cli/src/main.rs crates/cairn-cli/Cargo.toml Cargo.lock
git commit -m "feat(s2a): wire cairn run --target live (probe+orchestrate+report)"
```

---

## Sub-segment exit check (alignment, per user requirement)

After Task 11, before declaring S2-A done, run the full alignment pass:

- [ ] `cargo test --workspace` all green; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check` clean; `cargo audit` clean (or documented).
- [ ] `unsafe` appears in NO crate except `cairn-collectors-win` (verify:
  `grep -rn "unsafe" crates --include=*.rs | grep -v cairn-collectors-win | grep -v "forbid(unsafe"` → only the forbid lines).
- [ ] Real `cairn run --target live` produced a process list (incl. this PID) + net list + verifiable manifest (Task 11 Step 6 passed).
- [ ] `cairn evtx` still works unchanged (run an S1 fixture through it).
- [ ] Both CI jobs green after push: ubuntu (stubs compile) + windows (real FFI + smoke tests).
- [ ] Update the progress memory (`cairn-stage1-progress.md`) with what S2-A delivered and the next sub-segment (persistence or heuristics).
- [ ] Re-read SRS §3/§4/§16 S2 gate: confirm no drift; note which S2 items remain (persistence, heuristics, raw-NTFS, offline artifacts).
