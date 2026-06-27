# S2-D: WinVerifyTrust signature verification + persist signed backfill — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify Authenticode signatures via WinTrust, backfill `PersistenceRecord.signed`, and add an "unsigned amplifier" signal to the persist heuristic that fires only alongside another suspicion signal.

**Architecture:** New `signature` module in `cairn-collectors-win` (the only unsafe-FFI crate) exposes `verify_file(path) -> Option<bool>`. A `FileVerifier` trait in `cairn-core` is the seam; `PersistCollector` gains a `verifier` field and fills `signed` after fanning in its readers, staying `#![forbid(unsafe_code)]`. The persist heuristic adds `+20` when `signed == Some(false)` AND another signal already fired.

**Tech Stack:** Rust, `windows` 0.62.2 (feature `Win32_Security_WinTrust`), existing `cairn-core` traits, `cairn-heur` score.rs.

**Authoritative spec:** `docs/superpowers/specs/2026-06-13-s2d-signature-design.md`. Verified WinTrust API shapes are in that spec's "The WinVerifyTrust wrapper" section.

---

## File Structure

- `crates/cairn-core/src/traits.rs` (modify): add `FileVerifier` trait.
- `crates/cairn-collectors-win/Cargo.toml` (modify): add `Win32_Security_WinTrust` feature.
- `crates/cairn-collectors-win/src/signature.rs` (create): `verify_file` + `WinSigVerifier`.
- `crates/cairn-collectors-win/src/lib.rs` (modify): `pub mod signature;`.
- `crates/cairn-collectors/src/persist.rs` (modify): `verifier` field, `NoopVerifier`, fill `signed`.
- `crates/cairn-heur/src/persist.rs` (modify): unsigned-amplifier signal + tests.
- `crates/cairn-cli/src/main.rs` (modify): construct `PersistCollector` with the real verifier.

---

## Task 1: FileVerifier trait in cairn-core

**Files:**
- Modify: `crates/cairn-core/src/traits.rs` (append after the `Analyzer` trait, ~line 45)

The seam both the safe collector and the unsafe win crate depend on. Lives in core (no host deps) so neither side needs the other directly.

- [ ] **Step 1: Add the trait**

Append to `crates/cairn-core/src/traits.rs` after the `Analyzer` trait block:

```rust
/// Verifies a file's code signature. The seam between the safe collectors and the
/// unsafe WinTrust FFI (cairn-collectors-win): collectors depend only on this trait, so
/// they stay `#![forbid(unsafe_code)]`. `verify` is total — it never panics and never
/// errors; an unverifiable file (missing, unreadable, off-platform) yields `None`.
///
/// Contract:
/// - `Some(true)`  = signature present and trusted.
/// - `Some(false)` = unsigned or signature invalid/untrusted.
/// - `None`        = could not verify (file absent, path not convertible, off-platform).
pub trait FileVerifier: Send + Sync {
    fn verify(&self, path: &str) -> Option<bool>;
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p cairn-core`
Expected: compiles clean (a trait with no impls is valid).

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-core/src/traits.rs
git commit -m "feat(core): add FileVerifier trait (signature-verification seam)"
```

---

## Task 2: WinTrust feature flag

**Files:**
- Modify: `crates/cairn-collectors-win/Cargo.toml` (the windows features list)

- [ ] **Step 1: Add the feature**

In `crates/cairn-collectors-win/Cargo.toml`, add `"Win32_Security_WinTrust"` to the
`features` array under `[target.'cfg(windows)'.dependencies.windows]` (alphabetical-ish,
after `"Win32_Security"`):

```toml
features = [
  "Win32_Foundation",
  "Win32_System_Threading",
  "Win32_System_ProcessStatus",
  "Win32_System_Diagnostics_ToolHelp",
  "Win32_Security",
  "Win32_Security_WinTrust",
  "Win32_System_SystemInformation",
  "Win32_NetworkManagement_IpHelper",
  "Win32_Networking_WinSock",
]
```

- [ ] **Step 2: Verify it resolves**

Run: `cargo check -p cairn-collectors-win`
Expected: compiles clean (feature exists in windows 0.62.2; confirmed in spec).

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-collectors-win/Cargo.toml
git commit -m "build(win): enable Win32_Security_WinTrust feature"
```

---

## Task 3: verify_file wrapper + WinSigVerifier (the unsafe FFI)

**Files:**
- Create: `crates/cairn-collectors-win/src/signature.rs`
- Modify: `crates/cairn-collectors-win/src/lib.rs` (add `pub mod signature;`)

This is the only new unsafe code. Mirror the existing `host.rs` pattern exactly: non-Windows stub + `#[cfg(windows)] mod win` with SAFETY comments and an RAII guard for the WTD_STATEACTION_CLOSE teardown.

- [ ] **Step 1: Write the cross-platform skeleton + non-Windows stub**

Create `crates/cairn-collectors-win/src/signature.rs`:

```rust
//! Authenticode signature verification via WinTrust (WinVerifyTrust). Read-only: opens the
//! file only to verify its embedded signature; never writes. This is a NORMAL call to the
//! public verification API — not signing, hooking, or trust-provider patching (golden rule 1).
//!
//! `verify_file` is total (never panics, never errors): an unverifiable file yields None.
//! Mirrors the host.rs FFI pattern (non-Windows stub + cfg(windows) mod win + SAFETY notes).
use cairn_core::traits::FileVerifier;

/// Verify a file's embedded Authenticode signature.
/// - `Some(true)`  = WinVerifyTrust returned ERROR_SUCCESS (trusted).
/// - `Some(false)` = unsigned or untrusted (any non-zero status).
/// - `None`        = file missing / path unconvertible / off-platform (cannot verify).
#[cfg(not(windows))]
pub fn verify_file(_path: &str) -> Option<bool> {
    None
}

#[cfg(windows)]
pub fn verify_file(path: &str) -> Option<bool> {
    win::verify_file(path)
}

/// A `FileVerifier` backed by `verify_file`. The real default used on Windows.
pub struct WinSigVerifier;

impl FileVerifier for WinSigVerifier {
    fn verify(&self, path: &str) -> Option<bool> {
        verify_file(path)
    }
}
```

- [ ] **Step 2: Add the Windows FFI module**

Append to `crates/cairn-collectors-win/src/signature.rs`:

```rust
#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    /// Encode a path to a NUL-terminated wide string (UTF-16). Returns the owned Vec; the
    /// caller must keep it alive while the PCWSTR into it is in use.
    fn wide_nul(path: &str) -> Vec<u16> {
        std::ffi::OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn verify_file(path: &str) -> Option<bool> {
        if path.is_empty() || !std::path::Path::new(path).exists() {
            return None; // nothing to verify
        }
        let wide = wide_nul(path);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut wtd = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        wtd.Anonymous.pFile = &mut file_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // RAII guard: whatever happens after VERIFY, the provider state MUST be closed
        // (WTD_STATEACTION_CLOSE) or it leaks. The guard borrows wtd and runs CLOSE on drop.
        struct CloseGuard<'a>(&'a mut WINTRUST_DATA);
        impl Drop for CloseGuard<'_> {
            fn drop(&mut self) {
                self.0.dwStateAction = WTD_STATEACTION_CLOSE;
                let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                // SAFETY: self.0 is the same WINTRUST_DATA opened by the VERIFY call below;
                // CLOSE frees the provider's state data. Null HWND = no UI.
                unsafe {
                    let _ = WinVerifyTrust(
                        HWND::default(),
                        &mut action,
                        self.0 as *mut _ as *mut c_void,
                    );
                }
            }
        }

        // SAFETY: wtd/file_info/wide all outlive this call; pcwszFilePath points into `wide`
        // which is still owned here; pFile points at the live `file_info`. Null HWND = no UI.
        let status = unsafe {
            let s = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut wtd as *mut _ as *mut c_void,
            );
            // Arm the guard AFTER a successful VERIFY open so CLOSE always pairs with VERIFY.
            let _guard = CloseGuard(&mut wtd);
            s
        };

        Some(status == 0) // 0 == ERROR_SUCCESS == trusted
    }
}
```

- [ ] **Step 3: Register the module**

In `crates/cairn-collectors-win/src/lib.rs`, add after `pub mod proc;`:

```rust
pub mod signature;
```

- [ ] **Step 4: Verify it compiles on this host (Windows)**

Run: `cargo check -p cairn-collectors-win`
Expected: compiles clean. If the borrow checker rejects holding `_guard` while returning
`s`, restructure so the guard's scope ends before the `Some(status == 0)` return (e.g. wrap
the VERIFY call + guard in a block that returns `status`). The invariant to preserve: CLOSE
runs exactly once after VERIFY, even on early return.

- [ ] **Step 5: Smoke test (Windows-gated)**

Append to `crates/cairn-collectors-win/src/signature.rs`:

```rust
#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// A non-existent path is unverifiable -> None (never panics).
    #[test]
    fn missing_file_is_none() {
        assert_eq!(verify_file(r"C:\does\not\exist\nope.exe"), None);
    }

    /// An unsigned junk file -> Some(false). Writes a temp file with .exe name + garbage.
    #[test]
    fn unsigned_junk_is_false() {
        let p = std::env::temp_dir().join(format!("cairn_s2d_unsigned_{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ not a real signed PE, just junk bytes").unwrap();
        let got = verify_file(&p.to_string_lossy());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, Some(false), "unsigned junk must verify as not-trusted");
    }

    /// A known OS binary returns without panic. We assert it is Some(_) or None but do NOT
    /// hard-require Some(true): some system files are catalog-signed (not embedded), which
    /// WTD_CHOICE_FILE reports as unsigned (documented limitation, spec scope note). The
    /// point of this smoke test is "the FFI path runs and the CLOSE pairs with VERIFY".
    #[test]
    fn known_os_binary_does_not_panic() {
        let candidates = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\notepad.exe"];
        for c in candidates {
            if std::path::Path::new(c).exists() {
                let _ = verify_file(c); // must not panic; value is environment-dependent
                return;
            }
        }
        // No candidate present (unusual) — nothing to assert beyond no-panic above.
    }

    /// The WinSigVerifier trait impl delegates to verify_file.
    #[test]
    fn win_verifier_delegates() {
        assert_eq!(
            WinSigVerifier.verify(r"C:\does\not\exist\nope.exe"),
            None
        );
    }
}
```

Run: `cargo test -p cairn-collectors-win signature`
Expected: PASS (3-4 tests). `unsigned_junk_is_false` proves the verify path returns false
for unsigned; `missing_file_is_none` proves the existence guard.

- [ ] **Step 6: Verify non-Windows builds (the stub)**

The non-Windows path returns None and has no FFI. This is checked on CI (ubuntu). Locally,
just confirm the cfg gates are correct by reviewing that `verify_file`/`tests` are gated.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors-win/src/signature.rs crates/cairn-collectors-win/src/lib.rs
git commit -m "feat(win): WinVerifyTrust signature verification (verify_file + WinSigVerifier)"
```

---

## Task 4: Wire the verifier into PersistCollector

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs` (the `PersistCollector` struct + impls + tests)

`PersistCollector` becomes a struct with a boxed `FileVerifier`. A `NoopVerifier` (returns None) is the cross-platform default and the test default. `collect` fills `signed` after fanning in the readers. The collector stays `#![forbid(unsafe_code)]`.

- [ ] **Step 1: Write the failing wiring test (FakeVerifier)**

Add to the `tests` module in `crates/cairn-collectors/src/persist.rs`:

```rust
use cairn_core::traits::FileVerifier;

/// A verifier that maps known paths to a fixed result; unknown -> None.
struct FakeVerifier(std::collections::HashMap<String, bool>);
impl FileVerifier for FakeVerifier {
    fn verify(&self, path: &str) -> Option<bool> {
        self.0.get(path).copied()
    }
}

/// collect() fills `signed` from the verifier for records that have a binary_path.
#[test]
fn collect_fills_signed_from_verifier() {
    // Build a collector whose verifier knows two paths.
    let mut map = std::collections::HashMap::new();
    map.insert(r"C:\trusted\a.exe".to_string(), true);
    map.insert(r"C:\evil\b.exe".to_string(), false);
    let verifier: Box<dyn FileVerifier + Send + Sync> = Box::new(FakeVerifier(map));

    // Drive apply_signatures directly on hand-built records (no OS reads).
    let mut records = vec![
        PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("a".into()),
            command: Some(r"C:\trusted\a.exe".into()),
            binary_path: Some(r"C:\trusted\a.exe".into()),
            binary_sha256: None,
            signed: None,
            last_write: None,
        },
        PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("b".into()),
            command: Some(r"C:\evil\b.exe".into()),
            binary_path: Some(r"C:\evil\b.exe".into()),
            binary_sha256: None,
            signed: None,
            last_write: None,
        },
        PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("c".into()),
            command: Some(r"C:\unknown\c.exe".into()),
            binary_path: Some(r"C:\unknown\c.exe".into()),
            binary_sha256: None,
            signed: None,
            last_write: None,
        },
        PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("d".into()),
            command: None,
            binary_path: None, // never queried
            binary_sha256: None,
            signed: None,
            last_write: None,
        },
    ];
    apply_signatures(&mut records, verifier.as_ref());
    assert_eq!(records[0].signed, Some(true));
    assert_eq!(records[1].signed, Some(false));
    assert_eq!(records[2].signed, None); // verifier didn't know it
    assert_eq!(records[3].signed, None); // no binary_path -> not queried
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p cairn-collectors collect_fills_signed_from_verifier`
Expected: FAIL — `apply_signatures` not defined.

- [ ] **Step 3: Implement apply_signatures + the struct change**

Replace the `pub struct PersistCollector;` and its `impl Collector` in
`crates/cairn-collectors/src/persist.rs` with:

```rust
use cairn_core::traits::FileVerifier;

/// A verifier that never verifies (always None). Cross-platform default + test default; on
/// non-Windows it is also what the real collector uses (no WinTrust off-Windows).
pub struct NoopVerifier;
impl FileVerifier for NoopVerifier {
    fn verify(&self, _path: &str) -> Option<bool> {
        None
    }
}

/// Fill each record's `signed` from the verifier, for records that have a binary_path.
/// Pure wiring (no OS code); the verifier abstracts the platform. A binary_path of None is
/// left untouched (signed stays None).
fn apply_signatures(records: &mut [PersistenceRecord], verifier: &dyn FileVerifier) {
    for r in records.iter_mut() {
        if let Some(p) = r.binary_path.as_deref() {
            r.signed = verifier.verify(p);
        }
    }
}

/// Collector for live persistence mechanisms (SRS §4 persist_collector). Read-only.
/// Fans in the five mechanism readers; each is best-effort. Fills `signed` via the
/// injected verifier (the WinTrust seam stays in cairn-collectors-win).
pub struct PersistCollector {
    verifier: Box<dyn FileVerifier + Send + Sync>,
}

impl Default for PersistCollector {
    fn default() -> Self {
        #[cfg(windows)]
        let verifier: Box<dyn FileVerifier + Send + Sync> =
            Box::new(cairn_collectors_win::signature::WinSigVerifier);
        #[cfg(not(windows))]
        let verifier: Box<dyn FileVerifier + Send + Sync> = Box::new(NoopVerifier);
        Self { verifier }
    }
}

impl PersistCollector {
    /// Construct with a specific verifier (tests inject a fake; non-default callers).
    pub fn with_verifier(verifier: Box<dyn FileVerifier + Send + Sync>) -> Self {
        Self { verifier }
    }
}

impl Collector for PersistCollector {
    fn name(&self) -> &str {
        "persist"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let mut records: Vec<PersistenceRecord> = Vec::new();
        records.extend(read_run_keys());
        records.extend(read_services());
        records.extend(read_winlogon());
        records.extend(read_ifeo());
        records.extend(read_startup_folders());
        apply_signatures(&mut records, self.verifier.as_ref());
        Ok(records.into_iter().map(Record::Persistence).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "persistence".into(),
            path: "live:registry+startup".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }]
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p cairn-collectors collect_fills_signed_from_verifier`
Expected: PASS.

- [ ] **Step 5: Run the whole crate's tests (no regression)**

Run: `cargo test -p cairn-collectors`
Expected: all PASS (the existing persist tests still hold; PersistCollector default still constructs).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(persist): fill PersistenceRecord.signed via injected FileVerifier"
```

---

## Task 5: Unsigned amplifier in the persist heuristic

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs` (`score_persistence` + tests)

Add the amplifier AFTER the existing signals so it can see whether another signal fired. `signed == Some(false)` AND (suspicious-path fired OR recency fired) => +20, T1036.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/cairn-heur/src/persist.rs`. First extend the `rec`
helper to take `signed` — but to avoid touching every existing call, add a sibling helper:

```rust
/// Like `rec` but with an explicit `signed` value (for amplifier tests).
fn rec_signed(
    mechanism: &str,
    binary_path: Option<&str>,
    last_write: Option<DateTime<Utc>>,
    signed: Option<bool>,
) -> PersistenceRecord {
    let mut r = rec(mechanism, binary_path, last_write);
    r.signed = signed;
    r
}

/// Unsigned + suspicious path: amplifier fires (+20), reason mentions unsigned.
#[test]
fn unsigned_amplifies_suspicious_path() {
    let now = Utc::now();
    let old = now - Duration::days(400); // no recency, isolate the path signal
    let p = rec_signed(
        "run_key",
        Some(r"C:\Users\a\AppData\Local\Temp\x.exe"),
        Some(old),
        Some(false),
    );
    let s = score_persistence(&p, now);
    // run_key 10 + path 30 + unsigned 20 = 60
    assert_eq!(s.weight, 60, "weight {}", s.weight);
    assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
    assert!(s.mitre.contains(&"T1036".to_string()));
}

/// Unsigned in a NORMAL path, old: amplifier does NOT fire (no other signal).
#[test]
fn unsigned_alone_does_not_amplify() {
    let now = Utc::now();
    let old = now - Duration::days(400);
    let p = rec_signed(
        "run_key",
        Some(r"C:\Program Files\Vendor\app.exe"),
        Some(old),
        Some(false),
    );
    let s = score_persistence(&p, now);
    // run_key 10 only; no path, no recency -> amplifier off -> below floor
    assert_eq!(s.weight, 10, "weight {}", s.weight);
    assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
}

/// Signed (Some(true)) in a suspicious path: amplifier does NOT fire.
#[test]
fn signed_does_not_amplify() {
    let now = Utc::now();
    let old = now - Duration::days(400);
    let p = rec_signed(
        "run_key",
        Some(r"C:\Users\a\AppData\Local\Temp\x.exe"),
        Some(old),
        Some(true),
    );
    let s = score_persistence(&p, now);
    // run_key 10 + path 30 = 40; signed -> no amplifier
    assert_eq!(s.weight, 40, "weight {}", s.weight);
    assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
}

/// Unknown signature (None) in a suspicious path: amplifier does NOT fire (we never
/// penalize what we could not verify).
#[test]
fn unknown_signature_does_not_amplify() {
    let now = Utc::now();
    let old = now - Duration::days(400);
    let p = rec_signed(
        "run_key",
        Some(r"C:\Users\a\AppData\Local\Temp\x.exe"),
        Some(old),
        None,
    );
    let s = score_persistence(&p, now);
    assert_eq!(s.weight, 40, "weight {}", s.weight); // run_key 10 + path 30, no amplifier
}

/// Unsigned + recent (no suspicious path): recency is the other signal, so amplifier fires.
#[test]
fn unsigned_amplifies_recency() {
    let now = Utc::now();
    let p = rec_signed(
        "service",
        Some(r"C:\Windows\System32\svc.exe"), // normal path, no path signal
        Some(now),                            // recent -> recency signal fires
        Some(false),
    );
    let s = score_persistence(&p, now);
    // service 20 + recent 15 + unsigned 20 = 55
    assert_eq!(s.weight, 55, "weight {}", s.weight);
    assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p cairn-heur unsigned`
Expected: FAIL — the amplifier is not implemented, so weights are 40/10/40/40/35 instead of 60/10/40/40/55. (The signed-/unknown-/alone cases already pass coincidentally; the `unsigned_amplifies_*` cases fail.)

- [ ] **Step 3: Implement the amplifier**

The amplifier must fire only when a PATH or RECENCY signal already fired — NOT the bare
mechanism. The robust way to know "did path/recency fire" without coupling to reason
strings is to capture the weight BEFORE those two signals and compare. Restructure
`score_persistence` so the mechanism weight is recorded, then check whether path+recency
added anything.

In `crates/cairn-heur/src/persist.rs`, in `score_persistence`: right after the mechanism
`match` block (before the suspicious-path block), capture the base weight:

```rust
    // Weight contributed by the mechanism alone, captured before the path/recency signals
    // so the unsigned amplifier can tell whether ANOTHER signal (path or recency) fired.
    let mechanism_weight = s.weight;
```

Then, AFTER the recency block and BEFORE `s` is returned, add:

```rust
    // Unsigned amplifier: an unsigned binary is only a signal when ANOTHER suspicion is
    // already present (a suspicious path or a recent write added weight beyond the
    // mechanism base). Many legitimate tools are unsigned in normal locations — penalizing
    // that alone floods false positives. We never penalize what we could not verify (None)
    // nor what is trusted (Some(true)). `signed` is backfilled by the persist collector via
    // WinVerifyTrust (S2-D).
    let another_signal_fired = s.weight > mechanism_weight;
    if p.signed == Some(false) && another_signal_fired {
        s.add(20, "binary is unsigned (amplifies the above)", &["T1036"]);
    }
```

This matches the spec's worked cases: a bare unsigned mechanism (e.g. run_key 10 with no
path/recency) has `s.weight == mechanism_weight`, so the amplifier stays off. Note the
startup mechanism never gets a path signal (it is exempted earlier), so an unsigned startup
item amplifies only on recency — correct.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p cairn-heur`
Expected: all PASS (the 5 new amplifier tests + all existing persist/score tests).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): unsigned amplifier in persist heuristic (+20 only with another signal)"
```

---

## Task 6: Wire the real verifier in the CLI

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (~line 455, the collectors vec)

`PersistCollector` is no longer a unit struct — update its construction to use the default
(which picks WinSigVerifier on Windows).

- [ ] **Step 1: Update the construction**

In `crates/cairn-cli/src/main.rs`, change the persist collector line in the `collectors` vec:

```rust
                Box::new(cairn_collectors::persist::PersistCollector::default()),
```

(was `Box::new(cairn_collectors::persist::PersistCollector)`)

- [ ] **Step 2: Verify the workspace compiles**

Run: `cargo check --workspace`
Expected: compiles clean.

- [ ] **Step 3: Verify the full test suite**

Run: `cargo test --workspace`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): construct PersistCollector with the real signature verifier"
```

---

## Task 7: Acceptance gate (fmt / clippy / audit / dead-code)

**Files:** none (verification only)

- [ ] **Step 1: Format**

Run: `cargo fmt --all`
Then: `cargo fmt --all --check`
Expected: clean.

- [ ] **Step 2: Clippy with --locked (the CI condition that bit S2-C)**

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings`
Expected: clean. If a Windows-only helper is dead on Linux, add `#[allow(dead_code)]` (the
S2-C lesson). Specifically check: does `NoopVerifier` get used on Windows? It is the
non-Windows default AND the test default, so it is referenced on both — but confirm clippy
does not flag it on the Windows build (if it does, the test usage should keep it live; if
not, gate or allow as needed).

- [ ] **Step 3: Check + test with --locked**

Run: `cargo check --workspace --locked && cargo test --workspace --locked`
Expected: all green.

- [ ] **Step 4: Audit (new feature, no new crate)**

Run: `cargo audit --deny warnings`
Expected: clean (WinTrust is part of the already-present `windows` crate; no new dependency).

- [ ] **Step 5: Commit any fmt/allow fixes**

```bash
git add -A
git commit -m "chore(s2d): acceptance gate — fmt, clippy --locked, audit clean"
```

(Skip the commit if Steps 1-4 produced no changes.)

---

## Task 8: End-to-end verification on a live host (Windows, manual)

**Files:** none (manual verification; record results in the PR body)

- [ ] **Step 1: Build release**

Run: `cargo build --release`
Expected: builds (normal profile; no strip/abort tricks — golden rule 2).

- [ ] **Step 2: Run a live triage to a temp output dir**

Run: `./target/release/cairn run --target live --output /tmp/cairn-s2d-e2e`
Expected: exits 0; writes records.jsonl, findings.jsonl, manifest.json, run.log.

- [ ] **Step 3: Confirm signed is populated on persistence records**

Inspect `records.jsonl`: persistence records (`"kind":"persistence"`) now carry a `signed`
value that is `true`/`false`/`null` (not uniformly null). Count how many got a real bool:

```bash
grep '"kind":"persistence"' /tmp/cairn-s2d-e2e/records.jsonl | grep -c '"signed":true'
grep '"kind":"persistence"' /tmp/cairn-s2d-e2e/records.jsonl | grep -c '"signed":false'
```

Expected: a non-trivial number of `true` (signed OS/vendor binaries) and possibly some
`false`. If ALL are null, the verifier is not wired — investigate before proceeding.

- [ ] **Step 4: Confirm the amplifier shows in findings (if any unsigned+suspicious exist)**

Inspect `findings.jsonl` for any persistence finding whose `reason` contains "unsigned".
This is environment-dependent (you may have no unsigned-in-suspicious-path persistence —
that is a CLEAN result, not a failure). The assertion is: IF such a record exists, its
finding's weight reflects the +20 and the reason names it.

- [ ] **Step 5: Verify the archive integrity path still works**

Run: `./target/release/cairn run --target live --output /tmp/cairn-s2d-zip --zip` then
`./target/release/cairn verify /tmp/cairn-s2d-zip/manifest.json` (adjust path to the written manifest).
Expected: verify reports OK (exit 0). S1/S2-A/B/C paths unchanged.

- [ ] **Step 6: Record the e2e numbers**

Note for the PR body: total records, persistence count, signed true/false/null breakdown,
findings count, any "unsigned" findings, verify result.

---

## Final review

After all tasks: dispatch a holistic code review over the whole S2-D diff
(`git diff main...HEAD`). Focus areas:
- The unsafe block in `signature.rs`: SAFETY comments accurate? CLOSE pairs with VERIFY on
  every path (including early returns)? No handle/state leak? No panic path?
- The amplifier gate: precisely "path OR recency", not the bare mechanism? Reason-substring
  coupling documented (it depends on the exact reason strings of earlier signals)?
- `#![forbid(unsafe_code)]` still holds in cairn-collectors and cairn-heur; unsafe only in
  cairn-collectors-win.
- Golden rules: read-only verify, no evasion, normal release profile, signed three-state
  semantics honored.

Then use superpowers:finishing-a-development-branch.
