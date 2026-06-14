# S2-E: process full image path + signed backfill + unsigned-amplifier conversion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read each process's full image path, backfill `ProcessRecord.signed` via the existing `verify_file`, and convert the parentchild/netconn unsigned signals into amplifiers so catalog-signed system processes don't flood findings.

**Architecture:** `cairn-collectors-win/src/proc.rs` enriches each RawProc with the full image path (OpenProcess + QueryFullProcessImageNameW, best-effort, RAII handle guard). `ProcCollector` gains an injected `FileVerifier` (same seam as PersistCollector) and fills `signed` for absolute-path images only. The parentchild/netconn heuristics gate their unsigned signals on "another signal already fired".

**Tech Stack:** Rust, `windows` 0.62.2 (`Win32_System_Threading`, already enabled), the S2-D `FileVerifier`/`verify_file`/`WinSigVerifier`/`NoopVerifier` seam, `cairn-heur` score.rs.

**Authoritative spec:** `docs/superpowers/specs/2026-06-13-s2e-proc-signed-design.md`. Verified WinAPI shapes are in that spec's "full-image-path enrichment" section.

---

## File Structure

- `crates/cairn-collectors-win/src/proc.rs` (modify mod win): add OpenProcess + QueryFullProcessImageNameW enrichment with an RAII handle guard.
- `crates/cairn-collectors/src/proc.rs` (modify): `ProcCollector` gains a `verifier` field; add `is_absolute_path`; `collect` fills `signed`.
- `crates/cairn-heur/src/parentchild.rs` (modify): unsigned (+20) and unsigned+high-integrity (+15) become amplifiers.
- `crates/cairn-heur/src/netconn.rs` (modify): unsigned owner (+20) and the unsigned high-port listener (+25) gated on another signal.
- `crates/cairn-cli/src/main.rs` (modify): construct `ProcCollector::default()`.

---

## Task 1: Full image path enrichment (the unsafe FFI)

**Files:**
- Modify: `crates/cairn-collectors-win/src/proc.rs` (the `#[cfg(windows)] mod win`)

Mirror the existing `Snapshot` RAII guard. New WinAPI: OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_NAME_WIN32. No new crate feature.

- [ ] **Step 1: Read the current file**

Read `crates/cairn-collectors-win/src/proc.rs` fully. Note the `Snapshot(HANDLE)` RAII guard pattern, the SAFETY comment style, and the loop that fills `RawProc { image: <szExeFile>, ... }`.

- [ ] **Step 2: Add a process-handle RAII guard + the path helper**

Inside `mod win`, add the imports and a guard mirroring `Snapshot`. Add to the `use windows::Win32::...` block:

```rust
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::PWSTR;
```

(Some of `Foundation::{CloseHandle, HANDLE}` may already be imported for the snapshot — merge, don't duplicate.)

Add a guard + a function that resolves one pid's full path (returns None on any failure):

```rust
    /// RAII guard for a process HANDLE.
    /// INVARIANT: holds a valid handle from OpenProcess; closed exactly once on drop.
    struct ProcHandle(HANDLE);
    impl Drop for ProcHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid process handle from OpenProcess; closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Best-effort full image path for a pid via OpenProcess + QueryFullProcessImageNameW.
    /// Returns None if the process cannot be opened (privilege / exited) or the query fails.
    /// Never panics. Read-only: QUERY_LIMITED_INFORMATION cannot modify the target.
    fn full_image_path(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess with QUERY_LIMITED_INFORMATION returns an owned handle or Err;
        // wrapped immediately in the guard. bInheritHandle=false.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let guard = ProcHandle(handle);

        // First attempt with MAX_PATH; grow once on insufficient buffer.
        for cap in [260usize, 32768usize] {
            let mut buf = vec![0u16; cap];
            let mut len = cap as u32;
            // SAFETY: guard.0 is a valid handle; buf has `len` u16 slots; len is in/out.
            let r = unsafe {
                QueryFullProcessImageNameW(
                    guard.0,
                    PROCESS_NAME_WIN32,
                    PWSTR(buf.as_mut_ptr()),
                    &mut len,
                )
            };
            match r {
                Ok(()) => {
                    let s = String::from_utf16_lossy(&buf[..len as usize]);
                    return if s.is_empty() { None } else { Some(s) };
                }
                Err(_) => {
                    // On the first (small) buffer, an error is most likely insufficient
                    // buffer -> retry with the large cap. On the large buffer, give up.
                    continue;
                }
            }
        }
        None
    }
```

- [ ] **Step 3: Use it in the enumerate loop**

In the enumerate loop, after computing `image` (the szExeFile file name), prefer the full
path when obtainable:

```rust
            let file_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            // Prefer the full image path (for signature verification downstream); fall back
            // to the Toolhelp file name when the process can't be opened (privilege/exited).
            let image = full_image_path(entry.th32ProcessID).unwrap_or(file_name);
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
```

(Adjust to the exact existing variable names — the current code names the file name `image`; rename that local to `file_name` and set `image` from `full_image_path(...).unwrap_or(file_name)`.)

- [ ] **Step 4: Verify it compiles + smoke test**

Run: `cargo check -p cairn-collectors-win`
Expected: clean.

Update/extend the existing smoke test (`enumerate_includes_current_process`) OR add one asserting the current process now has an ABSOLUTE path:

```rust
    /// On Windows we can open our own process, so enumerate() yields an absolute image path
    /// for the current pid (proving the OpenProcess/QueryFullProcessImageNameW path works).
    #[test]
    fn current_process_has_absolute_image_path() {
        let procs = enumerate().expect("enumerate");
        let me = std::process::id();
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        // an absolute Windows path contains ":\" (drive) — the file-name fallback would not
        assert!(
            mine.image.contains(":\\"),
            "expected absolute path, got {:?}",
            mine.image
        );
    }
```

Run: `cargo test -p cairn-collectors-win proc`
Expected: PASS (existing smoke + the new absolute-path assertion).

- [ ] **Step 5: clippy + commit**

Run: `cargo clippy -p cairn-collectors-win --all-targets -- -D warnings`
Expected: clean.

```bash
git add crates/cairn-collectors-win/src/proc.rs
git commit -m "feat(win): resolve full process image path (OpenProcess + QueryFullProcessImageNameW)"
```

---

## Task 2: ProcCollector fills signed via injected verifier

**Files:**
- Modify: `crates/cairn-collectors/src/proc.rs`

Mirror the S2-D `PersistCollector` shape: a `verifier` field, `Default` (WinSigVerifier on Windows / NoopVerifier off-Windows), `with_verifier`. Add `is_absolute_path`. Only absolute images are verified. This crate stays `#![forbid(unsafe_code)]`.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/cairn-collectors/src/proc.rs`:

```rust
    use cairn_core::traits::FileVerifier;

    struct FakeVerifier(std::collections::HashMap<String, bool>);
    impl FileVerifier for FakeVerifier {
        fn verify(&self, path: &str) -> Option<bool> {
            self.0.get(path).copied()
        }
    }

    /// is_absolute_path: drive-letter and UNC are absolute; a bare name is not.
    #[test]
    fn absolute_path_detection() {
        assert!(is_absolute_path(r"C:\Windows\System32\svchost.exe"));
        assert!(is_absolute_path(r"\\server\share\app.exe"));
        assert!(!is_absolute_path("svchost.exe"));
        assert!(!is_absolute_path(""));
    }

    /// apply_signatures fills signed only for absolute-path images, via the verifier.
    #[test]
    fn apply_signatures_fills_only_absolute_images() {
        let mut map = std::collections::HashMap::new();
        map.insert(r"C:\evil\b.exe".to_string(), false);
        map.insert(r"C:\trusted\a.exe".to_string(), true);
        let v = FakeVerifier(map);

        let mut recs = vec![
            // absolute, known false
            ProcessRecord { pid:1, ppid:0, image:r"C:\evil\b.exe".into(), cmdline:String::new(), signed:None, integrity:None, user:None, start_time:None },
            // absolute, known true
            ProcessRecord { pid:2, ppid:0, image:r"C:\trusted\a.exe".into(), cmdline:String::new(), signed:None, integrity:None, user:None, start_time:None },
            // absolute, unknown to verifier -> None
            ProcessRecord { pid:3, ppid:0, image:r"C:\unknown\c.exe".into(), cmdline:String::new(), signed:None, integrity:None, user:None, start_time:None },
            // file-name-only -> never queried -> None
            ProcessRecord { pid:4, ppid:0, image:"svchost.exe".into(), cmdline:String::new(), signed:None, integrity:None, user:None, start_time:None },
        ];
        apply_signatures(&mut recs, &v);
        assert_eq!(recs[0].signed, Some(false));
        assert_eq!(recs[1].signed, Some(true));
        assert_eq!(recs[2].signed, None);
        assert_eq!(recs[3].signed, None);
    }
```

Run: `cargo test -p cairn-collectors absolute_path_detection apply_signatures_fills_only_absolute_images`
Expected: FAIL (functions not defined).

- [ ] **Step 2: Implement**

In `crates/cairn-collectors/src/proc.rs`, add `use cairn_core::traits::FileVerifier;` at the top, and:

```rust
/// True if `image` looks like a Windows absolute path (drive letter `X:\...` or UNC `\\...`).
/// Only absolute images are sent to signature verification; a bare file name (the
/// OpenProcess-failed fallback) is left unverified so we never resolve a name against the CWD.
pub fn is_absolute_path(image: &str) -> bool {
    let b = image.as_bytes();
    let drive = b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    let unc = image.starts_with(r"\\");
    drive || unc
}

/// Fill `signed` for records whose image is an absolute path, via the verifier. A
/// file-name-only image is left None (not verified). Pure wiring (no OS code here).
fn apply_signatures(records: &mut [ProcessRecord], verifier: &dyn FileVerifier) {
    for r in records.iter_mut() {
        if is_absolute_path(&r.image) {
            r.signed = verifier.verify(&r.image);
        }
    }
}
```

Then convert `ProcCollector` from a unit struct to one with a verifier (mirror PersistCollector exactly):

```rust
/// Collector that enumerates live processes (SRS §4 proc_collector). Read-only. Fills
/// `signed` via the injected verifier (the WinTrust seam stays in cairn-collectors-win).
pub struct ProcCollector {
    verifier: Box<dyn FileVerifier + Send + Sync>,
}

impl Default for ProcCollector {
    fn default() -> Self {
        #[cfg(windows)]
        let verifier: Box<dyn FileVerifier + Send + Sync> =
            Box::new(cairn_collectors_win::signature::WinSigVerifier);
        #[cfg(not(windows))]
        let verifier: Box<dyn FileVerifier + Send + Sync> = Box::new(NoopVerifier);
        Self { verifier }
    }
}

impl ProcCollector {
    /// Construct with a specific verifier (tests inject a fake).
    pub fn with_verifier(verifier: Box<dyn FileVerifier + Send + Sync>) -> Self {
        Self { verifier }
    }
}
```

Reuse the `NoopVerifier` from the persist module rather than redefining it: add
`use crate::persist::NoopVerifier;` (confirm `NoopVerifier` is `pub` in persist.rs — it is,
per S2-D). If it is not reachable, define a local `NoopVerifier` here with the same trivial
impl and `#[allow(dead_code)]` on Windows.

Update the `impl Collector for ProcCollector`:

```rust
    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let raw = cairn_collectors_win::proc::enumerate()?;
        let mut recs = build_process_records(&raw);
        // recs are Record::Process; fill signed on the inner ProcessRecord.
        for r in recs.iter_mut() {
            if let Record::Process(p) = r {
                if is_absolute_path(&p.image) {
                    p.signed = self.verifier.verify(&p.image);
                }
            }
        }
        Ok(recs)
    }
```

NOTE: `apply_signatures` (Step 1 test) operates on `&mut [ProcessRecord]`, but `collect`
holds `Vec<Record>`. Keep BOTH: `apply_signatures` is the unit-tested pure helper over
`ProcessRecord`; `collect` does the equivalent over the `Record::Process` wrapper inline (as
shown). Alternatively, refactor `build_process_records` to return `Vec<ProcessRecord>` and
wrap after applying signatures — but that changes its public signature and existing tests,
so prefer the inline form in `collect` and keep `apply_signatures` for the unit test. Ensure
the logic is identical (absolute-only). If you find the duplication unclean, have `collect`
build `Vec<ProcessRecord>` first, call `apply_signatures`, then map to `Record::Process` — do
this ONLY if `build_process_records`'s existing callers/tests still pass.

- [ ] **Step 3: Run tests**

Run: `cargo test -p cairn-collectors`
Expected: the two new tests pass; all existing proc tests still pass (the
`proc_collector_collects_without_panicking` test uses `ProcCollector` — update it to
`ProcCollector::default()` since it is no longer a unit struct).

- [ ] **Step 4: clippy + forbid check + commit**

Run: `cargo clippy -p cairn-collectors --all-targets --locked -- -D warnings`
Expected: clean. Confirm `#![forbid(unsafe_code)]` still at crate root; no unsafe added.

```bash
git add crates/cairn-collectors/src/proc.rs
git commit -m "feat(proc): fill ProcessRecord.signed via injected FileVerifier (absolute paths only)"
```

---

## Task 3: parentchild unsigned-amplifier conversion

**Files:**
- Modify: `crates/cairn-heur/src/parentchild.rs` (`score_process` + tests)

The unsigned (+20) and unsigned+high-integrity (+15) signals must fire only when another signal already fired. Because the LOLBAS signal currently comes AFTER the unsigned checks, move the unsigned checks to the END of `score_process` so "another signal fired" accounts for every other signal (parent anomaly, encoded PS, suspicious path, LOLBAS).

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/cairn-heur/src/parentchild.rs`:

```rust
    /// Unsigned WITH another signal (suspicious path): amplifier fires (+20).
    #[test]
    fn unsigned_amplifies_with_suspicious_path() {
        let mut p = proc(10, 0, r"C:\Users\a\AppData\Local\Temp\x.exe", "x.exe");
        p.signed = Some(false);
        let s = score_process(&p, None);
        // suspicious path 25 + unsigned 20 = 45
        assert_eq!(s.weight, 45);
        assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned ALONE (normal path, no parent/encoded/LOLBAS): amplifier does NOT fire.
    /// This is the catalog-signed-system-process case (reported unsigned) — must stay quiet.
    #[test]
    fn unsigned_alone_does_not_amplify() {
        let mut p = proc(11, 0, r"C:\Windows\System32\svchost.exe", "svchost.exe");
        p.signed = Some(false);
        p.integrity = Some("system".into());
        let s = score_process(&p, None);
        // no other signal -> neither unsigned (+20) nor unsigned+high-integrity (+15) fires
        assert_eq!(s.weight, 0);
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned + high integrity WITH another signal: both unsigned amplifiers fire.
    #[test]
    fn unsigned_high_integrity_amplifies_with_signal() {
        let mut p = proc(12, 0, r"C:\Users\a\AppData\Local\Temp\x.exe", "x.exe");
        p.signed = Some(false);
        p.integrity = Some("high".into());
        let s = score_process(&p, None);
        // suspicious path 25 + unsigned 20 + unsigned-high-integrity 15 = 60
        assert_eq!(s.weight, 60);
    }

    /// Signed (Some(true)) with a suspicious path: no unsigned amplifier.
    #[test]
    fn signed_does_not_amplify() {
        let mut p = proc(13, 0, r"C:\Users\a\AppData\Local\Temp\x.exe", "x.exe");
        p.signed = Some(true);
        let s = score_process(&p, None);
        assert_eq!(s.weight, 25); // suspicious path only
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }
```

Run: `cargo test -p cairn-heur unsigned_alone_does_not_amplify unsigned_amplifies_with_suspicious_path` — the `unsigned_alone` test FAILS today (current code adds 20+15=35 unconditionally), proving the bug the conversion fixes. The `amplifies_with_suspicious_path` may already pass (path+unsigned). Confirm which fail and why.

- [ ] **Step 2: Implement the conversion**

In `score_process`, REMOVE the two existing unsigned blocks (lines that add +20 "binary is
unsigned" and +15 "unsigned binary running at high integrity"). Then, AFTER the LOLBAS block
(i.e. at the very end, before `s`), add:

```rust
    // Unsigned amplifier: an unsigned binary is a signal only when ANOTHER suspicion has
    // already fired. catalog-signed OS binaries are reported unsigned by WTD_CHOICE_FILE, so
    // an unconditional unsigned signal would flood every signed-by-catalog system process.
    // We never penalize the unverifiable (None) nor the trusted (Some(true)). proc `signed`
    // is backfilled by the proc collector via WinVerifyTrust (S2-E).
    let another_signal_fired = !s.reasons.is_empty();
    if p.signed == Some(false) && another_signal_fired {
        s.add(20, "binary is unsigned", &[]);
        if matches!(p.integrity.as_deref(), Some("high") | Some("system")) {
            s.add(15, "unsigned binary running at high integrity", &["T1068"]);
        }
    }
```

`!s.reasons.is_empty()` is correct here because at this point `s` holds ONLY corroborating
signals (parent anomaly, encoded PS, suspicious path, LOLBAS) — the unsigned signals have
not been added yet. (Unlike persist, parentchild has no mechanism base weight, so an empty
reasons list means genuinely no other signal.)

- [ ] **Step 3: Run tests**

Run: `cargo test -p cairn-heur`
Expected: all pass — the 4 new tests + every existing parentchild/score test. If
`unsigned_from_temp_no_parent_scores` (existing) asserted `>= 45`, it still holds (path 25 +
unsigned 20 = 45). Confirm it passes unchanged; if it relied on unsigned firing without
another signal, update it to include a corroborating signal (it uses a Temp path, so it
already has one — verify).

- [ ] **Step 4: clippy + commit**

Run: `cargo clippy -p cairn-heur --all-targets --locked -- -D warnings`
Expected: clean.

```bash
git add crates/cairn-heur/src/parentchild.rs
git commit -m "fix(heur): parentchild unsigned signals become amplifiers (require another signal)"
```

---

## Task 4: netconn unsigned-amplifier conversion

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs` (`score_conn` + tests)

The unsigned-owner (+20) must require another connection/owner signal. The unsigned high-port listener (+25) must additionally require the suspicious-path signal (the only other owner-level signal), so catalog-signed services on high ports don't flag.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/cairn-heur/src/netconn.rs`:

```rust
    /// Unsigned owner WITH another signal (public IP + rare port): amplifier fires.
    #[test]
    fn unsigned_owner_amplifies_with_connection_signal() {
        let c = conn("tcp", 50000, Some("104.18.0.1"), Some(4444), Some("established"), Some(1));
        let o = owner(r"C:\Windows\System32\svc.exe", Some(false)); // normal path
        let s = score_conn(&c, Some(&o));
        // public ip 25 + rare port 20 + unsigned 20 = 65 (no suspicious path)
        assert_eq!(s.weight, 65);
        assert!(s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned owner, NO other connection signal (common port, no public-IP/rare/temp):
    /// amplifier does NOT fire — the catalog-signed-service case stays quiet.
    #[test]
    fn unsigned_owner_alone_does_not_amplify() {
        let c = conn("tcp", 50000, Some("104.18.0.1"), Some(443), Some("established"), Some(1));
        let o = owner(r"C:\Windows\System32\svchost.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        // common port 443 -> no rare/public-IP signal; normal path -> no path signal;
        // unsigned alone must not fire -> weight 0
        assert_eq!(s.weight, 0);
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned high-port listener in a NORMAL path: listener compound does NOT fire (a
    /// catalog-signed service on an ephemeral port must not flag).
    #[test]
    fn unsigned_listener_normal_path_does_not_fire() {
        let c = conn("tcp", 49500, None, None, Some("listen"), Some(1));
        let o = owner(r"C:\Windows\System32\svchost.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        assert_eq!(s.weight, 0, "catalog-signed service listener in System32 must stay quiet");
    }

    /// Unsigned high-port listener in a SUSPICIOUS path: both the path signal and the
    /// listener compound fire (genuinely suspicious).
    #[test]
    fn unsigned_listener_suspicious_path_fires() {
        let c = conn("tcp", 4444, None, None, Some("listen"), Some(1));
        let o = owner(r"C:\Users\a\AppData\Local\Temp\svc.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        // suspicious path 30 + unsigned 20 + listener 25 = 75
        assert_eq!(s.weight, 75);
        assert!(s.reasons.iter().any(|r| r.contains("listening on high port")));
    }
```

Confirm the `conn(...)` and `owner(...)` test helpers' exact signatures in the file and match the argument order. Run the tests; `unsigned_owner_alone_does_not_amplify` and `unsigned_listener_normal_path_does_not_fire` FAIL today (unconditional unsigned + listener). Confirm.

- [ ] **Step 2: Implement the conversion**

In `score_conn`, the current owner block is (roughly):

```rust
    if let Some(o) = owner {
        if is_suspicious_path(&o.image) {
            s.add(30, format!("owning process runs from a suspicious path: {}", o.image), &[]);
        }
        if o.signed == Some(false) {
            s.add(20, "owning process is unsigned", &[]);
        }
        if c.state.as_deref() == Some("listen") && c.lport > 1024 && o.signed == Some(false) {
            s.add(25, format!("unsigned process listening on high port {}", c.lport), &[]);
        }
    }
```

Replace the owner block with a version that (a) records whether the suspicious-path signal
fired, (b) records whether ANY signal fired before the unsigned checks, and (c) gates:

```rust
    if let Some(o) = owner {
        let mut owner_path_suspicious = false;
        if is_suspicious_path(&o.image) {
            s.add(30, format!("owning process runs from a suspicious path: {}", o.image), &[]);
            owner_path_suspicious = true;
        }
        // Unsigned owner is an amplifier: fire only if another signal (connection-level —
        // public-IP/rare-port — or the owner suspicious-path above) already fired. catalog-
        // signed OS binaries report unsigned via WTD_CHOICE_FILE, so an unconditional signal
        // would flood every signed-by-catalog service. Never penalize None/Some(true).
        let another_signal_fired = !s.reasons.is_empty();
        if o.signed == Some(false) && another_signal_fired {
            s.add(20, "owning process is unsigned", &[]);
        }
        // Unsigned high-port listener: keep listen + port>1024 + unsigned, but ALSO require
        // the suspicious-path signal so a catalog-signed service on an ephemeral port (every
        // svchost RPC listener) does not flag.
        if c.state.as_deref() == Some("listen")
            && c.lport > 1024
            && o.signed == Some(false)
            && owner_path_suspicious
        {
            s.add(25, format!("unsigned process listening on high port {}", c.lport), &[]);
        }
    }
```

IMPORTANT: `!s.reasons.is_empty()` here is evaluated AFTER the public-IP and rare-port
signals (which run earlier in `score_conn`, before the `if let Some(o)` block) and after the
owner suspicious-path signal. So it correctly means "some non-unsigned signal fired". Confirm
by reading the function: the public-IP (+25) and rare-port (+20) `s.add` calls precede the
owner block. If any owner-independent signal can be added AFTER this block, move the snapshot
accordingly — but per the current structure the owner block is last.

- [ ] **Step 3: Run tests**

Run: `cargo test -p cairn-heur`
Expected: all pass. Check the existing `unsigned_temp_to_public_rare_port_scores_high`
(public ip 25 + rare 20 + temp 30 + unsigned 20 = 95) still holds — it has corroborating
signals so the amplifier fires. Check `unsigned_high_port_listener_fires` (existing): it uses
a Temp path, so owner_path_suspicious is true and the listener fires — still passes. If that
existing test used a NON-suspicious path, it must be updated to a suspicious one (the new
gate is intentional); verify and adjust the test's expectation to match the corrected design,
documenting why.

- [ ] **Step 4: clippy + commit**

Run: `cargo clippy -p cairn-heur --all-targets --locked -- -D warnings`
Expected: clean.

```bash
git add crates/cairn-heur/src/netconn.rs
git commit -m "fix(heur): netconn unsigned signals become amplifiers (require another signal)"
```

---

## Task 5: Wire the real verifier in the CLI

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (~line 453)

- [ ] **Step 1: Update the construction**

Change the proc collector line in the `collectors` vec:

```rust
                Box::new(cairn_collectors::proc::ProcCollector::default()),
```

(was `Box::new(cairn_collectors::proc::ProcCollector)`)

- [ ] **Step 2: Verify the workspace compiles + tests**

Run: `cargo check --workspace && cargo test --workspace`
Expected: clean, all pass.

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): construct ProcCollector with the real signature verifier"
```

---

## Task 6: Acceptance gate (fmt / clippy --locked / audit)

**Files:** none (verification only)

- [ ] **Step 1: fmt**

Run: `cargo fmt --all` then `cargo fmt --all --check`
Expected: clean.

- [ ] **Step 2: clippy --locked (the CI condition)**

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings`
Expected: clean. Watch for Windows-only dead_code (the new `ProcHandle`, `full_image_path`
are inside `#[cfg(windows)] mod win` — used on Windows, absent on Linux, so no Linux dead_code;
but `is_absolute_path`/`apply_signatures`/`NoopVerifier` reachability on each target —
add `#[allow(dead_code)]` only if a target actually flags one, per the S2-C/S2-D lesson).

- [ ] **Step 3: check + test --locked**

Run: `cargo check --workspace --locked && cargo test --workspace --locked`
Expected: all green.

- [ ] **Step 4: audit**

Run: `cargo audit --deny warnings`
Expected: clean (no new external crate — Threading APIs are in the already-present `windows`).

- [ ] **Step 5: Commit any fixes**

```bash
git add -A
git commit -m "chore(s2e): acceptance gate — fmt, clippy --locked, audit clean"
```

(Skip if no changes.)

---

## Task 7: End-to-end verification on a live host (Windows, manual)

**Files:** none (manual; record results for the PR body)

- [ ] **Step 1: Build release**

Run: `cargo build --release`
Expected: builds (normal profile).

- [ ] **Step 2: Run a live triage**

Run: `./target/release/cairn run --target live --output <fresh temp dir>`
Expected: exits 0; writes records.jsonl, findings.jsonl, manifest.json, run.log.
(The binary may live under `CARGO_TARGET_DIR`; locate it as in prior stages.)

- [ ] **Step 3: Confirm proc signed is populated**

Inspect records.jsonl process records:
```bash
grep '"kind":"process"' <out>/records.jsonl | grep -c '"signed":true'
grep '"kind":"process"' <out>/records.jsonl | grep -c '"signed":false'
grep '"kind":"process"' <out>/records.jsonl | grep -c '"signed":null'
```
Expected: a non-trivial mix (true for signed/embedded, false for catalog-signed-reported-
unsigned and genuinely unsigned, null for processes we couldn't open — full path absent).
If ALL null, the enrichment or verifier is not wired — investigate before proceeding.

- [ ] **Step 4: Confirm NO unsigned flood in findings (the whole point)**

```bash
wc -l < <out>/findings.jsonl
grep -c '"severity":"high"' <out>/findings.jsonl
grep -c unsigned <out>/findings.jsonl
```
Expected: process/netconn findings did NOT balloon with "unsigned" reasons on catalog-signed
system processes. Compare the high count to a pre-S2-E baseline if available; a clean host
should show few/no unsigned-amplified process findings. If there is an unsigned flood, the
amplifier conversion is wrong — STOP and fix before the PR.

- [ ] **Step 5: Spot-check a few process records**

Pick a known signed app (e.g. the cairn.exe self process, or chrome.exe) — confirm signed is
true or a sensible value, and its image is an absolute path. Pick a svchost — confirm it is
NOT flagged as a finding despite likely `signed:false` (catalog).

- [ ] **Step 6: verify integrity path**

Run a `--zip` run + `cairn verify <manifest>`; expect VERIFY OK exit 0. Confirm S1/S2-A/B/C/D
paths unchanged.

- [ ] **Step 7: Record numbers for the PR body**

proc signed true/false/null breakdown; findings count + high count; any unsigned-amplified
findings; verify result.

---

## Final review

After all tasks: holistic review over `git diff main...HEAD`. Focus:
- The new unsafe in `proc.rs`: SAFETY comments accurate? OpenProcess handle closed on every
  path (RAII guard)? Buffer-grow retry correct? `full_image_path` total (no panic)?
- `is_absolute_path`: only absolute images verified (no bare-name verification)?
- Amplifier conversions: parentchild AND netconn fire unsigned ONLY with another signal? The
  catalog-signed-system-process case stays quiet (the e2e showed no flood)?
- `#![forbid(unsafe_code)]` intact in cairn-collectors and cairn-heur; unsafe only in
  cairn-collectors-win.
- Golden rules: read-only query (QUERY_LIMITED_INFORMATION), no evasion, normal profile,
  signed three-state semantics, graceful degrade (unopenable process keeps file name).

Then use superpowers:finishing-a-development-branch.
