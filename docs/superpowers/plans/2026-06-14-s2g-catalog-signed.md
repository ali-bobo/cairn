# S2-G Catalog-Signed Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `verify_file` recognize catalog-signed Windows binaries as trusted (`Some(true)`) instead of falsely reporting them unsigned (`Some(false)`), by adding a system-catalog fallback after the embedded-signature check fails.

**Architecture:** The only code file changed is `crates/cairn-collectors-win/src/signature.rs`, plus two feature flags in `crates/cairn-collectors-win/Cargo.toml`. `verify_file` keeps its existing embedded-signature check (`WTD_CHOICE_FILE`) verbatim as the fast path; on embedded failure it calls a new `verify_via_catalog` that hashes the file, looks the hash up in the system catalog (`CryptCATAdmin*`), and verifies the matching `.cat` via `WinVerifyTrust(WTD_CHOICE_CATALOG)`. Three RAII guards release the admin context, catalog context, and file handle on every path. The `FileVerifier` trait, all collectors, all heuristics, and the `Option<bool>` schema are unchanged — catalog-signed binaries flipping to `Some(true)` improves heuristic behavior automatically.

**Tech Stack:** Rust, `windows` crate 0.62.2 (WinTrust + CryptCATAdmin + FileSystem FFI). Unsafe is isolated to `cairn-collectors-win` (the single `#![allow(unsafe_code)]` crate). All API shapes verified against crate source — see the design spec.

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-s2g-catalog-signed-design.md`

---

## File Structure

- **Modify:** `crates/cairn-collectors-win/Cargo.toml` — add two `windows` features: `Win32_Security_Cryptography_Catalog` (catalog APIs) and `Win32_Storage_FileSystem` (`CreateFileW` + file constants).
- **Modify:** `crates/cairn-collectors-win/src/signature.rs` — add `verify_via_catalog` + three RAII guard structs inside `mod win`; wire the embedded→catalog fallback into `verify_file`; add a catalog-signed regression test.

No new files. No new crates. No changes outside `cairn-collectors-win`.

---

## Verified API reference (windows 0.62.2 — do NOT re-guess these)

From `windows-0.62.2/.../Security/Cryptography/Catalog/mod.rs`:
```rust
// All are `pub unsafe fn` under `windows::Win32::Security::Cryptography::Catalog`.
CryptCATAdminAcquireContext2(
    phcatadmin: *mut isize,
    pgsubsystem: Option<*const GUID>,
    pwszhashalgorithm: P2,                              // impl Param<PCWSTR>; pass w!("SHA256")
    pstronghashpolicy: Option<*const CERT_STRONG_SIGN_PARA>,
    dwflags: Option<u32>,
) -> windows_core::Result<()>

CryptCATAdminCalcHashFromFileHandle2(
    hcatadmin: isize,
    hfile: HANDLE,
    pcbhash: *mut u32,
    pbhash: Option<*mut u8>,                            // None = size probe
    dwflags: Option<u32>,
) -> windows_core::Result<()>

CryptCATAdminEnumCatalogFromHash(
    hcatadmin: isize,
    pbhash: &[u8],                                      // takes a slice; crate fills cbhash
    dwflags: Option<u32>,
    phprevcatinfo: Option<*mut isize>,
) -> isize                                              // 0 == not found in any catalog

CryptCATCatalogInfoFromContext(
    hcatinfo: isize,
    pscatinfo: *mut CATALOG_INFO,
    dwflags: u32,
) -> windows_core::Result<()>

CryptCATAdminReleaseCatalogContext(hcatadmin: isize, hcatinfo: isize, dwflags: u32) -> BOOL
CryptCATAdminReleaseContext(hcatadmin: isize, dwflags: u32) -> BOOL

// struct CATALOG_INFO { cbStruct: u32, wszCatalogFile: [u16; 260] }
```

From `.../Security/WinTrust/mod.rs`:
```rust
// struct WINTRUST_CATALOG_INFO {
//   cbStruct: u32, dwCatalogVersion: u32,
//   pcwszCatalogFilePath: PCWSTR, pcwszMemberTag: PCWSTR, pcwszMemberFilePath: PCWSTR,
//   hMemberFile: HANDLE, pbCalculatedFileHash: *mut u8, cbCalculatedFileHash: u32,
//   pcCatalogContext: *mut CTL_CONTEXT, hCatAdmin: isize }
// const WTD_CHOICE_CATALOG: WINTRUST_DATA_UNION_CHOICE = WINTRUST_DATA_UNION_CHOICE(2);
// (already imported in signature.rs: WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
//  WINTRUST_DATA, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE, WTD_UI_NONE)
```

From `.../Storage/FileSystem/mod.rs` and `.../Foundation/mod.rs`:
```rust
CreateFileW(
    lpfilename: P0,                                     // impl Param<PCWSTR>
    dwdesiredaccess: u32,                               // pass FILE_GENERIC_READ.0
    dwsharemode: FILE_SHARE_MODE,                       // FILE_SHARE_READ
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>,  // None
    dwcreationdisposition: FILE_CREATION_DISPOSITION,  // OPEN_EXISTING
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,   // FILE_ATTRIBUTE_NORMAL
    htemplatefile: Option<HANDLE>,                     // None
) -> windows_core::Result<HANDLE>

// FILE_GENERIC_READ: FILE_ACCESS_RIGHTS(1179785)  — use FILE_GENERIC_READ.0 for the u32 arg
// FILE_SHARE_READ:   FILE_SHARE_MODE(1)
// OPEN_EXISTING:     FILE_CREATION_DISPOSITION(3)
// FILE_ATTRIBUTE_NORMAL: FILE_FLAGS_AND_ATTRIBUTES(128)
```

Existing helpers in `signature.rs` to reuse: `wide_nul(path: &str) -> Vec<u16>` (NUL-terminated UTF-16), the `mod win` SAFETY-comment style, and the embedded `verify_file` block (Task 2 leaves it verbatim).

---

## Task 1: Enable the catalog + filesystem features

**Files:**
- Modify: `crates/cairn-collectors-win/Cargo.toml:14-25`

- [ ] **Step 1: Add the two features**

In the `features = [ ... ]` list (currently lines 14-25), add two entries. The final list:

```toml
features = [
  "Win32_Foundation",
  "Win32_System_Threading",
  "Win32_System_ProcessStatus",
  "Win32_System_Diagnostics_ToolHelp",
  "Win32_Security",
  "Win32_Security_Cryptography",
  "Win32_Security_Cryptography_Catalog",
  "Win32_Security_WinTrust",
  "Win32_Storage_FileSystem",
  "Win32_System_SystemInformation",
  "Win32_NetworkManagement_IpHelper",
  "Win32_Networking_WinSock",
]
```

- [ ] **Step 2: Verify it resolves (no code uses it yet, so this only checks the feature names are valid)**

Run: `cargo check --package cairn-collectors-win`
Expected: PASS (compiles clean; new features add API surface but nothing references it yet).

> If `cargo check` errors that a feature does not exist, the feature name is wrong — re-verify against `windows-0.62.2` Cargo.toml. The two names above are verified correct for 0.62.2.

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-collectors-win/Cargo.toml
git commit -m "build(s2g): enable Catalog + FileSystem windows features"
```

---

## Task 2: Add the three RAII guards + the catalog verifier skeleton (returns None)

This task lands the resource-safe scaffolding and the embedded→catalog wiring, with `verify_via_catalog` doing the acquire/open/hash/enum chain but returning `None`/`Some(false)` only (no WinVerifyTrust yet). This keeps each task independently compilable and testable. Task 3 adds the final catalog `WinVerifyTrust` step.

**Files:**
- Modify: `crates/cairn-collectors-win/src/signature.rs` (inside `#[cfg(windows)] mod win`)

- [ ] **Step 1: Add imports at the top of `mod win`**

Add to the existing `use` block inside `mod win` (after the current WinTrust imports, around line 42):

```rust
    use windows::core::w;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::WinTrust::{WINTRUST_CATALOG_INFO, WTD_CHOICE_CATALOG};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
```

(`HANDLE` and `PCWSTR` are already imported at the top of `mod win`.)

- [ ] **Step 2: Add the three RAII guard structs at the end of `mod win`, before the closing brace**

```rust
    /// RAII: releases a CryptCATAdmin context on drop. Held for the whole catalog lookup;
    /// must outlive any CatInfoCtx (release-catalog needs this admin handle still valid).
    struct CatAdminCtx(isize);
    impl Drop for CatAdminCtx {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid admin context from CryptCATAdminAcquireContext2;
            // released exactly once. dwflags must be 0.
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }

    /// RAII: releases a catalog context on drop. Stores the admin handle because
    /// CryptCATAdminReleaseCatalogContext requires it. Declared AFTER the admin guard so
    /// reverse-declaration drop order frees the catalog context first, then the admin.
    struct CatInfoCtx {
        admin: isize,
        info: isize,
    }
    impl Drop for CatInfoCtx {
        fn drop(&mut self) {
            // SAFETY: admin/info are the valid handles from acquire/enum; released once.
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(self.admin, self.info, 0);
            }
        }
    }

    /// RAII: closes a file handle on drop (mirrors proc.rs ProcHandle).
    struct FileHandle(HANDLE);
    impl Drop for FileHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid handle from CreateFileW; closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
```

- [ ] **Step 3: Add `verify_via_catalog` (acquire → open → hash → enum; no WinVerifyTrust yet) after the guards**

```rust
    /// Catalog fallback: returns Some(true) if the file's hash is found in a system catalog
    /// AND that catalog verifies, Some(false) if the hash is in no catalog (genuinely
    /// unsigned), None on any infrastructure failure (cannot acquire/open/hash). Total: never
    /// panics. (Task 2 lands acquire/open/hash/enum; the catalog WinVerifyTrust is added in
    /// Task 3 — until then a found hash returns Some(false) as a placeholder.)
    fn verify_via_catalog(path: &str, wide: &[u16]) -> Option<bool> {
        // 1) Acquire a SHA-256 catalog admin context.
        let mut admin_raw: isize = 0;
        // SAFETY: admin_raw is a valid out-param; w!("SHA256") is a 'static NUL-terminated
        // wide literal; other params None. On Err the context is not created (nothing to free).
        let acquired = unsafe {
            CryptCATAdminAcquireContext2(&mut admin_raw, None, w!("SHA256"), None, None)
        };
        if acquired.is_err() {
            return None;
        }
        let admin = CatAdminCtx(admin_raw);

        // 2) Open the file read-only to compute its hash. GENERIC_READ + SHARE_READ +
        //    OPEN_EXISTING: a read-only stat-and-read, never a write (golden rule 3).
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives this call; params are
        // the verified read-only/open-existing constants; returns an owned handle or Err.
        let hfile = match unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(h) => FileHandle(h),
            Err(_) => return None,
        };

        // 3) Two-stage hash: size probe (pbhash=None) then the actual hash buffer.
        let mut hash_len: u32 = 0;
        // SAFETY: admin.0/hfile.0 valid; pbhash None requests the length into hash_len.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.0, hfile.0, &mut hash_len, None, None)
        }
        .is_err()
            || hash_len == 0
        {
            return None;
        }
        let mut hash = vec![0u8; hash_len as usize];
        // SAFETY: admin.0/hfile.0 valid; hash has hash_len bytes; len is in/out.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.0,
                hfile.0,
                &mut hash_len,
                Some(hash.as_mut_ptr()),
                None,
            )
        }
        .is_err()
        {
            return None;
        }

        // 4) Look the hash up in the system catalog DB. 0 == not in any catalog == unsigned.
        // SAFETY: admin.0 valid; hash is a live slice; other params None.
        let info_raw =
            unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, None, None) };
        if info_raw == 0 {
            return Some(false);
        }
        let _catinfo = CatInfoCtx {
            admin: admin.0,
            info: info_raw,
        };

        // Task 3 replaces this: resolve the .cat path and WinVerifyTrust(WTD_CHOICE_CATALOG).
        // Until then, a hash present in a catalog conservatively returns Some(false).
        Some(false)
    }
```

- [ ] **Step 4: Wire the embedded→catalog fallback into `verify_file`**

In `mod win::verify_file`, the function currently ends with `Some(status == 0)`. Replace that final line so an embedded failure falls back to the catalog:

```rust
        if status == 0 {
            return Some(true); // embedded-signed: fast path, no catalog lookup
        }
        verify_via_catalog(path, &wide)
```

(The `wide` Vec built earlier in `verify_file` is reused — pass it by reference. Confirm `wide` is still in scope at the end of the function; it is, since it lives for the whole body.)

- [ ] **Step 5: Verify it compiles on Windows**

Run: `cargo check --package cairn-collectors-win`
Expected: PASS. (On Linux this code is `cfg(windows)`-gated and excluded; run `cargo check --package cairn-collectors-win` on the Windows dev host.)

- [ ] **Step 6: Run existing signature tests (must still pass — embedded path + missing-file unchanged)**

Run: `cargo test --package cairn-collectors-win --lib signature`
Expected: PASS. `missing_file_is_none`, `unsigned_junk_is_false` (junk PE: embedded fails, catalog enum finds nothing → `Some(false)`), `known_os_binary_does_not_panic`, `win_verifier_delegates` all green.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors-win/src/signature.rs
git commit -m "feat(s2g): catalog lookup scaffolding + RAII guards (no WinVerifyTrust yet)"
```

---

## Task 3: Complete the catalog WinVerifyTrust step

Replace the Task-2 placeholder (`Some(false)` after a hash is found) with the real catalog verification: resolve the `.cat` path, build `WINTRUST_CATALOG_INFO`, and call `WinVerifyTrust(WTD_CHOICE_CATALOG)` with proper provider-state CLOSE.

**Files:**
- Modify: `crates/cairn-collectors-win/src/signature.rs` (the tail of `verify_via_catalog`)

- [ ] **Step 1: Add a hex-encoding helper for the member tag, at the end of `mod win`**

`WinVerifyTrust(CATALOG)` needs the member tag as the uppercase hex string of the file hash:

```rust
    /// Uppercase hex of the file hash, NUL-terminated UTF-16 — the catalog member tag.
    fn hash_to_member_tag(hash: &[u8]) -> Vec<u16> {
        let mut s = String::with_capacity(hash.len() * 2);
        for b in hash {
            use std::fmt::Write as _;
            let _ = write!(s, "{:02X}", b);
        }
        wide_nul(&s)
    }
```

- [ ] **Step 2: Replace the Task-2 placeholder tail of `verify_via_catalog`**

Replace the block from `let _catinfo = CatInfoCtx { ... };` through the trailing `Some(false)` with:

```rust
        let catinfo = CatInfoCtx {
            admin: admin.0,
            info: info_raw,
        };

        // 5) Resolve the .cat file path for this catalog context.
        let mut ci = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        // SAFETY: catinfo.info is the valid catalog context; ci is a live out-param.
        if unsafe { CryptCATCatalogInfoFromContext(catinfo.info, &mut ci, 0) }.is_err() {
            return None;
        }

        // 6) Verify the member against its catalog via WinVerifyTrust(WTD_CHOICE_CATALOG).
        let member_tag = hash_to_member_tag(&hash);
        let mut cat_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: PCWSTR(ci.wszCatalogFile.as_ptr()),
            pcwszMemberTag: PCWSTR(member_tag.as_ptr()),
            pcwszMemberFilePath: PCWSTR(wide.as_ptr()),
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: hash_len,
            hCatAdmin: catinfo.admin,
            ..Default::default()
        };

        let mut wtd = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_CATALOG,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        wtd.Anonymous.pCatalog = &mut cat_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: wtd/cat_info/ci/member_tag/hash/wide all outlive this call; pCatalog points
        // at the live cat_info; its PCWSTR/hash pointers point into still-owned buffers.
        let cat_status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                std::ptr::addr_of_mut!(wtd).cast(),
            )
        };

        // MUST free provider state (CLOSE) regardless of status — same as the embedded path.
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut close_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: same wtd opened by VERIFY; CLOSE frees its provider state.
        unsafe {
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut close_action,
                std::ptr::addr_of_mut!(wtd).cast(),
            );
        }

        Some(cat_status == 0)
```

> Note: `hash` must be mutable (`let mut hash`) because `pbCalculatedFileHash` needs `as_mut_ptr()`. It already is from Task 2 (`let mut hash = vec![...]`). The Task-2 `enum` call borrowed `&hash` immutably and is finished before this mutable borrow, so there is no conflict.

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --package cairn-collectors-win`
Expected: PASS.

> If `wtd.Anonymous.pCatalog` errors as an unknown field, confirm the union field name in `WINTRUST_DATA` (verified: the union has `pFile` and `pCatalog`; the embedded path already uses `wtd.Anonymous.pFile`). If `HWND` is not in scope, it is already imported at the top of `mod win` (the embedded path uses it).

- [ ] **Step 4: Run signature tests**

Run: `cargo test --package cairn-collectors-win --lib signature`
Expected: PASS (same four tests as Task 2; behavior for junk/missing unchanged — junk PE still `Some(false)` because its hash is in no catalog).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors-win/src/signature.rs
git commit -m "feat(s2g): catalog WinVerifyTrust completes the fallback"
```

---

## Task 4: Add the catalog-signed regression test

The exact case S2-G fixes: a catalog-signed OS binary that returned `Some(false)` before now returns `Some(true)`. This is a Windows-only test guarded so Linux CI / unusual images skip gracefully.

**Files:**
- Modify: `crates/cairn-collectors-win/src/signature.rs` (the `#[cfg(all(test, windows))] mod tests` block)

- [ ] **Step 1: Add the test**

Add inside `mod tests` (after `known_os_binary_does_not_panic`):

```rust
    /// The S2-G fix: a catalog-signed OS binary (svchost has NO embedded signature; it is
    /// catalog-signed) must verify as Some(true) via the catalog fallback. Before S2-G this
    /// returned Some(false) (the false-unsigned report). Guarded by exists() so environments
    /// without this exact path skip rather than fail.
    #[test]
    fn catalog_signed_os_binary_is_true() {
        let candidates = [
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\SearchIndexer.exe",
        ];
        for c in candidates {
            if std::path::Path::new(c).exists() {
                assert_eq!(
                    verify_file(c),
                    Some(true),
                    "catalog-signed OS binary {c} must verify true via the catalog fallback"
                );
                return;
            }
        }
        // No candidate present (unusual): nothing to assert, test passes vacuously.
    }
```

- [ ] **Step 2: Run it on the Windows dev host**

Run: `cargo test --package cairn-collectors-win --lib signature::tests::catalog_signed_os_binary_is_true -- --nocapture`
Expected: PASS.

> **If this FAILS with `Some(false)`** the catalog lookup did not match — most likely a hash-algorithm mismatch (legacy SHA-1 catalog). Proceed to Task 5's SHA-1 fallback. **If it fails with `None`**, an infrastructure call failed — print the failing step (temporarily log which `is_err()` branch hit) and fix the FFI before continuing; do NOT add SHA-1 fallback for a `None` (that is a different bug).

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-collectors-win/src/signature.rs
git commit -m "test(s2g): catalog-signed OS binary verifies true (regression)"
```

---

## Task 5: SHA-1 fallback — ONLY if Task 4 returned Some(false)

**Conditional task.** Implement this ONLY if Task 4's test failed with `Some(false)` (a hash-algorithm mismatch), or if the Task 6 live e2e shows known catalog-signed files still reporting `false`. If Task 4 passed with SHA-256, SKIP this task entirely (YAGNI) and note in the commit log that SHA-1 fallback was not needed.

**Files:**
- Modify: `crates/cairn-collectors-win/src/signature.rs` (`verify_via_catalog`)

- [ ] **Step 1: Parameterize the hash algorithm**

Extract the acquire+hash+enum+verify body into `try_catalog_with_algo(path, wide, algo: PCWSTR) -> Option<bool>`, where `algo` is passed to `CryptCATAdminAcquireContext2`. Change the signature of the existing logic so `verify_via_catalog` becomes:

```rust
    fn verify_via_catalog(path: &str, wide: &[u16]) -> Option<bool> {
        // Modern Win10/11 catalogs are SHA-256; legacy ones SHA-1. Try SHA-256 first; only if
        // it yields a definitive "not in any catalog" (Some(false)) do we retry SHA-1, because
        // an old catalog would not match a SHA-256 hash. A None (infra failure) is returned
        // as-is — retrying a broken context would not help.
        match try_catalog_with_algo(path, wide, w!("SHA256")) {
            Some(true) => Some(true),
            None => None,
            Some(false) => try_catalog_with_algo(path, wide, w!("SHA1")),
        }
    }
```

Rename the Task-2/3 body to `try_catalog_with_algo(path: &str, wide: &[u16], algo: PCWSTR) -> Option<bool>` and replace its `w!("SHA256")` argument to `CryptCATAdminAcquireContext2` with the `algo` parameter.

- [ ] **Step 2: Re-run the regression test**

Run: `cargo test --package cairn-collectors-win --lib signature::tests::catalog_signed_os_binary_is_true`
Expected: PASS (now via SHA-256 or SHA-1).

- [ ] **Step 3: Commit**

```bash
git add crates/cairn-collectors-win/src/signature.rs
git commit -m "feat(s2g): SHA-1 catalog fallback for legacy catalogs"
```

---

## Task 6: Acceptance gate + live e2e self-run (the real arbiter)

The unit surface is thin; the live run is the proof. Run the full gate, then a live `cairn run` and confirm the false-unsigned set is fixed.

**Files:** none (verification only; a fix-up commit only if the gate finds something).

- [ ] **Step 1: Full static gate**

Run each; all must be clean:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
```
Expected: fmt clean; clippy no warnings; all tests pass; audit 0 advisories (no new external crate — only feature flags). If `fmt --check` fails, run `cargo fmt` and include in the gate commit.

- [ ] **Step 2: Confirm unsafe isolation**

Run: `grep -rn "unsafe" crates/cairn-collectors/src/ crates/cairn-core/src/ crates/cairn-heur/src/ crates/cairn-report/src/ crates/cairn-sigma/src/ crates/cairn-cli/src/`
Expected: zero matches (all new unsafe is in `cairn-collectors-win` only).

- [ ] **Step 3: Build the release binary and run live (persist + process)**

```bash
cargo build --package cairn-cli --release
"$CARGO_TARGET_DIR/release/cairn.exe" run --target live --only persist,process --output C:/Temp/cairn-s2g-test
```
(`CARGO_TARGET_DIR` is `C:/Users/bosen/AppData/Local/cairn-target` per `.cargo/config.toml`.)
Expected: writes `findings.jsonl`, `records.jsonl`, `manifest.json`, `run.log` with no error.

- [ ] **Step 4: Verify the false-unsigned set is fixed**

Inspect `records.jsonl`: the catalog-signed binaries that were `signed=false` in the S2-F e2e must now be `signed=true`. Quick check (PowerShell or python):

```python
import json
recs = [json.loads(l) for l in open(r"C:/Temp/cairn-s2g-test/records.jsonl", encoding="utf-8") if l.strip()]
def sig(name):
    for r in recs:
        bp = (r.get("binary_path") or "").lower()
        if name in bp:
            print(name, "->", r.get("signed"), bp)
            return
for n in ["svchost.exe", "searchindexer.exe", "securityhealthsystray.exe"]:
    sig(n)
from collections import Counter
print("persistence signed:", Counter(r.get("signed") for r in recs if r.get("kind")=="persistence"))
print("process signed:", Counter(r.get("signed") for r in recs if r.get("record_type")=="process" or r.get("kind")=="process"))
```
Expected: svchost / SearchIndexer / SecurityHealthSystray now `True`; the `False` count drops substantially vs the S2-F baseline; embedded-signed (Docker, Notion) stay `True`; genuinely unsigned / `.lnk` entries unchanged.

> **If a known catalog-signed file is still `False`:** go back to Task 5 (SHA-1 fallback) if not yet done, rebuild, and re-run this step. This is the self-run loop — iterate until the catalog-signed set verifies true, verified by re-run, not assumed.

- [ ] **Step 5: Verify run integrity**

Run: `"$CARGO_TARGET_DIR/release/cairn.exe" verify C:/Temp/cairn-s2g-test/manifest.json`
Expected: `VERIFY OK`, exit 0.

- [ ] **Step 6: Commit any gate fix-ups (only if Step 1 required fmt or a fix)**

```bash
git add -A
git commit -m "chore(s2g): acceptance gate passed"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Catalog fallback after embedded → Tasks 2-3. ✅
- `Win32_Security_Cryptography_Catalog` feature → Task 1 (plus `Win32_Storage_FileSystem` for `CreateFileW`, which the spec's `CreateFileW` reference implies). ✅
- RAII guards (admin, catalog, file) → Task 2 Step 2. ✅
- Embedded-first fast path → Task 2 Step 4. ✅
- `Some(true)`/`Some(false)`/`None` semantics → Tasks 2-3 (infra → None; not-in-catalog → false; verified → true). ✅
- SHA-256 first, SHA-1 only if needed → Task 5 (conditional). ✅
- Read-only `CreateFileW` (golden rule 3) → Task 2 Step 3 SAFETY note. ✅
- unsafe only in `cairn-collectors-win` → Task 6 Step 2. ✅
- Live e2e as arbiter → Task 6. ✅
- Catalog-signed regression test → Task 4. ✅

**Placeholder scan:** Task 2 deliberately ships an interim `Some(false)` that Task 3 replaces — this is a real, compilable, committed intermediate state (not a "TODO"), and Task 3 explicitly replaces the named block. No vague "add error handling" steps; every fallible call has an explicit `is_err()`/`==0` branch shown.

**Type consistency:** `CatAdminCtx(isize)`, `CatInfoCtx{admin,info}`, `FileHandle(HANDLE)`, `verify_via_catalog(path:&str, wide:&[u16])`, `try_catalog_with_algo(path:&str, wide:&[u16], algo:PCWSTR)`, `hash_to_member_tag(&[u8])->Vec<u16>` are used consistently across tasks. `hash` is `let mut` from Task 2 (needed for `as_mut_ptr()` in Task 3). `wide` is borrowed (`&wide`) into `verify_via_catalog` and reused for `pcwszMemberFilePath`. Field names (`pcwszCatalogFilePath`, `pcwszMemberTag`, `pcwszMemberFilePath`, `pbCalculatedFileHash`, `cbCalculatedFileHash`, `hCatAdmin`, `wszCatalogFile`, `cbStruct`) match the verified crate structs.
