# S2-J Signer Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the embedded Authenticode signer's subject CN ("who signed it") and surface it as `signer` on persistence + process records.

**Architecture:** `FileVerifier` gains a `signer()` method with a default `None`; only `WinSigVerifier` overrides it, calling a new `extract_signer` in `cairn-collectors-win` (CryptQueryObject → CryptMsgGetParam → CertFindCertificateInStore → CertGetNameStringW, RAII-released, unsafe isolated). Records gain `signer: Option<String>`; the two `apply_signatures` each add one line. No heuristic change; embedded-only (catalog-signed → None, documented).

**Tech Stack:** Rust; `windows` 0.62.2 `Win32_Security_Cryptography` (already enabled — no new dep/feature). Unsafe only in `cairn-collectors-win`; `cairn-core`/`cairn-collectors`/`cairn-heur` stay `#![forbid(unsafe_code)]`.

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-s2j-signer-identity-design.md`

---

## Verified API reference (windows 0.62.2 — do NOT re-guess)

All under `windows::Win32::Security::Cryptography`, all `pub unsafe fn`. Constants verified present:
```
CERT_QUERY_OBJECT_FILE = CERT_QUERY_OBJECT_TYPE(1)
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = CERT_QUERY_CONTENT_TYPE_FLAGS(1024)
CERT_QUERY_FORMAT_FLAG_BINARY = CERT_QUERY_FORMAT_TYPE_FLAGS(2)
CMSG_SIGNER_CERT_INFO_PARAM = 7u32
X509_ASN_ENCODING = CERT_QUERY_ENCODING_TYPE(1); PKCS_7_ASN_ENCODING = CERT_QUERY_ENCODING_TYPE(65536)
CERT_FIND_SUBJECT_CERT = CERT_FIND_FLAGS(720896)
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4u32

CryptQueryObject(dwObjectType: CERT_QUERY_OBJECT_TYPE, pvObject: *const c_void,
  dwExpectedContentTypeFlags: CERT_QUERY_CONTENT_TYPE_FLAGS,
  dwExpectedFormatTypeFlags: CERT_QUERY_FORMAT_TYPE_FLAGS, dwFlags: u32,
  pdwMsgAndCertEncodingType: Option<*mut CERT_QUERY_ENCODING_TYPE>,
  pdwContentType: Option<*mut CERT_QUERY_CONTENT_TYPE>,
  pdwFormatType: Option<*mut CERT_QUERY_FORMAT_TYPE>,
  phCertStore: Option<*mut HCERTSTORE>, phMsg: Option<*mut *mut c_void>,
  ppvContext: Option<*mut *mut c_void>) -> windows_core::Result<()>
CryptMsgGetParam(hCryptMsg: *const c_void, dwParamType: u32, dwIndex: u32,
  pvData: Option<*mut c_void>, pcbData: *mut u32) -> windows_core::Result<()>
CertFindCertificateInStore(hCertStore: HCERTSTORE, dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
  dwFindFlags: u32, dwFindType: CERT_FIND_FLAGS, pvFindPara: Option<*const c_void>,
  pPrevCertContext: Option<*const CERT_CONTEXT>) -> *mut CERT_CONTEXT   // null = not found
CertGetNameStringW(pCertContext: *const CERT_CONTEXT, dwType: u32, dwFlags: u32,
  pvTypePara: Option<*const c_void>, pszNameString: Option<&mut [u16]>) -> u32  // length incl NUL
CertFreeCertificateContext(Option<*const CERT_CONTEXT>) -> windows_core::BOOL
CryptMsgClose(Option<*const c_void>) -> windows_core::Result<()>
CertCloseStore(Option<HCERTSTORE>, dwFlags: u32) -> windows_core::Result<()>
```
`HCERTSTORE`, `CERT_CONTEXT`, `CERT_INFO` are in the same module. `wide_nul(path)->Vec<u16>` and
the cfg(windows) `mod win` + SAFETY-comment style already exist in `signature.rs`.

---

## File Structure

- **Modify:** `crates/cairn-core/src/record.rs` — add `signer: Option<String>` to `PersistenceRecord` + `ProcessRecord`.
- **Modify:** `crates/cairn-core/src/traits.rs` — add `signer()` default method to `FileVerifier`.
- **Modify:** `crates/cairn-collectors-win/src/signature.rs` — `extract_signer` + RAII guards + `WinSigVerifier::signer` override.
- **Modify:** `crates/cairn-collectors/src/persist.rs` + `crates/cairn-collectors/src/proc.rs` — one line each in `apply_signatures`.

No new files, no new dep, no new feature flag.

---

## Task 1: Add `signer` to the record schema + trait default

**Files:**
- Modify: `crates/cairn-core/src/record.rs`, `crates/cairn-core/src/traits.rs`

- [ ] **Step 1: Write the failing round-trip test**

In `crates/cairn-core/src/record.rs` tests (the module already has record round-trip tests; add):

```rust
    #[test]
    fn persistence_record_signer_roundtrips() {
        let mut r = PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKCU\\...\\Run".into(),
            value: Some("X".into()),
            command: Some("C:\\a.exe".into()),
            binary_path: Some("C:\\a.exe".into()),
            binary_sha256: None,
            signed: Some(true),
            signer: Some("Docker Inc".into()),
            last_write: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""signer":"Docker Inc""#));
        let back: PersistenceRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.signer.as_deref(), Some("Docker Inc"));
        r.signer = None;
        let j2 = serde_json::to_string(&r).unwrap();
        let back2: PersistenceRecord = serde_json::from_str(&j2).unwrap();
        assert_eq!(back2.signer, None);
    }

    #[test]
    fn process_record_signer_roundtrips() {
        let r = ProcessRecord {
            pid: 1, ppid: 0, image: "C:\\a.exe".into(), cmdline: "C:\\a.exe".into(),
            signed: Some(true), signer: Some("Google LLC".into()),
            integrity: None, user: None, start_time: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: ProcessRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.signer.as_deref(), Some("Google LLC"));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-core --lib signer`
Expected: FAIL — `PersistenceRecord`/`ProcessRecord` have no field `signer` (compile error).

- [ ] **Step 3: Add the field to both records**

In `crates/cairn-core/src/record.rs`, `ProcessRecord` — add after `signed`:
```rust
    pub signed: Option<bool>,
    pub signer: Option<String>,
```
`PersistenceRecord` — add after `signed`:
```rust
    pub signed: Option<bool>,
    pub signer: Option<String>,
```
(Place `signer` immediately after `signed` in each struct. The comment on PersistenceRecord's
`mechanism` listing the mechanisms is unrelated — leave it.)

- [ ] **Step 4: Add the trait default method**

In `crates/cairn-core/src/traits.rs`, extend the `FileVerifier` trait + its doc:
```rust
pub trait FileVerifier: Send + Sync {
    fn verify(&self, path: &str) -> Option<bool>;
    /// The embedded Authenticode signer's subject CN (e.g. "Docker Inc"), or None when the
    /// file has no embedded signature (catalog-signed or unsigned), cannot be read, or
    /// off-platform. Default None; only the Windows verifier overrides it. Total — never panics.
    fn signer(&self, _path: &str) -> Option<String> {
        None
    }
}
```

- [ ] **Step 5: Fix all `PersistenceRecord`/`ProcessRecord` literals that now miss `signer`**

Adding a field breaks every struct literal. Compile and fix each construction site to add
`signer: None` (collectors build records; tests build records). Run:
`cargo check --workspace` and add `signer: None` to each reported literal (e.g. in
`cairn-collectors/src/persist.rs` readers, `cairn-collectors/src/proc.rs`, `cairn-heur` test
helpers, any record-building test). Do NOT add signer logic yet — just `None` to compile.

- [ ] **Step 6: Run to verify pass**

Run: `cargo test --package cairn-core --lib signer` then `cargo check --workspace`
Expected: the 2 round-trip tests PASS; the workspace compiles (all literals fixed).

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-core/src/record.rs crates/cairn-core/src/traits.rs
git add -u   # the signer:None literal fixes across crates
git commit -m "feat(s2j): add signer field to records + FileVerifier::signer default"
```

---

## Task 2: `extract_signer` in cairn-collectors-win

**Files:**
- Modify: `crates/cairn-collectors-win/src/signature.rs`

- [ ] **Step 1: Add the non-Windows stub + the Windows entry + the override**

At the top level of `signature.rs` (next to `verify_file`):
```rust
/// The embedded Authenticode signer's subject CN, or None (no embedded sig / unreadable /
/// off-platform). Read-only; never panics.
#[cfg(not(windows))]
pub fn extract_signer(_path: &str) -> Option<String> {
    None
}

#[cfg(windows)]
pub fn extract_signer(path: &str) -> Option<String> {
    win::extract_signer(path)
}
```
Extend the `WinSigVerifier` impl:
```rust
impl FileVerifier for WinSigVerifier {
    fn verify(&self, path: &str) -> Option<bool> {
        verify_file(path)
    }
    fn signer(&self, path: &str) -> Option<String> {
        extract_signer(path)
    }
}
```

- [ ] **Step 2: Add the imports + RAII guards inside `mod win`**

In `mod win`'s use block add:
```rust
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT,
        CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_CERT_INFO_PARAM,
        HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use std::ffi::c_void;
```
(If any name fails to import, it is wrong — inspect the crate source at
`C:/Users/bosen/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/windows-0.62.2/src/Windows/Win32/Security/Cryptography/mod.rs` and correct it; do not guess.)

Add the RAII guards at the end of `mod win`:
```rust
    struct StoreGuard(HCERTSTORE);
    impl Drop for StoreGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the store opened by CryptQueryObject; closed once.
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }
    struct MsgGuard(*mut c_void);
    impl Drop for MsgGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the PKCS#7 msg handle from CryptQueryObject; closed once.
            unsafe {
                let _ = CryptMsgClose(Some(self.0));
            }
        }
    }
    struct CertGuard(*const CERT_CONTEXT);
    impl Drop for CertGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the cert context from CertFindCertificateInStore; freed once.
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
```

- [ ] **Step 3: Add `extract_signer` in `mod win`**

```rust
    pub fn extract_signer(path: &str) -> Option<String> {
        if path.is_empty() || !std::path::Path::new(path).exists() {
            return None;
        }
        let wide = wide_nul(path);

        let mut store: HCERTSTORE = HCERTSTORE::default();
        let mut msg: *mut c_void = std::ptr::null_mut();
        // SAFETY: wide outlives the call; pvObject points at the NUL-terminated wide path;
        // store/msg are valid out-params. Reads the embedded PKCS#7 only; no write.
        let q = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide.as_ptr() as *const c_void,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                None,
                None,
                None,
                Some(&mut store),
                Some(&mut msg),
                None,
            )
        };
        if q.is_err() {
            return None; // no embedded signature (catalog-signed/unsigned) or unreadable
        }
        let _store = StoreGuard(store);
        let _msg = MsgGuard(msg);

        // Two-stage: signer CERT_INFO (issuer + serial) for the find below.
        let mut len: u32 = 0;
        // SAFETY: msg valid; pvData None requests the size into len.
        if unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, None, &mut len) }
            .is_err()
            || len == 0
        {
            return None;
        }
        let mut info = vec![0u8; len as usize];
        // SAFETY: msg valid; info has len bytes; len is in/out.
        if unsafe {
            CryptMsgGetParam(
                msg,
                CMSG_SIGNER_CERT_INFO_PARAM,
                0,
                Some(info.as_mut_ptr() as *mut c_void),
                &mut len,
            )
        }
        .is_err()
        {
            return None;
        }

        // Find the signer's certificate in the store by its CERT_INFO.
        // SAFETY: store valid; info holds a CERT_INFO for the duration of this call.
        let cert = unsafe {
            CertFindCertificateInStore(
                store,
                CERT_QUERY_ENCODING(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(info.as_ptr() as *const c_void),
                None,
            )
        };
        if cert.is_null() {
            return None;
        }
        let _cert = CertGuard(cert);

        // Two-stage: subject CN length, then the string.
        // SAFETY: cert valid; None buffer returns the needed length (incl NUL).
        let n = unsafe {
            CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None)
        };
        if n <= 1 {
            return None; // 1 = just the NUL (empty name)
        }
        let mut name = vec![0u16; n as usize];
        // SAFETY: cert valid; name has n u16 slots.
        let written = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name),
            )
        };
        if written <= 1 {
            return None;
        }
        // Trim the trailing NUL and decode.
        let s = String::from_utf16_lossy(&name[..(written as usize - 1)]);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
```

> **API-shape caution:** `CERT_QUERY_ENCODING` is the newtype wrapping the encoding flags — if
> the constructor / OR-ing differs in 0.62.2, inspect the crate source and adjust (the encoding
> arg type is `CERT_QUERY_ENCODING_TYPE`; `X509_ASN_ENCODING`/`PKCS_7_ASN_ENCODING` are that
> type, so `CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0)` is the form —
> use the exact type name the crate exports). If `CryptMsgGetParam`/`CertGetNameStringW` buffer
> conventions differ, match the real signatures. Do NOT invent shapes — verify against source.

- [ ] **Step 4: Compile**

Run: `cargo check --package cairn-collectors-win`
Expected: PASS. Fix any import/type mismatch by checking the crate source (report what you changed).

- [ ] **Step 5: Add smoke tests**

In the `#[cfg(all(test, windows))] mod tests` block of signature.rs:
```rust
    #[test]
    fn extract_signer_missing_is_none() {
        assert_eq!(extract_signer(r"C:\does\not\exist\nope.exe"), None);
    }

    #[test]
    fn extract_signer_unsigned_junk_is_none() {
        let p = std::env::temp_dir().join(format!("cairn_s2j_{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ junk, no PKCS7").unwrap();
        let got = extract_signer(&p.to_string_lossy());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, None, "unsigned junk has no embedded signer");
    }

    #[test]
    fn extract_signer_catalog_signed_os_binary_is_none() {
        // notepad/svchost are catalog-signed (no embedded PKCS#7) -> embedded signer is None.
        // Locks the documented embedded-only limitation.
        for c in [r"C:\Windows\System32\notepad.exe", r"C:\Windows\notepad.exe"] {
            if std::path::Path::new(c).exists() {
                assert_eq!(extract_signer(c), None, "catalog-signed -> embedded signer None");
                return;
            }
        }
    }

    #[test]
    fn win_verifier_signer_delegates() {
        assert_eq!(WinSigVerifier.signer(r"C:\does\not\exist\nope.exe"), None);
    }
```

- [ ] **Step 6: Run smoke tests + clippy + fmt**

Run: `cargo test --package cairn-collectors-win --lib signature`
Expected: PASS (missing/junk/catalog→None; existing verify tests unaffected).
Run: `cargo clippy --package cairn-collectors-win --all-targets -- -D warnings` and `cargo fmt`.

> If `extract_signer_catalog_signed_os_binary_is_none` FAILS (returns Some), notepad on this
> build is embedded-signed — switch the assertion target to `svchost.exe` (reliably
> catalog-signed) or treat a Some as acceptable and assert non-empty instead; report the finding.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors-win/src/signature.rs
git commit -m "feat(s2j): extract_signer (embedded Authenticode subject CN) + WinSigVerifier override"
```

---

## Task 3: Wire signer into both collectors + acceptance gate + live e2e

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`, `crates/cairn-collectors/src/proc.rs`

- [ ] **Step 1: Write the failing wiring tests**

The FakeVerifiers in both test modules implement `verify`; they inherit `signer()=None` by
default. Add a signer mapping to each fake and a wiring test.

In `crates/cairn-collectors/src/persist.rs` tests — extend `FakeVerifier` and add a test:
```rust
    // in the existing FakeVerifier impl block, add:
        fn signer(&self, path: &str) -> Option<String> {
            if path.eq_ignore_ascii_case(r"C:\Users\a\AppData\Local\Programs\App\app.exe") {
                Some("App Vendor".into())
            } else {
                None
            }
        }
```
```rust
    #[test]
    fn apply_signatures_fills_signer() {
        let mut recs = vec![PersistenceRecord {
            mechanism: "run_key".into(),
            location: "HKCU\\...\\Run".into(),
            value: Some("X".into()),
            command: Some(r"C:\Users\a\AppData\Local\Programs\App\app.exe".into()),
            binary_path: Some(r"C:\Users\a\AppData\Local\Programs\App\app.exe".into()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
        }];
        apply_signatures(&mut recs, &FakeVerifier::default());
        assert_eq!(recs[0].signer.as_deref(), Some("App Vendor"));
    }
```
(Match `FakeVerifier`'s existing constructor — if it isn't `Default`, build it the way the
existing signed-wiring test does.)

In `crates/cairn-collectors/src/proc.rs` tests — extend its `FakeVerifier` similarly with a
`signer` override mapping an absolute image path → Some("Proc Vendor"), and a test asserting
`apply_signatures` fills `signer` for an absolute image and leaves None for a file-name-only image.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-collectors --lib apply_signatures_fills_signer`
Expected: FAIL — `apply_signatures` does not set `signer` yet (stays None).

- [ ] **Step 3: Wire signer into both `apply_signatures`**

`crates/cairn-collectors/src/persist.rs`:
```rust
fn apply_signatures(records: &mut [PersistenceRecord], verifier: &dyn FileVerifier) {
    for r in records.iter_mut() {
        if let Some(p) = r.binary_path.as_deref() {
            r.signed = verifier.verify(p);
            r.signer = verifier.signer(p);
        }
    }
}
```
`crates/cairn-collectors/src/proc.rs` (keep the absolute-path guard for signer too):
```rust
fn apply_signatures(records: &mut [ProcessRecord], verifier: &dyn FileVerifier) {
    for r in records.iter_mut() {
        if is_absolute_path(&r.image) {
            r.signed = verifier.verify(&r.image);
            r.signer = verifier.signer(&r.image);
        }
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-collectors --lib`
Expected: PASS — the two wiring tests + all existing collector tests.

- [ ] **Step 5: Full static gate**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
grep -rn "unsafe" crates/cairn-collectors/src/ crates/cairn-core/src/ crates/cairn-heur/src/   # expect none
```
Expected: fmt clean; clippy clean; all tests pass; audit 0 (no new dep); zero unsafe outside cairn-collectors-win. `cargo fmt` if --check fails, fold into the gate commit.

- [ ] **Step 6: Build release + live e2e**

```bash
cargo build --package cairn-cli --release
"$CARGO_TARGET_DIR/release/cairn.exe" run --target live --only persist,process --output C:/Temp/cairn-s2j-test
```
(`CARGO_TARGET_DIR` = `C:/Users/bosen/AppData/Local/cairn-target`.)

- [ ] **Step 7: Verify signer populated for third-party, None for catalog-signed**

```python
import json
from collections import Counter
recs=[json.loads(l) for l in open(r"C:/Temp/cairn-s2j-test/records.jsonl",encoding="utf-8") if l.strip()]
sig=[(r.get("binary_path") or r.get("image"), r.get("signed"), r.get("signer")) for r in recs]
withsigner=[s for s in sig if s[2]]
print("records with a signer:", len(withsigner))
for bp,sd,sr in withsigner[:15]:
    print(f"  {sr!r:30} signed={sd}  {(bp or '')[:55]}")
# catalog-signed system binaries should be signed=true, signer=None
for name in ["svchost.exe","searchindexer.exe"]:
    for bp,sd,sr in sig:
        if bp and name in bp.lower():
            print(f"  [{name}] signed={sd} signer={sr} (expect signed=True, signer=None)")
            break
```
Expected: third-party embedded-signed binaries (Docker/Notion/Chrome/cairn.exe if signed) show a
signer CN; catalog-signed system binaries show `signed=true, signer=None` (the documented limit).
`signed` values unchanged vs the S2-I baseline.

> **If a known embedded-signed third-party app shows signer=None:** the cert chain failed for it
> — log which step (temporarily) and verify against the real CryptMsgGetParam/CertGetNameString
> conventions; do NOT loosen to guessing. **If a catalog-signed binary shows a signer:** that
> would be unexpected (embedded-only) — investigate before claiming done.

- [ ] **Step 8: Verify run integrity**

Run: `"$CARGO_TARGET_DIR/release/cairn.exe" verify C:/Temp/cairn-s2j-test/manifest.json`
Expected: `VERIFY OK`, exit 0.

- [ ] **Step 9: Commit wiring + any gate fix-ups**

```bash
git add crates/cairn-collectors/src/persist.rs crates/cairn-collectors/src/proc.rs
git commit -m "feat(s2j): fill record.signer in persist + proc apply_signatures"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- `signer` field on both records → Task 1. ✅
- `FileVerifier::signer` default None → Task 1. ✅
- `extract_signer` cert chain + RAII (store/msg/cert) + WinSigVerifier override → Task 2. ✅
- embedded-only limit (catalog-signed → None) asserted → Task 2 Step 5 + e2e Step 7. ✅
- Both `apply_signatures` fill signer (persist any-binary_path; proc absolute-path guard) → Task 3. ✅
- No heuristic change, no new dep/feature → respected. ✅
- Acceptance gate, unsafe isolation, e2e (third-party populated / catalog None), verify → Task 3. ✅

**Placeholder scan:** no TBD/TODO; every code step is complete; the cert-chain API-shape risk and
the catalog/third-party e2e branches have concrete instructions, not vague "handle it".

**Type consistency:** `extract_signer(&str) -> Option<String>`, `FileVerifier::signer(&str) ->
Option<String>`, `signer: Option<String>` on both records, the three guards
(`StoreGuard`/`MsgGuard`/`CertGuard`), and the two-stage buffer idiom are consistent across
tasks. The `signer: None` literal fixes in Task 1 Step 5 keep every record construction
compiling before signer logic lands. `apply_signatures` signer line mirrors the existing signed
line in both collectors.
