# S2-J: signer identity extraction (embedded Authenticode subject CN) — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-14.
> Authoritative spec: `cairn-SRS.md` (§4 verify, §5 PersistenceRecord/ProcessRecord, §7 FR7
> "signer", §17 D6).
> Predecessors: S2-D (WinVerifyTrust verify_file + FileVerifier seam), S2-E (proc signed),
> S2-G (catalog-signed → accurate `signed`), S2-H (calibration), S2-I (scheduled tasks).
> Realizes the "signer identity" future hook S2-G/S2-H deferred (SRS §17 D6).

## Why this, not WMI (re-scope note)

S2-J was going to be WMI event-subscription persistence. Brainstorm feasibility verification
found: the CIM repository (`%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`, ~28 MB binary)
is non-admin-readable, BUT there is no Rust crate that parses it; the only correct route is the
`wmi` crate, a COM client whose internals are unsafe FFI. That would make the persist collector
depend on COM for the first time, breaking the no-unsafe path held since S2-C. Hand-parsing the
binary (no crate, fragile, cross-version drift) or string-scanning it (cannot reliably tell a
class definition from an instance, cannot correlate filter→consumer bindings) are not sound for
a forensic tool. WMI is therefore deferred to the raw-NTFS stage (which already accepts low-level
FFI). S2-J instead realizes **signer identity** — high-value, no new unsafe surface, and it
completes the signature mainline (S2-D→I) by turning `signed` from a bool into "who signed it".

## Purpose

`signed` answers "is this trusted?" (S2-D/E/G). It does not answer "WHO signed it?". A third-party
binary persisting at logon is more or less interesting depending on whether it is signed by
"Docker Inc", "Google LLC", or an unknown publisher. S2-J extracts the embedded Authenticode
signer's subject common name (CN) and surfaces it on each record, so an analyst sees the signer
and a future heuristic pass can apply publisher-aware trust.

## Scope

**In scope:**
- `extract_signer(path) -> Option<String>` in `cairn-collectors-win/src/signature.rs`: the
  embedded-Authenticode signer's subject CN, via the documented `CryptQueryObject` →
  `CryptMsgGetParam` → `CertFindCertificateInStore` → `CertGetNameStringW` chain. Read-only,
  unsafe isolated to this crate, RAII release of every handle.
- `FileVerifier::signer(&self, path) -> Option<String>` with a **default impl returning None**;
  only `WinSigVerifier` overrides it. Existing `verify` and all other impls are untouched.
- `signer: Option<String>` added to `PersistenceRecord` and `ProcessRecord`.
- The two `apply_signatures` (persist + proc) each gain one line filling `r.signer`.
- Output surfaces `signer` (it rides the existing serde serialization of the records; findings
  already render record context).

**Explicitly OUT of scope (deferred, with rationale):**
- **catalog-signed signer.** `CryptQueryObject(CERT_QUERY_OBJECT_FILE)` reads only the EMBEDDED
  PKCS#7. Catalog-signed files (most OS binaries — svchost etc., which S2-G verifies via the
  catalog) have no embedded signature, so `extract_signer` returns None for them. `signed=true,
  signer=None` is a LEGITIMATE state (catalog-signed), not a bug. Extracting the catalog signer
  needs the catalog context path (more complex, more FFI) — a future enhancement. On a clean
  host, `signer` is therefore populated mainly for third-party embedded-signed apps (Docker,
  Notion, Chrome), which is precisely the set an analyst wants — system binaries are known-Microsoft.
- **No heuristic change.** signer is extracted and surfaced only. Using it to tighten the S2-H
  AppData gate (close residual #9 — a valid-cert payload in Local\Programs) is a separate
  decision needing its own attacker evaluation and a careful known-publisher allowlist; deferred.
- **No signer chain / issuer / thumbprint.** Just the leaf subject CN (`signed` stays the trust
  verdict; CN is the identity). Issuer and full chain are future work if needed.
- **No new dependency, no new feature flag.** All APIs are in the already-enabled
  `Win32_Security_Cryptography` (S2-D/G use it).

## API chain (verified against windows 0.62.2 crate source)

All under `windows::Win32::Security::Cryptography`, all `pub unsafe fn`. Confirmed present
(signatures + constants read from crate source, not guessed):

```text
CryptQueryObject(
  dwObjectType: CERT_QUERY_OBJECT_TYPE,           // CERT_QUERY_OBJECT_FILE = 1
  pvObject: *const c_void,                         // *const u16 wide path
  dwExpectedContentTypeFlags: CERT_QUERY_CONTENT_TYPE_FLAGS, // PKCS7_SIGNED_EMBED = 1024
  dwExpectedFormatTypeFlags: CERT_QUERY_FORMAT_TYPE_FLAGS,   // FORMAT_FLAG_BINARY = 2
  dwFlags: u32,                                     // 0
  pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType: Option<*mut ...>, // None
  phCertStore: Option<*mut HCERTSTORE>,            // out: cert store
  phMsg: Option<*mut *mut c_void>,                 // out: PKCS#7 msg handle
  ppvContext: Option<*mut *mut c_void>,            // None
) -> Result<()>

CryptMsgGetParam(hCryptMsg, dwParamType: u32 /* CMSG_SIGNER_CERT_INFO_PARAM = 7 */,
  dwIndex: 0, pvData: Option<*mut c_void>, pcbData: *mut u32) -> Result<()>
  // two-stage: None to get size, then a buffer holding a CERT_INFO (issuer + serial).

CertFindCertificateInStore(hCertStore, dwCertEncodingType: CERT_QUERY_ENCODING_TYPE
    /* X509_ASN_ENCODING | PKCS_7_ASN_ENCODING = 1 | 65536 */,
  dwFindFlags: 0, dwFindType: CERT_FIND_FLAGS /* CERT_FIND_SUBJECT_CERT = 720896 */,
  pvFindPara: Option<*const c_void> /* the CERT_INFO from above */,
  pPrevCertContext: None) -> *mut CERT_CONTEXT   // null = not found

CertGetNameStringW(pCertContext, dwType: u32 /* CERT_NAME_SIMPLE_DISPLAY_TYPE = 4 */,
  dwFlags: 0, pvTypePara: None, pszNameString: Option<&mut [u16]>) -> u32
  // two-stage: call with None/0 to get length, then with a Vec<u16> buffer; returns the
  // subject CN (e.g. "Microsoft Windows", "Docker Inc"). Length includes the NUL.

// release: CertFreeCertificateContext(cert), CryptMsgClose(msg), CertCloseStore(store, 0)
```

## Architecture (data flow)

```
cairn-collectors-win/src/signature.rs  (#![allow(unsafe_code)] crate; cfg(windows) mod win)
  extract_signer(path) -> Option<String>:
    empty/!exists -> None
    wide = NUL-terminated UTF-16 (reuse wide_nul)
    CryptQueryObject(FILE, wide, PKCS7_SIGNED_EMBED, BINARY, ... &store, &msg)
       Err -> None                              [no embedded sig / unreadable]
       Ok  -> StoreGuard(store), MsgGuard(msg)  [RAII: close on drop]
    CryptMsgGetParam(msg, SIGNER_CERT_INFO, 0, None, &len)  -> size probe; Err/0 -> None
    buf = vec![0u8; len]; CryptMsgGetParam(..., Some(buf), &len) -> Err -> None
    cert = CertFindCertificateInStore(store, ENCODING, 0, SUBJECT_CERT, buf.as_ptr(), None)
       null -> None ; else CertGuard(cert)       [RAII: free on drop]
    len2 = CertGetNameStringW(cert, SIMPLE_DISPLAY, 0, None, None)  -> if <=1 -> None
    name = vec![0u16; len2]; CertGetNameStringW(cert, ..., Some(name)) -> trim NUL -> Some(cn)

  WinSigVerifier impl FileVerifier {
    fn verify(&self, p) -> Option<bool> { verify_file(p) }      // unchanged (S2-D/G)
    fn signer(&self, p) -> Option<String> { extract_signer(p) } // NEW override
  }

cairn-core/src/traits.rs
  trait FileVerifier {
    fn verify(&self, path: &str) -> Option<bool>;
    fn signer(&self, _path: &str) -> Option<String> { None }   // NEW default
  }

cairn-core/src/record.rs
  PersistenceRecord { ..., signer: Option<String> }   // NEW (after `signed`)
  ProcessRecord     { ..., signer: Option<String> }   // NEW (after `signed`)

cairn-collectors/src/persist.rs + proc.rs  (#![forbid(unsafe_code)])
  apply_signatures: for each record with a path:
    r.signed = verifier.verify(path);
    r.signer = verifier.signer(path);   // NEW one line
  NoopVerifier + the two FakeVerifiers inherit the default signer()=None (off-Windows, tests).
```

**RAII guards** (mirror the S2-G CryptCATAdmin guards): `StoreGuard(HCERTSTORE)` →
`CertCloseStore`; `MsgGuard(*mut c_void)` → `CryptMsgClose`; `CertGuard(*const CERT_CONTEXT)` →
`CertFreeCertificateContext`. Declared so drop order is safe (cert before store/msg). SAFETY note
on every unsafe block (the file's existing style).

**Two-stage buffers** for `CryptMsgGetParam` and `CertGetNameStringW` (size probe → alloc →
fill), the same idiom as S2-E QueryFullProcessImageNameW and S2-G CalcHashFromFileHandle2.

**Layering / unsafe:** all new unsafe is in `cairn-collectors-win`; `cairn-collectors`,
`cairn-core`, `cairn-heur` stay `#![forbid(unsafe_code)]`. The collectors touch signer only
through the `FileVerifier` trait.

## schema impact

`signer: Option<String>` is an append-only optional field. Record Option fields serialize to
`null` when None (the record structs have no `skip_serializing_if` — `signed`/`binary_sha256`
already serialize as null; this matches). Existing record round-trip tests accept the extra
field. `cairn verify` re-hashes output bytes; the new field changes record JSON content but the
manifest hashes are computed over the actual bytes written, so verify stays consistent.

## Security note (golden rules)

- Read-only: `CryptQueryObject(CERT_QUERY_OBJECT_FILE)` opens the file to read its embedded
  certificate; no write/execute/modify. `CertGetNameStringW` reads an in-memory cert. The same
  calls sigcheck / the file-properties "Digital Signatures" tab make. No evasion (golden rule 1),
  no host modification (golden rule 3).
- No outbound network: this reads the embedded cert only; it performs no chain-building fetch or
  revocation check (consistent with verify_file's WTD_REVOKE_NONE).
- Total / no panic: every FFI failure → None; all handles RAII-released on every path.

## Error handling / graceful degrade

- No embedded signature (catalog-signed, or unsigned) → CryptQueryObject Err → None. Legitimate.
- Any step failing (msg param, find cert, name string) → None; never panics.
- A file-name-only path (proc fallback when OpenProcess failed) — `apply_signatures` already
  only verifies absolute paths for `signed`; `signer` follows the same guard (no signer for a
  bare name). Consistent with S2-E.
- Determinism (NFR4): signer is a pure function of the file's embedded cert at run time; output
  ordering unaffected.

## Testing

Unsafe FFI surface → thin Windows smoke; the trait/default/wiring → pure unit tests.

- **trait default (pure, any platform):** a verifier that doesn't override `signer` returns None;
  `NoopVerifier.signer(...)` is None.
- **FakeVerifier signer wiring (pure):** extend the persist + proc FakeVerifiers to also map a
  path→signer; assert `apply_signatures` fills `record.signer` from it, and leaves None for a
  path the fake doesn't know / a None-path record. (Mirror the existing signed wiring tests.)
- **schema round-trip (cairn-core):** a PersistenceRecord / ProcessRecord with `signer=Some("X")`
  and with `signer=None` round-trips through JSON losslessly.
- **extract_signer smoke (Windows, #[cfg(all(test, windows))]):**
  - missing file → None; unsigned junk → None (no embedded PKCS#7).
  - a known embedded-signed binary, if locatable, → Some(non-empty CN), does not panic. Use a
    likely-embedded-signed third-party exe if present (e.g. the running cairn.exe once signed, or
    a common app); guard with exists() so CI/other hosts skip. A catalog-signed OS binary
    (notepad/svchost) is expected to return None (embedded-only) — assert None there to lock the
    documented limitation.
  - WinSigVerifier.signer delegates.
- **e2e (manual-then-self-run, Windows):** `cairn run --target live --only persist,process`;
  records carry `signer` for third-party embedded-signed binaries (Docker/Notion/Chrome if
  present) and None for catalog-signed system binaries; no panic; `signed` values unchanged
  vs S2-I; `cairn verify` passes. Record the populated-signer count and confirm the
  catalog-signed→None behavior on a couple of system binaries.

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new dep).
- `unsafe` appears in no crate except `cairn-collectors-win`; collectors/core/heur stay
  `#![forbid(unsafe_code)]`.
- A real live run populates `signer` for embedded-signed third-party binaries and returns None
  for catalog-signed system binaries (the documented limit); `signed` unchanged; `cairn verify`
  passes; earlier stages unchanged.
- No golden-rule violation (read-only cert read, no evasion, no network); no scope creep
  (no catalog signer, no heuristic change, no issuer/chain, no new dep).
- Linux CI: the trait default + wiring + round-trip tests run on ubuntu; the Windows-only
  extract_signer is `#[cfg(windows)]` with the default/None path off-Windows; Windows-only
  helpers unused on Linux carry `#[allow(dead_code)]` (the S2-C..I lesson).

## Non-goals / future hooks

- **Catalog-signed signer** (walk the catalog context to name the signer of svchost et al.) —
  would lift signer coverage to system binaries; its own future sub-segment.
- **Publisher-aware heuristic trust** — use `signer` (e.g. a known-publisher allowlist) to
  tighten the S2-H AppData gate / close residual #9; a separate calibration sub-segment with
  its own attacker evaluation.
- **Issuer / full chain / thumbprint** if richer signer provenance is ever needed.
- **WMI event subscriptions** — deferred to the raw-NTFS stage (accepts low-level FFI), per the
  re-scope note above.
- Remaining: FR14 binary hashing, raw-NTFS, offline artifacts, FR15/FR18 output packaging.
