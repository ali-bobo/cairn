# S2-G: catalog-signed verification (false-unsigned resolution) — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-14.
> Authoritative spec: `cairn-SRS.md` (§4 verify, §5 PersistenceRecord/ProcessRecord.signed,
> §10 heuristics, NFR3 unsafe-isolation, §17 D6 problem B).
> Predecessors: S2-D (WinVerifyTrust `verify_file` + FileVerifier seam), S2-E (proc signed +
> unsigned-amplifier conversion), S2-F (binary_path candidate normalization).
> Second of the D6/D7 trilogy: S2-F (problem A, done) → **S2-G (this, problem B)** → S2-H
> (heuristic calibration, problem C).

## Purpose

`verify_file` today uses `WinVerifyTrust` with `WTD_CHOICE_FILE`, which checks ONLY a PE's
*embedded* Authenticode signature. Most Windows OS binaries are **catalog-signed**: they carry
no embedded signature; instead their hash is recorded in a system catalog (`.cat` under
`%SystemRoot%\System32\CatRoot`). `WTD_CHOICE_FILE` therefore reports every catalog-signed
binary as untrusted → `Some(false)`. The S2-F live e2e confirmed this directly: `svchost.exe`,
`SearchIndexer.exe`, `SecurityHealthSystray.exe`, and inbox drivers all came back
`signed = false` despite being legitimately Microsoft-signed.

This false-unsigned report is the reason the entire heuristic layer currently gates its
unsigned signals behind amplifiers ("catalog-signed OS binaries are reported unsigned by
WTD_CHOICE_FILE, so an unconditional unsigned signal would flood"). S2-G fixes the ROOT cause:
when the embedded check fails, also consult the system catalog. A catalog-signed binary then
reports `Some(true)`, eliminating the false-unsigned reports at the source.

## Scope

**In scope:**
- Extend `verify_file` (in `cairn-collectors-win/src/signature.rs`) with a catalog fallback:
  embedded check first (unchanged); on embedded failure, hash the file and look it up in the
  system catalog via `CryptCATAdmin*` + `WinVerifyTrust(WTD_CHOICE_CATALOG)`.
- Add the `Win32_Security_Cryptography_Catalog` feature to `cairn-collectors-win/Cargo.toml`
  (verified: this single feature gates the `Catalog` mod; `Sip` is NOT required).
- RAII guards for the three catalog-chain resources (admin context, catalog context, file
  handle) so no early-return leaks.

**Explicitly OUT of scope (deferred, with rationale):**
- **Signer identity extraction** (who signed it — "Microsoft Windows" vs "Docker Inc"). The
  `signed` schema stays `Option<bool>`. Distinguishing signers is a richer change whose value
  is only realized in S2-H heuristic calibration; deferred there (SRS §17 D6/D7).
- **Heuristic re-tuning.** The amplifier gating stays as-is. With catalog-signed binaries now
  reporting `Some(true)`, the existing amplifiers simply stop firing on them — behavior
  improves automatically with NO heuristic code change. Re-tuning weights belongs to S2-H.
- **Revocation / chain-to-root policy.** We keep `WTD_REVOKE_NONE` (matching the embedded
  path today): triage answers "is this signed and trusted by the local policy", not "perform
  a full online revocation check". Consistent with the existing embedded behavior.
- **proc / persist collector code, the FileVerifier trait, schema.** All unchanged — the seam
  returns `Option<bool>` exactly as before.

## The catalog model (verified API shapes, windows 0.62.2)

Confirmed against crate source `windows-0.62.2/.../Security/Cryptography/Catalog/mod.rs` and
`.../Security/WinTrust/mod.rs` — NOT guessed. `WTGetSignatureInfo` was checked and is ABSENT
from this crate version (zero hits), so the high-level path is not available; the documented
`CryptCATAdmin*` chain is used instead (the same approach sigcheck / Process Explorer use).

```text
feature:  Win32_Security_Cryptography_Catalog   (new; the only one needed)
          Win32_Security_WinTrust               (already enabled)

CryptCATAdminAcquireContext2(phcatadmin: *mut isize, pgsubsystem: Option<*const GUID>,
    pwszhashalgorithm: P (PCWSTR), pstronghashpolicy: Option<*const CERT_STRONG_SIGN_PARA>,
    dwflags: Option<u32>) -> Result<()>
CryptCATAdminCalcHashFromFileHandle2(hcatadmin: isize, hfile: HANDLE, pcbhash: *mut u32,
    pbhash: Option<*mut u8>, dwflags: Option<u32>) -> Result<()>
CryptCATAdminEnumCatalogFromHash(hcatadmin: isize, pbhash: &[u8], dwflags: Option<u32>,
    phprevcatinfo: Option<*mut isize>) -> isize          // 0 == not found in any catalog
CryptCATCatalogInfoFromContext(hcatinfo: isize, pscatinfo: *mut CATALOG_INFO,
    dwflags: u32) -> Result<()>
CryptCATAdminReleaseCatalogContext(hcatadmin: isize, hcatinfo: isize, dwflags: u32) -> BOOL
CryptCATAdminReleaseContext(hcatadmin: isize, dwflags: u32) -> BOOL

CATALOG_INFO { cbStruct: u32, wszCatalogFile: [u16; 260] }
WINTRUST_CATALOG_INFO { cbStruct, dwCatalogVersion, pcwszCatalogFilePath, pcwszMemberTag,
    pcwszMemberFilePath, hMemberFile, pbCalculatedFileHash, cbCalculatedFileHash,
    pcCatalogContext, hCatAdmin }   (verified present in WinTrust mod)
WTD_CHOICE_CATALOG = WINTRUST_DATA_UNION_CHOICE(2)   (verified)
BCRYPT_SHA256_ALGORITHM = w!("SHA256")               (verified; or pass the literal w!("SHA256"))
```

## Architecture (data flow)

The ONLY code change is `crates/cairn-collectors-win/src/signature.rs`. The `FileVerifier`
trait, `WinSigVerifier`, all collectors, and all heuristics are untouched (return type stays
`Option<bool>`; the seam is clean).

```
verify_file(path) -> Option<bool>:
  if path empty or !exists -> None                       (unchanged)
  status = embedded check (existing WTD_CHOICE_FILE block, verbatim)
  if status == 0 -> Some(true)                           (embedded-signed: fast path, no catalog)
  else -> verify_via_catalog(path)                       (new)

verify_via_catalog(path) -> Option<bool>:
  admin = CryptCATAdminAcquireContext2(SHA256)           Err -> None  (infra failure, not "unsigned")
       [RAII: CryptCATAdminReleaseContext on drop]
  hfile = CreateFileW(path, GENERIC_READ, SHARE_READ, OPEN_EXISTING)  Err -> None
       [RAII: CloseHandle on drop]
  len = 0; CalcHashFromFileHandle2(admin, hfile, &mut len, None)      Err -> None  (size probe)
  hash = vec![0u8; len]; CalcHashFromFileHandle2(admin, hfile, &mut len, Some(hash))  Err -> None
  catinfo = EnumCatalogFromHash(admin, &hash)
  if catinfo == 0 -> Some(false)                         (hash in NO catalog: genuinely unsigned)
       [RAII: CryptCATAdminReleaseCatalogContext(admin, catinfo) on drop]
  ci = CATALOG_INFO::default(); ci.cbStruct = size_of
  CryptCATCatalogInfoFromContext(catinfo, &mut ci)       Err -> None
  status2 = WinVerifyTrust(WTD_CHOICE_CATALOG, WINTRUST_CATALOG_INFO{
              pcwszCatalogFilePath = ci.wszCatalogFile,
              pcwszMemberTag       = <hash as hex wide string>,
              pcwszMemberFilePath  = path (wide),
              pbCalculatedFileHash = hash, cbCalculatedFileHash = len,
              hCatAdmin            = admin })
            then STATEACTION_CLOSE (free provider state), as the embedded path does
  Some(status2 == 0)
```

**Return semantics (decided):**
- `Some(true)`  — embedded OR catalog signature present and trusted.
- `Some(false)` — embedded failed AND the file hash is in no catalog (genuinely unsigned),
  OR found in a catalog but `WinVerifyTrust(CATALOG)` rejected it.
- `None`        — file missing / unconvertible / off-platform (unchanged), OR a catalog
  *infrastructure* failure (cannot acquire context, cannot open file, hash calc failed). A
  broken verifier must NOT masquerade as "file unsigned" — keeps `None` honest and avoids
  polluting heuristics.

**Embedded-first rationale:** embedded-signed binaries (Docker, Notion, most third-party) take
the existing fast path and never touch the catalog — zero behavior change, zero added cost.
Only embedded-failures (catalog-signed OS components) pay the catalog lookup, which is exactly
the set we are fixing.

## unsafe FFI structure / RAII

All new unsafe lives in `cairn-collectors-win` (the single `#![allow(unsafe_code)]` crate);
every other crate stays `#![forbid(unsafe_code)]`. The catalog logic is isolated in a new
`verify_via_catalog` fn so the embedded path stays verbatim and the catalog chain is readable.

RAII guards (mirror the existing `Snapshot` / handle-guard pattern in proc.rs / host.rs):
- `CatAdminCtx(isize)` — `CryptCATAdminReleaseContext(self.0, 0)` on drop.
- `CatInfoCtx { admin: isize, info: isize }` — `CryptCATAdminReleaseCatalogContext(admin,
  info, 0)` on drop. Declared AFTER the admin guard so Rust's reverse-declaration drop order
  releases the catalog context first, then the admin context (release-catalog needs the admin
  handle still valid).
- File handle — `CloseHandle` on drop (reuse the proc.rs guard pattern; a tiny local guard
  is fine if not shared).

Two-stage hash buffer: `CalcHashFromFileHandle2` is called with `pbhash=None` to get the
length, then with an allocated `Vec<u8>` — same idiom as `QueryFullProcessImageNameW` in
proc.rs.

SAFETY notes go on each unsafe block (AcquireContext2, CreateFileW, CalcHash×2,
EnumCatalogFromHash, CatalogInfoFromContext, WinVerifyTrust, the Release/Close calls in Drop),
stating the handle/pointer-lifetime invariant, as the existing signature.rs does.

## Security note (golden rule 1 & 3)

- Read-only: the catalog path opens the target with `GENERIC_READ` only, to compute its hash;
  no file is written, executed, or modified. Catalog lookup reads the system catalog DB. This
  is the standard, documented signature-verification path — not signing, hooking, or
  trust-provider patching. No evasion.
- `WTD_REVOKE_NONE` matches the existing embedded behavior (local-policy trust, not an online
  revocation/CRL fetch); no outbound network is initiated by S2-G.
- A crafted path cannot cause traversal or unexpected access: we only open and hash the literal
  path the collector already resolved (S2-F), then look that hash up; we never follow, write,
  or execute it.

## Error handling / graceful degrade

- `verify_via_catalog` is total: every fallible API maps Err/0-handle to `None` (infra) or
  `Some(false)` (definitively not in catalog) per the semantics above; it never panics.
- Every resource is released on every path via Drop (including early `None` returns).
- The embedded path is unchanged, so embedded-signed and missing-file behavior is identical
  to S2-D/S2-F.
- Determinism (NFR4): verification is a pure function of the file + system catalog state at
  run time; output ordering unaffected.

## Hash-algorithm robustness (the one live-iteration risk)

Modern Win10/11 catalogs are SHA-256; this design acquires the context with SHA-256, covering
the overwhelming majority. Legacy catalogs may be SHA-1. The acceptance gate's live e2e is the
arbiter: if a known catalog-signed file still reports `Some(false)` after SHA-256, add a SHA-1
retry (acquire a second context with `w!("SHA1")`, repeat the hash+enum) before concluding
"unsigned". This is implemented only if the live run shows it is needed — verified by re-run,
not assumed. (This is why S2-G must be validated on a real host, not just unit-tested.)

## Testing

The unit-testable surface is thin (the logic is mostly FFI); the real proof is the live e2e.

- **unit / smoke (Windows, `#[cfg(all(test, windows))]`):**
  - missing file -> None (unchanged).
  - unsigned junk PE -> Some(false) (unchanged; embedded fails, catalog enum finds nothing).
  - a known embedded-signed binary, if locatable -> Some(true) via the fast path (no panic).
  - a known catalog-signed OS binary (e.g. `C:\Windows\System32\svchost.exe` — catalog-signed,
    no embedded sig) -> Some(true) via the catalog path. THIS is the new regression test; it
    is the exact case that returned Some(false) before S2-G. Guard with an `exists` check so
    Linux CI / odd images skip gracefully.
  - `WinSigVerifier.verify` still delegates.
- **off-Windows:** the non-Windows `verify_file` stub still returns None; the new code is all
  under `#[cfg(windows)] mod win`, so Linux CI compiles with the catalog code excluded. Any
  Windows-only helper unused on Linux carries `#[allow(dead_code)]` (the S2-C..F lesson).
- **e2e (manual-then-self-run, Windows):** `cairn run --target live --only persist,process`;
  confirm the previously-false catalog-signed binaries (svchost, SearchIndexer,
  SecurityHealthSystray) now report `signed=true`; embedded-signed entries (Docker, Notion)
  unchanged at `signed=true`; genuinely unsigned/.lnk entries unchanged; the signed=false
  count drops substantially vs the S2-F baseline; `cairn verify` passes. Record the
  before/after signed breakdown.

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new
  external crate — only a new feature flag on the already-present `windows` crate).
- `unsafe` appears in NO crate except `cairn-collectors-win`; all other crates stay
  `#![forbid(unsafe_code)]`.
- A real live run resolves catalog-signed OS binaries to `signed=true` (the S2-F false-unsigned
  set is fixed); embedded-signed and genuinely-unsigned entries unchanged; `cairn verify`
  passes; earlier stages (S1/S2-A..F) unchanged.
- No golden-rule violation (read-only hash + catalog lookup, no evasion, no new network); no
  scope creep (no signer identity, no heuristic re-tune, schema unchanged).

## Non-goals / future hooks

- **S2-H (next, problem C):** heuristic calibration — Winlogon default-value allowlist, AppData
  publisher/signer trust, a benign baseline corpus. With S2-G landing accurate `signed`, S2-H
  can re-tune the amplifier weights against real data and add signer-aware trust if it extracts
  signer identity then.
- **Signer identity** (Microsoft vs third-party): a future enhancement (likely folded into
  S2-H where it is actually consumed); `signed` stays `Option<bool>` until then.
- Later still: Scheduled Tasks, WMI subscriptions, raw-NTFS, offline artifacts, FR14 hashing.
- `.lnk` target resolution for startup entries remains a separate future enhancement (noted in
  S2-F): a startup `.lnk` verifies as the `.lnk`, not its target binary.
