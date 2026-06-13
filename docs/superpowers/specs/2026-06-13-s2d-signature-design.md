# S2-D: WinVerifyTrust signature verification + persist signed backfill — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-13.
> Authoritative spec: `cairn-SRS.md` (§4 collectors, §5 PersistenceRecord.signed, §10
> persistence rank, NFR3 unsafe-isolation).
> Predecessors: S2-A (live proc/net + orchestrator + `cairn-collectors-win` FFI crate),
> S2-B (parentchild/netconn heuristics + shared `score.rs`), S2-C (persist collector +
> persist heuristic; `PersistenceRecord.binary_path` is now populated, `signed` is None).

## Purpose

The persist collector enumerates autostart/persistence entries and the persist heuristic
flags suspicious ones, but every `PersistenceRecord.signed` is currently `None` — the tool
cannot yet tell a Microsoft-signed binary from an unsigned dropper sitting in a Run key.
This sub-segment adds **Authenticode signature verification** via the WinTrust API
(`WinVerifyTrust`), backfills `signed` for persistence records, and teaches the persist
heuristic to use "unsigned" as an **amplifier** of other suspicion signals — surfacing
genuinely malicious unsigned persistence while staying quiet for the many legitimately
unsigned tools (open-source utilities, in-house scripts) that live in normal locations.

## Scope

**In scope:**
- A new `signature` module in `cairn-collectors-win` (the single unsafe-FFI crate): a
  `verify_file(path) -> Option<bool>` wrapper over `WinVerifyTrust`
  (`WINTRUST_ACTION_GENERIC_VERIFY_V2`), behind a safe API, never panicking.
- `PersistCollector` calls verification for each record that has a `binary_path`, filling
  `signed`. Verification is injected via a `FileVerifier` trait so the collector stays
  `#![forbid(unsafe_code)]` and is testable without touching the OS.
- The persist heuristic gains an **unsigned amplifier** signal (`+20`) that fires ONLY
  when `signed == Some(false)` AND at least one other suspicion signal is already present
  (suspicious path or recent write).

**Explicitly OUT of scope (deferred, with rationale):**
- **Process `signed` backfill** — `ProcessRecord.signed` is also None, but the proc
  collector reads only the executable *file name* (`szExeFile`), not the full path that
  `WinVerifyTrust` requires. Reading the full image path needs a separate FFI
  (`QueryFullProcessImageNameW`) plus a process-handle open that hits privilege limits
  (a non-admin cannot read a SYSTEM process's path). That is its own sub-segment,
  **S2-E**, which will reuse this sub-segment's `verify_file` to fill proc `signed` and
  then add the unsigned signal to the netconn heuristic.
- **Signer identity** (e.g. "is the signer Microsoft?") — `signed` stays `Option<bool>`.
  Extracting the certificate subject needs `WTHelperProvDataFromStateData` /
  `CryptQueryObject` and a richer return type; deferred until a heuristic actually needs
  the distinction.
- **Catalog-signed files** — `WinVerifyTrust` with `WTD_CHOICE_FILE` verifies embedded
  Authenticode only; OS files signed via security catalogs (`.cat`) may report unsigned.
  This is acceptable for the heuristic (it treats `None`/`false` conservatively and only
  amplifies *other* signals), and is documented as a known limitation. A future
  enhancement may add `WTD_CHOICE_CATALOG` / `WTD_STATEACTION_AUTO_CACHE`.
- **Binary hashing** (`binary_sha256`) — that is FR14, a later sub-segment. Stays None.

## Architecture

Extends the established collector→analyzer pattern. One new module in the existing unsafe
crate, one trait seam in the collector, one new signal in the heuristic. No new crate.

```
cairn-collectors-win/src/signature.rs  (NEW; #![allow(unsafe_code)] inherited from crate)
   verify_file(path: &str) -> Option<bool>
     Some(true)  = WinVerifyTrust returned ERROR_SUCCESS (0): trusted Authenticode
     Some(false) = WinVerifyTrust returned non-zero (TRUST_E_NOSIGNATURE / _BAD_DIGEST /
                   _SUBJECT_NOT_TRUSTED / CERT_E_* ...): unsigned or untrusted
     None        = file does not exist, path not convertible, or the call could not run
                   (graceful: the heuristic's unsigned signal simply does not fire)
   non-Windows: always None
        │ (injected via trait, so the safe collector never links unsafe directly)
        ▼
cairn-core/src/traits.rs  (MODIFY: add the seam)
   pub trait FileVerifier { fn verify(&self, path: &str) -> Option<bool>; }
        │
        ▼
cairn-collectors/src/persist.rs  (MODIFY; stays #![forbid(unsafe_code)])
   PersistCollector { verifier: Box<dyn FileVerifier> }  (default = the win impl / a noop)
   collect(): after fanning in the five readers, for each record with binary_path =>
              record.signed = verifier.verify(path)   (pure wiring; no OS code here)
        │
        ▼
cairn-heur/src/persist.rs  (MODIFY; stays #![forbid(unsafe_code)])
   score_persistence(): after path + recency signals, add:
     if signed == Some(false) AND (had a suspicious-path OR recent signal) => +20 (T1036)
```

**New / changed units:**
- `crates/cairn-collectors-win/src/signature.rs` (new): `verify_file` + `WinSigVerifier`
  (a `FileVerifier` impl). Windows `mod win` does the FFI; non-Windows returns None.
- `crates/cairn-collectors-win/Cargo.toml`: add `Win32_Security_WinTrust` to the windows
  feature list (and `Win32_Foundation` is already present for HWND).
- `crates/cairn-collectors-win/src/lib.rs`: `pub mod signature;`.
- `crates/cairn-core/src/traits.rs`: add the `FileVerifier` trait (the seam; core has no
  host deps, so the trait lives here and both sides depend only on core).
- `crates/cairn-collectors/src/persist.rs`: `PersistCollector` gains a `verifier` field;
  `collect` fills `signed`; a `NoopVerifier` (returns None) is the cross-platform default
  used in tests and on non-Windows.
- `crates/cairn-collectors/Cargo.toml`: NO change — it already depends on
  `cairn-collectors-win` unconditionally (the win crate is an empty shell off-Windows), so
  `WinSigVerifier` is reachable for the `cfg(windows)` default without a new dependency.
- `crates/cairn-heur/src/persist.rs`: the unsigned-amplifier signal + tests.
- `crates/cairn-cli/src/main.rs`: construct `PersistCollector` with the real verifier
  (`WinSigVerifier` on Windows; the existing `PersistCollector` default elsewhere).

**Layering (preserves NFR3 / golden rule 3):**
- ALL new `unsafe` is in `signature.rs` inside `cairn-collectors-win` — the only crate
  with `#![allow(unsafe_code)]`. `cairn-collectors` and `cairn-heur` stay
  `#![forbid(unsafe_code)]`; they touch verification only through the `FileVerifier`
  trait defined in `cairn-core` (which has no host deps).
- The collector is read-only: `verify_file` opens the file for read to hash/verify the
  signature; it never writes. Golden rule 3 (collectors never modify the host) holds.

**Cross-platform build (mirrors S2-A/S2-C):** the WinTrust FFI is `cfg(windows)`. On
non-Windows `verify_file` returns None and `WinSigVerifier` is not constructed; the pure
collector/heuristic logic still compiles and tests on ubuntu CI via `NoopVerifier`.

## The WinVerifyTrust wrapper (verified API shapes, windows 0.62.2)

These are the real symbols in `windows-0.62.2`, confirmed against the crate source — not
guessed. The wrapper mirrors the canonical MSDN "Example C Program: Verifying the
Signature of a PE File" flow.

```text
feature:   Win32_Security_WinTrust   (plus the already-enabled Win32_Foundation)
fn:        WinVerifyTrust(hwnd: HWND, pgactionid: *mut GUID, pwvtdata: *mut c_void) -> i32
GUID:      WINTRUST_ACTION_GENERIC_VERIFY_V2
structs:   WINTRUST_DATA { cbStruct, dwUIChoice, fdwRevocationChecks, dwUnionChoice,
                           Anonymous: WINTRUST_DATA_0 { pFile: *mut WINTRUST_FILE_INFO },
                           dwStateAction, dwProvFlags, dwUIContext, ... }
           WINTRUST_FILE_INFO { cbStruct, pcwszFilePath: PCWSTR, hFile, pgKnownSubject }
consts:    WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE,
           WTD_STATEACTION_VERIFY (open), WTD_STATEACTION_CLOSE (free state data)
HWND null: HWND(core::ptr::null_mut())   // INVALID_HANDLE_VALUE not needed; null = no UI
return:    0 (ERROR_SUCCESS) => trusted; any non-zero => not trusted / unsigned
```

**Wrapper algorithm (`verify_file`):**
1. If `path` is empty or the file does not exist → return `None` (nothing to verify).
2. Encode `path` to a NUL-terminated `Vec<u16>` (`OsStr::encode_wide` + push 0).
3. Build `WINTRUST_FILE_INFO { cbStruct = size_of, pcwszFilePath = PCWSTR(wide.as_ptr()),
   hFile = HANDLE(null), pgKnownSubject = null }`.
4. Build `WINTRUST_DATA` zeroed (`Default`), then set: `cbStruct`, `dwUIChoice =
   WTD_UI_NONE`, `fdwRevocationChecks = WTD_REVOKE_NONE`, `dwUnionChoice =
   WTD_CHOICE_FILE`, `Anonymous.pFile = &mut file_info`, `dwStateAction =
   WTD_STATEACTION_VERIFY`.
5. **SAFETY**: call `WinVerifyTrust(HWND(null), &mut WINTRUST_ACTION_GENERIC_VERIFY_V2,
   &mut wtd as *mut _ as *mut c_void)`. `wtd`/`file_info`/`wide` all outlive the call;
   pointers are non-dangling for its duration.
6. Record `trusted = (status == 0)`.
7. **Always** flip `dwStateAction = WTD_STATEACTION_CLOSE` and call `WinVerifyTrust`
   again to free the provider's state data (the documented teardown; skipping it leaks).
   This is done via an RAII guard so an early return / panic-unwind still closes it —
   though the function itself never panics.
8. Return `Some(trusted)`.

`wide`, `file_info`, and `wtd` are local stack values held across both calls; the guard
borrows `wtd` to perform the CLOSE in `Drop`. No heap, no handles to leak besides the
provider state (closed by the guard).

## Wiring into the collector

`PersistCollector` becomes:

```text
pub struct PersistCollector { verifier: Box<dyn FileVerifier + Send + Sync> }

impl Default for PersistCollector
  - cfg(windows):     verifier = Box::new(WinSigVerifier)
  - cfg(not windows): verifier = Box::new(NoopVerifier)

impl PersistCollector
  pub fn with_verifier(v: Box<dyn FileVerifier + Send + Sync>) -> Self   // tests

impl Collector for PersistCollector
  collect():
    let mut records = <fan in the five readers>            // unchanged
    for r in &mut records {
        if let Some(p) = r.binary_path.as_deref() {
            r.signed = self.verifier.verify(p);            // None stays None
        }
    }
    Ok(records.into_iter().map(Record::Persistence).collect())
```

`NoopVerifier` (in `cairn-collectors`, returns `None`) keeps the cross-platform default
and is what unit tests inject (deterministic, no OS). A `FakeVerifier` in tests maps known
paths to `Some(true)/Some(false)` to exercise the wiring.

**Performance:** verification is per-file I/O. Persistence record counts are small (a few
hundred on a real host), so serial verification in `collect` is acceptable; no rayon. (If
a future host shows pathological counts, the loop is the obvious parallelization seam.)

## Rules — the unsigned amplifier (persist heuristic, SRS §10)

Added to `score_persistence`, AFTER the existing mechanism / suspicious-path / recency
signals, so it can observe whether any other signal already fired.

| Signal | Condition | Weight | ATT&CK |
|---|---|---|---|
| Unsigned amplifier | `signed == Some(false)` AND (the suspicious-path signal fired OR the recency signal fired) | +20 | T1036 |

It is an **amplifier, not a base signal**: an unsigned binary on its own does not raise a
finding (legitimately unsigned tools in normal paths stay quiet). It only adds weight when
another suspicion is already present. Worked cases (validated against the weight table —
mechanism bases ifeo 45 / winlogon 35 / service 20 / run_key 10 / startup 10; path +30;
recent +15):

- Legit unsigned run_key, normal path, old → `10` (no other signal → amplifier off) → **quiet**.
- Legit unsigned service, normal path, old → `20` (no other signal → amplifier off) → Low (an autostart service is worth one glance; reasonable).
- Unsigned run_key in Temp → `10 + 30(path) + 20(unsigned) = 60` → **High**.
- Unsigned IFEO in Temp, recent → `45 + 30 + 15 + 20 = 110` → **Critical**.
- **Signed** IFEO in Temp → amplifier off (`signed == Some(true)`); `45 + 30 = 75` still **Critical** (a Debugger value is wrong even if signed — correct).
- Unknown-signature (None) run_key in Temp → `10 + 30 = 40` → Medium; amplifier off (we never penalize what we could not verify).

`reason` gains "binary is unsigned (amplifies the above)" when the signal fires (golden
rule 6 — explainable).

## Finding construction

Unchanged from S2-C. The unsigned amplifier only adds weight + a reason string + the
T1036 tag (deduped by `Score`). Severity still comes from `severity_for`. `signed` is part
of the record (already serialized); the finding's reason surfaces it.

## Error handling / graceful degrade

- `verify_file` is total: missing file / unconvertible path / a call that cannot run all
  return `None`. It never errors the collector and never panics. The provider state is
  always closed (RAII guard) even on early return.
- A record whose `binary_path` is `None` (rare) is left `signed = None` — no verification
  attempted.
- The heuristic is unchanged in its totality guarantees: `signed == None` or `Some(true)`
  simply does not fire the amplifier. No new panic paths.
- Determinism (NFR4): verification does not change record ordering; the CLI's existing
  `sort_findings` still orders the output.

## Security note (golden rule 1 — "No evasion, ever")

This is the first Cairn code that touches the *signature* APIs. It is a NORMAL call to the
public `WinVerifyTrust` API to *read/verify* signatures — it is NOT signing, NOT patching
a trust provider, NOT hooking, NOT bypassing anything. It cannot be used for evasion. The
observation worth recording: code that calls WinTrust is marginally more likely to draw an
EDR's attention than pure registry reads, but because it is a documented, benign,
read-only verification call (the exact thing AV tools themselves do), the risk is low and
fully consistent with the "the EDR SHOULD see this tool and recognize it as benign" stance.

## Testing

Pure logic → full TDD; the WinTrust FFI → a thin smoke test (as S2-A/S2-C did for OS reads).

- **unsigned amplifier (cairn-heur, pure, no OS):**
  - unsigned + Temp path → amplifier fires (+20), reason mentions "unsigned"; weight matches the worked case.
  - unsigned + normal path + old → amplifier does NOT fire (no other signal); weight = mechanism base only.
  - signed (`Some(true)`) + Temp → amplifier does NOT fire.
  - unknown (`None`) + Temp → amplifier does NOT fire.
  - unsigned + recent (no suspicious path) → amplifier fires (recency is the other signal).
- **collector wiring (cairn-collectors, pure, FakeVerifier):**
  - a record with a binary_path the fake maps to `Some(false)` ends up with `signed == Some(false)`.
  - a record with binary_path the fake maps to `Some(true)` → `Some(true)`.
  - a record whose path the fake does not know (`None`) → `signed == None`.
  - a record with `binary_path == None` is never queried and stays `None`.
- **NoopVerifier:** always returns None (cross-platform default; ubuntu CI exercises it).
- **verify_file smoke (Windows only):**
  - a known OS binary with embedded Authenticode → `Some(true)`. NOTE: prefer a file that
    is embedded-signed rather than only catalog-signed; if a robust embedded-signed system
    file is not guaranteed, assert only "returns without panic and is `Some(_)` or `None`"
    to avoid a brittle environment-dependent assertion (document the choice in the test).
  - a freshly-written unsigned temp `.exe`-named file (junk bytes) → `Some(false)`.
  - a non-existent path → `None`.
  - the call does not panic and the second (CLOSE) call always runs.
- **e2e (manual, Windows):** `cairn run --target live` now populates `signed` on
  persistence records; unsigned + suspicious persistence is amplified in findings.jsonl
  (reason mentions unsigned); `cairn verify` passes; S1 / S2-A / S2-B / S2-C paths
  unchanged; the persist finding count does not regress for legitimately unsigned normal
  entries (they stay below the floor).

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new
  external crate — WinTrust is part of the already-present `windows` crate, gated by an
  added feature).
- `unsafe` appears in NO crate except `cairn-collectors-win`. `cairn-collectors` and
  `cairn-heur` remain `#![forbid(unsafe_code)]`; verification crosses the boundary only via
  the `cairn-core` `FileVerifier` trait.
- A real live run fills `signed` and amplifies unsigned suspicious persistence; `verify`
  passes; earlier stages unchanged.
- No golden-rule violation (read-only verify, no evasion); no scope creep (no proc signed,
  no signer identity, no catalog verification, no hashing — all deferred with rationale).
- Linux CI dead-code: any Windows-only helper that becomes unused on Linux carries
  `#[allow(dead_code)]` (the lesson from S2-C's CI failure).

## Non-goals / future hooks

- **S2-E (next):** `QueryFullProcessImageNameW` to read full process image paths; reuse
  `verify_file` to fill `ProcessRecord.signed`; add the unsigned signal to the netconn
  heuristic and re-tune.
- Later: signer-identity extraction (Microsoft vs third-party), catalog-signature support
  (`WTD_CHOICE_CATALOG`), binary hashing (FR14), `.lnk` target resolution for startup.
- The unsigned weight (`+20`) and the "amplifier requires another signal" rule are the
  config-loader seam — tunable without touching matching logic.
