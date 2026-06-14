# S2-E: process full image path + signed backfill + unsigned-amplifier conversion — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-13.
> Authoritative spec: `cairn-SRS.md` (§4 proc_collector, §5 ProcessRecord.signed, §10
> heuristics, NFR3 unsafe-isolation, §17 D6/D7).
> Predecessors: S2-A (proc/net live collectors + cairn-collectors-win FFI), S2-B
> (parentchild/netconn heuristics + the existing unsigned signals), S2-D (WinVerifyTrust
> `verify_file` + FileVerifier seam + the persist unsigned-amplifier pattern).

## Purpose

`ProcessRecord.signed` is always `None` today: the proc collector reads only the
executable *file name* (`szExeFile` from Toolhelp), not the full path that `WinVerifyTrust`
needs. This sub-segment reads each process's full image path, reuses S2-D's `verify_file`
to backfill `signed`, and — critically — converts the EXISTING unsigned signals in the
parentchild and netconn heuristics from unconditional `+20` into amplifiers that require
another suspicion signal. Those signals were written in S2-B but never fired (signed was
always None); the moment signed carries real values, catalog-signed system processes
(svchost, services, …) would be reported unsigned by `WTD_CHOICE_FILE` and flood false
positives. This sub-segment lands signed AND the guard against that flood together.

## Scope

**In scope:**
- `cairn-collectors-win/src/proc.rs`: for each enumerated pid, `OpenProcess`
  (`PROCESS_QUERY_LIMITED_INFORMATION`) + `QueryFullProcessImageNameW` to get the full
  image path. Best-effort: a process we cannot open (privilege, already exited) keeps the
  `szExeFile` file name (graceful — never fail the enumeration).
- `cairn-collectors/src/proc.rs`: `ProcCollector` gains an injected `FileVerifier` (the
  same seam as `PersistCollector`) and fills `signed` for records whose `image` is an
  absolute path. File-name-only images (the fallback) are NOT verified (signed stays None).
- `cairn-heur/src/parentchild.rs` and `cairn-heur/src/netconn.rs`: convert the existing
  unconditional unsigned signals into amplifiers (fire only with another signal present),
  mirroring the S2-D persist amplifier lesson.

**Explicitly OUT of scope (deferred, with rationale):**
- **Catalog-signed false reports** — `WTD_CHOICE_FILE` reports catalog-signed binaries
  (many OS files) as unsigned. Root-causing this needs signer-identity extraction; deferred
  (SRS §17 D6). The amplifier conversion is precisely the mitigation: an unsigned signal
  alone no longer raises severity, so a catalog-signed system process is not flagged.
- **Heuristic full calibration** (SRS §17 D7) — the AppData/Winlogon sensitivity items and
  any broader re-tuning belong in a dedicated tuning sub-segment with a benign baseline
  corpus. This sub-segment makes only the minimal change needed to prevent the KNOWN
  unsigned flood, not a general re-tune.
- **binary_path normalization** (SRS §17 D6, unquoted-cmdline truncation) — separate
  sub-segment.
- **Signer identity / certificate subject** — `signed` stays `Option<bool>`.

## Architecture

Reuses every seam S2-D built. No new crate; changes in the three existing ones.

```
cairn-collectors-win/src/proc.rs  (modify mod win; #![allow(unsafe_code)] inherited)
  enumerate(): after the Toolhelp loop fills pid/ppid/szExeFile, enrich each RawProc:
    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)         [RAII guard]
      ok(handle) -> QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf, &len)
                      ok -> RawProc.image = full path
                      err -> keep szExeFile name
      err(open)  -> keep szExeFile name (privilege / pid exited; graceful)
        │  (RawProc.image now a full path when obtainable, else the file name)
        ▼
cairn-collectors/src/proc.rs  (modify; stays #![forbid(unsafe_code)])
  ProcCollector { verifier: Box<dyn FileVerifier + Send + Sync> }   (mirror PersistCollector)
    Default: WinSigVerifier on Windows, NoopVerifier off-Windows
  collect(): build records, then for each record whose `image` is an ABSOLUTE path,
             record.signed = verifier.verify(&image)   (file-name-only -> left None)
        │
        ▼
cairn-heur/src/parentchild.rs + netconn.rs  (modify; stay #![forbid(unsafe_code)])
  the existing unconditional unsigned `+20` (and parentchild's unsigned+high-integrity +15)
  become amplifiers: add the weight only when another suspicion signal already fired.
```

**New / changed units:**
- `crates/cairn-collectors-win/src/proc.rs`: add the OpenProcess + QueryFullProcessImageNameW
  enrichment with an RAII handle guard (mirror the existing `Snapshot` guard). New WinAPI
  imports; no new crate feature (all in the already-enabled `Win32_System_Threading`).
- `crates/cairn-collectors/src/proc.rs`: `ProcCollector` becomes a struct with a `verifier`
  field (+ `Default`, `with_verifier`); `build_process_records` stays pure; `collect` fills
  signed. A small pure helper `is_absolute_path(&str)` decides what to verify.
- `crates/cairn-heur/src/parentchild.rs`: gate the unsigned (+20) and unsigned+high-integrity
  (+15) signals on "another signal already fired".
- `crates/cairn-heur/src/netconn.rs`: gate the unsigned owner (+20) signal likewise. The
  unsigned-high-port-listener (+25) compound signal ALREADY requires the listen-state +
  high-port conditions, so it is itself conditional — keep it, but confirm it does not
  double-flag a plain catalog-signed listener (it requires `signed==Some(false)` + listen +
  port>1024; a benign catalog-signed listener has `signed==Some(false)` too, so this needs
  the same care — see Rules).
- `crates/cairn-cli/src/main.rs`: construct `ProcCollector` with the real verifier
  (`ProcCollector::default()`), mirroring the S2-D PersistCollector change.

**Layering:** all new unsafe is in `cairn-collectors-win` (OpenProcess/Query are read-only
queries; `PROCESS_QUERY_LIMITED_INFORMATION` cannot modify the target). `verify_file` is
reused (no new verification unsafe). `cairn-collectors` and `cairn-heur` stay
`#![forbid(unsafe_code)]`.

**Cross-platform:** the enrichment is inside `#[cfg(windows)] mod win`; the non-Windows
`enumerate` stub still returns `vec![]`. The collector's verifier defaults to NoopVerifier
off-Windows. Pure helpers (`is_absolute_path`, amplifier logic) test on ubuntu CI.

## The full-image-path enrichment (verified API shapes, windows 0.62.2)

Confirmed against the crate source — not guessed:

```text
feature:   Win32_System_Threading  (already enabled)
OpenProcess(dwDesiredAccess: PROCESS_ACCESS_RIGHTS, bInheritHandle: bool, dwProcessId: u32)
   -> Result<HANDLE>
QueryFullProcessImageNameW(hProcess: HANDLE, dwFlags: PROCESS_NAME_FORMAT,
   lpExeName: PWSTR, lpdwSize: *mut u32) -> Result<()>
const PROCESS_QUERY_LIMITED_INFORMATION: PROCESS_ACCESS_RIGHTS = 4096
const PROCESS_NAME_WIN32: PROCESS_NAME_FORMAT = 0   (Win32 path form, not the \Device\ NT form)
```

**Algorithm (per pid, best-effort, never panics):**
1. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)`. On Err → keep szExeFile,
   continue. (`QUERY_LIMITED_INFORMATION` is the low-privilege form Vista+; a non-admin can
   open most same/lower-integrity processes; SYSTEM/protected processes still fail → graceful.)
2. Wrap the handle in an RAII guard (mirror the `Snapshot` guard: `CloseHandle` on drop).
3. Buffer `Vec<u16>` (start e.g. `MAX_PATH`=260; if `QueryFullProcessImageNameW` returns
   `ERROR_INSUFFICIENT_BUFFER`, grow once to a larger cap, e.g. 32768, and retry). `len` is
   in/out (capacity in, written length out).
4. On Ok → `RawProc.image = String::from_utf16_lossy(&buf[..len])`. On Err → keep szExeFile.

**SAFETY** notes go on each unsafe block (OpenProcess, QueryFullProcessImageNameW,
CloseHandle), as in the existing proc.rs `Snapshot` pattern. The handle is closed exactly
once via the guard, including on early continue.

## What to verify (collector)

`is_absolute_path(image)` — true if it looks like a Windows absolute path: a drive letter
(`X:\`) or a UNC (`\\`). Only absolute images are passed to `verify_file`; a file-name-only
image (the OpenProcess-failed fallback, e.g. `svchost.exe`) is left `signed = None` — we
never feed a bare name to verification (it would not resolve, or worse, resolve against the
CWD). This keeps signed honest: a real path verified, an unknown path left None.

Performance: OpenProcess + Query are lightweight (no file read); `verify_file` is the I/O
cost but process counts are typically smaller than persistence counts. Serial is fine; the
loop is the obvious parallelization seam if a pathological host ever needs it (NFR9/§19).

## Rules — unsigned-amplifier conversion (parentchild + netconn, SRS §10)

The lesson from S2-D: an unsigned signal must AMPLIFY another suspicion, not stand alone —
because catalog-signed OS binaries are reported unsigned by `WTD_CHOICE_FILE`. We apply the
same shape here. "Another signal fired" = the score gained weight from a non-unsigned
signal before the unsigned check.

**parentchild (`score_process`):**
| Signal | Before (S2-B) | After (S2-E) |
|---|---|---|
| unsigned | unconditional +20 | +20 only if another signal already fired (parent→child anomaly, encoded PS, suspicious path, or LOLBAS) |
| unsigned + high/system integrity | unconditional +15 (when unsigned) | +15 only if another signal already fired AND integrity is high/system |

Rationale: a signed-unknown (None) process is never penalized; a catalog-signed system
process (reported unsigned) with NO other suspicion stays quiet. A genuinely malicious
unsigned binary almost always also trips a path/parent/encoded signal, which licenses the
amplifier.

**netconn (`score_conn`):**
| Signal | Before (S2-B) | After (S2-E) |
|---|---|---|
| owning process unsigned | unconditional +20 | +20 only if another connection signal already fired (public-IP, rare port, owner-in-temp) |
| unsigned high-port listener | +25 when unsigned + listen + port>1024 | KEEP the listen+port>1024 conditions, but gate the unsigned-ness the same way: it should reflect a genuinely suspicious listener, not every catalog-signed service on a high port. Require the suspicious-path signal (the +30 owner-image-in-suspicious-path check, the only other owner-level signal) to have ALSO fired, in addition to unsigned+listen+port>1024. (Otherwise every svchost RPC listener on an ephemeral port flags, since catalog-signed → reported unsigned.) |

Implementation note: capture "weight before the unsigned signals" (as the persist amplifier
does with a pre-unsigned snapshot, or an explicit `another_signal_fired` bool), then gate.
Match the precise approach used in persist's `score_persistence` (a bool set when the
corroborating signal fires) for consistency and testability — do NOT couple to reason
strings.

**Reasons** keep their explainability (golden rule 6): the amplifier reason still names
"unsigned", and the gating means it only appears alongside the corroborating reason.

## Finding construction

Unchanged. `signed` is already `Option<bool>` on ProcessRecord (serde schema unchanged).
Findings gain accurate signed-driven weight where corroborated; lose the spurious unsigned
weight on lone catalog-signed processes.

## Error handling / graceful degrade

- Enrichment is best-effort: OpenProcess/Query failure keeps the file name; never errors
  the enumeration, never panics. The handle guard closes on every path.
- The collector leaves `signed = None` for file-name-only images and for verify failures.
- Heuristics stay total/pure; the amplifier gate adds no panic path.
- Determinism (NFR4): enrichment does not change record ordering; `sort_findings` unchanged.

## Security note (golden rule 1)

`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` are the
standard, documented, read-only way to learn a process's image path — the same call Task
Manager / Process Explorer make. `QUERY_LIMITED_INFORMATION` cannot read memory, inject, or
modify the target. No evasion, no host modification. Reusing `verify_file` adds no new
verification surface.

## Testing

Pure logic → full TDD; the OpenProcess/Query FFI → a thin smoke test (as S2-A/S2-D).

- **is_absolute_path (pure):** `C:\Windows\x.exe` → true; `\\server\share\x.exe` → true;
  `svchost.exe` → false; `` → false.
- **collector signed wiring (FakeVerifier):** a record with an absolute image the fake maps
  to Some(false) → signed Some(false); a file-name-only image is never queried → None; an
  absolute image the fake doesn't know → None. (Mirror the S2-D persist wiring test.)
- **parentchild amplifier:** unsigned + suspicious path → +20 fires; unsigned alone (no
  other signal, normal path) → no +20 (the catalog-signed-system-process case stays quiet);
  unsigned+high-integrity alone → no +15; signed (Some(true)) → no amplifier; None → no
  amplifier. Weights match worked cases.
- **netconn amplifier:** unsigned owner + public-IP/rare-port → +20 fires; unsigned owner
  with no other connection signal → no +20; the high-port-listener compound requires its
  suspicious-path/temp condition.
- **proc enrichment smoke (Windows):** `enumerate()` returns the current process with an
  ABSOLUTE image path (we can open our own process), proving the OpenProcess/Query path
  works; does not panic; other processes may keep file names (privilege) — don't hard-require.
- **e2e (manual, Windows):** `cairn run --target live` populates `signed` on process records
  (a non-trivial mix of true/false/null); confirm catalog-signed system processes are NOT
  flooded as findings (the amplifier holds); `cairn verify` passes; S1/S2-A/B/C/D unchanged.
  Record the signed breakdown and any unsigned-amplified findings (expect few/none on a
  clean host).

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new
  external crate — Threading APIs are in the already-present `windows` crate/feature).
- `unsafe` appears in NO crate except `cairn-collectors-win`; collectors + heur stay
  `#![forbid(unsafe_code)]`.
- A real live run fills proc `signed`; catalog-signed system processes are not flooded as
  findings (amplifier conversion verified); earlier stages unchanged.
- No golden-rule violation (read-only query, no evasion); no scope creep (no signer
  identity, no full heuristic re-tune, no binary_path normalization — all deferred per D6/D7).
- Linux CI dead-code: any Windows-only helper unused on Linux carries `#[allow(dead_code)]`
  (the S2-C/S2-D lesson).

## Non-goals / future hooks

- **D6 (binary_path normalization):** unquoted-cmdline truncation + (with signer identity)
  catalog-signed resolution — its own sub-segment.
- **D7 (heuristic calibration):** Winlogon default allowlist, AppData publisher trust, a
  benign baseline corpus — its own tuning sub-segment, where the unsigned amplifier weights
  here can be re-tuned with data.
- Later still: Scheduled Tasks, WMI subscriptions, raw-NTFS, offline artifacts, FR14 hashing.
