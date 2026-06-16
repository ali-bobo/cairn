# S2-N — $MFT MACB times + SI/FN dual-axis (forensic slice) — Design

> Sub-segment of Stage 2 (raw-NTFS). Authoritative spec: `cairn-SRS.md`
> (§4 mft_collector, FR12, §8 NFR4/NFR5/NFR10, §11 raw-NTFS method, §19.1).
> Predecessor: S2-M (`docs/superpowers/specs/2026-06-16-s2m-raw-volume-primitive-design.md`)
> — built `VolumeReader`, the two-layer DoS guard, and the profile/privilege wiring
> this segment reuses wholesale.
>
> **S2-N fills the time fields S2-M left as `None`** and changes the iteration model
> from "root-directory index" to "scan the whole $MFT". It deliberately does NOT do
> the timestomp *judgement* (that is S2-N′, a cairn-heur analyzer), nor full path
> reconstruction, nor the full NFR10 circuit breaker.

---

## Purpose

For every $MFT file record (bounded by a hard cap), read the `$STANDARD_INFORMATION`
(SI) and `$FILE_NAME` (FN) attributes and emit a `Record::FileMeta` carrying SI and FN
**both** creation-time (btime) and modification-time (mtime). This produces a complete,
`cairn verify`-able timeline of file metadata — the raw material a later heuristic
(S2-N′) compares for timestomp (SI/FN delta). S2-N proves "we can read MACB times off a
real volume and convert them correctly and safely at $MFT scale"; it stops short of
deciding what those deltas *mean*.

## Locked design decisions (from the 2026-06-17 brainstorm)

1. **Scope = forensic slice only.** S2-N = full $MFT iteration + SI/FN btime+mtime +
   record-count hard cap + `NtfsTime→DateTime<Utc>` conversion. The full NFR10 circuit
   breaker (RAM/wall-clock ceilings across all collectors) and NFR9 (max-threads,
   below-normal priority) are a separate **governance** sub-segment. S2-N only upgrades
   S2-M's "minimal nod" record cap into a real, manifest-recorded safety bound.
2. **Add `fn_mtime` to do SI/FN dual-axis.** The classic timestomp moves SI times but
   cannot move FN; the strongest signal is SI.mtime vs FN.mtime. S2-M found
   `FileMetaRecord` had `si_btime`/`si_mtime`/`fn_btime` but no `fn_mtime`. S2-N adds it
   (the only cairn-core schema change).
3. **Judgement is a heuristic, not the collector.** The collector only *reads* the four
   times into `FileMetaRecord`. The timestomp delta judgement (threshold → Finding with
   `reason` + ATT&CK T1070.006) is **S2-N′** in cairn-heur — keeping the collector/
   analyzer seam clean (golden rules 3 & 6).
4. **S2-N boundary = collector fills fields; heuristic is S2-N′.** This segment delivers
   a verifiable timeline but timestomp *detection* is not usable until S2-N′. Accepted
   trade-off (keeps each segment's review focus single).
5. **path = single FN name + (parent record number, NOT stored in the record).** Full
   path reconstruction (record→name map + parent-chain walk + cycle guard) is its own
   later segment; timestomp does not depend on it. `path` is the FN file name.
6. **Record-count hard cap = fixed default + override flag, truncation recorded.**
   `ceiling = min(capacity, max_mft_records)`, default `1_000_000`, `--max-mft-records N`
   overrides; hitting it records a truncation note in `manifest.sources[].errors` and
   continues (NFR10's "hit → degrade gracefully" made literal).

## What S2-M already gives us (verified by reading the code/crate on 2026-06-17)

- **`FileMetaRecord` exists** (`cairn-core/src/record.rs:80`) with `si_btime`/`si_mtime`/
  `fn_btime` already present. S2-N adds ONE field (`fn_mtime`).
- **`VolumeReader`** (`cairn-collectors-win/src/volume.rs`) — read-only `\\.\C:`
  `Read+Seek`, RAII guard, overflow-safe alignment, ≤1 MiB read cap. Reused unchanged.
- **Two-layer DoS guard** (`cairn-collectors/src/mft.rs`): guard (a) boot-sector length
  pre-check, guard (b) `catch_unwind` around the parse. Reused; the iteration loop S2-N
  introduces sits INSIDE guard (b).
- **Privilege gate + graceful degrade** (`MftCollector::collect`, orchestrator): no
  `admin && se_backup` → `Err(Privilege)` → SourceEntry note, continue. Reused unchanged.
- **Profile switch** (`selection.rs` `RAW_NTFS = ["mft"]`): `minimal` already skips mft.
  No selection change — S2-N changes mft's *internals*, not its registration.
- **No new dependency.** `chrono` (0.4.45) is already a dep of both cairn-core and
  cairn-collectors; `ntfs` 0.4.0 already pulled. `cargo audit` surface unchanged.

## ntfs 0.4.0 API — settled by reading the crate source on 2026-06-17 (NOT assumed)

Registry: `~/.cargo/registry/.../ntfs-0.4.0/src`.

- **Iterate the whole $MFT:** `Ntfs::file(&self, fs, file_record_number: u64) -> Result<NtfsFile>`
  (`ntfs.rs:85`; `checked_mul` guards offset overflow internally). `capacity =
  Ntfs::size() / Ntfs::file_record_size()` is the record-number upper bound. So the model
  is `for rec in 0..ceiling { ntfs.file(src, rec) }` — **distinct from S2-M's root-dir
  index walk, which S2-N replaces as the collector's main path.**
- **SI attribute:** `NtfsFile::info(&self) -> Result<NtfsStandardInformation>`
  (`file.rs:426`). `NtfsStandardInformation` exposes `creation_time()`,
  `modification_time()`, `mft_record_modification_time()`, `access_time()` — all return
  `NtfsTime` (`structured_values/standard_information.rs:84-122`).
- **FN attribute:** obtained from the file's `$FILE_NAME`; `NtfsFileName` exposes the
  same four `*_time()` getters returning `NtfsTime`
  (`structured_values/file_name.rs:118-205`) plus `name() -> U16StrLe` and `namespace()`.
- **Time conversion:** `NtfsTime` exposes only `nt_timestamp() -> u64` (Windows FILETIME:
  1601-01-01 epoch, 100 ns intervals) and `From<NtfsTime> for OffsetDateTime` (the `time`
  crate — which Cairn does NOT use; Cairn uses `chrono`). So S2-N converts via
  `nt_timestamp()` arithmetic into `chrono::DateTime<Utc>` (see §3).

**No TASK-0 verification debt remains for the API** — the iteration path, the four time
getters, and the conversion primitive are all confirmed against the crate source. The
ONE thing only an elevated e2e can confirm is that `ntfs` yields SI/FN for real records
on a real volume (the synthetic-image tests cover everything else).

## 1. Scope & iteration-model shift

| In scope | Out (deferred, see §8) |
|---|---|
| Full $MFT iteration `Ntfs::file(0..ceiling)` | timestomp judgement → S2-N′ (cairn-heur) |
| SI + FN btime & mtime (4 fields) | full path reconstruction / path map |
| record-count hard cap + manifest truncation note | NFR10 full circuit breaker (RAM/wall-clock) |
| `NtfsTime → DateTime<Utc>` conversion (cairn-core) | NFR9 max-threads / below-normal priority |

The iteration model **replaces** S2-M's root-directory index walk. S2-M listed names
under the root directory; S2-N scans every $MFT record. The root-dir path is no longer
the mft collector's main route after S2-N.

## 2. Schema change (cairn-core — the only core change)

`crates/cairn-core/src/record.rs`, `FileMetaRecord`: add one field.

```rust
pub struct FileMetaRecord {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub si_btime: Option<DateTime<Utc>>,
    pub si_mtime: Option<DateTime<Utc>>,
    pub fn_btime: Option<DateTime<Utc>>,
    pub fn_mtime: Option<DateTime<Utc>>,   // NEW: FN modification_time, paired with si_mtime
    pub zone_identifier: Option<String>,
}
```

**Backward compatibility (FR1 replay path):** `Option<T>` → serde deserializing older
JSONL that lacks `fn_mtime` yields `None`. A round-trip test plus an "old JSON missing
the field → None" test guard this. Every existing `FileMetaRecord { .. }` construction
site must add `fn_mtime` (S2-M's `mft.rs` emit site; any record.rs test fixture) — the
compiler enumerates them, none silently missed. Parent record number is **not** added to
the schema (it belongs to the later path-map segment).

## 3. Time conversion `NtfsTime → DateTime<Utc>` (cairn-core, pure arithmetic, no new dep)

Placed in cairn-core (pure time-semantics conversion, no host dependency — fits the
"depend-on-only crate" rule; $J reuses it later). Exposed as a small pure function.

```rust
// crates/cairn-core/src/time.rs (new module) or alongside record helpers.
use chrono::{DateTime, Utc};

/// Convert a Windows FILETIME (100 ns intervals since 1601-01-01 UTC) to a
/// `DateTime<Utc>`. Returns `None` for an unset (`0`) timestamp, a timestamp before
/// the Unix epoch (underflow), or one out of `DateTime`'s representable range.
/// Pure arithmetic — no `time` crate, no panic.
pub fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None; // unset timestamp (common in timestomped / sparse records)
    }
    const UNIX_EPOCH_AS_FILETIME: u64 = 11_644_473_600 * 10_000_000; // 1601→1970 in 100ns
    let since_unix_100ns = ft.checked_sub(UNIX_EPOCH_AS_FILETIME)?;   // pre-1970 → None
    let secs = (since_unix_100ns / 10_000_000) as i64;
    let nanos = ((since_unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos) // out-of-range → None
}
```

**Boundary handling (NFR5 "UTC RFC3339" + testability):** `ft == 0` → `None`;
`checked_sub` prevents underflow for 1601–1970 times → `None`; `from_timestamp` returns
`None` on overflow. Zero panic; fully unit-testable from FILETIME constants without a
real disk. Cross-check constant: ntfs's own `time.rs` test uses
`130018833000000000 → 2013-01-05T18:15:00Z`.

## 4. Collector full-$MFT iteration + DoS defenses (the heart of S2-N)

`crates/cairn-collectors/src/mft.rs` — `parse_mft_inner` (inside guard (b)) changes from
the root-dir index walk to:

```text
let ceiling = capacity.min(max_mft_records);   // hard cap
let mut emitted = 0u64;
let mut truncated = false;
for rec_num in 0..ceiling {
    let file = match ntfs.file(src, rec_num) {
        Ok(f) => f,
        Err(_) => continue,                    // single bad/unallocated record: skip + count
    };
    // skip records ntfs cannot validate as a file record
    let si = file.info().ok();                 // $STANDARD_INFORMATION (may be absent → None)
    // first_preferred_file_name returns the chosen $FILE_NAME's
    // (name: String, fn_btime_raw: u64, fn_mtime_raw: u64), where the two u64s are
    // already `.nt_timestamp()` of the FN creation_time / modification_time. Doing the
    // `.nt_timestamp()` extraction inside the helper keeps the emit site symmetric with
    // the SI axis below (both axes feed raw FILETIME u64 into filetime_to_utc).
    let fnm = first_preferred_file_name(&file, src); // $FILE_NAME (namespace pref, §4.1)
    let (path, fn_b_raw, fn_m_raw) = match fnm {
        Some(n) => (n.name, n.fn_btime_raw, n.fn_mtime_raw),
        None => continue,                      // no FN → not a meaningful file-meta record
    };
    emit Record::FileMeta {
        path,
        size: 0, sha256: None, zone_identifier: None,
        si_btime: si.as_ref().and_then(|s| filetime_to_utc(s.creation_time().nt_timestamp())),
        si_mtime: si.as_ref().and_then(|s| filetime_to_utc(s.modification_time().nt_timestamp())),
        fn_btime: filetime_to_utc(fn_b_raw),
        fn_mtime: filetime_to_utc(fn_m_raw),
    };
    emitted += 1;
}
if capacity > max_mft_records { truncated = true; }
```

(The exact streaming shape — pushing into the collector's output vec vs. an iterator — is
an implementation detail; it MUST NOT `collect()` the whole $MFT into an intermediate Vec
first; emit per record. See §5.)

### 4.1 FN namespace preference (forensic correctness + determinism)

A file may have multiple `$FILE_NAME` attributes (Win32, DOS 8.3, POSIX, Win32AndDos).
Pick the first **non-DOS** name (Win32 or Win32AndDos) to avoid emitting `PROGRA~1`-style
short names; fall back to the first available only if none is non-DOS. The rule is fixed
(deterministic, NFR4) and unit-tested with a synthetic multi-`$FILE_NAME` record.

### 4.2 Three DoS defenses (all required — at $MFT scale these are load-bearing, not a "nod")

**Attacker view (CLAUDE.md requirement).** Entry point = attacker-controlled $MFT bytes
on a compromised host. The NEW risk full iteration introduces over S2-M: a "capacity
field attack" — a boot sector lying about a huge volume `size` → huge `capacity` → a
loop that would run tens of millions of times = a wall-clock DoS against the responder
(SRS §19: "the triage tool must not become the incident").

1. **Record-count hard cap.** `ceiling = min(capacity, max_mft_records)`, default
   `1_000_000`, `--max-mft-records N` overrides. A lied-about capacity cannot make the
   loop exceed `max_mft_records`. Truncation (`capacity > max_mft_records`) → a note in
   `manifest.sources[].errors`: `"mft record cap reached: <cap> of <capacity>"`. The
   literal encoding of NFR10 "hit → degrade gracefully, record truncation, do not OOM".
2. **Single-record isolation.** Each `ntfs.file()` `Err` / invalid signature → `continue`
   (counted), never aborts the scan (per-record graceful degrade, golden rule 8). S2-M's
   `catch_unwind` guard (b) still wraps the whole loop against any unforeseen ntfs panic.
3. **Boot-sector length pre-check (S2-M guard (a)) retained** — the only known short-read
   panic trigger is unchanged.

**Mitigation summary:** the hard cap closes the capacity-field wall-clock vector;
per-record isolation closes "one bad record kills the run"; guards (a)/(b) close the
short-read panic. **Residual risk:** within the cap the scan can still be slow (each
record = seek + read); a true wall-clock ceiling is the governance segment's NFR10 work —
documented, not hidden here.

## 5. Determinism (NFR4) & streaming (SRS §3)

- Iteration is `rec_num` ascending → output order is record-number ascending,
  reproducible for a given volume state.
- Conversion is pure arithmetic — no float, no timezone ambiguity (all UTC);
  `filetime_to_utc(0) == None` stably.
- Emit per record; never `collect()` the full $MFT into an intermediate Vec. At full-scan
  scale this is the difference between bounded and unbounded peak RAM, not just style.

## 6. CLI wiring

- Add `--max-mft-records N` (clap), default `1_000_000`, threaded into `Config` (or the
  collect context the mft collector reads), mirroring existing config plumbing. No new
  collector registration (mft already registered in S2-M). `--profile minimal` still
  skips mft (unchanged). Document the flag in the CLI help and the SOC runbook touch-point
  only if a runbook table already lists collector knobs (do not invent new docs).

## 7. Testing (verifiability — the security precondition made concrete)

All run on Linux CI without a real disk (synthetic `Cursor<Vec<u8>>` NTFS image, the S2-M
technique), except the one elevated e2e.

| Test | Level | Platform | Asserts |
|---|---|---|---|
| `filetime_to_utc` known value → RFC3339 | unit | any | 1601-epoch math correct (cross-check `130018833000000000`→2013-01-05T18:15:00Z) |
| `filetime_to_utc(0)`/underflow/overflow → `None` | unit | any | boundaries, zero panic (NFR5) |
| record-count cap truncates → note, not panic | unit | any | capacity>cap synthetic boot sector: loop stops at cap, manifest records truncation |
| single bad record → `continue`, overall `Ok` | unit | any | bad-signature record mid-image: no abort, count correct |
| short/truncated source → `Err`, no panic | unit | any | S2-M guard (a)+(b) regression (same two panic inputs) |
| `fn_mtime` serde round-trip + old JSON missing field → `None` | unit | any | schema backward compat (FR1) |
| FN namespace preference (Win32 over DOS 8.3) | unit | any | synthetic multi-`$FILE_NAME` record → Win32 name |
| no admin → `Err(Privilege)` | unit | any | S2-M regression |
| full scan reads real SI/FN four times | **e2e manual, ELEVATED** | Windows admin | records have non-None si/fn btime+mtime; `cairn verify` passes |

**timestomp judgement correctness is NOT tested here** (that is S2-N′). S2-N tests only
that the four time fields are read and converted correctly — keeping this segment's review
focus single (raw-NTFS read + time conversion, no heuristic logic).

**Honest e2e gap (S2-M discipline):** this dev box is non-elevated; the real full-scan
read is an operator gate, not faked. Recorded as an unchecked item in the e2e evidence
file. Synthetic images already cover iteration, cap, bad records, conversion, namespace —
elevated only confirms "ntfs yields SI/FN per record on a real volume."

## 8. Acceptance gate

- `cargo fmt --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`;
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new
  dep — `fn_mtime`/conversion/iteration all use existing `ntfs`+`chrono`).
- `unsafe` appears in NO crate except `cairn-collectors-win`; core/collectors/cli stay
  `#![forbid(unsafe_code)]`.
- **DoS gate:** record-count hard cap proven by test to truncate + record in manifest +
  not panic; single bad record proven not to abort; S2-M short-read guards regression-green.
- **Time-conversion gate:** `filetime_to_utc` boundaries (0/underflow/overflow) all `None`
  no panic; known value → correct RFC3339.
- **Schema gate:** `fn_mtime` added; old JSON deserializes to `None` (compat test);
  no other schema change.
- **No scope creep:** no timestomp judgement, no path map, no full circuit breaker, no
  NFR9 thread/priority.
- Elevated e2e: real records carry non-None SI/FN four times; non-admin degrades;
  `--profile minimal` still skips mft; `cairn verify` passes; earlier stages unchanged.
- No golden-rule violation.

## 9. Explicitly OUT of scope (deferred, with rationale)

- **timestomp delta judgement** (SI/FN delta > threshold → Finding + ATT&CK T1070.006 +
  `reason`) → **S2-N′** (cairn-heur analyzer; golden rule 6 satisfied there).
- **Full path reconstruction / path map** (parent reference recursion + cycle guard) →
  its own later segment; timestomp does not depend on it.
- **NFR10 full circuit breaker** (peak-RAM + wall-clock ceiling across all collectors) →
  governance segment, where it bites across the board.
- **NFR9 max-threads / below-normal priority** (§19.1) → governance segment.
- **$J / USN** → S2-O. **Offline locked hives** → S2-P.
- **`access_time` / `mft_record_modification_time` (A and the second C of MACB)** → not
  needed for SI/FN timestomp delta; can be added when an analyzer needs them. S2-N reads
  only the two axes (btime, mtime) the timestomp heuristic compares.
