# S2-M — raw volume read primitive + $MFT minimal proof — Design

> Sub-segment of Stage 2 (raw-NTFS second half). Authoritative spec: `cairn-SRS.md`
> (§4 mft_collector, FR12, §8 NFR9-12, §11 raw-NTFS method, §19.1). Decomposition parent:
> `docs/superpowers/specs/2026-06-15-raw-ntfs-decomposition-and-s2l-design.md` (Part A).
> Predecessor: S2-L (profile/only wiring) — installed the `--profile` switch this builds on.
>
> **This is the FIRST raw-NTFS sub-segment.** It is Cairn's first `unsafe`, first admin
> requirement, first raw `\\.\C:` access. Its job is to DE-RISK the rest (S2-N $MFT MACB,
> S2-O $J, S2-P hives) by proving the read-path end-to-end with the smallest possible
> forensic surface. It deliberately does NOT do MACB/timestomp — that is S2-N.

---

## Purpose

Build a minimal `unsafe` `VolumeReader` in `cairn-collectors-win` that opens `\\.\C:`
read-only and presents it as `std::io::Read + Seek`. On top of that safe wrapper, run the
`ntfs` crate (pure-safe) to parse the volume far enough to prove the chain works: count the
`$MFT` records and list the first few file names, emitted as `Record::FileMeta`. This proves
"VolumeReader works + `ntfs` accepts our reader + we read real NTFS structures + a Record
flows to the manifest/output" without touching MACB, timestomp, $J, or hives.

## The four locked design decisions (from the brainstorm)

1. **Minimal primitive, self-controlled.** `cairn-collectors-win` owns ONE small `unsafe`
   module (`volume.rs`): open `\\.\C:`, read sectors, present `Read+Seek`. NTFS parsing is
   the `ntfs` crate's job (safe). unsafe surface = open handle + ReadFile + SetFilePointerEx
   + sector alignment, nothing more. (CLAUDE.md: "isolate unsafe behind a small reviewed
   module with a safe wrapper".)
2. **`ntfs` 0.4 (Colin Finck)** as the NTFS parser — trait-based (consumes the `Read+Seek`
   we supply; does NOT self-open the volume), no RustSec advisory. SRS §4/§11/§17 list it as
   a primary option. Carries forward to S2-N/O. (S2-P hives use a different crate, out of
   scope here.)
3. **Smallest proof = `$MFT` record count + first N file names**, emitted as
   `Record::FileMeta`. Walks the full collector→output path; stops short of MACB/timestomp.
4. **Privilege contract = skip + manifest reason.** No admin/SeBackup → the mft collector
   returns `Err(Privilege)`; the orchestrator already records it as a `SourceEntry` with
   `errors` and continues (golden rule 8). Zero new degrade machinery.

## What the existing codebase already gives us (framework fit)

Verified by reading the code on 2026-06-16, NOT assumed:

- **`Record::FileMeta` already exists** (`cairn-core/src/record.rs:80`, `FileMetaRecord`).
  SRS §4 maps `mft_collector → Record::FileMeta`. So S2-M has **no `cairn-core` schema
  change** — it populates an existing variant.
- **Graceful degrade is free.** `orchestrator::run_live` (`cairn-core/src/orchestrator.rs`)
  already turns a collector `Err` into a `SourceEntry { method, errors, .. }` + a warning,
  then continues. SRS SourceEntry schema already includes `"method":"raw_ntfs"`. The
  privilege contract lands entirely on this existing mechanism.
- **The profile switch is wired and waiting** (S2-L). `select_modules` +
  `selection::profile_base` (`cairn-core/src/selection.rs:36`) is the single place the
  profile→module mapping lives; the CLI run arm builds collectors from `selection.selected`
  via `AVAILABLE` (`cairn-cli/src/main.rs:575`) + per-name `if` blocks. S2-M plugs `"mft"`
  into both, AND makes `profile_base` diverge (see "Framework tension ①" below).
- **The unsafe-crate pattern is established.** `cairn-collectors-win` already has RAII handle
  guards (`TokenHandle` in `privilege.rs`), the `cfg(windows)` / `cfg(not(windows))` split,
  and the "every WinAPI call wrapped, never panic, degrade to `Err`" convention. `VolumeReader`
  follows it exactly — new module, same shape.

## Architecture

```
cairn-collectors-win/src/volume.rs          ← the ONLY new unsafe. Two cfg arms:
  #[cfg(windows)]  VolumeReader: CreateFileW(\\.\C:) handle (RAII guard)
                   impl std::io::Read  via ReadFile   (sector-aligned, bounded)
                   impl std::io::Seek  via SetFilePointerEx
  #[cfg(not(windows))]  open() -> Err(Unsupported)  (workspace still builds/tests on Linux CI)

cairn-collectors/src/mft.rs                 ← #![forbid(unsafe_code)]. MftCollector:
  - require admin + se_backup via CollectCtx; else Err(Privilege)  → orchestrator skips
  - open VolumeReader (from cairn-collectors-win) for the target volume
  - ntfs::Ntfs::new(&mut reader) → iterate $MFT records (STREAMING, not collect-then-count)
  - count records; take first N file names; emit Vec<Record::FileMeta> (count + names only)
  - sources(): one SourceEntry { artifact:"mft", method:"raw_ntfs", path:"\\.\C:" }

cairn-core/src/selection.rs                 ← profile_base diverges: minimal EXCLUDES raw-NTFS
cairn-cli/src/main.rs                        ← AVAILABLE gains "mft"; one more if-block + mirror
```

**Layering invariant:** `unsafe` appears in NO crate except `cairn-collectors-win`. `cairn-core`,
`cairn-collectors`, `cairn-cli` stay `#![forbid(unsafe_code)]`. The mft collector depends only
on the safe `VolumeReader` wrapper + the `ntfs` crate.

## VolumeReader — the unsafe module (the heart of S2-M)

### Read-only invariant (golden rules 3 + 4 — hard requirement)

`CreateFileW` MUST be opened with:
- `dwDesiredAccess = GENERIC_READ` only (NEVER any write/append/delete right),
- `dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE` (the volume is in use; do not block it),
- `dwCreationDisposition = OPEN_EXISTING`,
- no `FILE_FLAG_*` that could modify state.

This is the literal encoding of "Collectors never modify the host" (golden rule 3) and
"Never modify source artifacts" (golden rule 4). The code-review gate MUST verify these flags.

### RAII handle guard

A `VolumeHandle(HANDLE)` newtype with a `Drop` that `CloseHandle`s exactly once — identical
discipline to `TokenHandle` in `privilege.rs`. INVARIANT documented at the guard: holds a
valid open handle from `CreateFileW`; closed once on drop; never constructed with an invalid
handle (open returns `Err` instead).

### Sector alignment

Raw volume reads via `ReadFile` on `\\.\C:` must be aligned to the volume's logical sector
size (offset and length both multiples of the sector size; typically 512 or 4096). The
`Read`/`Seek` impl hides this: callers (the `ntfs` crate) see a normal byte stream;
`VolumeReader` buffers/aligns internally. The sector size is queried at open
(`Win32_System_Ioctl` / `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, or `GetDiskFreeSpace`) — **the
exact API to query sector size is a TASK-0 verification item** (see below); a safe default
(read in 4096-aligned blocks, which is a multiple of 512) is the fallback if the query is
unavailable.

### Bounded reads (NFR10 spirit, attacker view)

Each `ReadFile` is capped at a fixed maximum block size (e.g. 1 MiB) so a single read can
never request an unbounded buffer. This is the *minimal* nod to NFR10 — NOT the full circuit
breaker, which S2-N owns (see "Deferred").

## Framework tensions resolved in S2-M (the non-obvious work)

### ① `minimal` MUST skip raw-NTFS — connecting the S2-L hook (SRS §19.1)

S2-L's `profile_base` currently returns the full `available` set for ALL three profiles.
SRS §19.1 defines `--profile minimal = "SKIP raw-NTFS $MFT/$J full parse"`. The moment S2-M
registers `mft`, `profile_base` MUST diverge: `minimal` selects the live set but NOT raw-NTFS
collectors. **This is not scope creep — it is the S2-L hook being connected as designed.**

Mechanism (chosen for extensibility, so S2-N/O/P are automatically skipped too): introduce a
small classification rather than a hardcoded `"mft"` string. A `const RAW_NTFS: &[&str]` set
in `selection.rs` (initially `["mft"]`), and `profile_base(Minimal, available)` returns
`available` filtered to exclude any name in `RAW_NTFS`. `Standard`/`Verbose` keep the full
set. When S2-N/O/P add `"mft_macb"`/`"usn"`/`"hive"` to `RAW_NTFS`, `minimal` skips them with
no further change.

### ② Attacker view: malformed NTFS as a DoS vector (CLAUDE.md hard requirement)

**Entry point:** the raw bytes of the on-disk NTFS structures. On a compromised host the
attacker may control `$MFT` content — a deliberately corrupt MFT (huge attribute-length
fields, cyclic references, absurd record counts) could drive a parser to OOM or an infinite
loop. For a tool whose explicit promise is "don't take the production host down" (SRS §19),
that is a denial-of-service against the responder.

**Mitigations in S2-M:**
- The `ntfs` crate's behaviour on malformed input (panic vs `Err`) is **TASK-0 verification**
  — we do not assume it is robust.
- `VolumeReader` caps single-read size (above).
- The mft collector caps the number of records it will iterate (a configurable ceiling;
  default generous but finite) — the minimal NFR10 nod. Hitting the cap is recorded as a
  `SourceEntry` note ("record cap reached"), not a panic.
- Any parse error → `Err(Collector{..})`, never `panic!` (matches the existing collector
  convention; the orchestrator degrades gracefully).

**Residual risk:** a malformed volume could still slow the run before the cap trips; the full
circuit breaker / RAM ceiling (NFR10) that bounds wall-clock + peak RAM under adversarial
input is S2-N's job, not fully closed here. Documented, not hidden.

### ③ Streaming from day one (SRS §2 memory model, "MFT iterate")

Even though the proof only counts records, the collector MUST iterate the `$MFT` with the
`ntfs` streaming API — NOT `collect()` into a `Vec` then count. SRS line 46 requires "stream
records where possible (EVTX, MFT iterate); avoid loading whole artifacts." Writing it
streaming now means S2-N (full MACB) does not rewrite the iteration. Use the right shape at
the start.

## Privilege / graceful degrade (golden rule 8)

- mft collector first checks `ctx.admin && ctx.se_backup`; if not both, returns
  `Err(Privilege { what: "mft", need: "Administrator + SeBackupPrivilege" })`.
- `orchestrator::run_live` records this as `SourceEntry { artifact:"mft",
  method:"raw_ntfs", errors:[..] }` and continues — other collectors unaffected.
- Non-admin CI stays green (the collector degrades; it never panics, never aborts the run).
- Elevated e2e is the NEW validation step: it must be run from an Administrator shell on a
  real Windows host (prior segments were all non-admin). This is a manual gate, documented in
  the plan, not a CI job.

## Error handling

- Volume open failure (not elevated, volume missing, off-platform) → `Err`, degrade.
- `ntfs` parse failure → `Err(Collector{..})`, degrade, never panic.
- Off-platform (`cfg(not(windows))`) → `VolumeReader::open` returns `Err(Unsupported)`; the
  collector degrades; the workspace still compiles + tests on Linux CI.
- Determinism (NFR4): "first N file names" must be taken in a deterministic order (by MFT
  record number ascending), so output is reproducible.

## Security note (golden rules consolidated)

- **No evasion** (rule 1): plain documented WinAPI (`CreateFileW`/`ReadFile`/`SetFilePointerEx`);
  no syscall trickery, no hook bypass. The EDR SHOULD see a benign tool reading a volume.
- **Read-only** (rules 3, 4): `GENERIC_READ` + `OPEN_EXISTING` only; verified at review.
- **Footprint** (rule 4): raw read does not modify; no USN-journal disturbance from a read.
- **Explainability**: the `Record::FileMeta` provenance + the `SourceEntry { method:"raw_ntfs" }`
  make it auditable what was read and how.

## TASK-0 verification items (must be resolved by the FIRST plan task, before building)

These are **not assumptions to encode** — they are unknowns to settle empirically with a
throwaway probe (`cargo add ntfs`, a tiny `main`), because I have not compiled `ntfs` 0.4:

1. Does `ntfs` 0.4 accept an arbitrary `&mut impl Read + Seek` (our `VolumeReader`), and what
   is the exact API to (a) construct, (b) reach `$MFT`, (c) iterate records, (d) get a file
   name? Confirm it does NOT self-open the volume.
2. Does `ntfs` 0.4 return `Result` (not panic) on a truncated/garbage reader? Probe with a
   deliberately bad reader.
3. The exact WinAPI to query the volume's logical sector size (which `windows` crate feature).
   If costly/unavailable, fall back to fixed 4096-aligned blocks.
4. Whether reaching `$MFT` requires us to parse the boot sector for the MFT cluster, or `ntfs`
   does it from the volume start. (Expected: `ntfs` handles it, but verify.)

If TASK-0 shows `ntfs` 0.4 cannot eat an external `Read+Seek` or panics on bad input, STOP and
revisit crate choice (`ntfs-forensic`/`ntfs-reader`) before writing the collector.

## Testing

- **VolumeReader (unit, Linux + Windows):** `cfg(not(windows))` → `open()` returns
  `Err(Unsupported)`. The `Read`/`Seek` sector-alignment math is unit-tested against an
  in-memory fake byte source (no real volume needed) — feed a `Cursor<Vec<u8>>` through the
  alignment layer and assert reads land on aligned boundaries and return correct bytes.
- **selection (pure, any platform):** `profile_base(Minimal, ["proc","net","persist","mft"])`
  excludes `"mft"`; `Standard`/`Verbose` include it. `--only mft` selects only mft. Add to the
  existing `selection.rs` test module.
- **mft collector (unit):** with a fake non-elevated `CollectCtx` → `Err(Privilege)` (no host
  access attempted). The streaming/count logic is unit-tested by feeding `ntfs` a small
  synthetic NTFS image fixture IF one is feasible; otherwise the count path is covered by the
  e2e (documented honestly — no fake-passing test).
- **cli wiring (smoke):** `built_collector_names` mirror includes `"mft"` when selected;
  `--profile minimal` excludes it; `--only mft` includes only it.
- **e2e (manual, Windows, ELEVATED — the new gate):**
  `cairn run --target live --only mft` from an Administrator shell → records contain
  `Record::FileMeta` entries (count > 0, first N names present); manifest SourceEntry shows
  `method:"raw_ntfs"`; `cairn verify` passes.
  Non-elevated: `cairn run --only mft` → mft skipped, manifest records the privilege reason,
  run still succeeds, `cairn verify` passes.
  `cairn run --profile minimal` → mft NOT in selected modules (SRS §19.1).

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean.
- New dependency `ntfs` 0.4 added with pinned version + committed `Cargo.lock`; `cargo audit`
  shows no advisory for it. (A new external forensic-parsing dep, justified by SRS §4/§17;
  documented in the commit.)
- `unsafe` appears in NO crate except `cairn-collectors-win`; cli/core/collectors stay
  `#![forbid(unsafe_code)]`. The unsafe is confined to `volume.rs` and every `unsafe` block
  carries a `// SAFETY:` justifying it.
- `CreateFileW` verified read-only (`GENERIC_READ` + `OPEN_EXISTING`, no write flag) at review.
- Elevated e2e: a real raw-NTFS read produces `Record::FileMeta`; non-elevated degrades with a
  recorded reason; `--profile minimal` skips mft; `cairn verify` passes; earlier stages
  unchanged.
- No golden-rule violation. No scope creep (no MACB/timestomp, no $J, no hives, no full
  circuit breaker, no rayon).

## Explicitly OUT of scope (deferred, with rationale)

- **MACB times + SI/FN timestomp delta** → S2-N. (S2-M proves the read path; forensic fields
  are the next slice.)
- **$J / USN** → S2-O. **Offline locked hives** → S2-P.
- **Full circuit breaker / RAM + wall-clock ceiling under adversarial input (NFR10)** → S2-N,
  where full $MFT parse makes it bite. S2-M does the minimal nod (read cap + record cap).
- **Thread cap / rayon pool / IO priority (NFR9 rest)** → the sub-segment that introduces
  parallel parsing. Collectors still run serially; a cap would gate nothing.
- **VSS fallback (`--use-vss`, SRS D3)** → later. S2-M is raw-NTFS only (the documented default).
- **Per-volume target selection (only `C:` for now)** → the target plumbing can generalize
  later; S2-M reads the system volume.
