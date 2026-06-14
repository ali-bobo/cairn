# S2-F: binary_path candidate normalization (unquoted-cmdline truncation) — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-13.
> Authoritative spec: `cairn-SRS.md` (§4 persist_collector, §5 PersistenceRecord, §17 D6).
> Predecessors: S2-C (persist collector + `extract_binary_path`), S2-D (verify_file +
> signed backfill + service-ImagePath normalization), S2-E (proc signed).
> First of the D6/D7 trilogy: **S2-F (this, problem A) → S2-G (signer identity, problem B)
> → S2-H (heuristic calibration, problem C)**.

## Purpose

`extract_binary_path` truncates an UNQUOTED command line that contains spaces:
`C:\Program Files\Docker\Docker\Docker Desktop.exe` (no surrounding quotes) is clipped at
the first space to `C:\Program`. The truncated path does not exist on disk, so S2-D's
`verify_file` returns None and `signed` stays None. S2-D's live run measured this: Docker
and similar unquoted Run-key entries lost their signature coverage. This sub-segment makes
`extract_binary_path` produce a list of CANDIDATE paths (longest first), and has the persist
collector pick the first candidate that actually exists on disk — recovering the correct
binary path (and thus the signature) for unquoted paths, while keeping the parsing logic
pure and Linux-CI-testable (the filesystem probe is injected at the collector boundary).

## Scope

**In scope:**
- A pure candidate generator: `extract_binary_path_candidates(cmdline, lookup) -> Vec<String>`
  (the existing quote-stripping + %env% expansion, now emitting all reasonable split points
  for an unquoted path, longest first). No filesystem access — Linux-CI-testable.
- The persist collector selects the first candidate that exists, via an INJECTED
  `exists: impl Fn(&str) -> bool` (Windows uses `Path::exists`; tests inject a fake). If no
  candidate exists, it falls back to the first whitespace token (today's behavior) — never
  None, never a regression.
- Only the persist collector. Quoted command lines are unchanged (single candidate).

**Explicitly OUT of scope (deferred, with rationale):**
- **proc image paths** — `ProcessRecord.image` comes from S2-E's `QueryFullProcessImageNameW`,
  which already returns a full unambiguous path; no truncation problem there.
- **Signer identity / catalog-signed false reports** — that is problem B, sub-segment S2-G.
- **Heuristic calibration** (Winlogon allowlist, AppData trust) — problem C, sub-segment S2-H.
- The existing `extract_binary_path` public wrapper signature may change (it currently
  returns `Option<String>`); callers within persist are updated. No external crate depends
  on it (`pub(crate)`).

## The candidate model

A Windows command line's first token is ambiguous ONLY when unquoted and containing spaces.
The OS (CreateProcess) resolves this by trying each successive prefix as `<prefix>` and
`<prefix>.exe` until one names a real file. We mirror the "try each successive prefix" idea
but keep it pure: generate the candidates, let the collector probe.

**Quoted** (`"C:\Program Files\App\app.exe" -x`): the closing quote is unambiguous. One
candidate: `C:\Program Files\App\app.exe`. (Unchanged from today.)

**Unquoted** (`C:\Program Files\Docker\Docker\Docker Desktop.exe`): split on spaces; emit the
prefix up to each space boundary, LONGEST FIRST:
```
candidate 1: C:\Program Files\Docker\Docker\Docker Desktop.exe   (whole string)
candidate 2: C:\Program Files\Docker\Docker\Docker               (up to last space)
candidate 3: C:\Program Files\Docker\Docker\Docker Desktop.exe ... (each earlier space)
...
candidate N: C:\Program                                          (first token — today's value)
```
Precisely: for an unquoted string with spaces at byte positions s1 < s2 < ... < sk, the
candidates are the substrings `[0..len]`, `[0..sk]`, ..., `[0..s1]` — i.e. the whole string
first, then progressively shorter prefixes ending just before each space, with the bare
first token last. Longest first so the collector prefers the most complete real path.

**No spaces** (`C:\Windows\system32\svc.exe` or `app.exe`): one candidate (the token itself).

**%env% expansion** applies to every candidate (as today).

**Never empty:** an empty/whitespace-only cmdline yields an empty Vec (the collector then
leaves binary_path None, as today).

## Architecture (pure / FS boundary)

```
extract_binary_path_candidates(cmdline, lookup: impl Fn(&str)->Option<String>) -> Vec<String>
   pure; quoted -> 1 candidate; unquoted -> longest-first prefixes; %env% expanded
   (lives next to extract_binary_path_with; Linux-CI-testable)
        │
        ▼
persist collector — selection (injected FS probe):
   pick_binary_path(candidates: &[String], exists: impl Fn(&str)->bool) -> Option<String>
     return the first candidate for which exists(c) is true;
     else return candidates.last() (the bare first token — today's behavior);
     else (empty candidates) None.
   Windows: exists = |p| std::path::Path::new(p).exists()
   tests:   exists = a fake set membership
        │
        ▼
make_record / readers use pick_binary_path(...) to fill binary_path
```

**New / changed units:**
- `crates/cairn-collectors/src/persist.rs`:
  - `extract_binary_path_candidates` (new pure fn; the candidate generator).
  - `pick_binary_path` (new pure fn; selection given an injected `exists`).
  - `make_record` (or the readers) now build binary_path via candidates + a real `exists`.
  - The existing `extract_binary_path` / `extract_binary_path_with` either become thin
    wrappers over the candidate generator (return `candidates.into_iter().next()`, i.e. the
    longest candidate — preserving "best guess without FS") OR are removed if all callers
    move to the candidate path. Decide during implementation; keep the public surface minimal.

**Layering:** candidate generation is pure (no FS, no env mutation — env is injected),
testable on ubuntu CI. The only FS touch is the injected `exists` in the collector, which on
Windows is `Path::exists` (a read-only stat — golden rule 3 holds). `#![forbid(unsafe_code)]`
unchanged; no unsafe added.

## How this restores signed coverage

After selection, an unquoted Run-key entry like `C:\Program Files\Docker\...\Docker Desktop.exe`
resolves to the real file (candidate 1 exists) instead of `C:\Program` (today). S2-D's
`verify_file` is then handed the real path and returns a real `signed` value rather than None.
This directly lifts the signed coverage S2-D measured, and (via the S2-D/S2-E amplifiers) lets
a genuinely unsigned unquoted dropper in a suspicious path surface correctly.

## Error handling / graceful degrade

- Candidate generation never panics: it does byte-boundary-safe slicing on space positions
  (spaces are ASCII), returns an empty Vec for empty input.
- Selection is total: no candidate exists -> fall back to the bare first token (today's
  value), so behavior never regresses to None where it previously had a value.
- The injected `exists` is best-effort: an unreadable path simply returns false, moving to
  the next candidate; the fallback covers "nothing exists" (e.g. a deleted binary).
- Determinism (NFR4): selection is deterministic given the same FS; candidate order is fixed
  (longest first). Output ordering unaffected.

## Security note (golden rules)

- Read-only: the only filesystem interaction is `Path::exists` (a stat); no file is opened,
  read, or modified (golden rule 3). No host modification.
- No evasion, no unsafe. Pure parsing + a read-only existence probe.
- A crafted Run-key value cannot cause traversal or unexpected access: we only `exists`-check
  literal candidate substrings of the registry value; we never follow, open, or execute them.

## Testing

Pure logic → full TDD; the FS probe → injected fake in unit tests, real `Path::exists` in a
Windows smoke/e2e.

- **candidate generation (pure):**
  - quoted path + args -> exactly one candidate (the quoted content).
  - unquoted path with spaces -> candidates longest-first, whole string first, bare token last.
  - unquoted no spaces -> one candidate.
  - %env% expansion applied to candidates (`%ProgramFiles%\X Y\a.exe` -> expanded, still split).
  - empty / whitespace-only -> empty Vec.
  - adversarial (lone quote, trailing spaces, `%%`) -> no panic.
- **selection (pure, fake exists):**
  - first (longest) candidate exists -> chosen.
  - only a shorter candidate exists -> that one chosen (longest-first respected).
  - none exist -> fall back to the bare first token (candidates.last()).
  - empty candidates -> None.
- **persist collector wiring:** a record whose cmdline is an unquoted spaced path resolves
  binary_path to the existing full path (fake exists), not the truncated token.
- **regression:** quoted paths produce the SAME binary_path as before (single candidate).
- **e2e (manual, Windows):** an unquoted Run-key entry (e.g. Docker, if present) now gets the
  full binary_path and a real `signed` value (was None); quoted entries unchanged; signed
  coverage at least as high as S2-E; `cairn verify` passes; S1/S2-A..E paths unchanged.

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new dep).
- `unsafe` appears in NO crate except `cairn-collectors-win`; persist stays
  `#![forbid(unsafe_code)]`.
- A real live run resolves unquoted spaced Run-key paths to their real binary and fills
  `signed`; quoted paths unchanged; earlier stages unchanged.
- No golden-rule violation (read-only stat, no evasion); no scope creep (proc untouched, no
  signer identity, no heuristic calibration — those are S2-G / S2-H).
- Linux CI dead-code: Windows-only helpers carry `#[allow(dead_code)]` as needed (the
  S2-C..E lesson).

## Non-goals / future hooks

- **S2-G (next, problem B):** signer-identity extraction (WinTrust advanced API) to resolve
  catalog-signed false reports and distinguish "Microsoft-signed" from third-party.
- **S2-H (problem C):** heuristic calibration — Winlogon default allowlist, AppData
  publisher/signer trust (uses S2-G), with a benign baseline.
- Later: Scheduled Tasks, WMI subscriptions, raw-NTFS, offline artifacts, FR14 hashing.
- `.lnk` target resolution for the startup mechanism (a startup `.lnk` points at the real
  binary) remains a separate future enhancement, related but distinct from cmdline splitting.
