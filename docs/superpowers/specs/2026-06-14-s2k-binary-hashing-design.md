# S2-K: FR14 binary hashing (IOC sha256 for findings) — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-14.
> Authoritative spec: `cairn-SRS.md` (FR14, §5 PersistenceRecord.binary_sha256, NFR10).
> Predecessors: S2-C..J (persist/proc collectors, signed/signer mainline, scheduled tasks).
> **The stepping stone before raw-NTFS:** establishes the whole-file streaming read + size-cap
> pattern (NFR10's first concrete touch) that raw-NTFS resource governance will build on.

## Purpose

`binary_sha256` exists on `PersistenceRecord` but is always None. An analyst triaging a finding
has no IOC hash to pivot on (VirusTotal, threat intel). S2-K computes the sha256 of the binaries
behind findings and fills `binary_sha256`, so a suspicious persistence entry / process carries a
hash an analyst can look up. It also lands the first resource-governance guard (streaming read +
size cap), the pattern raw-NTFS will need.

## Scope

**In scope:**
- A pure streaming hasher in `cairn-collectors`: `hash_file_capped(path, max_bytes, open) ->
  Option<String>` — fixed-buffer streaming sha256 (constant memory), a size cap (skip → None
  for files over the cap), an injected `open` (Windows uses `std::fs::File`; tests inject an
  in-memory reader). Linux-CI-testable, no unsafe.
- `binary_sha256: Option<String>` added to `ProcessRecord` (PersistenceRecord already has it).
- A CLI enrichment step (in the `run` arm, after `run_live`, before writing output): for each
  record that produced a finding — matched by a STABLE KEY, not fragile path comparison — hash
  its `binary_path` and fill `binary_sha256`.
- `sha2` added to `cairn-collectors/Cargo.toml` (already a workspace dependency; zero supply-chain cost).

**Explicitly OUT of scope (deferred, with rationale):**
- **Hashing every binary on the host.** Only binaries behind a finding are hashed — IOC hashes
  are for pivoting on suspicious items, not a full host inventory; hashing hundreds of files is
  I/O-heavy and against the triage "fast, low-footprint" goal.
- **Zone.Identifier (MOTW) capture.** FR14 mentions it, but reading the `:Zone.Identifier` ADS
  is a distinct mechanism (NTFS alternate data stream) needing its own schema field; folded
  into the raw-NTFS stage (ADS is an NTFS concept). Deferred.
- **Hashing in the collector apply step (like signed/signer).** Scoring hasn't run at collect
  time, so "which records produced a finding" is unknown there. Hashing must happen post-analysis.
- **Finding-side hash field.** `EntityFile.sha256` exists but only covers file-backed (startup)
  findings; registry-backed and process findings have no entity sha256 slot. Filling
  `record.binary_sha256` covers all mechanisms. (A future pass could also mirror into
  EntityFile.sha256 for startup findings; not now.)
- **No new external dependency** beyond enabling `sha2` (already in the workspace).

## Architecture (data flow)

```
cairn-collectors/src/hash.rs  (NEW; #![forbid(unsafe_code)])
  hash_file_capped(path, max_bytes, open) -> Option<String>
    `open(path) -> Option<(u64 /*len*/, impl Read)>` — the injected probe returns the file
    length AND a streaming reader in one call (Windows: std::fs metadata().len() + File;
    tests: an in-memory (len, Cursor)). Returning len alongside the reader avoids needing Seek
    and keeps the cap check before any read.
    1. open(path) -> None  (missing/unreadable: graceful)
    2. if len > max_bytes -> None  (skip: don't stream a huge file)
    3. streaming: loop read into a fixed [u8; 64 KiB] buffer -> Sha256::update, until EOF
    4. Some(lowercase hex of the digest)
    PURE: no unsafe; constant memory (one fixed buffer regardless of file size);
    time-bounded (the cap stops a pathological multi-GB read). Injected `open` = Linux-CI-testable.

cli `run` arm  (after run_live, alongside stamp-host / sort-findings; orchestrator stays pure)
  enrich_hashes(&mut records, &findings, hash_fn):
    1. Build the set of record keys that produced a finding, from finding.entity:
         - registry-backed finding -> key = (entity.registry.key, entity.registry.value)
         - startup file finding     -> key = entity.file.path
         - process finding          -> key = entity.process.pid
    2. For each record whose stable key is in that set AND has a binary_path:
         record.binary_sha256 = hash_fn(binary_path)   // hash_file_capped with real fs + 256 MiB cap
    3. (records.jsonl now carries sha256 on the suspicious entries)
        ▼
  write records.jsonl + findings.jsonl + manifest  (existing)
```

**Stable-key correspondence (the core design point):** a finding does not carry a record id, but
its `entity` carries a STABLE identifier of the record it came from:
- `PersistenceRecord` ↔ persistence finding: `(location, value)` == `(entity.registry.key,
  entity.registry.value)` for registry-backed mechanisms; for the `startup` mechanism the entity
  is `EntityFile` and the key is its `path` (== record.binary_path/value).
- `ProcessRecord` ↔ process finding: `pid` == `entity.process.pid`.
This is matching on stable identity fields, NOT on raw command/path strings (which differ in
form between entity.data and the resolved binary_path — the S2-F lesson). Findings on a clean
host number in the single digits to low tens, so a linear scan to build the key set is cheap.

**Why CLI enrichment, not collector/analyzer:** hashing-the-findings needs findings to exist,
so it cannot run in the collector apply step (pre-scoring) nor in an analyzer (analyzers emit
findings, they don't re-touch records). It belongs in the same CLI post-processing layer as the
existing `stamp host onto findings` and `sort_findings` — the `run` arm's final shaping of the
`RunOutcome` before the reporter writes it. The orchestrator stays "collect + analyze" only.

**New / changed units:**
- `crates/cairn-collectors/src/hash.rs` (new): `hash_file_capped` + `DEFAULT_MAX_HASH_BYTES`
  const (256 MiB) + tests. Exposed `pub` for the CLI.
- `crates/cairn-collectors/Cargo.toml`: add `sha2.workspace = true`.
- `crates/cairn-collectors/src/lib.rs`: `pub mod hash;`
- `crates/cairn-core/src/record.rs`: `ProcessRecord` gains `binary_sha256: Option<String>`
  (after `signer`); fix the few ProcessRecord literals.
- `crates/cairn-cli/src/main.rs`: `enrich_hashes(records, findings)` helper + call it in the
  `run` arm after sort_findings, before building the manifest / writing output. (For `--dry-run`,
  enrichment still runs in memory but nothing is written — consistent with golden rule 4.)

**Layering:** the hasher is pure (injected `open`, no unsafe), testable on ubuntu CI. The only
FS touch is a read-only streaming read in the CLI (real `std::fs`). `#![forbid(unsafe_code)]`
holds across cairn-collectors and the CLI uses no unsafe.

## Resource governance (NFR10 first touch — the raw-NTFS stepping stone)

- **Constant memory:** a single fixed 64 KiB buffer feeds `Sha256::update` in a loop; peak RAM
  for hashing is bounded regardless of file size (unlike the existing `sha256_hex(&[u8])` which
  reads the whole file into a Vec — that one stays for small manifest outputs; binaries use the
  streaming path).
- **Size cap (256 MiB default):** a file larger than the cap is skipped (binary_sha256 stays
  None), so one pathological multi-GB binary cannot stall triage. 256 MiB covers essentially all
  legitimate executables; the few that exceed it (some games/IDE bundles) are not the IOC pivot
  targets that matter. The cap is a named const so raw-NTFS governance can later make it a
  `--profile`-driven setting (NFR9).
- This is the concrete first instance of "bound the tool's footprint" that SRS §19.1 calls for;
  raw-NTFS's $MFT/$J streaming will reuse the same fixed-buffer + cap shape.

## Error handling / graceful degrade

- `open` failure (missing/unreadable/locked) → None; never errors the run. A locked binary (e.g.
  a running exe with no share-read) simply yields no hash.
- Over-cap file → None (skipped, not an error).
- A read error mid-stream → None (defensive; never panics).
- A record with no binary_path, or no matching finding, is left untouched (binary_sha256 None).
- Determinism (NFR4): sha256 is deterministic for the same bytes; enrichment does not reorder
  records or findings.

## Security note (golden rules)

- Read-only: the hasher opens each binary read-only and streams it; no write/execute/modify
  (golden rule 3). It hashes only the literal `binary_path` already resolved by the collector
  (S2-F), never following or executing it.
- No evasion, no unsafe: pure `std::fs` + `sha2`.
- Footprint: streaming + cap actively bound the tool's own resource use (golden rule 4 spirit:
  minimize footprint).

## Testing

Pure hasher → full TDD with an injected reader; enrichment correspondence → unit tests with
constructed records + findings.

- **hash_file_capped (pure, injected reader):**
  - known bytes → known sha256 (e.g. "" → e3b0c442…; "abc" → ba7816bf…). Lock the well-known
    vectors so the streaming loop is proven correct.
  - a file at exactly the cap → hashed; one byte over the cap → None (skipped).
  - open failure → None.
  - a multi-chunk input (larger than the 64 KiB buffer) → same hash as a one-shot hash of the
    same bytes (proves the streaming loop accumulates correctly across reads).
- **enrich_hashes (pure, injected hash_fn):**
  - a persistence finding with entity.registry (key,value) matching a record → that record's
    binary_sha256 filled; a record with no finding → left None.
  - a process finding (pid) matching a process record → filled.
  - a startup finding (file.path) → matched and filled.
  - a record whose binary_path is None → not hashed (None).
  - the injected hash_fn is called only for matched records (assert call count / set).
- **schema round-trip (cairn-core):** ProcessRecord with binary_sha256 Some/None round-trips.
- **e2e (manual-then-self-run, Windows):** `cairn run --target live --only persist,process`;
  records that produced a finding carry a real `binary_sha256` (64-hex); records with no finding
  stay None; an over-cap or unreadable binary stays None gracefully; `cairn verify` passes; the
  count of hashed records ≈ the count of distinct find-producing binaries. Spot-check one hash
  against an independent sha256 of the same file.

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (sha2 already in
  the workspace; no new external crate).
- `unsafe` appears in no crate except `cairn-collectors-win`; cairn-collectors + cli stay
  unsafe-free (`#![forbid(unsafe_code)]` where declared).
- A real live run fills `binary_sha256` for find-producing binaries (streaming, capped),
  leaves None for non-findings / over-cap / unreadable; `cairn verify` passes; earlier stages
  unchanged.
- No golden-rule violation (read-only streaming, no evasion, footprint-bounded); no scope creep
  (no full-host hashing, no MOTW, no new dep).
- Linux CI: the pure hasher + enrichment tests run on ubuntu (injected reader/hash_fn); any
  Windows-only path carries `#[cfg(windows)]` / the real fs is only touched in the CLI.

## Non-goals / future hooks

- **Zone.Identifier / MOTW** capture (`:Zone.Identifier` ADS) — folded into the raw-NTFS stage.
- **Mirror hash into EntityFile.sha256** for startup findings (richer finding-side IOC) — optional later.
- **`--profile`-driven cap** (NFR9 resource governance) — when raw-NTFS lands the governance framework.
- **Full-host hashing mode** (an explicit opt-in flag) if an inventory use case ever appears.
- Remaining Stage 2+: raw-NTFS ($MFT/$J/offline hive — reuses this streaming+cap pattern), WMI
  subs, offline artifacts (Amcache/Shimcache/Prefetch), FR15/FR18 output packaging.
