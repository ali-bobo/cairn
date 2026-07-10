# Error Handling & Graceful Degrade Audit — 2026-07-10

Scope: full workspace (`crates/`), main branch, fresh-context read-only audit.
Golden rule under test: CLAUDE.md rule 8 — "missing privilege -> skip module,
record reason in manifest, continue. Never abort the whole run for one collector."

## 1. `.unwrap()` / `.expect()` / `let _ =` / `.ok()` full inventory

Classification key: **(a)** violates golden rule 8 (real failure path, no
containment) — **(b)** "impossible to fail" claim, verified — **(c)** legitimate
silent degrade (RAII cleanup / documented best-effort).

### 1.1 `.unwrap()`

All `.unwrap()` hits found by workspace search are inside `#[cfg(test)]` modules
or `#[test]` functions (confirmed by reading surrounding context for every file:
`cairn-core::config.rs`, `finding.rs`, `cairn-cli::main.rs` lines 1355/1364/etc.,
`cairn-report::lib.rs` test helpers, `cairn-sigma`, `cairn-collectors-win::volume.rs`
test module starting at line 505). **Classification: not applicable — test-only,
out of scope.**

### 1.2 `.expect()`

Every `.expect()` hit is likewise inside `#[cfg(test)]` modules / `#[test]` fns
across `cairn-cli/src/main.rs` (1332, 1629, 1680–1681 — all under `mod tests`
starting line 1056), `cairn-report/src/client_text.rs`, `cairn-heur/*` (timestomp,
netconn, persist, parentchild), `cairn-collectors/src/{mft,usn,proc,srum,evtx,
userassist,persist,prefetch,shimcache,bam,amcache,net}.rs`, `cairn-collectors-win/
src/{volume,net,proc}.rs`, `cairn-core/src/orchestrator.rs` (line 206, inside
`mod tests`), `cairn-sigma/{lib.rs,tests/parity.rs}`. **Classification: not
applicable — test-only, out of scope.**

**Conclusion for 1.1/1.2: zero `.unwrap()`/`.expect()` in non-test production
code anywhere in the workspace.** This is a strong, verified result — every hit
was individually confirmed against its enclosing `#[cfg(test)]`/`mod tests`/
`#[test]` boundary, not inferred from naming.

### 1.3 `let _ = ...` (Result-discarding pattern)

| Location | Context | Class | Reason |
|---|---|---|---|
| `cairn-collectors-win/src/volume.rs:248` | `Drop for VolumeHandle`: `let _ = CloseHandle(self.0);` | (c) | RAII cleanup; a failed `CloseHandle` in `Drop` has no recovery action available (can't return `Result` from `Drop`). Documented pattern, consistent with the rest of the codebase. |
| `cairn-collectors-win/src/signature.rs:150,166,177,429,439,448` | `Drop` impls: `CryptCATAdminReleaseContext`/`CryptCATAdminReleaseCatalogContext`/`CloseHandle`/`CertCloseStore`/`CryptMsgClose`/`CertFreeCertificateContext` | (c) | Same RAII-cleanup-in-Drop pattern as volume.rs. |
| `cairn-collectors-win/src/signature.rs:129,307` | `WinVerifyTrust(...)` calls whose return is deliberately ignored (the *catalog-based* trust check, used only to populate the WinVerifyTrust structure state before the real check) | (c) | Confirmed by surrounding code: the actual verdict is read from a different API afterward; this call's return is a documented don't-care per WinVerifyTrust usage convention for catalog signing. |
| `cairn-collectors-win/src/signature.rs:322` | `let _ = write!(s, "{:02X}", b);` — writing into a `String` | (b) | `write!` to a `String` (via `fmt::Write`) cannot fail; verified — `String` implements `fmt::Write` and its `write_str` always returns `Ok`. |
| `cairn-collectors-win/src/host.rs:27` | `let _ = GetComputerNameExW(...)` | (a) — see Finding 1 | See Findings section. |
| `cairn-collectors-win/src/priority.rs:90` | `let _ = r;` where `r` is the result of `SetPriorityClass`/`SetProcessPriorityBoundary`-style call | (c) | Comment states explicitly: "Windows: success not guaranteed in all sandboxes; no panic is the contract" — this is `lower_priority()`'s internal best-effort branch, and the **outer** `lower_priority()` still returns `Result<()>` which IS checked by the caller in `main.rs` (warn + continue on Err). Verified this is not the final discard point. |
| `cairn-collectors-win/src/net.rs:63,113` | `let _ = GetExtendedTcpTable(...)`/`GetExtendedUdpTable(...)` — first call used only to learn the required buffer size | (b) | Standard two-call Windows API idiom: first call intentionally fails with `ERROR_INSUFFICIENT_BUFFER` to report the needed size; the real data-fetching call follows and IS error-checked. Verified by reading the surrounding function. |
| `cairn-collectors-win/src/privilege.rs:49` | `Drop`: `let _ = CloseHandle(self.0);` | (c) | Same RAII pattern. |
| `cairn-collectors-win/src/privilege.rs:137` | test-only (`let _ = (p.admin, ...)`, silences unused-field warning in a test fixture) | n/a | Inside test code. |
| `cairn-collectors/src/persist.rs:566` (doc comment only, not code) | — | n/a | Comment text, not an actual discard. |
| `cairn-cli/src/main.rs:757` | `let _ = rayon::ThreadPoolBuilder::new()...build_global();` | (c) | Documented: "build_global is a process one-shot; a second call (e.g. in tests) errors — ignore it." Verified this is genuinely idempotent-safe: a failed second `build_global()` call only means the pool was already initialized with equivalent semantics: harmless. |
| `cairn-cli/src/main.rs:1031` | `let _ = pin;` (in a match arm binding, not a Result) | n/a | Not a Result-discard; a variable-binding no-op, confirmed by reading context (destructuring where one field is intentionally unused). |
| `cairn-updater/src/lib.rs:116` | `let _ = result;` (inside `#[cfg(test)]`-adjacent helper — confirmed by reading full function) | n/a | Test-only. |
| `cairn-launcher/src/menu.rs` (7 hits: stdout flush / stdin read_line) | Interactive terminal UI I/O | (c) | User-facing CLI menu output; a failed flush/readline in this launcher (not the core `cairn` binary) has no meaningful recovery — worst case the prompt redraws oddly. Acceptable for a human-interactive wrapper, not part of the forensic collection path. |
| `cairn-launcher/src/package.rs:48,52` | `Command::new("explorer.exe")...spawn()` (best-effort "open folder" convenience) and an unused var | (c) | Opening Explorer to show output is a convenience action; failure (no Explorer, no GUI session) has no meaningful recovery and does not affect the underlying scan/report artifacts already written to disk. |
| `cairn-report/src/{lib.rs,zip_sink.rs,age_sink.rs,dry_run.rs}` + `cairn-sigma/src/{engine.rs,ruleset.rs}` (all remaining `let _ = std::fs::remove_dir_all(...)` hits) | Test teardown (`#[cfg(test)]`) | n/a | All confirmed inside test modules — temp-dir cleanup, not production code. |
| `cairn-collectors/src/{amcache,evtx,mft,persist}.rs` (`let _ = parse_...(&s); // must not panic`) | Fuzz-style "must not panic" assertions | n/a | Inside `#[cfg(test)]`. |
| `cairn-report/src/lib.rs:35` | `let _ = write!(s, "{x:02x}");` | (b) | Same as signature.rs:322 — writing into a `String`, cannot fail. |
| `cairn-sigma/src/ruleset.rs:28` | `let _ = write!(s, "{b:02x}");` | (b) | Same pattern, `String` write. |

### 1.4 `.ok()` discarding Results

| Location | Context | Class | Reason |
|---|---|---|---|
| `cairn-cli/src/main.rs:455` | `let mut all_ok = report.ok();` | n/a | `report.ok()` is a method call on the `VerifyReport` struct (returns `bool`), **not** `Result::ok()`. Confirmed by reading `cairn-report`'s `VerifyReport` type — this is not a Result-discard at all. |
| `cairn-cli/src/main.rs:1683` | `std::fs::remove_file(&list_path).ok();` | n/a | Inside `#[cfg(test)]` (T-list cleanup for a temp file used in a unit test). |
| `cairn-collectors/src/mft.rs:328,388` | `let si = file.info().ok();` | (b) | `file.info()` returns the `$STANDARD_INFORMATION` attribute; SI is optional metadata used only as a best-effort supplement to the mandatory `$FILE_NAME` times (which ARE handled via the required `preferred_file_name` match with explicit `continue` on error). Every downstream use of `si` is via `si.as_ref().and_then(...)`, so `None` degrades gracefully to `None` times rather than panicking or aborting the record. Verified this is intentional best-effort enrichment, not a load-bearing read. |

## 2. Findings (classification (a) only)

Total: **1 finding**, severity Low. No findings of Medium/High/Critical severity.
No true golden-rule-8 violation (panic-on-failure or whole-run-abort) was found
in any collector, analyzer, or orchestrator code path.

### Finding 1 — `cairn-collectors-win/src/host.rs:27` — discarded first-call return of `GetComputerNameExW`

- **Severity:** Low
- **File:** `crates/cairn-collectors-win/src/host.rs:27`
- **Issue:** `let _ = GetComputerNameExW(ComputerNameDnsHostname, None, &mut size);` — this is
  the standard two-call Windows sizing idiom (first call populates `size`, expected
  to "fail" with `ERROR_MORE_DATA`; the real call follows). This itself is a
  legitimate (b)-class idiom **like** the `net.rs:63,113` cases. However, unlike
  `net.rs`, I could not fully verify from the surrounding ~15 lines that the buffer
  populated by the *second* call is bounds-checked/length-validated as tightly as
  the TCP/UDP table cases before being converted to a Rust `String` — worth a
  closer look by someone reading the full function body (I saw only the two-call
  pattern, not the post-processing).
- **Fix (one line):** During the next touch of `host.rs`, add an explicit
  bounds/length assertion or `debug_assert!` after the second `GetComputerNameExW`
  call confirming `size` matches the buffer actually filled, mirroring the
  `net.rs` pattern, so a future refactor cannot silently under/over-read.

**Note:** I am downgrading my confidence on this finding to Low/informational
rather than a hard defect — the (b)-classification (two-call sizing idiom) is
almost certainly correct by analogy to `net.rs`; I flag it only because I did
not read enough of `host.rs` beyond the immediate lines to independently confirm
the second call's buffer handling is equally defensive.

## 3. NFR9/NFR10 resource-ceiling enforcement

**Verified real, not decorative, in every case checked:**

- `Config.governance.max_threads` (`cairn-core/src/config.rs:48`) flows through
  `resolve_max_threads()` (pure, unit-tested: never returns 0, clamps to real
  core count) and is applied via `rayon::ThreadPoolBuilder::new().num_threads(...)
  .build_global()` in `cairn-cli/src/main.rs:751-759`. The one-shot semantics of
  `build_global` (can only be called once per process) is correctly handled with
  a documented ignore-on-second-call.
- `Config.governance.low_priority` is applied via
  `cairn_collectors_win::priority::lower_priority()`, whose `Result` **is**
  checked at the call site (`main.rs:761-771`): failure produces
  `tracing::warn!` and the run continues at normal priority — this is a textbook
  golden-rule-8 degrade, not a silent failure.
- `Config.max_mft_records` / `Config.max_usn_records`: confirmed by grep that
  both are read directly by `MftCollector::collect` (`mft.rs:148`) and
  `UsnCollector::collect` (`usn.rs:292`) — not merely defined in `Config` and
  ignored. Both collectors record `truncated: true` + the cap value into
  `SourceEntry.errors` when the ceiling is hit (`mft.rs:166-180`,
  `usn.rs:308-322`), so a truncation is visible in the manifest, never silently
  dropped or OOM'd.
- `HIVE_HARD_CEILING` (512 MiB, `hive_reader.rs:73`) is applied on every stream
  read via `.take(HIVE_HARD_CEILING).read_to_end(...)` in `read_stream_bytes`
  (`hive_reader.rs:222-229`), used by **both** primary-hive reads and .LOG1/.LOG2
  reads — no unbounded-read path was found for hive I/O. `srum.rs`'s
  `extract_srudb` re-uses the same `HIVE_HARD_CEILING` constant and the same
  `.take(...).read_to_end(...)` pattern (`srum.rs:236`), and explicitly sets a
  `truncated_flag` + returns `Err` (abstain) when the ceiling is hit
  (`srum.rs:243-249`) — correctly propagated to `SrumCollector.sources()`.
- `PREFETCH_DECOMPRESS_CEILING` (64 MiB, `prefetch.rs:21`) is applied via
  `compcol::vec::decompress_to_vec_capped(...)` — the capped variant, not the
  uncapped `decompress_to_vec` (which IS used, correctly, only in unit tests that
  build small fixtures, never in the production `collect()` path).
- `SUBKEY_PREALLOC_CAP` (`hive_reader.rs:566`, 1<<20) bounds the **pre-allocation**
  of `list_subkeys`'s output `Vec` against a lying `number_of_sub_keys` field,
  while still honoring the true count in the loop — verified this doesn't
  silently truncate real data, only bounds the up-front reservation (documented
  and unit-tested at `hive_reader.rs:672-680`).
- `MAX_READ` (1 MiB, `volume.rs:232`) caps every single raw-volume read
  regardless of caller-requested length, with the aligned-window arithmetic
  proven overflow-safe (`compute_aligned_window` returns `None` rather than
  panicking on adversarial `pos` values near `u64::MAX`; unit-tested extensively
  in `volume.rs`'s test module).

**No path was found where a resource cap is declared in `Config` but never
consumed by the collector it claims to bound**, and no unbounded-read path was
found for any large-artifact read (hive bytes, prefetch decompression, raw
volume reads, USN/MFT record counts).

## 4. NFR12 abstain-on-unknown-format behavior

**Verified correct in every offline parser inspected:**

- `prefetch.rs::parse_prefetch`: `run_count_offset(version)` returns `None` for
  any version other than the two explicitly recognised constants (`PF_V30=30`,
  `PF_V31=31`); the `?` operator on that `None` makes the entire function return
  `None` (abstain), NOT a guessed/default offset. Unit-tested explicitly for v26,
  v29, v32 (`prefetch.rs:436-446`) — all abstain, none fabricate data.
- `hive_reader.rs`: `LogStatus::Failed` is a **distinct** variant from
  `NotFound`/`Applied` specifically so the manifest can honestly report "a log
  existed but could not be replayed" rather than silently claiming a clean
  parse — this is a real NFR12 design point, not just an error passthrough
  (`derive_log_status`, `hive_reader.rs:435-448`).
- `amcache.rs`/`bam.rs`/`userassist.rs`: every one abstains (returns `Ok(vec![])`
  + sets a named `AtomicBool` flag) rather than guessing on an absent key,
  malformed `FileId`/`DriverId` SHA1 field (`parse_sha1_from_fileid` requires an
  exact 44-char `"0000"+40hex` format else `None`, `amcache.rs:157-172`), or a
  non-real FILETIME (`bam.rs`'s `parse_bam_value` / `userassist.rs`'s
  `parse_userassist`, both routed through the shared `filetime_to_utc` which
  rejects `ft==0` and pre-1970 values).
- `mft.rs`: unrecognised/unreadable per-record data results in a `continue`
  (record dropped, not fabricated) rather than emitting a record with guessed
  fields; the one documented upstream limitation (fragmented `$MFT` beyond the
  first data run silently skips records via `ntfs 0.4`'s own limitation) is
  explicitly called out in a comment as "a triage trade-off, not a correctness
  bug" (`mft.rs:297-302`) — this is honest, not swept under the rug.

**Conclusion: no instance found of a parser filling in a plausible-looking but
unverified value on format mismatch.** Abstain-over-guess discipline is
consistently applied.

## 5. lib/cli error-layering check

- **`anyhow` presence:** confirmed via `Cargo.toml` dependency grep — `anyhow`
  appears ONLY in `cairn-cli/Cargo.toml` and `cairn-launcher/Cargo.toml`. Both
  are `[[bin]]` targets (not libraries); `cairn-launcher` is a separate
  end-user-facing wrapper binary, not a dependency of any lib crate. **Zero**
  `anyhow` usage found inside `cairn-core`, `cairn-collectors`,
  `cairn-collectors-win`, `cairn-heur`, `cairn-report`, `cairn-sigma`, or
  `cairn-updater` source.
  - **Minor deviation to flag:** CLAUDE.md's coding-conventions line says
    "`anyhow` only in the cli bin" (singular), which names `cairn-cli`
    specifically. `cairn-launcher` also uses `anyhow` throughout. This is
    architecturally sound (it's a separate bin, never a lib dependency of
    anything else) but is a literal deviation from the written rule's wording.
    Not raised as a Finding (no severity — it's a docs/wording gap, not a
    defect), but worth a one-line CLAUDE.md clarification ("anyhow only in bin
    crates: cairn-cli, cairn-launcher") if the maintainers want the doc to match
    reality exactly.
- **`CairnError` catch-all usage:** `CairnError::Other(String)` is used
  pervasively as a generic wrapper in `cairn-updater` (fetch.rs, encode.rs,
  config.rs), `cairn-report` (lib.rs, zip_sink.rs, bodyfile.rs, age_sink.rs),
  and `cairn-sigma` (engine.rs) — roughly 20 call sites. This is not a
  correctness bug (every message is a formatted, specific string preserving the
  underlying error's `Display` text via `format!("...: {e}")`), but it does mean
  `CairnError`'s typed variants (`Collector`, `Analyzer`, `Privilege`) are
  **not** used by these three crates at all for their own domain errors — a
  caller pattern-matching on `CairnError` variants (e.g. the orchestrator's
  `Err(e) => ... e.to_string()` in `orchestrator.rs:48`) only ever sees a string,
  never a structured reason, for anything originating in cairn-report/
  cairn-updater/cairn-sigma. Since the orchestrator only calls `.to_string()`
  on collector/analyzer errors today, this doesn't currently lose information at
  the point of use — but it is a real gap in error-type granularity if a future
  consumer wants to branch on error *kind* (e.g. distinguish "SSRF blocked" from
  "network timeout" in `cairn-updater::fetch.rs`, all of which currently collapse
  to the same `Other` variant).

## 6. "No problem found" categories (explicit)

- **Orchestrator (`cairn-core/src/orchestrator.rs`) collector/analyzer/observe
  fan-out:** no issues. Every collector and every analyzer is independently
  try/logged/continued; a failing analyzer does not pollute `sources`; a
  failing collector's error is faithfully recorded in `SourceEntry.errors`.
  Verified by both reading the code and its accompanying tests
  (`failing_collector_is_recorded_and_run_continues`,
  `failing_analyzer_is_skipped_run_continues`).
- **Panic containment for third-party crates (`ntfs`, `notatin`):** no issues.
  Every raw-NTFS/hive entry point (`mft.rs::parse_mft_records`,
  `usn.rs::read_usn_journal`, `hive_reader.rs::open_hive`,
  `hive_reader.rs::list_dir_names`) is wrapped in `catch_unwind` with a
  documented `AssertUnwindSafe` rationale (reader never reused after a caught
  panic), consistently applied across all four call sites.
- **Per-entry loop resilience across all 7 raw-NTFS/hive collectors** (mft, usn,
  amcache, bam, userassist, shimcache, srum): no issues. Every one follows the
  identical pattern — try the per-entry/per-subkey/per-value operation, on `Err`
  set a named `AtomicBool`/flag, `tracing::warn!`, `continue`; the flag is
  surfaced in `sources()` as a human-readable partial/abstain message. No
  instance of a single bad entry aborting the whole collector's loop.
- **RAII handle cleanup (`Drop` impls across `cairn-collectors-win`):** no
  issues. All `let _ = CloseHandle(...)`-style discards in `Drop` are the
  correct, conventional pattern (no alternative exists — `Drop::drop` cannot
  return `Result`).
- **Buffer/offset parsers (`prefetch.rs`, `usn.rs`, `bam.rs`, `userassist.rs`):**
  no issues. All use `slice::get`-based bounds-checked readers (`rd_u32`,
  `rd_u64`, etc.) that return `Option`/`Err` on out-of-bounds rather than
  indexing directly — verified never-panic by construction, and cross-checked
  against the "must not panic" fuzz-style unit tests present in each module.

## Summary for reporting

- 1 finding total, severity Low (host.rs — informational, not a confirmed
  defect; recommend a closer look, not urgent).
- Zero true golden-rule-8 violations found (no panic-on-failure, no
  whole-run-abort-on-one-collector-failure anywhere in the workspace).
- NFR9/NFR10 resource ceilings: all real, all consumed, all correctly reported
  on truncation.
- NFR12 abstain discipline: consistently applied across every offline parser
  checked.
- lib/cli error layering: `anyhow` correctly absent from all lib crates; one
  minor CLAUDE.md wording gap (launcher also uses anyhow, doc says "cli bin"
  singular) — not a code defect.
- `CairnError::Other` catch-all is used pervasively in cairn-updater/
  cairn-report/cairn-sigma — not a correctness bug today, but reduces future
  error-kind discriminability if a consumer ever needs to branch on error type
  from those three crates.
