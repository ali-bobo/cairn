# S2-N — e2e evidence + manual elevated gate

> Honest record of what was verified and what still requires an operator on a real
> Administrator shell. Per the plan T6: do NOT fake-pass the elevated path.
> Mirrors `docs/superpowers/plans/2026-06-16-s2m-e2e-evidence.md`.

## Automated gate (run 2026-06-17, this dev box)

- `cargo fmt --check` — clean.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — 0 warnings.
- `cargo test --workspace --locked` — 243 tests pass, 0 failed.
- `cargo audit --deny warnings` — clean (251 deps scanned, no advisory).
- **No new dependency:** `git diff ba4cf47..HEAD -- Cargo.lock` is EMPTY — `fn_mtime`,
  `filetime_to_utc`, the full-$MFT scan, and `--max-mft-records` all use the existing
  `ntfs` 0.4.0 + `chrono` 0.4.45 already pulled by S2-M. `cargo audit` surface unchanged.

## Layering / golden-rule invariants (verified)

- `unsafe` appears in NO crate except `cairn-collectors-win`; `cairn-core`,
  `cairn-collectors`, `cairn-cli` keep `#![forbid(unsafe_code)]`. S2-N added ZERO unsafe
  (it consumes S2-M's `VolumeReader` safe wrapper).
- `VolumeReader` still opens `GENERIC_READ` + `OPEN_EXISTING` only — read-only (rules 3,4),
  unchanged from S2-M.
- All times go through `cairn_core::time::filetime_to_utc` → `DateTime<Utc>` (NFR5 / rule 7).

## DoS / NFR10 (verified by unit test, not just claimed)

- `record_cap_truncates_without_panic`: a boot sector declaring a huge volume → huge
  capacity; with a tiny `max_records` the scan stops at the cap (does not loop to
  capacity) and never panics. The hard cap closes the lied-about-capacity wall-clock DoS.
- `parse_garbage_mft_body_yields_zero_records_or_err`: a crafted-valid boot sector with a
  garbage MFT body → every `ntfs.file()` fails → per-record `continue` → `Ok(capacity, [])`
  (or `Err`), never a panic, never an abort (golden rule 8, per-record isolation).
- `parse_short_source_returns_err_not_panic` + `parse_mft_records_short_source_is_err_shape`:
  S2-M guard (a) (boot-sector length pre-check) + guard (b) (`catch_unwind`) regress green.
- Peak-RAM bound documented in the mft module doc: bounded by `max_mft_records`
  (default 1M) × ~one `FileMetaRecord`, NOT by the volume's declared capacity (NFR10).
- Upstream limitation documented in `parse_mft_inner`: `ntfs::Ntfs::file()` assumes the
  $MFT itself has no `$ATTRIBUTE_LIST`; on a heavily fragmented volume, records beyond the
  first MFT data run are silently skipped via the per-record `continue` (a triage
  trade-off, surfaced so the gap is auditable — not a correctness bug).

## Time-conversion (verified by unit test)

- `filetime_to_utc` known value: FILETIME `130018833000000000` → `2013-01-05T18:15:00Z`
  (cross-checked against the `ntfs` crate's own `time.rs` test constant).
- Boundaries all `None`, no panic: `0` (unset), pre-1970 (`checked_sub` underflow),
  out-of-`i64` (checked `try_from`). `u64::MAX` → `Some` (~year 60056, within chrono range).

## Non-admin e2e (RAN — graceful degrade, golden rule 8)

`cairn run --target live --only mft --output <off-target>` on a non-elevated shell
(output written to `C:\Users\bosen\AppData\Local\cairn-e2e-s2n-<ts>`, OFF the OneDrive tree):

- run.log: `privilege probe admin=false se_backup=false se_debug=false`
- run.log: `collector selection profile=standard modules=mft`  (← `--only mft` restricts to mft)
- run.log: `WARN collector failed; skipping collector="mft" error=insufficient privilege for `mft`
  (need: Administrator + SeBackupPrivilege)`  (← degrades, does not abort — golden rule 8)
- run.log: `live run complete` + process exit 0
- records.jsonl: empty (mft skipped; no other collector selected)
- manifest.json: `run.selected_modules=["mft"]`, source entry
  `{artifact:"mft", method:"api", errors:["insufficient privilege ... Administrator + SeBackupPrivilege"]}`
- `cairn verify <manifest>` → `VERIFY OK`, exit 0

`cairn run --target live --profile minimal --output <dir>`:

- run.log: `collector selection profile=minimal modules=proc,net,persist` — **mft NOT
  selected** (SRS §19.1 proven e2e; the full-$MFT scan is the heaviest collector and minimal skips it).

### Honest caveat on the degraded source-entry `method`

In the non-admin path the mft source entry shows `method:"api"`, not `"raw_ntfs"`. This is
the SAME pre-existing orchestrator behavior documented for S2-M: the collector returns
`Err(Privilege)` at the privilege gate BEFORE `sources()` (which returns `method:"raw_ntfs"`)
runs, so the orchestrator's degrade path builds the SourceEntry with its default
`method:"api"`. On the elevated success path `sources()` runs and the entry carries
`method:"raw_ntfs"`. Not an S2-N regression.

## Elevated e2e (NOT RUN here — requires an Administrator shell; operator gate)

This dev box session is non-elevated, so the actual raw `\\.\C:` full-$MFT scan that reads
real SI/FN times could not be exercised. The following MUST be run by an operator from an
Administrator PowerShell on a real Windows host before relying on the MACB read in the field:

```
# Elevated (Administrator), off-target output:
cairn run --target live --only mft --output <off-target-dir>
#   expect: records.jsonl has Record::FileMeta entries (kind=file_meta) with NON-null
#           si_btime / si_mtime / fn_btime / fn_mtime on real files (timestomp material);
#           run.log "mft scan" line with mft_capacity_estimate + records_emitted + record_cap;
#           manifest source entry artifact=mft method=raw_ntfs;
#           cairn verify <manifest> => VERIFY OK

# Cap behavior on a real volume:
cairn run --target live --only mft --max-mft-records 5 --output <dir2>
#   expect: <= 5 Record::FileMeta entries; run.log records_emitted <= 5; no panic.
```

> WALL-CLOCK NOTE (from final review): `ntfs::Ntfs::file()` re-resolves the $MFT's own
> `$DATA` on every call, so a full scan to the 1M default cap is I/O-heavy (roughly
> O(n²)-ish in I/O) — bounded (no DoS escape, the cap holds) but slow on a large real
> volume. The operator should time the elevated full-cap run and watch wall-clock; a
> streaming / custom-$MFT reader is already flagged as future work in the mft module doc.

What is already de-risked WITHOUT the elevated run:
- ntfs 0.4 API path (Ntfs::file iteration, info() for SI, attributes()/structured_value
  for FN, NtfsTime::nt_timestamp) — confirmed against the crate source 2026-06-17.
- Time conversion + all boundaries (unit-tested).
- Record cap, per-record isolation, short-read guards (unit-tested).
- FN namespace preference logic (code-reviewed; deterministic).
- Selection / degrade / verify / minimal-skips-mft (non-admin e2e above).

What ONLY the elevated run can confirm:
- That `ntfs` yields SI and FN attributes for real $MFT records over a real volume and the
  four times populate as non-null `DateTime<Utc>`.
- That the FN-namespace preference picks sensible (non-DOS-8.3) names on real files.
- That `--max-mft-records` bounds a real scan as expected.
