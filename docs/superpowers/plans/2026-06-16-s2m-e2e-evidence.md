# S2-M — e2e evidence + manual elevated gate

> Honest record of what was verified and what still requires an operator on a real
> Administrator shell. Per the plan T5: do NOT fake-pass the elevated path.

## Automated gate (run 2026-06-16, this dev box)

- `cargo fmt --check` — clean.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — 0 warnings.
- `cargo test --workspace --locked` — 232 tests pass, 0 failed.
- `cargo audit --deny warnings` — clean (251 deps incl. new `ntfs` 0.4.0 chain; no advisory).

## Layering / golden-rule invariants (verified by grep)

- No `unsafe {` block in `cairn-core`, `cairn-collectors`, `cairn-cli` (all keep `#![forbid(unsafe_code)]`).
- `VolumeReader` opens with `GENERIC_READ` + `OPEN_EXISTING` only — no GENERIC_WRITE / CREATE / TRUNCATE
  anywhere (read-only, golden rules 3,4).
- `ntfs` pinned to 0.4.0 in `Cargo.lock`.

## Non-admin e2e (RAN — graceful degrade, golden rule 8)

`cairn run --target live --only mft --output <off-target>` on a non-elevated shell:

- run.log: `privilege probe admin=false se_backup=false se_debug=false`
- run.log: `collector selection profile=standard modules=mft`  (← `--only mft` truly restricts to mft)
- run.log: `WARN collector failed; skipping collector="mft" error=insufficient privilege for `mft`
  (need: Administrator + SeBackupPrivilege)`  (← degrades, does not abort — golden rule 8)
- run.log: `live run complete` + process exit 0
- records.jsonl: empty (mft skipped; no other collector selected)
- manifest.json: `run.profile=standard`, `run.selected_modules=["mft"]`, and a source entry
  `{artifact:"mft", errors:["insufficient privilege ... Administrator + SeBackupPrivilege"]}`
  (← the skip reason is recorded honestly)
- `cairn verify <manifest>` → `VERIFY OK`, exit 0

`cairn run --target live --profile minimal --output <dir>`:

- manifest `run.selected_modules=["proc","net","persist"]` — **mft NOT selected** (SRS §19.1 proven e2e)
- run.log: `collector selection profile=minimal modules=proc,net,persist`

### Honest caveat on the degraded source-entry `method`

In the non-admin path the mft source entry shows `method:"api"`, not `"raw_ntfs"`. Reason: the
collector returns `Err(Privilege)` at the privilege gate BEFORE `sources()` (which returns
`method:"raw_ntfs"`) is reached; the orchestrator's degrade path builds the SourceEntry with its
default `method:"api"`. This is pre-existing orchestrator behavior, not an mft bug. On the
elevated success path `sources()` runs and the entry carries `method:"raw_ntfs"`.

## Elevated e2e (NOT RUN here — requires an Administrator shell; operator gate)

This dev box session is non-elevated, so the actual raw `\\.\C:` read could not be exercised.
The following MUST be run by an operator from an Administrator PowerShell on a real Windows host
before relying on the $MFT read in the field:

```
# Elevated (Administrator), off-target output:
cairn run --target live --only mft --output <off-target-dir>
#   expect: records.jsonl has Record::FileMeta entries (kind=file_meta) — first N file names;
#           run.log "mft proof" line with mft_capacity_estimate + names_emitted;
#           manifest source entry artifact=mft method=raw_ntfs;
#           cairn verify <manifest> => VERIFY OK
```

What is already de-risked WITHOUT the elevated run:
- `ntfs` 0.4 accepts our `Read+Seek` and its API path (probe, 2026-06-16).
- The short-read panic is contained by guard (a) length pre-check + guard (b) catch_unwind (unit-tested).
- VolumeReader read-only flags + overflow-safe window math (unit-tested, grep-verified).
- Selection/degrade/verify (non-admin e2e above).

What ONLY the elevated run can confirm:
- That `ntfs` reaches `$MFT` from our `VolumeReader` over a real volume and yields real file names.
- That the sector-alignment Read/Seek behaves correctly against the real NTFS access pattern.
