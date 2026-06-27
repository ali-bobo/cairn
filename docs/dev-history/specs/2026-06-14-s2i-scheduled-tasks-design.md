# S2-I: Scheduled Tasks persistence collector — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-14.
> Authoritative spec: `cairn-SRS.md` (§4 persist_collector, FR9, §5 PersistenceRecord, §10 heuristics).
> Predecessors: S2-C (persist collector + 5 mechanisms + persist heuristic), S2-D/E/G (accurate
> `signed`), S2-F (binary_path candidate model), S2-H (heuristic calibration).
> **The breadth turn:** after five signature-focused sub-segments (S2-D→H), this widens
> visibility from 5 to 6 high-value persistence mechanisms — adding the one cairn was most
> conspicuously blind to.

## Purpose

Scheduled Tasks are among the most common persistence mechanisms (MITRE T1053.005) — used
heavily by both legitimate software and attackers — yet cairn currently cannot see them at all.
This sub-segment adds a 6th persistence reader that parses live Scheduled Task definitions and
emits them as `PersistenceRecord`s, so the existing pipeline (binary_path candidate resolution,
signature verification, the calibrated persist heuristic) scores them with no new scoring logic.

## Scope

**In scope:**
- A new reader `read_scheduled_tasks()` in `cairn-collectors/src/persist.rs` that walks the
  live Task store (`%SystemRoot%\System32\Tasks`, recursively), reads each task's XML, and
  emits one `PersistenceRecord` per `<Exec>` action with `mechanism = "scheduled_task"`.
- A PURE parser `parse_task_xml(&str) -> Vec<ParsedExecAction>` (quick-xml; Linux-CI-testable;
  no FS, no env, no unsafe).
- The `scheduled_task` mechanism in the persist heuristic: base weight **20** (same band as
  `service`), wired into the existing `score_persistence` mechanism match.
- A new dependency: `quick-xml` v0.40.1, `--no-default-features` (verified: compiles, zero
  RustSec advisories, the core reader needs no feature flags).

**Explicitly OUT of scope (deferred, with rationale):**
- **TaskCache registry / COM ITaskService routes.** The XML route is pure-Rust, no-unsafe, and
  has the richest fields. The registry route hides the command in a binary `Actions` blob
  (complex to reverse, fragile); the COM route needs unsafe FFI. Both rejected for this
  sub-segment. (TaskCache could later supply tasks when XML is ACL-blocked — a future option.)
- **Non-Exec actions** (`<ComHandler>`, `<SendEmail>`, `<ShowMessage>`). They have no binary
  path to verify; skipped (no record). ComHandler-based persistence (a COM CLSID) is a distinct
  future artifact, noted as a non-goal.
- **Trigger analysis** (logon/boot/idle triggers as extra suspicion signals). The record keeps
  the command + location; trigger-aware scoring is a future heuristic refinement.
- **`.job` legacy tasks** (pre-Vista `C:\Windows\Tasks\*.job`, a binary format). Rare on modern
  Windows; deferred.
- **No schema change.** `PersistenceRecord` is reused as-is.

## Feasibility (self-verified, 2026-06-14)

- **Real Task XML structure confirmed** against live built-in tasks (via `schtasks /query /xml`):
  ```xml
  <Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo><URI>\Microsoft\Windows\...\TaskName</URI><Date>...</Date>...</RegistrationInfo>
    <Actions Context="LocalService">
      <Exec><Command>%windir%\system32\sc.exe</Command><Arguments>start w32time ...</Arguments></Exec>
    </Actions>
  </Task>
  ```
  The `<Exec>/<Command>/<Arguments>/<URI>` mapping holds. `<Command>` carries `%windir%`-style
  env vars — handled for free by the S2-F candidate model's `expand_env_vars`.
- **quick-xml 0.40.1 `--no-default-features` compiles** in cairn-collectors; `cargo audit` clean
  (235 deps, 0 advisories). The XML has an `xmlns` namespace and may contain `&`-escaped chars
  in paths/args — exactly what quick-xml handles correctly and a hand-rolled parser would not.
- **Non-admin graceful degrade confirmed:** `%SystemRoot%\System32\Tasks` is ACL-restricted —
  a non-admin enumeration sees zero files. The reader must return an empty Vec (not error, not
  panic) in that case; the collector continues with the other 5 mechanisms.

## Architecture (data flow)

```
read_scheduled_tasks()                         [cfg(windows): thin FS shell]
  walk %SystemRoot%\System32\Tasks recursively (std::fs); for each file:
    std::fs::read_to_string (best-effort; unreadable file skipped — graceful)
      → parse_task_xml(&xml)                   [PURE: quick-xml; Linux-CI-testable]
          returns Vec<ParsedExecAction> { command, arguments, uri }
            (one per <Exec>; non-Exec actions skipped; URI from <RegistrationInfo>)
      for each action → PersistenceRecord {
        mechanism: "scheduled_task",
        location:  uri (or the file's relative path under Tasks\ if URI absent),
        value:     task name (last URI segment, or file stem),
        command:   "<Command> <Arguments>".trim(),   // env vars intact for candidate resolver
        binary_path: None,                            // filled below
        binary_sha256: None, signed: None,
        last_write: file mtime (registration <Date> is a future option),
      }
        │ (binary_path resolved via the S2-F candidate model on `command`, same as
        │  read_services / make_record — pick the first candidate that exists on disk)
        ▼
collect(): records.extend(read_scheduled_tasks())     [6th reader, after read_startup_folders]
        ▼
apply_signatures()  [S2-D/G: WinVerifyTrust + catalog → signed]
        ▼
persist heuristic: "scheduled_task" => +20 base, then existing path/recency/unsigned signals
   and the S2-H suppression gates apply uniformly (a signed task in a normal path stays quiet).
```

**New / changed units:**
- `crates/cairn-collectors/src/persist.rs`:
  - `parse_task_xml(xml: &str) -> Vec<ParsedExecAction>` — PURE. Extracts the task `<URI>` and,
    per `<Exec>`, the `<Command>` and `<Arguments>`. Returns empty on malformed/no-Exec XML
    (never panics). `ParsedExecAction { command: String, arguments: String, uri: Option<String> }`.
  - `task_records_from_xml(xml, file_name, mtime) -> Vec<PersistenceRecord>` — PURE glue:
    parse + build records + resolve binary_path via the candidate model (injected `exists`),
    so the record-building is Linux-CI-testable end to end.
  - `read_scheduled_tasks()` — `cfg(windows)` FS walk calling the pure glue; `cfg(not(windows))`
    stub returns `vec![]`. Graceful: unreadable root/file → skip.
  - `collect()` gains `records.extend(read_scheduled_tasks())`.
- `crates/cairn-collectors/Cargo.toml`: `quick-xml = { version = "0.40.1", default-features = false }`.
- `crates/cairn-heur/src/persist.rs`: add `"scheduled_task" => s.add(20, "scheduled task
  persistence", &["T1053.005"])` to the mechanism match in `score_persistence`.

**Layering:** parsing + record-building are pure (quick-xml, no FS/env/unsafe), testable on
ubuntu CI. The only FS touch is the `cfg(windows)` walk + read (read-only) and the candidate
`Path::exists` probe (a stat). `#![forbid(unsafe_code)]` holds across both crates.

## binary_path resolution

`command` is `"<Command> <Arguments>"`, e.g. `%windir%\system32\sc.exe start w32time`. Resolve
binary_path with the existing S2-F candidate model (`extract_binary_path_candidates` +
`pick_binary_path`): it expands `%windir%`, then picks the first prefix candidate that exists on
disk — correctly yielding `C:\Windows\system32\sc.exe` and ignoring the `start w32time` args.
Quoted commands (`"C:\Program Files\App\app.exe" /bg`) resolve to the quoted path. This is the
same path read_services and the run-key readers already use — zero new resolution logic.

## Heuristic integration

`scheduled_task` base weight **20** = the `service` band. Rationale: scheduled tasks are a
common, legitimately-heavily-used mechanism (Windows ships hundreds of built-in tasks), so the
base alone (20, Low) must not raise a finding — it needs a corroborating signal (suspicious
path, unsigned-in-suspicious-path amplifier, recent write) to reach Medium/High, exactly like
`service`. The S2-H gates apply uniformly: a signed task whose binary is in a normal path stays
quiet; a signed per-user-app-style task in `\AppData\Local\Programs\` gets the same path-signal
suppression. No scheduled-task-specific gate is added.

## Error handling / graceful degrade (golden rule 8)

- Non-admin / ACL-blocked Tasks root → FS walk yields nothing → `read_scheduled_tasks()` returns
  `vec![]`. The collector's other 5 readers are unaffected. (Ideally the manifest notes the
  skip; the current persist `sources()` is a single coarse entry, so a per-mechanism skip note
  is a nice-to-have, not required for this sub-segment — the empty result is itself honest.)
- An individual unreadable / malformed task file → skipped (best-effort), never aborts the walk.
- `parse_task_xml` is total: malformed XML, missing `<Actions>`, or no `<Exec>` → empty Vec.
- Determinism (NFR4): the walk is deterministic given the FS; output is sorted downstream by
  (ts, record) as today. (If walk order ever matters for reproducibility, sort the file list.)

## Security note (golden rules)

- Read-only: `std::fs` directory walk + file read + `Path::exists`. No task is created,
  modified, run, or deleted; no host modification (golden rule 3).
- No unsafe, no evasion: pure XML parsing via a vetted crate + read-only FS. quick-xml has zero
  known RustSec advisories (vs the older `xml-rs`, RUSTSEC-2022-0048 — a reason to use quick-xml).
- A crafted task XML cannot cause traversal or code execution: we parse text and `exists`-check
  the literal resolved candidate paths; we never follow, open-for-write, or execute them. XXE is
  not a concern — quick-xml does not resolve external entities by default and we enable no such
  feature.

## Testing

Pure parser + record glue → full TDD; the FS walk → a thin Windows smoke test.

- **parse_task_xml (pure):**
  - real built-in task XML (sc.exe / defrag.exe samples, with xmlns + `%windir%`) → correct
    command/arguments/uri.
  - multiple `<Exec>` actions in one task → one ParsedExecAction each.
  - `&amp;`-escaped chars in `<Arguments>` → decoded correctly (quick-xml).
  - non-Exec action only (`<ComHandler>`) → empty Vec.
  - malformed / no `<Actions>` / empty string → empty Vec (no panic).
- **task_records_from_xml (pure, injected exists):**
  - `%windir%\system32\sc.exe start w32time` with a fake exists set → binary_path resolves to
    the expanded sc.exe path, command keeps the args verbatim, mechanism="scheduled_task".
  - quoted command with spaces → quoted path resolved.
  - nothing exists on disk → binary_path falls back to the bare first token (S2-F behavior).
- **heuristic (cairn-heur persist):**
  - scheduled_task in a normal signed path → base 20 only (Low), no finding-worthy escalation;
    matches the `service` baseline.
  - scheduled_task unsigned in `\Temp\` → base 20 + path 30 + unsigned 20 = High (fail-loud).
- **collector wiring / smoke (Windows):** `read_scheduled_tasks()` does not panic; on a non-admin
  host it returns an empty Vec (ACL) OR, if any task is readable, well-formed records — don't
  hard-require a count (privilege-dependent).
- **e2e (manual-then-self-run, Windows):** `cairn run --target live --only persist`; scheduled
  tasks appear as `mechanism=scheduled_task` records when readable (admin) or absent gracefully
  (non-admin); no panic; no other mechanism's output changed; signed/heuristic apply; `cairn
  verify` passes. Record whether the run was admin (tasks present) or not (graceful empty).

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (quick-xml 0.40.1,
  0 advisories).
- `unsafe` appears in no crate except `cairn-collectors-win`; collectors + heur stay
  `#![forbid(unsafe_code)]`.
- A real live run reads scheduled tasks when permitted and degrades gracefully (empty, no error)
  when ACL-blocked; the 5 existing mechanisms are unchanged; `cairn verify` passes.
- No golden-rule violation (read-only, no unsafe, no evasion); no scope creep (no TaskCache/COM,
  no non-Exec actions, no trigger scoring, no schema change).
- Linux CI: the pure parser + glue tests run on ubuntu; Windows-only FS walk carries
  `#[cfg(windows)]` / the stub returns `vec![]`; any Windows-only helper unused on Linux carries
  `#[allow(dead_code)]` (the S2-C..H lesson).

## Non-goals / future hooks

- **TaskCache registry fallback** to surface tasks when the XML store is ACL-blocked (non-admin).
- **ComHandler / COM-CLSID persistence** as a distinct artifact.
- **Trigger-aware scoring** (logon/boot triggers amplify suspicion).
- **`.job` legacy tasks**, **registration-date `last_write`** (vs file mtime).
- Remaining Stage 2+ work unchanged: WMI subscriptions, signer identity, raw-NTFS, offline
  artifacts, FR14 hashing, FR15/FR18 output packaging.
