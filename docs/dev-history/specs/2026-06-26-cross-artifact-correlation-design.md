# Cross-Artifact Correlation Analyzer — Design Spec

> **Status:** Approved for implementation.
> **Date:** 2026-06-26

## Problem

All artifacts are currently siloed. A binary can appear in:
- `PersistenceRecord` (autorun / service / scheduled task)
- `ExecutionRecord` (prefetch / amcache / BAM / userassist / shimcache)
- `ProcessRecord` (live running process)

with no Finding connecting them. The analyst must manually correlate across
`records.jsonl`. High-confidence signals are missed: a binary that is both
persisted AND was confirmed executed is nearly certain to have run at some point
— even if it's not running right now.

## Goal

Emit a `High` severity Finding when the **same binary** is corroborated across
≥2 artifact categories simultaneously:
- **Category A:** `PersistenceRecord` (any mechanism, any location)
- **Category B:** `ExecutionRecord` (prefetch / amcache / BAM / userassist / shimcache)

Optional third corroboration (no additional Finding; add to `reason` if present):
- **Category C:** Live `ProcessRecord` (binary is also running right now)

Inbox services are suppressed (no added value over the existing PersistHeuristic
Finding; the analyst already sees those). The correlation Finding is purely for
cases where the two independent artifact types agree.

## Key Design Decisions

### Normalization key
- **basename, no extension, lowercase** — e.g. `notion`, `msedge`, `docker`.
- Prefetch paths ARE basenames (the .pf file stores `NOTION.EXE-XXXXXXXX.pf`);
  the correlation key strips the `.pf` suffix too.
- Full binary_path is surfaced in `details`, not used as the key.
- SHA1 is NOT used as the join key (prefetch has no SHA1; shimcache has no SHA1).

### Inbox suppression
- Reuse existing `is_inbox_service_command(cmd)` from `score.rs`.
- If the persistence entry's `command` or `binary_path` passes `is_inbox_service_command`,
  skip that entry. (Inbox services dominate prefetch; this alone suppresses ~200+ false
  positives per run.)
- DriverStore binaries are NOT suppressed (BYOVD risk — `is_inbox_service_command`
  already returns false for DriverStore paths).

### Severity
- Always `High`. Rationale: two independent forensic artifacts agreeing on
  the same binary is high-confidence evidence of intentional persistence +
  execution. If the binary is also inbox-suppressed, this analyzer never fires.

### MITRE mapping
- Derived from `PersistenceRecord.mechanism`:
  - `service` → `T1543.003`
  - `run_key` / `startup` → `T1547.001`
  - `scheduled_task` → `T1053.005`
  - `winlogon` → `T1547.004`
  - `ifeo` → `T1546.012`
  - (fallback) → `T1547`

### Entity
- `entity.file = EntityFile { path: <best_path>, sha256: None, ... }` where
  `best_path` is `persistence.binary_path` (full path) if present, else
  `execution.path` (may be basename only).

### Finding fields
```
artifact   = "correlation"
source     = FindingSource::Heuristic
title      = "Confirmed persistence + execution: {name}"
details    = "{name} persisted via {mechanism} ({location}); confirmed executed ({exec_sources}, last_run: {last_run_ts})"
reason     = "binary found in both persistence ({mechanism}: {location}) and execution records ({exec_sources})"
             [+ " and currently running (pid={pid})" if ProcessRecord match found]
details_client = zh-TW via client_text dispatch
```

### No schema changes
`Finding` struct is unchanged. Evidence is encoded in `details` and `reason`
strings. No `correlation_refs` field — out of scope.

### One Finding per (key, persistence_mechanism)
To avoid explosion when `svchost.exe` has 60 service records: group by
`(basename, mechanism)` — pick the highest-confidence persistence record
(most recent `last_write`), list all execution sources.

`svchost` is inbox-suppressed anyway (System32), so in practice this grouping
only matters for 3rd-party services installed under non-inbox paths.

### Graceful degrade
If no execution records are present (e.g. ran without SeBackupPrivilege so
amcache/prefetch/BAM all failed): `ExecutionRecord` vec is empty → analyzer
emits zero Findings. This is correct behavior (no false positives on partial runs).

## Data Flow

```
records: &[Record]
  │
  ├─ filter Record::Execution  ──→ exec_map: HashMap<String, Vec<ExecutionRecord>>
  │                                          key = normalized_basename(execution.path)
  │
  ├─ filter Record::Persistence ─→ persist_map: HashMap<String, Vec<PersistenceRecord>>
  │                                             key = normalized_basename(command or binary_path)
  │
  └─ filter Record::Process ─────→ proc_map: HashMap<String, Vec<ProcessRecord>>
                                             key = normalized_basename(image)

for each (key, persist_entries) in persist_map:
    if exec_map.contains_key(key):
        for each mechanism_group in persist_entries.group_by(mechanism):
            if is_inbox_suppressed(persist_entry.command): continue
            emit Finding(High, title, details, reason, entity)
```

## New file

`crates/cairn-heur/src/correlation.rs` — `pub struct CorrelationAnalyzer`

Wired into `main.rs` analyzers vec alongside `PersistHeuristic`, etc.

## Tests

1. `exec_and_persist_same_binary_emits_high_finding` — basic trigger
2. `exec_without_persist_emits_nothing` — no persistence, no corroboration
3. `persist_without_exec_emits_nothing` — no execution evidence, no corroboration
4. `inbox_service_is_suppressed` — `system32\svchost.exe` service + prefetch = no Finding
5. `driverstore_binary_is_not_suppressed` — DriverStore path (BYOVD risk) does fire
6. `finding_title_and_artifact_field` — `artifact == "correlation"`, title contains basename
7. `finding_has_reason_and_details` — explainability golden rule 6
8. `svchost_group_by_mechanism_dedup` — 60 svchost services collapse to one group (svchost
   is inbox-suppressed, but the mechanism grouping logic is still tested with a non-inbox binary)
9. `process_corroboration_adds_to_reason` — live ProcessRecord adds "currently running" to reason
10. `no_exec_records_emits_nothing` — graceful degrade when SeBackup not available
