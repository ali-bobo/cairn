# S2-C: persistence collector + persist heuristic — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-13.
> Authoritative spec: `cairn-SRS.md` (§4 persist_collector, §7 FR9, §10 persistence rank,
> §5.1 Finding, §5 PersistenceRecord).
> Predecessors: S2-A (live proc/net + orchestrator), S2-B (parentchild/netconn heuristics,
> the `cairn-heur` crate + shared `score.rs`).

## Purpose

The tool collects live processes and network connections and flags suspicious ones,
but it cannot yet see how an attacker would survive a reboot. This sub-segment adds a
**persistence collector** (the high-value live-registry mechanisms) plus a
**persist heuristic**, so a live run enumerates autostart/persistence entries AND
flags the suspicious ones with an explainable reason — the same collect-then-judge
arc S2-B brought to proc/net, now for persistence (the artifact analysts check first
in almost every incident).

## Scope

**In scope (FR9 subset, FR13, SRS §10):**
- `PersistCollector` reading FIVE live mechanisms via the `winreg` crate (registry)
  and `std::fs` (folders), producing `PersistenceRecord`s:
  Run/RunOnce keys, Services (autostart), Winlogon (Shell/Userinit), IFEO (Debugger),
  Startup folders.
- `PersistHeuristic impl Analyzer` (SRS §10 persistence rank): weight by mechanism
  stealth + suspicious binary path + recent LastWrite → Finding with reason.
- Wire both into the CLI live run (collectors + analyzers vecs) — graceful degrade
  already provided by the orchestrator (S2-A/S2-B).

**Explicitly OUT of scope (deferred, with rationale):**
- **Binary signature verification** (`signed` field) — requires WinTrust
  (`WinVerifyTrust`) unsafe FFI, which belongs in `cairn-collectors-win`. Deferred to
  **S2-D**, which will add signature verification once and backfill `signed` for BOTH
  the proc collector (also currently None) and persist. `PersistenceRecord.signed`
  stays `None` this sub-segment; the persist heuristic compensates with higher weights
  on mechanism + path (see Rules) so genuinely malicious persistence still surfaces
  without the signed signal.
- **Scheduled Tasks** (Tasks XML + TaskCache) and **WMI event subscriptions** (CIM
  repository parsing) — the two hardest FR9 mechanisms (WMI especially: no mature Rust
  parser). Each is its own later sub-segment.
- **Binary hashing** (`binary_sha256`) — that is FR14, a later sub-segment. Stays None.
- **Offline hive parsing** (notatin, locked HKLM\SYSTEM via raw-NTFS) — S2 raw-NTFS
  segment. This sub-segment reads the LIVE registry only (winreg), which covers the
  running-host triage case without elevation for most keys.

## Architecture

Extends the established collector→analyzer pattern. No new crate; new modules in the
two existing ones.

```
PersistCollector (cairn-collectors/src/persist.rs, winreg + std::fs, #![forbid(unsafe_code)])
   ├─ Run/RunOnce keys  (HKLM + HKCU \...\CurrentVersion\Run and \RunOnce)        ─┐
   ├─ Services          (HKLM\SYSTEM\CurrentControlSet\Services\*, autostart)       ─┤
   ├─ Winlogon          (HKLM\...\Winlogon: Shell, Userinit)                        ─┼─→ Vec<PersistenceRecord>
   ├─ IFEO              (HKLM\...\Image File Execution Options\*\Debugger)           ─┤
   └─ Startup folders   (per-user %AppData%\...\Startup + %ProgramData%\...\Startup) ─┘
                          │ (into the orchestrator records bus)
                          ▼
PersistHeuristic (cairn-heur/src/persist.rs, pure scoring, reuses score.rs)
   mechanism stealth + suspicious path + recent LastWrite → Finding (signed signal: S2-D)
```

**New / changed units:**
- `crates/cairn-collectors/src/persist.rs` (new): the five mechanism readers + pure
  mapping helpers + `PersistCollector impl Collector`.
- `crates/cairn-collectors/Cargo.toml`: add `winreg` under `cfg(windows)` only.
- `crates/cairn-collectors/src/lib.rs`: `pub mod persist;`.
- `crates/cairn-heur/src/persist.rs` (new): `PersistHeuristic impl Analyzer`.
- `crates/cairn-heur/src/lib.rs`: `pub use persist::PersistHeuristic;`.
- `crates/cairn-cli/src/main.rs`: live arm adds `PersistCollector` to collectors and
  `PersistHeuristic` to analyzers.

**Layering (mirrors S2-A's clean split):**
- `winreg` is a safe wrapper, so the persist collector stays in `cairn-collectors`
  (`#![forbid(unsafe_code)]`); `cairn-collectors-win`'s unsafe surface does NOT grow.
- Pure mapping/classification (mechanism stealth ordering, binary-path extraction,
  path classification) are independently TDD'd. The actual OS/registry reads get a thin
  smoke test (as S2-A did for proc/net).
- `signed` and `binary_sha256` are always `None` this sub-segment (S2-D / FR14).

**Cross-platform build (mirrors S2-A):** `winreg` is a `cfg(windows)` dependency. On
non-Windows each reader returns an empty vec so the workspace still builds and the pure
logic still tests on ubuntu CI.

## Mechanism readers

Each maps to `PersistenceRecord { mechanism, location, value, command, binary_path,
binary_sha256: None, signed: None, last_write }`.

| Mechanism | Source | `mechanism` | Fields |
|---|---|---|---|
| Run/RunOnce | `HKLM` + `HKCU` `...\CurrentVersion\Run` and `\RunOnce` (4 keys) | `run_key` | per value: name→`value`, data→`command`, extract `binary_path`, key's last_write |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services\*` where `Start ∈ {0,1,2}` (boot/system/auto) and `ImagePath` present | `service` | subkey name→`value`, ImagePath→`command`+`binary_path`, last_write |
| Winlogon | `HKLM\...\Winlogon` values `Shell`, `Userinit` | `winlogon` | value name→`value`, data→`command`+`binary_path`, last_write |
| IFEO | `HKLM\...\Image File Execution Options\*` subkeys having a `Debugger` value | `ifeo` | hijacked image name→`value`, Debugger→`command`+`binary_path`, last_write |
| Startup folders | per-user `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup` + All Users `%ProgramData%\...\Startup`, `std::fs` | `startup` | file name→`value`, full path→`binary_path`, file mtime→`last_write` |

**`binary_path` extraction (pure, TDD'd helper):** a command line may be
`"C:\path\app.exe" -arg` or `C:\path\app.exe`. Strip surrounding quotes, take the first
token, expand environment variables (`%SystemRoot%`, `%ProgramFiles%`, etc.). On any
parse difficulty leave `binary_path = None` (never panic).

**LastWrite:** registry key last-write time via winreg's key info; for startup files,
the filesystem mtime. Both → `Option<DateTime<Utc>>` (None if unavailable).

## Rules — persist heuristic (SRS §10)

For each `PersistenceRecord`, accumulate signals. Named-constant tables in source (the
config-loader seam, as in S2-B). `now` is injected (default `Utc::now()`) so the recency
window is testable.

| Signal | Condition | Weight | ATT&CK |
|---|---|---|---|
| IFEO hijack | mechanism == `ifeo` (a Debugger value is almost never legitimate) | +45 | T1546.012 |
| Winlogon | mechanism == `winlogon` (Shell/Userinit tampering is high-risk) | +35 | T1547.004 |
| Service | mechanism == `service` | +20 | T1543.003 |
| Run key | mechanism == `run_key` (common, many legitimate → low base) | +10 | T1547.001 |
| Startup folder | mechanism == `startup` | +10 | T1547.001 |
| Suspicious binary path | `is_suspicious_path(binary_path)` (when binary_path is Some) | +30 | T1036 |
| Recent LastWrite | `last_write` within the last 7 days of `now` | +15 | — |

**Severity:** reuse `score::severity_for` (>=70 critical / 50–69 high / 30–49 medium /
15–29 low / <15 no finding).

Mechanism weights are mutually exclusive (one record has one mechanism), so the base
mechanism score is one of {45,35,20,10}; path (+30) and recency (+15) stack on top. This
means: an IFEO Debugger from Temp written this week = 45+30+15 = 90 (critical); a plain
Run key to a signed-looking Program Files path, old = 10 (below floor, quiet). That is
the intended quiet-by-default-for-legitimate behaviour, compensating for the absent
signed signal (S2-D will add an unsigned +20 signal and re-tune).

`reason` lists matched signals + the mechanism + binary_path (golden rule 6).

## Finding construction

- `source = Heuristic`, `reason = Some(...)` always; `rule_author = None` (not Sigma).
- `severity` from `severity_for`; `title` e.g. `"Suspicious persistence: <mechanism>"`.
- `mitre` from matched signals (mechanism's technique + T1036 for suspicious path).
- `artifact = "persistence"`.
- `entity.registry` populated for the registry-backed mechanisms (run_key, service,
  winlogon, ifeo) with this exact mapping: `hive` = the record's hive prefix (e.g.
  "HKLM"/"HKCU" parsed from `location`), `key` = the record's `location`, `value` =
  the record's `value` (or ""), `data` = the record's `command` (or ""), `last_write` =
  the record's `last_write`. For the `startup` (file) mechanism, populate `entity.file`
  instead with `path` = the record's `binary_path` (or `value`), `mtime` =
  `last_write`, and the other EntityFile fields (sha256/si_btime/fn_btime) = None.
- `host` left empty (CLI stamps it, as in S2-B).
- `ts` = `last_write` when available, else `now` (the record's observation time).

## Error handling / graceful degrade

- Readers are total: a missing/unreadable key or folder yields an empty contribution,
  not an error or panic (e.g. HKLM\SYSTEM services may be partially unreadable as a
  non-admin → skip what can't be read, return what can). The collector as a whole only
  returns `Err` if it genuinely cannot proceed; per-mechanism failures degrade to "fewer
  records" and are logged. (The orchestrator already records a collector-level Err into
  `sources[]`; a partial read is success with fewer records.)
- The heuristic is total/pure: missing binary_path → the suspicious-path signal simply
  does not fire; missing last_write → recency does not fire. No panics.
- Determinism (NFR4): the CLI's existing `sort_findings` orders all findings (ts → title
  → tiebreak) before writing; persist findings join that stream.

## Testing

Pure logic → full TDD; OS reads → thin smoke test (as S2-A).

- **binary_path extraction:** quoted path + args → bare path; unquoted path → itself;
  env-var path (`%SystemRoot%\system32\x.exe`) → expanded; junk → None (no panic).
- **persist heuristic (cairn-heur):** an IFEO Debugger in Temp written today → critical
  with T1546.012 + a reason naming the mechanism; a plain old Run key to Program Files →
  no finding (below floor); winlogon Shell tamper → high; missing binary_path / missing
  last_write → still scores mechanism signal, no panic; the 7-day window is exercised
  with an injected `now` (6 days → recency fires; 8 days → not).
- **PersistCollector mapping:** pure RawPersist→Record-style mapping (if a Raw struct is
  used) is TDD'd; mechanism strings match the record contract values.
- **smoke (Windows):** `PersistCollector.collect` returns without panic and yields only
  `Record::Persistence` variants; on a real host it finds at least the ubiquitous HKLM
  Run key entries (don't hard-require specific contents). On non-Windows: returns empty.
- **e2e (manual, Windows):** `cairn run --target live` now emits persistence records +
  any persist findings; findings.jsonl has `artifact:"persistence"` heuristic findings
  with reason; `cairn verify` passes; proc/net (S2-A) and parentchild/netconn (S2-B) and
  evtx (S1) all still work.

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` green; `cargo audit` clean (new dep `winreg` must be
  advisory-free and pinned).
- `unsafe` appears in NO crate except `cairn-collectors-win` (persist collector uses the
  safe `winreg` wrapper; `cairn-collectors` and `cairn-heur` stay `#![forbid(unsafe_code)]`).
- Real live run emits persistence records + explainable persist findings; verify passes;
  S1/S2-A/S2-B paths unchanged.
- No golden-rule violation; no deviation from SRS §4/§5/§10; no scope creep (no signed
  verification, no Scheduled Tasks, no WMI, no hashing — all deferred with rationale).

## Non-goals / future hooks

- **S2-D (next):** WinTrust signature verification in `cairn-collectors-win`; backfill
  `signed` for proc + persist; add the unsigned +20 signal to both netconn and persist
  heuristics and re-tune.
- Later: Scheduled Tasks, WMI subscriptions, binary hashing (FR14), offline-hive
  persistence (raw-NTFS), external LOLBAS dataset.
- The named-constant weight tables are the seam where a config loader plugs in without
  touching logic.
