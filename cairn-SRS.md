# Cairn — Windows Live-Forensics Triage Engine: Software Requirements Spec (v0.1 draft)

> Codename `cairn` is a placeholder (benign, trail-marker connotation) — rename freely.
> This doc is written dense, for code generation. Sections are independent; cross-refs use [§n].
> Authority: legitimate authorized DFIR only. No evasion, no offensive capability. See [§13].

---

## 1. Identity & Scope

- **What**: single signed Rust binary; agentless; user-space only; on-host Windows triage that (a) parses live + offline artifacts, (b) runs Sigma rules + heuristics, (c) emits a small, severity/ATT&CK-tagged, hashed timeline. Model = Hayabusa(engine) + Chainsaw(artifact hunt) + KAPE(collect/process split) + Velociraptor offline-collector(packaging), fused into one process.
- **Platform**: Windows 10/11, Server 2016+. x64 primary, arm64 later.
- **NOT in scope (hard exclusions)**: kernel driver, process injection, direct/indirect syscalls for hook evasion, AMSI/ETW patch, in-memory exec of remote code, packing/obfuscation/entropy reduction, artifact erasure, log tampering, any remote C2/agent. Any feature needing these = rejected by design [§13].
- **Differentiator vs existing tools**: unified single-pass (live state + EVTX + offline NTFS artifacts) tuned for an MDR analyst's report pipeline; output schema designed to feed downstream report-builder + de-identify tooling; bilingual (zh-TW client / en technical) finding text.

## 2. Glossary
- **Finding**: one normalized detection/observation row [§5.1].
- **Artifact source**: a parseable evidence origin (EVTX channel, MFT, hive, prefetch…).
- **Collector**: module that reads raw artifact → normalized records.
- **Analyzer**: module that consumes records → Findings (Sigma engine or heuristic).
- **Manifest**: integrity+metadata record of a run [§5.3, §12].
- **Locked file**: in-use system file unreadable via normal API; needs raw-NTFS or VSS [§11].

## 3. Architecture (modules + data flow)

```
CLI(clap) ──> Orchestrator
                 │  (run plan: which collectors/analyzers, privilege check, output target)
                 ├─> Collectors ──normalized Records──┐
                 │     evtx, proc, net, persist,       │
                 │     mft, usn, hive, prefetch,        ▼
                 │     amcache, shimcache, srum, ...  Record bus (typed enums, serde)
                 ├─> Analyzers <─────────────────────────┤
                 │     sigma_engine, heur_parentchild,   │
                 │     heur_persist, heur_netconn        │
                 │              │ Findings               │
                 ▼              ▼                         │
              Reporter <────────┴── Records (for timeline)┘
                 │  timeline(csv/jsonl) + summary + findings + manifest(sha256)
                 ▼
              Output sink: dir | zip(+manifest) | encrypted-zip(x509/pgp) | dry-run(virtual)
```

- All collectors emit a common `Record` enum; analyzers consume `Record` and emit `Finding`. Decoupling lets Sigma + heuristics run over the same normalized stream.
- Parallelism: `rayon` over files/records (Hayabusa model). Collectors independent → parallel; analyzers fan-in.
- Memory model: stream records where possible (EVTX, MFT iterate); avoid loading whole artifacts. Keep peak RAM bounded.

## 4. Module specs

Each: responsibility | input | output | key crates | privilege | stage.

| Module | Responsibility | Input | Output | Crates | Priv | Stage |
|---|---|---|---|---|---|---|
| `cli` | arg parse, subcommands, run plan | argv | Config | clap | - | 1 |
| `orchestrator` | sequence collectors/analyzers, volatility order, error capture | Config | run results | - | - | 1 |
| `evtx_collector` | parse EVTX → JSON records | .evtx files / live winevt dir | Record::Event | evtx | user* | 1 |
| `sigma_engine` | compile+match Sigma over Event records | Record::Event + ruleset | Finding | sigma_engine/sigmars/tau-engine | - | 1 |
| `reporter` | timeline, summary, findings, manifest | Records+Findings | files | serde_json, csv, sha2, zip | - | 1 |
| `proc_collector` | process tree, cmdline, image path, signer, integrity | live OS | Record::Process | windows-rs | admin for others | 2 |
| `net_collector` | TCP/UDP tables, listen ports, conn→PID | live OS | Record::NetConn | windows-rs (IpHelper) | user | 2 |
| `persist_collector` | Run/RunOnce, services, sched tasks, WMI subs, IFEO, startup, winlogon | hives+tasks+wmi repo | Record::Persistence | notatin/frnsc-hive, evtx, wmi repo parser | admin | 2 |
| `mft_collector` | $MFT MACB, timestomp delta, path map | raw \\.\C: | Record::FileMeta | ntfs/ntfs-reader | admin+SeBackup | 2 |
| `usn_collector` | $J create/delete/rename history | raw \\.\C: | Record::UsnEvent | ntfs-reader/usn-journal-rs | admin+SeBackup | 2 |
| `hive_collector` | offline hive read (locked) | raw-read hive bytes | Record::RegValue | notatin/frnsc-hive | admin+SeBackup | 2 |
| `amcache_collector` | program/file entries, sha1, first-exec | Amcache.hve | Record::Execution | notatin | admin+SeBackup | 2 |
| `shimcache_collector` | AppCompatCache entries | SYSTEM hive | Record::Execution | notatin | admin+SeBackup | 2 |
| `prefetch_collector` | run times, mapped files | C:\Windows\Prefetch | Record::Execution | frnsc-prefetch | admin | 2 |
| `srum_collector` | per-app/user resource+net bytes | SRUDB.dat (ESE) | Record::Execution | ese parser (eval) | admin+SeBackup | 3 |
| `userassist/bam_collector` | GUI launch counts, per-SID exec window | NTUSER/SYSTEM hive | Record::Execution | notatin | admin | 3 |
| `heur_parentchild` | anomalous parent→child, LOLBAS watchlist | Record::Process/Event | Finding | (internal) | - | 2 |
| `heur_persist` | rank/classify persistence findings | Record::Persistence | Finding | (internal) | - | 2 |
| `heur_netconn` | suspicious egress (rare port, raw IP, bad parent) | Record::NetConn/Process | Finding | (internal) | - | 2 |
| `integrity` | sha256 all sources, build manifest | all | Manifest | sha2 | - | 1→3 |
| `output_sink` | dir/zip/encrypted/dry-run, write off-target | files | archive | zip, flate2, rsa/pgp | - | 1→3 |
| `selftest/log` | log tool's own actions (transparency) | runtime | run.log | tracing | - | 1 |
| `update_rules` | fetch/pin Sigma ruleset | network | rules/ | reqwest (opt) | - | 4 |

\*EVTX from files: user if file readable; live channel read may need admin.

## 5. Data schemas (serde structs — code-gen targets)

**Schema-versioning contract.** `Finding` [§5.1] and `Manifest` [§5.3] are persisted
artifacts and each carries an inline `schema` field (`cairn.finding/1`,
`cairn.manifest/1`). `Record` [§4] is the INTERNAL Collector→Analyzer bus type; it is
NOT independently persisted and does NOT carry a `schema` field. The JSONL Record
interchange/replay path (§7 FR1) versions Records externally via the
`cairn.record/1` constant rather than an inline field. This asymmetry is intentional —
do not add a `schema` field to `Record`.

### 5.1 Finding
```jsonc
{
  "schema": "cairn.finding/1",
  "id": "uuid",
  "ts": "RFC3339 UTC",          // event/observation time
  "detected_at": "RFC3339 UTC", // analysis time
  "severity": "critical|high|medium|low|info",
  "title": "string",
  "source": "sigma|heuristic",
  "rule_id": "string|null",      // Sigma id
  "rule_author": "string|null",  // DRL 1.1 attribution REQUIRED if sigma [§13]
  "mitre": ["T1059.001", ...],
  "host": "string",
  "user": "string|null",
  "artifact": "evtx:Security|process|mft|hive:...|...",
  "entity": {                    // the thing implicated
    "process": {"pid":0,"ppid":0,"image":"","cmdline":"","signed":false,"integrity":""},
    "file": {"path":"","sha256":"","mtime":"","si_btime":"","fn_btime":""},
    "netconn": {"laddr":"","lport":0,"raddr":"","rport":0,"pid":0},
    "registry": {"hive":"","key":"","value":"","data":"","lastwrite":""}
  },                             // only relevant sub-objects populated
  "evidence_ref": "sha256 of raw blob in archive | record id",
  "details": "string",          // technical (en)
  "details_client": "string|null" // plain zh-TW, no jargon, no overstatement [§13]
}
```

### 5.2 Timeline record (CSV cols, Hayabusa-compatible)
`Timestamp,Host,Channel,EventID,Severity,RecordID,RuleTitle,RuleAuthor,MITRE,Details`
- The timeline is a **detection timeline**: one row per rule hit, projected from a
  [Finding §5.1]. The `RuleTitle/RuleAuthor/MITRE/Severity` columns come from the
  Finding, not the raw Record — so `OutputSink::write_timeline_csv` takes `&[Finding]`.
  There is NO separate raw-event timeline in scope (decision: detection-only; revisit
  only if a use case demands a per-event view).
- JSONL variant = full Finding [§5.1] one per line.
- Optional bodyfile export: `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` (plaso/mactime).

### 5.3 Manifest
```jsonc
{
  "schema": "cairn.manifest/1",
  "tool": {"name":"cairn","version":"x.y.z","build_sha":"","sigma_ruleset_ver":""},
  "run": {"started_utc":"","finished_utc":"","cmdline":"","operator":"","case_id":""},
  "host": {"hostname":"","os_build":"","timezone":"","wall_clock_utc_skew":""},
  "privileges": {"admin":false,"se_backup":false,"se_debug":false},
  "sources": [
    {"artifact":"evtx:Security","path":"","method":"api|raw_ntfs|vss","size":0,"sha256":"","errors":[]}
  ],
  "outputs": [{"file":"timeline.jsonl","sha256":""}],
  "counts": {"records":0,"findings_by_sev":{"critical":0,"high":0}},
  "integrity_note": "All hashes SHA-256 over bytes as collected."
}
```
- `host.hostname` source: an EVTX run borrows the parsed `Computer` field; a live run
  (`--target live`) has none, so it is read via `GetComputerNameExW` (in
  `cairn-collectors-win`). A live source (process/net table) is not a byte stream, so its
  `sources[].sha256` is empty and `method="api"` — SHA-256 applies to file-backed sources.

## 6. CLI surface
```
cairn run        --target <dir|live> --output <path> [--zip] [--encrypt <pubkey>]
                 [--dry-run] [--admin-features] [--rules <dir>] [--profile minimal|standard|verbose]
                 [--only evtx,process,persist,...] [--since <ts>] [--case-id <s>] [--operator <s>]
cairn evtx       <files...> [--rules <dir>]              # Stage1 engine only
cairn update-rules [--pin <ref>]
cairn verify     <manifest.json>                          # re-hash & check archive
cairn version
```
Defaults: standard profile, dir output, no admin features unless `--admin-features` AND privilege present. Always writes `run.log`.

## 7. Functional requirements (by stage)

Stage 1 (engine MVP):
- FR1 parse EVTX via `evtx` crate; support .evtx files + JSONL input.
- FR2 load Sigma ruleset; precompiled logsource→{Channel,EventID,field-renames} map (Hayabusa "de-abstraction" model); only run rules whose Channel/EventID present in data.
- FR3 match simple+aggregation+(stretch) correlation rules; emit Finding with severity from `level`, mitre from `tags`, author from rule.
- FR4 output timeline (csv+jsonl), detection summary (counts by sev, top hosts/users, eventID metrics), manifest with sha256 of inputs+outputs.
- FR5 dedupe identical detections with count.
- FR6 write `run.log` of every file read + action.

Stage 2 (live + heuristics + offline artifacts):
- FR7 enumerate processes: pid/ppid tree, cmdline, image path, signer (signed?), integrity level.
- FR8 net tables (TCP/UDP) + conn→PID.
- FR9 persistence enum: Run/RunOnce, services, scheduled tasks (Tasks XML + TaskCache), WMI event subs (__FilterToConsumerBinding + CommandLineEventConsumer), IFEO, startup folders, winlogon.
- FR10 heur_parentchild: flag Office/script→shell, LOLBAS watchlist hits, exec-from-temp/appdata, encoded ps.
- FR11 heur_netconn: rare rport / raw-IP raddr / bad-parent-owned conn.
- FR12 raw-NTFS collect $MFT (MACB + SI/FN timestomp delta), $J, locked hives; offline-parse Amcache/Shimcache/UserAssist/BAM.
- FR13 graceful degrade: missing privilege → skip module, record reason in manifest, continue.
- FR14 hash suspicious binaries (sha256), capture Zone.Identifier (MOTW) when present.

Stage 3 (forensic hardening + legitimacy):
- FR15 single-archive output (zip) + manifest; optional asymmetric encryption (embed public key only).
- FR16 `--dry-run` virtual archive (zero target writes); default to write output off-target.
- FR17 minimize target writes (cf. USN-journal preservation); reapply original timestamps if staging.
- FR18 produce `details_client` (zh-TW plain-language) for each Finding above medium.

Stage 4 (operationalize):
- FR19 `update-rules` fetch + version pin; noisy/exclude/level-tuning lists.
- FR20 bodyfile/plaso export; optional packaging as Velociraptor offline-collector artifact.

## 8. Non-functional requirements
- NFR1 single self-contained binary; bundled rules dir (rules may be XOR-encoded on disk to avoid AV FP on .yml, per Hayabusa precedent — encode *rules*, never the tool).
- NFR2 perf: EVTX throughput within ~2× Hayabusa on same corpus (acceptance, not marketing claim).
- NFR3 memory-safe Rust, `#![forbid(unsafe_code)]` except isolated raw-volume/WinAPI modules behind a reviewed FFI boundary.
- NFR4 deterministic output ordering (sort by ts then recordid) for reproducibility.
- NFR5 all timestamps UTC RFC3339; record host TZ + clock skew in manifest.
- NFR6 no network at runtime except explicit `update-rules`.
- NFR7 cross-compile via `cargo` for x64; CI builds reproducible; release artifacts hashed + signed.
- NFR8 licensing clean: code MIT/Apache-2.0; bundled Sigma under DRL 1.1 with attribution surfaced in output.
- NFR9 **resource governance** (production-host safety): the tool MUST be able to bound its
  own CPU/IO footprint so it never takes a live production host down (the "the IR team
  caused more damage than the attacker" failure). Levers, smallest-blast-radius first:
  (a) a `--max-threads N` cap on the rayon pool (default = min(cores, a sane ceiling), not
  "all cores"); (b) a below-normal process/IO priority by default on a live target
  (`SetPriorityClass` BELOW_NORMAL + `PROCESS_MODE_BACKGROUND_BEGIN` where available),
  overridable with `--full-speed`; (c) `--profile minimal` has DEFINED light-mode
  semantics (skip the heaviest collectors — raw-NTFS $MFT/$J full parse — and run only
  live state + EVTX + persistence). Acceptance: a `--profile minimal` live run on a large
  host stays materially below a `standard` run in peak CPU and RAM (measured, not claimed).
- NFR10 **resource ceilings / circuit breaker**: even on well-formed but huge inputs (a
  multi-GB $MFT, an enormous $J on a long-uptime server), peak RAM MUST stay bounded.
  Streaming iteration (SRS §3) is necessary but not sufficient — analyzers that accumulate
  state MUST have a documented bound. Define configurable ceilings (max records held,
  max per-artifact bytes processed) that, when hit, degrade gracefully (record the
  truncation in `manifest.sources[].errors`, continue) rather than OOM-killing the run.
  This generalizes the threat-model's malformed-input caps to "large-but-honest" inputs.
- NFR11 **output size discipline** (single-host footprint, not fleet orchestration): Cairn
  is agentless single-host triage — it is explicitly NOT a fleet collector. But its archive
  MUST stay small by default: package findings + manifest + run.log + *targeted evidence
  fragments* referenced by `evidence_ref`, NOT whole source artifacts ($MFT/$J/full hives)
  unless explicitly requested (`--collect-raw`). Default archive size SHOULD be on the
  order of MB, not GB. Fleet-scale collection/transport (the "500 endpoints over VPN"
  case) is out of scope by design — delegate to Velociraptor/EDR; Cairn feeds them small,
  typed output.
- NFR12 **OS-version artifact confidence**: offline-artifact parsers (Amcache, Shimcache,
  BAM, UserAssist, SRUM) read undocumented structures that Microsoft changes across builds
  (e.g. 23H2/24H2). A parser that silently misreads a changed structure is worse than one
  that abstains. Each such collector MUST detect when it cannot confidently parse the
  structure for the observed `host.os_build` and record a confidence/abstain note in
  `manifest.sources[].errors` rather than emit wrong data (graceful degrade, golden rule
  8). Wrong forensic data is a defect; "I don't recognize this build's structure" is
  acceptable.

## 9. Sigma engine integration
- Source ruleset: `SigmaHQ/sigma` (+ optionally `hayabusa-rules`), DRL 1.1.
- Do NOT resolve logsource at runtime: ship precompiled mapping table (Channel/EventID/field aliases). Reuse Hayabusa config concepts: `eventkey_alias`, `channel_abbreviations`, `target_event_IDs`, `noisy_rules`, `exclude_rules`, `level_tuning`.
- Engine candidates (eval order): `sigma_engine` (SigmaHQ, compiled+correlation), `sigmars` (Sigma 2.0 modifiers+correlation), `tau-engine` (Chainsaw-proven), `sigma-rust`. Pick one; abstract behind a `SigmaMatcher` trait so it's swappable.
- Known risk: regex/modifier semantics differ across engines → must test match parity vs reference on a labeled corpus (EVTX-ATTACK-SAMPLES).
- LOLBAS: ingest LOLBAS dataset as a watchlist enriching heur_parentchild (binary→expected behavior, ATT&CK, sigma id).

## 10. Heuristics spec
- parent_child: rule table {parent_image_pattern, child_image_pattern, weight}; seed with Office→cmd/powershell/wscript/mshta, services.exe anomalies, explorer→encoded-ps; combine with image-path (temp/appdata/programdata), signer (unsigned), integrity. Score → severity.
- persistence rank: weight by mechanism stealth (WMI sub > IFEO > service > Run key), binary unsigned, path anomaly, recent LastWrite/task mtime.
- netconn: flag {rport not in common-set} ∨ {raddr is literal public IP w/ no DNS} ∨ {owning proc in temp/appdata} ∨ {listener on high port owned by unsigned proc}.
- All heuristics emit Finding with explicit reason string (explainability) — never opaque scores.

## 11. Locked-file & privilege handling
- Primary method: raw `\\.\C:` volume read + NTFS parse (`ntfs`/`ntfs-reader`) → reach $MFT, $J, locked hives, locked Amcache/SRUM. Needs Administrator + SeBackupPrivilege.
- Secondary: create VSS snapshot, read point-in-time copy (consistency / edge cases). Both legitimate; neither is evasion.
- Two-pass (KAPE model): API-copy what's free; raw-read the rest.
- Privilege probe at startup → manifest.privileges; degrade gracefully [FR13].
- Decision default: raw-NTFS primary, VSS fallback flag `--use-vss`.

## 12. Evidence integrity / chain of custody
- SHA-256 over bytes-as-collected for every source + output; record in manifest [§5.3].
- Volatility order: process→net→(then) registry/files.
- Off-target output default; `--dry-run` virtual; never modify sources; log all actions.
- Archive = single zip {data + manifest.json + run.log}, append-only/read-only, optional asymmetric encryption (public key embedded only).
- `cairn verify` re-hashes archive vs manifest.

## 13. Legitimacy / anti-misclassification (REQUIREMENTS, not optional)
- MUST Authenticode-sign + timestamp every release (cert from MS Trusted Root Program CA). Note: post-Aug-2024 EV no longer auto-clears SmartScreen; reputation builds via consistent publisher/hash history.
- MUST embed version/manifest resources (CompanyName, ProductName, FileDescription, version); stable predictable binary name; ship README stating DFIR intent + authorized-use scope; publish release hashes; open-source.
- MUST transparent self-logging (run.log) [FR6].
- MUST provide SOC runbook: pre-allowlist by file-hash + signing-cert (Defender for Endpoint indicators); submit binary to MS WDSI FP portal.
- MUST surface Sigma rule author in output (DRL 1.1).
- Client text MUST NOT overstate (PUP≠infected), define jargon, preserve uncertainty ("assessed","likely") — matches analyst's client-comm principles.
- FORBIDDEN (auto-reject in review): injection, syscall/hook evasion, AMSI/ETW bypass, packing/entropy-reduction/obfuscation, anti-debug/anti-VM, artifact erasure, masquerade naming. EDR SHOULD see the tool and recognize it benign.

## 14. Crate dependency table
| Concern | Crate | Notes/License |
|---|---|---|
| EVTX | evtx (or hayabusa-evtx fork) | proven by Hayabusa+Chainsaw |
| Sigma | sigma_engine / sigmars / tau-engine | pick 1, trait-abstract |
| WinAPI | windows / windows-rs | MIT/Apache; proc enum, IpHelper, registry |
| live registry | winreg | ergonomic |
| raw NTFS/MFT/USN | ntfs, ntfs-reader, usn-journal-rs | raw \\.\C:; elevated |
| offline hive | notatin (primary), nt_hive2/frnsc-hive | log replay support |
| prefetch | frnsc-prefetch | MAM-compressed ok |
| ESE (SRUM) | (evaluate) | maturity TBD — Stage 3 |
| VSS | vss/rawcopy family | fallback path |
| sysinfo | sysinfo | cross-plat proc/system |
| traversal | walkdir | |
| serialize | serde, serde_json, csv | JSONL+CSV |
| hashing | sha2 | SHA-256 |
| cli | clap | |
| parallel | rayon | Hayabusa-style |
| time | chrono / time | UTC |
| archive | zip, flate2 | |
| crypto (opt) | rsa / pgp / age | asymmetric output enc |
| logging | tracing | self-log |
| net (opt) | reqwest | update-rules only |

## 15. Repo layout
```
cairn/
  Cargo.toml (workspace)
  crates/
    cairn-cli/             # bin
    cairn-core/            # Record/Finding types, orchestrator, traits
    cairn-collectors/      # evtx,proc,net,persist,prefetch,... (forbid(unsafe_code))
    cairn-collectors-win/  # Windows unsafe FFI ONLY (proc/net/host/privilege probe;
                           #   later raw-NTFS). The single allow(unsafe_code) crate (NFR3).
    cairn-sigma/           # SigmaMatcher trait + chosen backend + mapping
    cairn-heur/        # parentchild,persist,netconn
    cairn-report/      # timeline,summary,manifest,output_sink
    cairn-integrity/   # hashing,manifest,verify
  rules/               # bundled Sigma (DRL1.1) + config maps (optionally encoded)
  docs/                # README(intent), SOC-runbook, threat-model
  tests/               # EVTX-ATTACK-SAMPLES fixtures, parity tests
  .github/workflows/   # reproducible build + sign + hash
```

## 16. Stage roadmap + acceptance gates

> **Status as of 2026-06-26 (commit `1717a19`):** S1–S4 all complete. 448 tests pass.

- **S1** ✅ EVTX+Sigma+timeline+manifest. Gate: correct hits on EVTX-ATTACK-SAMPLES; throughput ≤2× Hayabusa; manifest verifies.
- **S2** ✅ live(proc/net/persist)+heuristics+raw-NTFS+offline hives. Collectors: proc / net / persist / $MFT / $J / shimcache / amcache / amcache_driver / prefetch / bam / userassist / srum; governance NFR9/10. Gate: runs admin & degrades non-admin; zero target writes with off-target output; persistence covers WMI subs+sched tasks+services+Run+IFEO.
- **S3** ✅ archive+encryption+dry-run+client-text+bodyfile. DirSink / ZipSink / AgeSink / DryRunSink; `details_client` zh-TW; `--bodyfile` mactime export. Gate: `verify` passes; dry-run writes nothing; client text reviewed for no-overstatement.
- **S4** ✅ update-rules (FR19). `cairn-updater` crate: SSRF whitelist + DRL 1.1 + XOR encode + PROVENANCE. Gate: rule refresh reproducible; `cairn update-rules --pin <bad>` errors before network; real-network fetch test passes.
- **Remaining / optional:** Velociraptor collector packaging; `--collect-raw` full artifact bundle; heuristic calibration (D7); binary_path normalization (D6).
- **Legitimacy work** (sign/WDSI/runbook) required BEFORE first real client use, regardless of stage. Currently skipped for self-use (decided 2026-06-22).

## 17. Open decisions (log)
- D1 Sigma engine choice — **RESOLVED (ADR-0001, Accepted): `sigma-rust` 0.7.** Native
  Sigma 2.0, exposes author/id/level/tags (DRL 1.1 reachable). tau-engine kept as the
  behind-the-trait fallback. Parity covered by the T8 harness (docs/perf-harness.md).
- D2 ESE/SRUM crate maturity — **RESOLVED (S3, Accepted): `srum-parser 0.1.0` (MIT, pure Rust) + `tempfile`.**
  VolumeReader reads SRUDB.dat raw → NamedTempFile → srum-parser → `srum_app` + `srum_net` records. Shipped in PR #27.
- D3 raw-NTFS vs VSS default — **RESOLVED: default raw (`\\.\C:` via VolumeReader), `--use-vss` flag defined but not yet implemented.** (VSS implementation remains optional backlog.)
- D4 rule-encoding on disk (XOR) vs plain — **RESOLVED (ADR-0002, Accepted): encode.**
  Public XOR key (codec.rs), decoded-as-data-never-executed, `--rules-plain` SOC bypass.
  Ruleset integrity is separately proven by the ADR-0003 aggregate hash, recorded in the
  manifest as `tool.sigma_ruleset_ver` and re-checked by `cairn verify` (T9).
- D5 codename/binary name — `cairn` confirmed for S1 (was placeholder; now the shipped
  binary name).
- D6 binary_path quality / `signed` coverage — **OPEN (owning stage: S2, a "binary_path
  normalization" sub-segment after S2-E).** S2-D's live run showed `extract_binary_path`
  truncates UNQUOTED command lines containing spaces (`C:\Program Files\Docker\Docker\Docker
  Desktop.exe` → `C:\Program`), so verification can't find the file → `signed = None`.
  Correct resolution = the Windows CreateProcess "probe each successive `<prefix>.exe`"
  search, which forces a design choice: keep `extract_binary_path_with` PURE and return
  candidate paths for the collector to probe, vs. let it touch the filesystem (losing the
  current Linux-CI-testable purity). Bundle with: catalog-signed false reports (needs
  signer-identity extraction, see below) and the S2-D service-ImagePath normalization
  already landed. Impact today is bounded — a missing/clipped path yields `None`, never a
  false positive (the unsigned amplifier requires a suspicious PATH, which `None` cannot
  satisfy).
- D7 heuristic calibration / known-good baselines — **OPEN (owning stage: a dedicated
  heuristic-tuning sub-segment, after proc `signed` lands in S2-E).** S2-C/S2-D scoring is
  intentionally sensitivity-biased; a live run produces a few expected-but-noisy High
  findings (per-user apps in `AppData\Local\Programs` like Notion/Warp; Winlogon entries
  carrying their default `explorer.exe`/`userinit.exe` values). These are not bugs — they
  are the cost of not yet having known-good baselines. Lowering them needs: a Winlogon
  default-value allowlist, AppData publisher/signer trust (depends on signer-identity from
  S2-E+), and a representative benign corpus to calibrate against — done carelessly, an
  allowlist creates FALSE NEGATIVES (an attacker swapping the Winlogon Shell is the classic
  attack). Deliberately deferred to a focused tuning pass with real calibration data, not
  hand-tuned inline.

## 18. Risks
- Crowded space (Hayabusa/Chainsaw/Velociraptor already strong) → value is integration+workflow fit, not raw engine novelty.
- Rust offline-artifact crates (ESE, some hive edge cases) less mature than C#/EZ Tools → may need to wrap or contribute upstream.
- Sigma match parity is non-trivial → budget testing.
- Live-host perturbation is unavoidable → document, minimize, never claim zero-impact.
- Scope is large → MVP-first is mandatory; S1 must stand alone as useful.
- **Resource exhaustion on production hosts** → an uncapped rayon pool + Sigma over huge
  EVTX, or a multi-GB $MFT/$J parse, can spike a live server to 100% CPU/RAM and cause an
  outage. Mitigation: NFR9 (thread/priority caps, defined `--profile minimal`) + NFR10
  (bounded peak RAM / circuit breaker). The triage tool must not become the incident.
- **EDR first-run window (reputation gap)** → before SOC allow-listing takes effect, a
  never-seen signed binary that reads low-level artifacts may be blocked/quarantined on
  first run (post-Aug-2024 EV no longer auto-clears SmartScreen; reputation is historical).
  Mitigation is procedural, not technical: SOC pre-allow-list by hash + signing cert BEFORE
  deployment (docs/SOC-runbook-template.md), submit to MS WDSI. Documented as a known
  operational precondition, not something the tool can self-solve without becoming evasive
  (which is forbidden, §13). See §19.
- **OS-build artifact drift** → Microsoft changes undocumented artifact structures
  (Amcache/Shimcache/BAM/SRUM) across Windows builds; a parser that silently misreads is
  worse than one that abstains. Mitigation: NFR12 (per-build confidence/abstain). Ongoing
  maintenance burden (FR19 tuning) is expected, not a defect.

## 19. Operational resilience (production-deployment design notes)

These notes consolidate the production-field concerns surfaced during design review
(2026-06-13) into one place, each mapped to the requirement that governs it and the stage
that implements it. They are DESIGN RECORD: no current sub-segment is blocked on them, but
they MUST be honored when the owning stage is built.

### 19.1 Don't take the host down (NFR9, NFR10) — owning stage: S2 (raw-NTFS) / S3 hardening
- Default the rayon pool to a capped size, not all cores; expose `--max-threads`.
- On a live target, lower process + IO priority by default (`SetPriorityClass`
  BELOW_NORMAL_PRIORITY_CLASS, `PROCESS_MODE_BACKGROUND_BEGIN`); `--full-speed` opts out.
  These WinAPI calls go in `cairn-collectors-win` (the unsafe-FFI crate), behind a safe
  wrapper, and are themselves benign (a forensic tool yielding CPU is not evasion).
- `--profile minimal` = live state + EVTX + persistence only; SKIP raw-NTFS $MFT/$J full
  parse and the heaviest offline collectors. `standard` = + offline artifacts.
  `verbose` = everything.
- Analyzer state bounds (NFR10): document each analyzer's peak-memory behavior; where an
  analyzer accumulates (e.g. correlation), cap held records and record truncation in the
  manifest rather than growing unbounded.

### 19.2 Keep output small (NFR11) — owning stage: S3 (archive/output_sink)
- Default archive = findings + manifest + run.log + evidence fragments referenced by
  `evidence_ref` (small carved slices, hashed). NOT whole $MFT/$J/hives.
- `--collect-raw` is the explicit opt-in for full raw artifacts (the GB case), for when an
  analyst truly needs the source bytes; off by default.
- Fleet-scale collection/transport is OUT OF SCOPE: Cairn emits small typed output for a
  fleet tool (Velociraptor/EDR) to carry. The SRS §1 "agentless single-host" identity is
  the boundary; do not grow Cairn into a fleet collector.

### 19.3 Survive EDR first contact (§13, §18) — owning stage: legitimacy work (any stage)
- Technical posture is fixed: be visible + benign (golden rule 1). The tool will NOT add
  any evasion to get past an EDR — that is auto-reject.
- The first-run reputation gap is solved PROCEDURALLY: SOC pre-allow-list by file hash +
  signing certificate before deployment (docs/SOC-runbook-template.md), submit binary to
  MS WDSI FP portal, build publisher/hash history over time. This is a deployment
  precondition documented for the operator, not a code feature.
- Even the S3 encrypt-and-archive step (which superficially resembles exfil staging) stays
  transparent: it is logged in run.log, the public key is embedded (no key exchange), and
  the behavior is predictable and documented in the runbook so a SOC can recognize it.

### 19.4 Don't emit wrong forensic data on new Windows builds (NFR12) — owning stage: S2/S3 offline collectors
- Each offline-artifact collector validates it can parse the structure for the observed
  `host.os_build`; on an unrecognized layout it ABSTAINS (records a confidence note in
  `manifest.sources[].errors`) instead of emitting guessed values.
- The `update-rules` channel (FR19) is the maintenance lever for keeping parsers and
  tuning current as Microsoft ships new builds; ongoing tracking is an accepted cost.

---

## 20. Development history (decision log + known-good lessons)

This section records the implementation journey for future maintainers: what was decided,
what broke, and why. Design specs and implementation plans live in `docs/dev-history/`
(one file per segment). The git log is the authoritative line-by-line record; this section
captures the *why* that git messages omit.

### 20.1 Stage 1 — EVTX + Sigma + timeline + manifest (2026-06 early)

**Commit range:** `341d1f8` (initial) → `1fc3374` (S1 wrap-up)

**Key decisions:**
- `sigma-rust 0.7` chosen over `tau-engine` / `sigmars` (ADR-0001): native Sigma 2.0
  modifiers, exposes `author`/`id`/`level`/`tags` needed for DRL 1.1 compliance.
- Rules XOR-encoded on disk (ADR-0002): public key, decoded-as-data-never-executed,
  prevents byte-pattern AV FP on bundled `.yml`. `--rules-plain` provides SOC bypass.
- ADR-0003: aggregate SHA-256 of decoded rules stored as `sigma_ruleset_ver` in manifest;
  `cairn verify` re-checks it. Prevents silent rule tampering.
- Logsource de-abstraction (Hayabusa model): precompiled Channel/EventID/field-alias map
  (`eventkey_alias`, `channel_abbreviations`) rather than runtime resolution.
- `cairn verify` subcommand: re-hash outputs+sources against manifest, independent of scan.

**Lessons learned:**
- Sigma engine's logsource gate must be enforced or it over-fires on unrelated channels
  (`eb9e766`: enforce logsource gate fix).
- Windows PE version resource embedded at build time (`a95c74c`) — a self-identifying
  binary is a legitimacy requirement, not optional polish.

---

### 20.2 Stage 2 — live proc/net/persist + heuristics + raw-NTFS + offline hives (2026-06-12 to 2026-06-23)

**Commit range:** `5395192` (collectors-win scaffold) → `df29f72` (userassist, S2 sealed)

**Segment sequence (36 plan files, see `docs/dev-history/`):**
- S2-A: orchestrator + proc/net collectors (PR #1)
- S2-B: heuristics (parent-child, netconn)
- S2-C/D: persistence (Run/IFEO/service/sched-task/WMI/winlogon/startup), signer path
- S2-E/F/G/H: binary path normalization, catalog-signed, heuristic calibration
- S2-I/J/K: scheduled tasks, signer identity, binary hashing
- S2-L/M: profile wiring, raw-NTFS volume primitive (`VolumeReader`)
- S2-N: $MFT MACB + timestomp detection + path reconstruction (`resolve_path`)
- S2-O: path map (parent reference chain → full path, PR #17)
- governance (PR #18, NFR9/10): `--max-threads`, `--full-speed`, below-normal IO priority
- hive reader + shimcache (PR #20): `notatin` with `.LOG1/.LOG2` replay in-memory (no
  temp file). **Key discovery:** `notatin` has `from_file<R:ReadSeek>` — no path needed.
  `nt_hive2` excluded (GPL-3.0 licence contagion). `nom` pinned to 7.1.3 (notatin
  declared `>=6`, cargo resolved to 8 which broke builds).
- USN $J (PR #19): ntfs crate reads `$UsnJrnl:$J` as ADS — zero new deps. Sparse runs
  auto-filled with zeros; `RecordLength==0` is the authoritative "no record" sentinel.
- amcache collector (PR #21): `InventoryApplicationFile` key; SHA-1 from `FileId` 40-hex
  suffix. **Bug caught in review:** `Vec::with_capacity(u32::MAX)` OOM risk — capped to
  `1<<20` for pre-alloc only (loop runs full count). Per-entry `continue` on value-read
  error (golden rule 8).
- amcache_driver (PR #22, BYOVD): `InventoryDriverBinary` → `Record::Execution
  source="amcache_driver"`. Refactored to `InventorySpec` + shared `collect_inventory()`
  helper; `first_non_empty_read()` pure early-stop selector catches non-equivalence bug.
- prefetch collector (PR #23): `compcol 0.6.5` (MIT, forbid-unsafe) for MAM
  Xpress-Huffman. **Two real bugs caught:**
  (a) MAM frame = `[u32 LE length][bitstream]`; original code sliced `raw[8..]` but
      correct offset is `raw[4..]` — unit tests false-positived because fixture was
      self-framed. Fixed + regression guard added.
  (b) This machine's prefetch is **v31** not v30; `run_count` offset is `0xC8` not
      `0xD0`. Found via live probe. **Lesson: medium-confidence format offsets MUST be
      validated on a real machine — unit tests with self-made fixtures will false-positive.**
- BAM collector (PR #24): SYSTEM hive `{ControlSet}\Services\bam\State\UserSettings\<SID>`
  ACL-protected; raw `\\.\C:` read bypasses ACL. `list_values` ground truth from notatin
  source: `detail.value_name()` (not a public field — accessor only). ControlSet number
  from `Select\Current` REG_DWORD = `CellValue::U32` (verified in cell_value.rs:30).
- userassist (PR #25, S2 sealed): per-user NTUSER.DAT, ROT-13 decode, 72-byte struct
  (`run_count`@4, FILETIME@60), SID reverse-lookup via SOFTWARE ProfileList. `list_dir_names`
  filters `NtfsFileNamespace::Dos` to avoid 8.3 short-name duplication — `dedup()` alone
  insufficient because `"DEFAUL~1" != "DefaultUser"`.

**Heuristic calibration lessons (S2-H/noise-reduction segment):**
- Inbox Windows services (DcomLaunch, Dhcp, tcpip.sys…) flood findings — suppressed via
  `is_inbox_service_command()` gate before scoring (not a whitelist, a structural check).
- cairn.exe itself scored Medium (AppData path); suppressed by excluding own PID.
- `details_client` said "未知程式" even when path known — template dispatch by `f.artifact`.
- Timeline `Details` was debug-format key=value — replaced with human-readable sentences.

---

### 20.3 Stage 3 — archive + encryption + dry-run + client text + bodyfile (2026-06-24/25)

**Commit range:** `9c0f2a4` (srum) → `5b210b7` (bodyfile, S3 sealed)

**Segments:**
- srum_collector (PR #27): `srum-parser 0.1.0` (MIT, pure Rust). VolumeReader reads
  SRUDB.dat raw → `tempfile::NamedTempFile` → parse → `srum_app` + `srum_net`. SRUDB.dat
  is an ESE database; no pure-Rust ESE crate was mature enough to write from scratch.
- output_sink (FR15/16/17): `DirSink` / `ZipSink` (`zip 2.4`) / `AgeSink` (age X25519
  asymmetric encryption, public key embedded only) / `DryRunSink` (zero writes). Symlink
  write guard tested. `zip::write::FileOptions::<()>::default()` requires turbofish in
  zip 2.4 API.
- details_client (FR18): static template dispatch by `f.artifact`; zh-TW plain-language,
  no overstatement, preserves uncertainty language ("assessed", "likely").
- bodyfile / plaso export (FR20): mactime 11-column format, `--bodyfile <path>` CLI flag,
  live-run only, auto-skipped on `--dry-run`.

---

### 20.4 Stage 4 — update-rules (2026-06-25/26)

**Commit range:** `f4bab7e` (update-rules, S4 sealed). PR: `cairn-updater` crate.

**Design:** `cairn update-rules [--pin <sha>]`. SSRF whitelist gates all fetch URLs to
`raw.githubusercontent.com/SigmaHQ/sigma`. DRL 1.1 `author:` field validated before
accept. XOR-encodes output into `rules/sigma/`, writes `PROVENANCE` file (pin SHA +
aggregate hash). Bad pin errors before any network request.

**Security review:**
- Whitelist domain check prevents redirect-based SSRF.
- Rules are data, never executed (ADR-0002).
- Network only on explicit `update-rules` subcommand (NFR6).

---

### 20.5 Post-S4 features — live EVTX integration + cairn-launcher + HTML report (2026-06-27)

**Commit range:** `776ec21` (live EVTX spec) → `c030a69` (HTML report wired)

**Live EVTX integration:**
- `EvtxLiveCollector` reads `C:\Windows\System32\winevt\Logs\` — only Sigma-referenced
  channels, filtered by `cfg.since` (default 24 h). Per-file graceful degrade.
- `SigmaAnalyzer` wraps `Engine` as an `Analyzer` trait implementor.
- `Engine` gains `ruleset_ver: String` field; `sigma_ruleset_ver` in manifest now filled
  from live ruleset rather than hardcoded empty string.

**cairn-launcher** (`crates/cairn-launcher`, commits `6038c7c`→`440abed`):
- Problem: `cairn.exe` requires typing `--rules`, `--output`, `--since` in ISO8601; not
  usable by non-technical responders. Solution: double-click `cairn-launcher.exe`.
- 5 modules: `main.rs` (env check + loop) / `menu.rs` (box UI) / `runner.rs` (arg build
  + subprocess) / `summary.rs` (reads `manifest.json` + `findings.jsonl`) / `package.rs`
  (zip + `explorer.exe`).
- CRT static link via `.cargo/config.toml` `[target.x86_64-pc-windows-msvc] rustflags =
  ["-C", "target-feature=+crt-static"]`. Virtual workspace manifests cannot hold
  `[target.*]` — must go in `.cargo/config.toml`, not `Cargo.toml`.
- Box UI truncates hostname and rules version string to prevent box overflow on FQDNs
  (`truncate()` uses `chars().count()` for CJK correctness).
- `zip::write::FileOptions::<()>::default()` turbofish required (zip 2.4 API).

**HTML report** (`crates/cairn-report/src/html.rs`, commits `b8aaa5f`→`c030a69`):
- Every scan now auto-generates `report.html` (self-contained, inlined CSS, no JS).
- XSS escape: `esc()` escapes `&` first, then `<>'"` — order matters to prevent
  double-encoding.
- `OutputSink::write_html_report()` default no-op in `cairn-core` (trait); `DirSink`
  overrides in `cairn-report` (avoids circular dep: `cairn-core` cannot depend on
  `cairn-report`).
- Placement in `cairn-cli/src/main.rs`: after `write_findings_jsonl`, before
  `manifest_outputs_then_write` (which moves `manifest`).

---

### 20.6 Cross-artifact correlation analyzer (2026-06-26)

**Commits:** `ce80533`→`a495dd0`

**Design:** `CorrelationAnalyzer` emits `High` Finding when the same binary appears in
≥2 artifact categories simultaneously:
- Category A: `PersistenceRecord` (any autorun mechanism)
- Category B: `ExecutionRecord` (prefetch / amcache / BAM / userassist / shimcache)
- Optional C: live `ProcessRecord` (binary also currently running — added to `reason`)

Inbox services suppressed (the `PersistHeuristic` already covers them; a correlation
Finding on `svchost.exe` would be noise). Key: `normalized_basename()` is the join key
across artifact types — full path may vary by hive/artifact.

---

### 20.7 Deployment package

**Location:** `dist/cairn-forensics/` (not git-tracked; regenerate with `scripts/package.ps1`)

```
dist/cairn-forensics/
├── cairn-launcher.exe   # double-click entry for non-technical responders
├── cairn.exe            # forensics engine
└── rules/sigma/         # XOR-encoded Sigma rules
```

`output/` is created by the launcher in the same directory on first scan.

**Build command (from workspace root, Admin PowerShell):**
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo build --release -p cairn-cli -p cairn-launcher
# then run scripts/package.ps1 to copy to dist/
```
