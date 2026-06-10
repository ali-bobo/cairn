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
| `proc_collector` | process tree, cmdline, image path, signer, integrity | live OS | Record::Process | windows-rs, sysinfo | admin for others | 2 |
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
    cairn-cli/         # bin
    cairn-core/        # Record/Finding types, orchestrator, traits
    cairn-collectors/  # evtx,proc,net,persist,mft,usn,hive,prefetch,...
    cairn-sigma/       # SigmaMatcher trait + chosen backend + mapping
    cairn-heur/        # parentchild,persist,netconn
    cairn-report/      # timeline,summary,manifest,output_sink
    cairn-integrity/   # hashing,manifest,verify
  rules/               # bundled Sigma (DRL1.1) + config maps (optionally encoded)
  docs/                # README(intent), SOC-runbook, threat-model
  tests/               # EVTX-ATTACK-SAMPLES fixtures, parity tests
  .github/workflows/   # reproducible build + sign + hash
```

## 16. Stage roadmap + acceptance gates
- S1 EVTX+Sigma+timeline+manifest. Gate: correct hits on EVTX-ATTACK-SAMPLES; throughput ≤2× Hayabusa; manifest verifies.
- S2 live(proc/net/persist)+heuristics+raw-NTFS+offline hives. Gate: runs admin & degrades non-admin; zero target writes with off-target output; persistence covers WMI subs+sched tasks+services+Run+IFEO.
- S3 archive+encryption+dry-run+client-text+footprint-min. Gate: `verify` passes; dry-run writes nothing; client text reviewed for no-overstatement.
- S4 update-rules+tuning+bodyfile/plaso+velociraptor-packaging. Gate: rule refresh reproducible; plaso ingest works.
- Legitimacy work (sign/README/WDSI/runbook) completed BEFORE first real client use, regardless of stage.

## 17. Open decisions (log)
- D1 Sigma engine choice — pending parity benchmark.
- D2 ESE/SRUM crate maturity — may slip to S3/cut.
- D3 raw-NTFS vs VSS default — default raw, VSS flag.
- D4 rule-encoding on disk (XOR) vs plain — lean encode to avoid AV FP on .yml.
- D5 codename/binary name — placeholder `cairn`.

## 18. Risks
- Crowded space (Hayabusa/Chainsaw/Velociraptor already strong) → value is integration+workflow fit, not raw engine novelty.
- Rust offline-artifact crates (ESE, some hive edge cases) less mature than C#/EZ Tools → may need to wrap or contribute upstream.
- Sigma match parity is non-trivial → budget testing.
- Live-host perturbation is unavoidable → document, minimize, never claim zero-impact.
- Scope is large → MVP-first is mandatory; S1 must stand alone as useful.
