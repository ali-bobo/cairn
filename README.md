# Cairn

**Cairn** is an open-source, single-binary, **user-space** live-forensics triage
engine for Windows endpoints, built for authorized incident response by MDR/SOC
analysts. It parses live system state, Windows event logs (EVTX), and offline
NTFS artifacts; applies Sigma detection rules and explainable heuristics; and
produces a concise, severity- and MITRE ATT&CK-tagged timeline with a SHA-256
integrity manifest.

## Intent and authorized use (please read)
Cairn is a **defensive DFIR tool**. It is intended to be run **only on systems you
own or are explicitly authorized to investigate**, as part of a documented incident
response engagement. Cairn:
- runs entirely in **user space** — no kernel driver, no process injection;
- contains **no offensive or evasion capability** — it does not hide from, tamper
  with, or bypass endpoint security products. On the contrary, it is designed to be
  *visible to* and *recognized as benign by* EDR/AV, and ships signed and documented
  so it can be allow-listed before use;
- **logs its own actions** (`run.log`) and records full collection provenance and
  hashes in a manifest for chain-of-custody.

Do not use Cairn to access systems without authorization. Doing so may be illegal.

## What it collects / detects (by stage)
- **S1**: EVTX parsing + Sigma rule matching -> timeline + detection summary + manifest.
- **S2**: live process tree / network state / persistence (Run keys, services,
  scheduled tasks, WMI subscriptions, IFEO, startup, winlogon); raw-NTFS `$MFT`/`$J`
  and offline registry hives (Amcache, Shimcache, UserAssist, BAM); parent-child,
  persistence, and network heuristics.
- **S3**: single-archive output + optional asymmetric encryption; `--dry-run`;
  bilingual (en/zh-TW) finding text.
- **S4**: rule updates + tuning; bodyfile/plaso export; Velociraptor offline-collector packaging.

## Privileges
Some collectors require Administrator and `SeBackupPrivilege` (raw disk / locked
files). Cairn degrades gracefully without them and records what it skipped.

## Build
```
cargo build --release --workspace
```

## Usage (Stage 1)
Triage one or more EVTX files against the bundled, pinned Sigma rules, then verify
the run's integrity:
```
# Parse EVTX + run Sigma -> ./out/{timeline.csv, findings.jsonl, manifest.json, run.log}
cairn evtx Security.evtx Sysmon.evtx --rules rules/sigma

# Re-hash the outputs and re-check the ruleset against the manifest (ADR-0003).
# Exits non-zero if any output byte or any rule was tampered with.
cairn verify out/manifest.json --rules rules/sigma
```
The bundled rules are XOR-encoded on disk only to avoid AV false-positives on the
`.yml` detection strings (NOT a security control; the key is public). To audit or run
un-encoded rules, regenerate the plain copies with `rules/fetch-and-encode.sh` and pass
`--rules-plain` (with `--rules rules/plain`). Every Sigma finding carries its rule's
author (DRL 1.1); output defaults off-target and the tool logs its own actions to
`run.log`.

## License
Code: Apache-2.0. Bundled Sigma rules: Detection Rule License (DRL) 1.1 —
rule authors are credited in detection output as the license requires.
