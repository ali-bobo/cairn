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

## License
Code: Apache-2.0. Bundled Sigma rules: Detection Rule License (DRL) 1.1 —
rule authors are credited in detection output as the license requires.
