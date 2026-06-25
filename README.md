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

## Platform support

| Platform | Status |
|---|---|
| Windows 10 / 11 x64 | ✅ Full support |
| Windows Server 2016 / 2019 / 2022 x64 | ✅ Full support |
| Linux / macOS | ⚠️ `cairn evtx` only (EVTX+Sigma; no live collectors) |

## What it collects / detects (all stages complete)

- **S1** ✅: EVTX parsing + Sigma rule matching → timeline + detection summary + manifest.
- **S2** ✅: live process tree / network state / persistence (Run keys, services,
  scheduled tasks, WMI subscriptions, IFEO, startup, winlogon); raw-NTFS `$MFT`/`$J`
  and offline registry hives (Amcache, Shimcache, UserAssist, BAM, Prefetch, SRUM);
  parent-child, persistence, and network heuristics; resource governance (NFR9/10).
- **S3** ✅: single-archive output (`--zip`) + optional asymmetric encryption (`--encrypt`);
  `--dry-run`; bilingual (en/zh-TW) finding text; bodyfile/plaso export (`--bodyfile`).
- **S4** ✅: `cairn update-rules` — SSRF-gated fetch of Sigma rules from SigmaHQ with
  pin/DRL-1.1 validation and XOR encoding; `cairn verify` integrity gate.

## Privileges

Some collectors require Administrator and `SeBackupPrivilege` (raw disk / locked
files). Cairn degrades gracefully without them: missing-privilege collectors are
skipped and the reason is recorded in `manifest.json`.

## Build

```powershell
# Requires Rust toolchain (https://rustup.rs)
# Set CARGO_TARGET_DIR outside OneDrive to avoid AV lock issues
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo build --release --workspace
```

## Quick start

```powershell
# EVTX-only (no Admin required)
cairn evtx Security.evtx Sysmon.evtx --rules rules/sigma

# Full live triage (Admin PowerShell)
cairn run --target live --output D:\IR\case001 --admin-features `
  --case-id IR-2026-001 --operator analyst --zip

# Verify run integrity
cairn verify D:\IR\case001\manifest.json --rules rules/sigma

# Update bundled Sigma rules from SigmaHQ
cairn update-rules
```

For complete flag reference and output format descriptions, see **[USER-MANUAL.md](USER-MANUAL.md)**.

## Output files

| File | Description |
|---|---|
| `timeline.csv` | Detection timeline: one row per Sigma hit, MITRE-tagged, rule-author attributed |
| `findings.jsonl` | Full Finding objects with `details` (en) + `details_client` (zh-TW) |
| `manifest.json` | SHA-256 of all inputs/outputs + tool version + governance report |
| `run.log` | Structured log of every file read and collector action (chain-of-custody) |
| `*.bodyfile` | mactime bodyfile for plaso/log2timeline (optional, `--bodyfile`) |

## Sigma rules

Bundled rules are XOR-encoded on disk to avoid AV false-positives on detection
strings (NOT a security control; key is public — ADR-0002). To audit rules directly,
use `--rules-plain`. The bundled set is small (3 example rules); expand it by editing
`rules/ruleset.toml` and running `cairn update-rules`.

## Documentation

| Document | Purpose |
|---|---|
| [USER-MANUAL.md](USER-MANUAL.md) | Full usage guide, flag reference, output format |
| [cairn-SRS.md](cairn-SRS.md) | Software requirements spec |
| [docs/threat-model.md](docs/threat-model.md) | Threat model + golden rules |
| [docs/SOC-runbook-template.md](docs/SOC-runbook-template.md) | Pre-engagement SOC allow-listing template |
| [docs/verifying-a-release.md](docs/verifying-a-release.md) | Binary integrity verification |
| [docs/REMAINING-WORK.md](docs/REMAINING-WORK.md) | Roadmap + backlog |

## License

Code: Apache-2.0. Bundled Sigma rules: Detection Rule License (DRL) 1.1 —
rule authors are credited in every detection output row as the license requires.
