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
- contains **no offensive or evasion capability by default** — it does not hide
  from, tamper with, or bypass endpoint security products. It is designed to be
  *visible to* and *recognized as benign by* EDR/AV, and can be built signed and
  documented so it can be allow-listed before use. (The one narrow exception —
  a live, per-conversation, user-approved override for the tool's own developers
  during specific engineering work — never affects a built binary's behavior at
  runtime; see `docs/threat-model.md`.);
- **logs its own actions** (`run.log`) and records full collection provenance and
  hashes in a manifest for chain-of-custody.

Do not use Cairn to access systems without authorization. Doing so may be illegal.

## Platform support

| Platform | Status |
|---|---|
| Windows 10 / 11 x64 | ✅ Full support |
| Windows Server 2016 / 2019 / 2022 x64 | ✅ Full support |
| Linux / macOS | ⚠️ `cairn evtx` only (EVTX+Sigma; no live collectors) |

## What it collects

- **Live process/network/persistence state**: process tree with command lines,
  signature status, and integrity level; network connections; autostart
  mechanisms (Run keys, services, scheduled tasks, WMI event subscriptions,
  IFEO, startup folder, winlogon shell/userinit); active logon sessions.
- **Offline artifacts**: raw NTFS `$MFT`/`$J` (USN journal); registry hives —
  Amcache, Shimcache, UserAssist, BAM; Prefetch; SRUM.
- **Windows Event Logs (EVTX)**: works from either a live host or standalone
  `.evtx` files.

## What it detects

- **80 bundled Sigma rules** (DRL 1.1 licensed, author-attributed in every
  finding) covering LOLBAS abuse, credential access, persistence, privilege
  escalation, defense evasion, lateral movement, PowerShell script-block
  content, authentication/logon abuse, and service installation — see
  `docs/sigma-rule-catalog.md` for the full list and each rule's audit-policy
  prerequisites. Update the bundled set anytime with `cairn update-rules`.
- **9 explainable heuristics** (every finding states *why* it fired, no opaque
  scores): parent-child process relationships (masquerading, script/Office
  parents), persistence mechanism gating with cross-artifact execution
  corroboration, network connections (owner-identity signals independent of
  port rarity, cross-corroborated with persistence findings), timestomping,
  known-vulnerable-driver (BYOVD) detection, account lifecycle events, logon
  brute-force and password-spraying, and a temporal-window correlator that
  attaches nearby USN/network activity to already-flagged processes as
  honestly-labeled circumstantial evidence (never presented as proven
  causation).
- **WMI persistence detection** specifically covers the case most heuristics
  miss: an `ActiveScriptEventConsumer` running inline script content with no
  invoked executable to pattern-match against.

## Honest scope

Cairn reads system state and correlates artifacts — it does not disassemble
code, run a sandbox, or do behavioral/ML-based malware classification. It will
not catch a threat with no forensic footprint in the artifacts above. Where a
detection is circumstantial rather than proven, the tool says so explicitly
(client-facing text avoids overstatement — "assessed," "likely," never
"confirmed" for correlated-but-unproven signals).

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

Or build a ready-to-run package (binary + launcher + rules + docs +
checksums) with `.\scripts\package.ps1` → `dist\cairn-forensics\`.

## Quick start

**Interactive (recommended for first-time use):** double-click
`cairn-launcher.exe` in the packaged distribution for a guided, menu-driven
run — no command-line flags to learn.

**Command line:**

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
| `observations.jsonl` | Inventory items that didn't clear the detection gate — nothing hidden |
| `manifest.json` | SHA-256 of all inputs/outputs + tool version + governance report |
| `report.html` | Self-contained IR summary report — severity/artifact/keyword filtering, no external resources |
| `run.log` | Structured log of every file read and collector action (chain-of-custody) |
| `*.bodyfile` | mactime bodyfile for plaso/log2timeline (optional, `--bodyfile`) |

## Sigma rules

Bundled rules are XOR-encoded on disk to avoid AV false-positives on detection
strings (NOT a security control; key is public — ADR-0002). To audit rules
directly, use `--rules-plain`. Expand or update the set by editing
`rules/ruleset.toml` and running `cairn update-rules`; see
`docs/sigma-rule-catalog.md` for what's bundled today.

## Documentation

| Document | Purpose |
|---|---|
| [USER-MANUAL.md](USER-MANUAL.md) | Full usage guide, flag reference, output format |
| [cairn-SRS.md](cairn-SRS.md) | Software requirements spec |
| [docs/threat-model.md](docs/threat-model.md) | Threat model + golden rules |
| [docs/sigma-rule-catalog.md](docs/sigma-rule-catalog.md) | Every bundled Sigma rule: what it detects, prerequisites, verification status |
| [docs/SOC-runbook-template.md](docs/SOC-runbook-template.md) | Pre-engagement SOC allow-listing template |
| [docs/verifying-a-release.md](docs/verifying-a-release.md) | Binary integrity verification |
| [docs/REMAINING-WORK.md](docs/REMAINING-WORK.md) | Roadmap + backlog |

## License

Code: MIT. Bundled Sigma rules: Detection Rule License (DRL) 1.1 —
rule authors are credited in every detection output row as the license requires.
