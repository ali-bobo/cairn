# Cairn

**Cairn** is an open-source, single-binary, **user-space** live-forensics triage
engine for Windows endpoints, built for authorized incident response by MDR/SOC
analysts. It reads live system state and Windows event logs (EVTX); applies
Sigma detection rules and explainable heuristics; and
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
- **Execution evidence**: Prefetch (`C:\Windows\Prefetch\*.pf`).
- **Windows Event Logs (EVTX)**: works from either a live host or standalone
  `.evtx` files.

## What it detects

- **80 bundled Sigma rules** (DRL 1.1 licensed, author-attributed in every
  finding) covering LOLBAS abuse, credential access, persistence, privilege
  escalation, defense evasion, lateral movement, PowerShell script-block
  content, authentication/logon abuse, and service installation — see
  `docs/sigma-rule-catalog.md` for the full list and each rule's audit-policy
  prerequisites.
- **Explainable heuristics** (every finding states *why* it fired, no opaque
  scores): parent-child process relationships (masquerading, script/Office
  parents), persistence mechanism gating with execution corroboration (live
  process, prefetch), network connections (owner-identity signals independent of
  port rarity, cross-corroborated with persistence findings), account lifecycle
  events, logon brute-force and password-spraying, event-log tampering /
  service and task installs / Defender changes, and ClickFix Run-dialog
  commands.
- **Broad persistence coverage** across ~25 autostart locations beyond Run
  keys and services — LSA packages/SSPs, password filters, netsh helpers,
  AppInit/AppCert DLLs, port monitors, time providers, IFEO/accessibility
  backdoors, SilentProcessExit, HKCU COM hijacks, Office Test, logon scripts,
  cmd AutoRun and PowerShell profiles — each mapped to its ATT&CK technique.
  `cairn coverage` prints exactly which techniques this build detects, and
  `docs/COVERAGE.md` explains how to verify each one on a lab VM with Atomic
  Red Team.
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

Some collectors require an elevated Administrator token (Prefetch, other users'
processes and persistence, the Security event log). Cairn degrades gracefully
without it: missing-privilege collectors are skipped and the reason is recorded in
`manifest.json`.

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

**One click (recommended):** double-click `cairn-launcher.exe` in the packaged
distribution. It asks for elevation through a normal UAC prompt, scans the last
30 days of this host (and exports those event logs to `evidence\evtx\` in the
output folder), zips the results and opens `report.html` in the browser. If the
output folder is on the system drive it warns first and asks before writing
anything (run it from a USB drive instead). It also asks for an optional case ID
and operator name.
Drop `.evtx` files or a folder onto it to analyze exported logs instead.

**Command line:**

```powershell
# EVTX-only (no Admin required)
cairn evtx Security.evtx Sysmon.evtx --rules rules/sigma

# Full live triage (Admin PowerShell)
cairn run --target live --output D:\IR\case001 `
  --case-id IR-2026-001 --operator analyst --zip

# Which ATT&CK techniques can this build detect?
cairn coverage

# Verify run integrity (every output's SHA-256 is in manifest.outputs)
cairn verify D:\IR\case001\manifest.json --rules rules/sigma
# ...or a --zip archive directly (inner manifest + <zip>.sha256 sidecar)
cairn verify D:\IR\case001.zip
```

`cairn run` looks back 30 days of EVTX by default (`--since` overrides), exports
those channels to `evidence/evtx/*.evtx` in the output location
(`--no-export-evtx` to skip; never under `--dry-run`), and records host clock
skew only when you pass `--reference-time <RFC3339>` from a trusted clock.

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

## Sigma rules

Bundled rules are plain SigmaHQ YAML under `rules/sigma/`, pinned to one upstream
commit (`rules/sigma/PROVENANCE`) and listed in `rules/ruleset.toml`; read them
directly to audit exactly what runs. To change the set, add or remove the `.yml`
files and the matching `ruleset.toml` entries (a test keeps the two in sync); see
`docs/sigma-rule-catalog.md` for what's bundled today.

## Documentation

| Document | Purpose |
|---|---|
| [USER-MANUAL.md](USER-MANUAL.md) | Full usage guide, flag reference, output format |
| [cairn-SRS.md](cairn-SRS.md) | Software requirements spec |
| [docs/threat-model.md](docs/threat-model.md) | Threat model + golden rules |
| [docs/COVERAGE.md](docs/COVERAGE.md) | Detected ATT&CK techniques and how to verify each one |
| [docs/sigma-rule-catalog.md](docs/sigma-rule-catalog.md) | Every bundled Sigma rule: what it detects, prerequisites, verification status |
| [docs/SOC-runbook-template.md](docs/SOC-runbook-template.md) | Pre-engagement SOC allow-listing template |
| [docs/verifying-a-release.md](docs/verifying-a-release.md) | Binary integrity verification |
| [docs/REMAINING-WORK.md](docs/REMAINING-WORK.md) | Roadmap + backlog |

## License

Code: MIT. Bundled Sigma rules: Detection Rule License (DRL) 1.1 —
rule authors are credited in every detection output row as the license requires.
