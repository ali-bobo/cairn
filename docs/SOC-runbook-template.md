# Cairn pre-engagement SOC allow-listing runbook (template)

Goal: before running Cairn on a client endpoint, get it recognized as benign by the
client's EDR/AV so it is not blocked or misclassified. Being allow-listed is part of
the engagement, not an evasion measure. Fill the bracketed fields per engagement.

## 1. Artifacts to provide the client SOC
- Binary name: `cairn.exe`, version `[x.y.z]`, build `[build_sha]`.
- SHA-256 of the exact binary: `[hash]` (publish; must match what you run).
- Authenticode signer: `[publisher / cert thumbprint]`, timestamped.
- Link to source + release notes: `[repo URL]`.
- Statement of intent and scope: `docs/threat-model.md` + this runbook.

## 2. Allow-list mechanisms (client applies, per their EDR)
- Microsoft Defender for Endpoint: add allow indicator by **file hash** AND by
  **signing certificate**; submit to MS WDSI as "software developer - false positive"
  if flagged.
- Other EDR (CrowdStrike/SentinelOne/etc.): hash and/or certificate allow rule,
  scoped to the IR window and the specific host(s).
- Prefer **certificate-based** allow when running multiple releases.

## 3. Authorization & scope (record before running)
- Authorizing party: `[name/role]`; date/time window: `[UTC range]`.
- In-scope hosts: `[list]`. Out-of-scope: `[list]`.
- Privileges granted: Administrator? `[y/n]` SeBackupPrivilege? `[y/n]`.
- Output destination (off-target): `[share/USB/SFTP]`. Encryption pubkey: `[id]`.

## 4. Run record (filled by analyst, goes to manifest too)
- Operator: `[name]`  Case ID: `[id]`
- Exact command line: `[...]`
- Start/finish UTC: `[...]`  Host clock skew noted: `[...]`

## 5. Expected EDR behavior
Cairn WILL generate telemetry (file reads, raw volume handle, process/registry
enumeration). This is expected and correct. Coordinate so the SOC distinguishes
Cairn's authorized activity from real threat activity during the window.
