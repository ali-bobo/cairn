# Cairn threat model & scope of authority

## Purpose
State, unambiguously, what Cairn is allowed to do and what it must never do, so
that (a) the tool stays a defensive DFIR instrument, and (b) reviewers can reject
any contribution that crosses the line.

## Operating assumptions
- Run by an authorized analyst on an owned/authorized host during IR.
- May run with or without Administrator. Raw-disk artifacts need admin + SeBackup.
- The host's own EDR/AV is present and SHOULD observe Cairn. Cairn is allow-listed
  by the client SOC before use (see SOC-runbook-template.md). Being seen is correct.

## Security properties Cairn must preserve
1. Host integrity: collectors are read-only w.r.t. the target. No writes to source
   artifacts; output written off-target by default; footprint minimized.
2. Evidence integrity: SHA-256 over bytes-as-collected; provenance + privileges +
   UTC times in manifest; `cairn verify` re-checks. Chain of custody defensible.
3. Confidentiality of output: optional asymmetric encryption of the result archive
   (public key embedded only; private key never on the host).
4. Transparency: the tool logs its own actions; it is open-source and signed.

## FORBIDDEN capabilities (auto-reject by default)
These overlap with malware/offensive tooling and are out of scope by design.
**Exception (2026-07-15, user-approved)**: any item below may be overridden only
by the user's explicit, per-conversation approval of that *specific* technique —
see CLAUDE.md GOLDEN RULES §1. No blanket or standing exception exists; a prior
approval does not extend to a new conversation or a different technique, and
each use must be logged (commit message or this file's lesson log) naming what
was approved and why.
- process injection / hollowing / APC / thread hijack;
- direct or indirect syscalls to bypass user-mode hooks; unhooking;
- AMSI or ETW patching/bypass;
- in-memory execution of downloaded/remote code;
- packing, crypters, obfuscation, deliberate entropy reduction (these RAISE
  suspicion and are malware indicators — the opposite of the project's goal);
- anti-debug / anti-VM / sandbox-evasion;
- erasing, clearing, or tampering with logs or forensic artifacts;
- masquerading as a system binary (naming/metadata) to deceive defenders;
- any remote control / C2 / agent persistence.

## Cairn as a target: untrusted-input handling

The FORBIDDEN list above governs what Cairn must not *do*. This section governs what
is *done to* Cairn. Cairn's core job is to parse evidence on a possibly-compromised
host — EVTX, NTFS structures, registry hives, and bundled rules. **Treat every parsed
artifact as attacker-controlled.** An adversary who anticipates IR may plant malformed
or hostile artifacts to crash the tool (denying triage), exhaust resources, or corrupt
the evidence chain. A forensic tool that falls over on hostile input is itself a
finding. Required postures (each maps to a Stage-1+ acceptance test):

1. **Malformed EVTX** (T4) — corrupt BinXML, oversized chunks, lying record counts.
   *Mitigation:* use the proven `evtx` crate; stream records (bounded peak RAM, SRS §3);
   cap per-record and per-file size; on a parse error, record the error in the manifest
   `sources[].errors` and continue (graceful degrade, golden rule 8) — never panic the run.
2. **Hostile Sigma YAML** (T5/T6) — ReDoS via pathological regex, YAML alias bombs
   (billion-laughs). *Mitigation:* load rules ONLY from a pinned, trusted ruleset
   (see SRS §9 / ADR-0003 rule supply chain); use a non-backtracking regex engine or a
   match timeout/complexity bound; use a YAML parser with alias-expansion limits.
3. **Output path traversal / symlink / junction redirect** (T7) — a crafted host name,
   case id, or rule title steering the timeline/manifest write onto the *target* volume
   or over an existing file, violating "never modify source / output off-target"
   (golden rule 4). *Mitigation:* canonicalize the output path; reject writes whose
   resolved path lands on the target/source volume; refuse to follow symlinks/junctions
   for output; sanitize any artifact-derived string used in a filename.
4. **Decompression amplification** (S3 `verify`/archive) — zip-bomb when re-reading an
   output archive. *Mitigation:* enforce an uncompressed-size and entry-count ceiling.

Cross-references: rule integrity → SRS §9 and ADR-0003; rule on-disk encoding (which is
NOT a security control) → ADR-0002.

## Why "be visible", not "be invisible"
Legitimacy is reputation-based: Authenticode signing, stable naming, version
resources, published hashes, open source, and SOC pre-allow-listing make the tool
trusted. A tool that tries to evade EDR looks exactly like the threat it hunts.
This remains the project's default posture even with the narrow, user-approved
exception clause above — the exception exists for a deliberate, logged, one-off
decision by the user, not as a routine way to quiet AV noise. Signing and
hash-based allow-listing (docs/verifying-a-release.md, docs/SOC-runbook-template.md)
are the intended default remedy for false positives.
