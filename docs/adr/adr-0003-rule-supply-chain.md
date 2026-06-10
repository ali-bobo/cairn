# ADR-0003: Sigma ruleset supply-chain integrity

- **Status:** Proposed
- **Date:** 2026-06-10 (UTC)
- **Deciders:** project owner
- **SRS / spec link:** §6 (`update-rules --pin`), §9 (ruleset source), §5.3 (manifest
  `sigma_ruleset_ver`); threat-model.md (untrusted-input #2)

## Context

Cairn's detections are only as trustworthy as its rules. Rules originate from an
external, mutable source (`SigmaHQ/sigma`, optionally `hayabusa-rules`). The CLI exposes
`update-rules --pin <ref>` and the manifest carries `sigma_ruleset_ver`, but neither is
defined: what does `--pin` pin, and how is ruleset integrity proven in a run? Without a
definition this is an unmanaged supply-chain dependency (cf. the global dependency-pin
policy) and a tampering vector (threat-model untrusted-input #2).

## Options considered

1. **Pin a git ref (commit SHA)** — exact, reproducible; ties the ruleset to an
   immutable upstream commit. Con: doesn't by itself detect post-fetch tampering of the
   bundled copy.
2. **Pin an aggregate content hash** — SHA-256 over the canonicalized rule set (sorted
   file list + per-file hashes). Detects any local tampering. Con: must define the
   canonicalization precisely or the hash isn't reproducible.
3. **Both: commit SHA for provenance + aggregate hash for integrity** — provenance says
   *where rules came from*; the hash says *they haven't changed since*.

## Decision

**Proposed: adopt option 3.**

- `update-rules --pin <ref>` pins the upstream **git commit SHA**. The fetched set is
  recorded with that SHA.
- An **aggregate SHA-256** is computed over the canonical rule set (lexicographically
  sorted relative paths, each followed by its file SHA-256; computed on the *decoded*
  plain YAML so the §ADR-0002 XOR layer doesn't affect it) and stored as
  `manifest.tool.sigma_ruleset_ver = "<commit-sha>+<aggregate-sha256>"`.
- `cairn verify` recomputes the aggregate hash of the rules actually used and flags a
  mismatch — extending verify (T9) from output/source hashing to ruleset integrity.

**To accept:** confirm the canonicalization is reproducible across machines and that the
aggregate hash is stable under the XOR codec (compute pre-encode).

## Consequences

- Defines the previously-undefined `--pin` and `sigma_ruleset_ver`.
- Adds a ruleset-integrity check to `cairn verify` (note in stage1-plan T9; the fetch
  side is S4 `update-rules`, but the manifest field + verify check land in S1/S3).
- Closes threat-model untrusted-input #2 (only run rules from a pinned, integrity-checked
  set).
