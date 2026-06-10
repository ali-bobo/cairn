# ADR-0002: On-disk rule encoding (XOR)

- **Status:** Accepted
- **Date:** 2026-06-10 (UTC)
- **Deciders:** project owner
- **SRS / spec link:** §8 NFR1, §17 D4; threat-model.md (FORBIDDEN list; untrusted-input)

## Context

Bundled Sigma `.yml` rules contain strings (malicious command-line patterns, attacker
tooling names, encoded-payload regexes) that naïve AV signatures flag, causing
false-positive detections on Cairn's own rules directory. Hayabusa hit the same problem
and ships its rules XOR-encoded on disk. We want the same FP avoidance.

This sits in tension with golden rule 2 / the threat-model FORBIDDEN list, which bans
"packing, crypters, obfuscation, deliberate entropy reduction." That ban exists because
those techniques *hide a program's behavior from defenders*. We must make crisp why
encoding rule **data** is categorically different, or the encoding undermines the very
legitimacy narrative the project depends on.

## Options considered

1. **Ship plain `.yml`** — maximally transparent; SOC can read rules directly. Con:
   recurring AV false positives on the rules dir; operational friction (analysts must
   exclude the dir, which is itself a bad signal).
2. **XOR-encode rules with a key embedded in the source** — removes the literal
   malicious strings from disk so byte-signature AV doesn't fire, while remaining
   trivially reversible and fully auditable. Con: must be argued as not-obfuscation.
3. **Encrypt rules with a real secret key** — rejected: a hidden key *is* obfuscation
   and crosses the FORBIDDEN line.

## Decision

**Accept option 2 (XOR-encode), bounded by these non-negotiable constraints:**

1. **The XOR key is a public constant in the open-source code.** It is NOT a secret and
   provides NO confidentiality. Its sole purpose is to keep verbatim malicious strings
   off disk so byte-pattern AV doesn't false-positive. This is the line that separates
   it from the FORBIDDEN "crypters/obfuscation": obfuscation hides intent; a published
   one-byte XOR with a published key hides nothing — anyone, including the SOC and the
   EDR vendor, can decode and read every rule.
2. **Decoded rules are parsed as data only — never executed.** Decoding yields YAML that
   feeds the Sigma matcher's data path. No code path turns rule bytes into executable
   logic (no eval, no dynamic loading).
3. **A `--rules-plain <dir>` bypass exists** so a SOC can point Cairn at un-encoded
   `.yml` and audit exactly what runs. The encoded form is a convenience, not a gate.
4. **The tool is never encoded** (golden rule 2) — only the rules directory.
5. **Document the key and the codec in the README/runbook** so allow-listing reviewers
   can verify the claim themselves.

## Consequences

- threat-model.md references this ADR to resolve the apparent FORBIDDEN-list tension.
- T5/T6 must implement the XOR codec with the published key and honor `--rules-plain`.
- The SOC runbook should mention the codec + key location so reviewers can decode rules
  out-of-band.
- If a SOC objects to any on-disk encoding, `--rules-plain` is the answer; the decision
  is reversible per-engagement at zero security cost.
