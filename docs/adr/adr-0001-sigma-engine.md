# ADR-0001: Sigma engine selection

- **Status:** Proposed (pending the parity benchmark in docs/sigma-engine-benchmark-plan.md)
- **Date:** 2026-06-10 (UTC)
- **Deciders:** project owner
- **SRS / spec link:** §9 (Sigma integration), §17 D1; benchmark plan in
  `docs/sigma-engine-benchmark-plan.md`

## Context

Stage 1 requires matching Sigma rules over normalized `EventRecord`s and surfacing
`rule_author` (DRL 1.1, golden rule 5). The engine is hidden behind
`cairn_sigma::SigmaMatcher` so it stays swappable, but exactly one engine must be
picked and wired (task T6). The choice is hard to reverse once rules, the
de-abstraction map (T5), and parity tests (T8) are built around its semantics —
especially regex/modifier behavior, which differs across engines and is not fully
pinned down by the Sigma spec itself.

## Options considered

1. **`sigma_engine` (SigmaHQ)** — compiled matchers, multithreaded, correlation
   support. First-party lineage. Pro: alignment with SigmaHQ reference. Con: maturity
   of author-metadata access and our `EventRecord.data` ergonomics TBD.
2. **`sigmars`** — Sigma 2.0 modifiers incl. fieldref + correlation. Pro: modern spec
   coverage. Con: ecosystem maturity TBD.
3. **`tau-engine` (WithSecure)** — battle-tested in Chainsaw on EVTX hunting. Pro:
   proven on exactly our workload. Con: not a 1:1 Sigma engine; may need a conversion
   layer; correlation story differs.
4. **`sigma-rust` (jopohl)** — YAML + JSON event parsing, Pratt-parsed conditions.
   Pro: simple integration. Con: spec-coverage breadth TBD.

## Decision

**Proposed: evaluate `sigma_engine` and `sigmars` head-to-head first**, scoring both
against the five criteria in the benchmark plan (parity, spec coverage, author/metadata
access, performance, ergonomics/license). Promote whichever wins to **Accepted** and
record the scores here. Keep `tau-engine` as the documented fallback if neither gives
acceptable Sigma-2 correlation, per the benchmark plan's fallback clause.

**Evidence required to accept:** a parity diff on the EVTX-ATTACK-SAMPLES labeled subset
(false pos/neg counts), throughput numbers, and confirmation that `rule_author` is
reachable from the matched rule.

## Consequences

- T6 is blocked until this ADR is `Accepted`; T5 (de-abstraction map) can proceed in
  parallel since it is engine-agnostic by design.
- License must be MIT/Apache-compatible (NFR8); a copyleft engine is disqualifying.
- Whatever is chosen, `SigmaMatcher::match_event` must populate `Finding.rule_author`
  or T6's acceptance gate fails.
