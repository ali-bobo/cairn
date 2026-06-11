# ADR-0001: Sigma engine selection

- **Status:** Accepted — `sigma-rust` (jopohl) v0.7.x
- **Date:** 2026-06-11 (UTC)
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

**Accepted: `sigma-rust` (jopohl), MIT OR Apache-2.0.**

A candidate survey (2026-06-11) decided it on the hard criteria, deferring the heavy
parity-diff to T8 (which is itself the parity/perf harness task — running it twice is
wasteful):

- **`sigma_engine`** — not published on crates.io; not a usable dependency. Eliminated.
- **`tau-engine` 1.15** — mature (Chainsaw's engine) but a generic document-tagging
  engine, not a native Sigma parser; would need a Sigma→tau conversion layer. Heavier
  than warranted for Stage 1. Kept as the documented fallback if sigma-rust's spec
  coverage proves insufficient at T8.
- **`sigmars` 0.2.2** — early (0.2.x); author-metadata access unverified. Passed over.
- **`sigma-rust` 0.7** — native Sigma 2.0; the `Rule` struct publicly exposes
  `author: Option<String>` (satisfies DRL 1.1 directly), plus `id`, `title`,
  `level: Option<Level>`, `tags: Option<Vec<String>>` (MITRE `attack.t*`), and
  `logsource: Logsource`. Events are built from JSON (`event_from_json`) and matched
  with `Rule::is_match(&Event) -> bool` — our `EventRecord.data` is already a JSON map,
  so the integration is direct. Best fit; chosen.

**Residual risk (revisit at T8):** sigma-rust's correlation/aggregation and exact
regex/modifier semantics vs the SigmaHQ reference are not yet parity-tested. T8 must
diff against the labeled corpus and, if coverage gaps appear, either contribute upstream
or fall back to tau-engine behind the unchanged `SigmaMatcher` trait.

## Consequences

- T6 implements `SigmaMatcher` over sigma-rust: load rules (decode via codec, ADR-0002),
  apply LogsourceMap field aliasing, match `EventRecord` → `Finding`, mapping
  `author`→`rule_author` (DRL 1.1), `level`→severity, `tags`→mitre.
- License is MIT/Apache (NFR8 satisfied).
- The `SigmaMatcher` trait keeps the engine swappable, so the T8 fallback to tau-engine
  stays cheap if needed.
