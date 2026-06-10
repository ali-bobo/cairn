# Sigma engine selection (Decision D1) — benchmark plan

Pick exactly one engine, hide it behind `cairn_sigma::SigmaMatcher`, keep it swappable.

## Candidates
- `sigma_engine` (SigmaHQ) — compiled matchers, multithreaded, correlation support.
- `sigmars` — Sigma 2.0 modifiers incl. fieldref + correlation rules.
- `tau-engine` (WithSecure) — proven in Chainsaw; battle-tested on EVTX hunting.
- `sigma-rust` (jopohl) — parses YAML + JSON events, Pratt-parsed conditions.

## Evaluation criteria (score each 1-5)
1. Correctness/parity vs SigmaHQ reference on EVTX-ATTACK-SAMPLES labeled set.
2. Sigma spec coverage: modifiers, `1 of`/`all of`, correlation (v2), regex semantics.
3. Author/metadata access (needed for DRL 1.1 rule_author surfacing).
4. Performance (events/sec single + multi-thread) and memory.
5. API ergonomics for our EventRecord.data map; maintenance/activity; license (need MIT/Apache-compatible).

## Method
- Build a 200-300 rule subset + the ATTACK-SAMPLES events. For each engine: load,
  match, diff results vs expected. Record false pos/neg, throughput, integration effort.
- Watch the known risk: regex/modifier semantics differ across engines and even
  Sigma itself doesn't fully define regex — log every divergence.

## Output
Promote docs/adr/adr-0001-sigma-engine.md to Accepted, naming the choice + scores +
fallback (if chosen engine lacks v2 correlation, fall back to shipping converted
hayabusa-rules format or wrapping tau-engine).
