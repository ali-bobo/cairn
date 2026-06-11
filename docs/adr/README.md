# Architecture Decision Records (ADRs)

Each ADR captures one significant, hard-to-reverse decision: the context, the options
weighed, the choice, and its consequences. They make the project's decision history
auditable — which is part of "specs are managed and controlled," not an afterthought.

- Use `adr-0000-template.md` for new records. Number sequentially, never reuse a number.
- An ADR is immutable once `Accepted`. To change a decision, write a new ADR that
  supersedes the old one and flip the old one's status to `Superseded by ADR-NNNN`.
- `Proposed` = decided in principle, pending evidence (e.g. a benchmark). Promote to
  `Accepted` once the evidence is in; record the evidence in the ADR.

## Index

| ADR | Title | Status | SRS link |
|-----|-------|--------|----------|
| [0001](adr-0001-sigma-engine.md) | Sigma engine selection (sigma-rust) | Accepted | §9 D1 |
| [0002](adr-0002-rule-encoding.md) | On-disk rule encoding (XOR) | Accepted | §8 NFR1, §17 D4 |
| [0003](adr-0003-rule-supply-chain.md) | Sigma ruleset supply-chain integrity | Proposed | §6, §9 |
