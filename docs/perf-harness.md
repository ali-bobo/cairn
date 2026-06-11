# T8 parity & perf harness

Stage-1 acceptance (docs/stage1-plan.md T8) has two halves:

1. **Deterministic parity core** — committed, network-free, runs in CI:
   `crates/cairn-sigma/tests/parity.rs` loads the bundled XOR-encoded SigmaHQ rules
   (`rules/sigma/`, pinned per ADR-0003) and asserts each fires on a technique-matching
   synthetic Sysmon EID-1 event (with a real `author`, DRL 1.1) and not on a benign one.
   This is the always-on regression signal.

2. **Corpus + throughput comparison** — environment-dependent, run by hand when an
   EVTX-ATTACK-SAMPLES corpus *and* a Hayabusa binary are present. It can't be a unit
   test (network fetch + external binary + machine-dependent timing), so it lives here
   as a runbook.

## Running the corpus parity + perf comparison

Prereqs: `git`, a Hayabusa release binary on `PATH` (or pass `--hayabusa <path>`), and
network access to fetch the corpus.

```bash
# 1. Fetch the full corpus (gitignored; tests/EVTX-ATTACK-SAMPLES/).
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES \
    tests/EVTX-ATTACK-SAMPLES

# 2. (Re)generate the pinned rule bundle if needed.
bash rules/fetch-and-encode.sh

# 3. Build release (normal profile — no strip/abort tricks; golden rule 2).
cargo build --release

# 4. Cairn over the corpus.
time ./target/release/cairn evtx tests/EVTX-ATTACK-SAMPLES/**/*.evtx --rules rules/sigma

# 5. Hayabusa over the same corpus (CSV timeline), for hit + throughput comparison.
time hayabusa csv-timeline -d tests/EVTX-ATTACK-SAMPLES -o /tmp/hayabusa.csv
```

Compare:

- **Hit parity** — for each `.evtx`, the rule ids Cairn fires vs Hayabusa fires. Record
  matches, Cairn-only (likely a logsource-gating gap, see below), and Hayabusa-only
  (rules Cairn doesn't bundle yet). The bundled set is intentionally small (3 rules), so
  expect Hayabusa-only deltas dominated by rules outside the bundle — that's coverage,
  not a defect. Grow `rules/sigma/` via `fetch-and-encode.sh` to close real gaps.
- **Throughput** — wall-clock and events/sec. Acceptance: Cairn within ~2× Hayabusa on
  the same corpus. Cairn is single-threaded over the file list today; `rayon` fan-out
  across files (collectors are independent) is the lever if it misses the bar.

## Known parity delta (recorded 2026-06-11)

**Logsource gate not yet enforced in matching.** The engine matches purely on field
content; `LogsourceMap`/`referenced_channels()` exist but are not applied as a pre-match
filter. Observed on the `exec_msxsl` fixture: the `Msxsl.EXE Execution` rule
(logsource `process_creation`) fires on BOTH the Sysmon EID-1 (process_creation) record
and an EID-7 (image_load) record, because the EID-7 record also carries an `Image` field
ending in `msxsl.exe`. Hayabusa would gate that rule to process-creation channels/EIDs
and not fire on EID 7.

- **Impact:** over-firing (extra Cairn-only hits on the wrong event type), not a miss.
- **Fix (follow-up, T5/T6 enhancement):** before matching a rule against an event, resolve
  the rule's `logsource` via `LogsourceMap` and skip events whose channel/event_id aren't
  in the resolved set. The de-abstraction map is already built; only the match-time gate
  is missing. Tracked for a post-T8 hardening pass.

This delta is deliberately left to keep T8d (manifest `sigma_ruleset_ver`) focused; it is
documented here so the corpus run interprets the Cairn-only hits correctly.
