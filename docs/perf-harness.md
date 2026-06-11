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

## Resolved parity delta — logsource gate (fixed 2026-06-11)

**Was:** the engine matched purely on field content, so a `process_creation` rule could
over-fire on a non-process-creation event carrying the same field. Observed on the
`exec_msxsl` fixture: `Msxsl.EXE Execution` fired on BOTH the Sysmon EID-1
(process_creation) record AND an EID-7 (image_load) record (both carry an `Image` ending
in `msxsl.exe`).

**Fix:** `Engine::event_passes_logsource` now resolves each rule's `logsource` via
`LogsourceMap::windows_builtin()` and gates matching to the EVTX channel/event_id the
logsource denotes (an entry `event_id == 0` means "any EID in that channel"). The gate is
**fail-open**: a logsource that resolves to nothing (unknown category / no logsource)
still matches on content, so unmapped detections are never silently dropped — the right
bias for triage (no false-negatives; a little over-firing only on rules the map can't
place). Verified end-to-end: the EID-7 msxsl over-fire is gone; the fixture run now emits
exactly the two correct process-creation hits. Tests:
`engine::tests::logsource_gate_*`.

This is intentionally a content gate, not a full Hayabusa logsource resolver — it covers
the common Windows logsources seeded in `LogsourceMap`. Rules outside that seed set fall
through fail-open; extend the map to gate them too.
