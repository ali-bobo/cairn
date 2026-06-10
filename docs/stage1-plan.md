# Stage 1 build plan (EVTX + Sigma + timeline + manifest)

Goal: a standalone, useful tool — `cairn evtx <files> --rules <dir>` parses EVTX,
runs Sigma, writes a severity/ATT&CK-tagged timeline (csv+jsonl), a detection
summary, and a verifiable SHA-256 manifest. Acceptance gate for the whole stage:
correct hits on the EVTX-ATTACK-SAMPLES corpus; throughput within ~2x Hayabusa on
the same set; `cairn verify` confirms the manifest.

Work strictly top-to-bottom. After each task: `cargo check` + that task's test.

## T0 — Toolchain & deps sanity
- `cargo check --workspace`; fix/pin every dependency version until it compiles.
- Set authors/repo in Cargo.toml. Add CI (.github/workflows) doing check+test+clippy+fmt.
- Commit `Cargo.lock` (reproducible builds, NFR7; global dependency-pin policy).
- Run `cargo audit`; resolve or document any advisory before the gate (global dep-security policy).
- Define build-metadata injection for `manifest.tool.build_sha` (e.g. `vergen` or a
  `build.rs` reading the git SHA) so the manifest can carry the real build commit (B4).
- Accept: clean `cargo check` + `cargo clippy -D warnings`; `cargo audit` clean (or
  documented); `Cargo.lock` committed; `build_sha` resolvable at build time.

## T1 — Core types compile & round-trip
- Confirm cairn-core Record/Finding/Manifest serialize+deserialize (serde) losslessly.
- Add unit tests: build a sample EventRecord/Finding/Manifest, to_json -> from_json eq.
- Accept: round-trip tests pass; schema strings present.

## T2 — CLI wiring
- Flesh out `cairn evtx` arg handling into a `Config`/run struct; init tracing -> run.log.
- Accept: `cairn evtx a.evtx b.evtx --rules ./rules` parses args and logs a plan.

## T3 — run.log / self-logging (golden rule 8 + transparency)
- Every file opened, every action, with UTC timestamps, into run.log.
- Accept: running over a fixture produces a run.log listing each input file read.

## T4 — EVTX parsing (external crate)
- Add `evtx` crate. Implement `evtx_collector`: .evtx -> Vec<EventRecord>, flattening
  System + EventData into EventRecord.data. Stream records; don't load whole file.
- Map channel/event_id/provider/computer/record_id/ts(UTC).
- Untrusted-input posture (threat-model #1): a malformed/oversized .evtx must NOT panic
  the run — record the parse error into `sources[].errors` and continue.
- Accept: parse a known sample .evtx; record count matches `evtx_dump`/Hayabusa count;
  AND a deliberately corrupted .evtx fixture is handled without panic, with the error
  surfaced in the manifest.

## T5 — Logsource de-abstraction map (offline build)
- Write a small build step/script that turns SigmaHQ logsource (category/product/
  service) into LogsourceMap entries {channel,event_id,field_aliases}, mirroring
  Hayabusa's approach (e.g. process_creation -> 4688 w/ Image->NewProcessName, and
  Sysmon EID 1). Seed config maps in rules/config/ (eventkey_alias, channel_abbrev).
- Implement the rule XOR codec with the published key, and honor `--rules-plain` to load
  un-encoded `.yml` (ADR-0002). Hostile-YAML posture (threat-model #2): bound regex and
  YAML alias expansion.
- Accept: map resolves the top ~20 Windows logsources to concrete channel/eventID;
  encoded and `--rules-plain` paths load the same rules to the same result.

## T6 — Sigma engine selection + matcher (DECISION D1 → ADR-0001)
- Run docs/sigma-engine-benchmark-plan.md; pick ONE engine; record the result by
  promoting docs/adr/adr-0001-sigma-engine.md to Accepted; add it to cairn-sigma.
- Implement `EngineX : SigmaMatcher`: load rules (decode if XOR), apply LogsourceMap
  field aliasing, match EventRecord -> Finding. MUST set rule_id, rule_author (DRL),
  severity from level, mitre from tags. Implement referenced_channels() for load-opt
  (skip rules whose channel isn't in the data).
- Accept: a hand-picked rule fires on a crafted matching EventRecord and not on a
  non-matching one; author present in Finding.

## T7 — Reporter: timeline + summary + manifest
- DirSink: write timeline.csv (TIMELINE_COLS, projected from Findings — SRS §5.2),
  findings.jsonl, summary, manifest.json.
- Dedup identical detections with a count (FR5). Sort by (ts, record_id).
- Manifest: tool/run/host/privileges/sources(sha256,method=api)/outputs(sha256)/counts;
  set `tool.sigma_ruleset_ver` per ADR-0003 (commit-sha+aggregate-sha256).
- Output-path safety (threat-model #3): canonicalize the output path; refuse writes that
  resolve onto the target/source volume or follow a symlink/junction; sanitize any
  artifact-derived string (host, case_id, rule title) used in a filename.
- Accept: outputs produced; manifest hashes match on re-read; deterministic ordering;
  a crafted host/case_id/rule-title cannot redirect a write outside the output dir.

## T8 — Parity & perf harness (use testing-strategy skill)
- Pull EVTX-ATTACK-SAMPLES into tests/ (gitignored, fetched by a script).
- Compare Cairn detections to expected/Hayabusa on the same inputs; record deltas.
- Time a run; compare to Hayabusa on the same corpus.
- Accept: documented match-parity report; throughput within ~2x Hayabusa.

## T9 — verify subcommand
- `cairn verify <manifest>`: re-hash listed outputs/sources, report mismatches.
- Also recompute the ruleset aggregate hash and check it against
  `tool.sigma_ruleset_ver` (ADR-0003), so a swapped/tampered ruleset is caught too.
- Accept: passes on a clean archive; fails loudly on a tampered output byte AND on a
  modified rule.

## Stage 1 exit
All T0-T9 accepted; tool is independently useful for EVTX triage. Only then start S2.
