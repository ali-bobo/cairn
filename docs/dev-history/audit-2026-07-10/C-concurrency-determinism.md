# Audit C — Concurrency Correctness & Determinism

Independent audit (fresh context), main branch, 2026-07-10.
Scope: verify CLAUDE.md "Coding conventions" claims — "Determinism: sort output
by (ts, record_id). Reproducible builds in CI." and "Parallelism via rayon;
collectors are independent, analyzers fan-in." Read-only; no code changed.

---

## 1. Determinism claim — verdict: **PARTIALLY TRUE (holds in practice, but not by the stated mechanism)**

Output determinism **does** hold, but *not* because output is sorted by
`(ts, record_id)` as the convention claims. The real basis is:

1. **`run_live` is fully sequential** (`cairn-core/src/orchestrator.rs:38-59`).
   There is **no parallel collection at all** — a plain `for c in collectors`
   loop appends records in collector-registration order. Collector order is
   fixed and deterministic (`cairn-cli/src/main.rs:801-860`, driven by the
   static AVAILABLE list). So record accumulation order is deterministic
   independent of any sort.
2. **Each offline collector sorts its own output** before returning
   (bam `:144`, amcache `:103`, prefetch `:259`, userassist `:257`,
   shimcache `:229`), by a domain key like `(user_sid, path)` or `path` —
   **never `(ts, record_id)`**. mft/usn/evtx emit in scan order.
3. **Findings** are sorted once in `main.rs:898` via `sort_findings`
   (`:171`) by `(ts, title, tiebreak=pid|lport|0)` — again **not record_id**;
   the code comment at `:170` explicitly says record_id is unavailable for
   heuristic findings.
4. **timeline.csv** re-sorts internally (`cairn-report/src/lib.rs:143`) by
   `(col0=ts_rfc3339, col5=evidence_ref)` — **`evidence_ref` is a String, not
   the numeric `record_id`**, and is empty for every heuristic finding.

**Net:** the literal claim "sort output by (ts, record_id)" is inaccurate on two
counts — (a) `record_id` is not the tiebreaker anywhere on the output path
(it's evidence_ref / title / path / user_sid depending on the file), and
(b) `records.jsonl`, `report.html`, and the bodyfile are **never sorted at all**
on the orchestration path — they consume `outcome.records` in collection order
(`main.rs:983,987,994`). Determinism of those three files rests entirely on the
sequential run + per-collector internal sorts, which happens to be deterministic
but is a different guarantee than the one documented.

No true data race is possible because there is no concurrent access to shared
state anywhere (see §2/§3). I could not run a real two-run byte-diff (the 7
raw-artifact collectors need SeBackupPrivilege, unavailable here — CLAUDE.md
§SeBackupPrivilege constraint), so this verdict is by code-path proof, not
empirical replay. The logic proof is solid: every output-feeding vector is
produced by a deterministic sequential pipeline with stable (`sort_by`) sorts.

## 2. Reproducible-builds claim — verdict: **TRUE (scoped)**

- Toolchain pinned: `rust-toolchain.toml` → `channel = "1.95.0"` (+ rustfmt,
  clippy). CI and local rustup both honor it.
- `Cargo.lock` committed; **every** CI cargo invocation uses `--locked`
  (`.github/workflows/ci.yml:38,41,44,57,63,71`; `release.yml:22`).
- Comment at `ci.yml:9` is honest: "Reproducible-**ish**". There is **no**
  `SOURCE_DATE_EPOCH`, no `--remap-path-prefix`, no `strip` (the latter is
  deliberately forbidden by golden rule 2). So builds are reproducible in the
  "same toolchain + locked deps → same dependency graph and codegen" sense, not
  bit-identical-binary reproducibility. That is the correct/expected reading for
  this project and matches NFR7. Claim stands.

---

## 3. Per-file parallel-correctness table

| File | Concurrency construct | Actually concurrent? | Verdict |
|---|---|---|---|
| cairn-core/orchestrator.rs | none (sequential `for`) | No | OK — deterministic by construction |
| cairn-cli/main.rs:757 | `rayon::ThreadPoolBuilder::build_global()` | **Pool built, never used** | See F1 (dead pool) |
| cairn-core/config.rs | `max_threads` knob + docs only | No | OK |
| collectors/mft.rs | `AtomicU64 truncated_cap` | No — 1 store in collect, 1 load in sources, same thread | OK — Relaxed correct |
| collectors/usn.rs | `AtomicU64 truncated_cap` | No — same as mft | OK — Relaxed correct |
| collectors/{bam,amcache,shimcache,prefetch,userassist,srum}.rs | `AtomicBool` status flags | No — interior mutability for `&self` under `Send+Sync`, single-threaded | OK — Relaxed correct |
| collectors/evtx_live.rs | (flagged by grep on "Arc" substring) | No shared mut state | OK |
| heur/persist.rs | (grep substring hit) | No shared mut state | OK |
| report/zip_sink.rs:146, launcher/package.rs:87 | `ZipArchive` (grep false-positive on "Arc") | No | OK |

**Why the atomics are correct despite `Ordering::Relaxed`:** they are *not*
cross-thread coordination. `Collector::collect(&self)` needs interior mutability
to record a truncation/abstain flag through a shared reference while the trait
requires `Send + Sync`; `AtomicU64/Bool` is the lightest such cell. Every store
happens in `collect`, every load in `sources`, and `run_live` calls them
sequentially on one thread (orchestrator.rs:41-44). There is a program-order
happens-before between store and load, no second thread touches the field, so
Relaxed loses no update and SeqCst would only add cost. Correct as written.

## 4. Findings

- **F1 — LOW — cairn-cli/src/main.rs:757-759:** a rayon global thread pool is
  built (`--max-threads` / NFR9 machinery, config.rs:44-76) but **no
  `par_iter`/`par_bridge`/`rayon::` consumer exists anywhere** (verified: the
  only rayon reference in `crates/**/src` is this build call). Collection and
  analysis are 100% sequential. Effect: dead configuration surface + a CLAUDE.md
  claim ("Parallelism via rayon; collectors are independent") that the code does
  not implement. Fix: either wire collectors through `collectors.par_iter()` in
  `run_live` (they're already independent + `Send+Sync`, so it's low-risk) **or**
  correct the docs to say collection is sequential and the pool is reserved.

- **F2 — LOW — CLAUDE.md:78 vs actual output path:** "sort output by
  (ts, record_id)" is inaccurate. `record_id` is the tiebreaker on **no** output
  file; timeline.csv uses `(ts, evidence_ref)` (lib.rs:143), findings use
  `(ts, title, pid|lport)` (main.rs:172), and records.jsonl / report.html /
  bodyfile are unsorted (rely on sequential collection order). Fix: reword the
  convention to describe the real per-artifact keys, or add a genuine
  `(ts, record_id)` sort of `outcome.records` before the records.jsonl/bodyfile
  writes if that ordering is actually desired.

- **F3 — INFO — cairn-report/src/lib.rs:143-144:** timeline sort key
  `(ts, evidence_ref)` is non-injective — distinct heuristic findings share the
  same ts and an empty evidence_ref. Determinism is preserved only because
  `sort_by` is *stable* and the input (`outcome.findings`) is already ordered by
  `sort_findings`. This is correct today but fragile: if a future change feeds
  timeline_csv unsorted findings, ties would order by input arrival. Consider
  making the tiebreak total (append title) to remove the hidden dependency.

## 5. Categories with no issues found

- **Shared mutable state / data races:** none. No `Arc<Mutex<_>>`, no
  `thread::spawn`, no `par_iter` writing shared buffers anywhere in the tree.
  This class is **clean**.
- **Atomic memory-ordering bugs:** none. All atomics are single-threaded
  interior-mutability cells; `Relaxed` is sound (§3).
- **Lost/double-counted truncation counts:** none possible — single writer,
  single reader, sequential (mft.rs:152/168, usn.rs:295/310).
- **Reproducible-build config:** correct and complete for its scope (§2).
