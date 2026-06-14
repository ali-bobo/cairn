# S2-H: heuristic calibration (false-positive dampening) — Design

> Sub-segment of Stage 2. Spec author date: 2026-06-14.
> Authoritative spec: `cairn-SRS.md` (§10 heuristics, §17 D7).
> Predecessors: S2-C (persist collector + persist heuristic), S2-D/E (signed via WinVerifyTrust),
> S2-G (catalog-signed → accurate `signed`).
> Third and last of the D6/D7 trilogy: S2-F (D6 problem A) → S2-G (D6 problem B) →
> **S2-H (this, D7 problem C)**.

## Purpose

The live e2e (through S2-G) produces a small set of benign-but-noisy **High** persistence
findings that drown the signal:
- **AppData per-user apps** (Notion, Warp in `AppData\Local\Programs`): `run_key(10) +
  suspicious-path \appdata\(30) + recent(15) = 55 → High`. These are legitimately signed
  modern per-user apps; before S2-G `signed` was unreliable, so it could not be trusted to
  dampen them. Now it can.
- **Winlogon default values** (`Shell=explorer.exe`, `Userinit=C:\Windows\system32\userinit.exe,`):
  `winlogon(35) + recent(15) = 50 → High`. These are the stock Windows values; `recent` fires
  only because the hive's last-write was bumped by a boot/update, not by an attacker.

S2-H calibrates the persist heuristic so these four stop reading as High — **without creating
false negatives**. SRS §17 D7 explicitly warns that a careless allowlist hides the classic
attack (swapping the Winlogon Shell). The design is therefore **trust-signal dampening, not
allowlist filtering**: a benign signal is suppressed only when the record exactly matches its
known-good shape AND its signature is not disproved. Any attacker mutation (changed value,
unsigned replacement, dropper in the wrong directory) breaks the gate and the finding floats
back to its original severity. **No finding is ever removed — severity is lowered by at most
one band, and the mechanism's own base weight always remains.**

## Scope

**In scope:**
- `crates/cairn-heur/src/score.rs`: named constants for the Winlogon default values and the
  trusted AppData install subpath, plus two pure predicates.
- `crates/cairn-heur/src/persist.rs`: two suppression gates in `score_persistence`, mirroring
  the existing startup-mechanism exemption pattern (gate a signal at its add-point; do not
  subtract).

**Explicitly OUT of scope (deferred, with rationale):**
- **Signer identity** (Microsoft vs third-party publisher). The AppData gate trusts
  `signed==Some(true)`; tightening it to "signer is a known publisher" would close the
  stolen-certificate gap (risk #9 below) but needs signer-identity extraction (S2-G deferred
  it). A future enhancement, likely its own sub-segment.
- **Config-driven tables.** The constants are built-in (score.rs already states "named-constant
  rule tables ... a config loader can later replace them"; matches the S2-B/C watchlist model).
  YAGNI: no multi-environment requirement yet.
- **parentchild / netconn re-tuning.** Those amplifiers were already converted to require
  corroboration in S2-E; this sub-segment touches only the persist heuristic's two known noise
  sources. A broader benign-baseline-corpus tuning pass is separate future work.
- **Negative weights / Score refactor.** Suppression is done by gating a signal's add, not by
  introducing subtraction (keeps Score additive and each suppression independently explainable).
- **Collector, core, schema, the other heuristics.** Unchanged.

## The two gates

Both gates live in `score_persistence` (`crates/cairn-heur/src/persist.rs`) and follow the
existing pattern at the suspicious-path block (`if p.mechanism != "startup"`): a condition that
prevents a signal from being added, with the reason naturally absent from the output.

### Gate 1 — Winlogon default value

Suppresses the **recency +15** when the Winlogon entry carries its stock value and the binary
is not disproved as unsigned.

Condition (all must hold):
- `p.mechanism == "winlogon"`, and
- `winlogon_value_is_default(value_name, command)` is true, and
- `p.signed != Some(false)` (trusted or unverifiable — NOT disproved).

Effect: the `recently created/modified` +15 is not added. A stock Winlogon entry scores
`winlogon(35) = Medium` instead of `High`. The mechanism base weight (35, Medium) **always
remains** — Winlogon persistence is always at least Medium, never silenced.

`winlogon_value_is_default(value_name, command)` (pure, score.rs):
- `value_name == "Shell"` and the normalized command equals the stock Shell value, OR
- `value_name == "Userinit"` and the normalized command is one of the stock Userinit values.
- Normalization: trim surrounding whitespace; lowercase for comparison; tolerate a single
  trailing comma (Windows writes `userinit.exe,`); expand a leading `%SystemRoot%`/`%windir%`
  to `C:\Windows` so `%SystemRoot%\system32\userinit.exe` and `C:\WINDOWS\system32\userinit.exe`
  both match. Constants:
  - `WINLOGON_SHELL_DEFAULT = "explorer.exe"`
  - `WINLOGON_USERINIT_DEFAULTS = ["c:\\windows\\system32\\userinit.exe", "userinit.exe"]`
    (both the absolute stock form and a bare-name form, post-normalization, comma-stripped)

### Gate 2 — trusted AppData install location

Suppresses the **suspicious-path +30** when a signed binary lives in the canonical modern
per-user app install directory.

Condition (all must hold), evaluated inside the existing suspicious-path block:
- `p.signed == Some(true)` (trusted — note `verify_file` returns `Some(true)` only for a file
  that exists and verifies, so this already implies the binary is present on disk), and
- `is_trusted_appdata_location(path)` is true.

Effect: the `binary in a suspicious path` +30 is not added, and `suspicious_path_fired` stays
false (so the unsigned amplifier, which is gated on `suspicious_path_fired`, also cannot fire —
correctly, since the binary is signed anyway). A signed `AppData\Local\Programs` app scores
`run_key(10) + recent(15) = 25 = Low` instead of `High`. It still appears in the timeline.

`is_trusted_appdata_location(path)` (pure, score.rs): the lowercased path contains
`\appdata\local\programs\`. Constant `TRUSTED_APPDATA_SUBPATH = r"\appdata\local\programs\"`.
Temp, Roaming, and any other AppData subpath are NOT trusted (droppers favor Temp/Roaming).

## Attacker-perspective evaluation (golden rule 1; SRS D7 false-negative caution)

Each gate was evaluated against real TTPs. The governing invariant: a gate suppresses only on
an **exact known-good match** with the **signature not disproved**, and only lowers severity by
one band — the mechanism base weight always remains, so no finding disappears.

**Winlogon gate — no material false negative:**
- Shell `explorer.exe,evil.exe` (classic append, T1547.004): command ≠ default → not
  suppressed → stays High. Caught.
- Shell replaced with `C:\Windows\Temp\evil.exe`: command ≠ default → High (and suspicious-path
  fires). Caught.
- Userinit append `userinit.exe,evil.exe`: command ≠ default → High. Caught.
- `C:\Windows\explorer.exe` body swapped for an unsigned malicious file (value unchanged):
  command matches but `signed == Some(false)` → not suppressed → High. Caught (via signed).
- Grey area: an *independent* attack (PATH/KnownDLLs/image hijack) making the bare `explorer.exe`
  token resolve elsewhere, where the resolved file happens to be validly signed. Here the
  Winlogon value itself is clean; suppressing the Winlogon recency signal is correct because
  Winlogon is not the attack vector — the malicious load point is a different artifact's
  responsibility. And Winlogon stays Medium regardless.

**AppData gate — one inherent false negative, documented:**
- Dropper in `AppData\Local\Temp` or `\Roaming`: not in `Local\Programs` → not suppressed →
  High. Caught.
- Unsigned malware in `Local\Programs`: `signed != Some(true)` → not suppressed → High. Caught.
- **Risk #9 (accepted residual):** a payload signed with a *valid* certificate (stolen,
  abused-EV, or supply-chain-poisoned signed app) placed in `Local\Programs` IS suppressed,
  dropping from High to Low. This is the inherent cost of trusting `signed==Some(true)` — the
  same blind spot SmartScreen and most EDRs share. Mitigations that hold: (a) the finding is
  not removed, only lowered to Low (run_key 10 + recency 15 = 25), so a timeline review still
  surfaces the AppData autostart; (b) obtaining a valid signing certificate is an
  APT/supply-chain capability, not commodity malware; (c) a future signer-identity gate (requiring
  a known publisher, not merely "signed") would close this — noted as future work.
- DLL side-load (run_key points at a signed exe; malice is an adjacent DLL): suppressing the
  run_key signal is correct — run_key is clean; the malicious DLL is a different artifact's job.

## Architecture

```
crates/cairn-heur/src/score.rs   (#![forbid(unsafe_code)], no new deps)
  + WINLOGON_SHELL_DEFAULT, WINLOGON_USERINIT_DEFAULTS, TRUSTED_APPDATA_SUBPATH
  + winlogon_value_is_default(value_name, command) -> bool   (pure)
  + is_trusted_appdata_location(path) -> bool                (pure)

crates/cairn-heur/src/persist.rs (#![forbid(unsafe_code)])
  score_persistence():
    suspicious-path block: add +30 UNLESS (signed==Some(true) && is_trusted_appdata_location)
    recency block:         add +15 UNLESS (winlogon && winlogon_value_is_default && signed!=Some(false))
```

All logic is pure (the `signed` value is already on the record from S2-D/E/G; no new I/O, no
FFI). `#![forbid(unsafe_code)]` holds across cairn-heur. Determinism (NFR4) unaffected — same
inputs, fewer additions, same ordering.

## Explainability (golden rule 6)

Each gate suppresses a signal at its add-point, so the suppressed reason is simply absent from
`Finding.reason` (no opaque "trusted, so −N" entry). A surviving signed AppData app reads
`Run/RunOnce key persistence; recently created/modified (last 7 days)` (no suspicious-path
line); a stock Winlogon entry reads `Winlogon Shell/Userinit persistence` (no recency line).
The narrative stays truthful — it states exactly the signals that did fire.

## Error handling / graceful degrade

- Both predicates are total: string comparisons on already-collected fields; no panic path,
  no I/O. A `None` binary_path or `None` signed simply means the gate condition is not met
  (no suppression) — the conservative direction (finding stays at full severity).
- No new dependency; `cargo audit` surface unchanged.

## Testing

Pure predicates → full TDD; the gated scoring → unit tests on `score_persistence` with injected
`now` and constructed records (the existing test pattern in persist.rs, e.g. `rec_signed`).

- **winlogon_value_is_default (pure):**
  - Shell="explorer.exe" → true; Shell="explorer.exe,evil.exe" → false; Shell="C:\\Temp\\x.exe" → false.
  - Userinit="C:\\WINDOWS\\system32\\userinit.exe," → true (case + trailing comma tolerated);
    Userinit="%SystemRoot%\\system32\\userinit.exe" → true (env expanded);
    Userinit="userinit.exe,evil.exe" → false.
  - wrong value_name (e.g. "Shell" with a userinit string) → false.
- **is_trusted_appdata_location (pure):**
  - `C:\Users\x\AppData\Local\Programs\Notion\Notion.exe` → true (any case).
  - `C:\Users\x\AppData\Local\Temp\e.exe` → false; `...\AppData\Roaming\e.exe` → false;
    `C:\Program Files\App\a.exe` → false.
- **Gate 1 (score_persistence, winlogon):**
  - stock Shell, signed None, recent → 35 (Medium), reason has NO recency line.
  - stock Shell, signed Some(false), recent → 50 (High) — disproved signature, NOT suppressed.
  - Shell="explorer.exe,evil.exe", recent → 50 (High) — mutated value, NOT suppressed.
  - stock Userinit (comma/case/env variants), signed None, recent → 35 (Medium).
- **Gate 2 (score_persistence, run_key AppData):**
  - signed Some(true), `\AppData\Local\Programs\`, recent → 25 (Low), reason has NO
    suspicious-path line and NO unsigned-amplifier line.
  - signed Some(false), same path, recent → 55 (High) — unsigned, NOT suppressed; and the
    unsigned amplifier is free to fire (suspicious_path_fired stays true here).
  - signed Some(true), `\AppData\Local\Temp\`, recent → 55 (High) — wrong subpath, NOT suppressed.
  - signed None, `\AppData\Local\Programs\`, recent → 55 (High) — unverified, NOT suppressed.
- **regression:** ifeo/service findings unchanged; startup exemption unchanged; a genuinely
  malicious unsigned run_key in Temp still scores High.
- **e2e (manual-then-self-run, Windows):** `cairn run --target live --only persist`; the four
  known noisy Highs are gone (Notion/Warp now Low, the two Winlogon defaults now Medium); no
  other finding's severity changed unexpectedly; no real-threat finding suppressed; `cairn
  verify` passes. Record the before/after High count (expect 4 → 0 on this clean host).

## Acceptance gate

- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked` green; `cargo audit --deny warnings` clean (no new dep).
- `unsafe` appears in no crate except `cairn-collectors-win`; cairn-heur stays
  `#![forbid(unsafe_code)]`.
- A real live run drops the four known benign Highs (AppData apps → Low, Winlogon defaults →
  Medium) with no other severity drift and no real-threat suppression; `cairn verify` passes.
- No golden-rule violation: dampening is fail-loud (exact match + signature-not-disproved),
  lowers severity by at most one band, never removes a finding, never blanket-allowlists a
  mechanism or location.
- No scope creep: signer identity, config tables, and parentchild/netconn re-tuning are out.

## Non-goals / future hooks

- **Signer identity** (known-publisher trust) to close AppData risk #9 — its own future
  sub-segment (needs signer extraction S2-G deferred).
- **Config-driven calibration tables** + a representative benign-baseline corpus for
  data-driven weight tuning — a dedicated tuning pass.
- Remaining Stage 2+ work unchanged: Scheduled Tasks, WMI subscriptions, raw-NTFS, offline
  artifacts, FR14 binary hashing, FR15/FR18 output packaging + zh-TW client details.
