# S2-H Heuristic Calibration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dampen the four known benign-but-noisy High persistence findings (Notion/Warp in AppData, the two Winlogon default values) without creating false negatives, via fail-loud trust-signal suppression.

**Architecture:** Two suppression gates in `cairn-heur`'s `score_persistence`, mirroring the existing startup-mechanism exemption (gate a signal at its add-point; never subtract). Gate 1 (Winlogon) suppresses the recency +15 when the value is the stock Windows default AND the signature is not disproved. Gate 2 (AppData) suppresses the suspicious-path +30 when a signed binary sits in `\AppData\Local\Programs\`. The logic is backed by named constants and two pure predicates in `score.rs`. Pure, no I/O, no unsafe.

**Tech Stack:** Rust, `cairn-heur` crate (`#![forbid(unsafe_code)]`), no new dependencies. All inputs (`signed`, `value`, `command`, `binary_path`) already on `PersistenceRecord` from S2-C/D/E/G.

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-s2h-heuristic-calibration-design.md`

---

## Background the engineer needs

`score_persistence(p: &PersistenceRecord, now) -> Score` in `crates/cairn-heur/src/persist.rs`
currently does, in order:
1. mechanism base weight (`ifeo` 45, `winlogon` 35, `service` 20, `run_key`/`startup` 10),
2. suspicious-path +30 (skipped for `startup`) — sets a local `suspicious_path_fired` bool,
3. recency +15 if `last_write` within 7 days,
4. unsigned amplifier +20 if `signed==Some(false)` AND `suspicious_path_fired`.

`Score::add(weight, reason, &[mitre])` appends weight + reason. `severity_for(weight)`:
`70+`=Critical, `50–69`=High, `30–49`=Medium, `15–29`=Low, `<15`=none.

Relevant `PersistenceRecord` fields (all `crates/cairn-core/src/record.rs`):
`mechanism: String`, `value: Option<String>`, `command: Option<String>`,
`binary_path: Option<String>`, `signed: Option<bool>`, `last_write: Option<DateTime<Utc>>`.

The four noisy Highs (from the live e2e):
- Notion/Warp: `run_key(10) + appdata-path(30) + recent(15) = 55` → High. `signed==Some(true)`,
  path under `\AppData\Local\Programs\`.
- Winlogon Shell=`explorer.exe`, Userinit=`C:\WINDOWS\system32\userinit.exe,`:
  `winlogon(35) + recent(15) = 50` → High. `value` is `"Shell"`/`"Userinit"`.

`score.rs` imports into persist.rs via: `use crate::score::{is_suspicious_path, severity_for, Score};`

Existing test helper `rec(mechanism, binary_path, last_write)` hardcodes `value: Some("Updater")`
and sets `command == binary_path`. `rec_signed(mechanism, binary_path, last_write, signed)` wraps
it. Both are in the `#[cfg(test)] mod tests` block of persist.rs. The Winlogon gate keys off
`value`, so a new helper that sets `value` and `command` independently is needed (Task 3).

---

## File Structure

- **Modify:** `crates/cairn-heur/src/score.rs` — add three constants + two pure predicates
  (`winlogon_value_is_default`, `is_trusted_appdata_location`) + their unit tests.
- **Modify:** `crates/cairn-heur/src/persist.rs` — wire the two gates into `score_persistence`;
  update the `use crate::score::{...}` import; add gate unit tests + a value-setting test helper.

No new files, no new crates, no schema change.

---

## Task 1: Winlogon default-value predicate (pure)

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`

- [ ] **Step 1: Write the failing tests**

Add to `score.rs`'s `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn winlogon_default_shell_matches() {
        assert!(winlogon_value_is_default("Shell", "explorer.exe"));
        assert!(winlogon_value_is_default("Shell", "  explorer.exe  ")); // trimmed
        assert!(winlogon_value_is_default("Shell", "EXPLORER.EXE")); // case-insensitive
    }

    #[test]
    fn winlogon_default_userinit_matches_variants() {
        // trailing comma (Windows writes "userinit.exe,") + case
        assert!(winlogon_value_is_default(
            "Userinit",
            r"C:\WINDOWS\system32\userinit.exe,"
        ));
        // env-var form expands to C:\Windows
        assert!(winlogon_value_is_default(
            "Userinit",
            r"%SystemRoot%\system32\userinit.exe"
        ));
        // bare-name form
        assert!(winlogon_value_is_default("Userinit", "userinit.exe"));
    }

    #[test]
    fn winlogon_tampered_values_do_not_match() {
        // appended payload (the classic attack) — must NOT match
        assert!(!winlogon_value_is_default("Shell", "explorer.exe,evil.exe"));
        assert!(!winlogon_value_is_default(
            "Userinit",
            r"C:\WINDOWS\system32\userinit.exe,evil.exe"
        ));
        // replaced shell
        assert!(!winlogon_value_is_default("Shell", r"C:\Temp\x.exe"));
        // wrong value name (a userinit string under the Shell name)
        assert!(!winlogon_value_is_default("Shell", "userinit.exe"));
        // unknown value name
        assert!(!winlogon_value_is_default("Notify", "explorer.exe"));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-heur --lib score::tests::winlogon`
Expected: FAIL — `winlogon_value_is_default` not found.

- [ ] **Step 3: Implement the constants + predicate**

Add to `score.rs` (after the `SUSPICIOUS_DIRS`/`COMMON_PORTS` constants, before the predicates):

```rust
/// Stock Winlogon `Shell` value on a default Windows install (post-normalization, lowercased).
pub const WINLOGON_SHELL_DEFAULT: &str = "explorer.exe";

/// Stock Winlogon `Userinit` values (post-normalization: lowercased, trailing comma stripped,
/// %SystemRoot%/%windir% expanded to c:\windows). Both the absolute and bare-name forms occur.
pub const WINLOGON_USERINIT_DEFAULTS: &[&str] =
    &[r"c:\windows\system32\userinit.exe", "userinit.exe"];
```

Add the predicate (next to the other `pub fn` predicates):

```rust
/// True if a Winlogon registry value carries its stock default (i.e. NOT attacker-modified).
/// `value_name` is the registry value ("Shell"/"Userinit"); `command` is its data.
/// Normalization tolerates case, surrounding whitespace, a single trailing comma (Windows
/// writes `userinit.exe,`), and a leading %SystemRoot%/%windir% (expanded to c:\windows).
/// Any appended payload, replacement, or wrong value name fails to match (fail-loud).
pub fn winlogon_value_is_default(value_name: &str, command: &str) -> bool {
    let norm = normalize_winlogon_command(command);
    match value_name {
        "Shell" => norm == WINLOGON_SHELL_DEFAULT,
        "Userinit" => WINLOGON_USERINIT_DEFAULTS.contains(&norm.as_str()),
        _ => false,
    }
}

/// Lowercase, trim, strip a single trailing comma, expand a leading %SystemRoot%/%windir%.
fn normalize_winlogon_command(command: &str) -> String {
    let mut s = command.trim().to_ascii_lowercase();
    if let Some(stripped) = s.strip_suffix(',') {
        s = stripped.to_string();
    }
    for var in ["%systemroot%", "%windir%"] {
        if let Some(rest) = s.strip_prefix(var) {
            s = format!(r"c:\windows{rest}");
            break;
        }
    }
    s
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-heur --lib score::tests::winlogon`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/score.rs
git commit -m "feat(s2h): winlogon_value_is_default predicate + defaults"
```

---

## Task 2: Trusted AppData location predicate (pure)

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`

- [ ] **Step 1: Write the failing test**

Add to `score.rs`'s `mod tests`:

```rust
    #[test]
    fn trusted_appdata_location_is_local_programs_only() {
        assert!(is_trusted_appdata_location(
            r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"
        ));
        assert!(is_trusted_appdata_location(
            r"c:\users\x\appdata\local\programs\warp\warp.exe"
        )); // case-insensitive
        // NOT trusted: droppers favor Temp / Roaming / other AppData subpaths
        assert!(!is_trusted_appdata_location(
            r"C:\Users\x\AppData\Local\Temp\e.exe"
        ));
        assert!(!is_trusted_appdata_location(
            r"C:\Users\x\AppData\Roaming\e.exe"
        ));
        assert!(!is_trusted_appdata_location(r"C:\Program Files\App\a.exe"));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --package cairn-heur --lib score::tests::trusted_appdata`
Expected: FAIL — `is_trusted_appdata_location` not found.

- [ ] **Step 3: Implement the constant + predicate**

Add the constant near the other path constants in `score.rs`:

```rust
/// The canonical install subpath for modern signed per-user apps (Notion, Warp, VS Code, …).
/// Matched case-insensitively as a substring. Only THIS AppData subpath earns suspicious-path
/// suppression; Temp/Roaming/other AppData subpaths stay suspicious (droppers favor them).
pub const TRUSTED_APPDATA_SUBPATH: &str = r"\appdata\local\programs\";
```

Add the predicate:

```rust
/// True if `path` (any case) is under the trusted per-user app install directory
/// (`\AppData\Local\Programs\`). Used only in combination with `signed==Some(true)`.
pub fn is_trusted_appdata_location(path: &str) -> bool {
    path.to_ascii_lowercase().contains(TRUSTED_APPDATA_SUBPATH)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-heur --lib score::tests::trusted_appdata`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/score.rs
git commit -m "feat(s2h): is_trusted_appdata_location predicate + constant"
```

---

## Task 3: Wire the AppData suspicious-path gate into score_persistence

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: Add a value-setting test helper + the failing gate tests**

In persist.rs `mod tests`, add a helper (after `rec_signed`):

```rust
    /// Like `rec_signed` but lets the test set the registry `value` and `command`
    /// independently (the Winlogon gate keys off `value`; the existing `rec` hardcodes it).
    fn rec_full(
        mechanism: &str,
        value: &str,
        command: &str,
        binary_path: Option<&str>,
        last_write: Option<DateTime<Utc>>,
        signed: Option<bool>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: "HKLM\\...\\Run".into(),
            value: Some(value.into()),
            command: Some(command.into()),
            binary_path: binary_path.map(|p| p.to_string()),
            binary_sha256: None,
            signed,
            last_write,
        }
    }
```

Add the AppData gate tests:

```rust
    /// Signed per-user app in AppData\Local\Programs: suspicious-path +30 is suppressed,
    /// dropping it from High (55) to Low (25). The finding still surfaces, just not as High.
    #[test]
    fn signed_appdata_local_programs_suppresses_path_signal() {
        let now = Utc::now();
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"),
            Some(now),
            Some(true),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 25, "run_key 10 + recent 15; path +30 suppressed");
        assert!(!s.reasons.iter().any(|r| r.contains("suspicious path")));
        assert!(!s.reasons.iter().any(|r| r.contains("unsigned")));
    }

    /// Unsigned binary in the SAME trusted location is NOT suppressed (fail-loud): the path
    /// signal fires and so does the unsigned amplifier.
    #[test]
    fn unsigned_appdata_local_programs_not_suppressed() {
        let now = Utc::now();
        let old = now - Duration::days(400); // isolate path + amplifier from recency
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\x\AppData\Local\Programs\et\evil.exe"),
            Some(old),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 60, "run_key 10 + path 30 + unsigned 20");
        assert!(s.reasons.iter().any(|r| r.contains("suspicious path")));
    }

    /// Signed binary in AppData\Local\TEMP is NOT suppressed (wrong subpath): path fires.
    #[test]
    fn signed_appdata_temp_not_suppressed() {
        let now = Utc::now();
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\x\AppData\Local\Temp\app.exe"),
            Some(now),
            Some(true),
        );
        let s = score_persistence(&p, now);
        // run_key 10 + path 30 + recent 15 = 55 (signed -> no unsigned amplifier)
        assert_eq!(s.weight, 55, "temp is not a trusted location; path +30 stays");
        assert!(s.reasons.iter().any(|r| r.contains("suspicious path")));
    }

    /// None signature in the trusted location is NOT suppressed (unverified, fail-loud).
    #[test]
    fn unverified_appdata_local_programs_not_suppressed() {
        let now = Utc::now();
        let p = rec_signed(
            "run_key",
            Some(r"C:\Users\x\AppData\Local\Programs\App\a.exe"),
            Some(now),
            None,
        );
        let s = score_persistence(&p, now);
        // run_key 10 + path 30 + recent 15 = 55 (None -> not suppressed, no amplifier)
        assert_eq!(s.weight, 55, "None signature must not earn suppression");
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-heur --lib persist::tests::signed_appdata persist::tests::unsigned_appdata persist::tests::unverified_appdata`
Expected: `signed_appdata_local_programs_suppresses_path_signal` FAILS (weight 55, not 25); the others may already pass (current behavior). The failing one proves the gate is needed.

- [ ] **Step 3: Implement the AppData gate**

Update the import line at the top of persist.rs:

```rust
use crate::score::{is_suspicious_path, is_trusted_appdata_location, severity_for, Score};
```

In `score_persistence`, replace the suspicious-path block:

```rust
    let mut suspicious_path_fired = false;
    if p.mechanism != "startup" {
        if let Some(path) = p.binary_path.as_deref() {
            if is_suspicious_path(path) {
                s.add(
                    30,
                    format!("binary in a suspicious path: {path}"),
                    &["T1036"],
                );
                suspicious_path_fired = true;
            }
        }
    }
```

with (adds the trusted-AppData exemption alongside the startup exemption):

```rust
    let mut suspicious_path_fired = false;
    if p.mechanism != "startup" {
        if let Some(path) = p.binary_path.as_deref() {
            // S2-H: a SIGNED binary in the canonical per-user app install dir
            // (\AppData\Local\Programs\) is not a suspicion signal — that path is where
            // Notion/Warp/VS Code legitimately install. Fail-loud: only when signed==Some(true)
            // AND in that exact subpath; Temp/Roaming/unsigned/unverified still fire +30.
            let trusted_appdata =
                p.signed == Some(true) && is_trusted_appdata_location(path);
            if is_suspicious_path(path) && !trusted_appdata {
                s.add(
                    30,
                    format!("binary in a suspicious path: {path}"),
                    &["T1036"],
                );
                suspicious_path_fired = true;
            }
        }
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-heur --lib persist`
Expected: PASS — all four new AppData tests + every existing persist test green.

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(s2h): suppress suspicious-path for signed AppData\\Local\\Programs apps"
```

---

## Task 4: Wire the Winlogon recency gate into score_persistence

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: Write the failing gate tests**

Add to persist.rs `mod tests` (using the `rec_full` helper from Task 3):

```rust
    /// Stock Winlogon Shell, recently written, signature unverifiable (explorer.exe has no
    /// absolute path -> signed None): recency +15 suppressed, dropping High (50) to Medium (35).
    #[test]
    fn winlogon_default_shell_suppresses_recency() {
        let now = Utc::now();
        let p = rec_full("winlogon", "Shell", "explorer.exe", None, Some(now), None);
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 35, "winlogon 35; recency +15 suppressed");
        assert!(!s.reasons.iter().any(|r| r.contains("recently")));
    }

    /// Stock Winlogon Userinit (comma + case variant), recent, None signed: recency suppressed.
    #[test]
    fn winlogon_default_userinit_suppresses_recency() {
        let now = Utc::now();
        let p = rec_full(
            "winlogon",
            "Userinit",
            r"C:\WINDOWS\system32\userinit.exe,",
            Some(r"C:\WINDOWS\system32\userinit.exe"),
            Some(now),
            None,
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 35, "winlogon 35; recency +15 suppressed");
    }

    /// Tampered Winlogon Shell (appended payload), recent: NOT suppressed -> stays High (50).
    #[test]
    fn winlogon_tampered_shell_not_suppressed() {
        let now = Utc::now();
        let p = rec_full(
            "winlogon",
            "Shell",
            "explorer.exe,evil.exe",
            Some(r"C:\Temp\evil.exe"),
            Some(now),
            None,
        );
        let s = score_persistence(&p, now);
        // winlogon 35 + recent 15 = 50 (tampered value -> recency NOT suppressed)
        assert!(s.weight >= 50, "tampered value must stay High; weight {}", s.weight);
    }

    /// Stock Winlogon value but the binary is DISPROVED as unsigned (signed==Some(false)):
    /// NOT suppressed (fail-loud on a swapped-but-named-explorer body) -> stays High (50).
    #[test]
    fn winlogon_default_value_unsigned_binary_not_suppressed() {
        let now = Utc::now();
        let p = rec_full(
            "winlogon",
            "Shell",
            "explorer.exe",
            Some(r"C:\Windows\explorer.exe"),
            Some(now),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert!(s.weight >= 50, "unsigned body must stay High; weight {}", s.weight);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-heur --lib persist::tests::winlogon_default persist::tests::winlogon_tampered`
Expected: `winlogon_default_shell_suppresses_recency` and `winlogon_default_userinit_suppresses_recency` FAIL (weight 50, not 35); the two "not suppressed" tests already pass. The failing ones prove the gate.

- [ ] **Step 3: Implement the Winlogon gate**

Update the import line at the top of persist.rs:

```rust
use crate::score::{
    is_suspicious_path, is_trusted_appdata_location, severity_for, winlogon_value_is_default,
    Score,
};
```

In `score_persistence`, replace the recency block:

```rust
    if let Some(lw) = p.last_write {
        if now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
            && now.signed_duration_since(lw) >= Duration::zero()
        {
            s.add(15, "recently created/modified (last 7 days)", &[]);
        }
    }
```

with (adds the Winlogon-default exemption):

```rust
    // S2-H: a Winlogon entry carrying its STOCK default value, whose binary is not disproved
    // as unsigned, gets its recency dampened — a boot/update bumps the hive's last-write on
    // every clean machine, which would otherwise push the default values to High. Fail-loud:
    // any value change (e.g. "explorer.exe,evil.exe") or an unsigned body (signed==Some(false))
    // breaks the match and recency fires again. The winlogon base weight (35, Medium) always
    // remains, so the finding is never silenced — only lowered one band.
    let winlogon_default = p.mechanism == "winlogon"
        && p.signed != Some(false)
        && p
            .value
            .as_deref()
            .zip(p.command.as_deref())
            .is_some_and(|(v, c)| winlogon_value_is_default(v, c));
    if let Some(lw) = p.last_write {
        if !winlogon_default
            && now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
            && now.signed_duration_since(lw) >= Duration::zero()
        {
            s.add(15, "recently created/modified (last 7 days)", &[]);
        }
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-heur --lib persist`
Expected: PASS — all Winlogon gate tests + every existing persist test green (including the
pre-existing `winlogon_scores_high_band`, which uses value `"Updater"` so the gate does not
apply to it and it stays High).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(s2h): suppress recency for stock Winlogon default values"
```

---

## Task 5: Acceptance gate + live e2e self-run (the arbiter)

**Files:** none (verification; a fix-up commit only if the gate finds something).

- [ ] **Step 1: Full static gate**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
```
Expected: fmt clean; clippy no warnings; all tests pass (the workspace count grows by the new
score + persist tests); audit 0 advisories (no new dep). If `fmt --check` fails, run `cargo fmt`
and include in the gate commit.

- [ ] **Step 2: Confirm unsafe isolation unchanged**

Run: `grep -rn "unsafe" crates/cairn-heur/src/`
Expected: zero matches (cairn-heur stays `#![forbid(unsafe_code)]`).

- [ ] **Step 3: Build release + live run (persist only)**

```bash
cargo build --package cairn-cli --release
"$CARGO_TARGET_DIR/release/cairn.exe" run --target live --only persist --output C:/Temp/cairn-s2h-test
```
(`CARGO_TARGET_DIR` = `C:/Users/bosen/AppData/Local/cairn-target`.) Expected: writes outputs, no error.

- [ ] **Step 4: Verify the four noisy Highs are gone and nothing else drifted**

Inspect `C:/Temp/cairn-s2h-test/findings.jsonl`:

```python
import json
from collections import Counter
fs=[json.loads(l) for l in open(r"C:/Temp/cairn-s2h-test/findings.jsonl",encoding="utf-8") if l.strip()]
print("severity counts:", Counter(f.get("severity") for f in fs))
print("HIGH/CRITICAL findings:")
for f in fs:
    if f.get("severity") in ("high","critical"):
        print(" ", f.get("title"), "|", f.get("reason"))
```
Expected: the AppData Notion/Warp run_key findings are now `low`; the two Winlogon default
findings (Shell=explorer.exe, Userinit=...userinit.exe,) are now `medium`. The High count drops
by 4 vs the S2-G baseline. No previously-Low/Medium finding jumped up; no genuinely suspicious
record (unsigned in Temp, IFEO, tampered Winlogon) was suppressed.

> **If a Winlogon default still reads High:** the value/command normalization missed a variant
> (e.g. a different `%SystemRoot%` casing or an extra space). Print the offending record's
> `value`/`command` and extend `normalize_winlogon_command` / `WINLOGON_USERINIT_DEFAULTS` to
> cover the real on-disk form, then re-run. This is the self-run loop — calibrate against the
> real registry values, not assumptions.
>
> **If a real-threat finding got suppressed:** STOP — that is a false negative, the gate is too
> broad. Re-check the exact-match conditions before proceeding.

- [ ] **Step 5: Verify run integrity**

Run: `"$CARGO_TARGET_DIR/release/cairn.exe" verify C:/Temp/cairn-s2h-test/manifest.json`
Expected: `VERIFY OK`, exit 0.

- [ ] **Step 6: Commit any gate fix-ups (only if Step 1/4 required a change)**

```bash
git add -A
git commit -m "chore(s2h): acceptance gate passed"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Winlogon default predicate + constants → Task 1. ✅
- Trusted AppData predicate + constant → Task 2. ✅
- AppData suspicious-path gate (signed==Some(true) && trusted location) → Task 3. ✅
- Winlogon recency gate (value default && signed!=Some(false)) → Task 4. ✅
- Fail-loud: tampered value, unsigned body, wrong subpath, None signature all NOT suppressed →
  tests in Tasks 3 & 4. ✅
- Severity lowered one band, base weight remains → asserted weights (winlogon→35 Medium,
  appdata→25 Low). ✅
- Built-in named constants, no config → Tasks 1–2. ✅
- No unsafe / forbid(unsafe_code) holds → Task 5 Step 2. ✅
- Live e2e arbiter (4 Highs → 0, no drift, no real-threat suppression) → Task 5. ✅
- Explainability (suppressed reason absent) → asserted via `!reasons.contains` in Tasks 3 & 4. ✅

**Placeholder scan:** No TBD/TODO; every code step shows the full edit; expected weights are
concrete numbers; the e2e loop gives a specific fix path if a variant is missed (not a vague
"handle edge cases").

**Type consistency:** `winlogon_value_is_default(value_name: &str, command: &str) -> bool`,
`is_trusted_appdata_location(path: &str) -> bool`, `normalize_winlogon_command(&str) -> String`,
constants `WINLOGON_SHELL_DEFAULT`/`WINLOGON_USERINIT_DEFAULTS`/`TRUSTED_APPDATA_SUBPATH`,
helper `rec_full(mechanism, value, command, binary_path, last_write, signed)` are used
consistently across Tasks 1–4. The `value`/`command`/`signed` field types (`Option<String>`,
`Option<bool>`) match `PersistenceRecord`. The `.zip().is_some_and()` pattern handles both being
`Some` before calling the predicate.
