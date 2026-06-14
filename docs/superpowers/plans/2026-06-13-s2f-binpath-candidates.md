# S2-F: binary_path candidate normalization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `extract_binary_path`'s single-token parsing with a candidate-list model so unquoted spaced paths (e.g. `C:\Program Files\Docker\...\Docker Desktop.exe`) resolve to the correct binary and receive a real `signed` value.

**Architecture:** Two new pure functions added to `cairn-collectors/src/persist.rs`: `extract_binary_path_candidates` (pure, Linux-testable; emits candidates longest-first) and `pick_binary_path` (injects an `exists: impl Fn(&str)->bool`; returns first existing candidate or falls back to the bare first token). `make_record` wires these together using the real `Path::exists` on Windows. The existing `extract_binary_path` / `extract_binary_path_with` are retained (they keep their `#[allow(dead_code)]` annotations) to avoid touching other callers. Services continue to go through `normalize_service_path` before the candidates step — the service reader calls `extract_binary_path` then `normalize_service_path`, and that chain is unchanged.

**Tech Stack:** Rust, `std::path::Path`, `cairn-collectors/src/persist.rs` only. No new crate, no unsafe, no new deps.

**Authoritative spec:** `docs/superpowers/specs/2026-06-13-s2f-binpath-candidates-design.md`.

---

## File Structure

- `crates/cairn-collectors/src/persist.rs` (modify only): add `extract_binary_path_candidates`, `pick_binary_path`; update `make_record` to use them with injected `exists`.
  - **No other file changes.** Services and proc collectors are unchanged.

---

## Task 1: `extract_binary_path_candidates` — pure candidate generator

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs` (add function + tests)

- [ ] **Step 1: Read the current file to understand existing code**

Read `crates/cairn-collectors/src/persist.rs` fully. Note:
- `extract_binary_path_with` signature: `fn(cmdline: &str, lookup: impl Fn(&str)->Option<String>) -> Option<String>`
- `expand_env_vars`: `fn(s: &str, lookup: &impl Fn(&str)->Option<String>) -> String`
- How `make_record` currently calls `extract_binary_path`.

- [ ] **Step 2: Write the failing tests for `extract_binary_path_candidates`**

Add the following tests inside the existing `#[cfg(test)] mod tests` block in `persist.rs`. Place them after the existing `normalize_service_path_never_panics_on_edge_cases` test.

```rust
    // ── S2-F: extract_binary_path_candidates ──────────────────────────────

    /// Helper: fake env that returns None for every var (no expansion side-effects).
    fn no_env(_: &str) -> Option<String> {
        None
    }

    /// Quoted path -> exactly one candidate (the path between the quotes).
    #[test]
    fn candidates_quoted_single() {
        let env = fake_env(&[]);
        let got = extract_binary_path_candidates(
            r#""C:\Program Files\App\app.exe" -silent"#,
            &env,
        );
        assert_eq!(got, vec![r"C:\Program Files\App\app.exe"]);
    }

    /// Unquoted path with no spaces -> one candidate.
    #[test]
    fn candidates_unquoted_no_spaces() {
        let got = extract_binary_path_candidates(
            r"C:\Windows\system32\svchost.exe",
            &no_env,
        );
        assert_eq!(got, vec![r"C:\Windows\system32\svchost.exe"]);
    }

    /// Unquoted path WITH spaces -> longest first, bare-token last.
    /// `C:\Program Files\Docker\Docker\Docker Desktop.exe` has spaces at positions
    /// after "Program", "Files\Docker\Docker\Docker", so candidates are:
    ///   [0] whole string
    ///   [1] up to last space (everything before " Desktop.exe")
    ///   [2] up to second-last space (everything before "Docker\Docker Desktop.exe")
    ///   ...
    ///   [N] bare first token "C:\Program"
    #[test]
    fn candidates_unquoted_spaces_longest_first() {
        let cmdline = r"C:\Program Files\Docker\Docker\Docker Desktop.exe";
        let got = extract_binary_path_candidates(cmdline, &no_env);
        // First candidate must be the full string.
        assert_eq!(got[0], cmdline);
        // Last candidate must be the bare first-space token.
        assert_eq!(got.last().unwrap(), "C:\\Program");
        // Candidates are strictly decreasing in length.
        for i in 1..got.len() {
            assert!(
                got[i].len() < got[i - 1].len(),
                "candidates must be longest-first, but [{i}] len={} >= [{j}] len={}",
                got[i].len(),
                got[i - 1].len(),
                j = i - 1
            );
        }
        // The full string minus " Desktop.exe" should appear somewhere.
        assert!(
            got.contains(&r"C:\Program Files\Docker\Docker\Docker".to_string()),
            "intermediate prefix missing: {:?}",
            got
        );
    }

    /// %env% expansion is applied to every candidate.
    #[test]
    fn candidates_env_expansion_applied() {
        let env = fake_env(&[("ProgramFiles", r"C:\Program Files")]);
        let got = extract_binary_path_candidates(r"%ProgramFiles%\App\a.exe", &env);
        assert_eq!(got, vec![r"C:\Program Files\App\a.exe"]);
    }

    /// Empty / whitespace-only -> empty Vec.
    #[test]
    fn candidates_empty_input() {
        assert!(extract_binary_path_candidates("", &no_env).is_empty());
        assert!(extract_binary_path_candidates("   ", &no_env).is_empty());
    }

    /// Adversarial: lone %, trailing spaces, mismatched quotes -> no panic.
    #[test]
    fn candidates_adversarial_no_panic() {
        let _ = extract_binary_path_candidates("%", &no_env);
        let _ = extract_binary_path_candidates("%%", &no_env);
        let _ = extract_binary_path_candidates(r#""C:\unclosed"#, &no_env);
        let _ = extract_binary_path_candidates("   leading spaces", &no_env);
    }
```

- [ ] **Step 3: Run tests to verify they fail**

```
cargo test --package cairn-collectors candidates_ -- --nocapture 2>&1 | head -30
```

Expected: compile error (function not found) or FAILED — function does not exist yet.

- [ ] **Step 4: Implement `extract_binary_path_candidates`**

Add the following function to `persist.rs` immediately after the `extract_binary_path_with` function (before `expand_env_vars`):

```rust
/// Produce a list of candidate binary paths from a command line, LONGEST FIRST.
///
/// • Quoted (`"C:\path with spaces\app.exe" -args`): exactly one candidate — the
///   content between the opening and closing quote. Unchanged from `extract_binary_path`.
/// • Unquoted, no spaces (`C:\Windows\notepad.exe`): one candidate — the full string.
/// • Unquoted WITH spaces (`C:\Program Files\App\app.exe`): one candidate per space
///   boundary, longest first:
///     - the whole string
///     - the substring before the LAST space
///     - the substring before the second-last space
///     - ...
///     - the bare first whitespace-delimited token (today's `extract_binary_path` value)
///   This mirrors how Windows `CreateProcess` resolves ambiguous paths.
///
/// `%VAR%` expansion is applied to each candidate via the injected `lookup`.
/// Returns an empty Vec for an empty / whitespace-only input (no panic).
#[allow(dead_code)]
pub(crate) fn extract_binary_path_candidates(
    cmdline: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    if let Some(rest) = trimmed.strip_prefix('"') {
        // Quoted: take up to the closing quote (same as extract_binary_path_with).
        let raw = rest.split('"').next().unwrap_or("");
        if raw.is_empty() {
            return vec![];
        }
        return vec![expand_env_vars(raw, &lookup)];
    }

    // Unquoted: find all space positions and emit longest-first prefixes.
    // Spaces are ASCII (single byte), so byte-index slicing is char-boundary-safe.
    let space_positions: Vec<usize> = trimmed
        .char_indices()
        .filter(|(_, c)| *c == ' ')
        .map(|(i, _)| i)
        .collect();

    if space_positions.is_empty() {
        // No spaces: single candidate.
        return vec![expand_env_vars(trimmed, &lookup)];
    }

    // Candidates: whole string, then prefix before each space (reverse order = longest first).
    let mut candidates = Vec::with_capacity(space_positions.len() + 1);
    candidates.push(expand_env_vars(trimmed, &lookup));
    for &pos in space_positions.iter().rev() {
        let prefix = &trimmed[..pos];
        if !prefix.is_empty() {
            let expanded = expand_env_vars(prefix, &lookup);
            // Avoid duplicates (can happen if expansion produces the same string).
            if Some(&expanded) != candidates.last() {
                candidates.push(expanded);
            }
        }
    }
    candidates
}
```

- [ ] **Step 5: Run tests to verify they pass**

```
cargo test --package cairn-collectors candidates_ -- --nocapture
```

Expected: all `candidates_*` tests PASS.

- [ ] **Step 6: Run clippy to confirm no warnings**

```
cargo clippy --package cairn-collectors -- -D warnings 2>&1 | tail -20
```

Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2f): add extract_binary_path_candidates pure fn

Emits longest-first candidate list for unquoted spaced paths; quoted
paths unchanged (single candidate). %env% expanded, empty input -> [].
Tests cover quoted, unquoted-no-spaces, unquoted-spaces, env expansion,
empty, and adversarial inputs."
```

---

## Task 2: `pick_binary_path` — injected FS probe selection

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs` (add function + tests)

- [ ] **Step 1: Write the failing tests for `pick_binary_path`**

Add these tests inside the `#[cfg(test)] mod tests` block, after the `candidates_*` tests:

```rust
    // ── S2-F: pick_binary_path ─────────────────────────────────────────────

    /// First (longest) candidate exists -> chosen.
    #[test]
    fn pick_first_existing() {
        let exists = |p: &str| p == r"C:\Program Files\Docker\Docker Desktop.exe";
        let candidates = vec![
            r"C:\Program Files\Docker\Docker Desktop.exe".to_string(),
            r"C:\Program Files\Docker\Docker".to_string(),
            r"C:\Program".to_string(),
        ];
        assert_eq!(
            pick_binary_path(&candidates, exists).as_deref(),
            Some(r"C:\Program Files\Docker\Docker Desktop.exe")
        );
    }

    /// Only a shorter candidate exists -> that one chosen (longest skipped).
    #[test]
    fn pick_shorter_when_longer_absent() {
        let exists = |p: &str| p == r"C:\Program Files\Docker\Docker";
        let candidates = vec![
            r"C:\Program Files\Docker\Docker Desktop.exe".to_string(),
            r"C:\Program Files\Docker\Docker".to_string(),
            r"C:\Program".to_string(),
        ];
        assert_eq!(
            pick_binary_path(&candidates, exists).as_deref(),
            Some(r"C:\Program Files\Docker\Docker")
        );
    }

    /// None of the candidates exist -> fall back to candidates.last() (bare first token).
    #[test]
    fn pick_fallback_to_last_when_none_exist() {
        let exists = |_: &str| false;
        let candidates = vec![
            r"C:\Program Files\Docker\Docker Desktop.exe".to_string(),
            r"C:\Program Files\Docker\Docker".to_string(),
            r"C:\Program".to_string(),
        ];
        assert_eq!(
            pick_binary_path(&candidates, exists).as_deref(),
            Some(r"C:\Program")
        );
    }

    /// Empty candidates -> None (no binary_path).
    #[test]
    fn pick_empty_candidates_is_none() {
        let exists = |_: &str| false;
        assert_eq!(pick_binary_path(&[], exists), None);
    }

    /// Single candidate (quoted path) -> returned regardless of exists.
    #[test]
    fn pick_single_candidate_returned() {
        let exists = |_: &str| false; // doesn't exist on CI, but fallback = last = the only one
        let candidates = vec![r"C:\Program Files\App\app.exe".to_string()];
        assert_eq!(
            pick_binary_path(&candidates, exists).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```
cargo test --package cairn-collectors pick_ -- --nocapture 2>&1 | head -20
```

Expected: compile error — function not found.

- [ ] **Step 3: Implement `pick_binary_path`**

Add the following function to `persist.rs` immediately after `extract_binary_path_candidates`:

```rust
/// Select the best binary path from a candidate list using an injected FS probe.
///
/// Returns the first candidate for which `exists(c)` is true. If none exist,
/// returns the last candidate (the bare first token — today's `extract_binary_path`
/// value, so behavior never regresses to None where it previously had a value).
/// Returns None only if `candidates` is empty.
///
/// The injected `exists` is read-only (`Path::exists` on Windows; a fake set in tests).
/// Never panics.
#[allow(dead_code)]
pub(crate) fn pick_binary_path(
    candidates: &[String],
    exists: impl Fn(&str) -> bool,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    for c in candidates {
        if exists(c.as_str()) {
            return Some(c.clone());
        }
    }
    // None found on disk: fall back to the last candidate (bare first token).
    candidates.last().cloned()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
cargo test --package cairn-collectors pick_ -- --nocapture
```

Expected: all `pick_*` tests PASS.

- [ ] **Step 5: Run clippy**

```
cargo clippy --package cairn-collectors -- -D warnings 2>&1 | tail -20
```

Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2f): add pick_binary_path with injected exists probe

Returns first existing candidate; falls back to bare first token (no
regression); empty candidates -> None. Fully injected: no FS access
in the fn, testable on Linux."
```

---

## Task 3: Wire candidates into `make_record` (run_key + winlogon + ifeo)

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs` (`make_record` function + regression test)

The `make_record` helper is used by `read_run_keys`, `read_winlogon`, and `read_ifeo`. Currently it calls `extract_binary_path`. Replace that with `extract_binary_path_candidates` + `pick_binary_path` + `Path::exists`.

Services (`read_services`) do NOT go through `make_record` — they already have a special pipeline (`extract_binary_path` → `normalize_service_path` → `PersistenceRecord`). Do not change services.

- [ ] **Step 1: Write the regression test and wiring test**

Add these tests inside the `#[cfg(test)] mod tests` block, after the `pick_*` tests:

```rust
    // ── S2-F: make_record wiring ───────────────────────────────────────────

    /// A quoted cmdline stays unchanged (single candidate -> same binary_path as before).
    /// This is the regression test: S2-F must not change quoted-path behavior.
    #[test]
    fn make_record_quoted_cmdline_unchanged() {
        let r = make_record_with_exists(
            "run_key",
            "HKLM\\...\\Run".into(),
            Some("MyApp".into()),
            Some(r#""C:\Program Files\App\app.exe" -silent"#.to_string()),
            None,
            |_| false, // nothing exists on CI
        );
        // Falls back to last candidate = the quoted content (only one candidate).
        assert_eq!(
            r.binary_path.as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }

    /// An unquoted spaced cmdline: the full string is a candidate and if it "exists",
    /// pick_binary_path selects it over the bare first token.
    #[test]
    fn make_record_unquoted_spaced_resolves_full_path() {
        let cmdline = r"C:\Program Files\App\My App.exe -x";
        // Fake: the full path minus args does NOT match any candidate because the args
        // are part of the cmdline. The candidates are substrings of the cmdline, not
        // "cmdline minus args". Let's check what the candidates look like:
        //   "C:\Program Files\App\My App.exe -x" has spaces -> candidates include:
        //     full: "C:\Program Files\App\My App.exe -x"
        //     before last space: "C:\Program Files\App\My App.exe"
        //     before prev space: "C:\Program Files\App\My"
        //     before prev space: "C:\Program Files\App\My App.exe -x" -- no, this is not right
        //   Actually candidates are space-boundary prefixes:
        //     [0] "C:\Program Files\App\My App.exe -x"  (whole)
        //     [1] "C:\Program Files\App\My App.exe"     (before "-x")
        //     [2] "C:\Program Files\App\My"             (before "App.exe")
        //     [3] "C:\Program"                          (first token)
        // Fake exists: only the .exe path (index 1) exists.
        let fake_exists = |p: &str| p == r"C:\Program Files\App\My App.exe";
        let r = make_record_with_exists(
            "run_key",
            "HKLM\\...\\Run".into(),
            Some("MyApp".into()),
            Some(cmdline.to_string()),
            None,
            fake_exists,
        );
        assert_eq!(
            r.binary_path.as_deref(),
            Some(r"C:\Program Files\App\My App.exe")
        );
    }

    /// Unquoted spaced cmdline where NOTHING exists -> fall back to bare first token.
    #[test]
    fn make_record_unquoted_spaced_fallback_when_nothing_exists() {
        let r = make_record_with_exists(
            "run_key",
            "HKLM\\...\\Run".into(),
            Some("MyApp".into()),
            Some(r"C:\Program Files\App\My App.exe -x".to_string()),
            None,
            |_| false,
        );
        // Fallback: last candidate = bare first token.
        assert_eq!(r.binary_path.as_deref(), Some(r"C:\Program"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```
cargo test --package cairn-collectors make_record_ -- --nocapture 2>&1 | head -20
```

Expected: compile error — `make_record_with_exists` does not exist.

- [ ] **Step 3: Add `make_record_with_exists` (the testable core) and update `make_record`**

Replace the existing `make_record` function with these two (keep the same public surface: `make_record` still has the same signature as before):

```rust
/// Testable core for building a PersistenceRecord: accepts an injected `exists` probe
/// for resolving unquoted spaced cmdlines to the real binary path (S2-F candidate model).
/// `make_record` (below) calls this with the real `Path::exists`.
#[allow(dead_code)]
fn make_record_with_exists(
    mechanism: &str,
    location: String,
    value: Option<String>,
    command: Option<String>,
    last_write: Option<DateTime<Utc>>,
    exists: impl Fn(&str) -> bool,
) -> PersistenceRecord {
    let binary_path = command.as_deref().and_then(|cmd| {
        let candidates = extract_binary_path_candidates(cmd, |name| std::env::var(name).ok());
        pick_binary_path(&candidates, &exists)
    });
    PersistenceRecord {
        mechanism: mechanism.to_string(),
        location,
        value,
        command,
        binary_path,
        binary_sha256: None,
        signed: None,
        last_write,
    }
}

/// Build a PersistenceRecord with the deferred fields (signed/sha256) as None.
/// Uses the candidate-list model (S2-F) so unquoted spaced paths resolve correctly.
#[allow(dead_code)]
fn make_record(
    mechanism: &str,
    location: String,
    value: Option<String>,
    command: Option<String>,
    last_write: Option<DateTime<Utc>>,
) -> PersistenceRecord {
    make_record_with_exists(
        mechanism,
        location,
        value,
        command,
        last_write,
        |p| std::path::Path::new(p).exists(),
    )
}
```

**Important:** The old `make_record` body was:
```rust
let binary_path = command.as_deref().and_then(extract_binary_path);
```
You are replacing that logic. The function signature (`mechanism`, `location`, `value`, `command`, `last_write`) is unchanged — callers inside `win` module are unaffected.

- [ ] **Step 4: Run ALL tests to verify they pass (including existing)**

```
cargo test --workspace -- --nocapture 2>&1 | tail -40
```

Expected: all tests PASS including the existing `collect_fills_signed_from_verifier`, `normalize_service_path_*`, `startup_*`, `quoted_path_with_args`, `unquoted_path_with_args`, etc.

- [ ] **Step 5: Run clippy**

```
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
```

Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2f): wire candidate model into make_record

make_record now uses extract_binary_path_candidates + pick_binary_path
with Path::exists so unquoted run-key entries with spaces resolve to the
real binary. Testable core extracted as make_record_with_exists.
Services path unchanged (goes through normalize_service_path separately)."
```

---

## Task 4: Acceptance gate — fmt / clippy / audit / full test suite

**Files:** none changed; this is a verification task.

- [ ] **Step 1: fmt check**

```
cargo fmt --check 2>&1
```

Expected: no output (clean).

If there is output, run `cargo fmt` and commit the formatting fix.

- [ ] **Step 2: clippy all targets**

```
cargo clippy --workspace --all-targets --locked -- -D warnings 2>&1 | tail -30
```

Expected: no warnings.

- [ ] **Step 3: full test suite**

```
cargo test --workspace --locked 2>&1 | tail -40
```

Expected: all tests PASS. Note the count of passing tests (should be >= the S2-E count).

- [ ] **Step 4: cargo audit**

```
cargo audit --deny warnings 2>&1 | tail -20
```

Expected: clean (no new dependency added in S2-F).

- [ ] **Step 5: Verify `unsafe` constraint**

```
grep -r "allow(unsafe_code)\|unsafe_code\|unsafe {" crates/cairn-collectors/src/ 2>&1
```

Expected: no `unsafe` in `cairn-collectors` (it's `#![forbid(unsafe_code)]`). Only `cairn-collectors-win` carries unsafe.

- [ ] **Step 6: Commit acceptance gate result (tag commit)**

If all gates pass, create a summary commit:

```bash
git commit --allow-empty -m "chore(s2f): acceptance gate passed

cargo fmt clean, clippy -D warnings clean, full test suite passing,
cargo audit clean, no new unsafe in cairn-collectors."
```

---

## Task 5: Manual e2e verification (Windows only)

**Files:** none changed; this is a verification/observation task.

This task is Windows-only. On Linux CI it is skipped.

- [ ] **Step 1: Run cairn on the live host**

```
cargo run --package cairn-cli -- run --target live --output C:\Temp\cairn-s2f-test 2>&1 | tail -50
```

- [ ] **Step 2: Inspect persistence findings for unquoted Run-key entries**

Open `C:\Temp\cairn-s2f-test\findings.jsonl` and look for any Run-key entries whose `command` field is unquoted (no leading `"`) and contains spaces. Verify that:

1. `binary_path` is the FULL path (not clipped at the first space).
2. `signed` has a real value (`true` or `false`) — not `null`.
3. Quoted Run-key entries are unchanged (same `binary_path` as before S2-F, `signed` same).

- [ ] **Step 3: Verify no regression in signed coverage**

Compare signed coverage with S2-E baseline. `signed` should be at least as high. A simple check:

```powershell
Get-Content C:\Temp\cairn-s2f-test\findings.jsonl | ConvertFrom-Json | Where-Object {$_.signed -ne $null} | Measure-Object | Select-Object Count
```

- [ ] **Step 4: Run `cairn verify`**

```
cargo run --package cairn-cli -- verify --output C:\Temp\cairn-s2f-test 2>&1
```

Expected: manifest hash verification passes.

- [ ] **Step 5: Record observations in a comment or note**

Note the number of Run-key entries that now have a real `binary_path` (vs. previously truncated), and whether any changed from `signed: null` to a real value. This is the evidence that S2-F improved signed coverage. No code change needed — this is documentation.

---

## Self-review checklist (coordinator, not a subagent dispatch)

After all tasks complete:

- [ ] Spec coverage: `extract_binary_path_candidates` (Task 1), `pick_binary_path` (Task 2), `make_record` wiring (Task 3), acceptance gate (Task 4), e2e (Task 5) — all spec sections covered.
- [ ] No placeholders.
- [ ] Type consistency: `extract_binary_path_candidates(cmdline: &str, lookup: impl Fn(&str)->Option<String>) -> Vec<String>` in Task 1; `pick_binary_path(candidates: &[String], exists: impl Fn(&str)->bool) -> Option<String>` in Task 2; `make_record_with_exists` uses both in Task 3. All consistent.
- [ ] Services unaffected: `read_services` in the `#[cfg(windows)] mod win` block calls `extract_binary_path` (not `make_record`), so the candidate wiring does not touch service paths.
- [ ] `#![forbid(unsafe_code)]` in `cairn-collectors` unchanged (Task 4 Step 5 verifies).
- [ ] Regression: `candidates_quoted_single` (Task 1) + `make_record_quoted_cmdline_unchanged` (Task 3) guard the quoted-path behavior.
