# S2-C: persistence collector + persist heuristic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `PersistCollector` (5 high-value live-registry/folder persistence mechanisms via the safe `winreg` wrapper + `std::fs`) and a `PersistHeuristic` analyzer, so `cairn run --target live` enumerates autostart/persistence entries and flags suspicious ones with an explainable reason.

**Architecture:** A new `crates/cairn-collectors/src/persist.rs` reads the 5 mechanisms and maps them to `PersistenceRecord`s — using `winreg` (a safe wrapper, so `cairn-collectors` stays `#![forbid(unsafe_code)]`; `cairn-collectors-win`'s unsafe surface does NOT grow). A new `crates/cairn-heur/src/persist.rs` ranks records by mechanism stealth + suspicious path + recent LastWrite, reusing the shared `score.rs`. The CLI live arm adds both to its collectors/analyzers vecs. `signed` and `binary_sha256` stay `None` (S2-D / FR14).

**Tech Stack:** Rust, `winreg` (new, Windows-only dep), `std::fs`, the existing Collector/Analyzer/Record/Finding contracts, `chrono`.

**Spec:** `docs/superpowers/specs/2026-06-13-s2c-persistence-design.md`

**Standing discipline (every task):** after the task's test passes, run the full gate
`cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
(from repo root `cairn/`; on Windows pass `dangerouslyDisableSandbox: true`), and `cargo audit`
when deps change. Then the anti-drift check: `#![forbid(unsafe_code)]` holds in `cairn-collectors`
and `cairn-heur` (no new unsafe; `winreg` is a safe wrapper), readers are read-only and never
panic, every persist Finding has `reason = Some(..)` + `source = Heuristic`, `signed`/`binary_sha256`
stay None (deferred), no deviation from SRS §4/§5/§10, no scope creep (no signed verification, no
Scheduled Tasks, no WMI, no hashing). Commit only after green. On Windows the AV may lock a build
probe → `os error 5`; just re-run the build (probes cache afterward).

---

## File Structure

- `crates/cairn-collectors/src/persist.rs` (new) — mechanism readers + pure helpers
  (`extract_binary_path`) + `PersistCollector impl Collector`. Largest new file; keep the
  pure helpers and the OS reads clearly separated within it.
- `crates/cairn-collectors/Cargo.toml` (modify) — add `winreg` under `cfg(windows)`.
- `crates/cairn-collectors/src/lib.rs` (modify) — `pub mod persist;`.
- `crates/cairn-heur/src/persist.rs` (new) — `PersistHeuristic impl Analyzer` + pure `score_persistence`.
- `crates/cairn-heur/src/lib.rs` (modify) — `pub use persist::PersistHeuristic;`.
- `crates/cairn-cli/src/main.rs` (modify) — add PersistCollector + PersistHeuristic to the live vecs.

**Dependency direction:** unchanged (`cairn-collectors → cairn-core`, `cairn-heur → cairn-core`,
`cairn-cli → both`). `winreg` is a leaf dep of `cairn-collectors` only.

**Implementation order rationale:** the persist heuristic (Tasks 2-3) is pure and can be fully
TDD'd with hand-built `PersistenceRecord`s BEFORE the collector exists — so we build judgment
first (testable in isolation), then the collector (Tasks 4-7), then wire (Task 8). This means the
heuristic never waits on the registry-reading code.

---

## Task 1: Add the `winreg` dependency (pinned, Windows-only)

**Files:**
- Modify: `Cargo.toml` (workspace deps)
- Modify: `crates/cairn-collectors/Cargo.toml`

- [ ] **Step 1: Find the exact current winreg version.**

Run: `cargo search winreg --limit 1`
Take the exact version printed (expected `0.56.0` or newer) — do NOT guess.

- [ ] **Step 2: Add to workspace deps.** In root `Cargo.toml` under `[workspace.dependencies]`, add (substitute the real version):

```toml
winreg = "0.56.0" # safe Windows Registry wrapper (cairn-collectors persist, Windows-only)
```

- [ ] **Step 3: Add to cairn-collectors as a Windows-only dep.** In `crates/cairn-collectors/Cargo.toml`, add a target-scoped dependency section (mirroring how cairn-collectors-win scopes `windows`):

```toml
[target.'cfg(windows)'.dependencies]
winreg.workspace = true
```

- [ ] **Step 4: Verify it resolves + builds + audits.**

Run: `cargo check -p cairn-collectors` (on Windows this downloads winreg + windows-sys).
Run: `cargo audit`
Expected: compiles; audit clean. If `cargo audit` flags winreg or its `windows-sys` backend, STOP and report — do not proceed with a vulnerable dep.

- [ ] **Step 5: Commit.**

```bash
git add Cargo.toml Cargo.lock crates/cairn-collectors/Cargo.toml
git commit -m "build(s2c): add winreg (safe registry wrapper, Windows-only) for persistence

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: persist heuristic — pure `score_persistence` (TDD)

**Files:**
- Create: `crates/cairn-heur/src/persist.rs`

This builds the judgment first, testable with hand-built records before any collector exists.

- [ ] **Step 1: Write the file with the pure scoring + tests.** Create `crates/cairn-heur/src/persist.rs`:

```rust
//! heur_persist (FR9 ranking, SRS §10): rank persistence records by mechanism stealth +
//! suspicious binary path + recent LastWrite. Pure scoring (Analyzer impl is Task 3).
//! `signed` is not yet available (S2-D); weights compensate so malicious persistence still
//! surfaces without it.
use crate::score::{is_suspicious_path, Score};
use cairn_core::record::PersistenceRecord;
use chrono::{DateTime, Duration, Utc};

/// Days within which a LastWrite counts as "recent" (a freshly-planted persistence entry).
const RECENT_DAYS: i64 = 7;

/// Score one persistence record. `now` is injected for testability (recency window).
fn score_persistence(p: &PersistenceRecord, now: DateTime<Utc>) -> Score {
    let mut s = Score::default();

    // Mechanism stealth: fewer legitimate uses -> higher base weight. Mutually exclusive.
    match p.mechanism.as_str() {
        "ifeo" => s.add(45, "IFEO Debugger hijack (almost never legitimate)", &["T1546.012"]),
        "winlogon" => s.add(35, "Winlogon Shell/Userinit persistence", &["T1547.004"]),
        "service" => s.add(20, "service autostart persistence", &["T1543.003"]),
        "run_key" => s.add(10, "Run/RunOnce key persistence", &["T1547.001"]),
        "startup" => s.add(10, "Startup folder persistence", &["T1547.001"]),
        _ => {}
    }

    if let Some(path) = p.binary_path.as_deref() {
        if is_suspicious_path(path) {
            s.add(30, format!("binary in a suspicious path: {path}"), &["T1036"]);
        }
    }

    if let Some(lw) = p.last_write {
        if now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
            && now.signed_duration_since(lw) >= Duration::zero()
        {
            s.add(15, "recently created/modified (last 7 days)", &[]);
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(mechanism: &str, binary_path: Option<&str>, last_write: Option<DateTime<Utc>>) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("Updater".into()),
            command: binary_path.map(|p| p.to_string()),
            binary_path: binary_path.map(|p| p.to_string()),
            binary_sha256: None,
            signed: None,
            last_write,
        }
    }

    /// An IFEO Debugger in Temp written today scores critical and tags T1546.012.
    #[test]
    fn ifeo_in_temp_recent_scores_critical() {
        let now = Utc::now();
        let p = rec("ifeo", Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"), Some(now));
        let s = score_persistence(&p, now);
        // ifeo 45 + suspicious path 30 + recent 15 = 90
        assert!(s.weight >= 70, "weight {}", s.weight);
        assert!(s.mitre.contains(&"T1546.012".to_string()));
    }

    /// A plain old Run key to Program Files scores below the floor (quiet for legit).
    #[test]
    fn old_run_key_program_files_is_quiet() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec("run_key", Some(r"C:\Program Files\Vendor\app.exe"), Some(old));
        let s = score_persistence(&p, now);
        // run_key 10 only -> below floor (15) -> no finding
        assert!(s.weight < 15, "weight {}", s.weight);
    }

    /// Winlogon tampering scores high even without a suspicious path.
    #[test]
    fn winlogon_scores_high_band() {
        let now = Utc::now();
        let p = rec("winlogon", Some(r"C:\Windows\System32\userinit.exe"), Some(now));
        let s = score_persistence(&p, now);
        // winlogon 35 + recent 15 = 50 -> high
        assert!(s.weight >= 50, "weight {}", s.weight);
    }

    /// The recency window: 6 days fires, 8 days does not.
    #[test]
    fn recency_window_boundary() {
        let now = Utc::now();
        let p6 = rec("service", Some(r"C:\Windows\System32\svc.exe"), Some(now - Duration::days(6)));
        let p8 = rec("service", Some(r"C:\Windows\System32\svc.exe"), Some(now - Duration::days(8)));
        assert!(score_persistence(&p6, now).reasons.iter().any(|r| r.contains("recently")));
        assert!(!score_persistence(&p8, now).reasons.iter().any(|r| r.contains("recently")));
    }

    /// Missing binary_path and missing last_write: still scores the mechanism, no panic.
    #[test]
    fn missing_fields_still_score_mechanism() {
        let now = Utc::now();
        let p = rec("ifeo", None, None);
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 45); // mechanism only
    }
}
```

- [ ] **Step 2: Register the module + dep.** Confirm `crates/cairn-heur/Cargo.toml` already has
  `chrono.workspace = true` (it does — added in S2-B Task 1). Add to `crates/cairn-heur/src/lib.rs`:

```rust
pub mod persist;
```
(Place it alphabetically among the existing `pub mod netconn; pub mod parentchild; pub mod score;`.)

Because `score_persistence` has no non-test caller until Task 3, add a module-level
`#![allow(dead_code)]` at the very top of `persist.rs` (above the doc comment is not allowed;
put the doc comment first, then the attribute) with a comment — same staging pattern as S2-B
Tasks 3/5. Concretely the file starts:

```rust
//! heur_persist (FR9 ranking, SRS §10): ... (doc lines as above)
// Task 2: pure scoring only; Task 3 adds the Analyzer that consumes score_persistence.
#![allow(dead_code)]
use crate::score::{is_suspicious_path, Score};
```

- [ ] **Step 3: Run tests + gate.**

Run: `cargo test -p cairn-heur persist`
Then full gate. Expected: 5 tests PASS, clippy clean (the allow keeps dead_code quiet).

- [ ] **Step 4: Commit.**

```bash
git add crates/cairn-heur/src/persist.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(s2c): persist heuristic pure scoring (mechanism stealth + path + recency)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `PersistHeuristic impl Analyzer` (TDD)

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`
- Modify: `crates/cairn-heur/src/lib.rs` (enable re-export)

- [ ] **Step 1: Write the failing test.** Append to the `#[cfg(test)] mod tests` block in `persist.rs`:

```rust
    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    /// The analyzer emits one Heuristic finding for a malicious IFEO record (reason +
    /// registry entity) and nothing for a quiet old Run key.
    #[test]
    fn analyzer_emits_finding_for_malicious_only() {
        let now = Utc::now();
        let bad = Record::Persistence(rec("ifeo", Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"), Some(now)));
        let quiet = Record::Persistence(rec("run_key", Some(r"C:\Program Files\V\a.exe"), Some(now - Duration::days(400))));
        let findings = PersistHeuristic.analyze(&[bad, quiet]).expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert_eq!(f.artifact, "persistence");
        assert!(f.entity.registry.is_some(), "ifeo is registry-backed");
        assert!(f.mitre.contains(&"T1546.012".to_string()));
    }

    /// A startup (file) mechanism populates entity.file, not entity.registry.
    #[test]
    fn startup_mechanism_uses_file_entity() {
        let now = Utc::now();
        let mut r = rec("startup", Some(r"C:\Users\a\AppData\Roaming\...\Startup\x.exe"), Some(now));
        r.location = r"C:\Users\a\...\Startup".into();
        let findings = PersistHeuristic.analyze(&[Record::Persistence(r)]).expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.entity.file.is_some());
        assert!(f.entity.registry.is_none());
    }
```

- [ ] **Step 2: Run it, watch it fail.**

Run: `cargo test -p cairn-heur analyzer_emits_finding_for_malicious_only`
Expected: FAIL — `PersistHeuristic` not defined.

- [ ] **Step 3: Implement.** First REMOVE the module-level `#![allow(dead_code)]` (and its staging
  comment) from the top of `persist.rs` — the analyzer now consumes `score_persistence`. Widen the
  imports at the top to:

```rust
use crate::score::{is_suspicious_path, severity_for, Score};
use cairn_core::record::{PersistenceRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use cairn_core::finding::{EntityFile, EntityRegistry};
use chrono::{DateTime, Duration, Utc};
```

Add (above the `#[cfg(test)] mod tests` block):

```rust
/// Analyzer: ranks persistence records, emitting findings above the noise floor.
pub struct PersistHeuristic;

impl Analyzer for PersistHeuristic {
    fn name(&self) -> &str {
        "heur_persist"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            let score = score_persistence(p, now);
            let Some(severity) = severity_for(score.weight) else { continue };

            let mut f = Finding::new(
                severity,
                format!("Suspicious persistence: {}", p.mechanism),
                FindingSource::Heuristic,
            );
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre;
            f.artifact = "persistence".into();
            f.details = format!(
                "mechanism={} location={} command={}",
                p.mechanism,
                p.location,
                p.command.as_deref().unwrap_or("-")
            );
            f.ts = p.last_write.unwrap_or(now);
            f.entity = persistence_entity(p);
            out.push(f);
        }
        Ok(out)
    }
}

/// Build the entity: registry-backed mechanisms -> entity.registry; the file-backed
/// `startup` mechanism -> entity.file (SRS §5.1 mapping in the design spec).
fn persistence_entity(p: &PersistenceRecord) -> Entity {
    if p.mechanism == "startup" {
        Entity {
            file: Some(EntityFile {
                path: p.binary_path.clone().or_else(|| p.value.clone()).unwrap_or_default(),
                sha256: None,
                mtime: p.last_write,
                si_btime: None,
                fn_btime: None,
            }),
            ..Entity::default()
        }
    } else {
        Entity {
            registry: Some(EntityRegistry {
                hive: hive_prefix(&p.location),
                key: p.location.clone(),
                value: p.value.clone().unwrap_or_default(),
                data: p.command.clone().unwrap_or_default(),
                last_write: p.last_write,
            }),
            ..Entity::default()
        }
    }
}

/// Parse the hive prefix ("HKLM"/"HKCU"/...) from a registry location string; "" if none.
fn hive_prefix(location: &str) -> String {
    location
        .split(['\\', '/'])
        .next()
        .filter(|h| h.starts_with("HK"))
        .unwrap_or("")
        .to_string()
}
```

- [ ] **Step 4: Enable the re-export.** In `crates/cairn-heur/src/lib.rs` add (next to the other re-exports):

```rust
pub use persist::PersistHeuristic;
```

- [ ] **Step 5: Run + gate.**

Run: `cargo test -p cairn-heur persist` + full gate.
Expected: PASS, clippy clean WITHOUT the dead_code allow (if a dead_code warning appears, the named
item is genuinely unused — investigate, don't re-add the blanket allow).

- [ ] **Step 6: Commit.**

```bash
git add crates/cairn-heur/src/persist.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(s2c): PersistHeuristic impl Analyzer (record->finding, registry/file entity)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: collector — `extract_binary_path` pure helper (TDD)

**Files:**
- Create: `crates/cairn-collectors/src/persist.rs`
- Modify: `crates/cairn-collectors/src/lib.rs` (`pub mod persist;`)

Start the collector file with the one pure helper that needs careful testing; the OS readers
come in Tasks 5-7.

- [ ] **Step 1: Create the file with the helper + tests.** Create `crates/cairn-collectors/src/persist.rs`:

```rust
//! PersistCollector (FR9 subset, SRS §4): reads high-value live persistence mechanisms
//! (Run/RunOnce, Services, Winlogon, IFEO, Startup folders) via the safe `winreg` wrapper
//! and std::fs, mapping each to a PersistenceRecord. Read-only; never modifies the host.
//! `signed`/`binary_sha256` are left None (S2-D / FR14).
#![allow(dead_code)] // Task 4: pure helper only; readers + Collector land in Tasks 5-8.

/// Extract the executable path from a command line. Handles a quoted first token
/// (`"C:\p a\app.exe" -x` -> `C:\p a\app.exe`) and a bare first token
/// (`C:\p\app.exe -x` -> `C:\p\app.exe`), then expands %ENV% variables. Returns None
/// if the input is empty or yields nothing usable (never panics).
pub(crate) fn extract_binary_path(cmdline: &str) -> Option<String> {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw = if let Some(rest) = trimmed.strip_prefix('"') {
        // quoted: take up to the closing quote
        rest.split('"').next().unwrap_or("")
    } else {
        // unquoted: first whitespace-delimited token
        trimmed.split_whitespace().next().unwrap_or("")
    };
    if raw.is_empty() {
        return None;
    }
    Some(expand_env_vars(raw))
}

/// Expand %VAR% occurrences using the process environment; unknown vars are left as-is.
fn expand_env_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(val) => out.push_str(&val),
                Err(_) => {
                    // leave the literal %NAME% in place
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            // no closing %: emit the rest verbatim and stop
            out.push('%');
            out.push_str(after);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_path_with_args() {
        assert_eq!(
            extract_binary_path(r#""C:\Program Files\App\app.exe" -silent"#).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }

    #[test]
    fn unquoted_path_with_args() {
        assert_eq!(
            extract_binary_path(r"C:\Windows\system32\rundll32.exe shell32.dll,Control").as_deref(),
            Some(r"C:\Windows\system32\rundll32.exe")
        );
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(extract_binary_path("   "), None);
        assert_eq!(extract_binary_path(""), None);
    }

    #[test]
    fn expands_known_env_and_keeps_unknown() {
        // Set a known var for the test, reference an unknown one.
        std::env::set_var("CAIRN_TEST_ROOT", r"C:\testroot");
        assert_eq!(
            extract_binary_path(r"%CAIRN_TEST_ROOT%\a.exe").as_deref(),
            Some(r"C:\testroot\a.exe")
        );
        assert_eq!(
            extract_binary_path(r"%CAIRN_DOES_NOT_EXIST%\a.exe").as_deref(),
            Some(r"%CAIRN_DOES_NOT_EXIST%\a.exe")
        );
    }
}
```

- [ ] **Step 2: Register the module.** Add to `crates/cairn-collectors/src/lib.rs`:

```rust
pub mod persist;
```
(alphabetically among `pub mod evtx; pub mod net; pub mod proc;`).

- [ ] **Step 3: Run tests + gate.**

Run: `cargo test -p cairn-collectors persist`
Then full gate. Expected: 4 tests PASS, clippy clean (the file-level allow covers the not-yet-used
items). NOTE: `std::env::set_var` in a test is fine here (single-threaded test, unique var name).

- [ ] **Step 4: Commit.**

```bash
git add crates/cairn-collectors/src/persist.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(s2c): persist collector extract_binary_path helper (quote/env, TDD)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: collector — registry reader scaffold + Run/RunOnce + Winlogon + IFEO

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

This adds the Windows registry readers behind `cfg(windows)` with non-Windows stubs, covering the
three "values/subkeys under one base key" mechanisms. Services (its own larger reader) is Task 6.

- [ ] **Step 1: Resolve the winreg API shape first (do not guess).** winreg 0.56's exact paths can
  differ. Read the installed source to confirm the API:

Run: `cargo doc -p winreg --no-deps` OR read `~/.cargo/registry/src/*/winreg-0.56*/src/lib.rs`.
Confirm these (the structure is stable; the exact names you must verify):
- `winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)` and `HKEY_CURRENT_USER`.
- `regkey.open_subkey(path) -> io::Result<RegKey>` (read-only open).
- iterate values: `regkey.enum_values()` yields `io::Result<(String, RegValue)>`; a value's string
  form via `regkey.get_value::<String, _>(name)` OR `RegValue`'s `to_string()`.
- iterate subkeys: `regkey.enum_keys()` yields `io::Result<String>`.
- last-write time: `regkey.query_info()?` returns `RegKeyMetadata`; call
  `.get_last_write_time_system()` → a `windows_sys` `SYSTEMTIME` with fields
  `wYear/wMonth/wDay/wHour/wMinute/wSecond` (u16). Convert SAFELY with
  `chrono::Utc.with_ymd_and_hms(...).single()` → `Option<DateTime<Utc>>` (out-of-range → None).
  IMPORTANT: do NOT use winreg's `get_last_write_time_chrono()` — that method calls `.expect()`
  internally and would PANIC on a malformed timestamp, violating the never-panic forensic
  contract. The manual `with_ymd_and_hms(...).single()` form returns None instead. (This also
  avoids needing winreg's `chrono` feature.) Verified against the installed winreg 0.55 source:
  `RegKeyMetadata::get_last_write_time_system()` exists and returns the SYSTEMTIME shape used
  in Step 2's `key_last_write`.

Write down (in the commit body later) the exact API you used.

- [ ] **Step 2: Add the record-building helper + the three readers (with stubs).** Append to
  `persist.rs`. Note the imports go at the top of the file:

```rust
use cairn_core::record::{PersistenceRecord, Record};
use chrono::{DateTime, Utc};
```

Then the shared record builder + the readers:

```rust
/// Build a PersistenceRecord with the deferred fields (signed/sha256) as None.
fn make_record(
    mechanism: &str,
    location: String,
    value: Option<String>,
    command: Option<String>,
    last_write: Option<DateTime<Utc>>,
) -> PersistenceRecord {
    let binary_path = command.as_deref().and_then(extract_binary_path);
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

/// Non-Windows: persistence reads are Windows-only; return empty so the workspace builds.
#[cfg(not(windows))]
fn read_run_keys() -> Vec<PersistenceRecord> { vec![] }
#[cfg(not(windows))]
fn read_winlogon() -> Vec<PersistenceRecord> { vec![] }
#[cfg(not(windows))]
fn read_ifeo() -> Vec<PersistenceRecord> { vec![] }

#[cfg(windows)]
fn read_run_keys() -> Vec<PersistenceRecord> {
    win::read_run_keys()
}
#[cfg(windows)]
fn read_winlogon() -> Vec<PersistenceRecord> {
    win::read_winlogon()
}
#[cfg(windows)]
fn read_ifeo() -> Vec<PersistenceRecord> {
    win::read_ifeo()
}
```

Then the Windows submodule. ADAPT the winreg calls to the API you confirmed in Step 1 — the
structure below is the intent; fix names if your installed winreg differs:

```rust
#[cfg(windows)]
mod win {
    use super::{make_record, PersistenceRecord};
    use chrono::{DateTime, Utc};
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    /// Best-effort last-write of a key as UTC; None if unavailable.
    fn key_last_write(key: &RegKey) -> Option<DateTime<Utc>> {
        // query_info().get_last_write_time_system() -> SYSTEMTIME-like; convert to Utc.
        // If the exact conversion is uncertain, return None (recency just won't fire).
        key.query_info().ok().and_then(|i| {
            let st = i.get_last_write_time_system();
            // Build a DateTime<Utc> from the SYSTEMTIME fields. Use chrono's
            // with_ymd_and_hms; on any out-of-range, return None.
            chrono::Utc
                .with_ymd_and_hms(
                    st.wYear as i32, st.wMonth as u32, st.wDay as u32,
                    st.wHour as u32, st.wMinute as u32, st.wSecond as u32,
                )
                .single()
        })
    }

    /// Run + RunOnce under both HKLM and HKCU.
    pub fn read_run_keys() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let bases = [
            (HKEY_LOCAL_MACHINE, "HKLM"),
            (HKEY_CURRENT_USER, "HKCU"),
        ];
        let subs = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ];
        for (hkey, hname) in bases {
            for sub in subs {
                let root = RegKey::predef(hkey);
                let Ok(key) = root.open_subkey(sub) else { continue };
                let lw = key_last_write(&key);
                let location = format!("{hname}\\{sub}");
                for item in key.enum_values() {
                    let Ok((name, val)) = item else { continue };
                    let data = val.to_string();
                    out.push(make_record("run_key", location.clone(), Some(name), Some(data), lw));
                }
            }
        }
        out
    }

    /// Winlogon Shell + Userinit (HKLM).
    pub fn read_winlogon() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let sub = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(key) = root.open_subkey(sub) else { return out };
        let lw = key_last_write(&key);
        let location = format!("HKLM\\{sub}");
        for name in ["Shell", "Userinit"] {
            if let Ok(data) = key.get_value::<String, _>(name) {
                out.push(make_record("winlogon", location.clone(), Some(name.to_string()), Some(data), lw));
            }
        }
        out
    }

    /// IFEO subkeys that carry a Debugger value (the hijack).
    pub fn read_ifeo() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let sub = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(ifeo) = root.open_subkey(sub) else { return out };
        for name in ifeo.enum_keys().flatten() {
            let Ok(img) = ifeo.open_subkey(&name) else { continue };
            if let Ok(dbg) = img.get_value::<String, _>("Debugger") {
                let lw = key_last_write(&img);
                let location = format!("HKLM\\{sub}\\{name}");
                out.push(make_record("ifeo", location, Some(name.clone()), Some(dbg), lw));
            }
        }
        out
    }
}
```

> NOTE: `chrono::Utc.with_ymd_and_hms` needs `use chrono::TimeZone;` in scope inside `win` —
> add it if the compiler asks. If winreg's last-write helper returns a different shape, adapt
> `key_last_write` to it; falling back to `None` is acceptable and documented (recency won't fire).

- [ ] **Step 3: Build + gate.**

Run: `cargo check -p cairn-collectors` then full gate. On non-Windows the stubs compile; on Windows
the readers compile against the real winreg. Expected: green. (No new unit tests for the OS readers
here — they get a smoke test via the Collector in Task 8; the pure mapping is covered by Task 4.)

- [ ] **Step 4: Commit** (put the confirmed winreg API in the body).

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2c): registry readers for Run/RunOnce, Winlogon, IFEO (winreg, win-gated)

Confirmed winreg 0.56 API: RegKey::predef/open_subkey/enum_values/enum_keys/
get_value/query_info().get_last_write_time_system(). Non-Windows stubs return empty.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: collector — Services reader (autostart only)

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: Add the stub + Windows reader.** In `persist.rs`, add the dispatch (next to the
  other readers):

```rust
#[cfg(not(windows))]
fn read_services() -> Vec<PersistenceRecord> { vec![] }
#[cfg(windows)]
fn read_services() -> Vec<PersistenceRecord> {
    win::read_services()
}
```

And in the `#[cfg(windows)] mod win { ... }`, add:

```rust
    /// Autostart services: HKLM\SYSTEM\CurrentControlSet\Services\* with Start in {0,1,2}
    /// (boot/system/auto) and an ImagePath. Manual/disabled services are skipped (not a
    /// persistence focus). Best-effort: unreadable subkeys are skipped (non-admin).
    pub fn read_services() -> Vec<PersistenceRecord> {
        let mut out = Vec::new();
        let sub = r"SYSTEM\CurrentControlSet\Services";
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(services) = root.open_subkey(sub) else { return out };
        for name in services.enum_keys().flatten() {
            let Ok(svc) = services.open_subkey(&name) else { continue };
            // Start is a REG_DWORD; only 0/1/2 are autostart.
            let start: u32 = match svc.get_value("Start") {
                Ok(v) => v,
                Err(_) => continue,
            };
            if start > 2 {
                continue;
            }
            let Ok(image) = svc.get_value::<String, _>("ImagePath") else { continue };
            let lw = key_last_write(&svc);
            let location = format!("HKLM\\{sub}\\{name}");
            out.push(make_record("service", location, Some(name.clone()), Some(image), lw));
        }
        out
    }
```

> NOTE: `Start` is a DWORD; `get_value::<u32, _>` is the winreg form. If the installed winreg
> returns DWORDs differently, adapt (e.g. read as `u32`). Confirm against the source you read in
> Task 5 Step 1 — do not guess.

- [ ] **Step 2: Build + gate.**

Run: `cargo check -p cairn-collectors` + full gate. Expected: green.

- [ ] **Step 3: Commit.**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2c): services reader (autostart Start<=2 with ImagePath, win-gated)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: collector — Startup folders reader (std::fs)

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: Add the reader (cross-platform via std::fs + env).** In `persist.rs` add:

```rust
/// Startup folders: per-user (%APPDATA%) and All Users (%PROGRAMDATA%) Startup dirs.
/// Uses std::fs + env, so it is not Windows-gated (returns empty if the env vars / dirs
/// are absent, which is the case off-Windows). Read-only.
fn read_startup_folders() -> Vec<PersistenceRecord> {
    let mut out = Vec::new();
    let rel = r"Microsoft\Windows\Start Menu\Programs\Startup";
    let candidates = [
        std::env::var("APPDATA").ok().map(|b| format!(r"{b}\{rel}")),
        std::env::var("PROGRAMDATA").ok().map(|b| format!(r"{b}\{rel}")),
    ];
    for dir in candidates.into_iter().flatten() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            // desktop.ini is folder metadata, not persistence.
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let last_write = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t));
            let full = path.to_string_lossy().to_string();
            out.push(make_record(
                "startup",
                dir.clone(),
                Some(name),
                Some(full.clone()),
                last_write,
            ));
        }
    }
    out
}
```

- [ ] **Step 2: Add a cross-platform unit test** (this reader is not Windows-gated, so it tests
  everywhere). Append to the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn startup_reader_reads_a_temp_dir_layout() {
        // Point APPDATA at a temp dir laid out like a Startup folder, and confirm a file
        // there becomes a startup PersistenceRecord while desktop.ini is skipped.
        let tmp = std::env::temp_dir().join(format!("cairn_s2c_{}", std::process::id()));
        let startup = tmp.join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        std::fs::create_dir_all(&startup).unwrap();
        std::fs::write(startup.join("evil.lnk"), b"x").unwrap();
        std::fs::write(startup.join("desktop.ini"), b"x").unwrap();

        // Save + override APPDATA; clear PROGRAMDATA so only our dir is read.
        let saved_appdata = std::env::var("APPDATA").ok();
        let saved_pd = std::env::var("PROGRAMDATA").ok();
        std::env::set_var("APPDATA", &tmp);
        std::env::remove_var("PROGRAMDATA");

        let recs = read_startup_folders();

        // restore env
        match saved_appdata { Some(v) => std::env::set_var("APPDATA", v), None => std::env::remove_var("APPDATA") }
        if let Some(v) = saved_pd { std::env::set_var("PROGRAMDATA", v); }
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(recs.iter().any(|r| r.value.as_deref() == Some("evil.lnk") && r.mechanism == "startup"));
        assert!(!recs.iter().any(|r| r.value.as_deref() == Some("desktop.ini")));
    }
```

- [ ] **Step 3: Run + gate.**

Run: `cargo test -p cairn-collectors persist` + full gate. Expected: PASS (the new test runs on all
platforms). NOTE: this test mutates process env; it is the only test touching APPDATA/PROGRAMDATA so
there is no cross-test interference, and it restores the originals.

- [ ] **Step 4: Commit.**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2c): startup-folders reader (std::fs, cross-platform, skips desktop.ini)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: `PersistCollector impl Collector` (TDD + smoke)

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: Write the test.** Append to the `#[cfg(test)] mod tests` block:

```rust
    use cairn_core::record::Record;
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::Config;

    /// PersistCollector.collect returns only Persistence records, never panics, name="persist".
    #[test]
    fn persist_collector_collects_without_panicking() {
        let c = PersistCollector;
        assert_eq!(c.name(), "persist");
        let cfg = Config::default();
        let ctx = CollectCtx { config: &cfg, admin: false, se_backup: false, se_debug: false };
        let recs = c.collect(&ctx).expect("collect");
        assert!(recs.iter().all(|r| matches!(r, Record::Persistence(_))));
        assert_eq!(c.sources()[0].artifact, "persistence");
        assert_eq!(c.sources()[0].method, "api");
    }
```

- [ ] **Step 2: Run it, watch it fail.**

Run: `cargo test -p cairn-collectors persist_collector`
Expected: FAIL — `PersistCollector` not defined.

- [ ] **Step 3: Implement.** First REMOVE the file-level `#![allow(dead_code)]` from the top of
  `persist.rs` (the Collector now consumes every reader + helper). Add the imports needed at the top:

```rust
use cairn_core::manifest::SourceEntry;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;
```

Then add (above the tests module):

```rust
/// Collector for live persistence mechanisms (SRS §4 persist_collector). Read-only.
pub struct PersistCollector;

impl Collector for PersistCollector {
    fn name(&self) -> &str {
        "persist"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        // Each reader is best-effort + total (returns what it can read; never panics).
        let mut records = Vec::new();
        records.extend(read_run_keys());
        records.extend(read_services());
        records.extend(read_winlogon());
        records.extend(read_ifeo());
        records.extend(read_startup_folders());
        Ok(records.into_iter().map(Record::Persistence).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "persistence".into(),
            path: "live:registry+startup".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(), // a live registry read is not a byte stream (spec §5)
            errors: vec![],
        }]
    }
}
```

- [ ] **Step 4: Run + gate.**

Run: `cargo test -p cairn-collectors persist` + full gate.
Expected: PASS, clippy clean WITHOUT the dead_code allow (everything is now used). On Windows the
smoke test exercises the real readers; on non-Windows it gets the startup reader + empty stubs (still
returns only Persistence records — possibly empty, which the test allows).

- [ ] **Step 5: Commit.**

```bash
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2c): PersistCollector impl Collector (fan-in 5 readers, live source)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: CLI wiring + end-to-end verification

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: Wire both into the live arm.** In `crates/cairn-cli/src/main.rs`, in the `Cmd::Run`
  live arm, the collectors and analyzers vecs currently read:

```rust
            let collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(cairn_collectors::proc::ProcCollector),
                Box::new(cairn_collectors::net::NetCollector),
            ];
            let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
            ];
```

Replace with (add the persist collector + analyzer):

```rust
            let collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(cairn_collectors::proc::ProcCollector),
                Box::new(cairn_collectors::net::NetCollector),
                Box::new(cairn_collectors::persist::PersistCollector),
            ];
            let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
                Box::new(cairn_heur::PersistHeuristic),
            ];
```

- [ ] **Step 2: Build + full workspace gate.**

Run: `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

- [ ] **Step 3: END-TO-END VERIFICATION on this live host.** (dangerouslyDisableSandbox: true.)

Run:
```
cargo run -q -p cairn-cli --bin cairn -- run --target live --output ./out-live-s2c
```
Then inspect with Read (not cat):
- `./out-live-s2c/records.jsonl` — now contains `"kind":"persistence"` lines (Run keys at least;
  the host's HKLM Run entries are ubiquitous), alongside the existing process + net_conn lines.
- `./out-live-s2c/findings.jsonl` — persist findings (if any score above the floor) have
  `"artifact":"persistence"`, `"source":"heuristic"`, a `"reason"`, and a registry or file entity.
  (An all-quiet host with only legitimate, old, Program-Files persistence is a valid empty-persist
  result — confirm the records are present even if no persist finding fires.)
- `./out-live-s2c/manifest.json` — `sources` now includes the `persistence` source;
  `counts.records` grew; `counts.findings_by_sev` consistent with findings.jsonl.
- `./out-live-s2c/run.log` — clean; "live collection + analysis complete" with counts.

Then verify integrity:
```
cargo run -q -p cairn-cli --bin cairn -- verify ./out-live-s2c/manifest.json
```
Expected: VERIFY OK, exit 0.

Record the observed numbers (total records, persistence-record count, persist findings by severity,
verify result) in your report. If verify FAILS or the run panics, STOP and report — do not paper over.

- [ ] **Step 4: Confirm prior paths intact.** `cargo test --workspace` (already green in Step 2)
  covers S1 evtx + S2-A proc/net + S2-B parentchild/netconn. Note that in the report.

- [ ] **Step 5: Commit.** The live run created `./out-live-s2c/` with real host data — it is covered
  by the repo's `/out-*` gitignore; confirm `git status` does NOT show it as addable, and do NOT add
  it. Only commit the CLI change:

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(s2c): wire PersistCollector + PersistHeuristic into cairn run --target live

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Sub-segment exit check (alignment)

After Task 9, before declaring S2-C done:

- [ ] `cargo test --workspace` green; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check` clean; `cargo audit` clean (incl. the new winreg dep).
- [ ] `unsafe` appears in NO crate except `cairn-collectors-win` (verify:
  `grep -rn "unsafe" crates --include=*.rs | grep -v cairn-collectors-win | grep -v "forbid(unsafe"` → only forbid lines). `cairn-collectors` + `cairn-heur` stay `#![forbid(unsafe_code)]`; no `#![allow(dead_code)]` left behind (Tasks 3 + 8 removed theirs).
- [ ] Every persist Finding has `reason = Some(..)` + `source = Heuristic`; `signed`/`binary_sha256` are None (deferred to S2-D / FR14).
- [ ] Real `cairn run --target live` emitted persistence records + verifiable manifest (Task 9 Step 3); proc/net/parentchild/netconn/evtx all still work.
- [ ] Both CI jobs green after push: ubuntu (stubs + startup reader + pure logic) + windows (real winreg readers).
- [ ] Update the progress memory (`cairn-stage1-progress.md`) with what S2-C delivered and the next sub-segment (S2-D: WinTrust signature verification, backfilling `signed` for proc + persist).
- [ ] Re-read SRS §4/§9/§10 + §16 S2 gate: confirm no drift; note remaining S2 (S2-D signed, Scheduled Tasks, WMI subs, raw-NTFS, offline artifacts, FR14 hashing, LOLBAS dataset).
