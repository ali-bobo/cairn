# S2-L: profile/only wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the declared-but-ignored `--profile` and `--only` CLI flags to real collector selection, so `--only persist` provably restricts the run and `--profile bogus` errors instead of silently falling back.

**Architecture:** A pure `Profile::from_str` (in cairn-core) parses `--profile` (invalid → Err). A pure `select_modules(profile, only, available)` decision function (in cairn-core) returns which collector names to run, intersecting the profile's base set with the optional `--only` allow-list. The CLI `run` arm parses both flags, calls `select_modules`, builds its collector vec from the result, and records the active profile + selected modules in the manifest and run.log. No host, no unsafe, no new dependency.

**Tech Stack:** Rust, clap (existing CLI), serde (existing manifest), `#![forbid(unsafe_code)]` throughout (cairn-core + cairn-cli).

---

## Critical context for the implementer (read before Task 1)

**The real collector names.** `Collector::name()` returns these EXACT strings today:
- `crates/cairn-collectors/src/proc.rs:60` → `"proc"`
- `crates/cairn-collectors/src/net.rs:12` → `"net"`
- `crates/cairn-collectors/src/persist.rs:812` → `"persist"`

The CLI help text and the spec sometimes say `process`/`evtx` — but selection MUST match against the real `name()` strings (`proc`, `net`, `persist`). `--only` therefore accepts the real names, PLUS one friendly alias `process` → `proc` (so the existing help string `evtx,process,persist` isn't a lie). `evtx` is NOT a live collector (it's the separate `cairn evtx` subcommand); an `--only evtx` on `cairn run` is an unknown-name warning, not a match.

**What exists already (do NOT recreate):**
- `crates/cairn-core/src/config.rs:15-21` — `Profile { Minimal, Standard, Verbose }` enum, `#[serde(rename_all = "lowercase")]`, derives `Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize`. NO `from_str` yet.
- `crates/cairn-core/src/config.rs:41` — `Config.only: Vec<String>` field (currently always `vec![]`).
- `crates/cairn-core/src/manifest.rs:27-33` — `RunInfo { started_utc, finished_utc, cmdline, operator, case_id }`. NO profile/modules fields yet.
- `crates/cairn-cli/src/main.rs:100-104` — `profile: String` (default "standard"), `only: Option<String>` (comma-separated). Both currently parsed into clap but IGNORED by the run arm.
- `crates/cairn-cli/src/main.rs:538-543` — the run arm uses `Config::default()` and a HARDCODED `vec![proc, net, persist]`.
- `crates/cairn-core/src/lib.rs:23` — `pub use config::{Config, OutputKind, Profile, Target};`

**Build/test commands (run from the `cairn/` workspace root — NOT `IIR_tool/`):**
```
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```
`CARGO_TARGET_DIR` is set to `C:/Users/bosen/AppData/Local/cairn-target` (out of OneDrive).

**Golden rules in play:** pure orchestration, no host modification (rule 3), no unsafe (cli/core stay `#![forbid(unsafe_code)]`), `--profile minimal` is a footprint lever (rule 4 spirit), profile/modules are LOGGED (transparency, FR6).

---

## File structure

| File | Responsibility | Change |
|------|----------------|--------|
| `crates/cairn-core/src/config.rs` | `Profile::from_str` (case-insensitive; invalid → Err) | Modify |
| `crates/cairn-core/src/selection.rs` | pure `select_modules(profile, only, available)` + alias resolution | Create |
| `crates/cairn-core/src/lib.rs` | `pub mod selection;` + re-export `select_modules`, `SelectionOutcome` | Modify |
| `crates/cairn-core/src/manifest.rs` | `RunInfo` gains `profile: String` + `selected_modules: Vec<String>` | Modify |
| `crates/cairn-cli/src/main.rs` | run arm: parse profile/only → select → build collectors → record in manifest/run.log | Modify |

`select_modules` lives in its own `selection.rs` (one clear purpose: the pure selection decision), not bolted onto config.rs, so it can be unit-tested in isolation and grows cleanly when S2-M+ add profile-tagged collectors.

---

## Task 1: `Profile::from_str` (parse `--profile`, invalid → Err)

**Files:**
- Modify: `crates/cairn-core/src/config.rs` (after the `Profile` enum, ~line 21)
- Test: `crates/cairn-core/src/config.rs` (the existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `crates/cairn-core/src/config.rs`:

```rust
#[test]
fn profile_from_str_parses_known_values_case_insensitively() {
    assert_eq!("minimal".parse::<Profile>().unwrap(), Profile::Minimal);
    assert_eq!("standard".parse::<Profile>().unwrap(), Profile::Standard);
    assert_eq!("verbose".parse::<Profile>().unwrap(), Profile::Verbose);
    // case-insensitive: an analyst typing --profile MINIMAL still works.
    assert_eq!("MINIMAL".parse::<Profile>().unwrap(), Profile::Minimal);
    assert_eq!("Standard".parse::<Profile>().unwrap(), Profile::Standard);
}

#[test]
fn profile_from_str_rejects_unknown_value() {
    let err = "bogus".parse::<Profile>().unwrap_err();
    // The error names the bad value AND the valid set (a usable CLI error).
    assert!(err.contains("bogus"), "error should echo the bad value: {err}");
    assert!(
        err.contains("minimal") && err.contains("standard") && err.contains("verbose"),
        "error should list valid profiles: {err}"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --package cairn-core --locked profile_from_str`
Expected: FAIL — `Profile` does not implement `FromStr` (`no method named parse ... trait FromStr is not implemented`).

- [ ] **Step 3: Implement `FromStr`**

Add to `crates/cairn-core/src/config.rs`, immediately after the `Profile` enum definition (after line 21, the closing `}` of `enum Profile`):

```rust
impl std::str::FromStr for Profile {
    /// A human-readable message (the bad value + the valid set), surfaced to the
    /// CLI user. `cairn-core` libs use `CairnError`, but `--profile` parsing is a
    /// pure string→enum mapping with no I/O; a `String` message keeps it dependency-
    /// free and lets the CLI present it directly.
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "minimal" => Ok(Profile::Minimal),
            "standard" => Ok(Profile::Standard),
            "verbose" => Ok(Profile::Verbose),
            other => Err(format!(
                "unknown profile '{other}'; valid profiles: minimal, standard, verbose"
            )),
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --package cairn-core --locked profile_from_str`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-core/src/config.rs
git commit -m "feat(s2l): Profile::from_str (case-insensitive; invalid value errors)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: pure `select_modules` (the selection decision)

**Files:**
- Create: `crates/cairn-core/src/selection.rs`
- Modify: `crates/cairn-core/src/lib.rs` (add `pub mod selection;` + re-export)
- Test: `crates/cairn-core/src/selection.rs` (`#[cfg(test)] mod tests` at the bottom)

This is the heart of S2-L: a pure function. Given the profile, the optional `--only` list, and the set of available collector names, it returns which modules to run and which `--only` names matched nothing (so the CLI can warn). PURE — no host, no I/O — fully unit-tested on Linux CI.

- [ ] **Step 1: Write the failing tests**

Create `crates/cairn-core/src/selection.rs` with ONLY the tests + a stub, so the test compiles and fails:

```rust
//! Pure collector-selection decision (S2-L). Given the run profile and an optional
//! `--only` allow-list, decide which collector modules run. No host, no I/O — the
//! selection is a deterministic string-set operation, unit-tested on any platform.
//!
//! Why a module of its own: this is the switch raw-NTFS (S2-M+) hangs off. When
//! heavier collectors are added tagged `standard`/`verbose`-only, `minimal` will
//! skip them automatically — the profile→base-set mapping here is the single place
//! that knowledge lives.

use crate::config::Profile;

#[cfg(test)]
mod tests {
    use super::*;

    fn avail() -> Vec<&'static str> {
        vec!["proc", "net", "persist"]
    }

    #[test]
    fn standard_no_only_selects_all_available() {
        let out = select_modules(Profile::Standard, None, &avail());
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn minimal_no_only_selects_the_live_light_set() {
        // Today the three live collectors are all light, so minimal == the full live
        // set. The DIFFERENCE appears when S2-M+ add raw-NTFS collectors tagged
        // standard/verbose-only; minimal will then skip them.
        let out = select_modules(Profile::Minimal, None, &avail());
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
    }

    #[test]
    fn only_restricts_to_named_modules() {
        let only = vec!["persist".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["persist"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn only_alias_process_resolves_to_proc() {
        // The CLI help advertises `process`; the real collector name is `proc`.
        let only = vec!["process".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["proc"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn only_unknown_name_is_reported_not_silently_dropped() {
        let only = vec!["persist".to_string(), "bogus".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["persist"]);
        assert_eq!(out.unknown_only, vec!["bogus".to_string()]);
    }

    #[test]
    fn only_all_unknown_yields_empty_selection_without_panic() {
        let only = vec!["nope".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert!(out.selected.is_empty());
        assert_eq!(out.unknown_only, vec!["nope".to_string()]);
    }

    #[test]
    fn only_evtx_on_live_run_is_unknown() {
        // evtx is the separate `cairn evtx` subcommand, not a live collector.
        let only = vec!["evtx".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert!(out.selected.is_empty());
        assert_eq!(out.unknown_only, vec!["evtx".to_string()]);
    }

    #[test]
    fn selection_order_is_deterministic_available_order() {
        // Order follows `available` (the canonical collector order), not `only` order,
        // so output is deterministic (NFR4) regardless of how the user typed --only.
        let only = vec!["persist".to_string(), "proc".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["proc", "persist"]);
    }

    #[test]
    fn duplicate_only_names_do_not_duplicate_selection() {
        let only = vec!["persist".to_string(), "persist".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["persist"]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --package cairn-core --locked selection`
Expected: FAIL to COMPILE — `select_modules` and `SelectionOutcome` are not defined.

- [ ] **Step 3: Implement `select_modules` + `SelectionOutcome`**

Insert ABOVE the `#[cfg(test)]` block in `crates/cairn-core/src/selection.rs` (after the `use crate::config::Profile;` line):

```rust
/// The result of a selection decision: the collector names to run (in canonical
/// `available` order, deterministic), plus any `--only` names that matched no
/// available collector (surfaced as a warning by the CLI — never silently dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionOutcome {
    pub selected: Vec<String>,
    pub unknown_only: Vec<String>,
}

/// Resolve one `--only` token to a canonical collector name. The CLI advertises a
/// friendly `process`; the real `Collector::name()` is `proc`. Resolution is
/// case-insensitive. Returns the canonical lowercase token (may still be unknown).
fn canonical_only_name(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "process" => "proc".to_string(),
        other => other.to_string(),
    }
}

/// Modules a profile selects from `available`, BEFORE the `--only` intersection.
/// Today all three profiles map to the full live set (the live collectors are
/// light). When S2-M+ register heavier collectors tagged standard/verbose-only,
/// `minimal` will return a subset — this is the single place that mapping lives.
fn profile_base<'a>(_profile: Profile, available: &[&'a str]) -> Vec<&'a str> {
    // Minimal/Standard/Verbose currently select the same live set. The mechanism
    // (intersect with `available`) is what S2-L installs; profiles diverge later.
    available.to_vec()
}

/// Decide which collector modules run.
///
/// 1. base = the profile's module set (intersected with what is `available`).
/// 2. if `only` is Some, keep only modules whose canonical name is in `only`;
///    `only` names matching no available collector go to `unknown_only`.
/// 3. result order follows `available` (deterministic, NFR4); no duplicates.
///
/// PURE: no host, no I/O. Unit-tested on any platform.
pub fn select_modules(
    profile: Profile,
    only: Option<&[String]>,
    available: &[&str],
) -> SelectionOutcome {
    let base = profile_base(profile, available);

    let selected: Vec<String> = match only {
        None => base.iter().map(|s| s.to_string()).collect(),
        Some(only_list) => {
            let wanted: std::collections::BTreeSet<String> =
                only_list.iter().map(|s| canonical_only_name(s)).collect();
            // Walk `available` order so output is deterministic regardless of how the
            // user ordered --only; de-dup is implicit (each available name once).
            base.iter()
                .filter(|name| wanted.contains(&name.to_string()))
                .map(|s| s.to_string())
                .collect()
        }
    };

    // An --only name that resolves to nothing in `available` is reported, not dropped.
    let unknown_only: Vec<String> = match only {
        None => Vec::new(),
        Some(only_list) => {
            let avail_set: std::collections::BTreeSet<String> =
                available.iter().map(|s| s.to_string()).collect();
            let mut seen = std::collections::BTreeSet::new();
            only_list
                .iter()
                .filter_map(|raw| {
                    let canon = canonical_only_name(raw);
                    if avail_set.contains(&canon) {
                        None
                    } else if seen.insert(canon) {
                        // Report the ORIGINAL token the user typed (clearer warning).
                        Some(raw.trim().to_string())
                    } else {
                        None
                    }
                })
                .collect()
        }
    };

    SelectionOutcome {
        selected,
        unknown_only,
    }
}
```

- [ ] **Step 4: Wire the module into the crate**

In `crates/cairn-core/src/lib.rs`, add after `pub mod record;` (keep alphabetical-ish with the existing list):

```rust
pub mod selection;
```

And add to the re-export block (after the `pub use record::Record;` line):

```rust
pub use selection::{select_modules, SelectionOutcome};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --package cairn-core --locked selection`
Expected: PASS (all selection tests).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-core/src/selection.rs crates/cairn-core/src/lib.rs
git commit -m "feat(s2l): pure select_modules (profile base ∩ --only; unknowns reported)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `RunInfo` records the active profile + selected modules

**Files:**
- Modify: `crates/cairn-core/src/manifest.rs` (the `RunInfo` struct, ~lines 27-33)
- Test: `crates/cairn-core/src/manifest.rs` (`#[cfg(test)] mod tests`; add one if none exists)

Transparency (FR6): the manifest must record WHAT was run. Add two fields to `RunInfo`.

- [ ] **Step 1: Write the failing test**

Add to `crates/cairn-core/src/manifest.rs`. If there is no `#[cfg(test)] mod tests` block, create one at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// RunInfo round-trips the new profile + selected_modules fields through serde.
    #[test]
    fn run_info_round_trips_profile_and_modules() {
        let ri = RunInfo {
            started_utc: chrono::Utc::now(),
            finished_utc: None,
            cmdline: "cairn run --profile minimal --only persist".into(),
            operator: String::new(),
            case_id: String::new(),
            profile: "minimal".into(),
            selected_modules: vec!["persist".into()],
        };
        let json = serde_json::to_string(&ri).unwrap();
        let back: RunInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.profile, "minimal");
        assert_eq!(back.selected_modules, vec!["persist".to_string()]);
    }
}
```

> If a `#[cfg(test)] mod tests` already exists in manifest.rs, add ONLY the test fn (and `use super::*;` if not already present) into it instead of creating a second module.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package cairn-core --locked run_info_round_trips`
Expected: FAIL to COMPILE — `RunInfo` has no `profile` / `selected_modules` field.

- [ ] **Step 3: Add the fields to `RunInfo`**

In `crates/cairn-core/src/manifest.rs`, modify the `RunInfo` struct (currently lines 27-33) to add the two fields after `case_id`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub started_utc: DateTime<Utc>,
    pub finished_utc: Option<DateTime<Utc>>,
    pub cmdline: String,
    pub operator: String,
    pub case_id: String,
    /// The active run profile (minimal|standard|verbose) — transparency (FR6).
    pub profile: String,
    /// The collector modules actually selected for this run (S2-L). Empty is honest:
    /// e.g. `--only nonexistent` ran no collectors.
    pub selected_modules: Vec<String>,
}
```

- [ ] **Step 4: Fix the existing `RunInfo` construction site**

There is exactly one `RunInfo { ... }` literal outside tests, in `crates/cairn-cli/src/main.rs` (~line 589, inside the `run` arm). It will now fail to compile (missing fields). For THIS task, add placeholder values so the crate compiles; Task 4 replaces them with the real selection:

In `crates/cairn-cli/src/main.rs`, find the `RunInfo {` literal and add the two fields after `case_id: String::new(),`:

```rust
                    profile: String::new(),         // set in Task 4
                    selected_modules: Vec::new(),   // set in Task 4
```

- [ ] **Step 5: Run test + workspace check to verify pass**

Run: `cargo test --package cairn-core --locked run_info_round_trips`
Expected: PASS.

Run: `cargo check --workspace --locked`
Expected: clean (the CLI literal now compiles with placeholders).

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-core/src/manifest.rs crates/cairn-cli/src/main.rs
git commit -m "feat(s2l): RunInfo records active profile + selected modules (FR6)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: wire the `run` arm to selection

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (the `run` arm, ~lines 526-610)

This is the integration task: parse `args.profile`/`args.only`, run `select_modules`, build the collector vec from the result, log + record the choice. Multi-file-aware integration (clap args + core selection + manifest) — use a standard model, not the cheapest.

- [ ] **Step 1: Parse `--profile` (clean error on bad value)**

In the `run` arm, BEFORE the existing `let cfg = Config::default();` line (~538), insert profile parsing. Use `anyhow` (the CLI's error crate) to surface the `from_str` `String` error:

```rust
            // S2-L: parse --profile into the typed enum; an invalid value is a clean
            // CLI error (exit non-zero), not a silent Standard fallback.
            let profile: cairn_core::Profile = args
                .profile
                .parse()
                .map_err(|e: String| anyhow::anyhow!(e))?;
```

> Note: `?` here returns before any output dir is created (the parse sits after logger init but the error propagates out of `main`, exiting non-zero). That is the desired behavior — a bad `--profile` should not start a run. If the implementer finds the logger-init ordering makes the error cosmetically log to a half-set-up sink, move this parse ABOVE the `_guard` logger setup block (it has no logging dependency).

- [ ] **Step 2: Parse `--only` (comma-separated → Vec, trimmed, empties dropped)**

Immediately after the profile parse:

```rust
            // S2-L: --only is a comma-separated allow-list. None => no restriction.
            let only: Option<Vec<String>> = args.only.as_deref().map(|csv| {
                csv.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            });
```

- [ ] **Step 3: Run the selection and warn on unknown names**

After the `--only` parse:

```rust
            // S2-L: decide which collectors run. The available set is the live
            // collectors' real Collector::name() strings.
            const AVAILABLE: &[&str] = &["proc", "net", "persist"];
            let selection =
                cairn_core::select_modules(profile, only.as_deref(), AVAILABLE);
            for name in &selection.unknown_only {
                tracing::warn!(
                    only = %name,
                    "--only names a module that is not an available live collector; ignoring it"
                );
            }
            tracing::info!(
                profile = %args.profile.to_ascii_lowercase(),
                modules = %selection.selected.join(","),
                "collector selection"
            );
```

- [ ] **Step 4: Build the collector vec from the selection**

REPLACE the hardcoded collector vec (currently `crates/cairn-cli/src/main.rs:539-543`):

```rust
            let cfg = Config::default();
            let collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(cairn_collectors::proc::ProcCollector::default()),
                Box::new(cairn_collectors::net::NetCollector),
                Box::new(cairn_collectors::persist::PersistCollector::default()),
            ];
```

with selection-driven construction (each collector included only if its name is selected):

```rust
            let cfg = Config::default();
            // S2-L: construct only the selected collectors. Match on the real
            // Collector::name() strings; order follows AVAILABLE (deterministic).
            let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
            if selection.selected.iter().any(|m| m == "proc") {
                collectors.push(Box::new(cairn_collectors::proc::ProcCollector::default()));
            }
            if selection.selected.iter().any(|m| m == "net") {
                collectors.push(Box::new(cairn_collectors::net::NetCollector));
            }
            if selection.selected.iter().any(|m| m == "persist") {
                collectors.push(Box::new(cairn_collectors::persist::PersistCollector::default()));
            }
```

- [ ] **Step 5: Record the selection in the manifest**

REPLACE the Task-3 placeholders in the `RunInfo { ... }` literal:

```rust
                    profile: String::new(),         // set in Task 4
                    selected_modules: Vec::new(),   // set in Task 4
```

with the real values:

```rust
                    profile: args.profile.to_ascii_lowercase(),
                    selected_modules: selection.selected.clone(),
```

- [ ] **Step 6: Build + clippy + test the workspace**

Run: `cargo build --workspace --locked`
Expected: clean build.

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings`
Expected: no warnings.

Run: `cargo test --workspace --locked`
Expected: all green (existing CLI tests + new core tests).

- [ ] **Step 7: Smoke-check the wiring on Windows (non-admin)**

This proves `--only` actually restricts collectors. Run from the `cairn/` workspace root:

```bash
# Build the binary once.
cargo build --package cairn-cli --locked

# --only persist: run.log "collector selection" line should show modules=persist,
# and records.jsonl should contain ONLY persistence records (no proc/net).
"$CARGO_TARGET_DIR/debug/cairn.exe" run --target live --only persist --output /tmp/cairn-s2l-only
# Inspect: the run.log line `collector selection ... modules=persist`
#          and manifest.json run.profile / run.selected_modules.

# --profile bogus: must exit non-zero with the from_str error, write no output.
"$CARGO_TARGET_DIR/debug/cairn.exe" run --target live --profile bogus --output /tmp/cairn-s2l-bogus
echo "exit=$?"   # expect non-zero; /tmp/cairn-s2l-bogus should not be populated
```

Expected: the `--only persist` run's manifest shows `"profile":"standard","selected_modules":["persist"]` and records.jsonl has only persistence records; the `--profile bogus` run exits non-zero printing `unknown profile 'bogus'; valid profiles: minimal, standard, verbose`.

> If `/tmp` is awkward on this Windows shell, use a path under `C:/Users/bosen/AppData/Local/` and clean it up after (ask before deleting per the consent rule). Do NOT write test output into the OneDrive tree.

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(s2l): wire run arm to select_modules (--profile/--only honored)

--profile parses to the typed enum (invalid value errors, no silent fallback);
--only restricts the collector vec by real Collector::name(); unknown --only
names warn; manifest/run.log record the active profile + selected modules.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: CLI-level test that selection drives collector construction

**Files:**
- Modify: `crates/cairn-cli/src/main.rs` (`#[cfg(test)] mod tests`)

Task 4's logic lives inline in the `run` arm, which is hard to unit-test directly. Add a small pure helper that mirrors the construction decision and test IT, so the "selection → which collectors" mapping is covered in CI (not only by the manual Windows smoke check).

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/cairn-cli/src/main.rs`:

```rust
#[test]
fn selected_collector_names_follow_selection() {
    use cairn_core::{select_modules, Profile};
    const AVAILABLE: &[&str] = &["proc", "net", "persist"];

    // --only persist => only persist constructed.
    let only = vec!["persist".to_string()];
    let sel = select_modules(Profile::Standard, Some(&only), AVAILABLE);
    let built = built_collector_names(&sel.selected);
    assert_eq!(built, vec!["persist".to_string()]);

    // no --only => all three, in canonical order.
    let sel = select_modules(Profile::Standard, None, AVAILABLE);
    let built = built_collector_names(&sel.selected);
    assert_eq!(built, vec!["proc", "net", "persist"]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package cairn-cli --locked selected_collector_names`
Expected: FAIL to COMPILE — `built_collector_names` is not defined.

- [ ] **Step 3: Extract the construction decision into a testable helper**

Add this pure helper to `crates/cairn-cli/src/main.rs` (near the other free functions like `enrich_hashes`, OUTSIDE the test module). It returns the NAMES of the collectors that would be constructed for a given selection — the single source of truth the run arm also uses:

```rust
/// The collector names that `build_selected_collectors` would construct for this
/// selection, in canonical order. Pure mirror of the run arm's construction `if`s,
/// so the selection→collectors mapping is unit-testable without a live host.
#[cfg(test)]
fn built_collector_names(selected: &[String]) -> Vec<String> {
    ["proc", "net", "persist"]
        .iter()
        .filter(|n| selected.iter().any(|m| m == *n))
        .map(|s| s.to_string())
        .collect()
}
```

> This keeps the run arm's three `if ... push(...)` blocks (they construct real `Box<dyn Collector>` which can't run off-Windows) but verifies the SELECTION→NAME mapping that drives them. The names list here MUST stay in sync with the run arm's three `if` blocks (both use `proc`/`net`/`persist` in that order).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --package cairn-cli --locked selected_collector_names`
Expected: PASS.

- [ ] **Step 5: Full workspace gate**

Run: `cargo fmt --check`
Run: `cargo clippy --workspace --all-targets --locked -- -D warnings`
Run: `cargo test --workspace --locked`
Expected: all clean/green.

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "test(s2l): cover selection→constructed-collector-names mapping

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Acceptance gate (all tasks complete)

- [ ] `cargo fmt --check` clean.
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` — no warnings.
- [ ] `cargo test --workspace --locked` — green (new: 2 Profile::from_str, 9 selection, 1 RunInfo round-trip, 1 CLI mapping).
- [ ] `cargo audit --deny warnings` — clean (NO new dependency was added).
- [ ] `unsafe` appears in no crate except `cairn-collectors-win`; cairn-core + cairn-cli stay `#![forbid(unsafe_code)]`.
- [ ] Manual Windows e2e (non-admin) PROVES: `cairn run --only persist` records only persistence + manifest shows `selected_modules:["persist"]`; `cairn run --profile minimal` runs the live set; `cairn run --profile bogus` exits non-zero with the listed-profiles error; `cairn verify` still passes on a normal run; the manifest/run.log show the active profile + selected modules.
- [ ] No golden-rule violation (pure orchestration, no host modification, no evasion, transparency-logged); no scope creep (NO thread cap, NO raw-NTFS, NO memory bounds — those are Part A deferrals).
- [ ] Earlier stages unchanged (S1 EVTX path, S2-A..K behavior intact).

## Out of scope (deferred — do NOT implement here)

- Thread cap / rayon pool / IO priority (collectors run serially today) → the raw-NTFS parsing sub-segment (S2-M+).
- `minimal` actually skipping a heavy collector → automatic once S2-M+ register raw-NTFS collectors tagged standard/verbose-only (the `profile_base` function is where that lands).
- Per-analyzer gating by profile → if/when an analyzer becomes expensive.
- `--zip` / `--encrypt` packaging (already reject with exit 2) → output-packaging sub-segment.
