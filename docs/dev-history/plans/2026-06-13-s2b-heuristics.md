# S2-B: parent/child + netconn heuristics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two pure heuristic analyzers (`heur_parentchild`, `heur_netconn`) over the live proc/net Records collected in S2-A, so `cairn run --target live` stops emitting an empty `findings.jsonl` and starts flagging suspicious items with an explainable reason.

**Architecture:** A new `cairn-heur` crate (`#![forbid(unsafe_code)]`, depends only on `cairn-core`) holds a shared scoring module (`score.rs`) and two `Analyzer` implementations. The `cairn-core` orchestrator gains an analyzer fan-in stage (collectors → analyzers → findings) with graceful degrade. The CLI `run --target live` arm wires the two analyzers, writes the real findings, and reflects them in the manifest counts.

**Tech Stack:** Rust, the existing `cairn-core` Record/Finding/Analyzer contracts, serde. No new external dependencies, no `unsafe`, no host or network access.

**Spec:** `docs/superpowers/specs/2026-06-13-s2b-heuristics-design.md`

**Standing discipline (every task):** after the task's test passes, run the full gate
`cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
(from repo root `cairn/`; on Windows pass `dangerouslyDisableSandbox: true`), and `cargo audit`
when deps change. Then the anti-drift check: `#![forbid(unsafe_code)]` holds in `cairn-heur`,
analyzers touch no host state, every heuristic Finding has `reason = Some(..)` and
`source = Heuristic`, no deviation from SRS §3/§4/§5.1/§10, no scope creep (no persist
heuristic, no external LOLBAS, no correlation). Commit only after green. On Windows the AV may
lock a build probe → `os error 5`; just re-run the build (probes cache afterward).

---

## File Structure

- `crates/cairn-heur/Cargo.toml` — new crate; dep on `cairn-core` only.
- `crates/cairn-heur/src/lib.rs` — `#![forbid(unsafe_code)]`; re-exports both analyzers + score helpers.
- `crates/cairn-heur/src/score.rs` — shared: suspicious-path classification, COMMON_PORTS, public-IP test, `Signal` accumulator, weight→`Severity` mapping. Pure + TDD'd.
- `crates/cairn-heur/src/parentchild.rs` — `ParentChildHeuristic` impl `Analyzer` (FR10).
- `crates/cairn-heur/src/netconn.rs` — `NetConnHeuristic` impl `Analyzer` (FR11).
- `crates/cairn-core/src/orchestrator.rs:modify` — add `findings` to `RunOutcome`, add `analyzers` param to `run_live`, run analyzers with graceful degrade.
- `crates/cairn-core/src/orchestrator.rs:modify` (tests) — add fake-analyzer tests.
- `Cargo.toml:modify` — add `crates/cairn-heur` to workspace members.
- `crates/cairn-cli/Cargo.toml:modify` — dep on `cairn-heur`.
- `crates/cairn-cli/src/main.rs:modify` — wire analyzers, write real findings, stamp host, sort, count.

**Dependency direction:** `cairn-heur → cairn-core`; `cairn-cli → cairn-heur`. No cycle.

---

## Task 1: Scaffold `cairn-heur` crate

**Files:**
- Create: `crates/cairn-heur/Cargo.toml`
- Create: `crates/cairn-heur/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Add the crate to the workspace.** In root `Cargo.toml` under
  `[workspace] members`, add after `"crates/cairn-report",` (keep the list ordered with
  core-ward crates first):

```toml
    "crates/cairn-heur",
```

- [ ] **Step 2: Create the crate Cargo.toml.**

```toml
[package]
name = "cairn-heur"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
cairn-core = { path = "../cairn-core" }
chrono.workspace = true
```

> NOTE: `chrono` is needed for `Finding.ts`. It is already a workspace dependency
> (used by cairn-core). If `cargo check` complains it is not in `[workspace.dependencies]`,
> use the same version string the other crates use (check `crates/cairn-core/Cargo.toml`).

- [ ] **Step 3: Create the lib.rs shell.**

```rust
//! cairn-heur: heuristic analyzers (SRS §10). Pure logic over the normalized Record
//! stream; touches no host state. Every Finding carries an explainable `reason`
//! (golden rule 6). The only analysis source besides Sigma.
#![forbid(unsafe_code)]

pub mod netconn;
pub mod parentchild;
pub mod score;

pub use netconn::NetConnHeuristic;
pub use parentchild::ParentChildHeuristic;
```

- [ ] **Step 4: Create empty module files so it compiles.** Create each of `score.rs`,
  `parentchild.rs`, `netconn.rs` in `src/` with just a doc line for now:

```rust
//! (filled in a later task)
```

- [ ] **Step 5: Verify it builds.**

Run: `cargo check -p cairn-heur`
Expected: compiles (empty modules; re-exports will fail — fix by commenting the
`pub use` lines until the types exist, OR create minimal placeholder types). To keep
Step 3 honest, temporarily comment the two `pub use` lines and uncomment them in Task 4
(parentchild) and Task 6 (netconn) when the types exist.

Apply now — replace lib.rs `pub use` block with:

```rust
// Re-exports enabled as the analyzers land (Task 4 / Task 6).
// pub use netconn::NetConnHeuristic;
// pub use parentchild::ParentChildHeuristic;
```

Run again: `cargo check -p cairn-heur` → compiles.

- [ ] **Step 6: Commit.**

```bash
git add Cargo.toml Cargo.lock crates/cairn-heur/
git commit -m "feat(s2b): scaffold cairn-heur crate (pure heuristic analyzers)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `score.rs` — path classification, common ports, public-IP, severity mapping (TDD)

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`

- [ ] **Step 1: Write the failing tests + signatures.** Replace `score.rs`:

```rust
//! Shared scoring primitives for the heuristics (SRS §10). Named-constant rule tables
//! live here so a config loader can later replace them without touching matching logic.
use cairn_core::Severity;
use std::net::Ipv4Addr;

/// Directories whose presence in an image path is a suspicious-execution signal.
/// Matched case-insensitively as a substring of the path.
pub const SUSPICIOUS_DIRS: &[&str] =
    &[r"\temp\", r"\appdata\", r"\programdata\", r"\downloads\", r"\public\"];

/// Remote ports considered ordinary egress; anything else is the "rare port" signal.
pub const COMMON_PORTS: &[u16] =
    &[80, 443, 53, 22, 3389, 445, 135, 139, 21, 25, 587, 993, 143, 110];

/// True if `path` (any case) contains one of the suspicious directory segments.
pub fn is_suspicious_path(path: &str) -> bool {
    unimplemented!()
}

/// True if `port` is NOT in the common-egress set.
pub fn is_rare_port(port: u16) -> bool {
    unimplemented!()
}

/// True if `addr` is a routable public IPv4 (not RFC1918/loopback/link-local/unspecified).
/// A string that does not parse as IPv4 returns false (signal simply does not fire).
pub fn is_public_ipv4(addr: &str) -> bool {
    unimplemented!()
}

/// Accumulates weighted signals + human-readable reasons + ATT&CK tags for one finding.
#[derive(Debug, Default)]
pub struct Score {
    pub weight: u32,
    pub reasons: Vec<String>,
    pub mitre: Vec<String>,
}

impl Score {
    /// Add a signal: its weight, a plain-English reason, and optional ATT&CK ids.
    pub fn add(&mut self, weight: u32, reason: impl Into<String>, mitre: &[&str]) {
        self.weight += weight;
        self.reasons.push(reason.into());
        for m in mitre {
            let m = m.to_string();
            if !self.mitre.contains(&m) {
                self.mitre.push(m);
            }
        }
    }
}

/// Map an accumulated weight to a Severity. Returns None below the noise floor (<15),
/// meaning "do not emit a finding".
pub fn severity_for(weight: u32) -> Option<Severity> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_path_matches_each_dir_case_insensitively() {
        assert!(is_suspicious_path(r"C:\Users\a\AppData\Local\Temp\x.exe"));
        assert!(is_suspicious_path(r"c:\users\a\downloads\y.exe"));
        assert!(is_suspicious_path(r"C:\ProgramData\z.exe"));
        // a normal system path is not suspicious
        assert!(!is_suspicious_path(r"C:\Windows\System32\cmd.exe"));
    }

    #[test]
    fn rare_port_excludes_common_ports() {
        assert!(!is_rare_port(443));
        assert!(!is_rare_port(53));
        assert!(is_rare_port(4444));
        assert!(is_rare_port(8081));
    }

    #[test]
    fn public_ipv4_excludes_private_and_garbage() {
        assert!(is_public_ipv4("8.8.8.8"));
        assert!(is_public_ipv4("203.0.113.5"));
        assert!(!is_public_ipv4("10.0.0.5")); // RFC1918
        assert!(!is_public_ipv4("192.168.1.1")); // RFC1918
        assert!(!is_public_ipv4("172.16.0.1")); // RFC1918
        assert!(!is_public_ipv4("127.0.0.1")); // loopback
        assert!(!is_public_ipv4("169.254.1.1")); // link-local
        assert!(!is_public_ipv4("0.0.0.0")); // unspecified
        assert!(!is_public_ipv4("not-an-ip")); // unparseable -> false
    }

    #[test]
    fn severity_boundaries() {
        assert_eq!(severity_for(70), Some(Severity::Critical));
        assert_eq!(severity_for(69), Some(Severity::High));
        assert_eq!(severity_for(50), Some(Severity::High));
        assert_eq!(severity_for(49), Some(Severity::Medium));
        assert_eq!(severity_for(30), Some(Severity::Medium));
        assert_eq!(severity_for(29), Some(Severity::Low));
        assert_eq!(severity_for(15), Some(Severity::Low));
        assert_eq!(severity_for(14), None); // below noise floor
        assert_eq!(severity_for(0), None);
    }

    #[test]
    fn score_accumulates_weight_reasons_and_dedups_mitre() {
        let mut s = Score::default();
        s.add(50, "office spawned shell", &["T1059"]);
        s.add(40, "encoded powershell", &["T1059.001", "T1059"]);
        assert_eq!(s.weight, 90);
        assert_eq!(s.reasons.len(), 2);
        assert_eq!(s.mitre, vec!["T1059", "T1059.001"]); // deduped, insertion order
    }
}
```

- [ ] **Step 2: Run tests, watch them fail.**

Run: `cargo test -p cairn-heur score`
Expected: FAIL — `unimplemented!()` panics (the four functions).

- [ ] **Step 3: Implement the four functions.** Replace each `unimplemented!()`:

```rust
pub fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SUSPICIOUS_DIRS.iter().any(|d| lower.contains(d))
}

pub fn is_rare_port(port: u16) -> bool {
    !COMMON_PORTS.contains(&port)
}

pub fn is_public_ipv4(addr: &str) -> bool {
    match addr.parse::<Ipv4Addr>() {
        Ok(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_multicast()
        }
        Err(_) => false,
    }
}

pub fn severity_for(weight: u32) -> Option<Severity> {
    match weight {
        70.. => Some(Severity::Critical),
        50..=69 => Some(Severity::High),
        30..=49 => Some(Severity::Medium),
        15..=29 => Some(Severity::Low),
        _ => None,
    }
}
```

> NOTE: the test uses `203.0.113.5` (TEST-NET-3, documentation range). `is_documentation()`
> returns true for it, so it would be excluded. Fix the test expectation: change that line
> to a routable example, e.g. `assert!(is_public_ipv4("198.51.100.5"));` is ALSO doc-range —
> use a clearly routable one like `assert!(is_public_ipv4("104.18.0.1"));`. Update the test
> before running Step 4. (8.8.8.8 stays valid.)

- [ ] **Step 4: Fix the doc-range test line, then run + gate.**

Replace in the test `assert!(is_public_ipv4("203.0.113.5"));` with
`assert!(is_public_ipv4("104.18.0.1"));`.

Run: `cargo test -p cairn-heur score` + full gate. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/cairn-heur/src/score.rs
git commit -m "feat(s2b): shared scoring (path/port/public-ip tests, severity map)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `parentchild.rs` — pure signal scoring (TDD)

**Files:**
- Modify: `crates/cairn-heur/src/parentchild.rs`

This task implements the pure per-process scoring (no `Analyzer` trait yet — that is
Task 4). Splitting keeps each unit testable: scoring logic first, trait wiring second.

- [ ] **Step 1: Write the failing test + signature.** Replace `parentchild.rs`:

```rust
//! heur_parentchild (FR10, SRS §10): anomalous parent->child, encoded PowerShell,
//! suspicious exec path, unsigned + integrity weighting, built-in LOLBAS-flavored list.
use crate::score::{is_suspicious_path, Score};
use cairn_core::record::ProcessRecord;

// --- Named rule tables (config-loader seam; see spec) -------------------------

/// Parent images whose spawning of a shell is anomalous (Office apps).
const OFFICE_PARENTS: &[&str] =
    &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
/// Script-host parents.
const SCRIPT_PARENTS: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe"];
/// Shell/child images that are suspicious when spawned by the above.
const SHELL_CHILDREN: &[&str] =
    &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
/// PowerShell binaries (for the `-e ` disambiguation).
const PS_BINARIES: &[&str] = &["powershell.exe", "pwsh.exe"];
/// Built-in LOLBAS-flavored watchlist (NOT the full external dataset; see spec scope).
const LOLBAS_WATCH: &[&str] = &[
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
    "bitsadmin.exe", "cscript.exe", "wscript.exe",
];

/// Lowercased file name (last path segment) of an image path.
fn file_name(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

/// True if cmdline shows an encoded-command flag with a base64-looking token.
/// `-e ` only counts when the image is a PowerShell binary (avoids unrelated -e flags).
fn has_encoded_powershell(image_name: &str, cmdline: &str) -> bool {
    let lc = cmdline.to_ascii_lowercase();
    let flag = lc.contains("-enc")
        || lc.contains("-encodedcommand")
        || (lc.contains("-e ") && PS_BINARIES.contains(&image_name));
    flag && has_base64_token(cmdline)
}

/// A run of >= 16 chars from the base64 alphabet.
fn has_base64_token(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            if run >= 16 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Score one process against its (optional) parent. Returns a Score (may be empty).
fn score_process(p: &ProcessRecord, parent: Option<&ProcessRecord>) -> Score {
    let mut s = Score::default();
    let child_name = file_name(&p.image);
    let parent_name = parent.map(|pp| file_name(&pp.image));

    if let Some(pn) = &parent_name {
        if OFFICE_PARENTS.contains(&pn.as_str()) && SHELL_CHILDREN.contains(&child_name.as_str()) {
            s.add(50, format!("Office app {pn} spawned shell {child_name}"), &["T1059"]);
        }
        if SCRIPT_PARENTS.contains(&pn.as_str())
            && ["cmd.exe", "powershell.exe", "pwsh.exe"].contains(&child_name.as_str())
        {
            s.add(30, format!("script host {pn} spawned {child_name}"), &["T1059"]);
        }
    }
    if has_encoded_powershell(&child_name, &p.cmdline) {
        s.add(40, "encoded PowerShell command", &["T1059.001"]);
    }
    if is_suspicious_path(&p.image) {
        s.add(25, format!("executes from a suspicious path: {}", p.image), &["T1036"]);
    }
    if p.signed == Some(false) {
        s.add(20, "binary is unsigned", &[]);
    }
    if p.signed == Some(false)
        && matches!(p.integrity.as_deref(), Some("high") | Some("system"))
    {
        s.add(15, "unsigned binary running at high integrity", &["T1068"]);
    }
    if LOLBAS_WATCH.contains(&child_name.as_str()) && lolbas_suspicious(&p.cmdline) {
        s.add(30, format!("LOLBAS {child_name} with suspicious arguments"), &["T1218"]);
    }
    s
}

/// Suspicious argument patterns for a watchlisted LOLBAS binary.
fn lolbas_suspicious(cmdline: &str) -> bool {
    let lc = cmdline.to_ascii_lowercase();
    lc.contains("http") || lc.contains("scrobj") || lc.contains("/i:") || has_base64_token(cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, ppid: u32, image: &str, cmdline: &str) -> ProcessRecord {
        ProcessRecord {
            pid, ppid, image: image.into(), cmdline: cmdline.into(),
            signed: None, integrity: None, user: None, start_time: None,
        }
    }

    /// Office -> encoded PowerShell scores high+ and tags T1059.001.
    #[test]
    fn office_encoded_powershell_scores_high() {
        let parent = proc(100, 4, r"C:\Program Files\Microsoft Office\winword.exe", "");
        let child = proc(
            200, 100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let s = score_process(&child, Some(&parent));
        assert!(s.weight >= 50, "weight {} should be high+", s.weight);
        assert!(s.mitre.contains(&"T1059.001".to_string()));
        assert!(s.reasons.iter().any(|r| r.contains("winword.exe")));
    }

    /// A benign explorer -> notepad (signed, normal path) scores 0.
    #[test]
    fn benign_explorer_notepad_scores_zero() {
        let parent = proc(50, 4, r"C:\Windows\explorer.exe", "");
        let mut child = proc(60, 50, r"C:\Windows\System32\notepad.exe", "notepad.exe");
        child.signed = Some(true);
        let s = score_process(&child, Some(&parent));
        assert_eq!(s.weight, 0);
    }

    /// Unsigned binary from Temp still scores even with NO parent (self-signals only).
    #[test]
    fn unsigned_from_temp_no_parent_scores() {
        let mut p = proc(70, 0, r"C:\Users\a\AppData\Local\Temp\evil.exe", "evil.exe");
        p.signed = Some(false);
        let s = score_process(&p, None);
        // suspicious path (25) + unsigned (20) = 45 -> at least medium, no panic
        assert!(s.weight >= 45);
    }
}
```

- [ ] **Step 2: Run tests, watch them fail (then pass).**

Run: `cargo test -p cairn-heur parentchild`
Expected: COMPILES and the three `score_process` tests PASS. This task writes the pure
scoring function alongside its tests (a single cohesive unit); the RED/GREEN is the test
suite asserting the scoring math. If any boundary is off, fix the weights/conditions until
green. The imports at the top are already trimmed to exactly what `score_process` needs
(`is_suspicious_path`, `Score`, `ProcessRecord`) — the `Analyzer`/`Finding`/`Entity`
imports are added in Task 4, so clippy stays clean here.

- [ ] **Step 3: Commit.**

```bash
git add crates/cairn-heur/src/parentchild.rs
git commit -m "feat(s2b): parentchild pure scoring (office/script->shell, enc-ps, lolbas)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: `ParentChildHeuristic impl Analyzer` (TDD)

**Files:**
- Modify: `crates/cairn-heur/src/parentchild.rs`
- Modify: `crates/cairn-heur/src/lib.rs` (enable the re-export)

- [ ] **Step 1: Write the failing test.** Append to `parentchild.rs` tests module:

```rust
    use cairn_core::traits::Analyzer;
    use cairn_core::record::Record;

    fn rec(p: ProcessRecord) -> Record { Record::Process(p) }

    /// The analyzer emits one Heuristic finding (with reason + entity) for a malicious
    /// Office->encoded-PS pair, and nothing for a benign process.
    #[test]
    fn analyzer_emits_finding_for_malicious_pair_only() {
        let parent = proc(100, 4, r"C:\...\winword.exe", "");
        let child = proc(
            200, 100, r"C:\...\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        );
        let mut benign = proc(60, 50, r"C:\Windows\System32\notepad.exe", "notepad.exe");
        benign.signed = Some(true);
        let recs = vec![rec(parent), rec(child), rec(benign)];

        let findings = ParentChildHeuristic.analyze(&recs).expect("analyze");
        assert_eq!(findings.len(), 1, "only the malicious child should fire");
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some(), "golden rule 6: reason required");
        assert!(f.entity.process.is_some());
        assert!(f.mitre.contains(&"T1059.001".to_string()));
    }
```

- [ ] **Step 2: Run it, watch it fail.**

Run: `cargo test -p cairn-heur analyzer_emits_finding`
Expected: FAIL — `ParentChildHeuristic` not defined.

- [ ] **Step 3: Implement the analyzer.** Add to `parentchild.rs` (above the tests
  module). First widen the imports at the top of the file to:

```rust
use crate::score::{is_suspicious_path, severity_for, Score};
use cairn_core::record::{ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use cairn_core::finding::EntityProcess;
use std::collections::HashMap;
```

Then add:

```rust
/// Analyzer: scores every process against its parent and emits findings above the floor.
pub struct ParentChildHeuristic;

impl Analyzer for ParentChildHeuristic {
    fn name(&self) -> &str {
        "heur_parentchild"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        // Index processes by pid for parent lookup.
        let by_pid: HashMap<u32, &ProcessRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Process(p) => Some((p.pid, p)),
                _ => None,
            })
            .collect();

        let mut out = Vec::new();
        for r in records {
            let Record::Process(p) = r else { continue };
            let parent = by_pid.get(&p.ppid).copied();
            let score = score_process(p, parent);
            let Some(severity) = severity_for(score.weight) else { continue };

            let mut f = Finding::new(severity, suspicious_title(p), FindingSource::Heuristic);
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre;
            f.artifact = "process".into();
            f.details = format!(
                "pid={} ppid={} image={} cmdline={}",
                p.pid, p.ppid, p.image, p.cmdline
            );
            f.ts = p.start_time.unwrap_or_else(chrono::Utc::now);
            f.entity = Entity {
                process: Some(EntityProcess {
                    pid: p.pid,
                    ppid: p.ppid,
                    image: p.image.clone(),
                    cmdline: p.cmdline.clone(),
                    signed: p.signed,
                    integrity: p.integrity.clone(),
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        Ok(out)
    }
}

/// A short title for a flagged process.
fn suspicious_title(p: &ProcessRecord) -> String {
    let name = file_name(&p.image);
    format!("Suspicious process: {name}")
}
```

- [ ] **Step 4: Enable the re-export in lib.rs.** Uncomment in `crates/cairn-heur/src/lib.rs`:

```rust
pub use parentchild::ParentChildHeuristic;
```

- [ ] **Step 5: Run + gate.**

Run: `cargo test -p cairn-heur parentchild` + full gate. Expected: PASS, clippy clean.

> If clippy flags `file_name` or `score_process` as used-only-in-tests in some config,
> they are used by the analyzer now — should be clean. The `HashMap` import is now used.

- [ ] **Step 6: Commit.**

```bash
git add crates/cairn-heur/src/parentchild.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(s2b): ParentChildHeuristic impl Analyzer (Record->Finding)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: `netconn.rs` — pure signal scoring (TDD)

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs`

- [ ] **Step 1: Write the failing test + implementation.** Replace `netconn.rs`:

```rust
//! heur_netconn (FR11, SRS §10): bare public-IP remote, rare remote port, owning-proc
//! in temp, unsigned owner, suspicious high-port listener. Pure scoring (analyzer is Task 6).
use crate::score::{is_public_ipv4, is_rare_port, is_suspicious_path, Score};
use cairn_core::record::{NetConnRecord, ProcessRecord};

/// Score one connection against its (optional) owning process.
fn score_conn(c: &NetConnRecord, owner: Option<&ProcessRecord>) -> Score {
    let mut s = Score::default();

    if let Some(raddr) = c.raddr.as_deref() {
        if is_public_ipv4(raddr) {
            s.add(25, format!("connection to bare public IP {raddr}"), &[]);
        }
    }
    if let Some(rport) = c.rport {
        if is_rare_port(rport) {
            s.add(20, format!("uncommon remote port {rport}"), &[]);
        }
    }
    if let Some(o) = owner {
        if is_suspicious_path(&o.image) {
            s.add(30, format!("owning process runs from a suspicious path: {}", o.image), &[]);
        }
        if o.signed == Some(false) {
            s.add(20, "owning process is unsigned", &[]);
        }
        if c.state.as_deref() == Some("listen") && c.lport > 1024 && o.signed == Some(false) {
            s.add(25, format!("unsigned process listening on high port {}", c.lport), &[]);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(proto: &str, lport: u16, raddr: Option<&str>, rport: Option<u16>, state: Option<&str>, pid: Option<u32>) -> NetConnRecord {
        NetConnRecord {
            proto: proto.into(),
            laddr: "0.0.0.0".into(),
            lport,
            raddr: raddr.map(|s| s.into()),
            rport,
            state: state.map(|s| s.into()),
            pid,
        }
    }
    fn owner(image: &str, signed: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid: 1, ppid: 0, image: image.into(), cmdline: String::new(),
            signed, integrity: None, user: None, start_time: None,
        }
    }

    /// Unsigned proc in Temp connecting to a public IP on a rare port scores high.
    #[test]
    fn unsigned_temp_to_public_rare_port_scores_high() {
        let c = conn("tcp", 50000, Some("104.18.0.1"), Some(4444), Some("established"), Some(1));
        let o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        // public ip 25 + rare port 20 + temp 30 + unsigned 20 = 95
        assert!(s.weight >= 70, "weight {}", s.weight);
        assert!(s.reasons.iter().any(|r| r.contains("104.18.0.1")));
    }

    /// A signed browser to 443 on a public IP scores below the floor (rare-port absent).
    #[test]
    fn signed_browser_https_scores_below_floor() {
        let c = conn("tcp", 51000, Some("104.18.0.1"), Some(443), Some("established"), Some(2));
        let o = owner(r"C:\Program Files\browser\b.exe", Some(true));
        let s = score_conn(&c, Some(&o));
        // public ip 25 only -> 25 is actually Low; spec wants this quiet. Adjust:
        // The "bare public IP" signal alone is 25 (Low). To keep normal browsing quiet,
        // the public-IP signal should require a rare port too. See Step 2 note.
        assert!(s.weight < 15, "normal https should be below floor, got {}", s.weight);
    }

    /// Loopback / private dest produces nothing.
    #[test]
    fn loopback_private_scores_zero() {
        let c = conn("tcp", 445, Some("127.0.0.1"), Some(445), None, Some(4));
        let o = owner(r"C:\Windows\System32\svchost.exe", Some(true));
        let s = score_conn(&c, Some(&o));
        assert_eq!(s.weight, 0);
    }

    /// Missing owner still evaluates connection-only signals without panic.
    #[test]
    fn missing_owner_scores_connection_signals() {
        let c = conn("tcp", 50000, Some("104.18.0.1"), Some(4444), Some("established"), Some(999));
        let s = score_conn(&c, None);
        // public ip 25 + rare port 20 = 45, no owner signals
        assert_eq!(s.weight, 45);
    }
}
```

- [ ] **Step 2: Reconcile the "quiet browser" requirement.** The spec requires normal
  HTTPS to stay below the floor, but "bare public IP" alone is 25 (Low). Resolve by making
  the public-IP signal fire ONLY together with a rare port (the spec's stated approximation:
  "public IP + uncommon port" is the bare-IP proxy). Change `score_conn`'s first block to:

```rust
    // "Bare public IP" is approximated as a public destination on an uncommon port
    // (no DNS lookup at runtime, NFR6). Public IP on a common port (normal browsing)
    // stays quiet.
    let rare = c.rport.map(is_rare_port).unwrap_or(false);
    if let Some(raddr) = c.raddr.as_deref() {
        if is_public_ipv4(raddr) && rare {
            s.add(25, format!("connection to bare public IP {raddr} on an uncommon port"), &[]);
        }
    }
    if let Some(rport) = c.rport {
        if is_rare_port(rport) {
            s.add(20, format!("uncommon remote port {rport}"), &[]);
        }
    }
```

Update the `missing_owner_scores_connection_signals` expectation: now public-IP fires only
with rare port → 25 + 20 = 45 still holds (rare port 4444). The
`signed_browser_https_scores_below_floor` test now passes (443 is common → public-IP signal
suppressed → weight 0). Adjust its assertion comment; the `assert!(s.weight < 15)` holds (0).

- [ ] **Step 3: Run + gate.**

Run: `cargo test -p cairn-heur netconn` + full gate. Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add crates/cairn-heur/src/netconn.rs
git commit -m "feat(s2b): netconn pure scoring (public-ip+rare-port, temp/unsigned owner)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: `NetConnHeuristic impl Analyzer` (TDD)

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs`
- Modify: `crates/cairn-heur/src/lib.rs` (enable the re-export)

- [ ] **Step 1: Write the failing test.** Append to `netconn.rs` tests module:

```rust
    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    /// The analyzer emits one Heuristic NetConn finding for the malicious conn, with
    /// reason + netconn entity, and nothing for loopback.
    #[test]
    fn analyzer_emits_finding_for_malicious_conn() {
        let bad = Record::NetConn(conn("tcp", 50000, Some("104.18.0.1"), Some(4444), Some("established"), Some(1)));
        let good = Record::NetConn(conn("tcp", 445, Some("127.0.0.1"), Some(445), None, Some(4)));
        let proc = Record::Process(owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", Some(false)));
        // owner pid must match the bad conn's pid (1)
        let recs = vec![bad, good, proc];

        let findings = NetConnHeuristic.analyze(&recs).expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert!(f.entity.netconn.is_some());
    }
```

- [ ] **Step 2: Run it, watch it fail.**

Run: `cargo test -p cairn-heur analyzer_emits_finding_for_malicious_conn`
Expected: FAIL — `NetConnHeuristic` not defined.

- [ ] **Step 3: Implement.** Add to `netconn.rs` (above the tests module). Widen the top
  imports to:

```rust
use crate::score::{is_public_ipv4, is_rare_port, is_suspicious_path, severity_for, Score};
use cairn_core::record::{NetConnRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result};
use cairn_core::finding::EntityNetConn;
use std::collections::HashMap;
```

Then add:

```rust
/// Analyzer: scores every connection against its owning process.
pub struct NetConnHeuristic;

impl Analyzer for NetConnHeuristic {
    fn name(&self) -> &str {
        "heur_netconn"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let by_pid: HashMap<u32, &ProcessRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::Process(p) => Some((p.pid, p)),
                _ => None,
            })
            .collect();

        let mut out = Vec::new();
        for r in records {
            let Record::NetConn(c) = r else { continue };
            let owner = c.pid.and_then(|pid| by_pid.get(&pid).copied());
            let score = score_conn(c, owner);
            let Some(severity) = severity_for(score.weight) else { continue };

            let mut f = Finding::new(
                severity,
                format!("Suspicious {} connection", c.proto),
                FindingSource::Heuristic,
            );
            f.reason = Some(score.reasons.join("; "));
            f.mitre = score.mitre;
            f.artifact = "netconn".into();
            f.details = format!(
                "{} {}:{} -> {}:{} pid={:?}",
                c.proto, c.laddr, c.lport,
                c.raddr.as_deref().unwrap_or("-"),
                c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                c.pid
            );
            f.entity = Entity {
                netconn: Some(EntityNetConn {
                    laddr: c.laddr.clone(),
                    lport: c.lport,
                    raddr: c.raddr.clone(),
                    rport: c.rport,
                    pid: c.pid,
                }),
                ..Entity::default()
            };
            out.push(f);
        }
        Ok(out)
    }
}
```

- [ ] **Step 4: Enable the re-export in lib.rs.** Uncomment in `crates/cairn-heur/src/lib.rs`:

```rust
pub use netconn::NetConnHeuristic;
```

- [ ] **Step 5: Run + gate.**

Run: `cargo test -p cairn-heur netconn` + full gate. Expected: PASS, clippy clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/cairn-heur/src/netconn.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(s2b): NetConnHeuristic impl Analyzer (conn->Finding, owner lookup)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Orchestrator analyzer fan-in (TDD, fake analyzers)

**Files:**
- Modify: `crates/cairn-core/src/orchestrator.rs`

- [ ] **Step 1: Write the failing tests.** In `orchestrator.rs`, add to the tests module
  (after the existing collector tests):

```rust
    use crate::finding::{Finding, Severity, FindingSource};
    use crate::traits::Analyzer;

    /// A fake analyzer returning a canned result (or an error).
    struct FakeAnalyzer {
        name: &'static str,
        result: std::sync::Mutex<Option<Result<Vec<Finding>, CairnError>>>,
    }
    impl FakeAnalyzer {
        fn ok(name: &'static str, findings: Vec<Finding>) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer { name, result: std::sync::Mutex::new(Some(Ok(findings))) })
        }
        fn err(name: &'static str) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                result: std::sync::Mutex::new(Some(Err(CairnError::Analyzer {
                    analyzer: name.into(), reason: "boom".into(),
                }))),
            })
        }
    }
    impl Analyzer for FakeAnalyzer {
        fn name(&self) -> &str { self.name }
        fn analyze(&self, _records: &[Record]) -> crate::Result<Vec<Finding>> {
            self.result.lock().unwrap().take().unwrap()
        }
    }

    fn a_finding() -> Finding {
        Finding::new(Severity::High, "t", FindingSource::Heuristic)
    }

    /// Analyzer findings land in RunOutcome.findings.
    #[test]
    fn analyzers_findings_are_collected() {
        let cfg = Config::default();
        let collectors = vec![FakeCollector::ok("proc", vec![proc_rec()])];
        let analyzers = vec![FakeAnalyzer::ok("h", vec![a_finding()])];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        assert_eq!(out.findings.len(), 1);
    }

    /// A failing analyzer is skipped; the run still returns the other's findings.
    #[test]
    fn failing_analyzer_is_skipped_run_continues() {
        let cfg = Config::default();
        let collectors = vec![FakeCollector::ok("proc", vec![proc_rec()])];
        let analyzers = vec![
            FakeAnalyzer::err("bad"),
            FakeAnalyzer::ok("good", vec![a_finding()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        assert_eq!(out.findings.len(), 1, "good analyzer still ran");
    }
```

- [ ] **Step 2: Run, watch it fail.**

Run: `cargo test -p cairn-core orchestrator`
Expected: FAIL to compile — `run_live` takes 4 args, `RunOutcome` has no `findings`.

- [ ] **Step 3: Update `RunOutcome` and `run_live`.** In `orchestrator.rs`:

Add `Finding` to the imports:

```rust
use crate::finding::Finding;
use crate::traits::{Analyzer, CollectCtx, Collector};
```

Add the field to `RunOutcome`:

```rust
#[derive(Debug)]
pub struct RunOutcome {
    pub records: Vec<Record>,
    pub findings: Vec<Finding>,
    pub sources: Vec<SourceEntry>,
    pub privileges: Privileges,
    pub hostname: String,
}
```

Change the `run_live` signature + add the analyzer stage before the `RunOutcome`
construction:

```rust
pub fn run_live(
    cfg: &Config,
    privileges: Privileges,
    hostname: String,
    collectors: &[Box<dyn Collector>],
    analyzers: &[Box<dyn Analyzer>],
) -> RunOutcome {
    let ctx = CollectCtx {
        config: cfg,
        admin: privileges.admin,
        se_backup: privileges.se_backup,
        se_debug: privileges.se_debug,
    };
    let mut records = Vec::new();
    let mut sources = Vec::new();
    for c in collectors {
        match c.collect(&ctx) {
            Ok(mut recs) => {
                records.append(&mut recs);
                sources.extend(c.sources());
            }
            Err(e) => {
                tracing::warn!(collector = c.name(), error = %e, "collector failed; skipping");
                sources.push(SourceEntry {
                    artifact: c.name().to_string(),
                    path: format!("live:{}", c.name()),
                    method: "api".into(),
                    size: 0,
                    sha256: String::new(),
                    errors: vec![e.to_string()],
                });
            }
        }
    }

    // Analyzer fan-in (SRS §3): each analyzer reads the accumulated records and emits
    // findings. A failing analyzer is logged + skipped (graceful degrade), never aborts.
    let mut findings = Vec::new();
    for a in analyzers {
        match a.analyze(&records) {
            Ok(mut fs) => findings.append(&mut fs),
            Err(e) => {
                tracing::warn!(analyzer = a.name(), error = %e, "analyzer failed; skipping");
            }
        }
    }

    RunOutcome {
        records,
        findings,
        sources,
        privileges,
        hostname,
    }
}
```

- [ ] **Step 4: Fix the two existing collector tests** (`accumulates_all_successful_collectors`,
  `failing_collector_is_recorded_and_run_continues`) — they call `run_live` with 4 args.
  Add `&[]` as the analyzers argument to each:

```rust
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &[]);
```

(Both call sites; the assertions are unchanged.)

- [ ] **Step 5: Run + gate.**

Run: `cargo test -p cairn-core orchestrator` + full gate. Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add crates/cairn-core/src/orchestrator.rs
git commit -m "feat(s2b): orchestrator analyzer fan-in with graceful degrade (TDD)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: CLI wiring + end-to-end verification

**Files:**
- Modify: `crates/cairn-cli/Cargo.toml` (dep on `cairn-heur`)
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: Add the dep.** In `crates/cairn-cli/Cargo.toml` `[dependencies]`:

```toml
cairn-heur = { path = "../cairn-heur" }
```

- [ ] **Step 2: Add a unit test for finding ordering.** In `main.rs` tests module, add a
  small pure helper test (the sort key from the spec). First the test:

```rust
    #[test]
    fn findings_sort_is_deterministic_by_ts_then_title() {
        use cairn_core::{Finding, FindingSource, Severity};
        let mut a = Finding::new(Severity::High, "b-title", FindingSource::Heuristic);
        let mut b = Finding::new(Severity::High, "a-title", FindingSource::Heuristic);
        // same ts -> tiebreak by title; a-title should sort before b-title
        let ts = chrono::Utc::now();
        a.ts = ts; b.ts = ts;
        let mut v = vec![a, b];
        sort_findings(&mut v);
        assert_eq!(v[0].title, "a-title");
        assert_eq!(v[1].title, "b-title");
    }
```

- [ ] **Step 3: Run it, watch it fail.**

Run: `cargo test -p cairn-cli findings_sort_is_deterministic`
Expected: FAIL — `sort_findings` not defined.

- [ ] **Step 4: Add `sort_findings` helper.** Near the other pure helpers in `main.rs`
  (e.g. by `write_records_jsonl`), add:

```rust
/// Deterministic output ordering (NFR4): sort by (ts, then a stable tiebreak key).
/// Heuristic findings have no record_id, so the tiebreak is (title, then entity pid for
/// process / lport for netconn). Never sort by the random Finding.id (uuid).
fn sort_findings(findings: &mut [cairn_core::Finding]) {
    findings.sort_by(|a, b| {
        a.ts.cmp(&b.ts)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| finding_tiebreak(a).cmp(&finding_tiebreak(b)))
    });
}

/// Stable secondary key: process pid or netconn lport (0 if neither).
fn finding_tiebreak(f: &cairn_core::Finding) -> u32 {
    if let Some(p) = &f.entity.process {
        p.pid
    } else if let Some(n) = &f.entity.netconn {
        n.lport as u32
    } else {
        0
    }
}
```

- [ ] **Step 5: Run the unit test.**

Run: `cargo test -p cairn-cli findings_sort_is_deterministic` → PASS.

- [ ] **Step 6: Wire the analyzers into the `Cmd::Run` live arm.** In `main.rs`, in the
  `Cmd::Run(args)` arm, REPLACE the block from `let collectors` through the two empty
  `write_*` calls. Current code (around lines 430-472):

```rust
            let collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(cairn_collectors::proc::ProcCollector),
                Box::new(cairn_collectors::net::NetCollector),
            ];
            let outcome = run_live(&cfg, privileges, hostname, &collectors);
            tracing::info!(records = outcome.records.len(), "live collection complete");

            let by_sev =
                cairn_report::Summary::from_findings(&[], outcome.records.len() as u64).by_severity;
```

Replace with (note: also import `Analyzer` at the top of the `Cmd::Run` arm next to the
existing `use cairn_core::traits::Collector;`):

```rust
            let collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(cairn_collectors::proc::ProcCollector),
                Box::new(cairn_collectors::net::NetCollector),
            ];
            let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
            ];
            let mut outcome = run_live(&cfg, privileges, hostname, &collectors, &analyzers);
            // Stamp the host onto each finding (analyzers don't know the hostname), then
            // sort for deterministic output (NFR4).
            for f in &mut outcome.findings {
                f.host = outcome.hostname.clone();
            }
            sort_findings(&mut outcome.findings);
            tracing::info!(
                records = outcome.records.len(),
                findings = outcome.findings.len(),
                "live collection + analysis complete"
            );

            let by_sev = cairn_report::Summary::from_findings(
                &outcome.findings,
                outcome.records.len() as u64,
            )
            .by_severity;
```

Then REPLACE the two empty writes (around lines 471-472):

```rust
            sink.write_timeline_csv(&[])?; // no findings yet (no analyzers this sub-segment)
            sink.write_findings_jsonl(&[])?;
```

with:

```rust
            sink.write_timeline_csv(&outcome.findings)?;
            sink.write_findings_jsonl(&outcome.findings)?;
```

> NOTE: `outcome` must be `mut` now (we mutate findings). The `let mut outcome` above
> handles that. Leave `write_records_jsonl(&dir, &outcome.records)?;` and
> `manifest_outputs_then_write` unchanged — manifest still hashes timeline.csv +
> findings.jsonl (now non-empty), counts now reflect real findings.

- [ ] **Step 7: Build + full workspace gate.**

Run: `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

- [ ] **Step 8: END-TO-END VERIFICATION on this live host.**

Run:
```
cargo run -q -p cairn-cli --bin cairn -- run --target live --output ./out-live-s2b
```
Then inspect (use Read, not shell cat):
- `./out-live-s2b/findings.jsonl` — NOW non-empty if anything on this host scores; each
  line has `"source":"heuristic"`, a `"reason"`, and a process/netconn `entity`. (If empty,
  that is a valid result on a clean host — confirm by lowering nothing; instead verify the
  analyzers ran via run.log "analysis complete findings=N".)
- `./out-live-s2b/timeline.csv` — header + one row per finding, sorted by Timestamp.
- `./out-live-s2b/manifest.json` — `counts.findings_by_sev` matches the findings file.
- `./out-live-s2b/run.log` — has "live collection + analysis complete" with a findings count.

Then verify integrity:
```
cargo run -q -p cairn-cli --bin cairn -- verify ./out-live-s2b/manifest.json
```
Expected: VERIFY OK, exit 0.

- [ ] **Step 9: Confirm S1 evtx path still works.** Run an S1 fixture through `cairn evtx`
  (fetch fixtures via `tests/fetch-fixtures.sh` if absent) and confirm it still produces
  findings + a passing verify. This guards against regressions in the shared reporter path.

- [ ] **Step 10: Commit.**

```bash
git add crates/cairn-cli/Cargo.toml crates/cairn-cli/src/main.rs Cargo.lock
git commit -m "feat(s2b): wire heuristics into cairn run --target live (real findings)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Sub-segment exit check (alignment)

After Task 8, before declaring S2-B done:

- [ ] `cargo test --workspace` all green; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check` clean; `cargo audit` clean.
- [ ] `unsafe` appears in NO crate except `cairn-collectors-win` (verify:
  `grep -rn "unsafe" crates --include=*.rs | grep -v cairn-collectors-win | grep -v "forbid(unsafe"` → only the forbid lines). `cairn-heur` is `#![forbid(unsafe_code)]`.
- [ ] Every heuristic Finding has `reason = Some(..)` and `source = Heuristic` (golden rules 5/6 — Sigma-only author requirement does not apply to heuristics).
- [ ] Real `cairn run --target live` produced timeline + findings + verifiable manifest (Task 8 Step 8 passed); `cairn evtx` unchanged (Step 9).
- [ ] Both CI jobs green after push: ubuntu + windows.
- [ ] Update the progress memory (`cairn-stage1-progress.md`) with what S2-B delivered and the next sub-segment (persistence collector → then persist heuristic; or raw-NTFS).
- [ ] Re-read SRS §3/§4/§10 + §16 S2 gate: confirm no drift; note remaining S2 items (persistence, persist heuristic, raw-NTFS, offline artifacts, hash-suspicious-binaries FR14, LOLBAS dataset).
