# S2-I Scheduled Tasks Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Scheduled Tasks as a 6th persistence mechanism — parse the live Task XML store, emit one PersistenceRecord per `<Exec>` action, and score it with the existing calibrated persist heuristic.

**Architecture:** A pure quick-xml parser (`parse_task_xml`) extracts each task's URI + per-`<Exec>` command/arguments; a pure glue fn turns those into PersistenceRecords reusing the existing `make_record_with_exists` (S2-F candidate model for binary_path); a `cfg(windows)` FS walk feeds real task files in, degrading gracefully to empty on the ACL-restricted store. The persist heuristic gains one mechanism arm (`scheduled_task` = weight 20). No unsafe; no schema change.

**Tech Stack:** Rust, `cairn-collectors` + `cairn-heur` (both `#![forbid(unsafe_code)]`), new dep `quick-xml` 0.40.1 (`default-features = false`, verified: compiles, 0 RustSec advisories).

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-s2i-scheduled-tasks-design.md`

---

## Background the engineer needs

`cairn-collectors/src/persist.rs` has a `PersistCollector` whose `collect()` calls five readers
(`read_run_keys`, `read_services`, `read_winlogon`, `read_ifeo`, `read_startup_folders`), each
returning `Vec<PersistenceRecord>`, then `apply_signatures()` backfills `signed`. A 6th reader
plugs in identically.

`PersistenceRecord` (cairn-core/src/record.rs): `mechanism: String`, `location: String`,
`value: Option<String>`, `command: Option<String>`, `binary_path: Option<String>`,
`binary_sha256: Option<String>`, `signed: Option<bool>`, `last_write: Option<DateTime<Utc>>`.

**Reuse `make_record_with_exists`** (already in persist.rs):
```rust
fn make_record_with_exists(
    mechanism: &str, location: String, value: Option<String>,
    command: Option<String>, last_write: Option<DateTime<Utc>>,
    exists: impl Fn(&str) -> bool,
) -> PersistenceRecord
```
It resolves `binary_path` from `command` via the S2-F candidate model (`%env%` expansion +
longest-first prefix probe via `exists`). `make_record(...)` wraps it with the real
`std::path::Path::exists`. So the Scheduled Tasks glue just calls this once per Exec action —
binary_path resolution is free and identical to the other mechanisms.

**Real Task XML** (verified via `schtasks /query /xml`; UTF-16-declared, has xmlns):
```xml
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\Microsoft\Windows\Time Synchronization\SynchronizeTime</URI>
  </RegistrationInfo>
  <Actions Context="LocalService">
    <Exec>
      <Command>%windir%\system32\sc.exe</Command>
      <Arguments>start w32time task_started</Arguments>
    </Exec>
  </Actions>
</Task>
```

**quick-xml 0.40.1 reader basics** (`default-features = false`): use `quick_xml::reader::Reader::from_str`,
loop `read_event()`, match `Event::Start`/`Event::Text`/`Event::End`. Element local-name via
`e.local_name()` (namespace-agnostic — the xmlns prefix does not change local names here). Text
is unescaped via `e.unescape()?` (handles `&amp;` etc.). No external-entity resolution (no XXE).

**Persist heuristic** (`cairn-heur/src/persist.rs`, `score_persistence`): a mechanism `match`
maps each mechanism to a base weight: `ifeo`=45, `winlogon`=35, `service`=20, `run_key`=10,
`startup`=10. Add `scheduled_task`=20.

---

## File Structure

- **Modify:** `crates/cairn-collectors/Cargo.toml` — add `quick-xml` 0.40.1, default-features off.
- **Modify:** `crates/cairn-collectors/src/persist.rs` — `ParsedExecAction` struct + pure
  `parse_task_xml`, pure `task_records_from_xml`, `cfg(windows)` `read_scheduled_tasks` (+ stub),
  wire into `collect()`; tests.
- **Modify:** `crates/cairn-heur/src/persist.rs` — one mechanism-match arm + a test.

No new files, no schema change.

---

## Task 1: Add the quick-xml dependency

**Files:**
- Modify: `crates/cairn-collectors/Cargo.toml`

- [ ] **Step 1: Add the dependency**

In `crates/cairn-collectors/Cargo.toml` `[dependencies]`, add:
```toml
quick-xml = { version = "0.40.1", default-features = false }
```

- [ ] **Step 2: Verify it resolves and the workspace still compiles**

Run: `cargo check --package cairn-collectors`
Expected: PASS (quick-xml 0.40.1 added; nothing references it yet).

- [ ] **Step 3: Verify audit is clean**

Run: `cargo audit --deny warnings`
Expected: 0 advisories (quick-xml 0.40.1 has none — verified during design).

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-collectors/Cargo.toml Cargo.lock
git commit -m "build(s2i): add quick-xml 0.40.1 (default-features off)"
```

---

## Task 2: Pure XML parser `parse_task_xml`

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block:

```rust
    const SAMPLE_TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\Microsoft\Windows\Time Synchronization\SynchronizeTime</URI>
  </RegistrationInfo>
  <Actions Context="LocalService">
    <Exec>
      <Command>%windir%\system32\sc.exe</Command>
      <Arguments>start w32time task_started</Arguments>
    </Exec>
  </Actions>
</Task>"#;

    #[test]
    fn parse_task_xml_single_exec() {
        let acts = parse_task_xml(SAMPLE_TASK_XML);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].command, r"%windir%\system32\sc.exe");
        assert_eq!(acts[0].arguments, "start w32time task_started");
        assert_eq!(
            acts[0].uri.as_deref(),
            Some(r"\Microsoft\Windows\Time Synchronization\SynchronizeTime")
        );
    }

    #[test]
    fn parse_task_xml_multiple_execs() {
        let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\T</URI></RegistrationInfo>
  <Actions>
    <Exec><Command>a.exe</Command></Exec>
    <Exec><Command>b.exe</Command><Arguments>-x</Arguments></Exec>
  </Actions>
</Task>"#;
        let acts = parse_task_xml(xml);
        assert_eq!(acts.len(), 2);
        assert_eq!(acts[0].command, "a.exe");
        assert_eq!(acts[0].arguments, "");
        assert_eq!(acts[1].command, "b.exe");
        assert_eq!(acts[1].arguments, "-x");
    }

    #[test]
    fn parse_task_xml_decodes_entities() {
        let xml = r#"<Task xmlns="x"><Actions><Exec>
            <Command>c.exe</Command><Arguments>-p a&amp;b</Arguments>
            </Exec></Actions></Task>"#;
        let acts = parse_task_xml(xml);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].arguments, "-p a&b");
    }

    #[test]
    fn parse_task_xml_skips_non_exec_and_malformed() {
        // ComHandler action -> no Exec -> empty
        let com = r#"<Task xmlns="x"><Actions><ComHandler>
            <ClassId>{GUID}</ClassId></ComHandler></Actions></Task>"#;
        assert!(parse_task_xml(com).is_empty());
        // no Actions
        assert!(parse_task_xml(r#"<Task xmlns="x"></Task>"#).is_empty());
        // malformed / empty
        assert!(parse_task_xml("not xml at all").is_empty());
        assert!(parse_task_xml("").is_empty());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-collectors --lib persist::tests::parse_task_xml`
Expected: FAIL — `parse_task_xml` / `ParsedExecAction` not found.

- [ ] **Step 3: Implement the struct + parser**

Add near the other pure helpers in persist.rs (e.g. after `extract_binary_path_candidates`):

```rust
/// One `<Exec>` action parsed from a Scheduled Task XML definition.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ParsedExecAction {
    pub command: String,
    pub arguments: String,
    /// The task's <URI> (\Folder\TaskName), shared by all actions in the task.
    pub uri: Option<String>,
}

/// Parse a Scheduled Task XML string into one `ParsedExecAction` per `<Exec>` action.
/// PURE: no FS, no env, never panics. Returns empty on malformed XML, missing <Actions>,
/// or a task whose only actions are non-Exec (ComHandler/SendEmail/ShowMessage).
/// Element matching is namespace-agnostic (uses local names), so the task xmlns is irrelevant.
#[allow(dead_code)]
pub(crate) fn parse_task_xml(xml: &str) -> Vec<ParsedExecAction> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    let mut uri: Option<String> = None;
    let mut out: Vec<ParsedExecAction> = Vec::new();

    // State: which leaf element's text we are currently capturing, and whether we are inside
    // an <Exec> (so <Command>/<Arguments> belong to an action, not some other element).
    let mut in_exec = false;
    let mut cur_command = String::new();
    let mut cur_arguments = String::new();
    let mut capture: Option<&'static str> = None; // "uri" | "command" | "arguments"

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"Exec" => {
                        in_exec = true;
                        cur_command.clear();
                        cur_arguments.clear();
                    }
                    b"URI" => capture = Some("uri"),
                    b"Command" if in_exec => capture = Some("command"),
                    b"Arguments" if in_exec => capture = Some("arguments"),
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(which) = capture {
                    // unescape() decodes &amp; etc.; on error keep nothing (defensive).
                    let text = e.unescape().map(|c| c.into_owned()).unwrap_or_default();
                    match which {
                        "uri" => uri = Some(text.trim().to_string()),
                        "command" => cur_command = text.trim().to_string(),
                        "arguments" => cur_arguments = text.trim().to_string(),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"URI" | b"Command" | b"Arguments" => capture = None,
                    b"Exec" => {
                        if !cur_command.is_empty() {
                            out.push(ParsedExecAction {
                                command: cur_command.clone(),
                                arguments: cur_arguments.clone(),
                                uri: uri.clone(),
                            });
                        }
                        in_exec = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            // Malformed XML: stop and return whatever was collected so far (never panic).
            Err(_) => break,
            _ => {}
        }
    }

    // <URI> may appear AFTER the actions in some tasks; backfill any action that missed it.
    if uri.is_some() {
        for a in &mut out {
            if a.uri.is_none() {
                a.uri = uri.clone();
            }
        }
    }
    out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-collectors --lib persist::tests::parse_task_xml`
Expected: PASS (4 tests).

> Note: `<URI>` precedes `<Actions>` in the verified real XML, so `uri` is set before any Exec
> closes — the backfill loop is a defensive fallback for ordering variance, not the main path.

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --package cairn-collectors --all-targets -- -D warnings
cargo fmt
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2i): pure parse_task_xml (quick-xml, one action per Exec)"
```

---

## Task 3: Pure glue `task_records_from_xml` (records + binary_path)

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
    #[test]
    fn task_records_resolves_binary_path_via_candidates() {
        // exists set: the expanded sc.exe path is present on "disk".
        let exists = |p: &str| p.eq_ignore_ascii_case(r"C:\Windows\system32\sc.exe");
        let env = fake_env(&[("windir", r"C:\Windows")]);
        let recs = task_records_from_xml(SAMPLE_TASK_XML, "SynchronizeTime", None, &env, &exists);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.mechanism, "scheduled_task");
        assert_eq!(
            r.location.as_str(),
            r"\Microsoft\Windows\Time Synchronization\SynchronizeTime"
        );
        assert_eq!(r.binary_path.as_deref(), Some(r"C:\Windows\system32\sc.exe"));
        // command keeps the args verbatim
        assert!(r.command.as_deref().unwrap().contains("start w32time"));
    }

    #[test]
    fn task_records_fallback_when_nothing_exists() {
        let exists = |_: &str| false;
        let env = fake_env(&[("windir", r"C:\Windows")]);
        let recs = task_records_from_xml(SAMPLE_TASK_XML, "SynchronizeTime", None, &env, &exists);
        assert_eq!(recs.len(), 1);
        // S2-F fallback: bare first token (expanded) when no candidate exists.
        assert_eq!(
            recs[0].binary_path.as_deref(),
            Some(r"C:\Windows\system32\sc.exe")
        );
    }

    #[test]
    fn task_records_empty_for_non_exec() {
        let exists = |_: &str| false;
        let env = fake_env(&[]);
        let com = r#"<Task xmlns="x"><Actions><ComHandler><ClassId>{G}</ClassId></ComHandler></Actions></Task>"#;
        assert!(task_records_from_xml(com, "X", None, &env, &exists).is_empty());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-collectors --lib persist::tests::task_records`
Expected: FAIL — `task_records_from_xml` not found.

- [ ] **Step 3: Implement the glue**

Add after `parse_task_xml`:

```rust
/// PURE glue: parse a task XML and build one PersistenceRecord per Exec action, resolving
/// binary_path via the S2-F candidate model. `lookup` (env) and `exists` (FS probe) are
/// injected for Linux-CI testability. `file_name` is the task file stem (the `value` fallback
/// when no <URI> leaf name is available); `last_write` is the file mtime. Never panics.
#[allow(dead_code)]
fn task_records_from_xml(
    xml: &str,
    file_name: &str,
    last_write: Option<DateTime<Utc>>,
    lookup: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Vec<PersistenceRecord> {
    let mut out = Vec::new();
    for act in parse_task_xml(xml) {
        let command = if act.arguments.is_empty() {
            act.command.clone()
        } else {
            format!("{} {}", act.command, act.arguments)
        };
        let candidates = extract_binary_path_candidates(&command, &lookup);
        let binary_path = pick_binary_path(&candidates, &exists);

        let location = act
            .uri
            .clone()
            .unwrap_or_else(|| file_name.to_string());
        // value = last URI segment (the task name), else the file stem.
        let value = act
            .uri
            .as_deref()
            .and_then(|u| u.rsplit(['\\', '/']).next())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| file_name.to_string());

        out.push(PersistenceRecord {
            mechanism: "scheduled_task".to_string(),
            location,
            value: Some(value),
            command: Some(command),
            binary_path,
            binary_sha256: None,
            signed: None,
            last_write,
        });
    }
    out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-collectors --lib persist::tests::task_records`
Expected: PASS (3 tests).

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --package cairn-collectors --all-targets -- -D warnings
cargo fmt
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2i): task_records_from_xml glue (records + candidate binary_path)"
```

---

## Task 4: `read_scheduled_tasks` FS walk + wire into collect()

**Files:**
- Modify: `crates/cairn-collectors/src/persist.rs`

- [ ] **Step 1: Add the cfg stubs + the windows reader**

Near the other `cfg(not(windows))` stubs (around the `read_run_keys` stub group), add:

```rust
#[cfg(not(windows))]
fn read_scheduled_tasks() -> Vec<PersistenceRecord> {
    Vec::new()
}
```

In the `#[cfg(windows)] mod win` block, add a reader (it walks the Task store and calls the
pure glue with the real env + `Path::exists`):

```rust
    /// Walk %SystemRoot%\System32\Tasks recursively; parse each task XML into records.
    /// Best-effort + graceful: an ACL-blocked root (non-admin) or unreadable file yields
    /// nothing rather than an error. Read-only.
    pub fn read_scheduled_tasks() -> Vec<super::PersistenceRecord> {
        let root = std::env::var("SystemRoot")
            .map(|r| format!(r"{r}\System32\Tasks"))
            .unwrap_or_else(|_| r"C:\Windows\System32\Tasks".to_string());
        let mut out = Vec::new();
        walk_tasks(std::path::Path::new(&root), &mut out);
        out
    }

    fn walk_tasks(dir: &std::path::Path, out: &mut Vec<super::PersistenceRecord>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return; // ACL-blocked or missing: graceful empty
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_tasks(&path, out);
            } else if path.is_file() {
                let Ok(xml) = std::fs::read_to_string(&path) else {
                    continue; // unreadable file: skip
                };
                let file_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let last_write = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(chrono::DateTime::<chrono::Utc>::from);
                out.extend(super::task_records_from_xml(
                    &xml,
                    &file_name,
                    last_write,
                    |name| std::env::var(name).ok(),
                    |p| std::path::Path::new(p).exists(),
                ));
            }
        }
    }
```

Add the windows delegator near the other delegators (next to `read_services` etc.):

```rust
#[cfg(windows)]
fn read_scheduled_tasks() -> Vec<PersistenceRecord> {
    win::read_scheduled_tasks()
}
```

> If `std::fs::read_to_string` rejects the UTF-16 task files at runtime (the XML declares
> `encoding="UTF-16"` but the on-disk bytes are typically UTF-8 in System32\Tasks), the e2e in
> Task 5 will surface it; if so, switch to `std::fs::read(&path)` + a lossy UTF-8/UTF-16 decode
> helper. Verified samples came back as readable text; keep `read_to_string` unless the e2e
> shows empty/garbled commands.

- [ ] **Step 2: Wire into collect()**

In `PersistCollector::collect`, after `records.extend(read_startup_folders());` add:
```rust
        records.extend(read_scheduled_tasks());
```

- [ ] **Step 3: Compile + run all persist tests**

Run: `cargo check --package cairn-collectors` then
`cargo test --package cairn-collectors --lib persist`
Expected: PASS (the pure tests; the FS walk is windows-gated and not unit-tested here — Task 5
exercises it live).

- [ ] **Step 4: clippy (Linux-dead-code check) + fmt + commit**

```bash
cargo clippy --package cairn-collectors --all-targets -- -D warnings
cargo fmt
git add crates/cairn-collectors/src/persist.rs
git commit -m "feat(s2i): read_scheduled_tasks FS walk + wire into collect()"
```

---

## Task 5: Heuristic mechanism arm + acceptance gate + live e2e

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: Write the failing heuristic tests**

Add to `cairn-heur/src/persist.rs` `mod tests`:

```rust
    /// A scheduled_task in a normal path, signed, old: base 20 only (Low band, like service).
    #[test]
    fn scheduled_task_normal_path_is_low() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "scheduled_task",
            Some(r"C:\Windows\System32\sc.exe"),
            Some(old),
            Some(true),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 20, "scheduled_task base only");
        assert!(s.reasons.iter().any(|r| r.contains("scheduled task")));
        assert!(s.mitre.contains(&"T1053.005".to_string()));
    }

    /// An unsigned scheduled_task in Temp: base 20 + path 30 + unsigned 20 = High (fail-loud).
    #[test]
    fn scheduled_task_unsigned_in_temp_is_high() {
        let now = Utc::now();
        let old = now - Duration::days(400);
        let p = rec_signed(
            "scheduled_task",
            Some(r"C:\Users\x\AppData\Local\Temp\evil.exe"),
            Some(old),
            Some(false),
        );
        let s = score_persistence(&p, now);
        assert_eq!(s.weight, 70, "task 20 + path 30 + unsigned 20");
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --package cairn-heur --lib persist::tests::scheduled_task`
Expected: FAIL — `scheduled_task` currently hits the `_ => {}` arm (weight 0 for the base), so
the assertions on 20/70 and the "scheduled task" reason fail.

- [ ] **Step 3: Add the mechanism arm**

In `cairn-heur/src/persist.rs` `score_persistence`, in the mechanism `match`, add (after the
`service` arm):

```rust
        "scheduled_task" => s.add(20, "scheduled task persistence", &["T1053.005"]),
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-heur --lib persist`
Expected: PASS (the 2 new tests + all existing persist heuristic tests).

- [ ] **Step 5: Full static gate**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
grep -rn "unsafe" crates/cairn-collectors/src/ crates/cairn-heur/src/   # expect none
```
Expected: fmt clean; clippy clean; all tests pass; audit 0; zero unsafe in those crates.
If `fmt --check` fails, run `cargo fmt` and fold into the gate commit.

- [ ] **Step 6: Build release + live e2e (persist)**

```bash
cargo build --package cairn-cli --release
"$CARGO_TARGET_DIR/release/cairn.exe" run --target live --only persist --output C:/Temp/cairn-s2i-test
```
(`CARGO_TARGET_DIR` = `C:/Users/bosen/AppData/Local/cairn-target`.)

- [ ] **Step 7: Verify scheduled_task records (or graceful empty) + no regression**

```python
import json
from collections import Counter
recs=[json.loads(l) for l in open(r"C:/Temp/cairn-s2i-test/records.jsonl",encoding="utf-8") if l.strip()]
p=[r for r in recs if r.get("kind")=="persistence"]
mech=Counter(r.get("mechanism") for r in p)
print("mechanisms:", dict(mech))
st=[r for r in p if r.get("mechanism")=="scheduled_task"]
print("scheduled_task records:", len(st))
for r in st[:8]:
    print(" ", r.get("value"), "|", (r.get("binary_path") or "")[:60], "| signed=", r.get("signed"))
```
Expected (NON-admin, the usual case): `scheduled_task` count may be **0** (ACL-blocked Tasks
store) — that is the verified graceful-degrade path, NOT a failure; the other 5 mechanisms must
be unchanged and present. Expected (ADMIN): scheduled_task records present with resolved
binary_path and signed values; commands like `%windir%\...\sc.exe` resolved to real paths.

> **If non-admin and 0 tasks:** correct (ACL). To positively exercise the parser on this host,
> note it in the e2e report and rely on the unit tests (which cover parsing/record-building on
> synthetic XML). Do NOT loosen ACLs or elevate to force data.
> **If admin and commands look empty/garbled:** the UTF-16 read issue (Task 4 note) — switch
> `read_to_string` to a bytes-read + decode and re-run.

- [ ] **Step 8: Verify run integrity**

Run: `"$CARGO_TARGET_DIR/release/cairn.exe" verify C:/Temp/cairn-s2i-test/manifest.json`
Expected: `VERIFY OK`, exit 0.

- [ ] **Step 9: Commit heuristic + any gate fix-ups**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(s2i): scheduled_task heuristic mechanism arm (weight 20, T1053.005)"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- quick-xml dep (no-default-features) → Task 1. ✅
- Pure `parse_task_xml`, one action per `<Exec>`, non-Exec skipped, entity decode, malformed→empty → Task 2. ✅
- Pure record glue reusing the candidate model, mechanism="scheduled_task", URI→location/value → Task 3. ✅
- `cfg(windows)` FS walk + graceful degrade (ACL→empty, unreadable→skip) + collect() wiring + non-windows stub → Task 4. ✅
- Heuristic arm weight 20 (service band) + T1053.005 → Task 5. ✅
- Acceptance gate, unsafe isolation, live e2e (admin vs non-admin graceful), verify → Task 5. ✅
- No schema change, no TaskCache/COM/non-Exec/trigger scoring → respected (none added). ✅

**Placeholder scan:** no TBD/TODO; every code step is complete; the two runtime risks (UTF-16
read, non-admin empty) have concrete branch instructions, not vague "handle it".

**Type consistency:** `ParsedExecAction { command: String, arguments: String, uri: Option<String> }`,
`parse_task_xml(&str) -> Vec<ParsedExecAction>`, `task_records_from_xml(xml, file_name,
last_write, lookup, exists)`, `read_scheduled_tasks() -> Vec<PersistenceRecord>` are used
consistently across tasks. The glue reuses the existing `extract_binary_path_candidates` +
`pick_binary_path` (S2-F) and the `fake_env` test helper (already in persist.rs tests). The
heuristic arm string `"scheduled_task"` matches the record's `mechanism`.
