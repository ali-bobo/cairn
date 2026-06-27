# S2-K Binary Hashing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compute the sha256 of binaries behind findings and fill `binary_sha256` so each suspicious record carries an IOC hash an analyst can pivot on.

**Architecture:** A pure streaming hasher (`hash_file_capped`, fixed 64 KiB buffer + 256 MiB cap, injected `open`) in `cairn-collectors`; `ProcessRecord` gains `binary_sha256`; a CLI enrichment step (after `run_live`, before output) hashes the `binary_path` of records that produced a finding — matched by a stable key (registry key+value / startup path / pid), not fragile path comparison. No unsafe; constant memory; size-capped (NFR10's first touch).

**Tech Stack:** Rust; `sha2` (already a workspace dep — add to cairn-collectors); `std::fs` streaming. `cairn-collectors` + cli stay unsafe-free.

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-s2k-binary-hashing-design.md`

---

## Background the engineer needs

`RunOutcome { records: Vec<Record>, findings: Vec<Finding>, hostname, ... }` is returned by
`run_live`. In the CLI `run` arm (crates/cairn-cli/src/main.rs ~line 489-495), after `run_live`,
the code stamps host onto findings and calls `sort_findings(&mut outcome.findings)`. Enrichment
slots in right AFTER `sort_findings` and BEFORE the manifest build (~line 507): both
`&mut outcome.records` and `&outcome.findings` are in scope.

`Record` is an enum: `Process(ProcessRecord)`, `Persistence(PersistenceRecord)`, etc.
`PersistenceRecord { mechanism, location, value: Option<String>, ..., binary_path, binary_sha256:
Option<String>, ... }`. `ProcessRecord { pid, ..., image, signed, signer, ... }` — NO
binary_sha256 yet (Task 1 adds it). Process records use `image` as the path.

`Finding { ..., entity: Entity, ... }`. `Entity { process: Option<EntityProcess>, file:
Option<EntityFile>, registry: Option<EntityRegistry>, netconn: ... }`.
`EntityRegistry { hive, key, value, data, last_write }` — `key` == persistence record.location,
`value` == record.value. `EntityFile { path, sha256, ... }` — startup findings; path == record's
binary_path/value. `EntityProcess { pid, ppid, image, ... }` — pid == process record.pid.

The persist heuristic builds the entity from the record (`persistence_entity`): registry-backed
mechanisms → `entity.registry` with key=location, value=record.value; the `startup` mechanism →
`entity.file` with path=binary_path-or-value. So the stable keys are reliable.

Existing digest reference: `cairn_report::sha256_hex(&[u8])` reads whole bytes — do NOT use it
for binaries (it loads the whole file). The new streaming hasher is separate.

---

## File Structure

- **Create:** `crates/cairn-collectors/src/hash.rs` — `hash_file_capped` + `DEFAULT_MAX_HASH_BYTES` + tests.
- **Modify:** `crates/cairn-collectors/src/lib.rs` — `pub mod hash;`
- **Modify:** `crates/cairn-collectors/Cargo.toml` — `sha2.workspace = true`.
- **Modify:** `crates/cairn-core/src/record.rs` — `ProcessRecord.binary_sha256` + literal fixes + round-trip test.
- **Modify:** `crates/cairn-cli/src/main.rs` — `enrich_hashes` helper + call in run arm + tests.

---

## Task 1: ProcessRecord gains binary_sha256

**Files:**
- Modify: `crates/cairn-core/src/record.rs`

- [ ] **Step 1: Write the failing round-trip test**

In `crates/cairn-core/src/record.rs` tests:
```rust
    #[test]
    fn process_record_binary_sha256_roundtrips() {
        let r = ProcessRecord {
            pid: 1, ppid: 0, image: "C:\\a.exe".into(), cmdline: "C:\\a.exe".into(),
            signed: Some(true), signer: Some("V".into()),
            binary_sha256: Some("ba7816bf".into()),
            integrity: None, user: None, start_time: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: ProcessRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.binary_sha256.as_deref(), Some("ba7816bf"));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --package cairn-core --lib process_record_binary_sha256`
Expected: FAIL — `ProcessRecord` has no field `binary_sha256` (compile error).

- [ ] **Step 3: Add the field**

In `ProcessRecord`, add after `signer`:
```rust
    pub signed: Option<bool>,
    pub signer: Option<String>,
    pub binary_sha256: Option<String>,
```

- [ ] **Step 4: Fix all ProcessRecord literals**

Run `cargo check --workspace --all-targets`; add `binary_sha256: None` to each reported
ProcessRecord literal (cairn-collectors proc.rs build_process_records + its test mk, orchestrator
test, cairn-heur netconn/parentchild test helpers, the new round-trip test already has it). Place
it after the `signer` field in each.

- [ ] **Step 5: Run to verify pass + compile**

Run: `cargo test --package cairn-core --lib process_record_binary_sha256` then `cargo check --workspace --all-targets`
Expected: round-trip PASS; workspace compiles.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(s2k): add binary_sha256 to ProcessRecord"
```

---

## Task 2: Pure streaming hasher `hash_file_capped`

**Files:**
- Create: `crates/cairn-collectors/src/hash.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`, `crates/cairn-collectors/Cargo.toml`

- [ ] **Step 1: Add sha2 dep + module**

`crates/cairn-collectors/Cargo.toml` `[dependencies]`: add `sha2.workspace = true`.
`crates/cairn-collectors/src/lib.rs`: add `pub mod hash;` (near the other `pub mod`s).

- [ ] **Step 2: Write the failing tests**

Create `crates/cairn-collectors/src/hash.rs` with tests first:
```rust
//! Streaming, size-capped sha256 of a file (FR14 IOC hashing). PURE: the file open+length probe
//! is injected, so this is Linux-CI-testable and unsafe-free. Constant memory (one fixed
//! buffer); a file over the cap is skipped (None) so a pathological huge file cannot stall
//! triage — the first concrete NFR10 resource-governance guard (raw-NTFS will reuse the shape).
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::io::Read;

/// Default size cap: 256 MiB. Files larger than this are skipped (binary_sha256 stays None).
pub const DEFAULT_MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

const CHUNK: usize = 64 * 1024;

/// Stream-hash `path` to a lowercase sha256 hex string, or None if it cannot be opened, exceeds
/// `max_bytes`, or errors mid-read. `open(path) -> Option<(len, reader)>` returns the file length
/// AND a streaming reader (Windows: fs metadata().len() + File; tests: an in-memory (len, Cursor)).
/// Never panics.
pub fn hash_file_capped<R: Read>(
    path: &str,
    max_bytes: u64,
    open: impl Fn(&str) -> Option<(u64, R)>,
) -> Option<String> {
    let (len, mut reader) = open(path)?;
    if len > max_bytes {
        return None; // skip: don't stream a huge file
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None, // mid-read error: defensive, no panic
        }
    }
    let digest = hasher.finalize();
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mem(bytes: &'static [u8]) -> impl Fn(&str) -> Option<(u64, Cursor<&'static [u8]>)> {
        move |_p: &str| Some((bytes.len() as u64, Cursor::new(bytes)))
    }

    #[test]
    fn hashes_known_vectors() {
        // sha256("") and sha256("abc") — locked well-known vectors.
        assert_eq!(
            hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, mem(b"")).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, mem(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn multi_chunk_matches_one_shot() {
        // input larger than CHUNK must hash the same as a one-shot hash of identical bytes.
        let big: &'static [u8] = Box::leak(vec![0xABu8; CHUNK * 3 + 123].into_boxed_slice());
        let got = hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, mem(big)).unwrap();
        let mut h = Sha256::new();
        h.update(big);
        let want: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn over_cap_is_skipped() {
        // len reported over the cap -> None, without reading.
        let open = |_p: &str| Some((10u64, Cursor::new(&b"0123456789"[..])));
        assert_eq!(hash_file_capped("x", 9, open), None);
        // exactly at the cap -> hashed.
        assert!(hash_file_capped("x", 10, open).is_some());
    }

    #[test]
    fn open_failure_is_none() {
        let open = |_p: &str| -> Option<(u64, Cursor<&[u8]>)> { None };
        assert_eq!(hash_file_capped("x", DEFAULT_MAX_HASH_BYTES, open), None);
    }
}
```

- [ ] **Step 3: Run to verify fail then pass**

Run: `cargo test --package cairn-collectors --lib hash`
Expected: after writing the impl above (it's in the same file), the 4 tests PASS. (If you wrote
tests first then impl, the red step is the missing `hash_file_capped`.)

- [ ] **Step 4: clippy + fmt + commit**

```bash
cargo clippy --package cairn-collectors --all-targets -- -D warnings
cargo fmt
git add crates/cairn-collectors/src/hash.rs crates/cairn-collectors/src/lib.rs crates/cairn-collectors/Cargo.toml Cargo.lock
git commit -m "feat(s2k): pure streaming hash_file_capped (fixed buffer + size cap)"
```

---

## Task 3: CLI enrich_hashes + wire into run arm + e2e

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: Write the failing enrichment test**

Add to `crates/cairn-cli/src/main.rs` tests:
```rust
    #[test]
    fn enrich_hashes_fills_only_find_producing_records() {
        use cairn_core::record::{PersistenceRecord, ProcessRecord, Record};
        use cairn_core::{Entity, Finding, FindingSource, Severity};
        use cairn_core::finding::EntityRegistry;

        // Two persistence records; only the first has a matching finding.
        let mut records = vec![
            Record::Persistence(PersistenceRecord {
                mechanism: "run_key".into(),
                location: "HKCU\\Run".into(),
                value: Some("Evil".into()),
                command: Some("C:\\evil.exe".into()),
                binary_path: Some("C:\\evil.exe".into()),
                binary_sha256: None,
                signed: None,
                signer: None,
                last_write: None,
            }),
            Record::Persistence(PersistenceRecord {
                mechanism: "run_key".into(),
                location: "HKCU\\Run".into(),
                value: Some("Benign".into()),
                command: Some("C:\\benign.exe".into()),
                binary_path: Some("C:\\benign.exe".into()),
                binary_sha256: None,
                signed: None,
                signer: None,
                last_write: None,
            }),
        ];
        // A finding whose registry (key,value) matches record[0].
        let mut f = Finding::new(Severity::High, "Suspicious persistence: run_key", FindingSource::Heuristic);
        f.entity = Entity {
            registry: Some(EntityRegistry {
                hive: "HKCU".into(),
                key: "HKCU\\Run".into(),
                value: "Evil".into(),
                data: "C:\\evil.exe".into(),
                last_write: None,
            }),
            ..Entity::default()
        };
        let findings = vec![f];

        // Injected hash_fn: returns a fixed hash for any path (we assert which records get it).
        let hash_fn = |p: &str| Some(format!("hash-of-{p}"));
        enrich_hashes(&mut records, &findings, hash_fn);

        let Record::Persistence(p0) = &records[0] else { panic!() };
        let Record::Persistence(p1) = &records[1] else { panic!() };
        assert_eq!(p0.binary_sha256.as_deref(), Some("hash-of-C:\\evil.exe"));
        assert_eq!(p1.binary_sha256, None, "benign record (no finding) not hashed");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --package cairn-cli enrich_hashes`
Expected: FAIL — `enrich_hashes` not found.

- [ ] **Step 3: Implement enrich_hashes**

Add to `crates/cairn-cli/src/main.rs` (near the other helpers like `sort_findings`):
```rust
/// Fill `binary_sha256` on the records that produced a finding, using an injected hasher.
/// Records are matched to findings by a STABLE KEY (not fragile path comparison):
///   - registry-backed persistence finding -> (entity.registry.key, entity.registry.value)
///     matches PersistenceRecord (location, value)
///   - startup file finding -> entity.file.path matches PersistenceRecord binary_path/value
///   - process finding -> entity.process.pid matches ProcessRecord pid
/// Only matched records with a binary_path/image are hashed. findings count is small (triage),
/// so the linear scans are cheap.
fn enrich_hashes(
    records: &mut [cairn_core::record::Record],
    findings: &[cairn_core::Finding],
    hash_fn: impl Fn(&str) -> Option<String>,
) {
    use cairn_core::record::Record;
    use std::collections::HashSet;

    // Build the stable-key sets from findings.
    let mut reg_keys: HashSet<(String, String)> = HashSet::new();
    let mut file_paths: HashSet<String> = HashSet::new();
    let mut pids: HashSet<u32> = HashSet::new();
    for f in findings {
        if let Some(r) = &f.entity.registry {
            reg_keys.insert((r.key.clone(), r.value.clone()));
        }
        if let Some(fi) = &f.entity.file {
            file_paths.insert(fi.path.clone());
        }
        if let Some(p) = &f.entity.process {
            pids.insert(p.pid);
        }
    }

    for rec in records.iter_mut() {
        match rec {
            Record::Persistence(p) => {
                let value = p.value.clone().unwrap_or_default();
                let matched = reg_keys.contains(&(p.location.clone(), value))
                    || p.binary_path.as_deref().is_some_and(|bp| file_paths.contains(bp));
                if matched {
                    if let Some(bp) = p.binary_path.as_deref() {
                        p.binary_sha256 = hash_fn(bp);
                    }
                }
            }
            Record::Process(p) => {
                if pids.contains(&p.pid) {
                    // process image: only hash an absolute path (mirror signed/signer guard).
                    if is_absolute_image(&p.image) {
                        p.binary_sha256 = hash_fn(&p.image);
                    }
                }
            }
            _ => {}
        }
    }
}

/// True if a process image looks like a Windows absolute path (drive or UNC). A bare file name
/// (OpenProcess-failed fallback) is not hashed. (Mirrors cairn_collectors::proc::is_absolute_path;
/// duplicated here to avoid a cross-crate pub dependency for one predicate.)
fn is_absolute_image(image: &str) -> bool {
    let b = image.as_bytes();
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    drive || image.starts_with(r"\\")
}
```

> If `cairn_collectors::proc::is_absolute_path` is already `pub`, prefer importing it over the
> local copy. Check with `grep -n "pub fn is_absolute_path" crates/cairn-collectors/src/proc.rs`;
> if public, replace `is_absolute_image` with that import and delete the local copy.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --package cairn-cli enrich_hashes`
Expected: PASS.

- [ ] **Step 5: Wire into the run arm**

In `crates/cairn-cli/src/main.rs` `run` arm, right after `sort_findings(&mut outcome.findings);`
(~line 495) and before the `Summary::from_findings` / manifest build, add:
```rust
            // FR14: hash the binaries behind findings (streaming, size-capped) and fill
            // binary_sha256 so each suspicious record carries an IOC hash.
            enrich_hashes(&mut outcome.records, &outcome.findings, |path| {
                cairn_collectors::hash::hash_file_capped(
                    path,
                    cairn_collectors::hash::DEFAULT_MAX_HASH_BYTES,
                    |p| {
                        let len = std::fs::metadata(p).ok()?.len();
                        let file = std::fs::File::open(p).ok()?;
                        Some((len, file))
                    },
                )
            });
```
(`std::fs::File` implements `Read`, so it fits `hash_file_capped`'s `R: Read`. This runs for
`--dry-run` too — it only mutates in-memory records; nothing is written, consistent with golden
rule 4.)

- [ ] **Step 6: Full static gate**

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
grep -rn "unsafe" crates/cairn-collectors/src/ crates/cairn-core/src/ crates/cairn-cli/src/   # expect none
```
Expected: fmt clean; clippy clean; all tests pass; audit 0 (sha2 already in workspace); zero unsafe in those crates. `cargo fmt` if --check fails.

- [ ] **Step 7: Build release + live e2e**

```bash
cargo build --package cairn-cli --release
"$CARGO_TARGET_DIR/release/cairn.exe" run --target live --only persist,process --output C:/Temp/cairn-s2k-test
```
(`CARGO_TARGET_DIR` = `C:/Users/bosen/AppData/Local/cairn-target`.)

- [ ] **Step 8: Verify binary_sha256 filled for find-producing records, None otherwise**

```python
import json
recs=[json.loads(l) for l in open(r"C:/Temp/cairn-s2k-test/records.jsonl",encoding="utf-8") if l.strip()]
finds=[json.loads(l) for l in open(r"C:/Temp/cairn-s2k-test/findings.jsonl",encoding="utf-8") if l.strip()]
hashed=[r for r in recs if r.get("binary_sha256")]
print("records:", len(recs), "findings:", len(finds), "records with sha256:", len(hashed))
for r in hashed[:10]:
    h=r.get("binary_sha256")
    print(f"  {len(h)}-char {h[:16]}...  {(r.get('binary_path') or r.get('image') or '')[:50]}")
# sanity: a non-finding record should be None
nonh=[r for r in recs if not r.get("binary_sha256")]
print("records without sha256 (no finding / over-cap / unreadable):", len(nonh))
```
Expected: `records with sha256` ≈ the count of distinct find-producing binaries (NOT all records);
each hash is 64 hex chars; the vast majority of records (no finding) stay None. Spot-check one hash:
`python -c "import hashlib;print(hashlib.sha256(open(r'<path>','rb').read()).hexdigest())"` should
match the record's binary_sha256.

> **If 0 records hashed but there ARE findings:** the stable-key match failed — print a finding's
> `entity` and the candidate record's `(location,value)`/`pid` and confirm the key shapes line up
> (the persist heuristic sets entity.registry.key=location, value=record.value). Fix the match,
> don't loosen to path comparison.

- [ ] **Step 9: Verify run integrity**

Run: `"$CARGO_TARGET_DIR/release/cairn.exe" verify C:/Temp/cairn-s2k-test/manifest.json`
Expected: `VERIFY OK`, exit 0.

- [ ] **Step 10: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(s2k): enrich_hashes fills binary_sha256 for find-producing records"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Pure streaming hasher (fixed buffer + cap + injected open) → Task 2. ✅
- ProcessRecord.binary_sha256 → Task 1. ✅
- Only find-producing records hashed, stable-key match (registry key+value / startup path / pid) → Task 3. ✅
- CLI enrichment post-analysis (orchestrator pure), runs for dry-run in-memory only → Task 3 Step 5. ✅
- NFR10 streaming + 256 MiB cap → Task 2 (DEFAULT_MAX_HASH_BYTES, CHUNK loop). ✅
- No unsafe / no new dep (sha2 in workspace) → Task 2 Step 1 + Task 3 Step 6. ✅
- e2e (find-producing hashed, others None, spot-check, verify) → Task 3. ✅

**Placeholder scan:** no TBD/TODO; the hasher impl, the enrichment match logic, and the run-arm
wiring are all complete code; the e2e has a concrete fix path for a key-mismatch, not "handle it".

**Type consistency:** `hash_file_capped(path, max_bytes, open: Fn(&str)->Option<(u64,R)>) ->
Option<String>` and `enrich_hashes(records, findings, hash_fn: Fn(&str)->Option<String>)` are
used consistently. `binary_sha256: Option<String>` matches both records. The run-arm closure
adapts real `std::fs` (metadata len + File) to the injected `open`. `is_absolute_image` mirrors
the proc guard (or is replaced by the pub import if available).
