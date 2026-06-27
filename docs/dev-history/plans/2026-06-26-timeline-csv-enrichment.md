# Timeline CSV Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `Reason`, `Entity`, and `DetailsClient` columns to `timeline.csv` so analysts can see why a finding triggered, what entity is involved, and the plain zh-TW explanation — all without opening `findings.jsonl`.

**Architecture:** Single file change in `crates/cairn-report/src/lib.rs`. Expand the row array from `[String; 10]` to `[String; 13]`, add a private `entity_summary()` helper, update `TIMELINE_COLS`, `timeline_row()`, `manual_csv()`, and fix all tests that reference the old size. No schema changes to Finding/Manifest; no new dependencies.

**Tech Stack:** Rust, existing `csv` crate, `cairn_core::finding::Finding`.

**Build command (run after every task):**
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

---

## File Map

| File | Change |
|------|--------|
| `crates/cairn-report/src/lib.rs` | Expand row to 13 cols; add `entity_summary()`; update all tests |

---

## Task 1 — Expand timeline.csv to 13 columns

**Files:**
- Modify: `crates/cairn-report/src/lib.rs`

### Context

Current state (lines 39–74 of `crates/cairn-report/src/lib.rs`):

```rust
pub const TIMELINE_COLS: &[&str] = &[
    "Timestamp", "Host", "Channel", "EventID", "Severity",
    "RecordID", "RuleTitle", "RuleAuthor", "MITRE", "Details",
];

fn timeline_row(f: &Finding) -> [String; 10] { ... }

pub fn timeline_csv(findings: &[Finding]) -> String {
    let mut rows: Vec<[String; 10]> = ...
}

fn manual_csv(rows: &[[String; 10]]) -> String { ... }
```

Tests at lines ~371–427 assert on `TIMELINE_COLS.join(",")` and use `[String; 10]`.

### What to implement

**Step 1: Write failing tests**

- [ ] Add these tests inside the existing `#[cfg(test)]` block in `crates/cairn-report/src/lib.rs`, after the existing `timeline_csv_dedupes_identical_rows` test:

```rust
/// New columns Reason, Entity, DetailsClient appear in the header.
#[test]
fn timeline_csv_has_enriched_columns() {
    let csv = timeline_csv(&[finding(1_700_000_000, "Susp PS", 42)]);
    let header = csv.lines().next().unwrap();
    assert!(header.contains("Reason"), "Reason missing: {header}");
    assert!(header.contains("Entity"), "Entity missing: {header}");
    assert!(header.contains("DetailsClient"), "DetailsClient missing: {header}");
}

/// Reason column carries finding.reason content.
#[test]
fn timeline_csv_reason_column_populated() {
    let mut f = finding(1_700_000_000, "Test", 1);
    f.reason = "service autostart persistence; recently created".into();
    let csv = timeline_csv(&[f]);
    let row = csv.lines().nth(1).unwrap();
    assert!(
        row.contains("service autostart persistence"),
        "reason not in row: {row}"
    );
}

/// DetailsClient column carries finding.details_client content.
#[test]
fn timeline_csv_details_client_column_populated() {
    let mut f = finding(1_700_000_000, "Test", 1);
    f.details_client = Some("主機 WS01 上偵測到可疑活動".into());
    let csv = timeline_csv(&[f]);
    let row = csv.lines().nth(1).unwrap();
    assert!(
        row.contains("主機 WS01 上偵測到可疑活動"),
        "details_client not in row: {row}"
    );
}

/// Entity column: process entity → "pid=N image=<name>".
#[test]
fn timeline_csv_entity_process() {
    use cairn_core::finding::EntityProcess;
    let mut f = finding(1_700_000_000, "Test", 1);
    f.entity.process = Some(EntityProcess {
        pid: 1234,
        ppid: 4,
        image: r"C:\Windows\System32\cmd.exe".into(),
        cmdline: "cmd /c whoami".into(),
        signed: None,
        integrity: None,
    });
    let csv = timeline_csv(&[f]);
    let row = csv.lines().nth(1).unwrap();
    assert!(row.contains("1234"), "pid in entity: {row}");
    assert!(row.contains("cmd.exe"), "image name in entity: {row}");
}

/// Entity column: registry entity → "svc=<key_last> bin=<data_last>".
#[test]
fn timeline_csv_entity_registry() {
    use cairn_core::finding::EntityRegistry;
    let mut f = finding(1_700_000_000, "Test", 1);
    f.entity.registry = Some(EntityRegistry {
        hive: "HKLM".into(),
        key: r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc".into(),
        value: "EvilSvc".into(),
        data: r"C:\Temp\evil.exe".into(),
        last_write: None,
    });
    let csv = timeline_csv(&[f]);
    let row = csv.lines().nth(1).unwrap();
    assert!(row.contains("EvilSvc"), "registry key name in entity: {row}");
    assert!(row.contains("evil.exe"), "binary name in entity: {row}");
}

/// Entity column: netconn entity → "pid=N raddr:rport".
#[test]
fn timeline_csv_entity_netconn() {
    use cairn_core::finding::EntityNetConn;
    let mut f = finding(1_700_000_000, "Test", 1);
    f.entity.netconn = Some(EntityNetConn {
        laddr: "192.168.0.1".into(),
        lport: 50000,
        raddr: Some("185.0.0.1".into()),
        rport: Some(4444),
        pid: Some(999),
    });
    let csv = timeline_csv(&[f]);
    let row = csv.lines().nth(1).unwrap();
    assert!(row.contains("185.0.0.1"), "raddr in entity: {row}");
    assert!(row.contains("4444"), "rport in entity: {row}");
}

/// manual_csv fallback also has 13 columns and quotes correctly.
#[test]
fn manual_csv_fallback_has_13_cols() {
    let mut f = finding(100, "t", 1);
    f.rule_author = Some("Alice, Bob".into());
    f.reason = "test reason".into();
    let rows: Vec<[String; 13]> = std::iter::once(&f).map(timeline_row).collect();
    let csv = manual_csv(&rows);
    let header = csv.lines().next().unwrap();
    assert_eq!(
        header.split(',').count(),
        13,
        "must have 13 columns: {header}"
    );
    assert!(header.contains("DetailsClient"));
}
```

- [ ] **Step 2: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-report timeline_csv_has_enriched timeline_csv_reason timeline_csv_details_client timeline_csv_entity manual_csv_fallback_has_13 2>&1 | tail -20
```

Expected: compile errors or FAILED — new columns not yet defined.

- [ ] **Step 3: Implement the changes**

Replace the relevant sections of `crates/cairn-report/src/lib.rs`. The changes touch four locations:

**3a. TIMELINE_COLS (replace lines 39–50):**

```rust
/// Detection timeline columns. Hayabusa-compatible core (cols 0–9) + three enrichment
/// cols (Reason, Entity, DetailsClient) that make the CSV self-contained for analysts.
pub const TIMELINE_COLS: &[&str] = &[
    "Timestamp",
    "Host",
    "Channel",
    "EventID",
    "Severity",
    "RecordID",
    "RuleTitle",
    "RuleAuthor",
    "MITRE",
    "Details",
    "Reason",
    "Entity",
    "DetailsClient",
];
```

**3b. Add `entity_summary()` helper (insert before `timeline_row`):**

```rust
/// Compact one-line summary of the entity implicated in a Finding, for the Entity
/// column of timeline.csv. Precedence: process > registry > netconn > file > "".
fn entity_summary(f: &Finding) -> String {
    if let Some(p) = &f.entity.process {
        let name = p.image.rsplit(['\\', '/']).next().unwrap_or(&p.image);
        return format!("pid={} image={}", p.pid, name);
    }
    if let Some(r) = &f.entity.registry {
        let key_name = r.key.rsplit('\\').next().unwrap_or(&r.key);
        let bin = r.data.trim_matches('"');
        let bin_name = bin.rsplit(['\\', '/']).next().unwrap_or(bin);
        return format!("svc={} bin={}", key_name, bin_name);
    }
    if let Some(c) = &f.entity.netconn {
        let raddr = c.raddr.as_deref().unwrap_or("-");
        let rport = c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        let pid = c.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
        return format!("pid={} {}:{}", pid, raddr, rport);
    }
    if let Some(fi) = &f.entity.file {
        let name = fi.path.rsplit(['\\', '/']).next().unwrap_or(&fi.path);
        return name.to_owned();
    }
    String::new()
}
```

**3c. Replace `timeline_row` (lines 52–75):**

```rust
/// Project a Finding into the TIMELINE_COLS row (detection timeline, SRS §5.2).
fn timeline_row(f: &Finding) -> [String; 13] {
    let channel = f
        .artifact
        .strip_prefix("evtx:")
        .unwrap_or(&f.artifact)
        .to_string();
    let severity = serde_json::to_value(f.severity)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "info".into());
    [
        f.ts.to_rfc3339(),
        f.host.clone(),
        channel,
        f.event_id.map(|e| e.to_string()).unwrap_or_default(),
        severity,
        f.evidence_ref.clone().unwrap_or_default(),
        f.title.clone(),
        f.rule_author.clone().unwrap_or_default(),
        f.mitre.join(";"),
        f.details.clone(),
        f.reason.clone(),
        entity_summary(f),
        f.details_client.clone().unwrap_or_default(),
    ]
}
```

**3d. Replace `timeline_csv` and `manual_csv` (lines 86–128):**

```rust
/// Render the detection timeline as CSV: one row per rule hit, sorted by
/// (ts, record_id) for reproducibility (NFR4), with identical detections
/// de-duplicated (FR5 — the count is reflected in the Summary, not here).
///
/// Panic-free by contract: this is on a forensic tool's output path, so even the
/// theoretically-impossible CSV-buffer errors must not abort a run. On any internal
/// writer error we fall back to a hand-built CSV (the inputs are our own owned Strings,
/// which the manual path quotes safely), so the worst case is a slightly less optimal
/// quoting, never a panic.
pub fn timeline_csv(findings: &[Finding]) -> String {
    let mut rows: Vec<[String; 13]> = findings.iter().map(timeline_row).collect();
    // Deterministic order: Timestamp then RecordID (cols 0 and 5).
    rows.sort_by(|a, b| (&a[0], &a[5]).cmp(&(&b[0], &b[5])));
    rows.dedup(); // identical adjacent detections collapse (rows are sorted)

    let mut wtr = csv::Writer::from_writer(Vec::new());
    let via_csv = wtr
        .write_record(TIMELINE_COLS)
        .and_then(|()| {
            for r in &rows {
                wtr.write_record(r)?;
            }
            Ok(())
        })
        .ok()
        .and_then(|()| wtr.into_inner().ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());

    via_csv.unwrap_or_else(|| manual_csv(&rows))
}

/// RFC-4180 fallback used only if the `csv` writer ever errs (it shouldn't for our
/// owned-String inputs). Quotes a field when it contains `,`, `"`, CR or LF; doubles
/// embedded quotes. Keeps `timeline_csv` total (never panics).
fn manual_csv(rows: &[[String; 13]]) -> String {
    fn field(s: &str) -> std::borrow::Cow<'_, str> {
        if s.contains([',', '"', '\n', '\r']) {
            std::borrow::Cow::Owned(format!("\"{}\"", s.replace('"', "\"\"")))
        } else {
            std::borrow::Cow::Borrowed(s)
        }
    }
    let mut out = String::new();
    out.push_str(&TIMELINE_COLS.join(","));
    out.push_str("\r\n");
    for r in rows {
        let line: Vec<std::borrow::Cow<'_, str>> = r.iter().map(|c| field(c)).collect();
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    out
}
```

- [ ] **Step 4: Fix the existing `manual_csv_fallback_quotes_and_matches_header` test**

This test at line ~389 still uses `[String; 10]` — update it to `[String; 13]`:

```rust
#[test]
fn manual_csv_fallback_quotes_and_matches_header() {
    let mut f = finding(100, "t", 1);
    f.rule_author = Some("Alice, Bob".into());
    let rows: Vec<[String; 13]> = std::iter::once(&f).map(timeline_row).collect();
    let csv = manual_csv(&rows);

    let mut lines = csv.lines();
    assert_eq!(lines.next().unwrap(), TIMELINE_COLS.join(","));
    let row = lines.next().unwrap();
    assert!(
        row.contains("\"Alice, Bob\""),
        "comma field must be quoted: {row}"
    );
}
```

- [ ] **Step 5: Check for any other `[String; 10]` references and fix them**

```powershell
cd "c:\Users\bosen\OneDrive\Desktop\claude_dev\IIR_tool\cairn"
grep -rn "String; 10" crates/
```

Expected: zero results after fixing. If any remain, update them to `[String; 13]`.

- [ ] **Step 6: Run all tests**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test --workspace 2>&1 | tail -10
```

Expected: all pass. The new 7 tests pass; the 4 existing timeline tests still pass.

- [ ] **Step 7: Clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: zero warnings.

- [ ] **Step 8: Commit**

```powershell
git add crates/cairn-report/src/lib.rs
git commit -m "feat(report): enrich timeline.csv with Reason, Entity, DetailsClient columns

Analysts can now read why a finding triggered, which process/service/connection
is implicated, and the plain zh-TW explanation directly from timeline.csv
without cross-referencing findings.jsonl."
```

---

## Self-Review

**Spec coverage:**
- Reason column → `f.reason` in col 10 ✓
- Entity column → `entity_summary()` in col 11 ✓  
- DetailsClient column → `f.details_client` in col 12 ✓
- All three columns in header → `TIMELINE_COLS` updated to 13 items ✓
- manual_csv fallback → updated to `[String; 13]` ✓
- Existing tests fixed → `manual_csv_fallback_quotes_and_matches_header` updated ✓

**Placeholder scan:** None found.

**Type consistency:**
- `timeline_row` returns `[String; 13]` ✓
- `timeline_csv` uses `Vec<[String; 13]>` ✓
- `manual_csv` accepts `&[[String; 13]]` ✓
- New test `manual_csv_fallback_has_13_cols` also uses `[String; 13]` ✓
- `entity_summary` imports: `Finding` already in scope via the existing `use cairn_core::finding::Finding` import ✓
- New tests import `EntityProcess`, `EntityRegistry`, `EntityNetConn` from `cairn_core::finding` — check that these are pub in that module (they are, based on earlier reads) ✓
