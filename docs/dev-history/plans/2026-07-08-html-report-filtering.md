# HTML Report Filtering & Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add client-side filtering (severity/artifact/keyword) and a same-source-binary
aggregation panel to `report.html`, plus fix two ir-snapshot-panels leftovers
(`state_active` display, netconn panel title).

**Architecture:** All UI/filtering logic lives in `crates/cairn-report/src/html.rs` as
inline HTML/CSS/JS (zero external resources, works offline). One additive schema field
(`LogonSessionRecord.state_active: bool`, `#[serde(default)]`) is threaded through
`cairn-core` → `cairn-collectors` → `cairn-report`.

**Tech Stack:** Rust (serde, no new dependencies), vanilla JavaScript (no frameworks,
inline `<script>`), existing `esc()` HTML-escaping helper.

**Spec:** `docs/dev-history/specs/2026-07-08-html-report-filtering-design.md`

---

## Task 1: Add `state_active` to `LogonSessionRecord` (schema, additive)

**Files:**
- Modify: `crates/cairn-core/src/record.rs:131-137` (`LogonSessionRecord` struct)
- Test: `crates/cairn-core/src/record.rs` (add to existing `#[cfg(test)] mod tests`)

This is the one step that touches a type shared across three crates (`cairn-core`,
`cairn-collectors`, `cairn-report`), so run the full workspace test suite after this
task (not just `-p cairn-core`) to confirm no cross-crate breakage before continuing.

- [ ] **Step 1: Write the failing test for old-JSON backward compatibility**

Add this test inside the existing `#[cfg(test)] mod tests` block in
`crates/cairn-core/src/record.rs` (the module already exists — find it near the bottom
of the file, alongside other `Record` round-trip tests):

```rust
#[test]
fn logon_session_state_active_defaults_false_on_old_json_and_roundtrips() {
    // Old JSON written before this field existed has no "state_active" key.
    let old = r#"{"kind":"logon_session","user":"DOMAIN\\alice","logon_type":"Interactive","logon_time":null,"source":null,"session_id":1}"#;
    let rec: Record = serde_json::from_str(old).unwrap();
    match rec {
        Record::LogonSession(s) => assert_eq!(s.state_active, false),
        _ => panic!("expected LogonSession variant"),
    }

    // New records carry the field and round-trip it.
    let rec2 = Record::LogonSession(LogonSessionRecord {
        user: r"DOMAIN\bob".into(),
        logon_type: "RemoteInteractive".into(),
        logon_time: None,
        source: Some("10.0.0.5".into()),
        session_id: Some(2),
        state_active: true,
    });
    let json = serde_json::to_string(&rec2).unwrap();
    assert!(json.contains("\"state_active\":true"));
    let back: Record = serde_json::from_str(&json).unwrap();
    match back {
        Record::LogonSession(s) => assert_eq!(s.state_active, true),
        _ => panic!("expected LogonSession variant"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-core logon_session_state_active --lib`
Expected: FAIL with a compile error — `state_active` is not a field of
`LogonSessionRecord` (the existing struct literal at `record.rs:313-319` in the
`round-trips` test also won't compile until Step 3 adds the field, since the struct
literal above doesn't yet have a real definition to satisfy).

- [ ] **Step 3: Add the field to `LogonSessionRecord`**

In `crates/cairn-core/src/record.rs`, change lines 131-137 from:

```rust
pub struct LogonSessionRecord {
    pub user: String,       // domain\username
    pub logon_type: String, // Interactive|RemoteInteractive|Network|Service|...
    pub logon_time: Option<DateTime<Utc>>,
    pub source: Option<String>, // source host/IP for network/RDP sessions
    pub session_id: Option<u32>,
}
```

to:

```rust
pub struct LogonSessionRecord {
    pub user: String,       // domain\username
    pub logon_type: String, // Interactive|RemoteInteractive|Network|Service|...
    pub logon_time: Option<DateTime<Utc>>,
    pub source: Option<String>, // source host/IP for network/RDP sessions
    pub session_id: Option<u32>,
    /// Whether the WTS session is in the Active state (vs. Disconnected/Idle/etc).
    /// Additive field: old JSON without this key defaults to `false` (conservative —
    /// don't claim a session is active when we don't know).
    #[serde(default)]
    pub state_active: bool,
}
```

- [ ] **Step 4: Fix the existing struct literal in the round-trip test**

`crates/cairn-core/src/record.rs` around line 313-319 has an existing test
(`logon_session_...` — find it via the `LogonSessionRecord {` struct literal already
in the test module) that constructs a `LogonSessionRecord` without `state_active`. Add
the field to that existing literal:

```rust
let rec = Record::LogonSession(LogonSessionRecord {
    user: r"DOMAIN\alice".into(),
    logon_type: "RemoteInteractive".into(),
    logon_time: None,
    source: Some("10.0.0.5".into()),
    session_id: Some(2),
    state_active: true,
});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p cairn-core logon_session --lib`
Expected: PASS (both the new test and the pre-existing round-trip test).

- [ ] **Step 6: Run the full workspace test suite (cross-crate boundary check)**

Run: `cargo test --workspace --exclude cairn-updater`
Expected: PASS across all crates — `cairn-collectors` and `cairn-report` both
construct `LogonSessionRecord` literals and will fail to compile until Tasks 2 and 5
add the field there too. **If this fails at this point, that's expected — don't treat
it as a blocker for Task 1 itself, just confirm the failures are exactly the two
missing-field compile errors in `logon_session.rs` and `html.rs`'s test module, not
something else.** Task 2 fixes the first; Task 5 fixes the second.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-core/src/record.rs
git commit -m "feat(core): add LogonSessionRecord.state_active (additive schema field)"
```

---

## Task 2: Wire `state_active` through the collector

**Files:**
- Modify: `crates/cairn-collectors/src/logon_session.rs:19-34`

**Files:**
- Modify: `crates/cairn-collectors/src/logon_session.rs:19-34`
- Test: `crates/cairn-collectors/src/logon_session.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add this test to the existing `#[cfg(test)] mod tests` block in
`crates/cairn-collectors/src/logon_session.rs` (the module already has
`collector_name_is_logon_session` — add alongside it):

```rust
#[test]
fn maps_state_active_from_wts_session() {
    // This collector calls cairn_collectors_win::logon::enumerate_sessions() directly,
    // which we can't control in a unit test (it hits the live WTS API). Instead,
    // verify the mapping logic in isolation by testing the closure's behavior via
    // the public collect() path is not feasible without a real session. So this test
    // documents the expected field-for-field mapping by asserting the struct shape
    // compiles and the field exists (compile-time proof); the true behavioral proof
    // is the compile success of Step 3 plus the pre-existing
    // `collector_name_is_logon_session` smoke test. If a real host has an active
    // session, the ignored e2e-style manual check in Task 6 (real scan) is the
    // actual behavioral verification.
    use cairn_core::record::{LogonSessionRecord, Record};
    let rec = Record::LogonSession(LogonSessionRecord {
        user: "test".into(),
        logon_type: "Interactive".into(),
        logon_time: None,
        source: None,
        session_id: Some(1),
        state_active: true,
    });
    match rec {
        Record::LogonSession(s) => assert!(s.state_active),
        _ => panic!("expected LogonSession"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cairn-collectors maps_state_active --lib`
Expected: FAIL with a compile error in `logon_session.rs`'s existing `collect()`
method — the `LogonSessionRecord { ... }` struct literal at line 19-33 is missing the
`state_active` field, which is now required (no `Default` impl on the struct).

- [ ] **Step 3: Add the mapping**

In `crates/cairn-collectors/src/logon_session.rs`, change the `collect()` method's
struct literal (lines 19-33) from:

```rust
                Record::LogonSession(LogonSessionRecord {
                    user: s.user,
                    // Derived from the WinStation name, not client_address (which is
                    // always None -- see logon.rs). Windows names an RDP session's
                    // station "RDP-Tcp#<n>" and the local console session "Console";
                    // this is the officially observable, reliably-parseable signal.
                    logon_type: if is_remote_station(s.station_name.as_deref()) {
                        "RemoteInteractive".into()
                    } else {
                        "Interactive".into()
                    },
                    logon_time: None, // WTS has no reliable logon timestamp; honest None
                    source: s.client_address,
                    session_id: Some(s.session_id),
                })
```

to:

```rust
                Record::LogonSession(LogonSessionRecord {
                    user: s.user,
                    // Derived from the WinStation name, not client_address (which is
                    // always None -- see logon.rs). Windows names an RDP session's
                    // station "RDP-Tcp#<n>" and the local console session "Console";
                    // this is the officially observable, reliably-parseable signal.
                    logon_type: if is_remote_station(s.station_name.as_deref()) {
                        "RemoteInteractive".into()
                    } else {
                        "Interactive".into()
                    },
                    logon_time: None, // WTS has no reliable logon timestamp; honest None
                    source: s.client_address,
                    session_id: Some(s.session_id),
                    state_active: s.state_active,
                })
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p cairn-collectors --lib logon_session`
Expected: PASS — `maps_state_active_from_wts_session`,
`collector_name_is_logon_session` both pass.

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors/src/logon_session.rs
git commit -m "feat(collectors): wire WtsSession.state_active into LogonSessionRecord"
```

---

## Task 3: `data-severity`/`data-artifact` attributes + artifact dropdown

**Files:**
- Modify: `crates/cairn-report/src/html.rs` (findings row loop, ~lines 397-451; `html_report` function, ~lines 352-583)
- Test: `crates/cairn-report/src/html.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add these tests to the existing `#[cfg(test)] mod tests` block in
`crates/cairn-report/src/html.rs` (near the other `html_report_*` tests):

```rust
#[test]
fn finding_rows_carry_severity_and_artifact_data_attributes() {
    let mut f = Finding::new(Severity::High, "Test High", FindingSource::Sigma);
    f.host = "TEST-PC".into();
    f.artifact = "evtx:Security".into();
    let html = html_report(&[f], &[], &[], &minimal_manifest());
    assert!(
        html.contains("data-severity=\"high\""),
        "missing data-severity attribute: {html}"
    );
    assert!(
        html.contains("data-artifact=\"evtx:Security\""),
        "missing data-artifact attribute: {html}"
    );
}

#[test]
fn artifact_dropdown_lists_deduplicated_sorted_values() {
    let mut f1 = Finding::new(Severity::High, "A", FindingSource::Sigma);
    f1.host = "TEST-PC".into();
    f1.artifact = "evtx:Security".into();
    let mut f2 = Finding::new(Severity::Medium, "B", FindingSource::Heuristic);
    f2.host = "TEST-PC".into();
    f2.artifact = "persist:run_key".into();
    let mut f3 = Finding::new(Severity::Low, "C", FindingSource::Sigma);
    f3.host = "TEST-PC".into();
    f3.artifact = "evtx:Security".into(); // duplicate of f1's artifact
    let html = html_report(&[f1, f2, f3], &[], &[], &minimal_manifest());
    assert!(html.contains("<option value=\"evtx:Security\">evtx:Security</option>"));
    assert!(html.contains("<option value=\"persist:run_key\">persist:run_key</option>"));
    // Deduplicated: "evtx:Security" appears exactly once as an <option>.
    let opt_count = html.matches("<option value=\"evtx:Security\">").count();
    assert_eq!(opt_count, 1, "artifact option must be deduplicated");
}

#[test]
fn filter_bar_absent_when_no_findings() {
    let html = html_report(&[], &[], &[], &minimal_manifest());
    assert!(
        !html.contains("filter-bar"),
        "filter bar must not render when there are no findings"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-report --lib finding_rows_carry_severity_and_artifact_data_attributes artifact_dropdown_lists_deduplicated_sorted_values filter_bar_absent_when_no_findings`
Expected: FAIL — none of `data-severity`, `data-artifact`, `<option value=`, or
`filter-bar` exist in the current output.

- [ ] **Step 3: Add a `sev_key()` helper (lowercase severity string for the data attribute)**

In `crates/cairn-report/src/html.rs`, add this function right after `sev_label`
(after line 41, before `sev_color`):

```rust
/// Lowercase severity string for use as an HTML data-attribute value (client-side
/// filter matches against this, not the display label from `sev_label`).
fn sev_key(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}
```

- [ ] **Step 4: Add `data-severity`/`data-artifact` to each finding `<tr>`**

In `crates/cairn-report/src/html.rs`, inside `html_report`, find the `rows` build
(the `.map(|f| { ... format!("<tr>\n ...` block, currently starting around line 402).
Change the `format!` call that builds each `<tr>` — currently:

```rust
                format!(
                    "<tr>\
                  <td style=\"white-space:nowrap;color:#6b7280;font-size:0.85em\">{ts}</td>\
                  <td><span style=\"background:{color};color:#fff;padding:2px 8px;\
                      border-radius:4px;font-size:0.8em;white-space:nowrap\">{sev}</span></td>\
                  <td style=\"font-weight:500\">{title}</td>\
                  <td style=\"font-size:0.85em;color:#6b7280\">{mitre}</td>\
                  <td style=\"font-size:0.85em\">{src}</td>\
                  <td style=\"font-size:0.85em;color:#374151\">{desc}{ev_html}</td>\
                </tr>"
                )
```

to (adding a `data_sev`/`data_art` binding above the `format!` and the two
`data-*` attributes on the `<tr>`):

```rust
                let data_sev = sev_key(f.severity);
                let data_art = esc(&f.artifact);
                format!(
                    "<tr data-severity=\"{data_sev}\" data-artifact=\"{data_art}\">\
                  <td style=\"white-space:nowrap;color:#6b7280;font-size:0.85em\">{ts}</td>\
                  <td><span style=\"background:{color};color:#fff;padding:2px 8px;\
                      border-radius:4px;font-size:0.8em;white-space:nowrap\">{sev}</span></td>\
                  <td style=\"font-weight:500\">{title}</td>\
                  <td style=\"font-size:0.85em;color:#6b7280\">{mitre}</td>\
                  <td style=\"font-size:0.85em\">{src}</td>\
                  <td style=\"font-size:0.85em;color:#374151\">{desc}{ev_html}</td>\
                </tr>"
                )
```

Note: `data_art` must be `esc()`-escaped since `f.artifact` is free-form text that
could theoretically contain `"` — this keeps the same escaping discipline as every
other user-controllable string in this file (defense in depth even though artifact
values in practice come from internal enums/constants, not raw external input).

- [ ] **Step 5: Add `id="findings-tbody"` to the `<tbody>` and build the artifact dropdown + filter bar HTML**

In `crates/cairn-report/src/html.rs`, find the `<tbody>` tag inside the format string
at the bottom of `html_report` (around line 554) and add an id:

```
<tbody id="findings-tbody">
```

Then, still inside `html_report`, right after the `sorted` vec is built (after line
395, `sorted.sort_by_key(|f| sev_order(f.severity));`) and before the `rows` build,
add the artifact-dropdown and filter-bar construction:

```rust
    // Filter bar: only rendered when there's at least one finding to filter.
    let filter_bar_html = if sorted.is_empty() {
        String::new()
    } else {
        use std::collections::BTreeSet;
        let artifacts: BTreeSet<&str> = sorted.iter().map(|f| f.artifact.as_str()).collect();
        let artifact_options: String = artifacts
            .iter()
            .map(|a| {
                let a_esc = esc(a);
                format!("<option value=\"{a_esc}\">{a_esc}</option>")
            })
            .collect();
        format!(
            r#"<div class="filter-bar">
  <div class="filter-group">
    <label><input type="checkbox" class="sev-filter" value="critical" checked> Critical</label>
    <label><input type="checkbox" class="sev-filter" value="high" checked> High</label>
    <label><input type="checkbox" class="sev-filter" value="medium" checked> Medium</label>
    <label><input type="checkbox" class="sev-filter" value="low" checked> Low</label>
    <label><input type="checkbox" class="sev-filter" value="info" checked> Info</label>
  </div>
  <select id="artifact-filter"><option value="">全部來源</option>{artifact_options}</select>
  <input type="text" id="keyword-filter" placeholder="搜尋標題或說明...">
  <span id="filter-count"></span>
</div>"#
        )
    };
```

- [ ] **Step 6: Insert `{filter_bar_html}` into the output template**

In the big `format!` at the bottom of `html_report` (the `r#"<!DOCTYPE html>..."#`
block), find this section (around line 546-559):

```
<div class="card" style="margin-top:1.25rem">
<div class="card-title">Findings（共 {total} 筆）</div>
<div style="overflow-x:auto">
<table>
```

and insert `{filter_bar_html}` right after the `card-title` div:

```
<div class="card" style="margin-top:1.25rem">
<div class="card-title">Findings（共 {total} 筆）</div>
{filter_bar_html}
<div style="overflow-x:auto">
<table>
```

- [ ] **Step 7: Add CSS for `.filter-bar` and `.filter-group`**

In the `<style>` block (around line 495-522), add after the `.stat-label` rule:

```css
.filter-bar{{display:flex;gap:1rem;flex-wrap:wrap;align-items:center;
            margin-bottom:.75rem;font-size:.85rem}}
.filter-group{{display:flex;gap:.75rem;flex-wrap:wrap}}
.filter-group label{{display:flex;align-items:center;gap:.25rem;cursor:pointer}}
#artifact-filter,#keyword-filter{{padding:.35rem .5rem;border:1px solid #d1d5db;
                                   border-radius:4px;font-size:.85rem}}
#keyword-filter{{flex:1;min-width:150px}}
#filter-count{{color:#6b7280;font-size:.8rem;white-space:nowrap}}
```

(Note: this is inside a Rust raw string with `{{`/`}}` escaping for literal braces,
matching the existing style in this file — see e.g. `.card{{...}}` above it.)

- [ ] **Step 8: Run tests to verify they pass**

Run: `cargo test -p cairn-report --lib finding_rows_carry_severity_and_artifact_data_attributes artifact_dropdown_lists_deduplicated_sorted_values filter_bar_absent_when_no_findings`
Expected: PASS.

- [ ] **Step 9: Run the full existing html.rs test suite to check for regressions**

Run: `cargo test -p cairn-report --lib`
Expected: PASS — all pre-existing tests (e.g. `html_report_contains_hostname`,
`html_contains_inventory_block_and_evidence_details`) still pass unchanged.

- [ ] **Step 10: Commit**

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): add data-severity/data-artifact attributes and filter bar UI"
```

---

## Task 4: Filtering JavaScript

**Files:**
- Modify: `crates/cairn-report/src/html.rs` (`html_report` output template)
- Test: `crates/cairn-report/src/html.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add these tests to `crates/cairn-report/src/html.rs`'s test module:

```rust
#[test]
fn filter_script_present_when_findings_exist() {
    let mut f = Finding::new(Severity::High, "Test High", FindingSource::Sigma);
    f.host = "TEST-PC".into();
    f.artifact = "evtx:Security".into();
    let html = html_report(&[f], &[], &[], &minimal_manifest());
    assert!(
        html.contains("addEventListener"),
        "filter script must be present: {html}"
    );
}

#[test]
fn filter_script_has_no_eval_or_innerhtml() {
    let mut f = Finding::new(Severity::High, "Test High", FindingSource::Sigma);
    f.host = "TEST-PC".into();
    f.artifact = "evtx:Security".into();
    let html = html_report(&[f], &[], &[], &minimal_manifest());
    assert!(!html.contains("eval("), "must not use eval()");
    assert!(!html.contains("innerHTML ="), "must not assign innerHTML");
}

#[test]
fn filter_script_absent_when_no_findings() {
    let html = html_report(&[], &[], &[], &minimal_manifest());
    assert!(
        !html.contains("sev-filter"),
        "filter script/UI must not render when there are no findings"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-report --lib filter_script_present_when_findings_exist filter_script_has_no_eval_or_innerhtml filter_script_absent_when_no_findings`
Expected: `filter_script_present_when_findings_exist` FAILs (no script yet);
`filter_script_has_no_eval_or_innerhtml` PASSes vacuously (no script means neither
string is present — that's fine, it'll keep passing once the script is added since
the script genuinely doesn't use either); `filter_script_absent_when_no_findings`
already PASSes from Task 3.

- [ ] **Step 3: Build the filter script, gated on `sorted.is_empty()`**

In `crates/cairn-report/src/html.rs`, inside `html_report`, right after the
`filter_bar_html` construction from Task 3 Step 5, add:

```rust
    let filter_script_html = if sorted.is_empty() {
        String::new()
    } else {
        r#"<script>
(function() {
  var checkboxes = document.querySelectorAll('.sev-filter');
  var artifactSel = document.getElementById('artifact-filter');
  var keywordInput = document.getElementById('keyword-filter');
  var rows = document.querySelectorAll('#findings-tbody tr[data-severity]');
  var countEl = document.getElementById('filter-count');
  if (!rows.length) { return; }

  function applyFilter() {
    var activeSevs = Array.prototype.filter.call(checkboxes, function(cb) { return cb.checked; })
                          .map(function(cb) { return cb.value; });
    var artifact = artifactSel.value;
    var keyword = keywordInput.value.toLowerCase();
    var visible = 0;
    rows.forEach(function(row) {
      var sevOk = activeSevs.indexOf(row.dataset.severity) !== -1;
      var artOk = !artifact || row.dataset.artifact === artifact;
      var kwOk = !keyword || row.textContent.toLowerCase().indexOf(keyword) !== -1;
      var show = sevOk && artOk && kwOk;
      row.style.display = show ? '' : 'none';
      if (show) { visible++; }
    });
    countEl.textContent = '顯示 ' + visible + ' / ' + rows.length + ' 筆';
  }
  checkboxes.forEach(function(cb) { cb.addEventListener('change', applyFilter); });
  artifactSel.addEventListener('change', applyFilter);
  keywordInput.addEventListener('input', applyFilter);
  applyFilter();
})();
</script>"#
            .to_string()
    };
```

- [ ] **Step 4: Insert `{filter_script_html}` into the output template**

In the same big `format!` block, find the footer section (around line 573-577):

```
<div class="footer">
  <p>{int_note}</p>
  <p style="margin-top:.25rem">cairn v{tool_ver} &nbsp;·&nbsp; 報告產生時間：{generated}</p>
</div>

</div>
</body>
</html>
```

Insert `{filter_script_html}` right before the closing `</div>\n</body>\n</html>`:

```
<div class="footer">
  <p>{int_note}</p>
  <p style="margin-top:.25rem">cairn v{tool_ver} &nbsp;·&nbsp; 報告產生時間：{generated}</p>
</div>

{filter_script_html}

</div>
</body>
</html>
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-report --lib filter_script_present_when_findings_exist filter_script_has_no_eval_or_innerhtml filter_script_absent_when_no_findings`
Expected: PASS.

- [ ] **Step 6: Run the full html.rs test suite to check for regressions**

Run: `cargo test -p cairn-report --lib`
Expected: PASS — no regressions from Task 3.

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): add client-side filtering JavaScript for findings table"
```

---

## Task 5: Same-source-binary aggregation panel

**Files:**
- Modify: `crates/cairn-report/src/html.rs` (new function + `html_report` wiring)
- Test: `crates/cairn-report/src/html.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add these tests to `crates/cairn-report/src/html.rs`'s test module:

```rust
#[test]
fn basename_extracts_from_backslash_path() {
    assert_eq!(basename(r"C:\Windows\System32\evil.exe"), "evil.exe");
}

#[test]
fn basename_extracts_from_forward_slash_path() {
    assert_eq!(basename("C:/Users/a/evil.exe"), "evil.exe");
}

#[test]
fn basename_returns_input_when_no_separator() {
    assert_eq!(basename("EVIL.EXE"), "EVIL.EXE");
}

#[test]
fn evidence_summary_lists_basenames_appearing_in_two_or_more_findings() {
    use cairn_core::finding::EvidenceItem;
    let mut f1 = Finding::new(Severity::High, "A", FindingSource::Sigma);
    f1.host = "TEST-PC".into();
    f1.artifact = "evtx:Security".into();
    f1.evidence.push(EvidenceItem {
        artifact: "prefetch".into(),
        path: Some("EVIL.EXE".into()),
        ts: None,
        detail: "run_count=3".into(),
    });
    let mut f2 = Finding::new(Severity::Medium, "B", FindingSource::Heuristic);
    f2.host = "TEST-PC".into();
    f2.artifact = "persist:run_key".into();
    f2.evidence.push(EvidenceItem {
        artifact: "shimcache".into(),
        path: Some(r"C:\Users\a\EVIL.EXE".into()),
        ts: None,
        detail: "seen in shimcache".into(),
    });
    let html = html_report(&[f1, f2], &[], &[], &minimal_manifest());
    assert!(
        html.contains("EVIL.EXE"),
        "aggregation panel must list the repeated basename: {html}"
    );
    assert!(html.contains("相同來源多次出現") || html.contains("同一執行檔"));
}

#[test]
fn evidence_summary_excludes_basenames_appearing_only_once() {
    use cairn_core::finding::EvidenceItem;
    let mut f = Finding::new(Severity::High, "A", FindingSource::Sigma);
    f.host = "TEST-PC".into();
    f.artifact = "evtx:Security".into();
    f.evidence.push(EvidenceItem {
        artifact: "prefetch".into(),
        path: Some("ONLYONE.EXE".into()),
        ts: None,
        detail: "run_count=1".into(),
    });
    let html = html_report(&[f], &[], &[], &minimal_manifest());
    assert!(
        !html.contains("相同來源多次出現") && !html.contains("同一執行檔"),
        "panel must not render when nothing repeats: {html}"
    );
}

#[test]
fn evidence_summary_counts_once_per_finding_not_per_evidence_item() {
    use cairn_core::finding::EvidenceItem;
    // A single finding with 3 evidence items all pointing at the same basename
    // must count as "1 finding mentions it", not 3.
    let mut f1 = Finding::new(Severity::High, "A", FindingSource::Sigma);
    f1.host = "TEST-PC".into();
    f1.artifact = "evtx:Security".into();
    for src in ["prefetch", "shimcache", "amcache"] {
        f1.evidence.push(EvidenceItem {
            artifact: src.into(),
            path: Some("SAME.EXE".into()),
            ts: None,
            detail: "seen".into(),
        });
    }
    let html = html_report(&[f1], &[], &[], &minimal_manifest());
    // Only one finding total -> SAME.EXE must NOT be treated as "repeated across findings".
    assert!(
        !html.contains("相同來源多次出現") && !html.contains("同一執行檔"),
        "must not count multiple evidence items within one finding as repetition: {html}"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-report --lib basename_extracts_from_backslash_path basename_extracts_from_forward_slash_path basename_returns_input_when_no_separator evidence_summary_lists_basenames_appearing_in_two_or_more_findings evidence_summary_excludes_basenames_appearing_only_once evidence_summary_counts_once_per_finding_not_per_evidence_item`
Expected: FAIL with a compile error (`basename` function doesn't exist yet).

- [ ] **Step 3: Add the `basename` helper function**

In `crates/cairn-report/src/html.rs`, add this function after `is_public_ipv4_hint`
(after line 31, before `sev_label`):

```rust
/// Extract the final path segment (file name) from a path string, handling both
/// backslash (Windows-native) and forward-slash (rare but honest to handle) separators.
/// A path with no separator is returned as-is (already a bare file name).
fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}
```

- [ ] **Step 4: Add the `evidence_source_summary_panel` function**

In `crates/cairn-report/src/html.rs`, add this function right after the
`logon_panel` function (after line 349, before `html_report`):

```rust
/// "Same binary across multiple findings" aggregation: counts, per distinct basename
/// derived from `Finding.evidence[].path`, how many *different findings* mention it
/// (not how many evidence items — a single finding with 3 evidence items pointing at
/// the same file counts once). Only basenames appearing in >= 2 findings are shown;
/// empty result renders nothing (same "no data, no panel" convention as the other
/// inventory panels in this file).
fn evidence_source_summary_panel(findings: &[&Finding]) -> String {
    use std::collections::{BTreeMap, BTreeSet};
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        let mut seen_in_this_finding: BTreeSet<String> = BTreeSet::new();
        for ev in &f.evidence {
            if let Some(path) = &ev.path {
                seen_in_this_finding.insert(basename(path).to_string());
            }
        }
        for base in seen_in_this_finding {
            *counts.entry(base).or_insert(0) += 1;
        }
    }
    let mut repeated: Vec<(&String, &usize)> = counts.iter().filter(|(_, &c)| c >= 2).collect();
    if repeated.is_empty() {
        return String::new();
    }
    // Most-repeated first, then alphabetical for ties.
    repeated.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let rows: String = repeated
        .iter()
        .map(|(base, count)| {
            format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                esc(base),
                count
            )
        })
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">相同來源多次出現 ({} 個檔名)</h2></summary>\
         <table><tr><th>檔名</th><th>出現於幾筆 finding</th></tr>{}</table></details>",
        repeated.len(),
        rows
    )
}
```

- [ ] **Step 5: Wire the panel into `html_report`**

In `crates/cairn-report/src/html.rs`, inside `html_report`, right after the
`sorted.sort_by_key(...)` line (line 395) and before the `filter_bar_html`
construction (added in Task 3), add:

```rust
    let evidence_summary_html = evidence_source_summary_panel(&sorted);
```

Then in the big output `format!`, find the panel-insertion section (around line
561-571):

```
{netconn_html}

{process_html}

{execution_html}

{file_activity_html}

{logon_html}

{obs_html}
```

and add `{evidence_summary_html}` right after the Findings card's closing `</div>`
(i.e., before `{netconn_html}`):

```
{evidence_summary_html}

{netconn_html}

{process_html}

{execution_html}

{file_activity_html}

{logon_html}

{obs_html}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p cairn-report --lib basename_extracts_from_backslash_path basename_extracts_from_forward_slash_path basename_returns_input_when_no_separator evidence_summary_lists_basenames_appearing_in_two_or_more_findings evidence_summary_excludes_basenames_appearing_only_once evidence_summary_counts_once_per_finding_not_per_evidence_item`
Expected: PASS.

- [ ] **Step 7: Run the full html.rs test suite to check for regressions**

Run: `cargo test -p cairn-report --lib`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): add same-source-binary aggregation panel"
```

---

## Task 6: `logon_panel` state_active column + `netconn_panel` title rename

**Files:**
- Modify: `crates/cairn-report/src/html.rs` (`logon_panel` ~lines 309-349, `netconn_panel` ~lines 76-129)
- Test: `crates/cairn-report/src/html.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add these tests to `crates/cairn-report/src/html.rs`'s test module. Note: the
existing `session()` test helper (around line 895-903) needs updating too since
`LogonSessionRecord` now requires `state_active` — do that as part of this step,
not as a separate task, since the helper is only used by these tests:

```rust
#[test]
fn logon_panel_shows_state_active_column() {
    let recs = vec![
        cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
            user: r"PC\alice".into(),
            logon_type: "Interactive".into(),
            logon_time: None,
            source: None,
            session_id: Some(1),
            state_active: true,
        }),
        cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
            user: r"PC\bob".into(),
            logon_type: "Interactive".into(),
            logon_time: None,
            source: None,
            session_id: Some(2),
            state_active: false,
        }),
    ];
    let html = html_report(&[], &[], &recs, &minimal_manifest());
    assert!(html.contains("<th>狀態</th>"), "missing state column header: {html}");
    assert!(html.contains("是"), "active session must show 是");
    assert!(html.contains("否"), "inactive session must show 否");
}

#[test]
fn netconn_panel_title_is_network_connections_not_external() {
    let recs = vec![netconn(
        "tcp",
        Some("8.8.8.8"),
        Some(443),
        "ESTABLISHED",
        Some(100),
    )];
    let html = html_report(&[], &[], &recs, &minimal_manifest());
    assert!(html.contains("網路連線"), "title must be renamed: {html}");
    assert!(!html.contains("對外連線"), "old title must be gone: {html}");
}
```

Also update the existing `session()` helper function (around line 895-903) — find
this in the test module:

```rust
    fn session(user: &str, ltype: &str, sid: u32, source: Option<&str>) -> cairn_core::Record {
        cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
            user: user.into(),
            logon_type: ltype.into(),
            logon_time: None,
            source: source.map(String::from),
            session_id: Some(sid),
        })
    }
```

and add `state_active: false,` to the struct literal:

```rust
    fn session(user: &str, ltype: &str, sid: u32, source: Option<&str>) -> cairn_core::Record {
        cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
            user: user.into(),
            logon_type: ltype.into(),
            logon_time: None,
            source: source.map(String::from),
            session_id: Some(sid),
            state_active: false,
        })
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cairn-report --lib logon_panel_shows_state_active_column netconn_panel_title_is_network_connections_not_external`
Expected: FAIL — `logon_panel_shows_state_active_column` fails (no `<th>狀態</th>`
column yet, `session_id` struct literal missing `state_active` won't even compile
until the Step 1 helper fix is in); `netconn_panel_title_is_network_connections_not_external`
fails because the title is still "對外連線".

- [ ] **Step 3: Add the state_active column to `logon_panel`**

In `crates/cairn-report/src/html.rs`, `logon_panel` function (lines 309-349), change
the `rows` build — currently:

```rust
    let rows: String = sessions
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&s.user),
                esc(&s.logon_type),
                s.session_id
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".into()),
                esc(s.source.as_deref().unwrap_or("-")),
            )
        })
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">登入 session ({} 個，其中 {} 個遠端)</h2></summary>\
         <table><tr><th>使用者</th><th>類型</th><th>Session ID</th><th>來源</th></tr>{}</table></details>",
        sessions.len(),
        remote_count,
        rows
    )
```

to:

```rust
    let rows: String = sessions
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&s.user),
                esc(&s.logon_type),
                s.session_id
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".into()),
                esc(s.source.as_deref().unwrap_or("-")),
                if s.state_active { "是" } else { "否" },
            )
        })
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">登入 session ({} 個，其中 {} 個遠端)</h2></summary>\
         <table><tr><th>使用者</th><th>類型</th><th>Session ID</th><th>來源</th><th>狀態</th></tr>{}</table></details>",
        sessions.len(),
        remote_count,
        rows
    )
```

- [ ] **Step 4: Rename the netconn panel title**

In `crates/cairn-report/src/html.rs`, `netconn_panel` function (lines 76-129), find
this line (currently line 123):

```rust
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">對外連線 ({} 條，其中 {} 條連往公網)</h2></summary>\
```

and change `對外連線` to `網路連線`:

```rust
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">網路連線 ({} 條，其中 {} 條連往公網)</h2></summary>\
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cairn-report --lib logon_panel_shows_state_active_column netconn_panel_title_is_network_connections_not_external`
Expected: PASS.

- [ ] **Step 6: Update the two pre-existing tests that assert on the old title string**

Grep confirms exactly two pre-existing assertions reference the old title (besides
the panel's own implementation, fixed in Step 4):

1. `netconn_panel_lists_and_counts_public` (around line 729-751) has:
   ```rust
   assert!(
       html.contains("對外連線 (2 條，其中 1 條連往公網)"),
       "html: missing panel"
   );
   ```
   Change `對外連線` to `網路連線` in this string literal.

2. `netconn_panel_absent_when_no_conns` (around line 753-757) has:
   ```rust
   assert!(!html.contains("對外連線"));
   ```
   This technically still passes after the rename (the string "對外連線" genuinely
   isn't present anymore), but it's now asserting against the *wrong* title and would
   silently keep passing even if a future edit reintroduced "對外連線" elsewhere by
   accident. Change it to assert against the current title instead:
   ```rust
   assert!(!html.contains("網路連線"));
   ```

- [ ] **Step 7: Run the full html.rs test suite (final regression check for this crate)**

Run: `cargo test -p cairn-report --lib`
Expected: PASS — every test in the file, old and new, passes.

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-report/src/html.rs
git commit -m "fix(report): show logon state_active column; rename netconn panel to 網路連線"
```

---

## Task 7: Full workspace verification + real-machine smoke check

**Files:** none (verification only)

- [ ] **Step 1: Run full workspace check**

Run: `cargo check --workspace`
Expected: PASS, no errors.

- [ ] **Step 2: Run full workspace test suite**

Run: `cargo test --workspace --exclude cairn-updater`
Expected: PASS across all crates (cairn-updater excluded — its own tests require
elevated privileges unrelated to this change, a pre-existing environment limitation
documented in `docs/REMAINING-WORK.md` segment 0).

- [ ] **Step 3: Run clippy matching CI exactly**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: zero warnings.

- [ ] **Step 4: Run fmt check**

Run: `cargo fmt --check`
Expected: PASS (no diff). If this fails, run `cargo fmt --all` and re-verify with
`cargo test --workspace --exclude cairn-updater` that formatting didn't change
behavior (it shouldn't — formatting is whitespace-only).

- [ ] **Step 5: Manual real-machine report check**

Run a live scan (adjust flags to your usual dev invocation, e.g.):
```
cargo run -p cairn-cli -- run --profile minimal --dry-run
```
(or the profile you normally use to generate `report.html` without touching a real
target — check `docs/REMAINING-WORK.md` / `CLAUDE.md` for the current CLI invocation
if this has changed). Open the generated `report.html` in a browser and verify:
1. Findings table has a filter bar above it (if there are any findings; if the scan
   produces zero findings, the filter bar should be absent — that's correct, not a bug).
2. Unchecking a severity checkbox hides matching rows; the count text updates.
3. Selecting an artifact from the dropdown filters correctly.
4. Typing a keyword that matches a finding's title narrows the rows to matches only.
5. If any finding has evidence with repeated basenames across findings, the "相同來源
   多次出現" panel appears with correct counts; if not, it's absent (also correct).
6. If the host has any logon sessions, the 登入 session panel shows a 狀態 column
   with 是/否 values.
7. The network-connections panel (if present) is titled "網路連線", not "對外連線".

- [ ] **Step 6: No commit for this task** (verification-only; if Step 4 required a
  `cargo fmt --all` fix, that fix was already committed as part of Step 4's own flow —
  otherwise there is nothing new to commit here)

---

## Self-Review Notes (completed during plan writing, not a task to execute)

**Spec coverage check:**
- §3.1 (data attributes) → Task 3 ✓
- §3.2 (filter bar UI) → Task 3 ✓
- §3.3 (JS) → Task 4 ✓
- §3.4 (aggregation panel) → Task 5 ✓
- §3.5.1 (state_active schema + display) → Tasks 1, 2, 6 ✓
- §3.5.2 (netconn title) → Task 6 ✓
- §5 test strategy table → every row has a corresponding test in Tasks 1-6 ✓
- §7 six-step segmentation → mapped 1:1 to Tasks 1-6, Task 7 added for the
  cross-cutting final verification the spec's §7 step 6 calls for ✓

**Type consistency check:** `LogonSessionRecord` field order and names used
identically across Task 1 (definition), Task 2 (collector mapping), and Task 6
(test helper `session()` and new test) — verified `state_active: bool` (not
`Option<bool>`) is used consistently everywhere, matching the confirmed
`WtsSession.state_active: bool` type in `cairn-collectors-win/src/logon.rs:10`.

**Pre-existing tests referencing the renamed title:** grepped `對外連線` across
`html.rs` and found exactly two test-side occurrences beyond the implementation
itself — both are now explicit steps in Task 6 (Step 6), not left as a vague
"check for other references" instruction.
