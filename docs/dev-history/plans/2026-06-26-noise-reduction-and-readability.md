# S5-A Noise Reduction + Output Readability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the three core problems that make Cairn output hard to read: 252 inbox-service false positives, the tool flagging itself, and findings saying "未知程式" instead of the actual program name.

**Architecture:** Six independent changes (R1–R6) across three crates: `cairn-heur` (scoring + heuristic analyzers), `cairn-report` (client text generation). No new crates, no new dependencies, no unsafe code, no schema version change.

**Tech Stack:** Rust, chrono (already in workspace), existing `cairn-heur` scoring primitives.

**Spec:** `docs/superpowers/specs/2026-06-26-noise-reduction-and-readability-design.md`

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
| `crates/cairn-heur/src/score.rs` | Add `is_inbox_service_command()` + `normalise_service_cmd()` |
| `crates/cairn-heur/src/persist.rs` | Apply suppress gate in `score_persistence()` service arm; replace `f.details` format |
| `crates/cairn-heur/src/parentchild.rs` | Add own-PID skip; replace `f.details` format |
| `crates/cairn-heur/src/netconn.rs` | Add own-PID skip; populate `entity.process`; replace `f.details` format |
| `crates/cairn-report/src/client_text.rs` | Replace `entity_path()` with `entity_name()`; add `short_name()`; richer templates for persistence + netconn |

---

## Task 1 — R1a: `is_inbox_service_command()` in score.rs

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`

### What and why

Add two pure functions:
- `normalise_service_cmd(cmd)` — collapses `%SystemRoot%\`, `%windir%\`, `\SystemRoot\`, `C:\Windows\`, `c:\windows\` to a single canonical prefix `<win>\` (case-insensitive), so the inbox-pattern match has one code path instead of five.
- `is_inbox_service_command(cmd)` — returns `true` when the command (after normalisation) starts with `<win>\system32\` or `<win>\syswow64\` OR the bare relative equivalents `system32\` / `syswow64\` — AND does NOT contain `\driverstore\`. DriverStore OEM drivers are intentionally kept visible.

- [ ] **Step 1: Write failing tests**

Add at the bottom of the `#[cfg(test)]` block in `crates/cairn-heur/src/score.rs`:

```rust
// --- R1: inbox service suppress gate ---

#[test]
fn inbox_svchost_pct_systemroot_suppressed() {
    assert!(is_inbox_service_command(
        r"%SystemRoot%\system32\svchost.exe -k DcomLaunch -p"
    ));
}

#[test]
fn inbox_svchost_pct_windir_suppressed() {
    assert!(is_inbox_service_command(
        r"%windir%\system32\svchost.exe -k netsvcs"
    ));
}

#[test]
fn inbox_backslash_systemroot_suppressed() {
    assert!(is_inbox_service_command(
        r"\SystemRoot\system32\lsass.exe"
    ));
}

#[test]
fn inbox_absolute_cwindows_suppressed() {
    assert!(is_inbox_service_command(
        r"C:\Windows\system32\SearchIndexer.exe /Embedding"
    ));
}

#[test]
fn inbox_relative_system32_suppressed() {
    assert!(is_inbox_service_command(r"System32\drivers\tcpip.sys"));
}

#[test]
fn inbox_relative_syswow64_suppressed() {
    assert!(is_inbox_service_command(r"SysWOW64\some32bitbin.exe"));
}

#[test]
fn inbox_case_insensitive() {
    assert!(is_inbox_service_command(r"SYSTEM32\DRIVERS\WDF01000.SYS"));
    assert!(is_inbox_service_command(
        r"%SYSTEMROOT%\SYSTEM32\SVCHOST.EXE -k LocalService"
    ));
}

#[test]
fn driverstore_not_suppressed_abs() {
    // %SystemRoot%\System32\DriverStore\... matches pattern but must NOT suppress
    assert!(!is_inbox_service_command(
        r"%SystemRoot%\System32\DriverStore\FileRepository\asusptpfilter.inf_amd64_e109\AsusPTPService.exe"
    ));
}

#[test]
fn driverstore_not_suppressed_rel() {
    assert!(!is_inbox_service_command(
        r"System32\DriverStore\FileRepository\genpass.inf_amd64_0c82d80c\genpass.sys"
    ));
}

#[test]
fn program_files_not_suppressed() {
    assert!(!is_inbox_service_command(
        r r#""C:\Program Files\Trend Micro\AMSP\coreServiceShell.exe""#
    ));
}

#[test]
fn windowsapps_not_suppressed() {
    assert!(!is_inbox_service_command(
        r#""C:\Program Files\WindowsApps\Claude_1.15\app\resources\cowork-svc.exe""#
    ));
}

#[test]
fn empty_command_not_suppressed() {
    assert!(!is_inbox_service_command(""));
}
```

- [ ] **Step 2: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur inbox_ 2>&1 | tail -20
```

Expected: multiple `FAILED` — `is_inbox_service_command` not yet defined.

- [ ] **Step 3: Implement the two functions**

Add after the existing `pub fn is_rare_port` block in `crates/cairn-heur/src/score.rs`:

```rust
/// Collapse the many Windows env-var / path-root prefixes used in service ImagePath
/// values into a single canonical prefix so inbox-pattern matching has one code path.
/// The caller must lowercase before matching.
///
/// Mappings (all input matched case-insensitively):
///   %systemroot%\  →  <win>\
///   %windir%\      →  <win>\
///   \systemroot\   →  <win>\
///   c:\windows\    →  <win>\   (or any single drive letter + :\windows\)
fn normalise_service_cmd(cmd: &str) -> String {
    let lower = cmd.trim().to_ascii_lowercase();
    // Env-var forms
    for prefix in [r"%systemroot%\", r"%windir%\"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return format!(r"<win>\{rest}");
        }
    }
    // \SystemRoot\ (no drive letter)
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        return format!(r"<win>\{rest}");
    }
    // C:\Windows\ (any single drive letter)
    if lower.len() >= 11 {
        let (head, rest) = lower.split_at(11); // "c:\windows\" is 11 chars
        if rest.is_empty() || rest.starts_with(['\\', ' ', '"']) {
            // edge: exactly "c:\windows" or shorter — not a match
        } else if head
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
            && head[1..] == *":\\windows\\"
        {
            return format!(r"<win>\{rest}");
        }
    }
    lower
}

/// True when `cmd` is a Windows inbox service binary — svchost, lsass, inbox System32
/// exe/driver, bare relative System32/SysWOW64 path — but NOT a DriverStore OEM path.
///
/// Used by `score_persistence` to suppress low-value service findings for stable
/// built-in services. DriverStore is excluded so BYOVD-planted drivers remain visible.
pub fn is_inbox_service_command(cmd: &str) -> bool {
    if cmd.trim().is_empty() {
        return false;
    }
    let norm = normalise_service_cmd(cmd);
    // DriverStore exception: OEM drivers loaded into System32 — keep visible for BYOVD
    if norm.contains(r"\driverstore\") {
        return false;
    }
    // Pattern 1+3: canonical Windows dir (any env-var form or absolute C:\Windows\)
    if norm.starts_with(r"<win>\system32\") || norm.starts_with(r"<win>\syswow64\") {
        return true;
    }
    // Pattern 2+4: bare relative paths (no drive letter, no env var) — Windows itself
    // writes service ImagePaths this way for many kernel-mode drivers
    let stripped = norm.trim_start_matches('"');
    if stripped.starts_with(r"system32\") || stripped.starts_with(r"syswow64\") {
        return true;
    }
    false
}
```

- [ ] **Step 4: Run tests, confirm they pass**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur inbox_ 2>&1 | tail -20
```

Expected: all `inbox_*` tests `ok`.

- [ ] **Step 5: Full workspace check**

```powershell
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: all pass, zero warnings.

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-heur/src/score.rs
git commit -m "feat(heur): add is_inbox_service_command() suppress gate (R1a)"
```

---

## Task 2 — R1b: Apply Suppress Gate in `score_persistence()`

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

### What and why

In `score_persistence()`, before adding the service base score, check if the command
matches the inbox pattern AND was NOT modified within the last 7 days. If both are true,
return an empty `Score::default()` immediately — no finding emitted. Recently-planted
inbox-looking services bypass the suppress so attackers can't hide by impersonating svchost.

- [ ] **Step 1: Write failing tests**

Add at the bottom of the `#[cfg(test)]` block in `crates/cairn-heur/src/persist.rs`:

```rust
// --- R1b: inbox suppress gate integration ---

fn svc(command: &str, last_write: Option<DateTime<Utc>>) -> PersistenceRecord {
    PersistenceRecord {
        mechanism: "service".into(),
        location: r"HKLM\SYSTEM\CurrentControlSet\Services\TestSvc".into(),
        value: Some("TestSvc".into()),
        command: Some(command.into()),
        binary_path: None,
        binary_sha256: None,
        signed: None,
        signer: None,
        last_write,
    }
}

/// Old inbox svchost → suppressed (Score::default() → no finding)
#[test]
fn old_inbox_svchost_suppressed() {
    let now = Utc::now();
    let old = now - Duration::days(400);
    let p = svc(r"%SystemRoot%\system32\svchost.exe -k DcomLaunch -p", Some(old));
    let s = score_persistence(&p, now);
    assert_eq!(s.weight, 0, "inbox svchost must be suppressed, weight={}", s.weight);
    assert!(s.reasons.is_empty());
}

/// Old inbox driver (bare relative path) → suppressed
#[test]
fn old_inbox_driver_suppressed() {
    let now = Utc::now();
    let old = now - Duration::days(30);
    let p = svc(r"System32\drivers\tcpip.sys", Some(old));
    let s = score_persistence(&p, now);
    assert_eq!(s.weight, 0, "inbox driver must be suppressed");
}

/// Recent inbox svchost (≤7d) → NOT suppressed (recency bypass)
#[test]
fn recent_inbox_svchost_not_suppressed() {
    let now = Utc::now();
    let recent = now - Duration::days(3);
    let p = svc(
        r"%SystemRoot%\system32\svchost.exe -k ClipboardSvcGroup -p",
        Some(recent),
    );
    let s = score_persistence(&p, now);
    // service(20) + recency(15) = 35 → Low finding emitted
    assert!(s.weight >= 15, "recent inbox svchost must NOT be suppressed, weight={}", s.weight);
    assert!(s.reasons.iter().any(|r| r.contains("service autostart")));
}

/// DriverStore OEM driver → NOT suppressed (BYOVD surface preserved)
#[test]
fn driverstore_oem_not_suppressed() {
    let now = Utc::now();
    let old = now - Duration::days(400);
    let p = svc(
        r"%SystemRoot%\System32\DriverStore\FileRepository\asusatp.inf_amd64\AsusATP.exe",
        Some(old),
    );
    let s = score_persistence(&p, now);
    // service(20) only, NOT suppressed
    assert_eq!(s.weight, 20, "DriverStore must not be suppressed");
}

/// Non-inbox Program Files service → scores normally (not suppressed)
#[test]
fn program_files_service_not_suppressed() {
    let now = Utc::now();
    let old = now - Duration::days(400);
    let p = svc(
        r#""C:\Program Files\WindowsApps\Claude_1.15\app\resources\cowork-svc.exe""#,
        Some(old),
    );
    let s = score_persistence(&p, now);
    assert_eq!(s.weight, 20, "non-inbox service must score normally");
}

/// No last_write (None) → treated as "not recent" → suppress applies
#[test]
fn no_last_write_treated_as_not_recent() {
    let now = Utc::now();
    let p = svc(r"%SystemRoot%\system32\sppsvc.exe", None);
    let s = score_persistence(&p, now);
    assert_eq!(s.weight, 0, "inbox with no last_write must suppress");
}
```

- [ ] **Step 2: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur old_inbox_ recent_inbox_ driverstore_oem program_files_service no_last_write 2>&1 | tail -20
```

Expected: FAILED — gate not yet applied.

- [ ] **Step 3: Add import and apply gate in `score_persistence()`**

First, add `is_inbox_service_command` to the import at the top of `crates/cairn-heur/src/persist.rs`:

```rust
use crate::score::{
    is_inbox_service_command, is_suspicious_path, is_trusted_appdata_location,
    severity_for, winlogon_value_is_default, Score,
};
```

Then replace the `"service" => s.add(20, ...)` arm in `score_persistence()`:

```rust
"service" => {
    // Suppress stable Windows inbox services (svchost, inbox System32 exe/drivers).
    // Bypass when recently planted (≤7 days) — an attacker impersonating svchost
    // must still surface. DriverStore OEM paths are never suppressed (BYOVD risk).
    let cmd = p.command.as_deref().unwrap_or("");
    let recently_modified = p.last_write.map(|lw| {
        let age = now.signed_duration_since(lw);
        age >= Duration::zero() && age <= Duration::days(RECENT_DAYS)
    }).unwrap_or(false);
    if is_inbox_service_command(cmd) && !recently_modified {
        return Score::default();
    }
    s.add(20, "service autostart persistence", &["T1543.003"]);
}
```

- [ ] **Step 4: Run tests, confirm they pass**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur 2>&1 | tail -10
```

Expected: all tests pass including existing ones.

- [ ] **Step 5: Full workspace check**

```powershell
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): apply inbox-service suppress gate in score_persistence (R1b)

Suppresses 240+ low-value Windows-inbox-service findings; recency bypass
preserves detection of recently planted svchost imposters. DriverStore paths
excluded (BYOVD surface preservation). Old tests all pass."
```

---

## Task 3 — R2: Self-PID Exclusion

**Files:**
- Modify: `crates/cairn-heur/src/parentchild.rs`
- Modify: `crates/cairn-heur/src/netconn.rs`

### What and why

Cairn currently flags itself: the binary runs from `AppData\Local\cairn-target` (suspicious
path → medium) and its update-rules HTTP connections score high. Adding a 2-line own-PID
skip at the top of each `analyze()` loop eliminates these false positives.

- [ ] **Step 1: Write failing tests (parentchild)**

Add at the bottom of the `#[cfg(test)]` block in `crates/cairn-heur/src/parentchild.rs`:

```rust
use std::process;

/// The heuristic must never flag the collector's own process, even if it runs
/// from a suspicious path (cairn runs from AppData\Local\cairn-target).
#[test]
fn own_process_not_flagged() {
    let own_pid = process::id();
    let own = Record::Process(ProcessRecord {
        pid: own_pid,
        ppid: 4,
        image: r"C:\Users\x\AppData\Local\cairn-target\release\cairn.exe".into(),
        cmdline: String::new(),
        signed: Some(false),
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: None,
        start_time: None,
    });
    let findings = ParentChildHeuristic.analyze(&[own]).expect("analyze");
    assert!(findings.is_empty(), "own PID must never produce a finding");
}

/// Other processes at the same path still get flagged (the skip is PID-specific).
#[test]
fn other_pid_suspicious_path_still_flagged() {
    let own_pid = process::id();
    let other = Record::Process(ProcessRecord {
        pid: own_pid + 9999,
        ppid: 4,
        image: r"C:\Users\x\AppData\Local\cairn-target\release\cairn.exe".into(),
        cmdline: String::new(),
        signed: Some(false),
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: None,
        start_time: None,
    });
    let findings = ParentChildHeuristic.analyze(&[other]).expect("analyze");
    assert!(!findings.is_empty(), "other PID at same path must still fire");
}
```

- [ ] **Step 2: Write failing tests (netconn)**

Add at the bottom of the `#[cfg(test)]` block in `crates/cairn-heur/src/netconn.rs`:

```rust
use std::process;

/// Connections from the collector's own PID (e.g. update-rules fetch) must be skipped.
#[test]
fn own_pid_netconn_not_flagged() {
    let own_pid = process::id();
    let bad_conn = Record::NetConn(NetConnRecord {
        proto: "tcp".into(),
        laddr: "192.168.0.11".into(),
        lport: 65146,
        raddr: Some("104.18.38.233".into()),
        rport: Some(80),
        state: Some("established".into()),
        pid: Some(own_pid),
    });
    let findings = NetConnHeuristic.analyze(&[bad_conn]).expect("analyze");
    assert!(findings.is_empty(), "own PID connections must never produce findings");
}

/// Connections from other PIDs to the same remote still fire.
#[test]
fn other_pid_netconn_still_flagged() {
    let own_pid = process::id();
    // Use a non-rare port so we get the path-signal path instead — but really any
    // unsuppressed connection from a non-own PID must still score.
    let bad_conn = Record::NetConn(NetConnRecord {
        proto: "tcp".into(),
        laddr: "192.168.0.11".into(),
        lport: 50000,
        raddr: Some("104.18.0.1".into()),
        rport: Some(4444),
        state: Some("established".into()),
        pid: Some(own_pid + 9999),
    });
    let findings = NetConnHeuristic.analyze(&[bad_conn]).expect("analyze");
    assert!(!findings.is_empty(), "other PID must still produce findings");
}
```

- [ ] **Step 3: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur own_pid own_process other_pid 2>&1 | tail -20
```

Expected: FAILED.

- [ ] **Step 4: Apply own-PID skip in parentchild.rs**

In `ParentChildHeuristic::analyze()`, add immediately after `let by_pid: HashMap<...>`:

```rust
let own_pid = std::process::id();
```

Then change the loop body's first line from:

```rust
let Record::Process(p) = r else { continue };
```

to:

```rust
let Record::Process(p) = r else { continue };
if p.pid == own_pid { continue } // never flag the forensic tool itself
```

- [ ] **Step 5: Apply own-PID skip in netconn.rs**

In `NetConnHeuristic::analyze()`, add immediately after `let by_pid: HashMap<...>`:

```rust
let own_pid = std::process::id();
```

Then change the loop body's first line from:

```rust
let Record::NetConn(c) = r else { continue };
```

to:

```rust
let Record::NetConn(c) = r else { continue };
if c.pid == Some(own_pid) { continue } // never flag own network connections
```

- [ ] **Step 6: Run tests, confirm they pass**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur 2>&1 | tail -10
```

- [ ] **Step 7: Full workspace check**

```powershell
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

- [ ] **Step 8: Commit**

```powershell
git add crates/cairn-heur/src/parentchild.rs crates/cairn-heur/src/netconn.rs
git commit -m "feat(heur): exclude own PID from process and netconn heuristics (R2)

Cairn no longer flags itself as a suspicious process or flags its own
update-rules HTTP connections as high-severity findings."
```

---

## Task 4 — R3+R4+R5: Richer `details_client` in client_text.rs

**Files:**
- Modify: `crates/cairn-report/src/client_text.rs`

### What and why

Three problems fixed together because they all live in one small file (~180 lines):

**R3:** `entity_path()` returns "未知程式" for persistence findings — it only checks
`entity.process` and `entity.file` but persistence uses `entity.registry`. Fix: new
`entity_name()` that also reads registry data/value/key.

**R4:** The persistence `details_client` template is a single generic sentence. Fix: four
mechanism-specific templates that include service name, binary, and timing.

**R5:** The netconn `details_client` template says "未知程式". Fix: read `entity.process`
(which Task 5 will populate) and fall back gracefully to PID only when process absent.

- [ ] **Step 1: Write failing tests**

Add at the bottom of the `#[cfg(test)]` block in `crates/cairn-report/src/client_text.rs`:

```rust
use cairn_core::finding::{EntityNetConn, EntityRegistry};

fn make_persist(mechanism: &str, key: &str, value: &str, data: &str,
                last_write: Option<DateTime<Utc>>) -> Finding {
    let mut f = Finding::new(Severity::Medium, "test", FindingSource::Heuristic);
    f.host = "WS01".into();
    f.artifact = "persistence".into();
    f.entity.registry = Some(EntityRegistry {
        hive: "HKLM".into(),
        key: key.into(),
        value: value.into(),
        data: data.into(),
        last_write,
    });
    f
}

fn make_netconn_with_process(image: &str, pid: u32, raddr: &str, rport: u16) -> Finding {
    let mut f = Finding::new(Severity::High, "test", FindingSource::Heuristic);
    f.host = "WS01".into();
    f.artifact = "netconn".into();
    f.entity.netconn = Some(EntityNetConn {
        laddr: "192.168.0.1".into(),
        lport: 50000,
        raddr: Some(raddr.into()),
        rport: Some(rport),
        pid: Some(pid),
    });
    f.entity.process = Some(cairn_core::finding::EntityProcess {
        pid,
        ppid: 4,
        image: image.into(),
        cmdline: String::new(),
        signed: None,
        integrity: None,
    });
    f
}

// R3: registry entity → entity_name uses registry data/value/key
#[test]
fn service_client_text_not_unknown() {
    let mut f = make_persist(
        "service",
        r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService",
        "CoworkVMService",
        r#""C:\Program Files\WindowsApps\Claude\cowork-svc.exe""#,
        None,
    );
    f.entity.process = None;
    f.entity.file = None;
    fill_details_client(&mut f);
    let text = f.details_client.unwrap();
    assert!(!text.contains("未知程式"), "must not say 未知程式: {text}");
    assert!(text.contains("cowork-svc.exe") || text.contains("CoworkVMService"),
        "must mention service name or binary: {text}");
}

// R4: service with recent last_write mentions timing
#[test]
fn service_client_text_includes_binary_and_timing() {
    let now = chrono::Utc::now();
    let recent = now - chrono::Duration::days(2);
    let mut f = make_persist(
        "service",
        r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc",
        "EvilSvc",
        r"C:\Users\x\AppData\Local\Temp\evil.exe",
        Some(recent),
    );
    f.entity.process = None;
    f.entity.file = None;
    fill_details_client(&mut f);
    let text = f.details_client.unwrap();
    assert!(text.contains("evil.exe"), "must name binary: {text}");
    assert!(text.contains("WS01"), "must name host: {text}");
}

// R4: IFEO text warns about severity
#[test]
fn ifeo_client_text_mentions_attack() {
    let mut f = make_persist(
        "ifeo",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
        "Debugger",
        r"C:\Temp\cmd.exe",
        None,
    );
    f.severity = Severity::High;
    f.entity.process = None;
    f.entity.file = None;
    fill_details_client(&mut f);
    let text = f.details_client.unwrap();
    assert!(text.contains("幾乎僅用於攻擊") || text.contains("IFEO") || text.contains("調查"),
        "IFEO text must mention attack context: {text}");
}

// R4: winlogon text mentions the value name (Shell/Userinit)
#[test]
fn winlogon_client_text_mentions_value() {
    let mut f = make_persist(
        "winlogon",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
        "explorer.exe",
        None,
    );
    f.entity.process = None;
    f.entity.file = None;
    fill_details_client(&mut f);
    let text = f.details_client.unwrap();
    assert!(text.contains("Shell") || text.contains("Winlogon"),
        "winlogon text must mention value: {text}");
}

// R5: netconn with owning process names the process
#[test]
fn netconn_client_text_includes_process_name() {
    let mut f = make_netconn_with_process(
        r"C:\Users\x\AppData\Local\Temp\beacon.exe",
        1234,
        "185.0.0.1",
        4444,
    );
    fill_details_client(&mut f);
    let text = f.details_client.unwrap();
    assert!(text.contains("beacon.exe"), "must name process: {text}");
    assert!(text.contains("WS01"), "must name host: {text}");
}

// R5: netconn without owning process still produces text (graceful fallback)
#[test]
fn netconn_client_text_without_process_graceful() {
    let mut f = Finding::new(Severity::High, "test", FindingSource::Heuristic);
    f.host = "WS01".into();
    f.artifact = "netconn".into();
    f.entity.netconn = Some(EntityNetConn {
        laddr: "0.0.0.0".into(),
        lport: 50000,
        raddr: Some("185.0.0.1".into()),
        rport: Some(4444),
        pid: Some(9999),
    });
    fill_details_client(&mut f);
    let text = f.details_client.unwrap();
    assert!(!text.is_empty(), "must still produce text without process entity");
    assert!(text.contains("WS01"));
}
```

- [ ] **Step 2: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-report service_client netconn_client ifeo_client winlogon_client 2>&1 | tail -20
```

Expected: FAILED.

- [ ] **Step 3: Replace client_text.rs completely**

Replace the full content of `crates/cairn-report/src/client_text.rs` with:

```rust
//! FR18: plain zh-TW client-facing text for Findings >= Medium severity.
//!
//! `fill_details_client` fills `Finding.details_client` with a human-readable
//! summary addressed to a non-technical analyst. Idempotent below Medium.
#![forbid(unsafe_code)]

use cairn_core::finding::{Finding, FindingSource, Severity};
use chrono::{DateTime, Duration, Utc};

fn is_medium_or_above(s: Severity) -> bool {
    matches!(s, Severity::Critical | Severity::High | Severity::Medium)
}

/// Extract the last path segment of a file/executable path.
/// Strips surrounding quotes (service ImagePath values are often quoted).
fn short_name(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

/// Best available human-readable name for the entity implicated in a finding.
/// Priority: process image > file path > registry data (binary path) > registry
/// value name > registry key last segment > "未知程式".
fn entity_name(f: &Finding) -> String {
    if let Some(p) = &f.entity.process {
        return short_name(&p.image);
    }
    if let Some(fi) = &f.entity.file {
        return short_name(&fi.path);
    }
    if let Some(reg) = &f.entity.registry {
        // registry.data is the service command / run-key value; prefer it when it
        // looks like a path (contains backslash or starts with %).
        let data = reg.data.trim_matches('"');
        if data.contains('\\') || data.starts_with('%') {
            return short_name(data);
        }
        // Fall back to the registry value name (e.g. "CoworkVMService").
        if !reg.value.is_empty() {
            return reg.value.clone();
        }
        // Last resort: last key path segment.
        if let Some(seg) = reg.key.rsplit('\\').next() {
            if !seg.is_empty() {
                return seg.to_owned();
            }
        }
    }
    "未知程式".to_owned()
}

/// Format a timing hint for persistence findings.
/// "N 天前新增" when last_write is within 30 days, else "時間較久遠".
fn timing_hint(last_write: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match last_write {
        Some(lw) => {
            let age = now.signed_duration_since(lw);
            if age >= Duration::zero() && age <= Duration::days(30) {
                format!("{}天前新增", age.num_days())
            } else {
                "時間較久遠".to_owned()
            }
        }
        None => "時間不明".to_owned(),
    }
}

/// Build the mechanism-specific persistence sentence.
fn persistence_client_text(host: &str, f: &Finding) -> String {
    let now = Utc::now();
    let reg = f.entity.registry.as_ref();
    let bin = reg
        .map(|r| short_name(r.data.trim_matches('"')))
        .unwrap_or_else(|| entity_name(f));
    let svc_name = reg
        .and_then(|r| r.key.rsplit('\\').next().map(str::to_owned))
        .unwrap_or_else(|| entity_name(f));
    let timing = timing_hint(reg.and_then(|r| r.last_write), now);
    let value_name = reg.map(|r| r.value.as_str()).unwrap_or("?");

    // Determine mechanism from the finding title (e.g. "Suspicious persistence: service")
    let mechanism = f
        .title
        .strip_prefix("Suspicious persistence: ")
        .unwrap_or("unknown");

    match mechanism {
        "service" => format!(
            "主機 {} 上偵測到服務 {} 指向 {}（{}），\
             建議確認是否為已知且授權的軟體。",
            host, svc_name, bin, timing
        ),
        "run_key" | "startup" => format!(
            "主機 {} 上，{} 在自動啟動項目中新增了 {}（{}），\
             建議確認是否為已知且授權的操作。",
            host, svc_name, bin, timing
        ),
        "scheduled_task" => format!(
            "主機 {} 上偵測到排程工作 {} 指向 {}（{}），\
             建議確認是否為已知且授權的操作。",
            host, svc_name, bin, timing
        ),
        "winlogon" => format!(
            "主機 {} 上，Winlogon {} 設定為 {}（{}），\
             若非預期值請立即調查。",
            host, value_name, bin, timing
        ),
        "ifeo" => format!(
            "主機 {} 上，{} 的 IFEO Debugger 被設定為 {}，\
             此手法幾乎僅用於攻擊，建議立即調查。",
            host, svc_name, bin
        ),
        _ => format!(
            "主機 {} 上，{} 疑似建立了持久化機制（{}），\
             建議確認該項目是否為已知且授權的軟體。",
            host,
            entity_name(f),
            timing
        ),
    }
}

/// Build the netconn client sentence, naming the owning process when available.
fn netconn_client_text(host: &str, f: &Finding) -> String {
    let proc_name = f
        .entity
        .process
        .as_ref()
        .map(|p| short_name(&p.image))
        .unwrap_or_else(|| "未知程式".to_owned());
    let remote = f
        .entity
        .netconn
        .as_ref()
        .map(|c| {
            format!(
                "{}:{}",
                c.raddr.as_deref().unwrap_or("-"),
                c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
            )
        })
        .unwrap_or_else(|| "未知目標".to_owned());
    format!(
        "主機 {} 上，{} 發起了對外連線至 {}，\
         建議確認連線目標是否屬於正常業務範疇。",
        host, proc_name, remote
    )
}

pub fn fill_details_client(f: &mut Finding) {
    if !is_medium_or_above(f.severity) {
        return;
    }
    let host = f.host.clone();
    let text = match f.source {
        FindingSource::Heuristic => {
            match f.artifact.as_str() {
                "process" => {
                    let name = entity_name(f);
                    format!(
                        "主機 {} 上，{} 以非預期的父行程方式執行，\
                         可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。",
                        host, name
                    )
                }
                "persistence" => persistence_client_text(&host, f),
                "netconn" => netconn_client_text(&host, f),
                "file_meta" => {
                    let name = entity_name(f);
                    format!(
                        "主機 {} 上，{} 的時間戳記疑似遭到竄改，\
                         建議進一步確認該檔案的真實建立時間。",
                        host, name
                    )
                }
                _ => format!("主機 {} 上偵測到疑似異常行為，建議分析師確認詳情。", host),
            }
        }
        FindingSource::Sigma => {
            let title = f.title.clone();
            match f.severity {
                Severity::Critical | Severity::High => format!(
                    "主機 {} 上偵測到與「{}」相關的可疑活動，\
                     此類活動具有較高風險，建議盡速進行調查。",
                    host, title
                ),
                _ => format!(
                    "主機 {} 上偵測到與「{}」相關的活動，\
                     建議分析師評估是否為授權操作。",
                    host, title
                ),
            }
        }
    };
    f.details_client = Some(text);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::{EntityProcess, Finding, FindingSource, Severity};

    fn make_heuristic(severity: Severity, artifact: &str) -> Finding {
        let mut f = Finding::new(severity, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.artifact = artifact.into();
        f.entity.process = Some(EntityProcess {
            pid: 1,
            ppid: 0,
            image: r"C:\Windows\cmd.exe".into(),
            cmdline: String::new(),
            signed: None,
            integrity: None,
        });
        f
    }

    fn make_sigma(severity: Severity, title: &str) -> Finding {
        let mut f = Finding::new(severity, title, FindingSource::Sigma);
        f.host = "WS01".into();
        f
    }

    #[test]
    fn parent_child_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "process");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("非預期的父行程"), "got: {text}");
        assert!(text.contains("WS01"), "host missing: {text}");
        assert!(text.contains("cmd.exe"), "path missing: {text}");
    }

    #[test]
    fn persist_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, "persistence");
        f.title = "Suspicious persistence: service".into();
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(!text.is_empty(), "got: {text}");
    }

    #[test]
    fn netconn_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "netconn");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("對外連線"), "got: {text}");
    }

    #[test]
    fn timestomp_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "file_meta");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("時間戳記疑似遭到竄改"), "got: {text}");
    }

    #[test]
    fn other_heuristic_filled() {
        let mut f = make_heuristic(Severity::Medium, "unknown_artifact");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("疑似異常行為"), "got: {text}");
    }

    #[test]
    fn sigma_high_filled() {
        let mut f = make_sigma(Severity::High, "Mimikatz Credential Dumping");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("較高風險"), "got: {text}");
        assert!(text.contains("Mimikatz Credential Dumping"), "title missing: {text}");
    }

    #[test]
    fn sigma_medium_filled() {
        let mut f = make_sigma(Severity::Medium, "Suspicious PowerShell");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("評估是否為授權操作"), "got: {text}");
    }

    #[test]
    fn low_severity_not_filled() {
        let mut f = make_sigma(Severity::Low, "Low Noise Rule");
        fill_details_client(&mut f);
        assert!(f.details_client.is_none(), "Low must remain None");

        let mut f2 = make_heuristic(Severity::Info, "process");
        fill_details_client(&mut f2);
        assert!(f2.details_client.is_none(), "Info must remain None");
    }

    #[test]
    fn entity_path_falls_back_to_unknown_when_no_entity() {
        let mut f = make_heuristic(Severity::High, "process");
        f.entity.process = None;
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(text.contains("未知程式"), "fallback path missing: {text}");
    }

    // --- R3/R4/R5 new tests ---
    use cairn_core::finding::{EntityNetConn, EntityRegistry};

    fn make_persist(mechanism: &str, key: &str, value: &str, data: &str,
                    last_write: Option<DateTime<Utc>>) -> Finding {
        let mut f = Finding::new(
            Severity::Medium,
            &format!("Suspicious persistence: {mechanism}"),
            FindingSource::Heuristic,
        );
        f.host = "WS01".into();
        f.artifact = "persistence".into();
        f.entity.registry = Some(EntityRegistry {
            hive: "HKLM".into(),
            key: key.into(),
            value: value.into(),
            data: data.into(),
            last_write,
        });
        f
    }

    fn make_netconn_with_process(image: &str, pid: u32, raddr: &str, rport: u16) -> Finding {
        let mut f = Finding::new(Severity::High, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.artifact = "netconn".into();
        f.entity.netconn = Some(EntityNetConn {
            laddr: "192.168.0.1".into(),
            lport: 50000,
            raddr: Some(raddr.into()),
            rport: Some(rport),
            pid: Some(pid),
        });
        f.entity.process = Some(EntityProcess {
            pid,
            ppid: 4,
            image: image.into(),
            cmdline: String::new(),
            signed: None,
            integrity: None,
        });
        f
    }

    #[test]
    fn service_client_text_not_unknown() {
        let mut f = make_persist(
            "service",
            r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService",
            "CoworkVMService",
            r#""C:\Program Files\WindowsApps\Claude\cowork-svc.exe""#,
            None,
        );
        f.entity.process = None;
        f.entity.file = None;
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(!text.contains("未知程式"), "must not say 未知程式: {text}");
        assert!(
            text.contains("cowork-svc.exe") || text.contains("CoworkVMService"),
            "must mention name or binary: {text}"
        );
    }

    #[test]
    fn service_client_text_includes_binary_and_timing() {
        let now = Utc::now();
        let recent = now - chrono::Duration::days(2);
        let mut f = make_persist(
            "service",
            r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc",
            "EvilSvc",
            r"C:\Users\x\AppData\Local\Temp\evil.exe",
            Some(recent),
        );
        f.entity.process = None;
        f.entity.file = None;
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(text.contains("evil.exe"), "must name binary: {text}");
        assert!(text.contains("WS01"), "must name host: {text}");
    }

    #[test]
    fn ifeo_client_text_mentions_attack() {
        let mut f = make_persist(
            "ifeo",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
            "Debugger",
            r"C:\Temp\cmd.exe",
            None,
        );
        f.severity = Severity::High;
        f.entity.process = None;
        f.entity.file = None;
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(
            text.contains("幾乎僅用於攻擊") || text.contains("調查"),
            "IFEO text must mention attack context: {text}"
        );
    }

    #[test]
    fn winlogon_client_text_mentions_value() {
        let mut f = make_persist(
            "winlogon",
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
            "explorer.exe",
            None,
        );
        f.entity.process = None;
        f.entity.file = None;
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(
            text.contains("Shell") || text.contains("Winlogon"),
            "winlogon text must mention value: {text}"
        );
    }

    #[test]
    fn netconn_client_text_includes_process_name() {
        let mut f = make_netconn_with_process(
            r"C:\Users\x\AppData\Local\Temp\beacon.exe",
            1234,
            "185.0.0.1",
            4444,
        );
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(text.contains("beacon.exe"), "must name process: {text}");
        assert!(text.contains("WS01"), "must name host: {text}");
    }

    #[test]
    fn netconn_client_text_without_process_graceful() {
        let mut f = Finding::new(Severity::High, "test", FindingSource::Heuristic);
        f.host = "WS01".into();
        f.artifact = "netconn".into();
        f.entity.netconn = Some(EntityNetConn {
            laddr: "0.0.0.0".into(),
            lport: 50000,
            raddr: Some("185.0.0.1".into()),
            rport: Some(4444),
            pid: Some(9999),
        });
        fill_details_client(&mut f);
        let text = f.details_client.unwrap();
        assert!(!text.is_empty(), "must still produce text: {text}");
        assert!(text.contains("WS01"));
    }
}
```

- [ ] **Step 4: Run tests, confirm they pass**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-report 2>&1 | tail -15
```

Expected: all tests pass.

- [ ] **Step 5: Full workspace check**

```powershell
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-report/src/client_text.rs
git commit -m "feat(report): richer details_client — R3 registry fallback, R4 mechanism templates, R5 netconn process name

R3: entity_name() reads registry data/value/key — no more '未知程式' on services.
R4: persistence uses mechanism-specific zh-TW templates with binary name and timing.
R5: netconn text includes owning process name when entity.process is populated."
```

---

## Task 5 — R5b: Populate `entity.process` in netconn findings

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs`

### What and why

Task 4 (R5) already handles the case when `entity.process` is populated. But currently
`NetConnHeuristic::analyze()` never populates it — only `entity.netconn` is set. This task
wires the `owner` process (already looked up in `by_pid`) into the entity so the richer
client text actually fires.

- [ ] **Step 1: Write a failing test**

Add at the bottom of the `#[cfg(test)]` block in `crates/cairn-heur/src/netconn.rs`:

```rust
/// When the owning process record is present, entity.process must be populated
/// so that details_client can name the process (R5).
#[test]
fn entity_process_populated_when_owner_known() {
    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    let bad = Record::NetConn(NetConnRecord {
        proto: "tcp".into(),
        laddr: "192.168.0.1".into(),
        lport: 50000,
        raddr: Some("104.18.0.1".into()),
        rport: Some(4444),
        state: Some("established".into()),
        pid: Some(42),
    });
    let proc = Record::Process(ProcessRecord {
        pid: 42,
        ppid: 4,
        image: r"C:\Users\x\AppData\Local\Temp\beacon.exe".into(),
        cmdline: String::new(),
        signed: Some(false),
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: None,
        start_time: None,
    });
    let findings = NetConnHeuristic.analyze(&[bad, proc]).expect("analyze");
    assert!(!findings.is_empty(), "must produce a finding");
    let f = &findings[0];
    assert!(
        f.entity.process.is_some(),
        "entity.process must be populated when owner is known"
    );
    assert_eq!(
        f.entity.process.as_ref().unwrap().pid,
        42,
        "entity.process.pid must match owner"
    );
}
```

- [ ] **Step 2: Run test, confirm it fails**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur entity_process_populated 2>&1 | tail -10
```

Expected: FAILED — `entity.process` is None.

- [ ] **Step 3: Wire owner into entity in netconn.rs**

In `NetConnHeuristic::analyze()`, replace:

```rust
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
```

with:

```rust
f.entity = Entity {
    netconn: Some(EntityNetConn {
        laddr: c.laddr.clone(),
        lport: c.lport,
        raddr: c.raddr.clone(),
        rport: c.rport,
        pid: c.pid,
    }),
    process: owner.map(|o| EntityProcess {
        pid: o.pid,
        ppid: o.ppid,
        image: o.image.clone(),
        cmdline: o.cmdline.clone(),
        signed: o.signed,
        integrity: o.integrity.clone(),
    }),
    ..Entity::default()
};
```

Also add the import at the top of the file (after existing imports):

```rust
use cairn_core::finding::EntityProcess;
```

- [ ] **Step 4: Run tests, confirm they pass**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur 2>&1 | tail -10
```

- [ ] **Step 5: Full workspace check**

```powershell
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```powershell
git add crates/cairn-heur/src/netconn.rs
git commit -m "feat(heur): populate entity.process on netconn findings when owner is known (R5b)"
```

---

## Task 6 — R6: Human-Readable `details` Field in All Heuristic Analyzers

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`
- Modify: `crates/cairn-heur/src/parentchild.rs`
- Modify: `crates/cairn-heur/src/netconn.rs`

### What and why

The `details` field is the `Details` column in `timeline.csv` — what an analyst sees
when opening the CSV in Excel. Currently it uses a debug key=value format. Replace with
natural-language mixed Chinese/English that is immediately readable.

- [ ] **Step 1: Write failing tests (persist)**

Add at bottom of `#[cfg(test)]` block in `crates/cairn-heur/src/persist.rs`:

```rust
use cairn_core::record::Record;
use cairn_core::traits::Analyzer;

fn full_svc_rec(name: &str, command: &str, last_write: Option<DateTime<Utc>>) -> Record {
    Record::Persistence(PersistenceRecord {
        mechanism: "service".into(),
        location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
        value: Some(name.into()),
        command: Some(command.into()),
        binary_path: None,
        binary_sha256: None,
        signed: None,
        signer: None,
        last_write,
    })
}

/// Service details format: "服務 <name> → <binary> (<date>)"
#[test]
fn service_details_format() {
    let rec = full_svc_rec(
        "CoworkVMService",
        r#""C:\Program Files\WindowsApps\Claude\cowork-svc.exe""#,
        Some(Utc::now() - Duration::days(2)),
    );
    let findings = PersistHeuristic.analyze(&[rec]).expect("analyze");
    assert!(!findings.is_empty(), "should fire (non-inbox, recent)");
    let details = &findings[0].details;
    assert!(details.contains("CoworkVMService"), "service name: {details}");
    assert!(details.contains("cowork-svc.exe"), "binary: {details}");
    assert!(!details.contains("mechanism="), "no debug format: {details}");
}

/// Winlogon details format: "Winlogon Shell: explorer.exe"
#[test]
fn winlogon_details_format() {
    let rec = Record::Persistence(PersistenceRecord {
        mechanism: "winlogon".into(),
        location: r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".into(),
        value: Some("Shell".into()),
        command: Some("explorer.exe,evil.exe".into()),
        binary_path: None,
        binary_sha256: None,
        signed: None,
        signer: None,
        last_write: None,
    });
    let findings = PersistHeuristic.analyze(&[rec]).expect("analyze");
    assert!(!findings.is_empty());
    let details = &findings[0].details;
    assert!(details.contains("Winlogon") || details.contains("Shell"), "got: {details}");
    assert!(!details.contains("mechanism="), "no debug format: {details}");
}
```

- [ ] **Step 2: Write failing tests (parentchild)**

Add at bottom of `#[cfg(test)]` block in `crates/cairn-heur/src/parentchild.rs`:

```rust
/// Process details format: "<name> (pid=N, parent=M)"
#[test]
fn process_details_format() {
    let parent = proc(100, 4, r"C:\Program Files\Microsoft Office\winword.exe", "");
    let child = proc(
        200, 100,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
    );
    let recs = vec![rec(parent), rec(child)];
    let findings = ParentChildHeuristic.analyze(&recs).expect("analyze");
    assert!(!findings.is_empty());
    let details = &findings[0].details;
    assert!(details.contains("cmd.exe"), "binary name: {details}");
    assert!(details.contains("pid="), "pid field: {details}");
    assert!(!details.contains("image="), "no debug format: {details}");
}
```

- [ ] **Step 3: Write failing test (netconn)**

Add at bottom of `#[cfg(test)]` block in `crates/cairn-heur/src/netconn.rs`:

```rust
/// Netconn details format: "<proc> (<pid>) → <raddr>:<rport>"
#[test]
fn netconn_details_format() {
    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    let bad = Record::NetConn(NetConnRecord {
        proto: "tcp".into(),
        laddr: "192.168.0.11".into(),
        lport: 50000,
        raddr: Some("104.18.0.1".into()),
        rport: Some(4444),
        state: Some("established".into()),
        pid: Some(1234),
    });
    let proc_rec = Record::Process(ProcessRecord {
        pid: 1234,
        ppid: 4,
        image: r"C:\Users\x\AppData\Local\Temp\beacon.exe".into(),
        cmdline: String::new(),
        signed: Some(false),
        signer: None,
        binary_sha256: None,
        integrity: None,
        user: None,
        start_time: None,
    });
    let findings = NetConnHeuristic.analyze(&[bad, proc_rec]).expect("analyze");
    assert!(!findings.is_empty());
    let details = &findings[0].details;
    assert!(details.contains("beacon.exe"), "process name: {details}");
    assert!(details.contains("1234"), "pid: {details}");
    assert!(details.contains("104.18.0.1"), "remote addr: {details}");
    assert!(!details.contains("pid=Some("), "no debug format: {details}");
}
```

- [ ] **Step 4: Run tests, confirm they fail**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test -p cairn-heur service_details_ winlogon_details_ process_details_ netconn_details_ 2>&1 | tail -20
```

Expected: FAILED.

- [ ] **Step 5: Add `format_persist_details` helper and update persist.rs**

Add this private function before `PersistHeuristic` in `crates/cairn-heur/src/persist.rs`:

```rust
fn short_name(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

fn format_persist_details(p: &PersistenceRecord) -> String {
    let svc_name = p.location.rsplit('\\').next().unwrap_or(&p.location);
    let cmd = p.command.as_deref().unwrap_or("-");
    let bin_short = short_name(cmd);
    let date = p
        .last_write
        .map(|lw| lw.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".into());
    match p.mechanism.as_str() {
        "service"        => format!("服務 {} → {} ({})", svc_name, bin_short, date),
        "run_key"        => format!("Run 鍵: {} → {} ({})", svc_name, bin_short, date),
        "scheduled_task" => format!("排程工作: {} → {} ({})", svc_name, bin_short, date),
        "winlogon"       => format!("Winlogon {}: {}", p.value.as_deref().unwrap_or("?"), cmd),
        "ifeo"           => format!("IFEO {}: {} → {}", svc_name, svc_name, bin_short),
        "startup"        => format!("Startup: {} ({})", bin_short, date),
        _                => format!("{}: {} → {}", p.mechanism, svc_name, bin_short),
    }
}
```

Then in `PersistHeuristic::analyze()`, replace:

```rust
f.details = format!(
    "mechanism={} location={} command={}",
    p.mechanism,
    p.location,
    p.command.as_deref().unwrap_or("-")
);
```

with:

```rust
f.details = format_persist_details(p);
```

- [ ] **Step 6: Update parentchild.rs `details` format**

In `ParentChildHeuristic::analyze()`, replace:

```rust
f.details = format!(
    "pid={} ppid={} image={} cmdline={}",
    p.pid, p.ppid, p.image, p.cmdline
);
```

with:

```rust
let p_name = p.image.rsplit(['\\', '/']).next().unwrap_or(&p.image);
f.details = if p.cmdline.is_empty() {
    format!("{} (pid={}, parent={})", p_name, p.pid, p.ppid)
} else {
    format!("{} (pid={}, parent={}, cmd={})", p_name, p.pid, p.ppid, p.cmdline)
};
```

- [ ] **Step 7: Update netconn.rs `details` format**

In `NetConnHeuristic::analyze()`, replace:

```rust
f.details = format!(
    "{} {}:{} -> {}:{} pid={:?}",
    c.proto,
    c.laddr,
    c.lport,
    c.raddr.as_deref().unwrap_or("-"),
    c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
    c.pid
);
```

with:

```rust
let proc_label = owner
    .map(|o| {
        let name = o.image.rsplit(['\\', '/']).next().unwrap_or(&o.image);
        format!("{} ({})", name, o.pid)
    })
    .or_else(|| c.pid.map(|pid| pid.to_string()))
    .unwrap_or_else(|| "unknown".into());
f.details = format!(
    "{} → {}:{}",
    proc_label,
    c.raddr.as_deref().unwrap_or("-"),
    c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
);
```

- [ ] **Step 8: Run all tests, confirm they pass**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo test --workspace 2>&1 | tail -10
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

- [ ] **Step 9: Commit**

```powershell
git add crates/cairn-heur/src/persist.rs crates/cairn-heur/src/parentchild.rs crates/cairn-heur/src/netconn.rs
git commit -m "feat(heur): human-readable details field in all heuristic analyzers (R6)

timeline.csv Details column now shows natural-language descriptions:
  服務 CoworkVMService → cowork-svc.exe (2026-06-24)
  beacon.exe (1234) → 185.0.0.1:4444
  cmd.exe (pid=200, parent=100, cmd=cmd.exe /c whoami)"
```

---

## Self-Review

### Spec coverage check

| Spec section | Task |
|-------------|------|
| R1: inbox-service suppress gate | T1 (is_inbox_service_command) + T2 (gate in score_persistence) |
| R2: self-PID exclusion | T3 |
| R3: entity_path registry fallback | T4 (entity_name in client_text.rs) |
| R4: richer details_client for persistence | T4 (persistence_client_text) |
| R5: richer details_client for netconn | T4 (netconn_client_text) + T5 (entity.process wiring) |
| R6: human-readable details field | T6 |

All spec requirements covered. ✓

### Placeholder scan

No TBD, TODO, or incomplete steps found. ✓

### Type consistency check

- `is_inbox_service_command()` defined in T1, used in T2. ✓
- `entity_name()` defined in T4, used only within client_text.rs. ✓
- `short_name()` defined in T4 (client_text.rs) and T6 (persist.rs) — two independent copies in different crates, intentional. ✓
- `EntityProcess` import needed in netconn.rs (T5) — noted in that task. ✓
- `format_persist_details()` defined and called in T6 within same file. ✓
- All test helper functions (`svc()`, `make_persist()`, etc.) are local to their test modules. ✓
