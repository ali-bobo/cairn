# Spec: Noise Reduction + Output Readability (S5-A)

**Date:** 2026-06-26
**Status:** Approved for implementation
**Related plans:** `docs/superpowers/plans/2026-06-26-noise-reduction-and-readability.md`

---

## Problem Statement

Live triage output (`timeline.csv`, `findings.jsonl`) currently has two intertwined
problems that make it hard to reconstruct an attack chain:

1. **252 low-severity service findings flood the timeline** — all legitimate Windows
   inbox services (DcomLaunch, Dhcp, tcpip.sys …) get flagged because the heuristic
   has no baseline for what "normal Windows" looks like.
2. **Key context is missing or machine-readable** — `details_client` says "未知程式"
   even when the service name and binary path are known; netconn findings don't name
   the process; timeline `Details` uses debug key=value format.
3. **The tool flags itself** — cairn.exe scores medium (suspicious path in
   AppData) and its update-rules HTTP calls score high; every run poisons its own
   report.

---

## Scope (this spec only)

| ID | Change | Crate(s) |
|----|--------|----------|
| R1 | Inbox-service suppress gate | `cairn-heur` (`score.rs`, `persist.rs`) |
| R2 | Self-PID exclusion | `cairn-heur` (`parentchild.rs`, `netconn.rs`) |
| R3 | `entity_path()` registry fallback | `cairn-report` (`client_text.rs`) |
| R4 | Richer `details_client` for persistence | `cairn-report` (`client_text.rs`) |
| R5 | Richer `details_client` for netconn | `cairn-report` (`client_text.rs`) |
| R6 | Human-readable `details` field in heuristics | `cairn-heur` (all four analyzers) |

Out of scope: cmdline/integrity/SHA256 enrichment (next PR); live-run Sigma wiring
(separate PR); DNS reverse lookup (separate PR).

---

## R1 — Inbox-Service Suppress Gate

### Goal

Reduce 252 low-severity service findings to ≤20 actionable ones by silencing
Windows-built-in service patterns **unless they were recently planted (≤7 days)**.

### Decision: A+C fusion

- **Layer A (hard suppress):** service command matches an inbox pattern AND the
  `last_write` is older than 7 days → return `Score::default()` immediately, no finding.
- **Layer C fallback:** if the command does NOT match an inbox pattern, existing scoring
  applies unchanged (service=+20, recency, suspicious-path, unsigned amplifier).
- **Recency bypass:** a recently-modified service that matches an inbox pattern is NOT
  suppressed — an attacker impersonating svchost within the last 7 days must still fire.
  This is the security invariant that lets us suppress boldly without risk.

### Inbox pattern rules (all case-insensitive after env-var normalisation)

Normalise the command string first: replace `%systemroot%`, `%windir%`,
`\systemroot\` with the literal placeholder `<win>` so all three formats unify.

A command is **inbox** when it matches ANY of these after normalisation,
**AND** does NOT contain `\driverstore\` (case-insensitive):

```
1. starts_with("<win>\\system32\\")              — svchost, lsass, sppsvc, SearchIndexer…
2. starts_with("system32\\")                     — bare relative paths (no drive letter)
3. starts_with("<win>\\syswow64\\")              — 32-bit inbox binaries
4. starts_with("syswow64\\")                     — bare relative SysWOW64
```

**DriverStore exclusion:** `%SystemRoot%\System32\DriverStore\FileRepository\...` and
`System32\DriverStore\...` are OEM/vendor drivers loaded into System32 — they match
pattern 1/2 above but must NOT be suppressed. BYOVD (Bring Your Own Vulnerable Driver)
attacks plant malicious drivers here; amcache_driver provides SHA1 for IoC correlation.
These remain visible as low-severity findings.

**NOT suppressed** regardless of pattern match:
- `last_write` within the last 7 days (recency bypass)
- Any path containing `\driverstore\` (OEM driver gate, see above)

**Examples:**

| Command | Suppressed? | Reason |
|---------|-------------|--------|
| `%SystemRoot%\system32\svchost.exe -k DcomLaunch` | ✅ (if old) | pattern 1 |
| `System32\drivers\tcpip.sys` | ✅ (if old) | pattern 2 |
| `\SystemRoot\system32\lsass.exe` | ✅ (if old) | pattern 1 (after norm) |
| `C:\Windows\system32\svchost.exe` | ✅ (if old) | pattern 1 |
| `%SystemRoot%\System32\DriverStore\FileRepository\...\AsusAtp.exe` | ❌ | DriverStore gate |
| `System32\DriverStore\FileRepository\...\genpass.sys` | ❌ | DriverStore gate |
| `"C:\Program Files\Vendor\app.exe"` | ❌ | not inbox |
| `"C:\Program Files\WindowsApps\Claude\cowork-svc.exe"` | ❌ | not inbox |
| `\SystemRoot\System32\drivers\TMUMH.sys` (new, ≤7d) | ❌ | recency bypass |
| `%SystemRoot%\system32\svchost.exe -k ClipboardSvcGroup` (new, ≤7d) | ❌ | recency bypass |

### Implementation

New function in `score.rs`:

```rust
/// Normalise a service command for inbox-pattern matching.
/// Replaces env-var and \systemroot\ prefixes with a canonical placeholder.
fn normalise_service_command(cmd: &str) -> String { ... }

/// True if `cmd` matches a known Windows inbox service path pattern.
/// Case-insensitive; call normalise_service_command first.
pub fn is_inbox_service_command(cmd: &str) -> bool { ... }
```

Change in `persist.rs` `score_persistence()` service arm:

```rust
"service" => {
    let cmd = p.command.as_deref().unwrap_or("");
    let recently_modified = p.last_write.map(|lw|
        now.signed_duration_since(lw) <= Duration::days(RECENT_DAYS)
        && now.signed_duration_since(lw) >= Duration::zero()
    ).unwrap_or(false);

    if is_inbox_service_command(cmd) && !recently_modified {
        return Score::default(); // suppress — Windows inbox, nothing to see
    }
    s.add(20, "service autostart persistence", &["T1543.003"]);
}
```

Note: the recency signal block later in the function still runs for non-suppressed
records, so a recently-modified inbox service gets service(+20) + recency(+15) = Low,
which surfaces it without false-alarming on stable services.

---

## R2 — Self-PID Exclusion

### Goal

cairn.exe must not flag itself. Every live run currently produces:
- `Suspicious process: cairn.exe` (medium) — suspicious AppData path
- `Suspicious tcp connection` × 4 (high) — update-rules HTTP calls from cairn's PID

### Implementation

Both `ParentChildHeuristic::analyze()` and `NetConnHeuristic::analyze()` add at the
top of their `analyze()` method:

```rust
let own_pid = std::process::id();
```

Then in the iteration loop, skip any record whose PID matches:

```rust
// parentchild
let Record::Process(p) = r else { continue };
if p.pid == own_pid { continue }  // never flag the collector itself

// netconn
let Record::NetConn(c) = r else { continue };
if c.pid == Some(own_pid) { continue }  // never flag own connections
```

This is 2 lines per file, zero unsafe, zero new dependencies.

---

## R3 — `entity_path()` Registry Fallback

### Goal

Fix `details_client` saying "未知程式" for persistence findings that have
`entity.registry` (services, run keys, winlogon, IFEO, scheduled tasks).

### Current code (`client_text.rs`)

```rust
fn entity_path(f: &Finding) -> &str {
    if let Some(p) = &f.entity.process { return &p.image; }
    if let Some(fi) = &f.entity.file { return &fi.path; }
    "未知程式"  // ← persistence findings fall through to here
}
```

### Fix

Extract a useful identifier from the registry entity when process and file are absent:

```rust
fn entity_name(f: &Finding) -> String {
    if let Some(p) = &f.entity.process {
        // last path segment: "C:\Windows\cmd.exe" → "cmd.exe"
        return short_name(&p.image);
    }
    if let Some(fi) = &f.entity.file {
        return short_name(&fi.path);
    }
    if let Some(reg) = &f.entity.registry {
        // Use the data (command) if it looks like a path, else the registry value name
        let data = reg.data.trim_matches('"');
        if data.contains('\\') || data.starts_with('%') {
            return short_name(data);
        }
        if !reg.value.is_empty() {
            return reg.value.clone();
        }
        // Fallback: last key segment = service/task name
        return reg.key.rsplit('\\').next().unwrap_or("unknown").to_owned();
    }
    "未知程式".to_owned()
}

fn short_name(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}
```

---

## R4 — Richer `details_client` for Persistence

### Goal

Replace the single-template persistence sentence with mechanism-aware text that
includes the service/key name, binary path, and timing context.

### New templates

**service:**
```
主機 {host} 上偵測到服務 {service_name} 指向 {binary}（{timing}），
建議確認是否為已知且授權的軟體。
```

**run_key / scheduled_task:**
```
主機 {host} 上，{name} 在登錄檔 Run 機碼／排程工作中新增了執行項目 {binary}（{timing}），
建議確認是否為已知且授權的操作。
```

**winlogon:**
```
主機 {host} 上，Winlogon {value_name} 指向 {command}（{timing}），
若非預期請立即調查。
```

**ifeo:**
```
主機 {host} 上，{key_name} 的 IFEO Debugger 被設定為 {binary}，
此手法幾乎僅用於攻擊，建議立即調查。
```

**timing** helper:
- `last_write` within 7 days → `"2026-06-24 新增"`
- otherwise → `"建立時間較久遠"`

### Implementation

New private helper in `client_text.rs`:

```rust
fn persistence_client_text(host: &str, f: &Finding) -> String { ... }
```

Called from the `"persistence"` arm of `fill_details_client`.

---

## R5 — Richer `details_client` for NetConn

### Goal

Include the owning process name in netconn client text so the analyst knows *who*
is making the connection.

### New template

```
主機 {host} 上，{process_name}（PID {pid}）發起了對外連線至 {remote}，
建議確認連線目標是否屬於正常業務範疇。
```

When `entity.netconn.pid` is None → omit PID clause.
When `entity.process` is available on the finding → use `p.image` short name.
When no process → use "未知程式".

**Note:** The netconn finding's `entity.process` is currently not populated —
the heuristic only populates `entity.netconn`. As part of R5, populate
`entity.process` in `NetConnHeuristic::analyze()` when `owner` is available:

```rust
f.entity = Entity {
    netconn: Some(EntityNetConn { ... }),
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

---

## R6 — Human-Readable `details` Field

### Goal

Replace debug key=value format with natural-language summary in the `details` field,
which appears as the `Details` column in `timeline.csv`.

### Current vs target

| Finding type | Current | Target |
|-------------|---------|--------|
| service | `mechanism=service location=HKLM\...\CoworkVMService command="...cowork-svc.exe"` | `服務 CoworkVMService → cowork-svc.exe (新增: 2026-06-24)` |
| netconn | `tcp 192.168.0.11:65146 -> 104.18.38.233:80 pid=Some(13752)` | `cairn.exe (13752) → 104.18.38.233:80` |
| process | `pid=13752 ppid=16320 image=cairn.exe cmdline=` | `cairn.exe (pid=13752, parent=16320)` |
| run_key | `mechanism=run_key location=HKLM\...\Run command=C:\...\evil.exe` | `Run 鍵: evil.exe → C:\...\evil.exe` |
| winlogon | `mechanism=winlogon location=... command=explorer.exe` | `Winlogon Shell: explorer.exe` |

### Implementation

Change the `f.details = format!(...)` line in each of the four heuristic analyzers:

**`parentchild.rs`:**
```rust
f.details = format!("{} (pid={}, parent={}{})",
    short_name(&p.image), p.pid, p.ppid,
    if p.cmdline.is_empty() { String::new() } else { format!(", cmd={}", p.cmdline) }
);
```

**`netconn.rs`:**
```rust
let proc_name = owner.map(|o| short_name(&o.image)).unwrap_or_else(|| "unknown".into());
f.details = format!("{} ({}) → {}:{}",
    proc_name,
    c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
    c.raddr.as_deref().unwrap_or("-"),
    c.rport.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
);
```

**`persist.rs`:**
```rust
f.details = format_persist_details(p);
```

New helper `format_persist_details`:
```rust
fn format_persist_details(p: &PersistenceRecord) -> String {
    let svc_name = p.location.rsplit('\\').next().unwrap_or(&p.location);
    let bin = p.command.as_deref().unwrap_or("-");
    let bin_short = bin.trim_matches('"').rsplit('\\').next().unwrap_or(bin);
    let timing = p.last_write
        .map(|lw| lw.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".into());
    match p.mechanism.as_str() {
        "service"        => format!("服務 {} → {} ({})", svc_name, bin_short, timing),
        "run_key"        => format!("Run 鍵: {} → {} ({})", svc_name, bin_short, timing),
        "scheduled_task" => format!("排程工作: {} → {} ({})", svc_name, bin_short, timing),
        "winlogon"       => format!("Winlogon {}: {}", p.value.as_deref().unwrap_or("?"), bin),
        "ifeo"           => format!("IFEO {}: {} → {}", svc_name, svc_name, bin_short),
        "startup"        => format!("Startup: {} ({})", bin_short, timing),
        _                => format!("{}: {} → {}", p.mechanism, svc_name, bin_short),
    }
}
```

---

## Schema Impact

| Field | Change |
|-------|--------|
| `Finding.details` | Format only — same field, new string content. Not schema change. |
| `Finding.details_client` | Format only — same optional string. Not schema change. |
| `Finding.entity.process` | Now also populated on netconn findings (R5). Additive, backward-compat. |

`cairn.finding/1` schema version unchanged. Existing consumers (tests, verify, bodyfile) unaffected.

---

## Test Plan

### R1 Inbox-service suppress
- `inbox_svchost_old_is_suppressed()` — svchost -k DcomLaunch, 400 days old → Score::default()
- `inbox_driver_old_is_suppressed()` — `System32\drivers\tcpip.sys`, old → suppressed
- `inbox_recent_bypasses_suppress()` — svchost -k ClipboardSvcGroup, 3 days old → score ≥ 15
- `non_inbox_always_scores()` — `"C:\Program Files\Vendor\app.exe"`, old → service base score
- `windowsapps_not_inbox()` — CoworkVMService path → not suppressed
- `driverstore_not_suppressed_abs()` — `%SystemRoot%\System32\DriverStore\FileRepository\...\drv.exe` (old) → not suppressed
- `driverstore_not_suppressed_rel()` — `System32\DriverStore\FileRepository\...\drv.sys` (old) → not suppressed

### R2 Self-PID exclusion
- `own_pid_process_not_flagged()` — insert Record::Process with pid=own_pid, verify no finding
- `own_pid_netconn_not_flagged()` — insert Record::NetConn with pid=Some(own_pid), verify no finding
- `other_pids_still_flagged()` — non-own pid still produces findings as before

### R3 entity_path registry fallback
- `registry_data_used_as_path()` — entity.registry with data=`"C:\x\app.exe"` → "app.exe"
- `registry_value_fallback()` — data empty, value="MyService" → "MyService"
- `registry_key_segment_fallback()` — data and value empty, key=`HKLM\...\ServiceFoo` → "ServiceFoo"

### R4 + R5 details_client content
- `service_client_text_includes_name_and_binary()` — cowork-svc.exe in text
- `service_client_text_includes_timing()` — new service → "新增" in text; old service → "較久遠"
- `winlogon_client_text_mentions_value_name()` — "Shell" or "Userinit" in text
- `ifeo_client_text_mentions_severity()` — "幾乎僅用於攻擊" in text
- `netconn_client_text_includes_process_name()` — process image short name in text

### R6 details field format
- `service_details_format()` — "服務 CoworkVMService → cowork-svc.exe" in details
- `netconn_details_format()` — "cairn.exe (13752) → 104.18.38.233:80"
- `process_details_format()` — "powershell.exe (pid=200, parent=100)"

---

## Definition of Done

- [ ] `cargo test --workspace` passes (448 + new tests)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` zero warnings
- [ ] Live run `live-20260626` re-run shows ≤ 20 service findings in timeline.csv
- [ ] No cairn.exe / cairn HTTP connections in findings
- [ ] details_client for CoworkVMService mentions "cowork-svc.exe" not "未知程式"
- [ ] timeline.csv Details column is human-readable Chinese/mixed format
- [ ] Schema version unchanged; `cairn verify` still passes on old manifests
