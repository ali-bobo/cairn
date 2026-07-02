# IR Snapshot Panels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把已收集但埋在 records.jsonl 的 IR 關鍵資料（對外連線 / 執行中程序 / 近期執行證據 /
可疑檔案活動 / 登入 session）攤成 report.html 的折疊面板，讓調查者一眼看到主機現況。

**Architecture:** 主解鎖是 `html_report` 簽名加 `records: &[Record]` 參數（連帶 OutputSink
trait 與所有 caller）。四個面板純呈現既有 Record；一個新 `LogonSessionCollector`（cairn-collectors-win
unsafe FFI）新增 `Record::LogonSession`。純函式維持，零新 heuristic / gate / Sigma 規則。

**Tech Stack:** Rust workspace（cairn-core / cairn-report / cairn-collectors / cairn-collectors-win /
cairn-cli）、windows crate 0.62.2。零新外部依賴（僅開 windows crate 新 feature）。

**Spec:** `docs/dev-history/specs/2026-07-03-ir-snapshot-panels-design.md`

**每個 task 開工前：**
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
```
**每個 task 驗收：**`cargo check --workspace` → task 指定測試 → `cargo clippy --workspace --all-targets -- -D warnings`。

---

## File Structure（全計畫觸及的檔案）

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-core/src/traits.rs` | Modify | OutputSink::write_html_report 簽名加 records |
| `crates/cairn-core/src/record.rs` | Modify（段3）| Record::LogonSession 變體 + LogonSessionRecord |
| `crates/cairn-report/src/html.rs` | Modify | html_report 加 records 參數 + 五面板 + 本地 public-IP 判斷 |
| `crates/cairn-report/src/lib.rs` | Modify | DirSink::write_html_report 加 records 參數 |
| `crates/cairn-cli/src/main.rs` | Modify | 兩處 write_html_report caller 加 records |
| `crates/cairn-collectors-win/src/logon.rs` | Create（段3）| unsafe LSA/WTS session 列舉 |
| `crates/cairn-collectors-win/src/lib.rs` | Modify（段3）| pub mod logon |
| `crates/cairn-collectors-win/Cargo.toml` | Modify（段3）| windows crate 新 feature |
| `crates/cairn-collectors/src/logon_session.rs` | Create（段3）| 安全 wrapper + LogonSessionCollector |
| `crates/cairn-collectors/src/lib.rs` | Modify（段3）| pub mod logon_session |

---

## 段 1（Task 1–5）：解鎖 records 進報告 + 前三面板

### Task 1: html_report 簽名加 records 參數 + 全 caller 連鎖（純機械，先讓它編譯）

**Files:**
- Modify: `crates/cairn-core/src/traits.rs`
- Modify: `crates/cairn-report/src/html.rs`
- Modify: `crates/cairn-report/src/lib.rs`
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: `traits.rs` — OutputSink::write_html_report 簽名加 records**

找到 `fn write_html_report`（約 69 行），改為：

```rust
    fn write_html_report(
        &mut self,
        _findings: &[Finding],
        _observations: &[Observation],
        _records: &[Record],
        _manifest: &crate::manifest::Manifest,
    ) -> Result<()> {
        Ok(())
    }
```

`Record` 已在此檔 `use crate::{... record::Record ...}` 匯入（analyze 用到）；若未匯入則補。

- [ ] **Step 2: `html.rs` — html_report 簽名加 records（暫不使用，先編譯過）**

找到 `pub fn html_report`（約 64 行），改為：

```rust
pub fn html_report(
    findings: &[Finding],
    observations: &[cairn_core::Observation],
    records: &[cairn_core::Record],
    manifest: &Manifest,
) -> String {
```

函式體暫時加一行 `let _ = records;` 避免 unused 警告（Task 2 起使用）。

- [ ] **Step 3: `lib.rs` — DirSink::write_html_report 加 records 並轉傳**

找到 DirSink 的 `fn write_html_report`（約 318 行），改為：

```rust
    fn write_html_report(
        &mut self,
        findings: &[Finding],
        observations: &[cairn_core::Observation],
        records: &[cairn_core::Record],
        manifest: &Manifest,
    ) -> Result<()> {
        let html = crate::html::html_report(findings, observations, records, manifest);
        self.write_file("report.html", html.as_bytes())
    }
```

- [ ] **Step 4: `main.rs` — 兩處 caller 加 records**

evtx 路徑（約 571 行）——evtx 模式無 live records，傳空：
```rust
            sink.write_html_report(&findings, &[], &[], &manifest)?;
```
live 路徑（約 948 行）——傳 outcome.records：
```rust
            sink.write_html_report(&outcome.findings, &outcome.observations, &outcome.records, &manifest)?;
```

- [ ] **Step 5: 修測試呼叫點**

搜尋 `write_html_report(` 與 `html_report(` 在測試中的呼叫（cairn-report/src/html.rs 與 lib.rs 的 `#[cfg(test)]`），
每處加一個 `&[]`（空 records slice）參數對齊新簽名。用
`grep -rn "html_report(" crates/` 找全部。

- [ ] **Step 6: 編譯 + 測試 + commit**

Run: `cargo test --workspace --exclude cairn-updater`
Expected: 全綠（純簽名改動，行為不變）。
Run: `cargo clippy --workspace --all-targets -- -D warnings`

```bash
git add -A crates/
git commit -m "refactor(report): thread records into html_report (unlocks IR panels; no behavior change)"
```

---

### Task 2: 對外連線面板（NetConnRecord）

**Files:**
- Modify: `crates/cairn-report/src/html.rs`

- [ ] **Step 1: 加本地 public-IP 判斷 helper（cairn-report 不依賴 cairn-heur，故本地實作）**

在 html.rs 的 `esc` 等 helper 附近加：

```rust
/// Minimal public-IPv4 test for panel sorting only (cairn-report doesn't depend on
/// cairn-heur's score::is_public_ipv4). Non-parseable or private/loopback/link-local
/// → false. This is a sort hint, not a security judgement, so the simplified check is fine.
fn is_public_ipv4_hint(addr: &str) -> bool {
    use std::net::Ipv4Addr;
    match addr.parse::<Ipv4Addr>() {
        Ok(ip) => !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified(),
        Err(_) => false,
    }
}
```

- [ ] **Step 2: 加面板建構函式**

在 `html_report` 函式之外（module 層級）加：

```rust
/// Outbound-connections panel: established + listening only; public-remote sorted first.
fn netconn_panel(records: &[cairn_core::Record]) -> String {
    use cairn_core::record::Record;
    let mut conns: Vec<&cairn_core::record::NetConnRecord> = records
        .iter()
        .filter_map(|r| match r {
            Record::NetConn(c) => Some(c),
            _ => None,
        })
        .filter(|c| {
            let st = c.state.as_deref().unwrap_or("").to_ascii_uppercase();
            st.is_empty() || st == "ESTABLISHED" || st == "LISTEN" || st == "LISTENING"
        })
        .collect();
    if conns.is_empty() {
        return String::new();
    }
    let public_count = conns
        .iter()
        .filter(|c| c.raddr.as_deref().is_some_and(is_public_ipv4_hint))
        .count();
    // Public-remote first, then by remote addr.
    conns.sort_by(|a, b| {
        let ap = a.raddr.as_deref().is_some_and(is_public_ipv4_hint);
        let bp = b.raddr.as_deref().is_some_and(is_public_ipv4_hint);
        bp.cmp(&ap).then_with(|| a.raddr.cmp(&b.raddr))
    });
    let rows: String = conns
        .iter()
        .map(|c| {
            let remote = match (c.raddr.as_deref(), c.rport) {
                (Some(a), Some(p)) => format!("{a}:{p}"),
                (Some(a), None) => a.to_string(),
                _ => "-".into(),
            };
            format!(
                "<tr><td>{}</td><td>{}:{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&c.proto),
                esc(&c.laddr),
                c.lport,
                esc(&remote),
                esc(c.state.as_deref().unwrap_or("-")),
                c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            )
        })
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">對外連線 ({} 條，其中 {} 條連往公網)</h2></summary>\
         <table><tr><th>協定</th><th>本地</th><th>遠端</th><th>狀態</th><th>PID</th></tr>{}</table></details>",
        conns.len(),
        public_count,
        rows
    )
}
```

- [ ] **Step 2b: 在 `html_report` 內呼叫並插入模板**

在 `html_report` 內、`obs_html` 計算之後加：
```rust
    let netconn_html = netconn_panel(records);
```
在最終 `format!` 模板中，`{obs_html}` 之前插入 `{netconn_html}`（面板在 findings 之後、盤點之前）。
並移除 Task 1 Step 2 暫加的 `let _ = records;`。

- [ ] **Step 3: 測試**

在 html.rs 測試 mod 加：
```rust
    fn netconn(proto: &str, raddr: Option<&str>, rport: Option<u16>, state: &str, pid: Option<u32>)
        -> cairn_core::Record {
        cairn_core::Record::NetConn(cairn_core::record::NetConnRecord {
            proto: proto.into(),
            laddr: "0.0.0.0".into(),
            lport: 1234,
            raddr: raddr.map(String::from),
            rport,
            state: Some(state.into()),
            pid,
        })
    }

    #[test]
    fn netconn_panel_lists_and_counts_public() {
        let recs = vec![
            netconn("tcp", Some("8.8.8.8"), Some(443), "ESTABLISHED", Some(100)),
            netconn("tcp", Some("192.168.1.5"), Some(445), "ESTABLISHED", Some(200)),
            netconn("tcp", None, None, "TIME_WAIT", None), // filtered out
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("對外連線 (2 條，其中 1 條連往公網)"), "html: missing panel");
        assert!(html.contains("8.8.8.8:443"));
        // public remote sorted first: 8.8.8.8 row appears before 192.168 row
        let pub_pos = html.find("8.8.8.8").unwrap();
        let priv_pos = html.find("192.168.1.5").unwrap();
        assert!(pub_pos < priv_pos, "public conn must sort first");
    }

    #[test]
    fn netconn_panel_absent_when_no_conns() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(!html.contains("對外連線"));
    }
```

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test -p cairn-report`

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): outbound-connections IR panel (established/listening, public-remote first)"
```

---

### Task 3: 執行中程序面板（ProcessRecord）

**Files:**
- Modify: `crates/cairn-report/src/html.rs`

- [ ] **Step 1: 加面板函式**

```rust
/// Running-processes panel: unsigned first, then signature-unknown.
fn process_panel(records: &[cairn_core::Record]) -> String {
    use cairn_core::record::Record;
    let mut procs: Vec<&cairn_core::record::ProcessRecord> = records
        .iter()
        .filter_map(|r| match r {
            Record::Process(p) => Some(p),
            _ => None,
        })
        .collect();
    if procs.is_empty() {
        return String::new();
    }
    let unsigned_count = procs.iter().filter(|p| p.signed == Some(false)).count();
    // rank: unsigned(0) < unknown(1) < signed(2)
    fn sig_rank(s: Option<bool>) -> u8 {
        match s {
            Some(false) => 0,
            None => 1,
            Some(true) => 2,
        }
    }
    procs.sort_by(|a, b| sig_rank(a.signed).cmp(&sig_rank(b.signed)).then_with(|| a.pid.cmp(&b.pid)));
    let rows: String = procs
        .iter()
        .map(|p| {
            let sig = match p.signed {
                Some(true) => "已簽章",
                Some(false) => "未簽章",
                None => "未知",
            };
            let cmd = p.cmdline.chars().take(120).collect::<String>();
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td style=\"font-size:0.8em;color:#6b7280\">{}</td></tr>",
                p.pid,
                p.ppid,
                esc(&p.image),
                esc(sig),
                esc(p.integrity.as_deref().unwrap_or("-")),
                esc(&cmd),
            )
        })
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">執行中程序 ({} 個，其中 {} 個未簽章)</h2></summary>\
         <table><tr><th>PID</th><th>PPID</th><th>映像路徑</th><th>簽章</th><th>完整性</th><th>命令列</th></tr>{}</table></details>",
        procs.len(),
        unsigned_count,
        rows
    )
}
```

- [ ] **Step 2: 呼叫 + 插入模板**

`html_report` 內加 `let process_html = process_panel(records);`，模板在 `{netconn_html}` 之後插入 `{process_html}`。

- [ ] **Step 3: 測試**

```rust
    fn proc(pid: u32, image: &str, signed: Option<bool>) -> cairn_core::Record {
        cairn_core::Record::Process(cairn_core::record::ProcessRecord {
            pid, ppid: 4, image: image.into(), cmdline: format!("{image} --run"),
            signed, signer: None, binary_sha256: None, integrity: Some("medium".into()),
            user: None, start_time: None,
        })
    }

    #[test]
    fn process_panel_lists_unsigned_first() {
        let recs = vec![
            proc(100, r"C:\Windows\System32\svchost.exe", Some(true)),
            proc(200, r"C:\Users\a\AppData\Roaming\x.exe", Some(false)),
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("執行中程序 (2 個，其中 1 個未簽章)"));
        let unsigned_pos = html.find("x.exe").unwrap();
        let signed_pos = html.find("svchost.exe").unwrap();
        assert!(unsigned_pos < signed_pos, "unsigned proc must sort first");
    }
```

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test -p cairn-report`

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): running-processes IR panel (unsigned first)"
```

---

### Task 4: 近期執行證據面板（ExecutionRecord）

**Files:**
- Modify: `crates/cairn-report/src/html.rs`

- [ ] **Step 1: 加面板函式**

```rust
/// Recent-execution panel: last_run newest first; prefetch flagged filename-only.
fn execution_panel(records: &[cairn_core::Record]) -> String {
    use cairn_core::record::Record;
    use std::collections::BTreeSet;
    let mut execs: Vec<&cairn_core::record::ExecutionRecord> = records
        .iter()
        .filter_map(|r| match r {
            Record::Execution(e) => Some(e),
            _ => None,
        })
        .collect();
    if execs.is_empty() {
        return String::new();
    }
    let sources: BTreeSet<&str> = execs.iter().map(|e| e.source.as_str()).collect();
    // newest last_run first (None sorts last)
    execs.sort_by(|a, b| b.last_run.cmp(&a.last_run));
    let rows: String = execs
        .iter()
        .map(|e| {
            let path = if e.source == "prefetch" {
                format!("{}（僅檔名）", e.path)
            } else {
                e.path.clone()
            };
            let fmt_ts = |t: &Option<chrono::DateTime<chrono::Utc>>| {
                t.map(|t| t.format("%Y-%m-%d %H:%MZ").to_string()).unwrap_or_else(|| "-".into())
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&e.source),
                esc(&path),
                e.run_count.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                esc(&fmt_ts(&e.first_run)),
                esc(&fmt_ts(&e.last_run)),
            )
        })
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">近期執行證據 ({} 筆，來自 {} 種來源)</h2></summary>\
         <table><tr><th>來源</th><th>路徑</th><th>執行次數</th><th>首次</th><th>末次</th></tr>{}</table></details>",
        execs.len(),
        sources.len(),
        rows
    )
}
```

- [ ] **Step 2: 呼叫 + 插入模板**

`let execution_html = execution_panel(records);`，模板 `{process_html}` 之後插入 `{execution_html}`。

- [ ] **Step 3: 測試**

```rust
    fn exec(source: &str, path: &str, last: Option<(i32,u32,u32,u32,u32)>) -> cairn_core::Record {
        use chrono::TimeZone;
        let last_run = last.map(|(y,mo,d,h,mi)| Utc.with_ymd_and_hms(y,mo,d,h,mi,0).unwrap());
        cairn_core::Record::Execution(cairn_core::record::ExecutionRecord {
            source: source.into(), path: path.into(), first_run: None, last_run,
            run_count: Some(3), sha1: None, user_sid: None, execution_confirmed: Some(true),
        })
    }

    #[test]
    fn execution_panel_newest_first_and_prefetch_flagged() {
        let recs = vec![
            exec("shimcache", r"C:\old.exe", Some((2026,1,1,0,0))),
            exec("prefetch", "NEW.EXE", Some((2026,6,1,0,0))),
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("近期執行證據 (2 筆，來自 2 種來源)"));
        assert!(html.contains("NEW.EXE（僅檔名）"));
        let new_pos = html.find("NEW.EXE").unwrap();
        let old_pos = html.find("old.exe").unwrap();
        assert!(new_pos < old_pos, "newest last_run must sort first");
    }
```

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test -p cairn-report`

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): recent-execution IR panel (newest last_run first, prefetch filename-flagged)"
```

---

### Task 5: 段 1 真機驗收

**Files:** 無（驗證 only）

- [ ] **Step 1: build + 真機掃描**

```powershell
cargo build --release -p cairn-cli
Copy-Item "$env:CARGO_TARGET_DIR\release\cairn.exe" .\dist\cairn-forensics\cairn.exe -Force
.\dist\cairn-forensics\cairn.exe run --target live --output .\out-panels-s1\
```

- [ ] **Step 2: 驗收斷言**

開 `out-panels-s1\report.html`，確認：
1. 「對外連線」面板存在且有內容（至少有 established 連線），公網連線排前。
2. 「執行中程序」面板存在，未簽章程序排前。
3. 「近期執行證據」面板存在（prefetch/shimcache 等有資料），末次執行新的排前。
4. findings 數量不因面板增加（純呈現不產生 finding）。
5. 三面板都是折疊的（`<details>`），不干擾既有 findings/盤點。

若某面板空：檢查該 collector 是否有進 records（`records.jsonl` grep `"kind":"net_conn"` / `"process"` / `"execution"`）。

段 1 完成後使用者最直接的痛（跑完看得到在跑什麼、連去哪、執行了什麼）即解決。

---

## 段 2（Task 6）：可疑檔案活動面板（USN + MOTW）

### Task 6: 可疑檔案活動面板 + 200 筆量控

**Files:**
- Modify: `crates/cairn-report/src/html.rs`

- [ ] **Step 1: 加面板函式（USN create/rename + MOTW 檔案，MOTW 排前，USN 截斷 200）**

```rust
/// Suspicious-file-activity panel: MOTW-tagged files first (download provenance),
/// then recent USN create/rename events (capped at 200; total noted in summary).
fn file_activity_panel(records: &[cairn_core::Record]) -> String {
    use cairn_core::record::Record;
    const USN_CAP: usize = 200;

    let motw: Vec<&cairn_core::record::FileMetaRecord> = records
        .iter()
        .filter_map(|r| match r {
            Record::FileMeta(m) if m.zone_identifier.is_some() => Some(m),
            _ => None,
        })
        .collect();

    let mut usn: Vec<&cairn_core::record::UsnEventRecord> = records
        .iter()
        .filter_map(|r| match r {
            Record::UsnEvent(u) => Some(u),
            _ => None,
        })
        .filter(|u| {
            let re = u.reason.to_ascii_lowercase();
            re.contains("create") || re.contains("rename")
        })
        .collect();

    if motw.is_empty() && usn.is_empty() {
        return String::new();
    }
    let usn_total = usn.len();
    usn.sort_by(|a, b| b.ts.cmp(&a.ts)); // newest first
    usn.truncate(USN_CAP);

    let motw_rows: String = motw
        .iter()
        .map(|m| {
            format!(
                "<tr><td>MOTW</td><td>{}</td><td>{}</td></tr>",
                esc(&m.path),
                esc(m.zone_identifier.as_deref().unwrap_or("-")),
            )
        })
        .collect();
    let usn_rows: String = usn
        .iter()
        .map(|u| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&u.reason),
                esc(&u.path),
                esc(&u.ts.format("%Y-%m-%d %H:%MZ").to_string()),
            )
        })
        .collect();
    let usn_note = if usn_total > USN_CAP {
        format!("（顯示前 {USN_CAP} 筆，共 {usn_total} 筆，完整見 records.jsonl）")
    } else {
        String::new()
    };
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">可疑檔案活動 ({} 個 MOTW 檔案 / {} 筆近期檔案事件)</h2></summary>\
         <p style=\"font-size:0.8em;color:#6b7280\">{}</p>\
         <table><tr><th>類型/動作</th><th>路徑</th><th>詳細</th></tr>{}{}</table></details>",
        motw.len(),
        usn_total,
        usn_note,
        motw_rows,
        usn_rows,
    )
}
```

- [ ] **Step 2: 呼叫 + 插入模板**

`let file_activity_html = file_activity_panel(records);`，模板 `{execution_html}` 之後插入 `{file_activity_html}`。

- [ ] **Step 3: 測試**

```rust
    fn usn(reason: &str, path: &str, ymd: (i32,u32,u32)) -> cairn_core::Record {
        use chrono::TimeZone;
        cairn_core::Record::UsnEvent(cairn_core::record::UsnEventRecord {
            ts: Utc.with_ymd_and_hms(ymd.0, ymd.1, ymd.2, 0, 0, 0).unwrap(),
            path: path.into(), reason: reason.into(), mft_ref: 1,
        })
    }
    fn motw_file(path: &str, zone: &str) -> cairn_core::Record {
        cairn_core::Record::FileMeta(cairn_core::record::FileMetaRecord {
            path: path.into(), size: 0, sha256: None, si_btime: None, si_mtime: None,
            fn_btime: None, fn_mtime: None, zone_identifier: Some(zone.into()), path_complete: None,
        })
    }

    #[test]
    fn file_activity_panel_motw_and_usn_filtered() {
        let recs = vec![
            usn("File_Create", r"C:\Users\a\Downloads\dropper.exe", (2026,6,1)),
            usn("Basic_Info_Change", r"C:\noise.txt", (2026,6,2)), // filtered (not create/rename)
            motw_file(r"C:\Users\a\Downloads\dropper.exe", "ZoneId=3"),
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("可疑檔案活動 (1 個 MOTW 檔案 / 1 筆近期檔案事件)"));
        assert!(html.contains("ZoneId=3"));
        assert!(!html.contains("noise.txt"), "non-create/rename USN filtered");
        // MOTW row before USN row
        let motw_pos = html.find("ZoneId=3").unwrap();
        let usn_pos = html.rfind("File_Create").unwrap();
        assert!(motw_pos < usn_pos, "MOTW must sort before USN events");
    }

    #[test]
    fn file_activity_panel_caps_usn_at_200() {
        let mut recs = Vec::new();
        for i in 0..250 {
            recs.push(usn("File_Create", &format!(r"C:\f{i}.exe"), (2026,6,1)));
        }
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("共 250 筆"), "must note total when capped");
        assert!(html.contains("顯示前 200 筆"));
    }
```

- [ ] **Step 4: 跑測試 + 真機驗收 + commit**

Run: `cargo test -p cairn-report`
真機（需 admin 讀 USN）：`cairn.exe run --target live --output .\out-panels-s2\`，
確認「可疑檔案活動」面板有內容、USN 若 >200 有截斷註記。

```bash
git add crates/cairn-report/src/html.rs
git commit -m "feat(report): suspicious-file-activity IR panel (MOTW first, USN create/rename capped at 200)"
```

---

## 段 3（Task 7–10）：LogonSession collector + 面板

### Task 7: cairn-core — Record::LogonSession 變體

**Files:**
- Modify: `crates/cairn-core/src/record.rs`

- [ ] **Step 1: Record enum 加變體**

在 `pub enum Record { ... }` 加 `LogonSession(LogonSessionRecord),`（在 Execution 後）。

- [ ] **Step 2: 加 struct（在 ExecutionRecord 定義後）**

```rust
/// A live logon session (LSA/WTS enumeration). "Who is using the host right now."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonSessionRecord {
    pub user: String,           // domain\username
    pub logon_type: String,     // Interactive|RemoteInteractive|Network|Service|...
    pub logon_time: Option<DateTime<Utc>>,
    pub source: Option<String>, // source host/IP for network/RDP sessions
    pub session_id: Option<u32>,
}
```

- [ ] **Step 3: 測試（往返 + kind tag）**

```rust
    #[test]
    fn logon_session_record_kind_tag() {
        let rec = Record::LogonSession(LogonSessionRecord {
            user: r"DOMAIN\alice".into(),
            logon_type: "RemoteInteractive".into(),
            logon_time: None,
            source: Some("10.0.0.5".into()),
            session_id: Some(2),
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"kind\":\"logon_session\""));
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }
```

- [ ] **Step 4: 跑測試 + commit**

Run: `cargo test -p cairn-core`

```bash
git add crates/cairn-core/src/record.rs
git commit -m "feat(core): Record::LogonSession variant (live logon session enumeration)"
```

---

### Task 8: cairn-collectors-win — logon.rs unsafe LSA/WTS 列舉

**Files:**
- Modify: `crates/cairn-collectors-win/Cargo.toml`
- Create: `crates/cairn-collectors-win/src/logon.rs`
- Modify: `crates/cairn-collectors-win/src/lib.rs`

- [ ] **Step 1: Cargo.toml 加 windows feature**

在 `windows` 的 `features = [...]` 清單加（列舉互動 session 用 WTS，最簡且不需 SeTcbPrivilege）：
```toml
  "Win32_System_RemoteDesktop",
```

（實作者：先 `cargo build -p cairn-collectors-win` 確認此 feature 提供 `WTSEnumerateSessionsW` /
`WTSQuerySessionInformationW` / `WTS_SESSION_INFO` / `WTSUserName` / `WTSClientAddress`。若某符號在
另一 feature 下，補上該 feature——windows crate 符號散落多 feature 是常態，以編譯器錯誤為準補齊。）

- [ ] **Step 2: 建 `logon.rs`——unsafe FFI，回傳純資料 struct（不洩漏 WinAPI 型別）**

```rust
//! Live logon-session enumeration via WTS (WTSEnumerateSessions). Read-only, official
//! API, EDR-visible (golden rule 1/3). The single unsafe surface stays behind a safe
//! wrapper returning owned plain data.
use windows::Win32::System::RemoteDesktop::{
    WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSClientAddress,
    WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSConnectStateClass,
};
use windows::core::PWSTR;

/// Owned, WinAPI-free view of one interactive logon session.
#[derive(Debug, Clone)]
pub struct WtsSession {
    pub session_id: u32,
    pub user: String,
    pub state_active: bool,
    pub client_address: Option<String>,
}

/// Enumerate WTS sessions. Best-effort: on any API failure returns an empty Vec
/// (the collector wrapper turns "no data" into a graceful skip). Never panics.
pub fn enumerate_sessions() -> Vec<WtsSession> {
    let mut out = Vec::new();
    unsafe {
        let mut p_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;
        if WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &mut p_info,
            &mut count,
        )
        .is_err()
        {
            return out;
        }
        let sessions = std::slice::from_raw_parts(p_info, count as usize);
        for s in sessions {
            let user = query_string(s.SessionId, WTSUserName).unwrap_or_default();
            if user.is_empty() {
                continue; // skip listener/services session-0 noise with no user
            }
            let client_address = query_string(s.SessionId, WTSClientAddress);
            out.push(WtsSession {
                session_id: s.SessionId,
                user,
                state_active: s.State == WTSActive,
                client_address,
            });
        }
        WTSFreeMemory(p_info as *mut _);
    }
    out
}

/// Query one WTS string property for a session; None on failure/empty. Total.
unsafe fn query_string(session_id: u32, info_class: WTSConnectStateClass) -> Option<String> {
    let mut buf: PWSTR = PWSTR::null();
    let mut bytes: u32 = 0;
    if WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE,
        session_id,
        std::mem::transmute(info_class),
        &mut buf,
        &mut bytes,
    )
    .is_err()
        || buf.is_null()
    {
        return None;
    }
    let s = buf.to_string().ok().filter(|s| !s.is_empty());
    WTSFreeMemory(buf.as_ptr() as *mut _);
    s
}
```

**實作者注意**：windows 0.62 的 WTS 常數/型別（`WTSUserName`/`WTSClientAddress` 是 `WTS_INFO_CLASS`
newtype，非 `WTSConnectStateClass`——上面型別是示意，以實際 crate 定義為準；`WTSClientAddress` 回傳的是
`WTS_CLIENT_ADDRESS` 結構非字串，需另外解析 IP bytes）。**先讀安裝的 windows crate 源碼確認每個
符號的真實型別與簽名**（同專案既有 collector 的作法），把 `query_string` 對 `WTSClientAddress` 的部分
改成解析 `WTS_CLIENT_ADDRESS.Address` bytes 為點分十進位；若過於複雜，`client_address` 這版先回 None
（誠實留空，NFR12），IP 解析列為後續。核心是 session_id + user + state 一定要正確。

- [ ] **Step 3: lib.rs 加 `pub mod logon;`**

- [ ] **Step 4: 編譯**

Run: `cargo build -p cairn-collectors-win`（Windows only；此 crate 在非 Windows 是空殼）
Expected: 編譯過。此 task 無單元測試（純 FFI 列舉，靠段 3 e2e 驗證）。

- [ ] **Step 5: commit**

```bash
git add crates/cairn-collectors-win/
git commit -m "feat(collectors-win): WTS logon-session enumeration (unsafe FFI, safe owned wrapper)"
```

---

### Task 9: cairn-collectors — LogonSessionCollector 安全包裝

**Files:**
- Create: `crates/cairn-collectors/src/logon_session.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`

- [ ] **Step 1: 建 `logon_session.rs`**

```rust
//! LogonSessionCollector: maps WTS session enumeration to Record::LogonSession.
//! #![forbid(unsafe_code)] — the unsafe FFI lives in cairn-collectors-win::logon.
use cairn_core::record::{LogonSessionRecord, Record};
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::Result;

pub struct LogonSessionCollector;

impl Collector for LogonSessionCollector {
    fn name(&self) -> &str {
        "logon_session"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        #[cfg(windows)]
        {
            let sessions = cairn_collectors_win::logon::enumerate_sessions();
            Ok(sessions
                .into_iter()
                .map(|s| {
                    Record::LogonSession(LogonSessionRecord {
                        user: s.user,
                        // WTS active/connected interactive sessions; refine type later.
                        logon_type: if s.client_address.is_some() {
                            "RemoteInteractive".into()
                        } else {
                            "Interactive".into()
                        },
                        logon_time: None, // WTS has no reliable logon timestamp; honest None
                        source: s.client_address,
                        session_id: Some(s.session_id),
                    })
                })
                .collect())
        }
        #[cfg(not(windows))]
        {
            let _ = _ctx;
            Ok(vec![])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_name_is_logon_session() {
        assert_eq!(LogonSessionCollector.name(), "logon_session");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_yields_empty() {
        let cfg = cairn_core::Config::default();
        let ctx = CollectCtx { config: &cfg, admin: false, se_backup: false, se_debug: false };
        assert!(LogonSessionCollector.collect(&ctx).unwrap().is_empty());
    }
}
```

**實作者注意**：`cairn-collectors` 需依賴 `cairn-collectors-win`（查證 Cargo.toml 是否已有；proc/net
collector 已用它，應已有 `#[cfg(windows)]` 依賴）。`Config::default()` / `CollectCtx` 欄位以實際定義為準。

- [ ] **Step 2: lib.rs 加 `pub mod logon_session;`**

- [ ] **Step 3: 跑測試 + commit**

Run: `cargo test -p cairn-collectors logon_session::`

```bash
git add crates/cairn-collectors/src/logon_session.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(collectors): LogonSessionCollector (safe wrapper over WTS enumeration)"
```

---

### Task 10: 接線 collector + 登入 session 面板 + 段 3 真機驗收

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`
- Modify: `crates/cairn-report/src/html.rs`

- [ ] **Step 1: main.rs 接進 live collector 清單**

在 proc/net collector 加入處（約 795–798 行）之後加：
```rust
                collectors.push(Box::new(cairn_collectors::logon_session::LogonSessionCollector));
```
（放在 AVAILABLE 且非 minimal profile 的分支，與 proc/net 同層；確認 selection gating 一致。）

- [ ] **Step 2: html.rs 加登入 session 面板**

```rust
/// Logon-session panel: RemoteInteractive (RDP) first.
fn logon_panel(records: &[cairn_core::Record]) -> String {
    use cairn_core::record::Record;
    let mut sessions: Vec<&cairn_core::record::LogonSessionRecord> = records
        .iter()
        .filter_map(|r| match r {
            Record::LogonSession(s) => Some(s),
            _ => None,
        })
        .collect();
    if sessions.is_empty() {
        return String::new();
    }
    let remote_count = sessions
        .iter()
        .filter(|s| s.logon_type.contains("Remote"))
        .count();
    // remote first
    sessions.sort_by(|a, b| {
        let ar = a.logon_type.contains("Remote");
        let br = b.logon_type.contains("Remote");
        br.cmp(&ar).then_with(|| a.user.cmp(&b.user))
    });
    let rows: String = sessions
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&s.user),
                esc(&s.logon_type),
                s.session_id.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
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
}
```

- [ ] **Step 3: 呼叫 + 插入模板**

`let logon_html = logon_panel(records);`，模板 `{file_activity_html}` 之後插入 `{logon_html}`。

- [ ] **Step 4: 測試**

```rust
    fn session(user: &str, ltype: &str, sid: u32, source: Option<&str>) -> cairn_core::Record {
        cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
            user: user.into(), logon_type: ltype.into(), logon_time: None,
            source: source.map(String::from), session_id: Some(sid),
        })
    }

    #[test]
    fn logon_panel_remote_first() {
        let recs = vec![
            session(r"PC\alice", "Interactive", 1, None),
            session(r"DOM\bob", "RemoteInteractive", 2, Some("10.0.0.5")),
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("登入 session (2 個，其中 1 個遠端)"));
        let remote_pos = html.find("bob").unwrap();
        let local_pos = html.find("alice").unwrap();
        assert!(remote_pos < local_pos, "remote session must sort first");
    }
```

- [ ] **Step 5: 全 workspace 測試 + clippy + 真機 e2e**

```powershell
cargo test --workspace --exclude cairn-updater
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p cairn-cli
Copy-Item "$env:CARGO_TARGET_DIR\release\cairn.exe" .\dist\cairn-forensics\cairn.exe -Force
.\dist\cairn-forensics\cairn.exe run --target live --output .\out-panels-s3\
```

驗收：`out-panels-s3\report.html` 五個面板全部有內容（連線/程序/執行/檔案/session）；
`records.jsonl` grep `"kind":"logon_session"` 至少一筆（當前互動 session）；findings 不因面板增加。

- [ ] **Step 6: 更新 REMAINING-WORK.md + 最終 commit**

在 REMAINING-WORK.md 記錄「IR 快照面板完成」，並註明 FUTURE 項：登入 session 的 logon_time /
WTS client IP 解析 / DNS collector / 無檔案 spec（FUTURE-fileless-attack-coverage-design.md）。

```bash
git add -A
git commit -m "feat: IR snapshot panels complete — 5 panels in report.html (conn/proc/exec/file/logon)

Spec: docs/dev-history/specs/2026-07-03-ir-snapshot-panels-design.md"
```

---

## Self-Review 紀錄（plan 完成後自查）

1. **Spec 覆蓋**：§4.1 對外連線（T2）、§4.2 執行中程序（T3）、§4.3 近期執行（T4）、
   §4.4 可疑檔案 USN+MOTW（T6）、§4.5 登入 session（T7–T10）、§5 新 collector（T8–T9）、
   §6 簽名連鎖（T1）、§8 測試（各 task 內）、§10 分段（段1=T1–5/段2=T6/段3=T7–10）。無缺口。
2. **Placeholder**：T8 的 WTS FFI 型別標「以實際 crate 定義為準」＋ client IP 解析可先回 None——
   這是 windows crate 符號散落的已知現實，給了明確的降級路徑（session_id+user+state 必對，IP 可延後），
   非空白 placeholder。
3. **型別一致**：LogonSessionRecord 欄位（user/logon_type/logon_time/source/session_id）在 T7 定義、
   T9 建構、T10 面板消費三處一致；html_report 四參數簽名 T1 定、T2–T6/T10 面板函式都收 `records: &[Record]`；
   面板函式命名一致（netconn_panel/process_panel/execution_panel/file_activity_panel/logon_panel）。
4. **cairn-report 不依賴 cairn-heur**（查證得出）→ 公網判斷用本地 `is_public_ipv4_hint`（T2），不跨 crate。
