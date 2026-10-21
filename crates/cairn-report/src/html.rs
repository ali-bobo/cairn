//! HTML report generation. Pure function: findings + manifest → HTML string.
//! No external dependencies; CSS is inlined.
#![allow(clippy::too_many_lines)]

use cairn_core::collectors;
use cairn_core::{
    finding::{Finding, Severity},
    manifest::Manifest,
};
use chrono::Utc;

/// Escape HTML special characters to prevent XSS in the generated report.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Minimal public-IPv4 test for panel sorting only (cairn-report doesn't depend on
/// cairn-heur's score::is_public_ipv4). Non-parseable or private/loopback/link-local
/// → false. This is a sort hint, not a security judgement, so the simplified check is fine.
fn is_public_ipv4_hint(addr: &str) -> bool {
    use std::net::Ipv4Addr;
    match addr.parse::<Ipv4Addr>() {
        Ok(ip) => {
            !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
        }
        Err(_) => false,
    }
}

/// Extract the final path segment (file name) from a path string, handling both
/// backslash (Windows-native) and forward-slash (rare but honest to handle) separators.
/// A path with no separator is returned as-is (already a bare file name).
fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

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

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#b91c1c",
        Severity::High => "#c2410c",
        Severity::Medium => "#b45309",
        Severity::Low => "#1d4ed8",
        Severity::Info => "#6b7280",
    }
}

fn sev_order(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn count_sev(findings: &[Finding], s: Severity) -> usize {
    findings.iter().filter(|f| f.severity == s).count()
}

fn short_ts(ts: &str) -> &str {
    // "2026-06-27T14:30:00Z" -> "2026-06-27T14:30"
    if ts.len() >= 16 {
        &ts[..16]
    } else {
        ts
    }
}

/// Network-connections panel: established + listening; public-remote sorted first.
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
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">網路連線 ({} 條，其中 {} 條連往公網)</h2></summary>\
         <table><tr><th>協定</th><th>本地</th><th>遠端</th><th>狀態</th><th>PID</th></tr>{}</table></details>",
        conns.len(),
        public_count,
        rows
    )
}

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
    procs.sort_by(|a, b| {
        sig_rank(a.signed)
            .cmp(&sig_rank(b.signed))
            .then_with(|| a.pid.cmp(&b.pid))
    });
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
    execs.sort_by_key(|e| std::cmp::Reverse(e.last_run));
    let rows: String = execs
        .iter()
        .map(|e| {
            let path = if e.source == "prefetch" {
                format!("{}（僅檔名）", e.path)
            } else {
                e.path.clone()
            };
            let fmt_ts = |t: &Option<chrono::DateTime<chrono::Utc>>| {
                t.map(|t| t.format("%Y-%m-%d %H:%MZ").to_string())
                    .unwrap_or_else(|| "-".into())
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&e.source),
                esc(&path),
                e.run_count
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
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
    // remote first, then by user. `sort_by_key` (not `sort_by`) to satisfy
    // clippy::unnecessary_sort_by; invert the bool so "is remote" (false) sorts first.
    sessions.sort_by_key(|s| (!s.logon_type.contains("Remote"), s.user.clone()));
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
}

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
    repeated.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let rows: String = repeated
        .iter()
        .map(|(base, count)| format!("<tr><td>{}</td><td>{}</td></tr>", esc(base), count))
        .collect();
    format!(
        "<details class=\"inventory\"><summary><h2 style=\"display:inline\">相同來源多次出現 ({} 個檔名)</h2></summary>\
         <table><tr><th>檔名</th><th>出現於幾筆 finding</th></tr>{}</table></details>",
        repeated.len(),
        rows
    )
}

/// Generate a self-contained HTML report from findings, observations and manifest.
/// One row of the "what was checked" overview.
struct Area {
    name: &'static str,
    /// Finding artifacts that belong to this area.
    artifacts: fn(&str) -> bool,
    /// Live records this area inspected.
    records: fn(&cairn_core::Record) -> bool,
    /// Canonical collector names (`cairn_core::collectors`, matched against
    /// `SourceEntry.collector`) whose failure means the area was not checked.
    modules: &'static [&'static str],
    /// Shown in offline EVTX mode too (event-log areas only).
    offline: bool,
}

fn is_run_mru(r: &cairn_core::Record) -> bool {
    matches!(r, cairn_core::Record::RegValue(v) if v.key.to_ascii_lowercase().ends_with(r"\explorer\runmru"))
}

fn is_event_on(r: &cairn_core::Record, channel: &str) -> bool {
    matches!(r, cairn_core::Record::Event(e) if e.channel.eq_ignore_ascii_case(channel))
}

const AREAS: &[Area] = &[
    Area {
        name: "持久化（開機或登入時自動執行的程式）",
        artifacts: |a| a == "persistence" || a == "run_key",
        records: |r| matches!(r, cairn_core::Record::Persistence(_)),
        modules: &[collectors::PERSIST, collectors::WMI_SUBSCRIPTION],
        offline: false,
    },
    Area {
        name: "正在執行的程式",
        artifacts: |a| a == "process",
        records: |r| matches!(r, cairn_core::Record::Process(_)),
        modules: &[collectors::PROC],
        offline: false,
    },
    Area {
        name: "網路連線",
        artifacts: |a| a.starts_with("netconn"),
        records: |r| matches!(r, cairn_core::Record::NetConn(_)),
        modules: &[collectors::NET],
        offline: false,
    },
    Area {
        name: "「執行」對話框貼上的指令（ClickFix）",
        artifacts: |a| a == "run_mru",
        records: is_run_mru,
        modules: &[collectors::PERSIST],
        offline: false,
    },
    Area {
        name: "帳號建立、群組變更、密碼猜測",
        artifacts: |a| a == "account" || a == "logon_bruteforce",
        records: |r| is_event_on(r, "Security"),
        modules: &[collectors::EVTX_LIVE],
        offline: true,
    },
    Area {
        name: "事件記錄（清除記錄、新服務、新排程、Defender、Sigma 規則）",
        artifacts: |a| a.starts_with("evtx:"),
        records: |r| matches!(r, cairn_core::Record::Event(_)),
        modules: &[collectors::EVTX_LIVE],
        offline: true,
    },
];

/// "這次檢查了什麼" — one row per area with its status, so a reader can tell a clean
/// area from one that was never checked. Offline EVTX runs (no live records) show only
/// the event-log areas.
fn overview_panel(
    findings: &[Finding],
    records: &[cairn_core::Record],
    manifest: &Manifest,
) -> String {
    let offline = records.is_empty();
    let mut rows = String::new();
    for area in AREAS.iter().filter(|a| !offline || a.offline) {
        let hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| (area.artifacts)(&f.artifact))
            .collect();
        let high = hits
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .count();
        let medium = hits
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let failed = manifest
            .sources
            .iter()
            .find(|s| !s.errors.is_empty() && area.modules.contains(&s.collector.as_str()));
        let inspected = if offline {
            manifest.counts.records as usize
        } else {
            records.iter().filter(|r| (area.records)(r)).count()
        };
        let (color, status) = if high > 0 {
            ("#b91c1c", format!("發現 {high} 筆高風險"))
        } else if medium > 0 {
            ("#b45309", format!("{medium} 筆需要確認"))
        } else if let Some(src) = failed {
            (
                "#6b7280",
                format!("未檢查：{}", esc(&src.errors.join("; "))),
            )
        } else if inspected == 0 {
            ("#6b7280", "沒有收集到資料，無法判斷".to_string())
        } else {
            ("#15803d", format!("未發現異常（檢查了 {inspected} 筆）"))
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td style=\"color:{color};font-weight:600\">{status}</td></tr>",
            area.name
        ));
    }
    format!(
        "<div class=\"card\"><div class=\"card-title\">這次檢查了什麼</div>\
         <table><tr><th>項目</th><th>結果</th></tr>{rows}</table></div>"
    )
}

/// Logging gaps that make a clean result less meaningful, inferred from what the live
/// EVTX collection actually returned. Empty for offline runs and when nothing is missing.
fn blind_spots_panel(records: &[cairn_core::Record], manifest: &Manifest) -> String {
    if records.is_empty() {
        return String::new();
    }
    let count = |channel: &str, eid: Option<u32>| {
        records
            .iter()
            .filter(|r| match r {
                cairn_core::Record::Event(e) => {
                    e.channel.eq_ignore_ascii_case(channel) && eid.is_none_or(|id| e.event_id == id)
                }
                _ => false,
            })
            .count()
    };
    let mut items: Vec<&str> = Vec::new();
    if !manifest.privileges.admin {
        items.push(
            "沒有以系統管理員身分執行：Security 事件記錄、其他使用者的登錄和部分系統位置讀不到。\
             請在程式上按右鍵選「以系統管理員身分執行」再掃一次。",
        );
    }
    let security = count("Security", None);
    if manifest.privileges.admin && security == 0 {
        items.push("讀不到 Security 事件記錄，帳號與登入相關的偵測沒有資料。");
    }
    if security > 0 && count("Security", Some(4688)) == 0 {
        items.push(
            "沒有「行程建立」事件（4688）：這台主機沒有開啟行程建立稽核，Sigma 的行程規則幾乎不會觸發。\
             建議用群組原則開啟「稽核行程建立」並勾選「在行程建立事件中包含命令列」。",
        );
    }
    if !manifest.tool.sigma_ruleset_ver.is_empty()
        && count("Microsoft-Windows-PowerShell/Operational", Some(4104)) == 0
    {
        items.push(
            "沒有 PowerShell 指令碼區塊記錄（4104）：看不到 PowerShell 實際執行的內容。\
             建議用群組原則開啟「開啟 PowerShell 指令碼區塊記錄」。",
        );
    }
    if items.is_empty() {
        return String::new();
    }
    let list: String = items.iter().map(|i| format!("<li>{i}</li>")).collect();
    format!(
        "<div class=\"card\"><div class=\"card-title\">偵測盲點（結果乾淨不代表沒事）</div>\
         <ul style=\"padding-left:1.25rem;line-height:1.8\">{list}</ul></div>"
    )
}

pub fn html_report(
    findings: &[Finding],
    observations: &[cairn_core::Observation],
    records: &[cairn_core::Record],
    manifest: &Manifest,
) -> String {
    let netconn_html = netconn_panel(records);
    let process_html = process_panel(records);
    let execution_html = execution_panel(records);
    let logon_html = logon_panel(records);
    let overview_html = overview_panel(findings, records, manifest);
    let blind_spots_html = blind_spots_panel(records, manifest);
    let critical = count_sev(findings, Severity::Critical);
    let high = count_sev(findings, Severity::High);
    let medium = count_sev(findings, Severity::Medium);
    let low = count_sev(findings, Severity::Low);
    let info = count_sev(findings, Severity::Info);

    let is_alert = critical > 0 || high > 0;
    // Nothing collected at all (no live records, no parsed events) is not a clean bill
    // of health; say so instead of showing a green banner.
    let no_data = records.is_empty() && manifest.counts.records == 0;
    let (verdict_bg, verdict_txt) = if is_alert {
        ("#7f1d1d", "⚠ 發現高風險事件，請立即聯絡資安工程師")
    } else if no_data {
        (
            "#374151",
            "沒有收集到可分析的資料，無法判斷這台主機是否安全",
        )
    } else if !blind_spots_html.is_empty() {
        ("#14532d", "✓ 未發現高風險威脅（請看下方「偵測盲點」）")
    } else {
        ("#14532d", "✓ 未發現高風險威脅")
    };

    let hostname = esc(&manifest.host.hostname);
    let started = manifest
        .run
        .started_utc
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let admin = if manifest.privileges.admin {
        "是"
    } else {
        "否"
    };
    let rules_ver = if manifest.tool.sigma_ruleset_ver.is_empty() {
        "未載入".to_string()
    } else {
        esc(&manifest.tool.sigma_ruleset_ver)
    };
    let tool_ver = esc(&manifest.tool.version);
    let int_note = esc(&manifest.integrity_note);
    let generated = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Sort findings: critical first
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| sev_order(f.severity));

    let evidence_summary_html = evidence_source_summary_panel(&sorted);

    // CSS for the filter bar is only emitted when the filter bar itself renders,
    // so `html.contains("filter-bar")` is a reliable presence check (see
    // filter_bar_absent_when_no_findings).
    let filter_css = if sorted.is_empty() {
        String::new()
    } else {
        r"
.filter-bar{display:flex;gap:1rem;flex-wrap:wrap;align-items:center;
            margin-bottom:.75rem;font-size:.85rem}
.filter-group{display:flex;gap:.75rem;flex-wrap:wrap}
.filter-group label{display:flex;align-items:center;gap:.25rem;cursor:pointer}
#artifact-filter,#keyword-filter{padding:.35rem .5rem;border:1px solid #d1d5db;
                                   border-radius:4px;font-size:.85rem}
#keyword-filter{flex:1;min-width:150px}
#filter-count{color:#6b7280;font-size:.8rem;white-space:nowrap}"
            .to_string()
    };

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

    // Build findings rows
    let rows = if sorted.is_empty() {
        "<tr><td colspan=\"6\" style=\"text-align:center;color:#6b7280;padding:2rem\">本次掃描無 finding</td></tr>".to_string()
    } else {
        sorted
            .iter()
            .map(|f| {
                let ts = esc(short_ts(&f.ts.to_rfc3339()));
                let sev = sev_label(f.severity);
                let color = sev_color(f.severity);
                let title = esc(&f.title);
                let mitre = esc(&f.mitre.join(", "));
                let src = esc(match f.source {
                    cairn_core::finding::FindingSource::Sigma => "Sigma",
                    cairn_core::finding::FindingSource::Heuristic => "啟發式",
                });
                let desc = esc(f.details_client.as_deref().unwrap_or(&f.details));
                let ev_html = if f.evidence.is_empty() {
                    String::new()
                } else {
                    let items: String = f
                        .evidence
                        .iter()
                        .map(|e| {
                            format!(
                                "<li><b>{}</b> {} {}<br>{}</li>",
                                esc(&e.artifact),
                                e.path.as_deref().map(esc).unwrap_or_default(),
                                e.ts.map(|t| t.format("%Y-%m-%d %H:%MZ").to_string())
                                    .unwrap_or_default(),
                                esc(&e.detail),
                            )
                        })
                        .collect();
                    format!(
                        "<details><summary>佐證來源 ({})</summary><ul>{}</ul></details>",
                        f.evidence.len(),
                        items
                    )
                };
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
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Host inventory (observations) — collapsed by default, grouped by category.
    let mut obs_html = String::new();
    if !observations.is_empty() {
        use std::collections::BTreeMap;
        let mut by_cat: BTreeMap<&str, Vec<&cairn_core::Observation>> = BTreeMap::new();
        for o in observations {
            by_cat.entry(o.category.as_str()).or_default().push(o);
        }
        let mut groups = String::new();
        for (cat, items) in &by_cat {
            let rows: String = items
                .iter()
                .map(|o| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        esc(&o.title),
                        o.path.as_deref().map(esc).unwrap_or_default(),
                        esc(&o.details),
                    )
                })
                .collect();
            groups.push_str(&format!(
                "<h3>{} ({})</h3><table><tr><th>項目</th><th>路徑</th><th>詳細</th></tr>{}</table>",
                esc(cat),
                items.len(),
                rows
            ));
        }
        obs_html = format!(
            "<details class=\"inventory\"><summary><h2 style=\"display:inline\">主機盤點 Host Inventory ({} 項)</h2></summary>{}</details>",
            observations.len(),
            groups
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cairn 威脅鑑識報告</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      background:#f3f4f6;color:#111827;line-height:1.5}}
.banner{{background:{verdict_bg};color:#fff;text-align:center;
         padding:1.25rem;font-size:1.2rem;font-weight:600;letter-spacing:.02em}}
.container{{max-width:1100px;margin:0 auto;padding:1.5rem}}
.card{{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);
       padding:1.25rem;margin-bottom:1.25rem}}
.card-title{{font-size:.75rem;font-weight:600;color:#6b7280;
             text-transform:uppercase;letter-spacing:.05em;margin-bottom:.75rem}}
.info-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem}}
.info-item label{{font-size:.75rem;color:#9ca3af}}
.info-item p{{font-weight:500;word-break:break-all}}
.stats{{display:flex;gap:1rem;flex-wrap:wrap}}
.stat{{flex:1;min-width:80px;background:#fff;border-radius:8px;
       padding:1rem;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.stat-num{{font-size:2rem;font-weight:700}}
.stat-label{{font-size:.75rem;color:#6b7280;margin-top:.25rem}}
{filter_css}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th{{text-align:left;padding:.6rem .75rem;background:#f9fafb;
    color:#6b7280;font-size:.75rem;font-weight:600;
    text-transform:uppercase;border-bottom:1px solid #e5e7eb}}
td{{padding:.6rem .75rem;border-bottom:1px solid #f3f4f6;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#f9fafb}}
.footer{{text-align:center;color:#9ca3af;font-size:.8rem;margin-top:1.5rem;padding:.75rem}}
</style>
</head>
<body>
<div class="banner">{verdict_txt}</div>
<div class="container">

<div class="card">
<div class="card-title">主機資訊</div>
<div class="info-grid">
  <div class="info-item"><label>主機名稱</label><p>{hostname}</p></div>
  <div class="info-item"><label>掃描開始時間 (UTC)</label><p>{started}</p></div>
  <div class="info-item"><label>管理員權限</label><p>{admin}</p></div>
  <div class="info-item"><label>Sigma 規則版本</label><p>{rules_ver}</p></div>
</div>
</div>

{overview_html}

{blind_spots_html}

<div class="stats">
  <div class="stat"><div class="stat-num" style="color:#b91c1c">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:#c2410c">{high}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:#b45309">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-num" style="color:#1d4ed8">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat"><div class="stat-num" style="color:#6b7280">{info}</div><div class="stat-label">Info</div></div>
</div>

<div class="card" style="margin-top:1.25rem">
<div class="card-title">Findings（共 {total} 筆）</div>
{filter_bar_html}
<div style="overflow-x:auto">
<table>
<thead><tr>
  <th>時間</th><th>嚴重度</th><th>標題</th>
  <th>MITRE</th><th>來源</th><th>說明</th>
</tr></thead>
<tbody id="findings-tbody">
{rows}
</tbody>
</table>
</div>
</div>

{evidence_summary_html}

{netconn_html}

{process_html}

{execution_html}


{logon_html}

{obs_html}

<div class="footer">
  <p>{int_note}</p>
  <p style="margin-top:.25rem">cairn v{tool_ver} &nbsp;·&nbsp; 報告產生時間：{generated}</p>
</div>

{filter_script_html}

</div>
</body>
</html>"#,
        total = sorted.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::{
        finding::{Finding, FindingSource, Severity},
        manifest::{Counts, GovernanceReport, HostInfo, Manifest, Privileges, RunInfo, ToolInfo},
    };
    use chrono::TimeZone;

    fn minimal_manifest() -> Manifest {
        Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo {
                name: "cairn".into(),
                version: "0.1.0".into(),
                build_sha: "abc".into(),
                sigma_ruleset_ver: "98781da+abcd".into(),
            },
            run: RunInfo {
                started_utc: Utc.with_ymd_and_hms(2026, 6, 27, 14, 30, 0).unwrap(),
                finished_utc: None,
                cmdline: String::new(),
                operator: String::new(),
                case_id: String::new(),
                profile: "standard".into(),
                selected_modules: vec![],
            },
            host: HostInfo {
                hostname: "TEST-PC".into(),
                os_build: String::new(),
                timezone: "UTC".into(),
                wall_clock_utc_skew: "unknown".into(),
            },
            privileges: Privileges {
                admin: true,
                se_backup: false,
                se_debug: false,
            },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: "All hashes SHA-256.".into(),
            governance: GovernanceReport::default(),
        }
    }

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
        assert!(
            !html.contains("相同來源多次出現") && !html.contains("同一執行檔"),
            "must not count multiple evidence items within one finding as repetition: {html}"
        );
    }

    #[test]
    fn html_report_contains_hostname() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(html.contains("TEST-PC"), "should contain hostname");
    }

    #[test]
    fn html_report_clean_verdict_when_no_high() {
        let mut m = minimal_manifest();
        m.counts.records = 10;
        let html = html_report(&[], &[], &[], &m);
        assert!(html.contains("未發現高風險威脅"));
        assert!(!html.contains("發現高風險事件"));
    }

    /// No collected data is "cannot tell", never a green all-clear.
    #[test]
    fn html_report_says_no_data_instead_of_clean() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(html.contains("沒有收集到可分析的資料"), "{html}");
        assert!(!html.contains("未發現高風險威脅"));
    }

    #[test]
    fn html_report_alert_verdict_when_has_high() {
        let mut f = Finding::new(Severity::High, "Test High", FindingSource::Sigma);
        f.host = "TEST-PC".into();
        f.artifact = "evtx:Security".into();
        let html = html_report(&[f], &[], &[], &minimal_manifest());
        assert!(html.contains("發現高風險事件"));
    }

    #[test]
    fn html_report_escapes_xss() {
        let mut m = minimal_manifest();
        m.host.hostname = "<script>alert(1)</script>".into();
        let html = html_report(&[], &[], &[], &m);
        assert!(
            !html.contains("<script>"),
            "raw script tag should be escaped"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_report_no_findings_shows_empty_message() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(html.contains("本次掃描無 finding"));
    }

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
        f3.artifact = "evtx:Security".into();
        let html = html_report(&[f1, f2, f3], &[], &[], &minimal_manifest());
        assert!(html.contains("<option value=\"evtx:Security\">evtx:Security</option>"));
        assert!(html.contains("<option value=\"persist:run_key\">persist:run_key</option>"));
        let opt_count = html.matches("<option value=\"evtx:Security\">").count();
        assert_eq!(opt_count, 1, "artifact option must be deduplicated");
    }

    #[test]
    fn filter_bar_absent_when_no_findings() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        // The `.filter-bar` CSS rule is always present in the static <style> block;
        // what must not render is the actual filter bar markup (the div itself).
        assert!(
            !html.contains("<div class=\"filter-bar\">"),
            "filter bar div must not render when there are no findings"
        );
    }

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

    /// Findings render their evidence list (collapsible "佐證來源"), and observations
    /// render as a collapsible host-inventory block, both with the evidence/observation
    /// path escaped for HTML.
    #[test]
    fn html_contains_inventory_block_and_evidence_details() {
        use cairn_core::finding::EvidenceItem;

        let mut f = Finding::new(Severity::High, "Test High", FindingSource::Sigma);
        f.host = "TEST-PC".into();
        f.artifact = "evtx:Security".into();
        f.evidence.push(EvidenceItem {
            artifact: "prefetch".into(),
            path: Some(r"C:\Windows\Prefetch\EVIL.EXE-1234.pf".into()),
            ts: Some(Utc.with_ymd_and_hms(2026, 6, 27, 23, 31, 0).unwrap()),
            detail: "run_count=12 last_run=2026-06-27T23:31Z".into(),
        });

        let mut o = cairn_core::Observation::new("service", "服務 X → x.exe");
        o.host = "TEST-PC".into();
        o.path = Some(r"C:\Program Files\X\x.exe".into());
        o.details = "位置=HKLM\\...\\Services\\X".into();
        o.source_artifact = "persistence".into();

        let html = html_report(&[f], &[o], &[], &minimal_manifest());

        assert!(
            html.contains("主機盤點"),
            "missing host-inventory heading: {html}"
        );
        assert!(
            html.contains("佐證來源 (1)"),
            "missing evidence summary: {html}"
        );
        assert!(
            html.contains(r"C:\Program Files\X\x.exe"),
            "missing observation path: {html}"
        );
    }

    fn netconn(
        proto: &str,
        raddr: Option<&str>,
        rport: Option<u16>,
        state: &str,
        pid: Option<u32>,
    ) -> cairn_core::Record {
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
            netconn(
                "tcp",
                Some("192.168.1.5"),
                Some(445),
                "ESTABLISHED",
                Some(200),
            ),
            netconn("tcp", None, None, "TIME_WAIT", None), // filtered out
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(
            html.contains("網路連線 (2 條，其中 1 條連往公網)"),
            "html: missing panel"
        );
        assert!(html.contains("8.8.8.8:443"));
        // public remote sorted first: 8.8.8.8 row appears before 192.168 row
        let pub_pos = html.find("8.8.8.8").unwrap();
        let priv_pos = html.find("192.168.1.5").unwrap();
        assert!(pub_pos < priv_pos, "public conn must sort first");
    }

    #[test]
    fn netconn_panel_absent_when_no_conns() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(!html.contains("網路連線"));
    }

    fn proc(pid: u32, image: &str, signed: Option<bool>) -> cairn_core::Record {
        cairn_core::Record::Process(cairn_core::record::ProcessRecord {
            pid,
            ppid: 4,
            image: image.into(),
            cmdline: format!("{image} --run"),
            signed,
            signer: None,
            binary_sha256: None,
            integrity: Some("medium".into()),
            user: None,
            start_time: None,
            signer_source: None,
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

    #[test]
    fn process_panel_absent_when_no_processes() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(!html.contains("執行中程序"));
    }

    fn exec(
        source: &str,
        path: &str,
        last: Option<(i32, u32, u32, u32, u32)>,
    ) -> cairn_core::Record {
        let last_run =
            last.map(|(y, mo, d, h, mi)| Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap());
        cairn_core::Record::Execution(cairn_core::record::ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run: None,
            last_run,
            run_count: Some(3),
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
            full_path: None,
        })
    }

    #[test]
    fn execution_panel_newest_first_and_prefetch_flagged() {
        let recs = vec![
            exec("shimcache", r"C:\old.exe", Some((2026, 1, 1, 0, 0))),
            exec("prefetch", "NEW.EXE", Some((2026, 6, 1, 0, 0))),
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("近期執行證據 (2 筆，來自 2 種來源)"));
        assert!(html.contains("NEW.EXE（僅檔名）"));
        let new_pos = html.find("NEW.EXE").unwrap();
        let old_pos = html.find("old.exe").unwrap();
        assert!(new_pos < old_pos, "newest last_run must sort first");
    }

    #[test]
    fn execution_panel_absent_when_no_executions() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(!html.contains("近期執行證據"));
    }

    fn session(user: &str, ltype: &str, sid: u32, source: Option<&str>) -> cairn_core::Record {
        cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
            user: user.into(),
            logon_type: ltype.into(),
            logon_time: None,
            source: source.map(String::from),
            session_id: Some(sid),
            state_active: false,
            logon_server: None,
            session_state: None,
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

    #[test]
    fn logon_panel_absent_when_no_sessions() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(!html.contains("登入 session"));
    }

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
                logon_server: None,
                session_state: None,
            }),
            cairn_core::Record::LogonSession(cairn_core::record::LogonSessionRecord {
                user: r"PC\bob".into(),
                logon_type: "Interactive".into(),
                logon_time: None,
                source: None,
                session_id: Some(2),
                state_active: false,
                logon_server: None,
                session_state: None,
            }),
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(
            html.contains("<th>狀態</th>"),
            "missing state column header: {html}"
        );
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

    fn persist_record() -> cairn_core::Record {
        cairn_core::Record::Persistence(cairn_core::record::PersistenceRecord {
            mechanism: cairn_core::Mechanism::RunKey,
            location: r"HKLM\Run".into(),
            value: Some("x".into()),
            command: Some(r"C:\Program Files\x.exe".into()),
            binary_path: Some(r"C:\Program Files\x.exe".into()),
            binary_sha256: None,
            signed: Some(true),
            signer: None,
            last_write: None,
            bound: None,
            signer_source: None,
            service_start: None,
        })
    }

    fn event(channel: &str, eid: u32) -> cairn_core::Record {
        cairn_core::Record::Event(cairn_core::record::EventRecord {
            ts: Utc.with_ymd_and_hms(2026, 6, 27, 14, 0, 0).unwrap(),
            channel: channel.into(),
            event_id: eid,
            provider: String::new(),
            computer: String::new(),
            record_id: 1,
            data: serde_json::Map::new(),
        })
    }

    #[test]
    fn overview_marks_clean_high_and_unchecked_areas() {
        let mut m = minimal_manifest();
        m.sources.push(cairn_core::manifest::SourceEntry {
            collector: cairn_core::collectors::NET.into(),
            artifact: "netconn".into(),
            path: "live:net".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(),
            errors: vec!["access denied".into()],
        });
        let mut f = Finding::new(Severity::High, "acct", FindingSource::Heuristic);
        f.artifact = "account".into();
        let html = overview_panel(&[f], &[persist_record(), event("Security", 4624)], &m);
        assert!(html.contains("未發現異常（檢查了 1 筆）"), "{html}");
        assert!(html.contains("發現 1 筆高風險"), "{html}");
        assert!(html.contains("未檢查：access denied"), "{html}");
        assert!(
            html.contains("沒有收集到資料"),
            "process area had no records: {html}"
        );
    }

    #[test]
    fn offline_overview_shows_only_event_log_areas() {
        let mut m = minimal_manifest();
        m.counts.records = 42;
        let html = overview_panel(&[], &[], &m);
        assert!(!html.contains("持久化"), "{html}");
        assert!(html.contains("檢查了 42 筆"), "{html}");
    }

    #[test]
    fn blind_spots_flag_missing_process_and_powershell_logging() {
        let m = minimal_manifest();
        let html = blind_spots_panel(&[persist_record(), event("Security", 4624)], &m);
        assert!(html.contains("4688"), "{html}");
        assert!(html.contains("4104"), "{html}");
        let none = blind_spots_panel(
            &[
                event("Security", 4688),
                event("Microsoft-Windows-PowerShell/Operational", 4104),
            ],
            &m,
        );
        assert!(none.is_empty(), "{none}");
    }

    #[test]
    fn blind_spots_tell_non_admin_to_elevate() {
        let mut m = minimal_manifest();
        m.privileges.admin = false;
        let html = blind_spots_panel(&[persist_record()], &m);
        assert!(html.contains("系統管理員"), "{html}");
    }

    #[test]
    fn report_places_overview_before_findings() {
        let html = html_report(&[], &[], &[persist_record()], &minimal_manifest());
        let ov = html.find("這次檢查了什麼").unwrap();
        let fi = html.find("Findings（共").unwrap();
        assert!(ov < fi);
    }
}
