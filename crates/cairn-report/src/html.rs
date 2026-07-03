//! HTML report generation. Pure function: findings + manifest → HTML string.
//! No external dependencies; CSS is inlined.
#![allow(clippy::too_many_lines)]

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
        Ok(ip) => !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified(),
        Err(_) => false,
    }
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
    usn.sort_by_key(|u| std::cmp::Reverse(u.ts)); // newest first
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

/// Generate a self-contained HTML report from findings, observations and manifest.
pub fn html_report(
    findings: &[Finding],
    observations: &[cairn_core::Observation],
    records: &[cairn_core::Record],
    manifest: &Manifest,
) -> String {
    let netconn_html = netconn_panel(records);
    let process_html = process_panel(records);
    let execution_html = execution_panel(records);
    let file_activity_html = file_activity_panel(records);
    let critical = count_sev(findings, Severity::Critical);
    let high = count_sev(findings, Severity::High);
    let medium = count_sev(findings, Severity::Medium);
    let low = count_sev(findings, Severity::Low);
    let info = count_sev(findings, Severity::Info);

    let is_alert = critical > 0 || high > 0;
    let verdict_bg = if is_alert { "#7f1d1d" } else { "#14532d" };
    let verdict_txt = if is_alert {
        "⚠ 發現高風險事件，請立即聯絡資安工程師"
    } else {
        "✓ 未發現高風險威脅"
    };

    let hostname = esc(&manifest.host.hostname);
    let started = esc(&manifest.run.started_utc.to_rfc3339());
    let admin = if manifest.privileges.admin { "是" } else { "否" };
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
                                e.ts
                                    .map(|t| t.format("%Y-%m-%d %H:%MZ").to_string())
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
.info-item p{{font-weight:500}}
.stats{{display:flex;gap:1rem;flex-wrap:wrap}}
.stat{{flex:1;min-width:80px;background:#fff;border-radius:8px;
       padding:1rem;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.stat-num{{font-size:2rem;font-weight:700}}
.stat-label{{font-size:.75rem;color:#6b7280;margin-top:.25rem}}
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

<div class="stats">
  <div class="stat"><div class="stat-num" style="color:#b91c1c">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:#c2410c">{high}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:#b45309">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-num" style="color:#1d4ed8">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat"><div class="stat-num" style="color:#6b7280">{info}</div><div class="stat-label">Info</div></div>
</div>

<div class="card" style="margin-top:1.25rem">
<div class="card-title">Findings（共 {total} 筆）</div>
<div style="overflow-x:auto">
<table>
<thead><tr>
  <th>時間</th><th>嚴重度</th><th>標題</th>
  <th>MITRE</th><th>來源</th><th>說明</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>

{netconn_html}

{process_html}

{execution_html}

{file_activity_html}

{obs_html}

<div class="footer">
  <p>{int_note}</p>
  <p style="margin-top:.25rem">cairn v{tool_ver} &nbsp;·&nbsp; 報告產生時間：{generated}</p>
</div>

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
    fn html_report_contains_hostname() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(html.contains("TEST-PC"), "should contain hostname");
    }

    #[test]
    fn html_report_clean_verdict_when_no_high() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(html.contains("未發現高風險威脅"));
        assert!(!html.contains("發現高風險事件"));
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
        assert!(!html.contains("<script>"), "raw script tag should be escaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_report_no_findings_shows_empty_message() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(html.contains("本次掃描無 finding"));
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

        assert!(html.contains("主機盤點"), "missing host-inventory heading: {html}");
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
            netconn("tcp", Some("192.168.1.5"), Some(445), "ESTABLISHED", Some(200)),
            netconn("tcp", None, None, "TIME_WAIT", None), // filtered out
        ];
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(
            html.contains("對外連線 (2 條，其中 1 條連往公網)"),
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
        assert!(!html.contains("對外連線"));
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

    fn exec(source: &str, path: &str, last: Option<(i32, u32, u32, u32, u32)>) -> cairn_core::Record {
        let last_run = last.map(|(y, mo, d, h, mi)| Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap());
        cairn_core::Record::Execution(cairn_core::record::ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run: None,
            last_run,
            run_count: Some(3),
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
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

    fn usn(reason: &str, path: &str, ymd: (i32, u32, u32)) -> cairn_core::Record {
        cairn_core::Record::UsnEvent(cairn_core::record::UsnEventRecord {
            ts: Utc.with_ymd_and_hms(ymd.0, ymd.1, ymd.2, 0, 0, 0).unwrap(),
            path: path.into(),
            reason: reason.into(),
            mft_ref: 1,
        })
    }
    fn motw_file(path: &str, zone: &str) -> cairn_core::Record {
        cairn_core::Record::FileMeta(cairn_core::record::FileMetaRecord {
            path: path.into(),
            size: 0,
            sha256: None,
            si_btime: None,
            si_mtime: None,
            fn_btime: None,
            fn_mtime: None,
            zone_identifier: Some(zone.into()),
            path_complete: None,
        })
    }

    #[test]
    fn file_activity_panel_motw_and_usn_filtered() {
        let recs = vec![
            usn("File_Create", r"C:\Users\a\Downloads\dropper.exe", (2026, 6, 1)),
            usn("Basic_Info_Change", r"C:\noise.txt", (2026, 6, 2)), // filtered (not create/rename)
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
            recs.push(usn("File_Create", &format!(r"C:\f{i}.exe"), (2026, 6, 1)));
        }
        let html = html_report(&[], &[], &recs, &minimal_manifest());
        assert!(html.contains("共 250 筆"), "must note total when capped");
        assert!(html.contains("顯示前 200 筆"));
    }

    #[test]
    fn file_activity_panel_absent_when_no_data() {
        let html = html_report(&[], &[], &[], &minimal_manifest());
        assert!(!html.contains("可疑檔案活動"));
    }
}
