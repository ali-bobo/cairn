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

/// Generate a self-contained HTML report from findings and manifest.
pub fn html_report(findings: &[Finding], manifest: &Manifest) -> String {
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
                format!(
                    "<tr>\
                  <td style=\"white-space:nowrap;color:#6b7280;font-size:0.85em\">{ts}</td>\
                  <td><span style=\"background:{color};color:#fff;padding:2px 8px;\
                      border-radius:4px;font-size:0.8em;white-space:nowrap\">{sev}</span></td>\
                  <td style=\"font-weight:500\">{title}</td>\
                  <td style=\"font-size:0.85em;color:#6b7280\">{mitre}</td>\
                  <td style=\"font-size:0.85em\">{src}</td>\
                  <td style=\"font-size:0.85em;color:#374151\">{desc}</td>\
                </tr>"
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

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
        let html = html_report(&[], &minimal_manifest());
        assert!(html.contains("TEST-PC"), "should contain hostname");
    }

    #[test]
    fn html_report_clean_verdict_when_no_high() {
        let html = html_report(&[], &minimal_manifest());
        assert!(html.contains("未發現高風險威脅"));
        assert!(!html.contains("發現高風險事件"));
    }

    #[test]
    fn html_report_alert_verdict_when_has_high() {
        let mut f = Finding::new(Severity::High, "Test High", FindingSource::Sigma);
        f.host = "TEST-PC".into();
        f.artifact = "evtx:Security".into();
        let html = html_report(&[f], &minimal_manifest());
        assert!(html.contains("發現高風險事件"));
    }

    #[test]
    fn html_report_escapes_xss() {
        let mut m = minimal_manifest();
        m.host.hostname = "<script>alert(1)</script>".into();
        let html = html_report(&[], &m);
        assert!(!html.contains("<script>"), "raw script tag should be escaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_report_no_findings_shows_empty_message() {
        let html = html_report(&[], &minimal_manifest());
        assert!(html.contains("本次掃描無 finding"));
    }
}
