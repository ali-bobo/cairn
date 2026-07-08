//! 讀取掃描結果 manifest.json + findings.jsonl，產生人類可讀摘要。

use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Clean, // 無 critical / high
    Alert, // 有 critical 或 high
}

#[derive(Debug)]
pub struct ScanSummary {
    pub hostname: String,
    pub started_utc: String,      // 已格式化字串 "2026-06-27 14:30 UTC"
    pub time_window_desc: String, // 由 runner 傳入，如 "最近 24 小時"
    pub admin: bool,
    pub verdict: Verdict,
    pub counts: std::collections::BTreeMap<String, u64>, // "critical"->N ...
    /// Critical + High findings，最多 5 筆，格式 ("CRITICAL", "title")
    pub top_findings: Vec<(String, String)>,
    pub sigma_ruleset_ver: String,
}

/// 從 output 子目錄（含 manifest.json + findings.jsonl）載入摘要。
/// output_dir: cairn 執行後產生的子目錄，如 .\output\20260627_143022\
pub fn load_summary(output_dir: &Path, time_window_desc: &str) -> anyhow::Result<ScanSummary> {
    // 讀 manifest.json
    let manifest_path = output_dir.join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text)?;

    let hostname = manifest["host"]["hostname"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let admin = manifest["privileges"]["admin"].as_bool().unwrap_or(false);
    let sigma_ruleset_ver = manifest["tool"]["sigma_ruleset_ver"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let started_utc = manifest["run"]["started_utc"]
        .as_str()
        .unwrap_or("")
        .to_string();
    // 格式化為 "YYYY-MM-DD HH:MM UTC"
    let started_utc = started_utc
        .get(..16)
        .unwrap_or(&started_utc)
        .replace('T', " ")
        + " UTC";

    // counts
    let counts: std::collections::BTreeMap<String, u64> = manifest["counts"]["findings_by_sev"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();

    let critical = counts.get("critical").copied().unwrap_or(0);
    let high = counts.get("high").copied().unwrap_or(0);
    let verdict = if critical > 0 || high > 0 {
        Verdict::Alert
    } else {
        Verdict::Clean
    };

    // 讀 findings.jsonl，取 Critical + High，最多 5 筆
    let findings_path = output_dir.join("findings.jsonl");
    let mut top_findings: Vec<(String, String)> = Vec::new();
    if findings_path.exists() {
        let content = std::fs::read_to_string(&findings_path)?;
        for line in content.lines() {
            if top_findings.len() >= 5 {
                break;
            }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let sev = v["severity"].as_str().unwrap_or("").to_lowercase();
            if sev == "critical" || sev == "high" {
                let label = sev.to_uppercase();
                let title = v["title"].as_str().unwrap_or("(unknown)").to_string();
                top_findings.push((label, title));
            }
        }
    }

    Ok(ScanSummary {
        hostname,
        started_utc,
        time_window_desc: time_window_desc.to_string(),
        admin,
        verdict,
        counts,
        top_findings,
        sigma_ruleset_ver,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn minimal_manifest(critical: u64, high: u64, medium: u64) -> String {
        format!(
            r#"{{
  "tool": {{"name":"cairn","version":"0.1.0","build_sha":"abc","sigma_ruleset_ver":"98781da+abcd"}},
  "run": {{"started_utc":"2026-06-27T14:30:00Z","finished_utc":"2026-06-27T14:31:00Z","cmdline":"","operator":"","case_id":"","profile":"standard","selected_modules":[]}},
  "host": {{"hostname":"TEST-PC","os_build":"","timezone":"UTC","wall_clock_utc_skew":"unknown"}},
  "privileges": {{"admin":true,"se_backup":false,"se_debug":false}},
  "sources": [], "outputs": [],
  "counts": {{"records":100,"findings_by_sev":{{"critical":{},"high":{},"medium":{},"low":0,"info":0}}}},
  "integrity_note":"",
  "governance": {{"effective_threads":4,"low_priority_applied":false,"truncations":[]}}
}}"#,
            critical, high, medium
        )
    }

    #[test]
    fn no_high_critical_is_clean() {
        let dir = tempfile::TempDir::new().unwrap();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(0, 0, 2));
        write_temp(dir.path(), "findings.jsonl", "");
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.verdict, Verdict::Clean);
        assert_eq!(s.hostname, "TEST-PC");
        assert!(s.admin);
    }

    #[test]
    fn has_high_is_alert() {
        let dir = tempfile::TempDir::new().unwrap();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(0, 2, 0));
        write_temp(dir.path(), "findings.jsonl", "");
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.verdict, Verdict::Alert);
    }

    #[test]
    fn has_critical_is_alert() {
        let dir = tempfile::TempDir::new().unwrap();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(1, 0, 0));
        write_temp(dir.path(), "findings.jsonl", "");
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.verdict, Verdict::Alert);
    }

    #[test]
    fn top_findings_capped_at_5() {
        let dir = tempfile::TempDir::new().unwrap();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(0, 10, 0));
        // 10 high findings
        let mut jsonl = String::new();
        for i in 0..10 {
            jsonl.push_str(&format!(
                r#"{{"severity":"high","title":"Event {i}","ts":"2026-06-27T14:30:00Z","detected_at":"2026-06-27T14:30:00Z","id":"00000000-0000-0000-0000-00000000000{i}","schema":"","source":"heuristic","mitre":[],"host":"TEST","artifact":"","entity":{{}},"details":"","rule_author":null,"rule_id":null,"user":null,"event_id":null,"evidence_ref":null,"details_client":null,"reason":null}}"#
            ));
            jsonl.push('\n');
        }
        write_temp(dir.path(), "findings.jsonl", &jsonl);
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.top_findings.len(), 5);
    }

    #[test]
    fn only_critical_and_high_in_top_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        write_temp(dir.path(), "manifest.json", &minimal_manifest(1, 1, 5));
        let jsonl = concat!(
            r#"{"severity":"medium","title":"Medium Event","ts":"2026-06-27T14:30:00Z","detected_at":"2026-06-27T14:30:00Z","id":"00000000-0000-0000-0000-000000000001","schema":"","source":"heuristic","mitre":[],"host":"TEST","artifact":"","entity":{},"details":"","rule_author":null,"rule_id":null,"user":null,"event_id":null,"evidence_ref":null,"details_client":null,"reason":null}"#,
            "\n",
            r#"{"severity":"high","title":"High Event","ts":"2026-06-27T14:30:00Z","detected_at":"2026-06-27T14:30:00Z","id":"00000000-0000-0000-0000-000000000002","schema":"","source":"heuristic","mitre":[],"host":"TEST","artifact":"","entity":{},"details":"","rule_author":null,"rule_id":null,"user":null,"event_id":null,"evidence_ref":null,"details_client":null,"reason":null}"#,
            "\n",
        );
        write_temp(dir.path(), "findings.jsonl", jsonl);
        let s = load_summary(dir.path(), "最近 24 小時").unwrap();
        assert_eq!(s.top_findings.len(), 1);
        assert_eq!(s.top_findings[0].0, "HIGH");
        assert_eq!(s.top_findings[0].1, "High Event");
    }
}
