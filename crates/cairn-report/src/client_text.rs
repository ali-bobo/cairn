//! FR18: plain zh-TW client-facing text for Findings >= Medium severity.
//!
//! `fill_details_client` fills `Finding.details_client` with a one-sentence
//! summary addressed to a non-technical audience. It is idempotent when the
//! severity is below Medium (Low / Info) — it simply returns without touching
//! the field.
#![forbid(unsafe_code)]

use cairn_core::finding::{Finding, FindingSource, Severity};

fn is_medium_or_above(s: Severity) -> bool {
    matches!(s, Severity::Critical | Severity::High | Severity::Medium)
}

fn entity_path(f: &Finding) -> &str {
    if let Some(p) = &f.entity.process {
        return &p.image;
    }
    if let Some(fi) = &f.entity.file {
        return &fi.path;
    }
    "未知程式"
}

pub fn fill_details_client(f: &mut Finding) {
    if !is_medium_or_above(f.severity) {
        return;
    }
    let host = f.host.clone();
    let text = match f.source {
        FindingSource::Heuristic => {
            let path = entity_path(f).to_owned();
            match f.artifact.as_str() {
                "process" => format!(
                    "主機 {} 上，{} 以非預期的父行程方式執行，\
                     可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。",
                    host, path
                ),
                "persistence" => format!(
                    "主機 {} 上，{} 疑似建立了持久化機制，\
                     建議確認該項目是否為已知且授權的軟體。",
                    host, path
                ),
                "netconn" => format!(
                    "主機 {} 上，{} 發起了對外網路連線，\
                     建議確認連線目標是否屬於正常業務範疇。",
                    host, path
                ),
                "file_meta" => format!(
                    "主機 {} 上，{} 的時間戳記疑似遭到竄改，\
                     建議進一步確認該檔案的真實建立時間。",
                    host, path
                ),
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
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for Medium");
        assert!(text.contains("持久化機制"), "got: {text}");
    }

    #[test]
    fn netconn_heuristic_filled() {
        let mut f = make_heuristic(Severity::High, "netconn");
        fill_details_client(&mut f);
        let text = f.details_client.expect("must be Some for High");
        assert!(text.contains("對外網路連線"), "got: {text}");
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
        assert!(
            text.contains("Mimikatz Credential Dumping"),
            "title missing: {text}"
        );
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
}
