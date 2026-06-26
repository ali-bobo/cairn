#![forbid(unsafe_code)]

use cairn_core::record::Record;
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};

/// Cross-artifact correlation: emit High Finding when the same binary
/// appears in both persistence and execution artifact sources.
pub struct CorrelationAnalyzer;

/// Normalize a binary path or filename to a bare lowercase stem for correlation.
///
/// Examples:
///   `C:\Windows\System32\svchost.exe`  → `svchost`
///   `NOTION.EXE-1234ABCD.pf`           → `notion.exe-1234abcd` (strip only last suffix)
///   `%windir%\system32\svchost.exe`    → `svchost`
///
/// Returns empty string for empty input — callers skip empty keys.
// Task 2 will call this from `analyze`; suppress the dead_code lint until then.
#[allow(dead_code)]
pub(crate) fn normalized_basename(path: &str) -> String {
    let s = path.trim().trim_matches('"').to_ascii_lowercase();
    let stem = s
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&s);
    // Strip exactly one known forensic extension
    let stem = stem
        .strip_suffix(".exe")
        .or_else(|| stem.strip_suffix(".pf"))
        .unwrap_or(stem);
    stem.to_string()
}

impl Analyzer for CorrelationAnalyzer {
    fn name(&self) -> &str {
        "heur_correlation"
    }

    fn analyze(&self, _records: &[Record]) -> Result<Vec<Finding>> {
        Ok(vec![]) // placeholder — implemented in Task 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::{EntityFile, FindingSource, Severity};
    use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn exec(path: &str, source: &str) -> Record {
        Record::Execution(ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        })
    }

    fn persist(mechanism: &str, location: &str, command: &str, binary_path: Option<&str>) -> Record {
        Record::Persistence(PersistenceRecord {
            mechanism: mechanism.into(),
            location: location.into(),
            value: Some(mechanism.into()),
            command: Some(command.into()),
            binary_path: binary_path.map(|s| s.into()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
        })
    }

    fn process_rec(image: &str, pid: u32) -> Record {
        Record::Process(ProcessRecord {
            pid,
            ppid: 1,
            image: image.into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        })
    }

    // ── normalized_basename ───────────────────────────────────────────────────

    #[test]
    fn basename_full_path_exe() {
        assert_eq!(
            normalized_basename(r"C:\Windows\System32\svchost.exe"),
            "svchost"
        );
    }

    #[test]
    fn basename_prefetch_name() {
        assert_eq!(
            normalized_basename("NOTION.EXE-1234ABCD.pf"),
            "notion.exe-1234abcd"
        );
    }

    #[test]
    fn basename_env_var_path() {
        assert_eq!(
            normalized_basename(r"%windir%\system32\svchost.exe"),
            "svchost"
        );
    }

    #[test]
    fn basename_bare_name() {
        assert_eq!(normalized_basename("explorer.exe"), "explorer");
    }

    #[test]
    fn basename_empty() {
        assert_eq!(normalized_basename(""), "");
    }

    #[test]
    fn basename_quoted_path() {
        assert_eq!(
            normalized_basename(r#""C:\Temp\evil.exe""#),
            "evil"
        );
    }

    // ── CorrelationAnalyzer (placeholder — Task 2 implements analyze) ─────────

    #[test]
    fn exec_and_persist_same_binary_emits_high_finding() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
                    Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe")),
            exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        // Task 2 will make this pass; for now just verify it doesn't panic
        let _ = findings;
    }

    #[test]
    fn exec_without_persist_emits_nothing() {
        let records = vec![exec(r"C:\Temp\evil.exe", "prefetch")];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn persist_without_exec_emits_nothing() {
        let records = vec![persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Temp\evil.exe",
            Some(r"C:\Temp\evil.exe"),
        )];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn inbox_service_is_suppressed() {
        let records = vec![
            persist("service", r"HKLM\SYSTEM\CurrentControlSet\Services\Schedule",
                    r"C:\Windows\System32\svchost.exe -k netsvcs",
                    Some(r"C:\Windows\System32\svchost.exe")),
            exec("SVCHOST.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let _ = CorrelationAnalyzer.analyze(&records).unwrap();
    }

    #[test]
    fn driverstore_binary_not_suppressed() {
        let records = vec![
            persist("service", r"HKLM\SYSTEM\CurrentControlSet\Services\EvilDrv",
                    r"C:\Windows\System32\DriverStore\FileRepository\evil.inf_amd64\evil.exe",
                    Some(r"C:\Windows\System32\DriverStore\FileRepository\evil.inf_amd64\evil.exe")),
            exec("EVIL.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let _ = CorrelationAnalyzer.analyze(&records).unwrap();
    }

    #[test]
    fn finding_title_and_artifact_field() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let _ = CorrelationAnalyzer.analyze(&records).unwrap();
    }

    #[test]
    fn finding_has_reason_and_details() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let _ = CorrelationAnalyzer.analyze(&records).unwrap();
    }

    #[test]
    fn process_corroboration_adds_to_reason() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
            process_rec(r"C:\Temp\bad.exe", 1234),
        ];
        let _ = CorrelationAnalyzer.analyze(&records).unwrap();
    }

    #[test]
    fn no_exec_records_emits_nothing() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Temp\bad.exe", Some(r"C:\Temp\bad.exe")),
            process_rec(r"C:\Temp\bad.exe", 1234),
        ];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn multiple_exec_sources_listed_in_reason() {
        let records = vec![
            persist("run_key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
                    Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe")),
            exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
            exec(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe", "amcache"),
        ];
        let _ = CorrelationAnalyzer.analyze(&records).unwrap();
    }

    // ── suppress unused import warnings for Task 2 readiness ─────────────────

    #[allow(dead_code)]
    fn _use_imports(_: EntityFile, _: FindingSource, _: Severity) {}
}
