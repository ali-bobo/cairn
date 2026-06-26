#![forbid(unsafe_code)]

use crate::score::is_inbox_service_command;
use cairn_core::finding::{EntityFile, FindingSource, Severity};
use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::Utc;
use std::collections::{BTreeSet, HashMap};

/// Cross-artifact correlation: emit High Finding when the same binary
/// appears in both persistence and execution artifact sources.
pub struct CorrelationAnalyzer;

fn mechanism_to_mitre(mechanism: &str) -> &'static str {
    match mechanism {
        "service" => "T1543.003",
        "run_key" | "startup" => "T1547.001",
        "scheduled_task" => "T1053.005",
        "winlogon" => "T1547.004",
        "ifeo" => "T1546.012",
        _ => "T1547",
    }
}

impl Analyzer for CorrelationAnalyzer {
    fn name(&self) -> &str {
        "heur_correlation"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let mut exec_map: HashMap<String, Vec<&ExecutionRecord>> = HashMap::new();
        let mut persist_map: HashMap<String, Vec<&PersistenceRecord>> = HashMap::new();
        let mut proc_map: HashMap<String, Vec<&ProcessRecord>> = HashMap::new();

        for r in records {
            match r {
                Record::Execution(e) => {
                    let key = normalized_basename(&e.path);
                    if !key.is_empty() {
                        exec_map.entry(key).or_default().push(e);
                    }
                }
                Record::Persistence(p) => {
                    let raw = p
                        .binary_path
                        .as_deref()
                        .or(p.command.as_deref())
                        .unwrap_or("");
                    let key = normalized_basename(raw);
                    if !key.is_empty() {
                        persist_map.entry(key).or_default().push(p);
                    }
                }
                Record::Process(pr) => {
                    let key = normalized_basename(&pr.image);
                    if !key.is_empty() {
                        proc_map.entry(key).or_default().push(pr);
                    }
                }
                _ => {}
            }
        }

        let mut findings = Vec::new();
        let now = Utc::now();

        for (key, persist_entries) in &persist_map {
            let exec_entries = match exec_map.get(key.as_str()) {
                Some(e) => e,
                None => continue,
            };

            // Group by mechanism to avoid one Finding per service entry
            let mut by_mechanism: HashMap<&str, Vec<&&PersistenceRecord>> = HashMap::new();
            for p in persist_entries {
                by_mechanism.entry(p.mechanism.as_str()).or_default().push(p);
            }

            for (mechanism, group) in &by_mechanism {
                // Representative: latest last_write, fallback to first
                let repr = group
                    .iter()
                    .max_by_key(|p| p.last_write)
                    .copied()
                    .unwrap_or(group[0]);

                let cmd = repr
                    .command
                    .as_deref()
                    .unwrap_or_else(|| repr.binary_path.as_deref().unwrap_or(""));
                if is_inbox_service_command(cmd) {
                    continue;
                }

                // Execution evidence — deduplicated, sorted source names
                let exec_sources: Vec<&str> = exec_entries
                    .iter()
                    .map(|e| e.source.as_str())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let last_run = exec_entries.iter().filter_map(|e| e.last_run).max();
                let exec_src_str = exec_sources.join(", ");

                // Process corroboration
                let live_pids: Vec<u32> = proc_map
                    .get(key.as_str())
                    .map(|ps| ps.iter().map(|p| p.pid).collect())
                    .unwrap_or_default();

                // Best path for entity
                let best_path = repr
                    .binary_path
                    .as_deref()
                    .filter(|p| !p.is_empty())
                    .or_else(|| exec_entries.first().map(|e| e.path.as_str()))
                    .unwrap_or(key.as_str())
                    .to_string();

                let mitre = mechanism_to_mitre(mechanism);

                let last_run_str = last_run
                    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| "unknown".into());
                let details = format!(
                    "{key} persisted via {mechanism} ({loc}); confirmed executed [{exec_src_str}] last_run={last_run_str}",
                    loc = repr.location
                );

                let mut reason_parts = vec![
                    format!("binary found in persistence ({mechanism}: {})", repr.location),
                    format!("and execution records ({exec_src_str})"),
                ];
                if !live_pids.is_empty() {
                    let pid_str = live_pids
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    reason_parts.push(format!("and currently running (pid={pid_str})"));
                }
                let reason = reason_parts.join(" ");

                let mut f = Finding::new(
                    Severity::High,
                    format!("Confirmed persistence + execution: {key}"),
                    FindingSource::Heuristic,
                );
                f.ts = now;
                f.artifact = "correlation".into();
                f.mitre = vec![mitre.into()];
                f.entity.file = Some(EntityFile {
                    path: best_path,
                    sha256: None,
                    mtime: None,
                    si_btime: None,
                    fn_btime: None,
                    si_mtime: None,
                    fn_mtime: None,
                    path_complete: None,
                });
                f.details = details;
                f.reason = Some(reason);

                findings.push(f);
            }
        }

        Ok(findings)
    }
}

/// Normalize a binary path or filename to a bare lowercase stem for correlation.
///
/// Examples:
///   `C:\Windows\System32\svchost.exe`  → `svchost`
///   `NOTION.EXE-1234ABCD.pf`           → `notion`
///   `%windir%\system32\svchost.exe`    → `svchost`
///
/// Prefetch filenames have the form `BINARY.EXE-HASHVALUE.pf`. We strip `.pf` first,
/// then strip the `.exe-HASH` suffix so they correlate with plain `.exe` paths.
///
/// Returns empty string for empty input — callers skip empty keys.
pub(crate) fn normalized_basename(path: &str) -> String {
    let s = path.trim().trim_matches('"').to_ascii_lowercase();
    let stem = s.rsplit(['\\', '/']).next().unwrap_or(&s);
    // Two-step for prefetch filenames (e.g. "NOTION.EXE-AABBCCDD.pf"):
    // 1. strip ".pf"  → "notion.exe-aabbccdd"
    // 2. strip ".exe-HASH"  → "notion"
    let stem = if let Some(pf_stripped) = stem.strip_suffix(".pf") {
        if let Some(exe_pos) = pf_stripped.find(".exe-") {
            &pf_stripped[..exe_pos]
        } else {
            pf_stripped
        }
    } else {
        stem.strip_suffix(".exe").unwrap_or(stem)
    };
    stem.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
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
            "notion"
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

    // ── CorrelationAnalyzer ──────────────────────────────────────────────────

    #[test]
    fn exec_and_persist_same_binary_emits_high_finding() {
        let records = vec![
            persist(
                "run_key",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
                Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"),
            ),
            exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1, "expected one correlation finding");
        let f = &findings[0];
        assert_eq!(f.severity, Severity::High);
        assert!(
            f.title.to_ascii_lowercase().contains("notion"),
            "title: {}",
            f.title
        );
        assert_eq!(f.artifact, "correlation");
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
            persist(
                "service",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Schedule",
                r"C:\Windows\System32\svchost.exe -k netsvcs",
                Some(r"C:\Windows\System32\svchost.exe"),
            ),
            exec("SVCHOST.EXE-AABBCCDD.pf", "prefetch"),
        ];
        assert!(
            CorrelationAnalyzer.analyze(&records).unwrap().is_empty(),
            "inbox svchost service must be suppressed"
        );
    }

    #[test]
    fn driverstore_binary_not_suppressed() {
        let records = vec![
            persist(
                "service",
                r"HKLM\SYSTEM\CurrentControlSet\Services\EvilDrv",
                r"C:\Windows\System32\DriverStore\FileRepository\evil.inf_amd64\evil.exe",
                Some(r"C:\Windows\System32\DriverStore\FileRepository\evil.inf_amd64\evil.exe"),
            ),
            exec("EVIL.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1, "DriverStore BYOVD must fire");
    }

    #[test]
    fn finding_title_and_artifact_field() {
        let records = vec![
            persist(
                "run_key",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Temp\bad.exe",
                Some(r"C:\Temp\bad.exe"),
            ),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.artifact, "correlation");
        assert!(
            f.title.to_ascii_lowercase().contains("bad"),
            "title: {}",
            f.title
        );
        assert_eq!(f.source, FindingSource::Heuristic);
    }

    #[test]
    fn finding_has_reason_and_details() {
        let records = vec![
            persist(
                "run_key",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Temp\bad.exe",
                Some(r"C:\Temp\bad.exe"),
            ),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        let f = &findings[0];
        assert!(f.reason.is_some(), "reason must be set (golden rule 6)");
        let reason = f.reason.as_deref().unwrap();
        assert!(
            reason.contains("run_key") || reason.contains("persist"),
            "reason: {reason}"
        );
        assert!(!f.details.is_empty(), "details must be set");
    }

    #[test]
    fn process_corroboration_adds_to_reason() {
        let records = vec![
            persist(
                "run_key",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Temp\bad.exe",
                Some(r"C:\Temp\bad.exe"),
            ),
            exec("BAD.EXE-AABBCCDD.pf", "prefetch"),
            process_rec(r"C:\Temp\bad.exe", 1234),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        let reason = findings[0].reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("running") || reason.contains("1234"),
            "reason: {reason}"
        );
    }

    #[test]
    fn no_exec_records_emits_nothing() {
        let records = vec![
            persist(
                "run_key",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Temp\bad.exe",
                Some(r"C:\Temp\bad.exe"),
            ),
            process_rec(r"C:\Temp\bad.exe", 1234),
        ];
        assert!(CorrelationAnalyzer.analyze(&records).unwrap().is_empty());
    }

    #[test]
    fn multiple_exec_sources_listed_in_reason() {
        let records = vec![
            persist(
                "run_key",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
                Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"),
            ),
            exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
            exec(
                r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
                "amcache",
            ),
        ];
        let findings = CorrelationAnalyzer.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        let reason = findings[0].reason.as_deref().unwrap_or("");
        let details = &findings[0].details;
        let combined = format!("{reason} {details}");
        assert!(combined.contains("prefetch"), "prefetch source: {combined}");
        assert!(combined.contains("amcache"), "amcache source: {combined}");
    }
}
