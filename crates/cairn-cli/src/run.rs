//! `cairn run`: live triage of this host. Probe privileges, select and build the
//! collectors from the registry, run them and the analyzers through the orchestrator,
//! enrich, then write timeline/findings/observations/report/records/manifest.
use crate::cli::RunArgs;
use crate::output::{self, BUILD_SHA};
use crate::registry::{self, BuildCtx, Mode};
use cairn_core::manifest::{GovernanceReport, HostInfo, Manifest};
use cairn_core::orchestrator::{run_live, RunOutcome};
use cairn_core::{Config, OutputKind, Profile, SelectionOutcome};
use cairn_report::client_text;
use std::path::{Path, PathBuf};

/// Where run.log goes. For `--zip` it is the archive's parent directory, NOT the
/// output path itself: create_dir_all on a .zip path would make a directory named
/// "cairn_out.zip", which then conflicts when ZipSink opens that path as a file.
fn log_dir(args: &RunArgs) -> PathBuf {
    if !args.zip {
        return args.output.clone();
    }
    match args.output.parent() {
        Some(p) if p != Path::new("") => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// OutputKind from the CLI flags: --dry-run > --zip > plain dir.
fn output_kind(args: &RunArgs) -> OutputKind {
    if args.dry_run {
        OutputKind::DryRun
    } else if args.zip {
        OutputKind::Zip(args.output.clone())
    } else {
        OutputKind::Dir(args.output.clone())
    }
}

/// The run Config from the CLI flags. No --rules: use the bundled rules next to the
/// binary (or under the current directory) so a plain `cairn run` still runs Sigma.
fn build_config(args: &RunArgs, profile: Profile) -> anyhow::Result<Config> {
    let mut cfg = Config {
        profile,
        output: output_kind(args),
        ..Config::default()
    };
    cfg.rules_dir = args.rules.clone().or_else(output::default_rules_dir);
    cfg.case_id = args.case_id.clone().unwrap_or_default();
    cfg.operator = args.operator.clone().unwrap_or_default();
    // Resource governance (NFR9/NFR10): `run` only triages the live host.
    cfg.governance.low_priority =
        matches!(cfg.target, cairn_core::Target::Live) && !args.full_speed;
    // Live-EVTX look-back: --since (RFC3339 UTC) or the registry default.
    cfg.since = Some(match args.since.as_deref() {
        Some(s) => s
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|e| anyhow::anyhow!("--since parse error: {e}"))?,
        None => registry::default_since(chrono::Utc::now()),
    });
    Ok(cfg)
}

/// Lower process priority when governance asks for it; true if applied.
fn apply_low_priority(cfg: &Config) -> bool {
    if !cfg.governance.low_priority {
        return false;
    }
    match cairn_collectors_win::priority::lower_priority() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "failed to lower process priority; continuing at normal priority");
            false
        }
    }
}

/// Pure collector selection from the registry, logged for transparency (FR6).
fn select(profile: Profile, only: Option<&[String]>) -> SelectionOutcome {
    let selection = cairn_core::select_modules(profile, only, &registry::module_infos());
    for name in &selection.unknown_only {
        tracing::warn!(
            only = %name,
            "--only names a module that is not an available live collector; ignoring it"
        );
    }
    tracing::info!(
        profile = %format!("{profile:?}").to_lowercase(),
        modules = %selection.selected.join(","),
        "collector selection"
    );
    selection
}

/// Stamp host onto findings/observations and sort both deterministically (NFR4).
fn finalize_outcome(outcome: &mut RunOutcome) {
    for f in &mut outcome.findings {
        f.host = outcome.hostname.clone();
    }
    output::sort_findings(&mut outcome.findings);
    for o in &mut outcome.observations {
        o.host = outcome.hostname.clone();
    }
    outcome.observations.sort_by(|a, b| {
        (a.category.as_str(), a.title.as_str()).cmp(&(b.category.as_str(), b.title.as_str()))
    });
}

/// The live run's manifest: the shared skeleton plus live host/privilege/source facts.
fn live_manifest(
    cfg: &Config,
    outcome: &RunOutcome,
    selection: &SelectionOutcome,
    started_utc: chrono::DateTime<chrono::Utc>,
    low_priority_applied: bool,
) -> Manifest {
    let mut m = output::base_manifest(
        cfg,
        &outcome.hostname,
        outcome.records.len() as u64,
        &outcome.findings,
        outcome.observations.len() as u64,
        started_utc,
    );
    m.run.selected_modules = selection.selected.clone();
    m.host = HostInfo {
        hostname: outcome.hostname.clone(),
        os_build: cairn_collectors::host_info::os_build(),
        timezone: cairn_collectors::host_info::timezone(),
        wall_clock_utc_skew: "unknown".into(),
    };
    m.privileges = outcome.privileges.clone();
    m.sources = outcome.sources.clone();
    m.governance = GovernanceReport {
        low_priority_applied,
    };
    m
}

/// Write every output through the sink. manifest.outputs stays empty for live runs:
/// DirSink logs per-file sha256 at finalize; the zip sink is integrity-checked at the
/// archive level.
fn write_outputs(cfg: &Config, outcome: &RunOutcome, manifest: Manifest) -> anyhow::Result<()> {
    let mut sink = output::build_sink(&cfg.output);
    sink.write_timeline_csv(&outcome.findings)?;
    sink.write_findings_jsonl(&outcome.findings)?;
    sink.write_observations(&outcome.observations)?;
    sink.write_html_report(
        &outcome.findings,
        &outcome.observations,
        &outcome.records,
        &manifest,
    )?;
    if let OutputKind::Dir(ref d) = cfg.output {
        output::write_records_jsonl(d, &outcome.records)?;
    }
    sink.write_manifest(&manifest)?;
    for o in sink.finalize()? {
        tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
    }
    Ok(())
}

pub fn run(args: &RunArgs) -> anyhow::Result<()> {
    let started_utc = chrono::Utc::now();

    // Parse --profile FIRST: an invalid value is a clean CLI error before any output
    // is created or a run starts — not a silent Standard fallback.
    let profile: Profile = args
        .profile
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let cfg = build_config(args, profile)?;

    // --dry-run (FR16 / golden rule 4): write NOTHING — no output dir, no run.log; logs
    // go to stderr and only a summary is printed.
    let guard = if args.dry_run {
        output::init_stderr_logging();
        None
    } else {
        let dir = log_dir(args);
        std::fs::create_dir_all(&dir)?;
        Some(output::init_file_logging(&dir))
    };

    tracing::info!(
        "cairn {} ({}) starting (live)",
        env!("CARGO_PKG_VERSION"),
        BUILD_SHA
    );
    let privileges = cairn_collectors_win::privilege::probe();
    tracing::info!(
        admin = privileges.admin,
        se_backup = privileges.se_backup,
        se_debug = privileges.se_debug,
        "privilege probe"
    );
    let hostname = cairn_collectors_win::host::hostname().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "hostname probe failed; using 'unknown'");
        "unknown".into()
    });

    let selection = select(profile, args.only_list().as_deref());
    let low_priority_applied = apply_low_priority(&cfg);

    // Sigma loads before collector construction so the live EVTX collector reads the
    // channels the rules reference.
    let sigma = output::load_sigma(&cfg);
    let ctx = BuildCtx {
        cfg: &cfg,
        sigma_channels: sigma.as_ref().map(|s| s.channels()),
    };
    let collectors = registry::build_collectors(&selection.selected, &ctx);
    let analyzers = registry::analyzers(&cfg, Mode::Live, sigma);

    let mut outcome = run_live(&cfg, privileges, hostname, &collectors, &analyzers);
    finalize_outcome(&mut outcome);
    crate::enrich::enrich_hashes(
        &mut outcome.records,
        &outcome.findings,
        crate::enrich::hash_on_disk,
    );
    tracing::info!(
        records = outcome.records.len(),
        findings = outcome.findings.len(),
        "live collection + analysis complete"
    );

    let manifest = live_manifest(
        &cfg,
        &outcome,
        &selection,
        started_utc,
        low_priority_applied,
    );
    for f in &mut outcome.findings {
        client_text::fill_details_client(f, manifest.run.started_utc);
    }
    write_outputs(&cfg, &outcome, manifest)?;
    if args.dry_run {
        println!(
            "dry-run: {} records, {} findings — no files written (would have gone to {})",
            outcome.records.len(),
            outcome.findings.len(),
            args.output.display()
        );
    } else {
        tracing::info!(output = ?cfg.output, "run complete");
    }
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::manifest::Privileges;
    use cairn_core::record::{EventRecord, Record};
    use cairn_core::traits::{CollectCtx, Collector};
    use chrono::Utc;
    use clap::Parser;

    fn args(extra: &[&str]) -> RunArgs {
        let mut v = vec!["cairn", "--output", "out/cairn.zip"];
        v.extend_from_slice(extra);
        RunArgs::parse_from(v)
    }

    #[test]
    fn zip_logs_beside_the_archive_and_dir_logs_inside() {
        assert_eq!(log_dir(&args(&["--zip"])), PathBuf::from("out"));
        assert_eq!(log_dir(&args(&[])), PathBuf::from("out/cairn.zip"));
        let bare = RunArgs::parse_from(["cairn", "--output", "c.zip", "--zip"]);
        assert_eq!(log_dir(&bare), PathBuf::from("."));
    }

    #[test]
    fn dry_run_wins_over_zip() {
        assert!(matches!(
            output_kind(&args(&["--zip", "--dry-run"])),
            OutputKind::DryRun
        ));
        assert!(matches!(output_kind(&args(&["--zip"])), OutputKind::Zip(_)));
    }

    #[test]
    fn config_carries_flags_and_default_since() {
        let a = args(&["--case-id", "IR-9", "--full-speed"]);
        let cfg = build_config(&a, Profile::Minimal).unwrap();
        assert_eq!(cfg.case_id, "IR-9");
        assert!(!cfg.governance.low_priority, "--full-speed opts out");
        let since = cfg.since.unwrap();
        let age = Utc::now() - since;
        assert!(age >= chrono::Duration::days(7) && age < chrono::Duration::days(8));
        assert!(build_config(&args(&["--since", "nope"]), Profile::Standard).is_err());
    }

    fn privs() -> Privileges {
        Privileges {
            admin: false,
            se_backup: false,
            se_debug: false,
        }
    }

    struct FixedEvents(Vec<EventRecord>);
    impl Collector for FixedEvents {
        fn name(&self) -> &str {
            "fake_events"
        }
        fn collect(&self, _ctx: &CollectCtx<'_>) -> cairn_core::Result<Vec<Record>> {
            Ok(self.0.iter().cloned().map(Record::Event).collect())
        }
    }

    fn event(eid: u32, record_id: u64, data: &[(&str, &str)]) -> EventRecord {
        let mut map = serde_json::Map::new();
        for (k, v) in data {
            map.insert(
                (*k).to_string(),
                serde_json::Value::String((*v).to_string()),
            );
        }
        EventRecord {
            ts: Utc::now() + chrono::Duration::seconds(record_id as i64 * 20),
            channel: "Security".to_string(),
            event_id: eid,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            computer: "TEST".to_string(),
            record_id,
            data: map,
        }
    }

    /// Integration: the registry's live analyzer set (with Sigma) wired into run_live
    /// receives Record::Event and produces an attributed Sigma finding.
    #[test]
    fn sigma_analyzer_findings_appear_in_live_outcome() {
        const RULE: &str = r#"
title: Test PowerShell detection
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
level: high
author: test-integration
"#;
        let ev = event(
            4688,
            42,
            &[(
                "Image",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            )],
        );
        let engine = cairn_sigma::engine::Engine::from_rules(&[RULE]).expect("rule must parse");
        let cfg = Config::default();
        let analyzers = registry::analyzers(
            &cfg,
            Mode::Live,
            Some(cairn_heur::SigmaAnalyzer::new(engine)),
        );
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FixedEvents(vec![ev]))];
        let outcome = run_live(&cfg, privs(), "TEST".into(), &collectors, &analyzers);

        assert_eq!(outcome.records.len(), 1, "event record must be collected");
        let sigma: Vec<_> = outcome
            .findings
            .iter()
            .filter(|f| f.analyzer == cairn_core::analyzers::SIGMA)
            .collect();
        assert!(!sigma.is_empty(), "sigma finding must be present");
        assert_eq!(
            sigma[0].rule_author.as_deref(),
            Some("test-integration"),
            "finding must carry DRL 1.1 rule_author"
        );
    }

    /// Integration: the registry's brute-force heuristic detects the pattern end to end
    /// (fake collector -> run_live -> RunOutcome.findings).
    #[test]
    fn logon_bruteforce_heuristic_fires_in_live_outcome() {
        let events: Vec<EventRecord> = (0..5)
            .map(|i| {
                event(
                    4625,
                    100 + i,
                    &[
                        ("TargetUserName", "integration_user"),
                        ("IpAddress", "192.0.2.10"),
                    ],
                )
            })
            .collect();
        let cfg = Config::default();
        let analyzers = registry::analyzers(&cfg, Mode::Evtx, None);
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FixedEvents(events))];
        let outcome = run_live(&cfg, privs(), "TEST".into(), &collectors, &analyzers);

        assert_eq!(outcome.records.len(), 5);
        let f = outcome
            .findings
            .iter()
            .find(|f| f.analyzer == cairn_core::analyzers::LOGON_BRUTEFORCE)
            .expect("bruteforce finding must be present in RunOutcome");
        assert_eq!(f.severity, cairn_core::finding::Severity::Medium);
        assert!(f.reason.is_some(), "golden rule 6: reason must be set");
        assert_eq!(f.mitre, vec!["T1110.001".to_string()]);
    }
}
