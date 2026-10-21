//! `cairn run`: live triage of this host. Probe privileges, select and build the
//! collectors from the registry, run them, hash persistence targets, run the analyzers,
//! then write timeline/findings/observations/records/report/EVTX evidence/manifest.
use crate::cli::RunArgs;
use crate::output::{self, BUILD_SHA};
use crate::registry::{self, BuildCtx, Mode};
use cairn_core::manifest::{GovernanceReport, HostInfo, Manifest};
use cairn_core::orchestrator::{run_analyzers, run_live, RunOutcome};
use cairn_core::traits::{Analyzer, Collector};
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

/// Clock facts for the manifest (golden rule 7). The UTC offset is always measurable.
/// Skew against true time is not measurable from user space without a network time
/// source, so it is recorded as such unless the operator supplied `--reference-time`
/// (the true UTC at run start), in which case it is `started_utc - reference` seconds.
fn host_clock(
    started_utc: chrono::DateTime<chrono::Utc>,
    utc_offset_seconds: i32,
    reference_time: Option<chrono::DateTime<chrono::Utc>>,
) -> HostInfo {
    use cairn_core::manifest::{format_skew, skew_seconds, SKEW_NOT_MEASURED};
    let skew = reference_time.map(|r| skew_seconds(started_utc, r));
    HostInfo {
        hostname: String::new(),
        os_build: String::new(),
        timezone: String::new(),
        wall_clock_utc_skew: skew.map_or_else(|| SKEW_NOT_MEASURED.to_string(), format_skew),
        utc_offset_seconds: Some(utc_offset_seconds),
        reference_time_utc: reference_time,
        skew_seconds: skew,
    }
}

/// Run the collectors, hash every persistence target, THEN run the analyzers — so the
/// analyzers (and the findings they emit) see `binary_sha256` — and finally hash the
/// process images behind findings that still lack one. Collector/analyzer failures are
/// recorded in `sources` exactly as `run_live` records them.
fn collect_then_analyze(
    cfg: &Config,
    privileges: cairn_core::manifest::Privileges,
    hostname: String,
    collectors: &[Box<dyn Collector>],
    analyzers: &[Box<dyn Analyzer>],
    hash_fn: impl Fn(&str) -> Option<String> + Copy,
) -> RunOutcome {
    let mut outcome = run_live(cfg, privileges, hostname, collectors, &[]);
    crate::enrich::enrich_persistence_hashes(&mut outcome.records, hash_fn);
    let analysis = run_analyzers(&outcome.records, analyzers);
    outcome.findings = analysis.findings;
    outcome.observations = analysis.observations;
    outcome.sources.extend(analysis.errors);
    finalize_outcome(&mut outcome);
    crate::enrich::enrich_process_hashes(&mut outcome.records, &outcome.findings, hash_fn);
    outcome
}

/// The live run's manifest: the shared skeleton plus live host/privilege/source facts.
fn live_manifest(
    cfg: &Config,
    outcome: &RunOutcome,
    selection: &SelectionOutcome,
    started_utc: chrono::DateTime<chrono::Utc>,
    low_priority_applied: bool,
    reference_time: Option<chrono::DateTime<chrono::Utc>>,
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
        ..host_clock(
            started_utc,
            chrono::Local::now().offset().local_minus_utc(),
            reference_time,
        )
    };
    m.privileges = outcome.privileges.clone();
    m.sources = outcome.sources.clone();
    m.governance = GovernanceReport {
        low_priority_applied,
    };
    m
}

/// Write every output through the sink — dir and zip alike — then embed every data
/// output's SHA-256 + size into `manifest.outputs` before writing the manifest itself
/// (chain of custody; `cairn verify` re-hashes each one). EVTX evidence is exported
/// first so a failed channel is in the manifest (and report) sources. Under `--dry-run`
/// the sink discards everything and nothing touches the disk.
fn write_outputs(
    cfg: &Config,
    outcome: &RunOutcome,
    mut manifest: Manifest,
    export: Option<&crate::export::ExportPlan>,
) -> anyhow::Result<()> {
    use cairn_core::traits::OutputSink;
    let mut sink = output::build_sink(&cfg.output);
    if let Some(plan) = export.filter(|_| !sink.is_dry_run()) {
        let failures = crate::export::export_into(
            &mut sink,
            plan,
            cairn_collectors_win::evtx_export::export_channel,
        );
        manifest.sources.extend(failures);
    }
    sink.write_timeline_csv(&outcome.findings)?;
    sink.write_findings_jsonl(&outcome.findings)?;
    sink.write_observations(&outcome.observations)?;
    sink.write_records_jsonl(&outcome.records)?;
    sink.write_html_report(
        &outcome.findings,
        &outcome.observations,
        &outcome.records,
        &manifest,
    )?;
    manifest.outputs = sink.outputs_so_far();
    sink.write_manifest(&manifest)?;
    for o in sink.finalize()? {
        tracing::info!(file = %o.file, sha256 = %o.sha256, size = o.size, "wrote output");
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
    let reference_time = args.reference_time()?;

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
    let export_plan = crate::export::plan(
        args.export_evtx_enabled() && !args.dry_run,
        &selection.selected,
        registry::live_evtx_channels(ctx.sigma_channels),
        cfg.since
            .unwrap_or_else(|| registry::default_since(chrono::Utc::now())),
    );
    let analyzers = registry::analyzers(&cfg, Mode::Live, sigma);

    let mut outcome = collect_then_analyze(
        &cfg,
        privileges,
        hostname,
        &collectors,
        &analyzers,
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
        reference_time,
    );
    for f in &mut outcome.findings {
        client_text::fill_details_client(f, manifest.run.started_utc);
    }
    write_outputs(&cfg, &outcome, manifest, export_plan.as_ref())?;
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
        assert!(age >= chrono::Duration::days(30) && age < chrono::Duration::days(31));
        assert!(build_config(&args(&["--since", "nope"]), Profile::Standard).is_err());
    }

    /// Without a reference the skew is explicitly "not measured"; with one it is
    /// host-minus-reference seconds, and the offset is always recorded.
    #[test]
    fn host_clock_records_offset_and_optional_skew() {
        let start = Utc::now();
        let h = host_clock(start, 28800, None);
        assert_eq!(
            h.wall_clock_utc_skew,
            cairn_core::manifest::SKEW_NOT_MEASURED
        );
        assert_eq!(h.utc_offset_seconds, Some(28800));
        assert!(h.skew_seconds.is_none());
        let h = host_clock(start, 0, Some(start - chrono::Duration::seconds(42)));
        assert_eq!(h.skew_seconds, Some(42));
        assert_eq!(h.wall_clock_utc_skew, "+42s");
        assert_eq!(
            h.reference_time_utc,
            Some(start - chrono::Duration::seconds(42))
        );
    }

    /// Persistence targets are hashed BEFORE the analyzers run: an analyzer sees
    /// `binary_sha256` on the record.
    #[test]
    fn analyzers_see_persistence_hashes() {
        use cairn_core::record::PersistenceRecord;
        struct Persist;
        impl Collector for Persist {
            fn name(&self) -> &str {
                "fake_persist"
            }
            fn collect(&self, _: &CollectCtx<'_>) -> cairn_core::Result<Vec<Record>> {
                Ok(vec![Record::Persistence(PersistenceRecord {
                    mechanism: cairn_core::Mechanism::RunKey,
                    location: "HKCU\\Run".into(),
                    value: Some("x".into()),
                    command: Some(r"C:\x.exe".into()),
                    binary_path: Some(r"C:\x.exe".into()),
                    binary_sha256: None,
                    signed: None,
                    signer: None,
                    last_write: None,
                    service_start: None,
                    signer_source: None,
                    bound: None,
                })])
            }
        }
        struct SeesHash;
        impl Analyzer for SeesHash {
            fn name(&self) -> &str {
                "sees_hash"
            }
            fn analyze(
                &self,
                records: &[Record],
                _: &[cairn_core::Finding],
            ) -> cairn_core::Result<Vec<cairn_core::Finding>> {
                Ok(records
                    .iter()
                    .filter_map(|r| match r {
                        Record::Persistence(p) => p.binary_sha256.clone(),
                        _ => None,
                    })
                    .map(|h| {
                        cairn_core::Finding::new(
                            cairn_core::Severity::Low,
                            h,
                            cairn_core::FindingSource::Heuristic,
                        )
                    })
                    .collect())
            }
        }
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Persist)];
        let analyzers: Vec<Box<dyn Analyzer>> = vec![Box::new(SeesHash)];
        let outcome = collect_then_analyze(
            &Config::default(),
            privs(),
            "T".into(),
            &collectors,
            &analyzers,
            |_| Some("abc123".into()),
        );
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].title, "abc123");
        assert_eq!(
            outcome.findings[0].host, "T",
            "finalize_outcome still applied"
        );
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
        // Every loaded rule reports whether it could fire on this run's logs.
        let statuses: Vec<_> = outcome
            .observations
            .iter()
            .filter(|o| o.category == cairn_core::observation::CATEGORY_SIGMA_RULE)
            .collect();
        assert_eq!(statuses.len(), 1, "one status per loaded rule");
        assert_eq!(
            statuses[0].sigma_rule.as_ref().map(|s| s.viability),
            Some(cairn_core::observation::RuleViability::Runnable),
            "a collected 4688 proves process-creation auditing"
        );
    }

    fn outcome_with_one_record() -> RunOutcome {
        RunOutcome {
            records: vec![Record::Event(event(4688, 7, &[("Image", "x.exe")]))],
            findings: vec![{
                let mut f = cairn_core::Finding::new(
                    cairn_core::Severity::High,
                    "t",
                    cairn_core::FindingSource::Sigma,
                );
                f.rule_author = Some("A".into());
                f
            }],
            observations: vec![],
            sources: vec![],
            privileges: privs(),
            hostname: "TEST".into(),
        }
    }

    fn manifest_for(cfg: &Config, outcome: &RunOutcome) -> Manifest {
        let selection = SelectionOutcome {
            selected: vec!["proc".into()],
            unknown_only: vec![],
        };
        live_manifest(cfg, outcome, &selection, Utc::now(), false, None)
    }

    /// A live dir run lists every written data file in manifest.outputs (with size),
    /// records.jsonl included; verify passes, and tampering ONE output makes it fail.
    #[test]
    fn live_dir_outputs_are_listed_and_tamper_fails_verify() {
        let dir = std::env::temp_dir().join("cairn_live_dir_outputs");
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            output: OutputKind::Dir(dir.clone()),
            ..Config::default()
        };
        let outcome = outcome_with_one_record();
        write_outputs(&cfg, &outcome, manifest_for(&cfg, &outcome), None).unwrap();

        let m = cairn_report::read_manifest(&dir.join("manifest.json")).unwrap();
        let names: Vec<&str> = m.outputs.iter().map(|o| o.file.as_str()).collect();
        for want in [
            "timeline.csv",
            "findings.jsonl",
            "observations.jsonl",
            "records.jsonl",
            "report.html",
        ] {
            assert!(names.contains(&want), "{want} missing from {names:?}");
        }
        assert!(m
            .outputs
            .iter()
            .all(|o| o.size > 0 || o.file == "observations.jsonl"));
        assert!(crate::verify::run_verify(&dir.join("manifest.json"), None).unwrap());

        let p = dir.join("records.jsonl");
        let mut c = std::fs::read(&p).unwrap();
        c[0] ^= 0x20;
        std::fs::write(&p, &c).unwrap();
        assert!(
            !crate::verify::run_verify(&dir.join("manifest.json"), None).unwrap(),
            "tampered records.jsonl must fail verify"
        );
    }

    /// A live zip run carries records.jsonl + report.html as members, lists the member
    /// hashes in the inner manifest, writes a `<zip>.sha256` sidecar, and verifies.
    #[test]
    fn live_zip_lists_members_writes_sidecar_and_verifies() {
        let dir = std::env::temp_dir().join("cairn_live_zip_outputs");
        let _ = std::fs::remove_dir_all(&dir);
        let zip = dir.join("c.zip");
        let cfg = Config {
            output: OutputKind::Zip(zip.clone()),
            ..Config::default()
        };
        let outcome = outcome_with_one_record();
        write_outputs(&cfg, &outcome, manifest_for(&cfg, &outcome), None).unwrap();
        assert!(dir.join("c.zip.sha256").is_file(), "sidecar written");
        let (m, report) = cairn_report::verify_zip(&zip).unwrap();
        assert!(m.outputs.iter().any(|o| o.file == "records.jsonl"));
        assert!(m.outputs.iter().any(|o| o.file == "report.html"));
        assert!(report.ok(), "{:?}", report.failures());
        assert!(crate::verify::run_verify(&zip, None).unwrap());
    }

    /// --dry-run writes nothing at all, even with EVTX export requested.
    #[test]
    fn dry_run_write_outputs_touches_nothing() {
        let dir = std::env::temp_dir().join("cairn_live_dry_run_outputs");
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            output: OutputKind::DryRun,
            ..Config::default()
        };
        let outcome = outcome_with_one_record();
        let plan = crate::export::ExportPlan {
            channels: vec!["Security".into()],
            since: Utc::now(),
        };
        write_outputs(&cfg, &outcome, manifest_for(&cfg, &outcome), Some(&plan)).unwrap();
        assert!(!dir.exists());
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

    struct FixedRecords(Vec<Record>);
    impl Collector for FixedRecords {
        fn name(&self) -> &str {
            "fake_records"
        }
        fn collect(&self, _ctx: &CollectCtx<'_>) -> cairn_core::Result<Vec<Record>> {
            Ok(self.0.clone())
        }
    }

    /// Integration: the phase 3F analyzers are in the live set and fire end to end on
    /// dropscan-shaped records (fake collector -> run_live -> RunOutcome.findings).
    #[test]
    fn phase3f_heuristics_fire_in_live_outcome() {
        use cairn_core::record::{FileListingRecord, ShadowCopyRecord};
        let records = vec![
            Record::FileListing(FileListingRecord {
                path: r"C:\Users\Public\lsass.dmp".into(),
                size: 50_000_000,
                modified: Some(Utc::now()),
                magic: Some(cairn_core::record::MAGIC_MINIDUMP.into()),
                created: None,
            }),
            Record::ShadowCopies(ShadowCopyRecord {
                count: Some(0),
                client_os: Some(true),
                system_restore_enabled: Some(true),
            }),
            Record::Event(event(
                5145,
                1,
                &[("ShareName", r"\\*\ADMIN$"), ("IpAddress", "10.1.2.3")],
            )),
        ];
        let cfg = Config::default();
        let analyzers = registry::analyzers(&cfg, Mode::Live, None);
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FixedRecords(records))];
        let outcome = run_live(&cfg, privs(), "TEST".into(), &collectors, &analyzers);
        for (name, mitre) in [
            (cairn_core::analyzers::CRED_DUMP, "T1003.001"),
            (cairn_core::analyzers::RANSOM, "T1490"),
            (cairn_core::analyzers::LATERAL, "T1021.002"),
        ] {
            let f = outcome
                .findings
                .iter()
                .find(|f| f.analyzer == name)
                .unwrap_or_else(|| panic!("{name} finding missing"));
            assert!(f.reason.is_some(), "golden rule 6: reason must be set");
            assert_eq!(f.mitre[0], mitre);
        }
    }
}
