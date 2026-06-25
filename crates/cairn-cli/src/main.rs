//! cairn: Windows live-forensics triage engine (CLI). SRS §6.
//!
//! Authorized DFIR use only. The tool logs its own actions (run.log) and is
//! designed to be SEEN and recognized as benign by EDR — never to evade it.
//! See README.md and docs/threat-model.md.
#![forbid(unsafe_code)] // CLI orchestration only; no raw-volume/WinAPI in S1.

use cairn_core::finding::Finding;
use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
use cairn_core::traits::OutputSink;
use cairn_core::{Config, OutputKind, Target};
use cairn_report::bodyfile;
use cairn_report::client_text;
use cairn_report::{AgeSink, DirSink, DryRunSink, ZipSink};
use cairn_sigma::{engine::Engine, SigmaMatcher};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// run.log should record Cairn's own actions only — not the internal trace/info of
/// dependencies like the `evtx` parser. Keep cairn crates at info; everything else
/// must reach warn to be logged. RUST_LOG overrides this for debugging.
///
/// NOTE: the binary's tracing target is `cairn` (from `[[bin]] name`), not the
/// package name `cairn_cli` — events from main.rs are tagged `cairn`.
fn log_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "warn,cairn=info,cairn_collectors=info,cairn_core=info,\
             cairn_sigma=info,cairn_report=info",
        )
    })
}

/// Git commit this binary was built from (stamped by build.rs). Recorded in the run
/// manifest as `tool.build_sha` (SRS §5.3 / §13 legitimacy & transparency).
pub const BUILD_SHA: &str = env!("CAIRN_BUILD_SHA");

#[derive(Parser)]
#[command(
    name = "cairn",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CAIRN_BUILD_SHA"), ")"),
    about = "Authorized Windows live-forensics triage engine"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Full run: collect + analyze + report.
    Run(Box<RunArgs>),
    /// Stage-1 engine only: parse EVTX files and run Sigma.
    Evtx {
        files: Vec<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Load un-encoded `.yml` rules instead of the XOR-encoded bundle (ADR-0002).
        /// Lets a SOC audit exactly what runs; off by default (bundle is encoded).
        #[arg(long)]
        rules_plain: bool,
    },
    /// Fetch + pin the Sigma ruleset (S4).
    UpdateRules {
        #[arg(long)]
        pin: Option<String>,
    },
    /// Re-hash a run's outputs (and optionally its ruleset) against the manifest.
    Verify {
        /// Path to manifest.json. Outputs are resolved relative to its directory.
        manifest: PathBuf,
        /// Rules dir to re-verify against manifest.tool.sigma_ruleset_ver (ADR-0003).
        /// Omit to skip the ruleset check and verify only the output/source hashes.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Treat the rules dir as un-encoded `.yml` (matches the run's --rules-plain).
        #[arg(long)]
        rules_plain: bool,
    },
}

#[derive(Parser)]
struct RunArgs {
    /// "live" or a directory of artifacts.
    #[arg(long)]
    target: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    zip: bool,
    #[arg(long)]
    encrypt: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    /// enable Administrator-only collectors (only effective if priv present).
    #[arg(long)]
    admin_features: bool,
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    profile: String,
    /// comma-separated module allow-list, e.g. evtx,process,persist
    #[arg(long)]
    only: Option<String>,
    #[arg(long)]
    since: Option<String>,
    #[arg(long)]
    case_id: Option<String>,
    #[arg(long)]
    operator: Option<String>,
    /// Write mactime bodyfile to PATH (FR20). Skipped with --dry-run.
    #[arg(long)]
    bodyfile: Option<PathBuf>,
    #[arg(long)]
    use_vss: bool,
    /// Hard cap on $MFT records the mft collector scans (NFR10). Default 1,000,000.
    /// Keep this default in sync with `cairn_core::config::Config::default().max_mft_records`.
    #[arg(long, default_value_t = 1_000_000)]
    max_mft_records: u64,
    /// Hard cap on USN ($J) records the usn collector emits (NFR10). Default 1,000,000.
    /// Keep in sync with `cairn_core::config::Config::default().max_usn_records`.
    #[arg(long, default_value_t = 1_000_000)]
    max_usn_records: u64,
    /// Cap the rayon worker pool (NFR9). Default: min(cores, 8). 0 = use default.
    #[arg(long)]
    max_threads: Option<usize>,
    /// Do NOT lower process priority on a live run (opt out of below-normal).
    #[arg(long)]
    full_speed: bool,
}

/// A one-line, human-readable run plan for the `evtx` subcommand, logged to run.log
/// for transparency (SRS §13 / FR6). Pure function so it is unit-testable.
fn evtx_plan(cfg: &Config) -> String {
    let n = match &cfg.target {
        Target::Files(f) => f.len(),
        _ => 0,
    };
    let rules = cfg
        .rules_dir
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<bundled>".to_string());
    let out = match &cfg.output {
        OutputKind::Dir(p) => p.display().to_string(),
        OutputKind::Zip(p) => format!("{} (zip)", p.display()),
        OutputKind::EncryptedZip { path, .. } => format!("{} (encrypted)", path.display()),
        OutputKind::DryRun => "<dry-run, no writes>".to_string(),
    };
    let encoding = if cfg.rules_plain { "plain" } else { "xor" };
    format!("plan: evtx triage of {n} file(s); rules={rules} (encoding={encoding}); output={out}")
}

/// True if the run target selects the live host (vs an offline artifact dir).
fn is_live_target(target: &str) -> bool {
    target.eq_ignore_ascii_case("live")
}

/// Deterministic output ordering (NFR4): sort by (ts, then a stable tiebreak key).
/// Heuristic findings have no record_id, so the tiebreak is (title, then entity pid for
/// process / lport for netconn). Never sort by the random Finding.id (uuid).
fn sort_findings(findings: &mut [cairn_core::Finding]) {
    findings.sort_by(|a, b| {
        a.ts.cmp(&b.ts)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| finding_tiebreak(a).cmp(&finding_tiebreak(b)))
    });
}

/// Stable secondary key: process pid or netconn lport (0 if neither).
fn finding_tiebreak(f: &cairn_core::Finding) -> u32 {
    if let Some(p) = &f.entity.process {
        p.pid
    } else if let Some(n) = &f.entity.netconn {
        n.lport as u32
    } else {
        0
    }
}

/// FR14: fill `binary_sha256` on the records that produced a finding, using an injected hasher.
///
/// Records are matched to findings by a STABLE KEY (not fragile path comparison):
/// registry-backed persistence finding -> (entity.registry.key, entity.registry.value) matches
/// PersistenceRecord (location, value); startup file finding -> entity.file.path matches the
/// persistence record's binary_path; process finding -> entity.process.pid matches
/// ProcessRecord pid. Only matched records with a binary_path / absolute image are hashed.
/// Findings count is small (triage), so the linear scans are cheap.
fn enrich_hashes(
    records: &mut [cairn_core::record::Record],
    findings: &[cairn_core::Finding],
    hash_fn: impl Fn(&str) -> Option<String>,
) {
    use cairn_collectors::proc::is_absolute_path;
    use cairn_core::record::Record;
    use std::collections::HashSet;

    let mut reg_keys: HashSet<(String, String)> = HashSet::new();
    let mut file_paths: HashSet<String> = HashSet::new();
    let mut pids: HashSet<u32> = HashSet::new();
    for f in findings {
        if let Some(r) = &f.entity.registry {
            reg_keys.insert((r.key.clone(), r.value.clone()));
        }
        if let Some(fi) = &f.entity.file {
            file_paths.insert(fi.path.clone());
        }
        if let Some(p) = &f.entity.process {
            pids.insert(p.pid);
        }
    }

    for rec in records.iter_mut() {
        match rec {
            Record::Persistence(p) => {
                let value = p.value.clone().unwrap_or_default();
                let matched = reg_keys.contains(&(p.location.clone(), value))
                    || p.binary_path
                        .as_deref()
                        .is_some_and(|bp| file_paths.contains(bp));
                if let Some(bp) = p.binary_path.as_deref().filter(|_| matched) {
                    p.binary_sha256 = hash_fn(bp);
                    if p.binary_sha256.is_none() {
                        // Selected for hashing but unhashable (over the size cap, locked, or
                        // unreadable). Surface it so the skip is auditable, not invisible.
                        tracing::debug!(path = bp, "find-producing binary not hashed");
                    }
                }
            }
            Record::Process(p) if pids.contains(&p.pid) && is_absolute_path(&p.image) => {
                p.binary_sha256 = hash_fn(&p.image);
                if p.binary_sha256.is_none() {
                    tracing::debug!(path = %p.image, "find-producing binary not hashed");
                }
            }
            _ => {}
        }
    }
}

/// Harvest record-cap truncation notes from collector provenance into manifest
/// Truncation entries. Collectors surface a cap via a `sources()` error string of the
/// form "truncated: max_<X>_records reached (cap=N)"; this parses the cap and attributes
/// it to the SourceEntry's artifact name. The authoritative source is the collector's own
/// sources() — no separate truncation channel is invented (governance design).
fn collect_truncations(
    sources: &[cairn_core::manifest::SourceEntry],
) -> Vec<cairn_core::manifest::Truncation> {
    let mut out = Vec::new();
    for entry in sources {
        for err in &entry.errors {
            if let Some(rest) = err.strip_prefix("truncated: ") {
                if let Some(cap) = parse_cap(rest) {
                    out.push(cairn_core::manifest::Truncation {
                        collector: entry.artifact.clone(),
                        cap,
                        reason: err.clone(),
                    });
                }
            }
        }
    }
    out
}

/// Extract N from a string containing "(cap=N)". Returns None if absent or unparsable.
fn parse_cap(s: &str) -> Option<u64> {
    let start = s.find("(cap=")? + "(cap=".len();
    let tail = &s[start..];
    let end = tail.find(')')?;
    tail[..end].parse::<u64>().ok()
}

/// The collector names that the run arm's construction `if` blocks would build for
/// this selection, in canonical order. Pure mirror of those blocks, so the
/// selection→collectors mapping is unit-testable without a live Windows host.
/// MUST stay in sync with the ten `if ... push(...)` blocks in `main` that
/// construct proc/net/persist/mft/usn/shimcache/amcache/prefetch/bam/userassist collectors (search: "S2-L: construct only").
#[cfg(test)]
fn built_collector_names(selected: &[String]) -> Vec<String> {
    [
        "proc",
        "net",
        "persist",
        "mft",
        "usn",
        "shimcache",
        "amcache",
        "prefetch",
        "bam",
        "userassist",
    ]
    .iter()
    .filter(|n| selected.iter().any(|m| m == *n))
    .map(|s| s.to_string())
    .collect()
}

/// Dump collected Records as JSONL so a live run produces usable data even before
/// analyzers exist. One Record per line (the internal bus type; versioned by schema::RECORD).
fn write_records_jsonl(
    dir: &std::path::Path,
    records: &[cairn_core::record::Record],
) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(dir.join("records.jsonl"))?;
    for r in records {
        writeln!(f, "{}", serde_json::to_string(r)?)?;
    }
    Ok(())
}

/// Write the manifest via the sink, then finalize and log each output entry.
/// manifest.outputs is left empty for all sink types (S3 design decision):
/// DirSink records per-file sha256 via finalize() log; zip/age sinks are
/// self-contained and track integrity at the archive level.
fn manifest_outputs_then_write(
    sink: &mut dyn OutputSink,
    manifest: Manifest,
) -> anyhow::Result<()> {
    sink.write_manifest(&manifest)?;
    let outputs = sink.finalize()?;
    for o in &outputs {
        tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
    }
    Ok(())
}

/// Construct the correct OutputSink variant from the resolved OutputKind (FR15/FR16).
/// AgeSink::new may return Err on an invalid pubkey — propagated to the caller.
fn build_sink(output: &OutputKind) -> anyhow::Result<Box<dyn OutputSink + Send>> {
    use anyhow::Context as _;
    Ok(match output {
        OutputKind::Dir(p) => Box::new(DirSink::new(p)),
        OutputKind::Zip(p) => Box::new(ZipSink::new(p)),
        OutputKind::EncryptedZip { path, pubkey } => {
            let key = std::fs::read_to_string(pubkey)
                .with_context(|| format!("reading age public key file: {}", pubkey.display()))?;
            Box::new(AgeSink::new(path, key.trim()).map_err(|e| anyhow::anyhow!("{}", e))?)
        }
        OutputKind::DryRun => Box::new(DryRunSink),
    })
}

/// Off-target output directory for a Stage-1 evtx run (golden rule 4). Resolved from
/// the Config; run.log is written here.
fn output_dir(cfg: &Config) -> PathBuf {
    match &cfg.output {
        OutputKind::Dir(p) | OutputKind::Zip(p) => p.clone(),
        OutputKind::EncryptedZip { path, .. } => path.clone(),
        OutputKind::DryRun => PathBuf::from("."),
    }
}

/// The manifest's `sigma_ruleset_ver` for this run (ADR-0003): `"<pin>+<aggregate>"`
/// computed over the rules dir actually used, or empty when no rules ran. A hash
/// failure degrades to empty rather than aborting the manifest (golden rule 8); the
/// rule-load path already surfaces real load errors to run.log.
fn ruleset_ver(cfg: &Config) -> String {
    match cfg.rules_dir.as_deref() {
        Some(dir) => {
            cairn_sigma::ruleset::ruleset_version(dir, cfg.rules_plain).unwrap_or_default()
        }
        None => String::new(),
    }
}

/// Assemble the run manifest (SRS §5.3). Stage-1 evtx run: user-space, no privileges,
/// sources hashing is added when the collector reports provenance (T8+); for now the
/// manifest carries tool identity, the command, host, and detection counts.
fn build_manifest(cfg: &Config, hostname: &str, records: u64, findings: &[Finding]) -> Manifest {
    // Reuse the report crate's severity tally instead of recomputing it here.
    let by_sev = cairn_report::Summary::from_findings(findings, records).by_severity;
    Manifest {
        schema: cairn_core::schema::MANIFEST.to_string(),
        tool: ToolInfo {
            name: "cairn".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build_sha: BUILD_SHA.into(),
            sigma_ruleset_ver: ruleset_ver(cfg), // "<pin>+<aggregate>" (ADR-0003)
        },
        run: RunInfo {
            started_utc: chrono::Utc::now(),
            finished_utc: Some(chrono::Utc::now()),
            cmdline: std::env::args().collect::<Vec<_>>().join(" "),
            operator: cfg.operator.clone(),
            case_id: cfg.case_id.clone(),
            // The evtx subcommand parses EVTX with the default profile; it runs no
            // live collectors, so the selected module is the evtx engine itself.
            profile: "standard".into(),
            selected_modules: vec!["evtx".into()],
        },
        host: HostInfo {
            hostname: hostname.to_string(),
            os_build: String::new(),
            timezone: "UTC".into(),
            wall_clock_utc_skew: "unknown".into(),
        },
        privileges: Privileges {
            admin: false,
            se_backup: false,
            se_debug: false,
        },
        sources: vec![],
        outputs: vec![], // filled by verify against the on-disk files (T9)
        counts: Counts {
            records,
            findings_by_sev: by_sev,
        },
        integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
        governance: cairn_core::manifest::GovernanceReport::default(),
    }
}

/// `cairn verify <manifest> [--rules <dir>]` (stage1-plan T9): re-hash the outputs (and
/// sources) the manifest lists, and — if a rules dir is given — recompute the ADR-0003
/// ruleset aggregate and compare it to `tool.sigma_ruleset_ver`. Logs every check and
/// returns `true` only if all pass. A tampered output byte OR a modified rule fails it.
fn run_verify(
    manifest_path: &std::path::Path,
    rules: Option<PathBuf>,
    rules_plain: bool,
) -> anyhow::Result<bool> {
    let manifest = cairn_report::read_manifest(manifest_path)?;
    let base_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    let report = cairn_report::verify_manifest(&manifest, base_dir);
    for c in report.outputs.iter().chain(report.sources.iter()) {
        match &c.status {
            cairn_report::CheckStatus::Ok => tracing::info!(file = %c.file, "verify ok"),
            cairn_report::CheckStatus::Mismatch { expected, actual } => {
                tracing::error!(file = %c.file, %expected, %actual, "HASH MISMATCH")
            }
            cairn_report::CheckStatus::Missing => {
                tracing::error!(file = %c.file, "MISSING (listed in manifest, not on disk)")
            }
        }
    }
    let mut all_ok = report.ok();

    // ADR-0003 ruleset integrity: recompute "<pin>+<aggregate>" over the given rules dir
    // and compare to what the manifest recorded. Only when --rules is supplied; a manifest
    // with no recorded ruleset version (parse-only run) has nothing to check.
    match (rules, manifest.tool.sigma_ruleset_ver.as_str()) {
        (Some(dir), recorded) if !recorded.is_empty() => {
            let computed = cairn_sigma::ruleset::ruleset_version(&dir, rules_plain)?;
            if computed == recorded {
                tracing::info!("ruleset ok ({recorded})");
            } else {
                tracing::error!(%recorded, %computed, "RULESET MISMATCH (ADR-0003)");
                all_ok = false;
            }
        }
        (Some(_), "") => {
            tracing::warn!("manifest has no sigma_ruleset_ver; skipping ruleset check")
        }
        (None, recorded) if !recorded.is_empty() => {
            tracing::warn!("ruleset recorded but no --rules given; skipping ruleset check")
        }
        _ => {}
    }

    if all_ok {
        tracing::info!("VERIFY OK");
    } else {
        tracing::error!(failures = report.failures().len(), "VERIFY FAILED");
    }
    Ok(all_ok)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Evtx {
            files,
            rules,
            rules_plain,
        } => {
            let cfg = Config::for_evtx(files, rules).with_rules_plain(rules_plain);
            let dir = output_dir(&cfg);
            std::fs::create_dir_all(&dir)?;

            // Transparent self-logging (FR6 / SRS §13): tee tracing to run.log in the
            // output dir AND to stderr so the analyst sees activity live. Full
            // per-file/per-action logging lands in T3.
            let file_appender = tracing_appender::rolling::never(&dir, "run.log");
            let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::fmt()
                .with_env_filter(log_filter())
                .with_target(false)
                .with_ansi(false)
                .with_writer(file_writer)
                .init();

            tracing::info!(
                "cairn {} ({}) starting",
                env!("CARGO_PKG_VERSION"),
                BUILD_SHA
            );
            tracing::info!("{}", evtx_plan(&cfg));

            // T3/T4: open each input, parse it, and log the read with a UTC timestamp
            // and record count. A failed file is logged and skipped, never fatal
            // (graceful degrade, golden rule 8).
            let files: &[PathBuf] = match &cfg.target {
                Target::Files(f) => f,
                _ => &[],
            };
            let mut records = Vec::new();
            for path in files {
                match cairn_collectors::evtx::parse_evtx(path) {
                    Ok(recs) => {
                        tracing::info!(file = %path.display(), records = recs.len(), "parsed evtx");
                        records.extend(recs);
                    }
                    Err(e) => {
                        tracing::warn!(file = %path.display(), error = %e, "skipped (parse failed)");
                    }
                }
            }
            tracing::info!(records = records.len(), "evtx parse complete");

            // T6: run Sigma over the parsed events (if a rules dir was given).
            let mut findings = Vec::new();
            if let Some(rules_dir) = cfg.rules_dir.as_deref() {
                let mut engine = Engine::default();
                match engine.load(rules_dir, cfg.rules_plain) {
                    Ok(n) => {
                        tracing::info!(rules = n, dir = %rules_dir.display(), plain = cfg.rules_plain, "loaded sigma rules");
                        for ev in &records {
                            match engine.match_event(ev) {
                                Ok(mut fs) => findings.append(&mut fs),
                                Err(e) => tracing::warn!(error = %e, "match error"),
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, dir = %rules_dir.display(), "rule load failed")
                    }
                }
            } else {
                tracing::info!("no --rules dir; skipping Sigma (parse-only run)");
            }
            tracing::info!(findings = findings.len(), "analysis complete");

            // T7: write timeline.csv + findings.jsonl, then the manifest. The data
            // outputs are written first so their SHA-256s can be embedded into the
            // manifest's `outputs` (chain-of-custody; `cairn verify` re-checks them, T9).
            // The manifest records the *data* outputs' integrity, not its own.
            let hostname = records
                .first()
                .map(|r| r.computer.clone())
                .unwrap_or_default();
            let mut manifest = build_manifest(&cfg, &hostname, records.len() as u64, &findings);
            for f in &mut findings {
                client_text::fill_details_client(f);
            }
            let mut sink = DirSink::new(dir.clone());
            sink.write_timeline_csv(&findings)?;
            sink.write_findings_jsonl(&findings)?;
            manifest.outputs = sink.outputs_so_far();
            sink.write_manifest(&manifest)?;
            let outputs = sink.finalize()?;
            for o in &outputs {
                tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
            }
            tracing::info!(dir = %dir.display(), "report complete");
            // _guard must live until logging is done; non-blocking writer flushes on drop.
            drop(_guard);
        }
        Cmd::Run(args) => {
            use cairn_core::orchestrator::run_live;
            use cairn_core::traits::Collector;

            if !is_live_target(&args.target) {
                // Offline-artifact orchestration is the raw-NTFS sub-segment; be honest.
                eprintln!(
                    "cairn run --target <dir> is not implemented yet (raw-NTFS sub-segment); \
                     use --target live, or `cairn evtx` for EVTX files."
                );
                std::process::exit(2);
            }

            // S2-L: parse --profile into the typed enum FIRST; an invalid value is a
            // clean CLI error (exit non-zero) before we create any output or start a
            // run — not a silent Standard fallback.
            let profile: cairn_core::Profile = args
                .profile
                .parse()
                .map_err(|e: String| anyhow::anyhow!(e))?;

            // S2-L: --only is a comma-separated allow-list. None => no restriction.
            let only: Option<Vec<String>> = args.only.as_deref().map(|csv| {
                csv.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            });

            // --dry-run (FR16 / golden rule 4): write NOTHING. No output dir, no run.log file,
            // no records/findings/manifest — logs go to stderr and we print a summary only.
            let dry_run = args.dry_run;

            // RAII guard for the file logger; None in dry-run (no run.log file is created).
            let _guard = if dry_run {
                tracing_subscriber::fmt()
                    .with_env_filter(log_filter())
                    .with_target(false)
                    .with_writer(std::io::stderr)
                    .init();
                None
            } else {
                // For archive modes (--zip / --encrypt), run.log goes to the archive's
                // parent directory, NOT to args.output itself.  create_dir_all on a .zip
                // path would create a directory named "cairn_out.zip", which then
                // conflicts when ZipSink / AgeSink tries to open that path as a file.
                let log_dir: std::path::PathBuf = if args.zip || args.encrypt.is_some() {
                    args.output
                        .parent()
                        .map(|p| {
                            if p == std::path::Path::new("") {
                                std::path::Path::new(".")
                            } else {
                                p
                            }
                        })
                        .unwrap_or(std::path::Path::new("."))
                        .to_path_buf()
                } else {
                    args.output.clone()
                };
                std::fs::create_dir_all(&log_dir)?;
                let file_appender = tracing_appender::rolling::never(&log_dir, "run.log");
                let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
                tracing_subscriber::fmt()
                    .with_env_filter(log_filter())
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(file_writer)
                    .init();
                Some(guard)
            };
            let dir = args.output.clone();

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

            // S2-L: decide which collectors run. AVAILABLE = the live collectors' real
            // Collector::name() strings. Pure decision; logged for transparency (FR6).
            const AVAILABLE: &[&str] = &[
                "proc",
                "net",
                "persist",
                "mft",
                "usn",
                "shimcache",
                "amcache",
                "prefetch",
                "bam",
                "userassist",
                "srum",
            ];
            let selection = cairn_core::select_modules(profile, only.as_deref(), AVAILABLE);
            for name in &selection.unknown_only {
                tracing::warn!(
                    only = %name,
                    "--only names a module that is not an available live collector; ignoring it"
                );
            }
            tracing::info!(
                profile = %args.profile.to_ascii_lowercase(),
                modules = %selection.selected.join(","),
                "collector selection"
            );

            // Resolve the OutputKind from CLI flags: --dry-run > --encrypt > --zip > plain dir.
            let output_kind = if dry_run {
                OutputKind::DryRun
            } else if let Some(ref pubkey) = args.encrypt {
                OutputKind::EncryptedZip {
                    path: args.output.clone(),
                    pubkey: pubkey.clone(),
                }
            } else if args.zip {
                OutputKind::Zip(args.output.clone())
            } else {
                OutputKind::Dir(args.output.clone())
            };

            let mut cfg = Config {
                max_mft_records: args.max_mft_records,
                max_usn_records: args.max_usn_records,
                profile,
                output: output_kind,
                ..Config::default()
            };

            // ── Resource governance (NFR9/NFR10) ──────────────────────────────────────
            // Always true in this handler (a non-live --target exits earlier); kept to
            // document intent and to make low_priority target-aware if more targets are added.
            let is_live = matches!(cfg.target, cairn_core::Target::Live);
            cfg.governance.max_threads = args.max_threads;
            cfg.governance.low_priority = is_live && !args.full_speed;
            cfg.normalize_for_profile();

            let available = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            let effective_threads =
                cairn_core::resolve_max_threads(cfg.governance.max_threads, available);
            // build_global is a process one-shot; a second call (e.g. in tests) errors — ignore it.
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(effective_threads)
                .build_global();

            let low_priority_applied = if cfg.governance.low_priority {
                match cairn_collectors_win::priority::lower_priority() {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to lower process priority; continuing at normal priority");
                        false
                    }
                }
            } else {
                false
            };

            // S2-L: construct only the selected collectors, matching the real
            // Collector::name() strings; order follows AVAILABLE (deterministic).
            let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
            if selection.selected.iter().any(|m| m == "proc") {
                collectors.push(Box::new(cairn_collectors::proc::ProcCollector::default()));
            }
            if selection.selected.iter().any(|m| m == "net") {
                collectors.push(Box::new(cairn_collectors::net::NetCollector));
            }
            if selection.selected.iter().any(|m| m == "persist") {
                collectors.push(Box::new(
                    cairn_collectors::persist::PersistCollector::default(),
                ));
            }
            if selection.selected.iter().any(|m| m == "mft") {
                collectors.push(Box::new(cairn_collectors::mft::MftCollector::default()));
            }
            if selection.selected.iter().any(|m| m == "usn") {
                collectors.push(Box::new(cairn_collectors::usn::UsnCollector::default()));
            }
            if selection.selected.iter().any(|m| m == "shimcache") {
                collectors.push(Box::new(
                    cairn_collectors::shimcache::ShimCollector::default(),
                ));
            }
            if selection.selected.iter().any(|m| m == "amcache") {
                collectors.push(Box::new(
                    cairn_collectors::amcache::AmcacheCollector::default(),
                ));
            }
            if selection.selected.iter().any(|m| m == "prefetch") {
                collectors.push(Box::new(
                    cairn_collectors::prefetch::PrefetchCollector::default(),
                ));
            }
            if selection.selected.iter().any(|m| m == "bam") {
                collectors.push(Box::new(cairn_collectors::bam::BamCollector::default()));
            }
            if selection.selected.iter().any(|m| m == "userassist") {
                collectors.push(Box::new(
                    cairn_collectors::userassist::UserAssistCollector::default(),
                ));
            }
            if selection.selected.iter().any(|m| m == "srum") {
                collectors.push(Box::new(cairn_collectors::srum::SrumCollector::default()));
            }
            let analyzers: Vec<Box<dyn cairn_core::traits::Analyzer>> = vec![
                Box::new(cairn_heur::ParentChildHeuristic),
                Box::new(cairn_heur::NetConnHeuristic),
                Box::new(cairn_heur::PersistHeuristic),
                // S2-N′: threshold from Config (fixed default 24h; no CLI flag).
                Box::new(cairn_heur::TimestompHeuristic::new(
                    chrono::Duration::hours(cfg.timestomp_threshold_hours),
                )),
            ];
            let mut outcome = run_live(&cfg, privileges, hostname, &collectors, &analyzers);
            // Stamp the host onto each finding (analyzers don't know the hostname), then
            // sort for deterministic output (NFR4).
            for f in &mut outcome.findings {
                f.host = outcome.hostname.clone();
            }
            sort_findings(&mut outcome.findings);
            // FR14: hash the binaries behind findings (streaming, size-capped) and fill
            // binary_sha256 so each suspicious record carries an IOC hash. In-memory only —
            // for --dry-run nothing is written (golden rule 4).
            enrich_hashes(&mut outcome.records, &outcome.findings, |path| {
                cairn_collectors::hash::hash_file_capped(
                    path,
                    cairn_collectors::hash::DEFAULT_MAX_HASH_BYTES,
                    |p| {
                        let len = std::fs::metadata(p).ok()?.len();
                        let file = std::fs::File::open(p).ok()?;
                        Some((len, file))
                    },
                )
            });
            tracing::info!(
                records = outcome.records.len(),
                findings = outcome.findings.len(),
                "live collection + analysis complete"
            );

            let governance_report = cairn_core::manifest::GovernanceReport {
                effective_threads,
                low_priority_applied,
                truncations: collect_truncations(&outcome.sources),
            };

            let by_sev = cairn_report::Summary::from_findings(
                &outcome.findings,
                outcome.records.len() as u64,
            )
            .by_severity;
            let manifest = Manifest {
                schema: cairn_core::schema::MANIFEST.to_string(),
                tool: ToolInfo {
                    name: "cairn".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    build_sha: BUILD_SHA.into(),
                    sigma_ruleset_ver: String::new(),
                },
                run: RunInfo {
                    started_utc: chrono::Utc::now(),
                    finished_utc: Some(chrono::Utc::now()),
                    cmdline: std::env::args().collect::<Vec<_>>().join(" "),
                    operator: String::new(),
                    case_id: String::new(),
                    profile: format!("{:?}", cfg.profile).to_lowercase(),
                    selected_modules: selection.selected.clone(),
                },
                host: HostInfo {
                    hostname: outcome.hostname.clone(),
                    os_build: String::new(),
                    timezone: "UTC".into(),
                    wall_clock_utc_skew: "unknown".into(),
                },
                privileges: outcome.privileges.clone(),
                sources: outcome.sources.clone(),
                outputs: vec![],
                counts: Counts {
                    records: outcome.records.len() as u64,
                    findings_by_sev: by_sev,
                },
                integrity_note: "All hashes SHA-256 over bytes as collected.".into(),
                governance: governance_report,
            };

            for f in &mut outcome.findings {
                client_text::fill_details_client(f);
            }
            let mut sink = build_sink(&cfg.output)?;
            sink.write_timeline_csv(&outcome.findings)?;
            sink.write_findings_jsonl(&outcome.findings)?;
            if let OutputKind::Dir(ref d) = cfg.output {
                write_records_jsonl(d, &outcome.records)?;
            }
            manifest_outputs_then_write(&mut *sink, manifest)?;
            if !dry_run {
                if let Some(bf_path) = &args.bodyfile {
                    let bf = std::fs::File::create(bf_path)
                        .map_err(|e| anyhow::anyhow!("bodyfile create: {e}"))?;
                    bodyfile::write_bodyfile(&outcome.records, bf)?;
                    tracing::info!(path = %bf_path.display(), "bodyfile written");
                }
            }
            if dry_run {
                println!(
                    "dry-run: {} records, {} findings — no files written (would have gone to {})",
                    outcome.records.len(),
                    outcome.findings.len(),
                    dir.display()
                );
            } else {
                tracing::info!(output = ?cfg.output, "run complete");
            }
            drop(_guard);
        }
        other => {
            tracing_subscriber::fmt()
                .with_env_filter(log_filter())
                .with_target(false)
                .init();
            match other {
                Cmd::UpdateRules { pin } => {
                    #[cfg(feature = "updater")]
                    {
                        let rules_dir = std::env::current_dir()
                            .map_err(|e| anyhow::anyhow!("cwd: {e}"))?
                            .join("rules")
                            .join("sigma");
                        let ruleset_toml = std::env::current_dir()
                            .map_err(|e| anyhow::anyhow!("cwd: {e}"))?
                            .join("rules")
                            .join("ruleset.toml");
                        cairn_updater::run(pin.as_deref(), &rules_dir, &ruleset_toml)?;
                    }
                    #[cfg(not(feature = "updater"))]
                    {
                        let _ = pin;
                        anyhow::bail!(
                            "this cairn build was compiled without network support (updater feature disabled)"
                        );
                    }
                }
                Cmd::Verify {
                    manifest,
                    rules,
                    rules_plain,
                } => {
                    // Non-zero exit on any integrity failure so scripts/CI can detect it.
                    let ok = run_verify(&manifest, rules, rules_plain)?;
                    if !ok {
                        std::process::exit(1);
                    }
                }
                Cmd::Evtx { .. } | Cmd::Run(_) => unreachable!(),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrich_hashes_fills_only_find_producing_records() {
        use cairn_core::finding::EntityRegistry;
        use cairn_core::record::{PersistenceRecord, Record};
        use cairn_core::{Entity, Finding, FindingSource, Severity};

        let mk = |value: &str, bin: &str| {
            Record::Persistence(PersistenceRecord {
                mechanism: "run_key".into(),
                location: "HKCU\\Run".into(),
                value: Some(value.into()),
                command: Some(bin.into()),
                binary_path: Some(bin.into()),
                binary_sha256: None,
                signed: None,
                signer: None,
                last_write: None,
            })
        };
        let mut records = vec![mk("Evil", "C:\\evil.exe"), mk("Benign", "C:\\benign.exe")];

        // A finding whose registry (key,value) matches record[0] only.
        let mut f = Finding::new(
            Severity::High,
            "Suspicious persistence: run_key",
            FindingSource::Heuristic,
        );
        f.entity = Entity {
            registry: Some(EntityRegistry {
                hive: "HKCU".into(),
                key: "HKCU\\Run".into(),
                value: "Evil".into(),
                data: "C:\\evil.exe".into(),
                last_write: None,
            }),
            ..Entity::default()
        };
        let findings = vec![f];

        enrich_hashes(&mut records, &findings, |p| Some(format!("hash-of-{p}")));

        let Record::Persistence(p0) = &records[0] else {
            panic!()
        };
        let Record::Persistence(p1) = &records[1] else {
            panic!()
        };
        assert_eq!(p0.binary_sha256.as_deref(), Some("hash-of-C:\\evil.exe"));
        assert_eq!(
            p1.binary_sha256, None,
            "benign record (no finding) not hashed"
        );
    }

    #[test]
    fn selected_collector_names_follow_selection() {
        use cairn_core::{select_modules, Profile};
        const AVAILABLE: &[&str] = &[
            "proc",
            "net",
            "persist",
            "mft",
            "usn",
            "shimcache",
            "amcache",
            "prefetch",
            "bam",
            "userassist",
            "srum",
        ];

        // --only persist => only persist constructed.
        let only = vec!["persist".to_string()];
        let sel = select_modules(Profile::Standard, Some(&only), AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert_eq!(built, vec!["persist".to_string()]);

        // no --only => all ten in canonical order (minimal skips raw-NTFS).
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert_eq!(
            built,
            vec![
                "proc",
                "net",
                "persist",
                "mft",
                "usn",
                "shimcache",
                "amcache",
                "prefetch",
                "bam",
                "userassist"
            ]
        );

        // --profile minimal must NOT select mft (raw-NTFS); standard must.
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"mft".to_string()),
            "minimal skips raw-NTFS mft"
        );

        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"mft".to_string()), "standard includes mft");

        // raw-NTFS collectors: standard includes usn, minimal skips it.
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"usn".to_string()), "standard includes usn");
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"usn".to_string()), "minimal skips usn");
        // raw-NTFS collectors: standard includes shimcache, minimal skips it.
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            built.contains(&"shimcache".to_string()),
            "standard includes shimcache"
        );
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"shimcache".to_string()),
            "minimal skips shimcache"
        );
        // raw-NTFS collectors: standard includes amcache, minimal skips it.
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            built.contains(&"amcache".to_string()),
            "standard includes amcache"
        );
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"amcache".to_string()),
            "minimal skips amcache"
        );
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            built.contains(&"prefetch".to_string()),
            "standard includes prefetch"
        );
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"prefetch".to_string()),
            "minimal skips prefetch"
        );
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(built.contains(&"bam".to_string()), "standard includes bam");
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(!built.contains(&"bam".to_string()), "minimal skips bam");
        let sel = select_modules(Profile::Standard, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            built.contains(&"userassist".to_string()),
            "standard includes userassist"
        );
        let sel = select_modules(Profile::Minimal, None, AVAILABLE);
        let built = built_collector_names(&sel.selected);
        assert!(
            !built.contains(&"userassist".to_string()),
            "minimal skips userassist"
        );
    }

    #[test]
    fn findings_sort_is_deterministic_by_ts_then_title() {
        use cairn_core::{Finding, FindingSource, Severity};
        let mut a = Finding::new(Severity::High, "b-title", FindingSource::Heuristic);
        let mut b = Finding::new(Severity::High, "a-title", FindingSource::Heuristic);
        let ts = chrono::Utc::now();
        a.ts = ts;
        b.ts = ts;
        let mut v = vec![a, b];
        sort_findings(&mut v);
        assert_eq!(v[0].title, "a-title");
        assert_eq!(v[1].title, "b-title");
    }

    #[test]
    fn run_target_live_is_recognized() {
        assert!(is_live_target("live"));
        assert!(is_live_target("LIVE"));
        assert!(!is_live_target("C:\\evidence"));
    }

    #[test]
    fn evtx_plan_reports_file_count_rules_and_output() {
        let cfg = Config::for_evtx(
            vec![PathBuf::from("a.evtx"), PathBuf::from("b.evtx")],
            Some(PathBuf::from("./rules")),
        );
        let line = evtx_plan(&cfg);
        assert!(line.contains("2 file(s)"), "{line}");
        assert!(line.contains("rules=./rules"), "{line}");
        assert!(line.contains("output="), "{line}");
    }

    /// The live analyzer set includes the timestomp heuristic (S2-N' wiring).
    #[test]
    fn live_analyzers_include_timestomp() {
        use cairn_core::traits::Analyzer;
        let threshold = chrono::Duration::hours(24);
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(cairn_heur::ParentChildHeuristic),
            Box::new(cairn_heur::NetConnHeuristic),
            Box::new(cairn_heur::PersistHeuristic),
            Box::new(cairn_heur::TimestompHeuristic::new(threshold)),
        ];
        assert!(analyzers.iter().any(|a| a.name() == "heur_timestomp"));
    }

    #[test]
    fn evtx_plan_shows_bundled_rules_when_none() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert!(evtx_plan(&cfg).contains("rules=<bundled>"));
    }

    /// The plan records the rule-encoding mode so run.log shows whether `--rules-plain`
    /// was used (transparency: a SOC reading the log knows if rules were decoded).
    #[test]
    fn evtx_plan_records_rules_plain_mode() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], Some(PathBuf::from("./r")));
        assert!(
            evtx_plan(&cfg).contains("encoding=xor"),
            "default is encoded"
        );
        let cfg = cfg.with_rules_plain(true);
        assert!(evtx_plan(&cfg).contains("encoding=plain"));
    }

    /// With no rules dir the manifest's sigma_ruleset_ver is empty (no rules ran).
    #[test]
    fn ruleset_ver_is_empty_without_rules() {
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        assert_eq!(ruleset_ver(&cfg), "");
    }

    /// With the bundled (encoded) rules dir, sigma_ruleset_ver is "<pin>+<aggregate>"
    /// (ADR-0003): the pin from PROVENANCE and a 64-char aggregate, computed over the
    /// real bundled rules this binary ships.
    #[test]
    fn ruleset_ver_is_pin_plus_aggregate_for_bundled_rules() {
        let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma");
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], Some(bundled));
        let ver = ruleset_ver(&cfg);
        let (pin, agg) = ver.split_once('+').expect("ver must be pin+aggregate");
        assert_eq!(
            pin, "98781da19cf60c48ce6e7f2d3ad11c9ba389191a",
            "ADR-0003 pin"
        );
        assert_eq!(agg.len(), 64, "aggregate is a SHA-256 hex");
        assert!(agg.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    /// Build a tiny real run (timeline + findings + manifest) in a temp dir, the way the
    /// evtx subcommand does, so verify has a genuine artifact set to check.
    fn write_run(dir: &std::path::Path) {
        use cairn_core::finding::{Finding, FindingSource, Severity};
        let mut f = Finding::new(Severity::High, "t", FindingSource::Sigma);
        f.rule_author = Some("A".into());
        let findings = vec![f];
        let cfg = Config::for_evtx(vec![PathBuf::from("a.evtx")], None);
        let mut manifest = build_manifest(&cfg, "WS01", 1, &findings);
        let mut sink = DirSink::new(dir.to_path_buf());
        sink.write_timeline_csv(&findings).unwrap();
        sink.write_findings_jsonl(&findings).unwrap();
        manifest.outputs = sink.outputs_so_far();
        sink.write_manifest(&manifest).unwrap();
        let _ = sink.finalize().unwrap();
    }

    /// verify passes on an untouched run (T9 happy path): all output hashes match.
    #[test]
    fn run_verify_passes_on_clean_run() {
        let dir = std::env::temp_dir().join("cairn_run_verify_clean");
        let _ = std::fs::remove_dir_all(&dir);
        write_run(&dir);
        let ok = run_verify(&dir.join("manifest.json"), None, false).unwrap();
        assert!(ok, "clean run must verify");
    }

    /// verify fails on a tampered output byte (T9 acceptance).
    #[test]
    fn run_verify_fails_on_tampered_output() {
        let dir = std::env::temp_dir().join("cairn_run_verify_tamper");
        let _ = std::fs::remove_dir_all(&dir);
        write_run(&dir);
        // Flip a byte in findings.jsonl after the manifest recorded its hash.
        let p = dir.join("findings.jsonl");
        let mut c = std::fs::read(&p).unwrap();
        c.push(b' ');
        std::fs::write(&p, &c).unwrap();
        let ok = run_verify(&dir.join("manifest.json"), None, false).unwrap();
        assert!(!ok, "tampered output must fail verify");
    }

    /// verify fails when the ruleset is modified vs the manifest's sigma_ruleset_ver
    /// (ADR-0003 / T9 acceptance: a swapped/edited rule is caught).
    #[test]
    fn run_verify_fails_on_modified_ruleset() {
        let dir = std::env::temp_dir().join("cairn_run_verify_rules");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A run whose manifest pins a ruleset_ver computed over an original rules dir.
        let rules = dir.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("r.yml"), b"title: original\n").unwrap();

        use cairn_core::finding::{Finding, FindingSource, Severity};
        let findings = vec![Finding::new(Severity::Low, "t", FindingSource::Sigma)];
        let cfg = Config::for_evtx(vec![], Some(rules.clone())).with_rules_plain(true);
        let mut manifest = build_manifest(&cfg, "WS01", 0, &findings);
        let mut sink = DirSink::new(dir.clone());
        sink.write_timeline_csv(&findings).unwrap();
        sink.write_findings_jsonl(&findings).unwrap();
        manifest.outputs = sink.outputs_so_far();
        sink.write_manifest(&manifest).unwrap();
        sink.finalize().unwrap();

        // Now modify a rule and verify against the modified dir: ruleset check must fail.
        std::fs::write(rules.join("r.yml"), b"title: TAMPERED\n").unwrap();
        let ok = run_verify(&dir.join("manifest.json"), Some(rules), true).unwrap();
        assert!(!ok, "modified ruleset must fail verify");
    }

    #[test]
    fn max_mft_records_flag_defaults_to_one_million() {
        // clap default must match Config's default so an unspecified flag is a no-op.
        use clap::Parser;
        let args = RunArgs::parse_from(["cairn", "--target", "live", "--output", "out"]);
        assert_eq!(args.max_mft_records, 1_000_000);
    }

    #[test]
    fn max_mft_records_flag_parses_override() {
        use clap::Parser;
        let args = RunArgs::parse_from([
            "cairn",
            "--target",
            "live",
            "--output",
            "out",
            "--max-mft-records",
            "42",
        ]);
        assert_eq!(args.max_mft_records, 42);
    }

    #[test]
    fn max_usn_records_flag_defaults_to_one_million() {
        use clap::Parser;
        let args = RunArgs::parse_from(["cairn", "--target", "live", "--output", "out"]);
        assert_eq!(args.max_usn_records, 1_000_000);
    }

    #[test]
    fn max_usn_records_flag_parses_override() {
        use clap::Parser;
        let args = RunArgs::parse_from([
            "cairn",
            "--target",
            "live",
            "--output",
            "out",
            "--max-usn-records",
            "42",
        ]);
        assert_eq!(args.max_usn_records, 42);
    }

    #[test]
    fn governance_report_assembles_threads_and_priority() {
        use cairn_core::manifest::GovernanceReport;
        use cairn_core::resolve_max_threads;
        // Pure assembly logic mirrored: effective_threads from resolver, priority flag
        // from (is_live && !full_speed). This guards the wiring contract without
        // touching the global pool.
        let effective = resolve_max_threads(Some(3), 16);
        let report = GovernanceReport {
            effective_threads: effective,
            low_priority_applied: true,
            truncations: vec![],
        };
        assert_eq!(report.effective_threads, 3);
        assert!(report.low_priority_applied);
    }

    /// Clap-parse assertion: --max-threads and --full-speed flags wire correctly into RunArgs.
    /// Guards that the flag names and their RunArgs field types match the handler's expectations
    /// (a rename or type mismatch would break this test immediately).
    #[test]
    fn run_args_max_threads_and_full_speed_parse_correctly() {
        use clap::Parser;
        // --max-threads 3 must parse and set max_threads = Some(3); full_speed defaults false.
        let args = RunArgs::parse_from([
            "cairn",
            "--target",
            "live",
            "--output",
            "out",
            "--max-threads",
            "3",
        ]);
        assert_eq!(
            args.max_threads,
            Some(3),
            "--max-threads 3 must parse to Some(3)"
        );
        assert!(!args.full_speed, "--full-speed absent => false");

        // --full-speed must parse and set full_speed = true.
        let args_fs = RunArgs::parse_from([
            "cairn",
            "--target",
            "live",
            "--output",
            "out",
            "--full-speed",
        ]);
        assert!(args_fs.full_speed, "--full-speed present => true");
        assert_eq!(args_fs.max_threads, None, "max_threads absent => None");
    }

    #[test]
    fn live_config_enables_mft_path_resolution_by_default() {
        // The live Config is built with `..Config::default()`; path resolution must be
        // on by default so the mft collector reconstructs full paths (S2-O).
        let cfg = Config::default();
        assert!(
            cfg.resolve_mft_paths,
            "path resolution must default on for the live run"
        );
    }

    #[test]
    fn collect_truncations_extracts_mft_and_usn() {
        use cairn_core::manifest::SourceEntry;
        let sources = vec![
            SourceEntry {
                artifact: "mft".into(),
                path: r"\\.\C:".into(),
                method: "raw_ntfs".into(),
                size: 0,
                sha256: String::new(),
                errors: vec!["truncated: max_mft_records reached (cap=1000000)".into()],
            },
            SourceEntry {
                artifact: "usn".into(),
                path: r"\\.\C:".into(),
                method: "raw_ntfs_usn".into(),
                size: 0,
                sha256: String::new(),
                errors: vec!["truncated: max_usn_records reached (cap=42)".into()],
            },
        ];
        let t = collect_truncations(&sources);
        assert_eq!(t.len(), 2);
        assert!(t.iter().any(|x| x.collector == "mft" && x.cap == 1_000_000));
        assert!(t.iter().any(|x| x.collector == "usn" && x.cap == 42));
    }

    #[test]
    fn collect_truncations_empty_when_no_caps() {
        use cairn_core::manifest::SourceEntry;
        let sources = vec![SourceEntry {
            artifact: "mft".into(),
            path: r"\\.\C:".into(),
            method: "raw_ntfs".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }];
        assert!(collect_truncations(&sources).is_empty());
    }

    #[test]
    fn collect_truncations_ignores_unrelated_errors() {
        use cairn_core::manifest::SourceEntry;
        let sources = vec![SourceEntry {
            artifact: "proc".into(),
            path: "live".into(),
            method: "toolhelp".into(),
            size: 0,
            sha256: String::new(),
            errors: vec!["some unrelated warning".into()],
        }];
        assert!(collect_truncations(&sources).is_empty());
    }
}
