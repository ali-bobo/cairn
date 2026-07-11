//! Minimal live-run orchestrator (SRS §3): probe privileges (injected), sequence the
//! given collectors in order, accumulate Records + provenance, and degrade gracefully —
//! a failing collector is logged + recorded but never aborts the run (FR13, golden rule 8).
use crate::finding::Finding;
use crate::manifest::{Privileges, SourceEntry};
use crate::observation::Observation;
use crate::record::Record;
use crate::traits::{Analyzer, CollectCtx, Collector};
use crate::Config;

/// Result of a live run, ready to feed the manifest builder + reporter.
#[derive(Debug)]
pub struct RunOutcome {
    pub records: Vec<Record>,
    pub findings: Vec<Finding>,
    pub observations: Vec<Observation>,
    pub sources: Vec<SourceEntry>,
    pub privileges: Privileges,
    pub hostname: String,
}

/// Stable topological sort of `analyzers` by `depends_on()`. Returns the execution
/// order as indices into `analyzers`. Ties (no dependency relationship) are broken by
/// original array position (Kahn's algorithm with an index-ordered ready queue), so the
/// same input always produces the same order (Determinism, CLAUDE.md). A name in
/// `depends_on()` with no matching `name()` among `analyzers` is silently ignored — it
/// simply contributes no edge. Panics if a cycle exists (a static configuration error,
/// not a runtime condition — see spec's rationale for panic over Result here).
fn topo_sort(analyzers: &[Box<dyn Analyzer>]) -> Vec<usize> {
    let n = analyzers.len();
    let name_to_idx: std::collections::HashMap<&str, usize> = analyzers
        .iter()
        .enumerate()
        .map(|(i, a)| (a.name(), i))
        .collect();

    // in_degree[i] = number of unresolved dependencies analyzers[i] has.
    // dependents[i] = indices of analyzers that depend on analyzers[i].
    let mut in_degree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, a) in analyzers.iter().enumerate() {
        for dep_name in a.depends_on() {
            if let Some(&dep_idx) = name_to_idx.get(dep_name) {
                dependents[dep_idx].push(i);
                in_degree[i] += 1;
            }
            // Unknown dependency name: silently ignored (no edge added).
        }
    }

    let mut ready: std::collections::BinaryHeap<std::cmp::Reverse<usize>> = analyzers
        .iter()
        .enumerate()
        .filter(|(i, _)| in_degree[*i] == 0)
        .map(|(i, _)| std::cmp::Reverse(i))
        .collect();

    let mut order = Vec::with_capacity(n);
    while let Some(std::cmp::Reverse(i)) = ready.pop() {
        order.push(i);
        for &dep in &dependents[i] {
            in_degree[dep] -= 1;
            if in_degree[dep] == 0 {
                ready.push(std::cmp::Reverse(dep));
            }
        }
    }

    if order.len() != n {
        let stuck: Vec<&str> = (0..n)
            .filter(|i| in_degree[*i] > 0)
            .map(|i| analyzers[i].name())
            .collect();
        panic!(
            "circular dependency among analyzers: {} still have unresolved depends_on() after topological sort",
            stuck.join(", ")
        );
    }
    order
}

/// Run the given collectors against the host, then fan-in analyzers over the accumulated
/// records. `privileges`/`hostname` are provided by the caller (real probe in the bin;
/// fakes in tests) so this stays pure + testable.
pub fn run_live(
    cfg: &Config,
    privileges: Privileges,
    hostname: String,
    collectors: &[Box<dyn Collector>],
    analyzers: &[Box<dyn Analyzer>],
) -> RunOutcome {
    let ctx = CollectCtx {
        config: cfg,
        admin: privileges.admin,
        se_backup: privileges.se_backup,
        se_debug: privileges.se_debug,
    };
    let mut records = Vec::new();
    let mut sources = Vec::new();
    for c in collectors {
        let started = std::time::Instant::now();
        tracing::info!(collector = c.name(), "collector started");
        match c.collect(&ctx) {
            Ok(mut recs) => {
                tracing::info!(
                    collector = c.name(),
                    records = recs.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "collector finished"
                );
                records.append(&mut recs);
                sources.extend(c.sources());
            }
            Err(e) => {
                // Graceful degrade: record the failure as a source entry, keep going.
                tracing::warn!(
                    collector = c.name(),
                    error = %e,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "collector failed; skipping"
                );
                sources.push(SourceEntry {
                    artifact: c.name().to_string(),
                    path: format!("live:{}", c.name()),
                    method: "api".into(),
                    size: 0,
                    sha256: String::new(),
                    errors: vec![e.to_string()],
                });
            }
        }
    }
    // Analyzer fan-in (SRS §3): each analyzer reads the accumulated records + prior
    // analyzers' findings (dependency-ordered) and emits findings. A failing analyzer is
    // logged + skipped (graceful degrade), never aborts.
    let order = topo_sort(analyzers);
    let mut findings = Vec::new();
    for &idx in &order {
        let a = &analyzers[idx];
        match a.analyze(&records, &findings) {
            Ok(mut fs) => findings.append(&mut fs),
            Err(e) => {
                tracing::warn!(analyzer = a.name(), error = %e, "analyzer failed; skipping");
            }
        }
    }
    // Observation fan-in (spec §6): inventory from analyzers that own one. A failing
    // observe is logged + skipped, mirroring the analyze contract.
    let mut observations = Vec::new();
    for a in analyzers {
        match a.observe(&records) {
            Ok(mut os) => observations.append(&mut os),
            Err(e) => {
                tracing::warn!(analyzer = a.name(), error = %e, "observe failed; skipping");
            }
        }
    }
    RunOutcome {
        records,
        findings,
        observations,
        sources,
        privileges,
        hostname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{NetConnRecord, ProcessRecord};
    use crate::CairnError;

    /// A test double: returns a canned result, advertises one source. Uses Mutex (not
    /// RefCell) because the Collector trait requires Send + Sync.
    struct FakeCollector {
        name: &'static str,
        result: std::sync::Mutex<Option<Result<Vec<Record>, CairnError>>>,
    }
    impl FakeCollector {
        fn ok(name: &'static str, recs: Vec<Record>) -> Box<dyn Collector> {
            Box::new(FakeCollector {
                name,
                result: std::sync::Mutex::new(Some(Ok(recs))),
            })
        }
        fn err(name: &'static str) -> Box<dyn Collector> {
            Box::new(FakeCollector {
                name,
                result: std::sync::Mutex::new(Some(Err(CairnError::Privilege {
                    what: name.into(),
                    need: "Administrator".into(),
                }))),
            })
        }
    }
    impl Collector for FakeCollector {
        fn name(&self) -> &str {
            self.name
        }
        fn collect(&self, _ctx: &CollectCtx<'_>) -> crate::Result<Vec<Record>> {
            self.result.lock().unwrap().take().unwrap()
        }
        fn sources(&self) -> Vec<SourceEntry> {
            vec![SourceEntry {
                artifact: self.name.into(),
                path: format!("live:{}", self.name),
                method: "api".into(),
                size: 0,
                sha256: String::new(),
                errors: vec![],
            }]
        }
    }

    fn privs() -> Privileges {
        Privileges {
            admin: true,
            se_backup: false,
            se_debug: false,
        }
    }
    fn proc_rec() -> Record {
        Record::Process(ProcessRecord {
            pid: 1,
            ppid: 0,
            image: "a.exe".into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        })
    }
    fn net_rec() -> Record {
        Record::NetConn(NetConnRecord {
            proto: "tcp".into(),
            laddr: "127.0.0.1".into(),
            lport: 1,
            raddr: None,
            rport: None,
            state: None,
            pid: Some(1),
        })
    }

    /// All collectors succeed: records + sources accumulate in order, privileges/hostname
    /// pass through.
    #[test]
    fn accumulates_all_successful_collectors() {
        let cfg = Config::default();
        let collectors = vec![
            FakeCollector::ok("proc", vec![proc_rec()]),
            FakeCollector::ok("net", vec![net_rec()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &[]);
        assert_eq!(out.records.len(), 2);
        assert_eq!(out.sources.len(), 2);
        assert_eq!(out.hostname, "WS01");
        assert!(out.privileges.admin);
    }

    /// One collector erroring does NOT abort: the other still runs, and the failure is
    /// recorded as a source with a non-empty errors list (graceful degrade, FR13).
    #[test]
    fn failing_collector_is_recorded_and_run_continues() {
        let cfg = Config::default();
        let collectors = vec![
            FakeCollector::err("proc"),
            FakeCollector::ok("net", vec![net_rec()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &[]);
        // net still produced its record.
        assert_eq!(out.records.len(), 1);
        // proc's failure is captured as a source entry carrying the error.
        let failed = out
            .sources
            .iter()
            .find(|s| s.artifact == "proc")
            .expect("proc source");
        assert!(!failed.errors.is_empty(), "failure must be recorded");
    }

    use crate::finding::{Finding, FindingSource, Severity};
    use crate::traits::Analyzer;

    /// A fake analyzer returning a canned result (or an error). `deps` declares
    /// `depends_on()`; `record_prior_count` is set true to make this analyzer's
    /// single returned Finding's title encode how many prior_findings it saw
    /// (`"saw:<N>"`), so tests can assert on it without a new Finding field.
    struct FakeAnalyzer {
        name: &'static str,
        deps: Vec<&'static str>,
        result: std::sync::Mutex<Option<Result<Vec<Finding>, CairnError>>>,
        record_prior_count: bool,
    }
    impl FakeAnalyzer {
        fn ok(name: &'static str, findings: Vec<Finding>) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                deps: vec![],
                result: std::sync::Mutex::new(Some(Ok(findings))),
                record_prior_count: false,
            })
        }
        fn err(name: &'static str) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                deps: vec![],
                result: std::sync::Mutex::new(Some(Err(CairnError::Analyzer {
                    analyzer: name.into(),
                    reason: "boom".into(),
                }))),
                record_prior_count: false,
            })
        }
        /// Declares dependencies on the given analyzer names; its Finding's title
        /// will be `"saw:<N>"` where N is `prior_findings.len()` at call time.
        fn with_deps(name: &'static str, deps: &[&'static str]) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                deps: deps.to_vec(),
                result: std::sync::Mutex::new(Some(Ok(vec![]))), // overwritten in analyze()
                record_prior_count: true,
            })
        }
    }
    impl Analyzer for FakeAnalyzer {
        fn name(&self) -> &str {
            self.name
        }
        fn analyze(
            &self,
            _records: &[Record],
            prior_findings: &[Finding],
        ) -> crate::Result<Vec<Finding>> {
            if self.record_prior_count {
                return Ok(vec![Finding::new(
                    Severity::Info,
                    format!("saw:{}", prior_findings.len()),
                    FindingSource::Heuristic,
                )]);
            }
            self.result.lock().unwrap().take().unwrap()
        }
        fn depends_on(&self) -> &[&str] {
            &self.deps
        }
    }

    fn a_finding() -> Finding {
        Finding::new(Severity::High, "t", FindingSource::Heuristic)
    }

    /// B depends on A: B's prior_findings must include A's Finding (A ran first).
    #[test]
    fn dependency_is_honored_prior_findings_visible() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            FakeAnalyzer::with_deps("b", &["a"]), // declared first, but must run AFTER a
            FakeAnalyzer::ok("a", vec![a_finding()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        // a's finding (title "t") + b's finding (title "saw:1", since it saw a's 1 finding)
        assert_eq!(out.findings.len(), 2);
        assert!(
            out.findings.iter().any(|f| f.title == "saw:1"),
            "b must have seen a's 1 finding by the time it ran; findings: {:?}",
            out.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    /// No dependency relationships: execution order matches injection order (stable),
    /// reproducibly across repeated calls on the same input.
    #[test]
    fn no_deps_execution_order_is_stable_and_matches_injection_order() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let build = || -> Vec<Box<dyn Analyzer>> {
            vec![
                FakeAnalyzer::ok("first", vec![a_finding()]),
                FakeAnalyzer::ok("second", vec![a_finding()]),
            ]
        };
        let out1 = run_live(&cfg, privs(), "WS01".into(), &collectors, &build());
        let out2 = run_live(&cfg, privs(), "WS01".into(), &collectors, &build());
        let titles1: Vec<&str> = out1.findings.iter().map(|f| f.title.as_str()).collect();
        let titles2: Vec<&str> = out2.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles1, titles2, "same input must produce the same order every time");
    }

    /// A circular dependency (a depends on b, b depends on a) must panic at run_live,
    /// with a message naming both analyzers.
    #[test]
    #[should_panic(expected = "circular")]
    fn circular_dependency_panics() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            FakeAnalyzer::with_deps("a", &["b"]),
            FakeAnalyzer::with_deps("b", &["a"]),
        ];
        run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
    }

    /// Declaring a dependency on an analyzer name that isn't present in the current run
    /// is NOT an error — it's silently ignored, and the run proceeds normally.
    #[test]
    fn dependency_on_absent_analyzer_name_is_ignored_not_an_error() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let analyzers: Vec<Box<dyn Analyzer>> =
            vec![FakeAnalyzer::with_deps("solo", &["nonexistent"])];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        assert_eq!(out.findings.len(), 1, "run must proceed despite the dangling dependency");
    }

    /// Analyzer findings land in RunOutcome.findings.
    #[test]
    fn analyzers_findings_are_collected() {
        let cfg = Config::default();
        let collectors = vec![FakeCollector::ok("proc", vec![proc_rec()])];
        let analyzers = vec![FakeAnalyzer::ok("h", vec![a_finding()])];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        assert_eq!(out.findings.len(), 1);
    }

    /// A failing analyzer is skipped; the run still returns the other's findings.
    #[test]
    fn failing_analyzer_is_skipped_run_continues() {
        let cfg = Config::default();
        let collectors = vec![FakeCollector::ok("proc", vec![proc_rec()])];
        let analyzers = vec![
            FakeAnalyzer::err("bad"),
            FakeAnalyzer::ok("good", vec![a_finding()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        assert_eq!(out.findings.len(), 1, "good analyzer still ran");
        // The failing analyzer must NOT pollute provenance: sources holds only the
        // collector's entry (analyzer failures are logged, not recorded as sources).
        assert_eq!(
            out.sources.len(),
            1,
            "analyzer failure must not add a source"
        );
    }
}
