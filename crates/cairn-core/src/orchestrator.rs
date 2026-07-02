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
        match c.collect(&ctx) {
            Ok(mut recs) => {
                records.append(&mut recs);
                sources.extend(c.sources());
            }
            Err(e) => {
                // Graceful degrade: record the failure as a source entry, keep going.
                tracing::warn!(collector = c.name(), error = %e, "collector failed; skipping");
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
    // Analyzer fan-in (SRS §3): each analyzer reads the accumulated records and emits
    // findings. A failing analyzer is logged + skipped (graceful degrade), never aborts.
    let mut findings = Vec::new();
    for a in analyzers {
        match a.analyze(&records) {
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

    /// A fake analyzer returning a canned result (or an error).
    struct FakeAnalyzer {
        name: &'static str,
        result: std::sync::Mutex<Option<Result<Vec<Finding>, CairnError>>>,
    }
    impl FakeAnalyzer {
        fn ok(name: &'static str, findings: Vec<Finding>) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                result: std::sync::Mutex::new(Some(Ok(findings))),
            })
        }
        fn err(name: &'static str) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                result: std::sync::Mutex::new(Some(Err(CairnError::Analyzer {
                    analyzer: name.into(),
                    reason: "boom".into(),
                }))),
            })
        }
    }
    impl Analyzer for FakeAnalyzer {
        fn name(&self) -> &str {
            self.name
        }
        fn analyze(&self, _records: &[Record]) -> crate::Result<Vec<Finding>> {
            self.result.lock().unwrap().take().unwrap()
        }
    }

    fn a_finding() -> Finding {
        Finding::new(Severity::High, "t", FindingSource::Heuristic)
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
