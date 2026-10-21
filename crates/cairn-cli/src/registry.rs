//! The one list of what a run can execute.
//!
//! - [`COLLECTORS`]: every live collector, in canonical run order, with its
//!   `--profile minimal` flag and constructor. Selection (`cairn_core::select_modules`),
//!   construction and the manifest's `selected_modules` all come from this table.
//! - [`analyzers`]: every analyzer, built for a live run or the offline `cairn evtx`
//!   path from one table, so the two modes cannot drift apart.
//!
//! Names are the `cairn_core::collectors` / `cairn_core::analyzers` constants.
use cairn_core::traits::{Analyzer, Collector};
use cairn_core::{collectors as names, Config, ModuleInfo};

/// `now - cairn_core::config::DEFAULT_SINCE_HOURS` (30 days): the start of the default
/// live-EVTX window when `--since` is not given. Incidents are routinely found weeks
/// after initial access, and EVTX logs are size-bounded, so a month costs little.
pub fn default_since(now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    now - chrono::Duration::hours(cairn_core::config::DEFAULT_SINCE_HOURS)
}

/// Channels the live EVTX collector reads: whatever the loaded Sigma rules reference,
/// plus the channels the built-in event-log heuristics need, so account, brute-force
/// and log-clearing detections still run when no rules are loaded.
pub fn live_evtx_channels(sigma: Option<&[String]>) -> Vec<String> {
    let mut out: Vec<String> = sigma.map(<[String]>::to_vec).unwrap_or_default();
    for ch in cairn_heur::eventlog::CHANNELS {
        if !out.iter().any(|c| c.eq_ignore_ascii_case(ch)) {
            out.push((*ch).to_string());
        }
    }
    out
}

/// What collector constructors may need beyond their defaults.
pub struct BuildCtx<'a> {
    pub cfg: &'a Config,
    /// Channels the loaded Sigma rules reference (None when no rules loaded).
    pub sigma_channels: Option<&'a [String]>,
}

/// One live collector: selection info plus constructor.
pub struct CollectorEntry {
    pub info: ModuleInfo,
    pub build: fn(&BuildCtx<'_>) -> Box<dyn Collector>,
}

const fn light(name: &'static str) -> ModuleInfo {
    ModuleInfo {
        name,
        in_minimal: true,
    }
}

const fn standard_only(name: &'static str) -> ModuleInfo {
    ModuleInfo {
        name,
        in_minimal: false,
    }
}

/// Every live collector in canonical run order. `--profile minimal` skips the two that
/// scan many files (prefetch, live EVTX).
pub const COLLECTORS: &[CollectorEntry] = &[
    CollectorEntry {
        info: light(names::PROC),
        build: |_| Box::new(cairn_collectors::proc::ProcCollector::default()),
    },
    CollectorEntry {
        info: light(names::NET),
        build: |_| Box::new(cairn_collectors::net::NetCollector),
    },
    CollectorEntry {
        info: light(names::LOGON_SESSION),
        build: |_| Box::new(cairn_collectors::logon_session::LogonSessionCollector),
    },
    CollectorEntry {
        info: light(names::PERSIST),
        build: |_| Box::new(cairn_collectors::persist::PersistCollector::default()),
    },
    CollectorEntry {
        info: standard_only(names::PREFETCH),
        build: |_| Box::new(cairn_collectors::prefetch::PrefetchCollector::default()),
    },
    CollectorEntry {
        info: light(names::WMI_SUBSCRIPTION),
        build: |_| Box::new(cairn_collectors::wmi_subscription::WmiSubscriptionCollector),
    },
    CollectorEntry {
        info: standard_only(names::EVTX_LIVE),
        build: |ctx| {
            let channels = live_evtx_channels(ctx.sigma_channels);
            let since = ctx
                .cfg
                .since
                .unwrap_or_else(|| default_since(chrono::Utc::now()));
            Box::new(cairn_collectors::evtx_live::EvtxLiveCollector::new(
                channels, since,
            ))
        },
    },
];

/// Selection view of [`COLLECTORS`] for `cairn_core::select_modules`.
pub fn module_infos() -> Vec<ModuleInfo> {
    COLLECTORS.iter().map(|c| c.info).collect()
}

/// Construct the selected collectors, in registry order.
pub fn build_collectors(selected: &[String], ctx: &BuildCtx<'_>) -> Vec<Box<dyn Collector>> {
    COLLECTORS
        .iter()
        .filter(|c| selected.iter().any(|s| s == c.info.name))
        .map(|c| (c.build)(ctx))
        .collect()
}

/// Which run an analyzer set is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `cairn run`: every analyzer.
    Live,
    /// `cairn evtx`: only analyzers that read EVTX events alone.
    Evtx,
}

struct AnalyzerEntry {
    name: &'static str,
    /// Reads only `Record::Event`, so it also runs on offline EVTX files.
    events_only: bool,
    build: fn(&Config) -> Box<dyn Analyzer>,
}

/// Every built-in heuristic. Sigma is appended by [`analyzers`] when rules loaded.
const ANALYZERS: &[AnalyzerEntry] = &[
    AnalyzerEntry {
        name: cairn_core::analyzers::PARENTCHILD,
        events_only: false,
        build: |_| Box::new(cairn_heur::ParentChildHeuristic),
    },
    AnalyzerEntry {
        name: cairn_core::analyzers::NETCONN,
        events_only: false,
        build: |_| Box::new(cairn_heur::NetConnHeuristic),
    },
    AnalyzerEntry {
        name: cairn_core::analyzers::PERSIST,
        events_only: false,
        build: |_| Box::new(cairn_heur::PersistHeuristic),
    },
    AnalyzerEntry {
        name: cairn_core::analyzers::ACCOUNT,
        events_only: true,
        build: |_| Box::new(cairn_heur::AccountHeuristic),
    },
    AnalyzerEntry {
        name: cairn_core::analyzers::EVENTLOG,
        events_only: true,
        build: |_| Box::new(cairn_heur::EventLogHeuristic),
    },
    AnalyzerEntry {
        name: cairn_core::analyzers::CLICKFIX,
        events_only: false,
        build: |_| Box::new(cairn_heur::ClickFixHeuristic),
    },
    AnalyzerEntry {
        name: cairn_core::analyzers::LOGON_BRUTEFORCE,
        events_only: true,
        build: |cfg| {
            Box::new(cairn_heur::LogonBruteforceHeuristic::new(
                chrono::Duration::minutes(cfg.logon_bruteforce_window_minutes),
                cfg.logon_bruteforce_threshold,
                chrono::Duration::minutes(cfg.password_spraying_window_minutes),
                cfg.password_spraying_threshold,
            ))
        },
    },
];

/// The analyzers for `mode`, in registry order, then Sigma (when rules loaded).
pub fn analyzers(
    cfg: &Config,
    mode: Mode,
    sigma: Option<cairn_heur::SigmaAnalyzer>,
) -> Vec<Box<dyn Analyzer>> {
    let selected: Vec<&AnalyzerEntry> = ANALYZERS
        .iter()
        .filter(|a| mode == Mode::Live || a.events_only)
        .collect();
    let mut names: Vec<&str> = selected.iter().map(|a| a.name).collect();
    let mut out: Vec<Box<dyn Analyzer>> = selected.iter().map(|a| (a.build)(cfg)).collect();
    if let Some(sa) = sigma {
        names.push(cairn_core::analyzers::SIGMA);
        out.push(Box::new(sa));
    }
    tracing::info!(analyzers = %names.join(","), "analyzer selection");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::{select_modules, Profile};

    fn names_of(selected: &[String]) -> Vec<String> {
        let cfg = Config::default();
        let ctx = BuildCtx {
            cfg: &cfg,
            sigma_channels: None,
        };
        build_collectors(selected, &ctx)
            .iter()
            .map(|c| c.name().to_string())
            .collect()
    }

    /// Each registry entry's constructor builds the collector its name says: the
    /// table and the collectors' own name() never disagree.
    #[test]
    fn collector_names_match_constructed_collectors() {
        let all: Vec<String> = COLLECTORS.iter().map(|c| c.info.name.to_string()).collect();
        assert_eq!(names_of(&all), all);
    }

    #[test]
    fn selected_collectors_follow_selection() {
        // --only persist => only persist constructed.
        let only = vec!["persist".to_string()];
        let sel = select_modules(Profile::Standard, Some(&only), &module_infos());
        assert_eq!(names_of(&sel.selected), vec!["persist"]);

        // no --only => every collector in canonical order.
        let sel = select_modules(Profile::Standard, None, &module_infos());
        assert_eq!(names_of(&sel.selected).len(), COLLECTORS.len());

        // --profile minimal skips prefetch and evtx_live.
        let sel = select_modules(Profile::Minimal, None, &module_infos());
        let built = names_of(&sel.selected);
        assert!(!built.contains(&names::PREFETCH.to_string()));
        assert!(!built.contains(&names::EVTX_LIVE.to_string()));
        assert!(built.contains(&names::PROC.to_string()));
    }

    #[test]
    fn analyzer_names_match_constructed_analyzers() {
        let cfg = Config::default();
        let built: Vec<String> = analyzers(&cfg, Mode::Live, None)
            .iter()
            .map(|a| a.name().to_string())
            .collect();
        let table: Vec<String> = ANALYZERS.iter().map(|a| a.name.to_string()).collect();
        assert_eq!(built, table);
    }

    /// The offline path runs exactly the event-only subset of the live set.
    #[test]
    fn evtx_mode_is_the_event_only_subset_of_live() {
        let cfg = Config::default();
        let live: Vec<String> = analyzers(&cfg, Mode::Live, None)
            .iter()
            .map(|a| a.name().to_string())
            .collect();
        let evtx: Vec<String> = analyzers(&cfg, Mode::Evtx, None)
            .iter()
            .map(|a| a.name().to_string())
            .collect();
        assert_eq!(
            evtx,
            vec![
                cairn_core::analyzers::ACCOUNT,
                cairn_core::analyzers::EVENTLOG,
                cairn_core::analyzers::LOGON_BRUTEFORCE
            ]
        );
        assert!(evtx.iter().all(|n| live.contains(n)));
    }

    #[test]
    fn live_evtx_channels_always_include_builtin_channels() {
        let none = live_evtx_channels(None);
        for ch in cairn_heur::eventlog::CHANNELS {
            assert!(none.iter().any(|c| c == ch), "{ch} missing without Sigma");
        }
        let sigma = vec![
            "security".to_string(),
            "Microsoft-Windows-PowerShell/Operational".to_string(),
        ];
        let merged = live_evtx_channels(Some(&sigma));
        assert_eq!(
            merged
                .iter()
                .filter(|c| c.eq_ignore_ascii_case("Security"))
                .count(),
            1,
            "{merged:?}"
        );
        assert!(merged
            .iter()
            .any(|c| c == "Microsoft-Windows-PowerShell/Operational"));
    }

    #[test]
    fn default_since_looks_back_thirty_days() {
        let now = chrono::Utc::now();
        assert_eq!(now - default_since(now), chrono::Duration::days(30));
    }
}
