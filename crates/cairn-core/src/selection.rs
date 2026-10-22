//! Pure collector-selection decision (S2-L). Given the run profile and an optional
//! `--only` allow-list, decide which collector modules run. No host, no I/O — the
//! selection is a deterministic string-set operation, unit-tested on any platform.
//!
//! Which modules a profile includes is carried by each [`ModuleInfo`] (from the CLI
//! collector registry); this module only applies it.

use crate::config::Profile;

/// The result of a selection decision: the collector names to run (in canonical
/// `available` order, deterministic), plus any `--only` names that matched no
/// available collector (surfaced as a warning by the CLI — never silently dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionOutcome {
    pub selected: Vec<String>,
    pub unknown_only: Vec<String>,
}

/// Resolve one `--only` token to a canonical collector name. The CLI advertises a
/// friendly `process`; the real `Collector::name()` is `proc`. Resolution is
/// case-insensitive. Returns the canonical lowercase token (may still be unknown).
fn canonical_only_name(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "process" => "proc".to_string(),
        other => other.to_string(),
    }
}

/// What selection needs to know about one collector module: its canonical name and
/// whether `--profile minimal` runs it. The CLI's collector registry is the one list of
/// these (with constructors); this crate only decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: &'static str,
    /// True when the light `minimal` profile runs this module. The heavy file scanners
    /// (prefetch, live EVTX) are standard-only.
    pub in_minimal: bool,
}

/// Modules a profile selects from `available`, BEFORE the `--only` intersection.
fn profile_base(profile: Profile, available: &[ModuleInfo]) -> Vec<&'static str> {
    available
        .iter()
        .filter(|m| match profile {
            Profile::Minimal => m.in_minimal,
            Profile::Standard => true,
        })
        .map(|m| m.name)
        .collect()
}

/// Decide which collector modules run.
///
/// 1. base = the profile's module set (intersected with what is `available`).
/// 2. if `only` is Some, keep only modules whose canonical name is in `only`;
///    `only` names matching no available collector go to `unknown_only`.
/// 3. result order follows `available` (deterministic, NFR4); no duplicates.
///
/// PURE: no host, no I/O. Unit-tested on any platform.
pub fn select_modules(
    profile: Profile,
    only: Option<&[String]>,
    available: &[ModuleInfo],
) -> SelectionOutcome {
    let base = profile_base(profile, available);

    let selected: Vec<String> = match only {
        None => base.iter().map(|s| s.to_string()).collect(),
        Some(only_list) => {
            let wanted: std::collections::BTreeSet<String> =
                only_list.iter().map(|s| canonical_only_name(s)).collect();
            // Walk `available` order so output is deterministic regardless of how the
            // user ordered --only; de-dup is implicit (each available name once).
            base.iter()
                .filter(|name| wanted.contains(**name))
                .map(|s| s.to_string())
                .collect()
        }
    };

    // An --only name that resolves to nothing in `available` is reported, not dropped.
    let unknown_only: Vec<String> = match only {
        None => Vec::new(),
        Some(only_list) => {
            let avail_set: std::collections::BTreeSet<String> =
                available.iter().map(|m| m.name.to_string()).collect();
            let mut seen = std::collections::BTreeSet::new();
            only_list
                .iter()
                .filter_map(|raw| {
                    let canon = canonical_only_name(raw);
                    if avail_set.contains(&canon) {
                        None
                    } else if seen.insert(canon) {
                        // Report the ORIGINAL token the user typed (clearer warning).
                        Some(raw.trim().to_string())
                    } else {
                        None
                    }
                })
                .collect()
        }
    };

    SelectionOutcome {
        selected,
        unknown_only,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &'static str, in_minimal: bool) -> ModuleInfo {
        ModuleInfo { name, in_minimal }
    }

    fn avail() -> Vec<ModuleInfo> {
        vec![m("proc", true), m("net", true), m("persist", true)]
    }

    #[test]
    fn standard_no_only_selects_all_available() {
        let out = select_modules(Profile::Standard, None, &avail());
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn minimal_no_only_selects_the_live_light_set() {
        // Every avail() module is in_minimal, so minimal and standard return
        // the same set here. The divergence is tested by minimal_skips_prefetch_and_evtx_live.
        let out = select_modules(Profile::Minimal, None, &avail());
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
    }

    #[test]
    fn only_restricts_to_named_modules() {
        let only = vec!["persist".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["persist"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn only_alias_process_resolves_to_proc() {
        // The CLI help advertises `process`; the real collector name is `proc`.
        let only = vec!["process".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["proc"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn only_unknown_name_is_reported_not_silently_dropped() {
        let only = vec!["persist".to_string(), "bogus".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["persist"]);
        assert_eq!(out.unknown_only, vec!["bogus".to_string()]);
    }

    #[test]
    fn only_all_unknown_yields_empty_selection_without_panic() {
        let only = vec!["nope".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert!(out.selected.is_empty());
        assert_eq!(out.unknown_only, vec!["nope".to_string()]);
    }

    #[test]
    fn only_evtx_on_live_run_is_unknown() {
        // evtx is the separate `cairn evtx` subcommand, not a live collector.
        let only = vec!["evtx".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert!(out.selected.is_empty());
        assert_eq!(out.unknown_only, vec!["evtx".to_string()]);
    }

    #[test]
    fn selection_order_is_deterministic_available_order() {
        // Order follows `available` (the canonical collector order), not `only` order,
        // so output is deterministic (NFR4) regardless of how the user typed --only.
        let only = vec!["persist".to_string(), "proc".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["proc", "persist"]);
    }

    #[test]
    fn duplicate_only_names_do_not_duplicate_selection() {
        let only = vec!["persist".to_string(), "persist".to_string()];
        let out = select_modules(Profile::Standard, Some(&only), &avail());
        assert_eq!(out.selected, vec!["persist"]);
    }

    #[test]
    fn minimal_skips_prefetch_and_evtx_live() {
        let available = vec![
            m("proc", true),
            m("net", true),
            m("persist", true),
            m("prefetch", false),
            m("evtx_live", false),
        ];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        let std = select_modules(Profile::Standard, None, &available);
        assert_eq!(
            std.selected,
            vec!["proc", "net", "persist", "prefetch", "evtx_live"]
        );
    }

    #[test]
    fn only_prefetch_under_minimal_still_excluded() {
        // --only cannot re-enable a module the profile base excludes (only INTERSECTS base).
        let available = vec![
            m("proc", true),
            m("net", true),
            m("persist", true),
            m("prefetch", false),
        ];
        let only = vec!["prefetch".to_string()];
        let out = select_modules(Profile::Minimal, Some(&only), &available);
        assert!(out.selected.is_empty());
        // "prefetch" IS available (just not in minimal's base), so it is NOT unknown.
        assert!(out.unknown_only.is_empty());
    }
}
