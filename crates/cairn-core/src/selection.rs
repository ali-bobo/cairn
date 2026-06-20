//! Pure collector-selection decision (S2-L). Given the run profile and an optional
//! `--only` allow-list, decide which collector modules run. No host, no I/O — the
//! selection is a deterministic string-set operation, unit-tested on any platform.
//!
//! Why a module of its own: this is the switch raw-NTFS (S2-M+) hangs off. When
//! heavier collectors are added tagged `standard`/`verbose`-only, `minimal` will
//! skip them automatically — the profile→base-set mapping here is the single place
//! that knowledge lives.

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

/// Collector names that are raw-NTFS reads (admin + heavy). `--profile minimal` skips
/// these (SRS §19.1). Grows as S2-N/O/P add modules — the single place that knowledge lives.
const RAW_NTFS: &[&str] = &["mft", "usn"];

/// Modules a profile selects from `available`, BEFORE the `--only` intersection.
/// `minimal` = the light live set (raw-NTFS excluded, SRS §19.1). `standard`/`verbose`
/// currently select everything available. The mechanism is here; profiles diverge as
/// heavier collectors register into `RAW_NTFS`.
fn profile_base<'a>(profile: Profile, available: &[&'a str]) -> Vec<&'a str> {
    match profile {
        Profile::Minimal => available
            .iter()
            .copied()
            .filter(|name| !RAW_NTFS.contains(name))
            .collect(),
        Profile::Standard | Profile::Verbose => available.to_vec(),
    }
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
    available: &[&str],
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
                available.iter().map(|s| s.to_string()).collect();
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

    fn avail() -> Vec<&'static str> {
        vec!["proc", "net", "persist"]
    }

    #[test]
    fn standard_no_only_selects_all_available() {
        let out = select_modules(Profile::Standard, None, &avail());
        assert_eq!(out.selected, vec!["proc", "net", "persist"]);
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn minimal_no_only_selects_the_live_light_set() {
        // Today's avail() fixture has no raw-NTFS modules, so minimal and standard return
        // the same set here. The profile divergence is tested by minimal_excludes_raw_ntfs_collectors.
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
    fn minimal_excludes_raw_ntfs_collectors() {
        // SRS §19.1: --profile minimal SKIPS raw-NTFS. "mft" is the first raw-NTFS module.
        let available = vec!["proc", "net", "persist", "mft"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]); // no "mft"
    }

    #[test]
    fn standard_and_verbose_include_raw_ntfs() {
        let available = vec!["proc", "net", "persist", "mft"];
        let std = select_modules(Profile::Standard, None, &available);
        assert_eq!(std.selected, vec!["proc", "net", "persist", "mft"]);
        let vb = select_modules(Profile::Verbose, None, &available);
        assert_eq!(vb.selected, vec!["proc", "net", "persist", "mft"]);
    }

    #[test]
    fn only_mft_under_minimal_still_excluded() {
        // --only cannot re-enable a module the profile base excludes (only INTERSECTS base).
        let available = vec!["proc", "net", "persist", "mft"];
        let only = vec!["mft".to_string()];
        let out = select_modules(Profile::Minimal, Some(&only), &available);
        assert!(out.selected.is_empty());
        // "mft" IS available (just not in minimal's base), so it is NOT an unknown_only warning.
        assert!(out.unknown_only.is_empty());
    }

    #[test]
    fn minimal_excludes_usn() {
        let available = vec!["proc", "net", "persist", "mft", "usn"];
        let out = select_modules(Profile::Minimal, None, &available);
        assert_eq!(out.selected, vec!["proc", "net", "persist"]); // no mft, no usn
        let std = select_modules(Profile::Standard, None, &available);
        assert!(std.selected.contains(&"usn".to_string())); // standard keeps usn (Vec<String>)
    }
}
