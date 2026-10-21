//! Canonical live-collector names: the exact `Collector::name()` strings, stamped into
//! `SourceEntry.collector` and `RunInfo.selected_modules`. Collectors, the CLI's
//! collector registry, and the HTML report all use these constants so a name exists in
//! exactly one place. Run order, the `--profile minimal` flag and the constructors live
//! in the CLI registry (`cairn-cli/src/registry.rs`), which is the one list of what runs.

pub const PROC: &str = "proc";
pub const NET: &str = "net";
pub const LOGON_SESSION: &str = "logon_session";
pub const PERSIST: &str = "persist";
pub const PREFETCH: &str = "prefetch";
pub const WMI_SUBSCRIPTION: &str = "wmi_subscription";
pub const EVTX_LIVE: &str = "evtx_live";
