//! Canonical analyzer names: the exact `Analyzer::name()` strings, which every analyzer
//! also stamps into `Finding.analyzer`. Reports and cross-analyzer correlation match on
//! these constants (a typed field plus one spelling) instead of parsing titles/reasons.

pub const SIGMA: &str = "sigma";
pub const ACCOUNT: &str = "heur_account";
pub const CLICKFIX: &str = "heur_clickfix";
pub const EVENTLOG: &str = "heur_eventlog";
pub const LOGON_BRUTEFORCE: &str = "heur_logon_bruteforce";
pub const NETCONN: &str = "heur_netconn";
pub const PARENTCHILD: &str = "heur_parentchild";
pub const PERSIST: &str = "heur_persist";
pub const RMM: &str = "heur_rmm";
pub const DEFENSE: &str = "heur_defense";
pub const LATERAL: &str = "heur_lateral";
pub const CRED_DUMP: &str = "heur_cred_dump";
pub const RANSOM: &str = "heur_ransom";
