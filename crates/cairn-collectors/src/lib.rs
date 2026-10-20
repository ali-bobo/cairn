//! cairn-collectors: raw artifact -> normalized `Record`. SRS §4.
//!
//! Collectors are read-only with respect to the host and isolate every external
//! forensic-parsing dependency (e.g. the `evtx` crate) here, keeping `cairn-core`
//! dependency-free per its contract. Stage 1 ships only `evtx`.
#![forbid(unsafe_code)]

pub mod amcache;
pub mod asep;
pub mod bam;
pub mod evtx;
pub mod evtx_live;
pub mod hash;
pub mod hive_reader;
pub mod host_info;
pub mod logon_session;
pub mod mft;
pub mod net;
pub mod persist;
pub mod prefetch;
pub mod proc;
pub mod shimcache;
pub mod srum;
pub mod userassist;
pub mod usn;
pub mod wmi_subscription;

/// Privilege gate shared by every collector that opens `\\.\C:` for raw reads (mft,
/// usn, amcache, shimcache, bam, userassist, srum). Opening a volume handle with
/// `GENERIC_READ` needs an elevated Administrator token; SeBackupPrivilege is not
/// required. (It is present but *disabled* on a normal admin token, so gating on it
/// silently skipped all seven collectors on every ordinary admin run.)
pub(crate) fn can_read_raw_volume(ctx: &cairn_core::traits::CollectCtx<'_>) -> bool {
    ctx.admin
}

#[cfg(test)]
mod tests {
    use super::can_read_raw_volume;
    use cairn_core::config::Config;
    use cairn_core::traits::CollectCtx;

    fn ctx(cfg: &Config, admin: bool, se_backup: bool) -> CollectCtx<'_> {
        CollectCtx {
            config: cfg,
            admin,
            se_backup,
            se_debug: false,
        }
    }

    /// A normal elevated admin (SeBackupPrivilege disabled) passes the raw-volume gate.
    #[test]
    fn admin_without_se_backup_can_read_raw_volume() {
        let cfg = Config::default();
        assert!(can_read_raw_volume(&ctx(&cfg, true, false)));
    }

    /// A non-admin never passes, whatever its privileges.
    #[test]
    fn non_admin_cannot_read_raw_volume() {
        let cfg = Config::default();
        assert!(!can_read_raw_volume(&ctx(&cfg, false, true)));
        assert!(!can_read_raw_volume(&ctx(&cfg, false, false)));
    }
}
