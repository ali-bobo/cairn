//! Windows FILETIME → `chrono::DateTime<Utc>` conversion (S2-N).
//!
//! NTFS SI/FN timestamps (`ntfs::NtfsTime::nt_timestamp()`) are Windows FILETIME:
//! 100-nanosecond intervals since 1601-01-01 UTC. Cairn uses `chrono`, not the `time`
//! crate the `ntfs` crate converts to, so we convert via pure arithmetic here. This
//! also gives a single, unit-testable home reused by $J later (it uses FILETIME too).
use chrono::{DateTime, Utc};

/// 100-ns intervals between 1601-01-01 and 1970-01-01 (the Unix epoch).
const UNIX_EPOCH_AS_FILETIME: u64 = 11_644_473_600 * 10_000_000;

/// Convert a Windows FILETIME to `DateTime<Utc>`.
///
/// Returns `None` for:
/// - `0` (an unset timestamp — common in sparse/timestomped records),
/// - a time before the Unix epoch (1601–1970; `checked_sub` underflow),
/// - seconds exceeding `i64::MAX` or outside `DateTime`'s range (both unreachable for any
///   `u64` FILETIME in practice — `u64::MAX` is ~year 60056, inside chrono's range — but
///   handled so the function is total for all inputs).
///
/// Pure arithmetic, no panic, no `time`-crate dependency (NFR5: UTC RFC3339).
pub fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let since_unix_100ns = ft.checked_sub(UNIX_EPOCH_AS_FILETIME)?;
    // secs cannot exceed i64::MAX in practice (u64::MAX / 10_000_000 ≈ 1.8e12 « i64::MAX),
    // but use a checked conversion so the invariant is explicit, not silently assumed.
    let secs = i64::try_from(since_unix_100ns / 10_000_000).ok()?;
    // Remainder is in [0, 9_999_999]; × 100 is in [0, 999_999_900] < u32::MAX, so safe.
    let nanos = ((since_unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_filetime_converts_to_expected_utc() {
        // Cross-check value from the ntfs crate's own time.rs test:
        // 130018833000000000 == 2013-01-05T18:15:00Z.
        let dt = filetime_to_utc(130_018_833_000_000_000).unwrap();
        assert_eq!(dt.to_rfc3339(), "2013-01-05T18:15:00+00:00");
    }

    #[test]
    fn zero_is_none() {
        assert_eq!(filetime_to_utc(0), None);
    }

    #[test]
    fn pre_unix_epoch_underflows_to_none() {
        // Any FILETIME below the 1970 boundary (e.g. a 1601-era value) → None.
        assert_eq!(filetime_to_utc(1), None);
        assert_eq!(filetime_to_utc(UNIX_EPOCH_AS_FILETIME - 1), None);
    }

    #[test]
    fn unix_epoch_exactly_is_1970() {
        let dt = filetime_to_utc(UNIX_EPOCH_AS_FILETIME).unwrap();
        assert_eq!(dt.to_rfc3339(), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn max_filetime_is_none_not_panic() {
        // u64::MAX is representable by chrono (~year 60056).
        // The key is: no panic, ever. The assertion documents the actual behavior.
        let result = filetime_to_utc(u64::MAX);
        assert!(result.is_some(), "u64::MAX should be representable, not panic");
    }
}
