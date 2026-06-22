//! BamCollector: parse the SYSTEM hive's Background Activity Moderator (bam)
//! UserSettings into per-SID Record::Execution with a real last-execution time.
//!
//! bam records the last background-activity time per program per user under
//! {ControlSet}\Services\bam\State\UserSettings\<SID>. Each value's NAME is the
//! executable's NT device path; its DATA begins with an 8-byte LE FILETIME. This is
//! reached via a raw \\.\C: hive read (the live registry denies the SYSTEM-only ACL).
//! On an absent key or unrecognised structure it ABSTAINS (records the reason) rather
//! than guess (NFR12).

use chrono::{DateTime, Utc};

use cairn_core::time::filetime_to_utc;

/// Parse the last-execution time from a bam value's data: the leading 8 bytes are a
/// little-endian FILETIME. Returns None if the data is shorter than 8 bytes or the
/// FILETIME is zero (legitimate "no time" padding). Never panics (bounds-checked).
#[allow(dead_code)] // removed in Task 4 (BamCollector consumes it)
fn parse_bam_value(data: &[u8]) -> Option<DateTime<Utc>> {
    let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
    let ft = u64::from_le_bytes(bytes);
    filetime_to_utc(ft)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FILETIME for 2021-01-01T00:00:00Z (verified: 132_539_328_000_000_000).
    const FT_2021: u64 = 132_539_328_000_000_000;

    #[test]
    fn parses_valid_8_byte_filetime() {
        let data = FT_2021.to_le_bytes().to_vec();
        let got = parse_bam_value(&data).expect("valid FILETIME must parse");
        assert_eq!(got, filetime_to_utc(FT_2021).unwrap());
    }

    #[test]
    fn trailing_padding_is_ignored() {
        // 8-byte FILETIME + 16 bytes of trailing padding must parse identically.
        let mut data = FT_2021.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 16]);
        let got = parse_bam_value(&data).expect("must parse despite padding");
        assert_eq!(got, filetime_to_utc(FT_2021).unwrap());
    }

    #[test]
    fn short_data_is_none_no_panic() {
        assert_eq!(parse_bam_value(&[]), None);
        assert_eq!(parse_bam_value(&[1, 2, 3]), None);
        assert_eq!(parse_bam_value(&[0u8; 7]), None); // one byte short
    }

    #[test]
    fn all_zero_filetime_is_none() {
        // Zero FILETIME is legitimate "no time" padding, not an error.
        assert_eq!(parse_bam_value(&[0u8; 8]), None);
        assert_eq!(parse_bam_value(&[0u8; 24]), None);
    }
}
