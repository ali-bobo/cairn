#![forbid(unsafe_code)]

use cairn_core::{
    record::{FileMetaRecord, Record, UsnEventRecord},
    Result,
};
use chrono::{DateTime, Utc};
use std::io::Write;

pub fn write_bodyfile<W: Write>(records: &[Record], mut w: W) -> Result<()> {
    for rec in records {
        match rec {
            Record::FileMeta(fm) => write_filemeta_line(fm, &mut w)?,
            Record::UsnEvent(usn) => write_usn_line(usn, &mut w)?,
            _ => {}
        }
    }
    Ok(())
}

fn write_filemeta_line<W: Write>(fm: &FileMetaRecord, w: &mut W) -> Result<()> {
    let atime  = ts_unix(fm.si_mtime);
    let mtime  = ts_unix(fm.si_mtime);
    let ctime  = ts_unix(fm.fn_mtime);
    let crtime = ts_unix(fm.si_btime);
    writeln!(
        w,
        "0|{}|0|0|0|0|{}|{}|{}|{}|{}",
        fm.path, fm.size, atime, mtime, ctime, crtime
    )
    .map_err(|e| cairn_core::CairnError::Other(e.to_string()))
}

fn write_usn_line<W: Write>(usn: &UsnEventRecord, w: &mut W) -> Result<()> {
    let mtime = usn.ts.timestamp();
    writeln!(w, "0|{}|0|0|0|0|0|0|{}|0|0", usn.path, mtime)
        .map_err(|e| cairn_core::CairnError::Other(e.to_string()))
}

fn ts_unix(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map(|d| d.timestamp()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn filemeta(path: &str, size: u64, si_mtime: Option<i64>, fn_mtime: Option<i64>, si_btime: Option<i64>) -> Record {
        Record::FileMeta(FileMetaRecord {
            path: path.to_string(),
            size,
            sha256: None,
            si_btime: si_btime.map(fixed_ts),
            si_mtime: si_mtime.map(fixed_ts),
            fn_btime: None,
            fn_mtime: fn_mtime.map(fixed_ts),
            zone_identifier: None,
            path_complete: None,
        })
    }

    fn usn(path: &str, ts_secs: i64) -> Record {
        Record::UsnEvent(UsnEventRecord {
            ts: fixed_ts(ts_secs),
            path: path.to_string(),
            reason: "create".to_string(),
            mft_ref: 0,
        })
    }

    fn bodyfile_lines(records: &[Record]) -> Vec<String> {
        let mut buf = Vec::new();
        write_bodyfile(records, &mut buf).unwrap();
        String::from_utf8(buf)
            .unwrap()
            .lines()
            .map(str::to_string)
            .filter(|l| !l.is_empty())
            .collect()
    }

    #[test]
    fn filemeta_line_format() {
        let lines = bodyfile_lines(&[filemeta(
            "C:\\foo\\bar.exe",
            4096,
            Some(1_000_000),
            Some(900_000),
            Some(800_000),
        )]);
        assert_eq!(lines.len(), 1, "expected exactly 1 line");
        let fields: Vec<&str> = lines[0].split('|').collect();
        assert_eq!(fields.len(), 11, "bodyfile must have 11 fields: {}", lines[0]);
        assert_eq!(fields[0], "0",              "MD5 must be 0");
        assert_eq!(fields[1], "C:\\foo\\bar.exe", "name field");
        assert_eq!(fields[6], "4096",           "size field");
        assert_eq!(fields[7], "1000000",        "atime = si_mtime");
        assert_eq!(fields[8], "1000000",        "mtime = si_mtime");
        assert_eq!(fields[9], "900000",         "ctime = fn_mtime");
        assert_eq!(fields[10], "800000",        "crtime = si_btime");
    }

    #[test]
    fn usn_line_format() {
        let lines = bodyfile_lines(&[usn("C:\\Windows\\temp.tmp", 1_234_567)]);
        assert_eq!(lines.len(), 1);
        let fields: Vec<&str> = lines[0].split('|').collect();
        assert_eq!(fields.len(), 11);
        assert_eq!(fields[1], "C:\\Windows\\temp.tmp");
        assert_eq!(fields[6], "0",       "size = 0 for USN");
        assert_eq!(fields[7], "0",       "atime = 0 for USN");
        assert_eq!(fields[8], "1234567", "mtime = ts.timestamp()");
        assert_eq!(fields[9], "0",       "ctime = 0 for USN");
        assert_eq!(fields[10], "0",      "crtime = 0 for USN");
    }

    #[test]
    fn non_filemeta_records_skipped() {
        use cairn_core::record::EventRecord;
        use chrono::Utc;
        let records = vec![Record::Event(EventRecord {
            ts: Utc::now(),
            computer: "host".into(),
            channel: "Security".into(),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id: 4688,
            data: serde_json::Map::new(),
            record_id: 1,
        })];
        let lines = bodyfile_lines(&records);
        assert!(lines.is_empty(), "Event records must produce zero bodyfile lines");
    }

    #[test]
    fn none_timestamps_become_zero() {
        let lines = bodyfile_lines(&[filemeta("C:\\x.dll", 0, None, None, None)]);
        assert_eq!(lines.len(), 1);
        let fields: Vec<&str> = lines[0].split('|').collect();
        assert_eq!(fields[7], "0");
        assert_eq!(fields[8], "0");
        assert_eq!(fields[9], "0");
        assert_eq!(fields[10], "0");
    }

    #[test]
    fn size_field() {
        let lines = bodyfile_lines(&[filemeta("C:\\big.bin", 12345, None, None, None)]);
        let fields: Vec<&str> = lines[0].split('|').collect();
        assert_eq!(fields[6], "12345");
    }
}
