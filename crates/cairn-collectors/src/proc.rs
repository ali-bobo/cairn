//! Pure mapping: RawProc -> Record::Process. No OS access here (that's cairn-collectors-win).
use cairn_collectors_win::proc::RawProc;
use cairn_core::record::{ProcessRecord, Record};

/// Map raw processes to normalized Records. Pure + total (never panics). A None cmdline
/// becomes "" (ProcessRecord.cmdline is String). integrity_raw maps to a label.
pub fn build_process_records(raw: &[RawProc]) -> Vec<Record> {
    raw.iter()
        .map(|r| {
            Record::Process(ProcessRecord {
                pid: r.pid,
                ppid: r.ppid,
                image: r.image.clone(),
                cmdline: r.cmdline.clone().unwrap_or_default(),
                signed: r.signed,
                integrity: r.integrity_raw.map(integrity_label),
                user: r.user.clone(),
                start_time: r.start_time,
            })
        })
        .collect()
}

/// Windows integrity RID -> label (SRS forensic field). Common RIDs only; unknown -> "".
fn integrity_label(rid: u32) -> String {
    match rid {
        0x0000 => "untrusted",
        0x1000 => "low",
        0x2000 => "medium",
        0x3000 => "high",
        0x4000 => "system",
        _ => "",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_collectors_win::proc::RawProc;

    fn raw(pid: u32, ppid: u32, image: &str) -> RawProc {
        RawProc {
            pid,
            ppid,
            image: image.into(),
            cmdline: None,
            integrity_raw: None,
            signed: None,
            user: None,
            start_time: None,
        }
    }

    /// Each RawProc becomes one Record::Process with pid/ppid/image carried through and a
    /// None cmdline normalized to "".
    #[test]
    fn maps_raw_to_process_records() {
        let recs = build_process_records(&[raw(100, 4, r"C:\Windows\explorer.exe")]);
        assert_eq!(recs.len(), 1);
        let Record::Process(p) = &recs[0] else {
            panic!("expected Process record")
        };
        assert_eq!(p.pid, 100);
        assert_eq!(p.ppid, 4);
        assert_eq!(p.image, r"C:\Windows\explorer.exe");
        assert_eq!(p.cmdline, ""); // None -> ""
    }

    /// integrity_raw maps to its label; the well-known "high" RID is 0x3000 (12288).
    #[test]
    fn maps_integrity_rid_to_label() {
        let mut r = raw(1, 0, "x.exe");
        r.integrity_raw = Some(0x3000);
        let recs = build_process_records(&[r]);
        let Record::Process(p) = &recs[0] else {
            panic!()
        };
        assert_eq!(p.integrity.as_deref(), Some("high"));
    }
}
