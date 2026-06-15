//! Pure mapping: RawProc -> Record::Process. No OS access here (that's cairn-collectors-win).
#[cfg(not(windows))]
use crate::persist::NoopVerifier;
use cairn_collectors_win::proc::RawProc;
use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ProcessRecord, Record};
use cairn_core::traits::{CollectCtx, Collector, FileVerifier};
use cairn_core::Result;

/// True if `image` looks like a Windows absolute path (drive `X:\...` or UNC `\\...`).
/// Only absolute images are sent to verification; a bare file name (the OpenProcess-failed
/// fallback) is left unverified so we never resolve a name against the CWD.
pub fn is_absolute_path(image: &str) -> bool {
    let b = image.as_bytes();
    // Drive path: a letter, a colon, then a separator (e.g. `C:\`). Requiring the leading
    // ASCII letter rejects malformed `:\x` shapes (defensive; real images never hit this).
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    let unc = image.starts_with(r"\\");
    drive || unc
}

/// Fill `signed` for records whose image is an absolute path, via the verifier. A
/// file-name-only image is left None. Pure wiring (no OS code).
fn apply_signatures(records: &mut [ProcessRecord], verifier: &dyn FileVerifier) {
    for r in records.iter_mut() {
        if is_absolute_path(&r.image) {
            r.signed = verifier.verify(&r.image);
            r.signer = verifier.signer(&r.image);
        }
    }
}

/// Collector that enumerates live processes (SRS §4 proc_collector).
pub struct ProcCollector {
    verifier: Box<dyn FileVerifier + Send + Sync>,
}

impl Default for ProcCollector {
    fn default() -> Self {
        #[cfg(windows)]
        let verifier: Box<dyn FileVerifier + Send + Sync> =
            Box::new(cairn_collectors_win::signature::WinSigVerifier);
        #[cfg(not(windows))]
        let verifier: Box<dyn FileVerifier + Send + Sync> = Box::new(NoopVerifier);
        Self { verifier }
    }
}

impl ProcCollector {
    /// Construct with a specific verifier (tests inject a fake).
    pub fn with_verifier(verifier: Box<dyn FileVerifier + Send + Sync>) -> Self {
        Self { verifier }
    }
}

impl Collector for ProcCollector {
    fn name(&self) -> &str {
        "proc"
    }
    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        let raw = cairn_collectors_win::proc::enumerate()?;
        // build_process_records produces only Process variants; extract them, fill signed,
        // then wrap back into Record::Process.
        let mut proc_recs: Vec<ProcessRecord> = build_process_records(&raw)
            .into_iter()
            .filter_map(|r| {
                if let Record::Process(p) = r {
                    Some(p)
                } else {
                    None
                }
            })
            .collect();
        apply_signatures(&mut proc_recs, self.verifier.as_ref());
        Ok(proc_recs.into_iter().map(Record::Process).collect())
    }
    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "process".into(),
            path: "live:process".into(),
            method: "api".into(),
            size: 0,
            sha256: String::new(), // a live table is not a byte stream (spec §5)
            errors: vec![],
        }]
    }
}

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
                signer: None,
                binary_sha256: None,
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

    use cairn_core::traits::FileVerifier;

    struct FakeVerifier(std::collections::HashMap<String, bool>);
    impl FileVerifier for FakeVerifier {
        fn verify(&self, path: &str) -> Option<bool> {
            self.0.get(path).copied()
        }
        fn signer(&self, path: &str) -> Option<String> {
            if path.eq_ignore_ascii_case(r"C:\trusted\a.exe") {
                Some("Proc Vendor".into())
            } else {
                None
            }
        }
    }

    /// is_absolute_path: drive-letter and UNC are absolute; a bare name is not.
    #[test]
    fn absolute_path_detection() {
        assert!(is_absolute_path(r"C:\Windows\System32\svchost.exe"));
        assert!(is_absolute_path(r"\\server\share\app.exe"));
        assert!(!is_absolute_path("svchost.exe"));
        assert!(!is_absolute_path(""));
    }

    /// apply_signatures fills signed only for absolute-path images, via the verifier.
    #[test]
    fn apply_signatures_fills_only_absolute_images() {
        let mut map = std::collections::HashMap::new();
        map.insert(r"C:\evil\b.exe".to_string(), false);
        map.insert(r"C:\trusted\a.exe".to_string(), true);
        let v = FakeVerifier(map);

        let mk = |pid: u32, image: &str| ProcessRecord {
            pid,
            ppid: 0,
            image: image.into(),
            cmdline: String::new(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
        };
        let mut recs = vec![
            mk(1, r"C:\evil\b.exe"),    // absolute, known false
            mk(2, r"C:\trusted\a.exe"), // absolute, known true
            mk(3, r"C:\unknown\c.exe"), // absolute, unknown -> None
            mk(4, "svchost.exe"),       // file-name only -> never queried -> None
        ];
        apply_signatures(&mut recs, &v);
        assert_eq!(recs[0].signed, Some(false));
        assert_eq!(recs[1].signed, Some(true));
        assert_eq!(recs[2].signed, None);
        assert_eq!(recs[3].signed, None);
        // signer is filled only for the absolute path the fake knows; file-name-only is never queried.
        assert_eq!(recs[1].signer.as_deref(), Some("Proc Vendor"));
        assert_eq!(recs[0].signer, None);
        assert_eq!(
            recs[3].signer, None,
            "file-name-only image: signer not queried"
        );
    }

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

    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::Config;

    /// ProcCollector.collect returns Process records (>=1 on a real OS; >=0 if the
    /// platform stub returns empty) and never panics; its name() is "proc".
    #[test]
    fn proc_collector_collects_without_panicking() {
        let collector = ProcCollector::default();
        assert_eq!(collector.name(), "proc");
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        let recs = collector.collect(&ctx).expect("collect");
        // Every record must be a Process variant.
        assert!(recs.iter().all(|r| matches!(r, Record::Process(_))));
        // sources() advertises the live process source.
        assert_eq!(collector.sources().len(), 1);
        assert_eq!(collector.sources()[0].method, "api");
    }
}
