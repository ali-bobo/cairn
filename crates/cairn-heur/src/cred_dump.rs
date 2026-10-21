//! Credential dumping (ATT&CK T1003): signs that LSASS memory or the SAM / NTDS
//! secrets were copied, judged from what cairn collected without ever opening LSASS.
//!
//! - **Dump files** (`dropscan` [`FileListingRecord`]): a minidump (`MDMP` signature)
//!   in a drop zone is Medium; one whose name mentions lsass is High. A file named
//!   like an lsass dump without the signature (renamed, encrypted or packed) is Medium.
//! - **WER LocalDumps for lsass.exe** (`dropscan` RegValue for
//!   [`WER_LSASS_LOCALDUMPS_KEY`]): makes Windows write a full LSASS dump on the next
//!   crash; almost never set legitimately. High.
//! - **Command lines** (live processes and Security 4688): comsvcs.dll `MiniDump`,
//!   ProcDump of lsass, Mimikatz modules, PowerShell `Out-Minidump`, `reg save` of the
//!   SAM / SECURITY hives, `ntdsutil` IFM and copies of `ntds.dit`. High.
#![forbid(unsafe_code)]

use cairn_core::finding::{EntityFile, EntityRegistry, FindingSource, Severity};
use cairn_core::record::{
    FileListingRecord, Record, RegValueRecord, MAGIC_MINIDUMP, WER_LSASS_LOCALDUMPS_KEY,
};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};

use crate::cmdline::{command_lines, program, CommandLine};

/// One command-line technique: what it is and its ATT&CK sub-technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpTechnique {
    pub label: &'static str,
    pub mitre: &'static str,
}

const LSASS_MEMORY: &str = "T1003.001";
const SAM: &str = "T1003.002";
const NTDS: &str = "T1003.003";

/// The technique a command line uses, if any. `prog` is the
/// [`crate::trust::exe_name`] of the program, `cmd` the normalized command line.
pub fn dump_technique(prog: &str, cmd: &str) -> Option<DumpTechnique> {
    let t = |label, mitre| Some(DumpTechnique { label, mitre });
    if cmd.contains("comsvcs") && (cmd.contains("minidump") || cmd.contains("#24")) {
        return t("comsvcs.dll MiniDump (LOLBin process dump)", LSASS_MEMORY);
    }
    if (prog.starts_with("procdump") || cmd.contains("procdump")) && cmd.contains("lsass") {
        return t("ProcDump of lsass", LSASS_MEMORY);
    }
    if ["sekurlsa::", "lsadump::", "privilege::debug"]
        .iter()
        .any(|m| cmd.contains(m))
    {
        return t("Mimikatz module on the command line", LSASS_MEMORY);
    }
    if cmd.contains("out-minidump") {
        return t("PowerShell Out-Minidump", LSASS_MEMORY);
    }
    if prog == "reg"
        && [" save ", " export "].iter().any(|v| cmd.contains(v))
        && [
            "hklm\\sam",
            "hklm\\security",
            "hkey_local_machine\\sam",
            "hkey_local_machine\\security",
        ]
        .iter()
        .any(|h| cmd.contains(h))
    {
        return t("reg save of the SAM / SECURITY hive", SAM);
    }
    if prog == "ntdsutil" && (cmd.contains("ifm") || cmd.contains("ac i ntds")) {
        return t("ntdsutil IFM copy of the AD database", NTDS);
    }
    if cmd.contains("ntds.dit")
        && ["copy", "esentutl", "robocopy", "xcopy"]
            .iter()
            .any(|c| cmd.contains(c))
    {
        return t("copy of ntds.dit", NTDS);
    }
    None
}

fn file_name_lower(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// Severity and reason for a drop-zone file, None when it does not look like a dump.
pub fn judge_file(f: &FileListingRecord) -> Option<(Severity, String)> {
    let name = file_name_lower(&f.path);
    let named_lsass = name.contains("lsass");
    let minidump = f.magic.as_deref() == Some(MAGIC_MINIDUMP);
    let size = format!("{} bytes", f.size);
    match (minidump, named_lsass) {
        (true, true) => Some((
            Severity::High,
            format!("minidump (MDMP signature) named like an LSASS dump in a drop zone, {size}"),
        )),
        (true, false) => Some((
            Severity::Medium,
            format!(
                "minidump (MDMP signature) in a drop zone, {size}; may be an application crash \
                 dump or a renamed LSASS dump"
            ),
        )),
        (false, true)
            if name.ends_with(".dmp") || name.ends_with(".mdmp") || name.ends_with(".bin") =>
        {
            Some((
                Severity::Medium,
                format!(
                    "file named like an LSASS dump without the MDMP signature (signature {}), \
                     {size}; may be encrypted or packed",
                    f.magic.as_deref().unwrap_or("unreadable")
                ),
            ))
        }
        _ => None,
    }
}

fn file_finding(fl: &FileListingRecord, severity: Severity, reason: String) -> Finding {
    let name = file_name_lower(&fl.path);
    let mut f = Finding::new(
        severity,
        format!("可疑記憶體傾印檔：{name}"),
        FindingSource::Heuristic,
    );
    if let Some(t) = fl.modified.max(fl.created) {
        f.ts = t;
    }
    f.artifact = "dropscan:listing".into();
    f.mitre = vec![LSASS_MEMORY.into()];
    f.details = format!(
        "{} size={} magic={} modified={} created={}",
        fl.path,
        fl.size,
        fl.magic.as_deref().unwrap_or("-"),
        fl.modified
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "-".into()),
        fl.created
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "-".into()),
    );
    f.reason = Some(reason);
    f.details_client = Some(format!(
        "在 {} 找到一個記憶體傾印檔。攻擊者常把系統登入程序（LSASS）的記憶體存成這種檔案，\
         再從中取出帳號密碼；請確認這個檔案是誰、為了什麼產生的，若無法說明，\
         應視為密碼可能已外洩並更換相關帳號密碼。",
        fl.path
    ));
    f.entity.file = Some(EntityFile {
        path: fl.path.clone(),
        sha256: None,
        mtime: fl.modified,
    });
    f
}

fn is_wer_lsass(r: &RegValueRecord) -> bool {
    r.hive.eq_ignore_ascii_case("HKLM") && r.key.eq_ignore_ascii_case(WER_LSASS_LOCALDUMPS_KEY)
}

fn wer_finding(r: &RegValueRecord) -> Finding {
    let mut f = Finding::new(
        Severity::High,
        "已設定 LSASS 當機自動傾印（WER LocalDumps）",
        FindingSource::Heuristic,
    );
    if let Some(t) = r.last_write {
        f.ts = t;
    }
    f.artifact = "registry".into();
    f.mitre = vec![LSASS_MEMORY.into()];
    let values = if r.data.is_empty() {
        "-"
    } else {
        r.data.as_str()
    };
    f.details = format!("HKLM\\{} present; values: {values}", r.key);
    f.reason = Some(
        "WER LocalDumps is configured for lsass.exe: Windows writes a full LSASS memory dump \
         (credentials included) on the next crash; a known way to dump LSASS without opening it"
            .into(),
    );
    f.details_client = Some(
        "這台主機被設定成「系統登入程序（LSASS）當機時自動存下完整記憶體」。\
         這個設定一般用不到，攻擊者會利用它取得帳號密碼；請確認是否為除錯需要而設定，\
         否則應移除並檢查是否已有傾印檔產生。"
            .into(),
    );
    f.entity.registry = Some(EntityRegistry {
        hive: r.hive.clone(),
        key: r.key.clone(),
        value: r.value.clone(),
        data: r.data.clone(),
        last_write: r.last_write,
    });
    f
}

fn cmd_finding(c: &CommandLine<'_>, t: DumpTechnique) -> Finding {
    let mut f = Finding::new(
        Severity::High,
        format!("疑似竊取帳密：{}", t.label),
        FindingSource::Heuristic,
    );
    c.apply_to(&mut f);
    f.mitre = vec![t.mitre.into()];
    f.details = format!("{} ({}): {}", c.image, c.artifact, c.cmd);
    f.reason = Some(format!("command line matches {} ({})", t.label, t.mitre));
    f.details_client = Some(format!(
        "這台主機上執行過一個用來取出帳號密碼的指令：{}。這是攻擊者取得管理員密碼、\
         進一步入侵其他電腦的常見步驟；若不是資安人員授權的測試，應視為密碼已外洩，\
         盡速更換相關帳號密碼並調查來源。",
        c.cmd
    ));
    f
}

/// LSASS / SAM / NTDS credential-dump signs (see module docs).
pub struct CredDumpHeuristic;

impl CredDumpHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::CRED_DUMP;
}

impl Analyzer for CredDumpHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        for r in records {
            match r {
                Record::FileListing(fl) => {
                    if let Some((sev, reason)) = judge_file(fl) {
                        out.push(file_finding(fl, sev, reason));
                    }
                }
                Record::RegValue(rv) if is_wer_lsass(rv) => out.push(wer_finding(rv)),
                _ => {}
            }
        }
        for c in command_lines(records) {
            if let Some(t) = dump_technique(&program(&c), &c.normalized()) {
                out.push(cmd_finding(&c, t));
            }
        }
        Ok(crate::stamped(out, Self::NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::ProcessRecord;

    fn proc(cmd: &str) -> Record {
        Record::Process(ProcessRecord {
            pid: 42,
            ppid: 1,
            image: String::new(),
            cmdline: cmd.into(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: Some("bob".into()),
            start_time: None,
            signer_source: None,
        })
    }

    fn file(path: &str, magic: Option<&str>) -> Record {
        Record::FileListing(FileListingRecord {
            path: path.into(),
            size: 48_000_000,
            modified: None,
            magic: magic.map(str::to_string),
            created: None,
        })
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        CredDumpHeuristic.analyze(records, &[]).unwrap()
    }

    #[test]
    fn command_line_techniques() {
        let cases = [
            (
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t\x.dmp full",
                LSASS_MEMORY,
            ),
            ("rundll32 comsvcs.dll #24 624 out.bin full", LSASS_MEMORY),
            (
                "procdump64.exe -accepteula -ma lsass.exe l.dmp",
                LSASS_MEMORY,
            ),
            (
                r#"m.exe "privilege::debug" "sekurlsa::logonpasswords" exit"#,
                LSASS_MEMORY,
            ),
            (r"reg.exe save HKLM\SAM C:\t\sam.save", SAM),
            (
                r#"ntdsutil.exe "ac i ntds" "ifm" "create full c:\t" q q"#,
                NTDS,
            ),
            (
                r"cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\t\",
                NTDS,
            ),
        ];
        for (cmd, mitre) in cases {
            let f = run(&[proc(cmd)]);
            assert_eq!(f.len(), 1, "{cmd}");
            assert_eq!(f[0].severity, Severity::High);
            assert_eq!(f[0].mitre, vec![mitre], "{cmd}");
            assert_eq!(f[0].analyzer, cairn_core::analyzers::CRED_DUMP);
            assert!(f[0].reason.is_some() && f[0].details_client.is_some());
            assert_eq!(f[0].entity.process.as_ref().unwrap().pid, 42);
        }
    }

    #[test]
    fn benign_command_lines_are_quiet() {
        for cmd in [
            r"reg.exe save HKLM\SOFTWARE C:\backup\sw.hiv",
            r"reg query HKLM\SAM",
            "procdump -ma notepad.exe",
            r"C:\Windows\System32\svchost.exe -k netsvcs",
            "ntdsutil snapshot",
        ] {
            assert!(run(&[proc(cmd)]).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn dump_files_by_signature_and_name() {
        let f = run(&[file(r"C:\Users\Public\lsass.dmp", Some("MDMP"))]);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(
            f[0].entity.file.as_ref().unwrap().path,
            r"C:\Users\Public\lsass.dmp"
        );
        let f = run(&[file(r"C:\Windows\Temp\debug.bin", Some("MDMP"))]);
        assert_eq!(f[0].severity, Severity::Medium);
        let f = run(&[file(r"C:\PerfLogs\lsass_1.dmp", Some("0011223344556677"))]);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].reason.as_deref().unwrap().contains("without the MDMP"));
        assert!(run(&[file(r"C:\Users\a\Downloads\setup.zip", Some("PK"))]).is_empty());
        assert!(run(&[file(r"C:\Users\a\Downloads\lsass-notes.zip", Some("PK"))]).is_empty());
    }

    #[test]
    fn wer_localdumps_for_lsass_is_high() {
        let rv = Record::RegValue(RegValueRecord {
            hive: "HKLM".into(),
            key: WER_LSASS_LOCALDUMPS_KEY.into(),
            value: String::new(),
            data: r"DumpFolder=C:\d".into(),
            last_write: None,
            mru_rank: None,
        });
        let f = run(&[rv]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].details.contains(r"DumpFolder=C:\d"));
    }
}
