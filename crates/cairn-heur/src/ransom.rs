//! Ransomware precursors (ATT&CK T1490 Inhibit System Recovery): before encrypting,
//! ransomware deletes the shadow copies and backups and turns off Windows recovery.
//!
//! - **Command lines** (live processes and Security 4688): `vssadmin delete shadows` /
//!   `resize shadowstorage`, `wmic shadowcopy delete`, PowerShell / WMI deletion of
//!   `Win32_ShadowCopy`, `wbadmin delete catalog|systemstatebackup|backup`, and
//!   `bcdedit` turning off recovery or ignoring boot failures. High.
//! - **No shadow copies** (`dropscan` [`ShadowCopyRecord`]): a client edition with
//!   System Restore on but zero shadow copies. Medium: a new install or a cleanup tool
//!   also leaves zero, so the reason says so. Raised only when all three facts were
//!   read; any unknown leaves it silent.
#![forbid(unsafe_code)]

use cairn_core::finding::{FindingSource, Severity};
use cairn_core::record::{Record, ShadowCopyRecord};
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};

use crate::cmdline::{command_lines, program, CommandLine};

const INHIBIT_RECOVERY: &str = "T1490";

/// What a command line does to recovery, if anything. `prog` is the
/// [`crate::trust::exe_name`] of the program, `cmd` the normalized command line.
pub fn recovery_action(prog: &str, cmd: &str) -> Option<&'static str> {
    let has = |s: &str| cmd.contains(s);
    let runs = |exe: &str| prog == exe || has(&format!("{exe}.exe ")) || has(&format!("{exe} "));
    if runs("vssadmin") && has("delete shadows") {
        return Some("vssadmin delete shadows");
    }
    if runs("vssadmin") && has("resize shadowstorage") {
        return Some("vssadmin resize shadowstorage (shrinking it deletes shadow copies)");
    }
    if runs("wmic") && has("shadowcopy") && has("delete") {
        return Some("wmic shadowcopy delete");
    }
    if has("win32_shadowcopy")
        && ["delete", "remove-wmiobject", "remove-ciminstance"]
            .iter()
            .any(|v| has(v))
    {
        return Some("Win32_ShadowCopy deleted through WMI / PowerShell");
    }
    if runs("wbadmin")
        && has("delete")
        && ["catalog", "systemstatebackup", "backup"]
            .iter()
            .any(|v| has(v))
    {
        return Some("wbadmin deletes the backup catalog / backups");
    }
    if runs("bcdedit") && (has("recoveryenabled no") || has("recoveryenabled off")) {
        return Some("bcdedit turns off Windows recovery");
    }
    if runs("bcdedit") && has("bootstatuspolicy") && has("ignoreallfailures") {
        return Some("bcdedit ignores boot failures (no recovery screen)");
    }
    None
}

fn cmd_finding(c: &CommandLine<'_>, action: &str) -> Finding {
    let mut f = Finding::new(
        Severity::High,
        format!("疑似勒索前置動作：{action}"),
        FindingSource::Heuristic,
    );
    c.apply_to(&mut f);
    f.mitre = vec![INHIBIT_RECOVERY.into()];
    f.details = format!("{} ({}): {}", c.image, c.artifact, c.cmd);
    f.reason = Some(format!(
        "command line removes recovery options: {action}; ransomware does this right before encrypting"
    ));
    f.details_client = Some(format!(
        "這台主機上執行過刪除系統還原點或備份的指令：{}。勒索軟體在加密檔案前通常會先這麼做，\
         讓受害者無法自行還原；若不是 IT 人員的已知維護作業，請立即隔離這台主機並確認備份是否完好。",
        c.cmd
    ));
    f
}

/// True when the host is a client with System Restore on and zero shadow copies.
pub fn no_shadow_copies(s: &ShadowCopyRecord) -> bool {
    s.client_os == Some(true) && s.system_restore_enabled == Some(true) && s.count == Some(0)
}

fn shadow_finding(deletions: usize) -> Finding {
    let mut f = Finding::new(
        Severity::Medium,
        "系統還原已開啟但沒有任何還原點",
        FindingSource::Heuristic,
    );
    f.artifact = "wmi:Win32_ShadowCopy".into();
    f.mitre = vec![INHIBIT_RECOVERY.into()];
    f.details = "client edition, System Restore enabled, Win32_ShadowCopy count = 0".into();
    let corroboration = if deletions > 0 {
        format!("; {deletions} shadow-copy / backup deletion command(s) were also seen this run")
    } else {
        "; a fresh install or a disk-cleanup tool also leaves zero, so confirm with the user".into()
    };
    f.reason = Some(format!(
        "System Restore is on for this workstation but it holds no shadow copies; ransomware \
         deletes them before encrypting{corroboration}"
    ));
    f.details_client = Some(
        "這台電腦開啟了系統還原功能，卻一個還原點都沒有。勒索軟體常在加密前刪光還原點；\
         也可能是剛重灌或使用了清理工具。請詢問使用者近期是否做過這些事，\
         並確認重要資料有其他備份。"
            .into(),
    );
    f
}

/// Shadow-copy / backup deletion and missing restore points (see module docs).
pub struct RansomHeuristic;

impl RansomHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::RANSOM;
}

impl Analyzer for RansomHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior: &[Finding]) -> Result<Vec<Finding>> {
        let mut out: Vec<Finding> = command_lines(records)
            .iter()
            .filter_map(|c| {
                recovery_action(&program(c), &c.normalized()).map(|a| cmd_finding(c, a))
            })
            .collect();
        let deletions = out.len();
        if records
            .iter()
            .any(|r| matches!(r, Record::ShadowCopies(s) if no_shadow_copies(s)))
        {
            out.push(shadow_finding(deletions));
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
            pid: 7,
            ppid: 1,
            image: String::new(),
            cmdline: cmd.into(),
            signed: None,
            signer: None,
            binary_sha256: None,
            integrity: None,
            user: None,
            start_time: None,
            signer_source: None,
        })
    }

    fn shadows(count: Option<u32>, client: Option<bool>, sr: Option<bool>) -> Record {
        Record::ShadowCopies(ShadowCopyRecord {
            count,
            client_os: client,
            system_restore_enabled: sr,
        })
    }

    fn run(records: &[Record]) -> Vec<Finding> {
        RansomHeuristic.analyze(records, &[]).unwrap()
    }

    #[test]
    fn recovery_inhibition_commands_are_high() {
        for cmd in [
            "vssadmin.exe Delete Shadows /All /Quiet",
            r"C:\Windows\System32\vssadmin.exe resize shadowstorage /for=c: /on=c: /maxsize=401MB",
            "wmic shadowcopy delete /nointeractive",
            "powershell -c \"Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }\"",
            "wbadmin delete catalog -quiet",
            "wbadmin DELETE SYSTEMSTATEBACKUP",
            "bcdedit /set {default} recoveryenabled No",
            "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
            "cmd.exe /c vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no",
        ] {
            let f = run(&[proc(cmd)]);
            assert_eq!(f.len(), 1, "{cmd}");
            assert_eq!(f[0].severity, Severity::High);
            assert_eq!(f[0].mitre, vec!["T1490"]);
            assert_eq!(f[0].analyzer, cairn_core::analyzers::RANSOM);
            assert!(f[0].reason.is_some());
        }
    }

    #[test]
    fn benign_commands_are_quiet() {
        for cmd in [
            "vssadmin list shadows",
            "vssadmin create shadow /for=C:",
            "wmic shadowcopy list brief",
            "wbadmin get versions",
            "bcdedit /enum",
            "bcdedit /set {default} recoveryenabled yes",
        ] {
            assert!(run(&[proc(cmd)]).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn zero_shadow_copies_on_a_protected_client_is_medium() {
        let f = run(&[shadows(Some(0), Some(true), Some(true))]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].reason.as_deref().unwrap().contains("fresh install"));
        let f = run(&[
            shadows(Some(0), Some(true), Some(true)),
            proc("vssadmin delete shadows /all"),
        ]);
        assert_eq!(f.len(), 2);
        assert!(f[1].reason.as_deref().unwrap().contains("1 shadow-copy"));
    }

    #[test]
    fn unknown_or_other_shadow_states_are_quiet() {
        for r in [
            shadows(None, Some(true), Some(true)),
            shadows(Some(0), None, Some(true)),
            shadows(Some(0), Some(false), Some(true)),
            shadows(Some(0), Some(true), Some(false)),
            shadows(Some(0), Some(true), None),
            shadows(Some(3), Some(true), Some(true)),
        ] {
            assert!(run(&[r]).is_empty());
        }
    }
}
