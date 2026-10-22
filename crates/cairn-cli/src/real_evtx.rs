//! Real EVTX samples through the offline `cairn evtx` pipeline: the EVTX collector's
//! parser, the event-only analyzer set from the registry and the bundled Sigma rules,
//! exactly as `cairn evtx <files>` runs them ([`crate::evtx::analyze`]).
//!
//! The samples are public attack recordings committed under `tests/fixtures/` (source,
//! license and what each holds: `tests/fixtures/README.md`). Each test names the
//! technique in its sample and asserts the analyzer, severity and ATT&CK technique
//! that must fire, plus the false positives the sample's benign events must not
//! raise. A missing fixture fails the test; nothing is skipped.
//!
//! `cargo test -p cairn-cli real_evtx::print_findings -- --ignored --nocapture` prints
//! every finding per fixture (set `CAIRN_EVTX_DIR` to look at another directory).
use crate::evtx::analyze;
use cairn_core::analyzers::{ACCOUNT, EVENTLOG, LATERAL, LOGON_BRUTEFORCE, SIGMA};
use cairn_core::finding::Severity;
use cairn_core::traits::Analyzer;
use cairn_core::{Config, Finding, Record};
use chrono::Datelike;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fixture(name: &str) -> PathBuf {
    let p = fixtures_dir().join(name);
    assert!(
        p.is_file(),
        "fixture missing: {p:?} (committed; restore with tests/fetch-fixtures.sh)"
    );
    p
}

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma")
}

/// Records and findings of `cairn evtx <name>` with the bundled Sigma rules.
fn run(name: &str) -> (Vec<Record>, Vec<Finding>) {
    let cfg = Config::for_evtx(vec![fixture(name)], Some(rules_dir()));
    let (records, _, analysis) = analyze(&cfg);
    assert!(!records.is_empty(), "{name}: no records parsed");
    assert!(
        analysis.errors.is_empty(),
        "{name}: analyzer errors {:?}",
        analysis.errors
    );
    (records, analysis.findings)
}

fn by<'a>(f: &'a [Finding], analyzer: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.analyzer == analyzer).collect()
}

fn has_technique(f: &Finding, technique: &str) -> bool {
    f.mitre.iter().any(|m| {
        let m = m.trim_start_matches("attack.");
        m.eq_ignore_ascii_case(technique)
    })
}

/// The findings of `analyzer` that carry `technique`, at `severity`.
fn fired<'a>(
    f: &'a [Finding],
    analyzer: &str,
    severity: Severity,
    technique: &str,
) -> Vec<&'a Finding> {
    f.iter()
        .filter(|x| x.analyzer == analyzer && x.severity == severity && has_technique(x, technique))
        .collect()
}

fn titles(f: &[Finding]) -> String {
    f.iter()
        .map(|x| {
            format!(
                "{:?} [{}] {:?} {}",
                x.severity, x.analyzer, x.mitre, x.title
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every heuristic finding explains itself, every Sigma finding names its author.
fn assert_explained(f: &[Finding]) {
    for x in f {
        if x.analyzer == SIGMA {
            assert!(
                x.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
                "sigma finding without rule_author: {}",
                x.title
            );
        } else {
            assert!(
                x.reason.as_deref().is_some_and(|r| !r.is_empty()),
                "heuristic finding without reason: {}",
                x.title
            );
        }
    }
}

/// Before the collector fix every Service Control Manager event parsed as EventID 0
/// (its `Qualifiers` form), so nothing here fired. Now each 7045 does.
#[test]
fn service_installs_with_qualified_event_ids() {
    let (_, f) = run("LM_Remote_Service02_7045.evtx");
    let svc = by(&f, EVENTLOG);
    assert_eq!(svc.len(), 3, "{}", titles(&f));
    assert!(svc.iter().all(|x| x.event_id == Some(7045)));
    // ImagePath cmd.exe: a launcher as the service binary.
    assert_eq!(fired(&f, EVENTLOG, Severity::High, "T1543.003").len(), 2);
    // ImagePath calc.exe (relative, outside the trusted trees).
    assert_eq!(fired(&f, EVENTLOG, Severity::Medium, "T1543.003").len(), 1);
    assert_explained(&f);
}

/// Metasploit psexec on the target: random service, exe in %SYSTEMROOT%, then the
/// getsystem named-pipe service.
#[test]
fn metasploit_psexec_native() {
    let (_, f) = run("metasploit-psexec-native-target-system.evtx");
    assert_eq!(fired(&f, EVENTLOG, Severity::High, "T1070.001").len(), 1);
    // Both services are remote execution for heur_lateral, whose finding absorbs
    // heur_eventlog's service-install finding on the same 7045 (same-evidence rule):
    // one finding per service, with both techniques.
    let remote = fired(&f, LATERAL, Severity::High, "T1569.002");
    assert_eq!(remote.len(), 2, "{}", titles(&f));
    assert!(remote.iter().all(|x| has_technique(x, "T1543.003")));
    assert!(!f
        .iter()
        .any(|x| x.analyzer == EVENTLOG && x.event_id == Some(7045)));
    // %SYSTEMROOT%\duKhLYUX.exe: heur_eventlog rated it Medium (was Low, "Windows
    // tree", before that fix); its reason is kept in the merged finding.
    let root = remote
        .iter()
        .find(|x| x.title.contains("KgXItsbKgTJzdzwl"))
        .unwrap();
    let reason = root.reason.as_deref().unwrap();
    assert!(
        reason.contains("Windows folder") && reason.contains(EVENTLOG),
        "{reason}"
    );
    // cmd.exe /c echo ... > \\.\pipe\...: heur_eventlog's launcher flag, merged.
    let pipe = remote.iter().find(|x| x.title.contains("hgabms")).unwrap();
    assert!(pipe.reason.as_deref().unwrap().contains("launches cmd"));
    // The bundled Sigma rule on 7045 fires too.
    assert!(by(&f, SIGMA)
        .iter()
        .any(|x| x.event_id == Some(7045) && has_technique(x, "t1543.003")));
    assert_explained(&f);
}

/// Metasploit psexec_psh: %COMSPEC% running an encoded PowerShell stager.
#[test]
fn metasploit_psexec_powershell() {
    let (_, f) = run("metasploit-psexec-powershell-target-system.evtx");
    // One finding per service: heur_lateral's, with T1543.003 merged in. The
    // PowerShell stager's heur_eventlog finding is skipped (the High Sigma rule below
    // already says it); the pipe service's is absorbed into heur_lateral's.
    let remote = fired(&f, LATERAL, Severity::High, "T1569.002");
    assert_eq!(remote.len(), 2, "{}", titles(&f));
    assert!(remote.iter().all(|x| has_technique(x, "T1543.003")));
    assert!(!f
        .iter()
        .any(|x| x.analyzer == EVENTLOG && x.event_id == Some(7045)));
    assert!(remote.iter().any(|x| x
        .reason
        .as_deref()
        .unwrap()
        .contains("Suspicious Service Installation")));
    assert!(fired(&f, SIGMA, Severity::High, "t1543.003")
        .iter()
        .any(|x| x.title == "Suspicious Service Installation"));
    assert_explained(&f);
}

/// 294 explicit-credential logons, 41 accounts, one SMB server; TargetServerName is
/// the local name, the server only in IpAddress. Fired nothing before the fix.
#[test]
fn password_spray_over_smb_4648() {
    let (_, f) = run("password-spray.evtx");
    let lat = by(&f, LATERAL);
    assert_eq!(lat.len(), 1, "one grouped finding: {}", titles(&f));
    let x = lat[0];
    assert_eq!(x.severity, Severity::High);
    assert!(has_technique(x, "T1110.003"));
    assert!(x.title.contains("172.16.144.128"), "{}", x.title);
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("41 different accounts"),
        "{:?}",
        x.reason
    );
    assert_explained(&f);
}

/// winlogon / lsass 4648s for this host (localhost, machine-account caller, client
/// address in IpAddress) are noise; the loopback RDP logon is the finding.
#[test]
fn rdp_tunnel_with_local_explicit_credential_noise() {
    let (_, f) = run("DE_RDP_Tunnel_5156.evtx");
    assert!(
        !f.iter()
            .any(|x| x.analyzer == LATERAL && x.event_id == Some(4648)),
        "{}",
        titles(&f)
    );
    let rdp = fired(&f, LATERAL, Severity::High, "T1021.001");
    assert_eq!(rdp.len(), 1, "{}", titles(&f));
    assert!(rdp[0].reason.as_deref().unwrap().contains("tunnel"));
    let (_, f) = run("DE_RDP_Tunneling_4624.evtx");
    assert_eq!(fired(&f, LATERAL, Severity::High, "T1021.001").len(), 1);
}

/// RemoteConnectionManager 1149 from private addresses: UserData EventXML Param1..3.
#[test]
fn rdp_1149_user_and_source_from_user_data() {
    let name = "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx";
    let (_, f) = run(name);
    let rdp = fired(&f, LATERAL, Severity::Low, "T1021.001");
    assert_eq!(rdp.len(), 4, "{}", titles(&f));
    assert!(rdp.iter().all(|x| x.event_id == Some(1149)));
    assert!(rdp
        .iter()
        .any(|x| x.title.contains("10.0.2.15") && x.user.as_deref() == Some(r"example\admin01")));
    // The event time (TimeCreated), not this exported log's later record header
    // (2018-11-06T21:48:54Z for the first 1149).
    let first = rdp
        .iter()
        .find(|x| x.user.as_deref() == Some(r"ie11win7\administrator"))
        .unwrap();
    assert_eq!(first.ts.to_rfc3339(), "2018-11-06T21:45:50.411264+00:00");
}

/// Brute force: 3,558 NTLM failures against Administrator from one address.
#[test]
fn smb_password_guessing_4625() {
    let (_, f) = run("smb-password-guessing-security.evtx");
    let b = by(&f, LOGON_BRUTEFORCE);
    assert_eq!(b.len(), 1, "{}", titles(&f));
    assert_eq!(b[0].severity, Severity::Medium);
    assert!(has_technique(b[0], "T1110.001"));
    assert!(b[0].title.contains("Administrator") && b[0].title.contains("192.168.198.149"));
}

/// Kerberos spray on a DC: 7 failed 4768 (unknown names, 0x6) + 2 failed 4771 (bad
/// password, 0x18), 9 accounts in under a second. The default spraying threshold
/// (10 accounts) is above this small sample, so it is checked at 5; before the fix
/// only the two 4771s counted and even that threshold was not reached.
#[test]
fn kerberos_spray_counts_failed_tgt_requests() {
    let (records, f) = run("kerberos_pwd_spray_4771.evtx");
    assert_eq!(fired(&f, EVENTLOG, Severity::High, "T1070.001").len(), 1);
    let h = cairn_heur::LogonBruteforceHeuristic::new(
        chrono::Duration::minutes(5),
        5,
        chrono::Duration::minutes(1),
        5,
    );
    let spray = h.analyze(&records, &[]).unwrap();
    assert_eq!(spray.len(), 1, "{spray:?}");
    assert!(
        has_technique(&spray[0], "T1110.003"),
        "{:?}",
        spray[0].mitre
    );
    assert!(spray[0].evidence.iter().any(|e| e.detail.contains("4768")));
}

/// Event Log service set to disabled (7040), then the System log cleared (104).
#[test]
fn eventlog_service_disabled_7040() {
    let (_, f) = run("disablestop-eventlog.evtx");
    let off = fired(&f, EVENTLOG, Severity::High, "T1562.002");
    assert_eq!(off.len(), 1, "{}", titles(&f));
    assert_eq!(off[0].event_id, Some(7040));
    assert_eq!(fired(&f, EVENTLOG, Severity::High, "T1070.001").len(), 1);
}

/// WMI-Activity: one CommandLineEventConsumer binding among the stock SCM Event Log
/// consumer, Windows' own temporary subscriptions and 119 provider loads.
#[test]
fn wmi_activity_permanent_consumer_only() {
    let (_, f) = run("wmi-event-filter-persistance.evtx");
    let lat = by(&f, LATERAL);
    assert_eq!(lat.len(), 1, "{}", titles(&f));
    assert_eq!(lat[0].severity, Severity::High);
    assert!(has_technique(lat[0], "T1546.003"));
    assert!(lat[0].title.contains("CommandLineEventConsumer"));
    // Before the fix: a Medium 5860 for LOCAL SERVICE's security-center query, whose
    // NetBIOS ClientMachine (15 chars) differs from the 16-char host name.
    assert!(!f.iter().any(|x| x.event_id == Some(5860)));
}

/// Scheduled task over ATSVC: ADMIN$ / IPC$ share access, then 4698.
#[test]
fn remote_scheduled_task_atsvc() {
    let (_, f) = run("LM_ScheduledTask_ATSVC_target_host.evtx");
    let task = fired(&f, EVENTLOG, Severity::High, "T1053.005");
    assert_eq!(task.len(), 1, "{}", titles(&f));
    assert!(task[0].title.contains("CYAlyNSS"));
    let share = fired(&f, LATERAL, Severity::Medium, "T1021.002");
    assert_eq!(share.len(), 1);
    assert!(share[0].title.contains("10.0.2.17"));
    let (_, f) = run("LM_renamed_psexecsvc_5145.evtx");
    let share = fired(&f, LATERAL, Severity::Medium, "T1021.002");
    assert_eq!(share.len(), 1, "{}", titles(&f));
    assert!(share[0].title.contains("10.0.2.16"));
}

/// sekurlsa::pth on the source machine: 4624 type 9 / seclogo.
#[test]
fn pass_the_hash_newcredentials_logon() {
    let (_, f) = run("LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx");
    let pth = fired(&f, LATERAL, Severity::Low, "T1550.002");
    assert_eq!(pth.len(), 1, "{}", titles(&f));
    assert!(by(&f, SIGMA)
        .iter()
        .any(|x| x.title == "Successful Overpass the Hash Attempt"));
    assert_explained(&f);
}

/// Account created and added to Administrators. The creation is recent relative to
/// the log's own end, so it rates High even though the sample is years old.
#[test]
fn new_local_admin_account() {
    let (_, f) = run("new-user-security.evtx");
    assert_eq!(fired(&f, ACCOUNT, Severity::High, "T1136.001").len(), 1);
    let admin = fired(&f, ACCOUNT, Severity::High, "T1098.007");
    assert_eq!(admin.len(), 1, "{}", titles(&f));
    assert!(admin[0].title.contains("Administrators"));
}

/// Sigma on Security 4662 and Sysmon 1.
#[test]
fn sigma_on_real_security_and_sysmon_events() {
    let (_, f) = run("CA_DCSync_4662.evtx");
    let dcsync = fired(&f, SIGMA, Severity::Critical, "t1003.006");
    assert_eq!(dcsync.len(), 3, "{}", titles(&f));
    let (_, f) = run("sysmon_10_1_memdump_comsvcs_minidump.evtx");
    assert!(fired(&f, SIGMA, Severity::High, "t1003.001")
        .iter()
        .any(|x| x.title == "Process Memory Dump Via Comsvcs.DLL"));
    assert_explained(&f);
}

/// System 104: UserData LogFileCleared, and a zero (1601) record header.
#[test]
fn system_log_cleared_104_keeps_its_event_time() {
    let (_, f) = run("DE_104_system_log_cleared.evtx");
    let c = fired(&f, EVENTLOG, Severity::High, "T1070.001");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].ts.to_rfc3339(), "2019-03-19T23:34:25.894341+00:00");
    assert!(c[0].details.contains("user01"), "{}", c[0].details);
}

/// No finding from any fixture is dated by a zero record header (1601).
#[test]
fn no_fixture_finding_is_dated_1601() {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".evtx"))
        .collect();
    names.sort();
    assert!(
        names.len() >= 3,
        "expected the committed fixtures: {names:?}"
    );
    for n in names {
        let (records, f) = run(&n);
        for r in &records {
            if let Record::Event(e) = r {
                assert!(e.ts.year() >= 2010, "{n}: {e:?}");
            }
        }
        for x in f {
            assert!(x.ts.year() >= 2010, "{n}: {}", x.title);
        }
    }
}

/// Dev aid: print every finding per fixture.
#[test]
#[ignore]
fn print_findings() {
    let dir = std::env::var("CAIRN_EVTX_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixtures_dir());
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "evtx"))
        .collect();
    files.sort();
    for p in files {
        let cfg = Config::for_evtx(vec![p.clone()], Some(rules_dir()));
        let (records, _, a) = analyze(&cfg);
        println!(
            "=== {} ({} records, {} findings)",
            p.display(),
            records.len(),
            a.findings.len()
        );
        println!("{}", titles(&a.findings));
    }
}
