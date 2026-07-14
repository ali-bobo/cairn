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
        hits.iter().all(|h| h.rule_author.as_deref().is_some_and(|a| !a.is_empty())),
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
        hits.iter().all(|h| h.rule_author.as_deref().is_some_and(|a| !a.is_empty())),
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
