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
