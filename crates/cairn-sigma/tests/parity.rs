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
