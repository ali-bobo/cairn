//! EVTX collector: parse Windows .evtx into normalized `EventRecord`s. SRS §4 (FR1).

use cairn_core::record::EventRecord;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::path::Path;

/// Errors from EVTX parsing. Kept local; the orchestrator maps these into the
/// manifest's per-source `errors` (graceful degrade, golden rule 8).
#[derive(Debug, thiserror::Error)]
pub enum EvtxError {
    // Boxed: evtx::err::EvtxError is large; keep the Ok path's Result small.
    #[error("open evtx `{path}`: {source}")]
    Open {
        path: String,
        source: Box<evtx::err::EvtxError>,
    },
}

/// Parse one .evtx file into normalized EventRecords (SRS §4, FR1).
///
/// Streams records from the parser (the `evtx` crate does not load the whole file).
/// A record that fails to deserialize is skipped, not fatal — a single malformed
/// record must not abort the file (threat-model untrusted-input #1). Opening a
/// missing/unreadable file is an error the caller records and continues past.
pub fn parse_evtx(path: &Path) -> Result<Vec<EventRecord>, EvtxError> {
    let mut parser = evtx::EvtxParser::from_path(path).map_err(|source| EvtxError::Open {
        path: path.display().to_string(),
        source: Box::new(source),
    })?;

    let mut out = Vec::new();
    for record in parser.records_json_value() {
        // Skip records that fail to parse rather than aborting the whole file.
        let Ok(rec) = record else { continue };
        let ts = jiff_to_utc(rec.timestamp);
        if let Some(ev) = normalize(&rec.data, rec.event_record_id, ts) {
            out.push(ev);
        }
    }
    Ok(out)
}

/// Convert the `evtx`/`jiff` timestamp to `chrono::DateTime<Utc>` (golden rule 7:
/// all timestamps UTC RFC3339). EVTX FILETIMEs are post-1601 and always valid;
/// fall back to the epoch only if the conversion is somehow out of range.
fn jiff_to_utc(ts: evtx::Timestamp) -> DateTime<Utc> {
    DateTime::from_timestamp(ts.as_second(), ts.subsec_nanosecond().max(0) as u32)
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// Map one EVTX JSON record (`{"Event": {"System": {...}, "EventData": {...}}}`)
/// into an `EventRecord`, flattening System + EventData into `data`.
fn normalize(value: &Value, record_id: u64, ts: DateTime<Utc>) -> Option<EventRecord> {
    let event = value.get("Event")?;
    let system = event.get("System");

    let channel = sys_str(system, "Channel").unwrap_or_default();
    let event_id = sys_event_id(system);
    let provider = system
        .and_then(|s| s.get("Provider"))
        .and_then(|p| p.get("#attributes"))
        .and_then(|a| a.get("Name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let computer = sys_str(system, "Computer").unwrap_or_default();

    // Flatten System + EventData fields into one map (Sigma matches against this).
    let mut data = Map::new();
    for key in ["System", "EventData", "UserData"] {
        if let Some(Value::Object(obj)) = event.get(key) {
            for (k, v) in obj {
                data.insert(k.clone(), v.clone());
            }
        }
    }

    Some(EventRecord {
        ts,
        channel,
        event_id,
        provider,
        computer,
        record_id,
        data,
    })
}

fn sys_str(system: Option<&Value>, key: &str) -> Option<String> {
    system?.get(key)?.as_str().map(str::to_owned)
}

/// EventID may be a number or, when it has qualifiers, an object `{"#text": "1", ...}`.
fn sys_event_id(system: Option<&Value>) -> u32 {
    let Some(eid) = system.and_then(|s| s.get("EventID")) else {
        return 0;
    };
    match eid {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
        Value::String(s) => s.parse().unwrap_or(0),
        Value::Object(o) => o
            .get("#text")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        // Workspace tests/fixtures/, relative to this crate (crates/cairn-collectors).
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    /// A real EVTX fixture parses into one or more EventRecords with the core fields
    /// populated (channel, event_id, record_id, UTC ts) — golden rule 7.
    #[test]
    fn parses_real_evtx_into_event_records() {
        let path = fixture("sysmon_compiledhtml.evtx");
        if !path.exists() {
            eprintln!("skipping: fixture missing (run tests/fetch-fixtures.sh): {path:?}");
            return;
        }
        let records = parse_evtx(&path).expect("should parse a valid evtx");
        assert!(!records.is_empty(), "expected at least one record");

        let first = &records[0];
        assert!(!first.channel.is_empty(), "channel should be set");
        assert!(first.event_id > 0, "event_id should be set");
        assert!(
            !first.data.is_empty(),
            "EventData/System should be flattened"
        );
        // Sysmon operational channel for this corpus.
        assert!(
            records.iter().any(|r| r.channel.contains("Sysmon")),
            "expected a Sysmon channel somewhere in the sample"
        );
    }

    /// Parser completeness (T4 acceptance): our record count matches the count the
    /// `evtx` crate yields for the same file — we don't silently drop valid records.
    #[test]
    fn record_count_matches_evtx_crate() {
        let path = fixture("sysmon_compiledhtml.evtx");
        if !path.exists() {
            eprintln!("skipping: fixture missing: {path:?}");
            return;
        }
        let ours = parse_evtx(&path).unwrap().len();

        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        let theirs = parser.records_json_value().filter(|r| r.is_ok()).count();

        assert_eq!(ours, theirs, "parsed {ours}, evtx crate had {theirs}");
        assert!(ours > 0);
    }

    /// A missing file returns Err, never panics (graceful degrade, golden rule 8).
    #[test]
    fn missing_file_is_err_not_panic() {
        let res = parse_evtx(&fixture("does_not_exist.evtx"));
        assert!(res.is_err());
    }

    /// Malformed input (valid magic, truncated body) must not panic the parser
    /// (threat-model untrusted-input #1). It returns Err or yields zero records.
    #[test]
    fn malformed_evtx_does_not_panic() {
        let dir = std::env::temp_dir().join("cairn_evtx_malformed_test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("truncated.evtx");
        // "ElfFile\0" magic then garbage — looks like EVTX, isn't.
        let mut bytes = b"ElfFile\0".to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        std::fs::write(&p, &bytes).unwrap();

        // Must return (Ok or Err) without panicking.
        let _ = parse_evtx(&p);
    }
}
