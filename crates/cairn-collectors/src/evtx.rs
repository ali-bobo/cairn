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
    let mut out = Vec::new();
    stream_evtx(path, None, |ev| out.push(ev))?;
    Ok(out)
}

/// Per-file counts from [`stream_evtx`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Records handed to the sink.
    pub kept: u64,
    /// Records skipped because their header timestamp is before `since` (never rendered).
    pub skipped_old: u64,
    /// Records (or chunks) that failed to parse and were skipped.
    pub failed: u64,
}

/// Stream one .evtx file, handing each normalized record to `sink`.
///
/// The `since` filter runs first on the record HEADER timestamp, before the record's
/// BinXML is rendered to JSON, so an old record costs no JSON/map allocation at all; a
/// header time that is not plausible (zero / pre-1980, as in exported logs) is not
/// trusted, and such a record is rendered and filtered on its TimeCreated. Memory is
/// bounded per record (plus the `evtx` crate's per-chunk batch), not per file: records
/// are converted one at a time and given to `sink` immediately. A record that fails to
/// parse is counted and skipped (threat-model untrusted-input #1).
pub fn stream_evtx(
    path: &Path,
    since: Option<DateTime<Utc>>,
    mut sink: impl FnMut(EventRecord),
) -> Result<StreamStats, EvtxError> {
    let mut parser = evtx::EvtxParser::from_path(path).map_err(|source| EvtxError::Open {
        path: path.display().to_string(),
        source: Box::new(source),
    })?;
    let mut stats = StreamStats::default();
    let iter = parser.serialized_records(move |record| {
        let record = record?;
        let header_ts = jiff_to_utc(record.timestamp);
        // Cheap pre-filter on the header's written time. Only a plausible header time
        // is trusted: exported / carved logs carry zero (1601) headers whose events
        // can still be recent, and those must be rendered to read TimeCreated.
        if since.is_some_and(|s| header_ts >= plausible_floor() && header_ts < s) {
            return Ok(None); // old: skip before rendering
        }
        let id = record.event_record_id;
        let json = record.into_json_value()?;
        Ok(Some(normalize(&json.data, id, header_ts)))
    });
    for item in iter {
        match item {
            Ok(None) => stats.skipped_old += 1,
            Ok(Some(Some(ev))) if since.is_some_and(|s| ev.ts < s) => stats.skipped_old += 1,
            Ok(Some(Some(ev))) => {
                stats.kept += 1;
                sink(ev);
            }
            Ok(Some(None)) | Err(_) => stats.failed += 1,
        }
    }
    Ok(stats)
}

/// Streaming sha256 of a reader with a fixed 64 KiB buffer: `(lowercase hex, bytes read)`.
/// Used for EVTX source hashes; constant memory whatever the file size.
pub fn sha256_reader<R: std::io::Read>(mut r: R) -> std::io::Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((
        h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        total,
    ))
}

/// [`sha256_reader`] over a file opened read-only. On a LIVE log the file keeps
/// growing: the hash and byte count describe exactly the bytes read by this pass at
/// collection time, not the file as it is later.
pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    sha256_reader(std::fs::File::open(path)?)
}

/// Convert the `evtx`/`jiff` timestamp to `chrono::DateTime<Utc>` (golden rule 7:
/// all timestamps UTC RFC3339). EVTX FILETIMEs are post-1601 and always valid;
/// fall back to the epoch only if the conversion is somehow out of range.
fn jiff_to_utc(ts: evtx::Timestamp) -> DateTime<Utc> {
    DateTime::from_timestamp(ts.as_second(), ts.subsec_nanosecond().max(0) as u32)
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// Header times before this are not a real write time (a zeroed FILETIME renders as
/// 1601-01-01): seen in exported / carved logs such as EVTX-ATTACK-SAMPLES.
fn plausible_floor() -> DateTime<Utc> {
    DateTime::from_timestamp(315_532_800, 0).unwrap_or(DateTime::UNIX_EPOCH) // 1980-01-01
}

/// The event's own creation time, `System/TimeCreated/@SystemTime` (RFC3339 UTC).
fn time_created(system: Option<&Value>) -> Option<DateTime<Utc>> {
    let raw = system?
        .get("TimeCreated")?
        .get("#attributes")?
        .get("SystemTime")?
        .as_str()?;
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Map one EVTX JSON record (`{"Event": {"System": {...}, "EventData": {...}}}`)
/// into an `EventRecord`, flattening System + EventData into `data`.
///
/// `ts` is `System/TimeCreated/@SystemTime`, the time the event happened. The record
/// header's written time (`header_ts`) is only the fallback: real exported logs
/// (EVTX-ATTACK-SAMPLES) carry headers that are zero (1601) or days after the event.
fn normalize(value: &Value, record_id: u64, header_ts: DateTime<Utc>) -> Option<EventRecord> {
    let event = value.get("Event")?;
    let system = event.get("System");
    let ts = time_created(system).unwrap_or(header_ts);

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

/// EventID may be a number or, when it has qualifiers, an object
/// `{"#attributes": {"Qualifiers": 16384}, "#text": 7045}`. The `evtx` crate renders
/// that `#text` as a JSON number (seen on every Service Control Manager event: 7036,
/// 7040, 7045), so a number and a string are both accepted there.
fn sys_event_id(system: Option<&Value>) -> u32 {
    fn scalar(v: &Value) -> Option<u32> {
        match v {
            Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
    let Some(eid) = system.and_then(|s| s.get("EventID")) else {
        return 0;
    };
    match eid {
        Value::Object(o) => o.get("#text").and_then(scalar),
        v => scalar(v),
    }
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        // Workspace tests/fixtures/, relative to this crate (crates/cairn-collectors).
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    /// A committed real EVTX fixture. Missing is a failure, never a silent skip.
    fn fixture(name: &str) -> PathBuf {
        let p = fixture_path(name);
        assert!(
            p.is_file(),
            "fixture missing: {p:?} (committed; restore with tests/fetch-fixtures.sh)"
        );
        p
    }

    /// A real EVTX fixture parses into one or more EventRecords with the core fields
    /// populated (channel, event_id, record_id, UTC ts) — golden rule 7.
    #[test]
    fn parses_real_evtx_into_event_records() {
        let path = fixture("sysmon_compiledhtml.evtx");
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
        let ours = parse_evtx(&path).unwrap().len();

        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        let theirs = parser.records_json_value().filter(|r| r.is_ok()).count();

        assert_eq!(ours, theirs, "parsed {ours}, evtx crate had {theirs}");
        assert!(ours > 0);
    }

    /// The since filter skips old records before rendering and keeps the rest; the
    /// split always adds up to the unfiltered count.
    #[test]
    fn stream_since_filter_partitions_records() {
        let path = fixture("sysmon_compiledhtml.evtx");
        let all = parse_evtx(&path).unwrap();
        let mut ts: Vec<_> = all.iter().map(|e| e.ts).collect();
        ts.sort();
        let cut = ts[ts.len() / 2];
        let mut kept = Vec::new();
        let stats = stream_evtx(&path, Some(cut), |e| kept.push(e)).unwrap();
        assert!(kept.iter().all(|e| e.ts >= cut));
        assert_eq!(stats.kept as usize, kept.len());
        assert_eq!(
            kept.len(),
            all.iter().filter(|e| e.ts >= cut).count(),
            "filter must keep exactly the records at/after since"
        );
        assert_eq!((stats.kept + stats.skipped_old) as usize, all.len());
        // a since in the far future keeps nothing
        let future = chrono::Utc::now() + chrono::Duration::days(3650);
        let s = stream_evtx(&path, Some(future), |_| panic!("nothing expected")).unwrap();
        assert_eq!(s.kept, 0);
    }

    #[test]
    fn sha256_reader_known_vectors_and_length() {
        let (h, n) = sha256_reader(std::io::Cursor::new(b"abc".to_vec())).unwrap();
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(n, 3);
        let big = vec![7u8; 64 * 1024 * 2 + 5];
        let (h2, n2) = sha256_reader(std::io::Cursor::new(big.clone())).unwrap();
        use sha2::{Digest, Sha256};
        let want: String = Sha256::digest(&big)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!((h2, n2), (want, big.len() as u64));
        assert!(sha256_file(&fixture_path("does_not_exist.evtx")).is_err());
    }

    /// Service Control Manager events carry `Qualifiers`, which the `evtx` crate
    /// renders as `{"#attributes": {"Qualifiers": 16384}, "#text": 7045}` with a
    /// NUMBER `#text`. Before the fix every such event came out as EventID 0.
    #[test]
    fn qualified_event_ids_from_real_logs() {
        let recs = parse_evtx(&fixture("LM_Remote_Service02_7045.evtx")).unwrap();
        assert_eq!(recs.len(), 3);
        assert!(recs.iter().all(|r| r.event_id == 7045), "{recs:?}");
        assert_eq!(recs[0].data["ServiceName"], "spoolfool");
        assert_eq!(recs[0].data["ImagePath"], "cmd.exe");
        let recs = parse_evtx(&fixture("metasploit-psexec-native-target-system.evtx")).unwrap();
        let ids: Vec<u32> = recs.iter().map(|r| r.event_id).collect();
        assert_eq!(ids, vec![104, 7045, 7036, 7036, 7036, 7045, 7009]);
        // 7036 as Windows writes it: param1 service, param2 state, Binary key name.
        let r7036 = &recs[2];
        assert_eq!(r7036.data["param1"], "KgXItsbKgTJzdzwl");
        assert_eq!(r7036.data["param2"], "running");
        assert!(r7036.data["Binary"]
            .as_str()
            .unwrap()
            .ends_with("2F0034000000"));
    }

    #[test]
    fn event_id_shapes() {
        let ev = |eid: Value| serde_json::json!({"Event": {"System": {"EventID": eid, "Channel": "System"}}});
        let ts = DateTime::UNIX_EPOCH;
        for (shape, want) in [
            (serde_json::json!(4624), 4624),
            (serde_json::json!("4624"), 4624),
            (
                serde_json::json!({"#attributes": {"Qualifiers": 16384}, "#text": 7045}),
                7045,
            ),
            (
                serde_json::json!({"#attributes": {"Qualifiers": 0}, "#text": "7036"}),
                7036,
            ),
            (serde_json::json!({"#text": null}), 0),
            (serde_json::json!(-1), 0),
        ] {
            let r = normalize(&ev(shape.clone()), 1, ts).unwrap();
            assert_eq!(r.event_id, want, "{shape}");
        }
    }

    /// `ts` is TimeCreated. Exported logs carry zero (1601) record headers and headers
    /// written days after the event; neither may become the event time.
    #[test]
    fn timestamps_come_from_time_created_not_the_record_header() {
        let recs = parse_evtx(&fixture("DE_104_system_log_cleared.evtx")).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0]
                .ts
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "2019-03-19T23:34:25.894341Z"
        );
        let rcm = "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx";
        let recs = parse_evtx(&fixture(rcm)).unwrap();
        let r = recs.iter().find(|r| r.record_id == 9).unwrap();
        // The record header says 2018-11-22; the event happened on 2018-11-06.
        assert_eq!(
            r.ts.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "2018-11-06T21:49:31.193924Z"
        );
        // A zero header never pre-filters a record that is inside the window.
        let since = "2019-03-01T00:00:00Z".parse().unwrap();
        let mut kept = Vec::new();
        let p = fixture("DE_104_system_log_cleared.evtx");
        let stats = stream_evtx(&p, Some(since), |e| kept.push(e)).unwrap();
        assert_eq!((stats.kept, kept.len()), (1, 1));
        let late = "2019-03-20T00:00:00Z".parse().unwrap();
        let stats = stream_evtx(&p, Some(late), |_| panic!("before since")).unwrap();
        assert_eq!((stats.kept, stats.skipped_old), (0, 1));
    }

    /// `UserData` payloads stay one object level below `data`, as the analyzers'
    /// `event_field` lookups expect (real 1149: `EventXML.Param1..3`).
    #[test]
    fn user_data_payload_is_nested_one_level() {
        let rcm = "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx";
        let recs = parse_evtx(&fixture(rcm)).unwrap();
        let r = recs.iter().find(|r| r.event_id == 1149).unwrap();
        let xml = r.data["EventXML"].as_object().unwrap();
        assert_eq!(xml["Param1"], "administrator");
        assert_eq!(xml["Param2"], "ie11win7");
        assert_eq!(xml["Param3"], "10.0.2.16");
        let recs = parse_evtx(&fixture("DE_104_system_log_cleared.evtx")).unwrap();
        assert_eq!(recs[0].data["LogFileCleared"]["SubjectUserName"], "user01");
    }

    /// A missing file returns Err, never panics (graceful degrade, golden rule 8).
    #[test]
    fn missing_file_is_err_not_panic() {
        let res = parse_evtx(&fixture_path("does_not_exist.evtx"));
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
