//! Remote-access tools' own log files (part of the `dropscan` collector).
//!
//! Read-only. For every well-known self-log that exists ([`candidates`]), one
//! [`RmmLogRecord`] with its size and last-write time. Two formats are simple text and
//! are parsed for incoming connections inside the `--since` window:
//!
//! - AnyDesk `connection_trace.txt` (`%ProgramData%\AnyDesk\` for the installed
//!   service, `%APPDATA%\AnyDesk\` for a per-user or portable copy): one line per
//!   incoming connection, `Incoming  2024-03-01, 10:15  User  123456789  123456789`
//!   (direction, date, time, authentication type, remote ID, ...).
//! - TeamViewer `Connections_incoming.txt` (in the TeamViewer program folder):
//!   tab-separated `remote ID, remote name, start (dd-mm-yyyy HH:MM:SS), end, local
//!   user, connection type, session GUID`.
//!
//! Both formats come from published DFIR write-ups, not from vendor documentation, and
//! their timestamps are read as UTC; a line that does not parse is skipped. Only the
//! last [`MAX_TAIL_BYTES`] of a file are read and at most [`MAX_ENTRIES`] connections
//! (the newest) are kept per file; hitting either cap sets `truncated`. The other
//! logs (AnyDesk `ad.trace` / `ad_svc.trace`, TeamViewer `TeamViewer*_Logfile*.log`,
//! `*.log` in a ScreenConnect / ConnectWise Control client folder) are listed by
//! metadata only.

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{RmmConnection, RmmLogKind, RmmLogRecord};
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// Bytes read from the end of a parsed log.
pub const MAX_TAIL_BYTES: u64 = 2 * 1024 * 1024;
/// Incoming connections kept per log (the newest).
pub const MAX_ENTRIES: usize = 500;
/// Matching files listed per scanned folder.
const MAX_FILES_PER_DIR: usize = 50;
/// `SourceEntry.method` of a parsed log / a metadata-only log.
pub const PARSED_METHOD: &str = "fs:metadata+text_tail";
pub const METADATA_METHOD: &str = "fs:metadata";

/// Where to look: fixed files, and folders whose matching files are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    File(RmmLogKind, String),
    /// Files directly in the folder whose lowercase name starts with `prefix` and
    /// ends with `suffix`.
    Dir {
        kind: RmmLogKind,
        dir: String,
        prefix: &'static str,
        suffix: &'static str,
    },
    /// Subfolders of `parent` whose lowercase name starts with one of `prefixes`,
    /// each listed like [`Candidate::Dir`].
    Subdirs {
        kind: RmmLogKind,
        parent: String,
        prefixes: &'static [&'static str],
        suffix: &'static str,
    },
}

const SCREENCONNECT_DIRS: &[&str] = &["screenconnect client (", "connectwise control client ("];

/// Every self-log location for these profile folders and environment
/// (`ProgramData` / `ProgramFiles` / `ProgramFiles(x86)` fall back to `C:` defaults).
pub fn candidates(env: impl Fn(&str) -> Option<String>, homes: &[String]) -> Vec<Candidate> {
    let trim = |s: String| s.trim_end_matches(['\\', '/']).to_string();
    let drive = env("SystemDrive").map(trim).unwrap_or_else(|| "C:".into());
    let pd = env("ProgramData")
        .map(trim)
        .unwrap_or_else(|| format!(r"{drive}\ProgramData"));
    let pf = env("ProgramFiles")
        .map(trim)
        .unwrap_or_else(|| format!(r"{drive}\Program Files"));
    let pf86 = env("ProgramFiles(x86)")
        .map(trim)
        .unwrap_or_else(|| format!(r"{drive}\Program Files (x86)"));
    let mut out = Vec::new();
    let anydesk = |out: &mut Vec<Candidate>, dir: &str| {
        for name in ["ad.trace", "ad_svc.trace"] {
            out.push(Candidate::File(
                RmmLogKind::AnyDeskTrace,
                format!(r"{dir}\{name}"),
            ));
        }
        out.push(Candidate::File(
            RmmLogKind::AnyDeskConnectionTrace,
            format!(r"{dir}\connection_trace.txt"),
        ));
    };
    anydesk(&mut out, &format!(r"{pd}\AnyDesk"));
    for home in homes {
        let home = home.trim_end_matches(['\\', '/']);
        anydesk(&mut out, &format!(r"{home}\AppData\Roaming\AnyDesk"));
        out.push(Candidate::Dir {
            kind: RmmLogKind::TeamViewerLogfile,
            dir: format!(r"{home}\AppData\Roaming\TeamViewer"),
            prefix: "teamviewer",
            suffix: ".log",
        });
    }
    for root in [&pf, &pf86] {
        let tv = format!(r"{root}\TeamViewer");
        out.push(Candidate::File(
            RmmLogKind::TeamViewerIncoming,
            format!(r"{tv}\Connections_incoming.txt"),
        ));
        out.push(Candidate::Dir {
            kind: RmmLogKind::TeamViewerLogfile,
            dir: tv,
            prefix: "teamviewer",
            suffix: ".log",
        });
    }
    for parent in [&pf, &pf86, &pd] {
        out.push(Candidate::Subdirs {
            kind: RmmLogKind::ScreenConnectLog,
            parent: parent.clone(),
            prefixes: SCREENCONNECT_DIRS,
            suffix: ".log",
        });
    }
    out
}

/// One AnyDesk `connection_trace.txt` line, if it is an incoming connection.
pub fn parse_anydesk_line(line: &str) -> Option<RmmConnection> {
    let toks: Vec<&str> = line
        .split_whitespace()
        .map(|t| t.trim_matches('"'))
        .filter(|t| !t.is_empty())
        .collect();
    if toks.len() < 5 || !toks[0].eq_ignore_ascii_case("incoming") {
        return None;
    }
    let date = NaiveDate::parse_from_str(toks[1].trim_end_matches(','), "%Y-%m-%d").ok()?;
    let time = NaiveTime::parse_from_str(toks[2], "%H:%M")
        .or_else(|_| NaiveTime::parse_from_str(toks[2], "%H:%M:%S"))
        .ok()?;
    let remote_id = toks[4];
    if !remote_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '@' || c == '.')
    {
        return None;
    }
    Some(RmmConnection {
        ts: date.and_time(time).and_utc(),
        remote_id: remote_id.to_string(),
        remote_name: None,
        user: None,
        detail: Some(toks[3].to_string()),
    })
}

/// One TeamViewer `Connections_incoming.txt` line.
pub fn parse_teamviewer_line(line: &str) -> Option<RmmConnection> {
    let cols: Vec<&str> = line.split('\t').map(str::trim).collect();
    if cols.len() < 3 {
        return None;
    }
    let remote_id: String = cols[0].chars().filter(|c| !c.is_whitespace()).collect();
    if remote_id.is_empty() || !remote_id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let ts = NaiveDateTime::parse_from_str(cols[2], "%d-%m-%Y %H:%M:%S")
        .ok()?
        .and_utc();
    let opt = |i: usize| cols.get(i).map(|s| s.to_string()).filter(|s| !s.is_empty());
    Some(RmmConnection {
        ts,
        remote_id,
        remote_name: opt(1),
        user: opt(4),
        detail: opt(5),
    })
}

/// What a bounded tail read of one log produced.
#[derive(Debug, Default)]
pub struct Parsed {
    pub incoming: Vec<RmmConnection>,
    pub truncated: bool,
}

/// Keep `c` if it is inside the window, dropping the oldest past [`MAX_ENTRIES`].
fn keep(
    c: Option<RmmConnection>,
    since: DateTime<Utc>,
    out: &mut VecDeque<RmmConnection>,
    truncated: &mut bool,
) {
    if let Some(c) = c.filter(|c| c.ts >= since) {
        out.push_back(c);
        if out.len() > MAX_ENTRIES {
            out.pop_front();
            *truncated = true;
        }
    }
}

/// Stream the last `max_bytes` of a log line by line through `parse`. UTF-16LE (with a
/// BOM) is decoded; anything else is read as UTF-8, invalid bytes replaced.
pub fn parse_tail(
    path: &Path,
    since: DateTime<Utc>,
    max_bytes: u64,
    parse: fn(&str) -> Option<RmmConnection>,
) -> std::io::Result<Parsed> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut bom = [0u8; 2];
    let n = f.read(&mut bom)?;
    let utf16 = n == 2 && bom == [0xFF, 0xFE];
    let mut start = len.saturating_sub(max_bytes);
    if utf16 {
        // Skip the BOM and stay on a code-unit boundary.
        start = start.max(2);
        start += start % 2;
    }
    f.seek(SeekFrom::Start(start))?;
    let mut truncated = start > if utf16 { 2 } else { 0 };
    let mut out: VecDeque<RmmConnection> = VecDeque::new();
    // After a seek into the middle, the first line is partial.
    let mut skip_partial = truncated;
    let mut reader = BufReader::new(f.take(max_bytes));
    if utf16 {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&units);
        for line in text.lines() {
            if std::mem::take(&mut skip_partial) {
                continue;
            }
            keep(parse(line), since, &mut out, &mut truncated);
        }
    } else {
        for line in reader.split(b'\n') {
            let line = line?;
            if std::mem::take(&mut skip_partial) {
                continue;
            }
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_start_matches('\u{feff}').trim_end_matches('\r');
            keep(parse(text), since, &mut out, &mut truncated);
        }
    }
    Ok(Parsed {
        incoming: out.into(),
        truncated,
    })
}

fn parser(kind: RmmLogKind) -> Option<fn(&str) -> Option<RmmConnection>> {
    match kind {
        RmmLogKind::AnyDeskConnectionTrace => Some(parse_anydesk_line),
        RmmLogKind::TeamViewerIncoming => Some(parse_teamviewer_line),
        _ => None,
    }
}

/// The record for one existing log file, with its manifest entry.
pub fn read_log(
    kind: RmmLogKind,
    path: &Path,
    since: DateTime<Utc>,
) -> Option<(RmmLogRecord, SourceEntry)> {
    let meta = std::fs::metadata(path).ok().filter(|m| m.is_file())?;
    let mut rec = RmmLogRecord {
        log_kind: kind,
        path: path.display().to_string(),
        size: meta.len(),
        modified: meta.modified().ok().map(DateTime::<Utc>::from),
        incoming: Vec::new(),
        truncated: false,
    };
    let mut errors = Vec::new();
    let method = match parser(kind) {
        Some(parse) => {
            match parse_tail(path, since, MAX_TAIL_BYTES, parse) {
                Ok(p) => {
                    rec.incoming = p.incoming;
                    rec.truncated = p.truncated;
                    if p.truncated {
                        errors.push(format!(
                            "read capped at the last {MAX_TAIL_BYTES} bytes / {MAX_ENTRIES} entries"
                        ));
                    }
                }
                Err(e) => errors.push(format!("read failed: {e}")),
            }
            PARSED_METHOD
        }
        None => METADATA_METHOD,
    };
    let src = SourceEntry {
        collector: String::new(),
        artifact: "dropscan:rmm_log".into(),
        path: rec.path.clone(),
        method: method.into(),
        size: rec.size,
        sha256: String::new(),
        errors,
    };
    Some((rec, src))
}

/// Files directly in `dir` matching `prefix` / `suffix` (lowercase name), sorted,
/// at most [`MAX_FILES_PER_DIR`]. Symbolic links are not followed.
fn matching_files(dir: &Path, prefix: &str, suffix: &str) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<_> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            n.starts_with(prefix) && n.ends_with(suffix)
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out.truncate(MAX_FILES_PER_DIR);
    out
}

/// Read every candidate that exists (duplicates by path, any case, read once).
pub fn collect(
    cands: &[Candidate],
    since: DateTime<Utc>,
    sources: &mut Vec<SourceEntry>,
) -> Vec<RmmLogRecord> {
    let mut files: Vec<(RmmLogKind, std::path::PathBuf)> = Vec::new();
    for c in cands {
        match c {
            Candidate::File(kind, p) => files.push((*kind, p.into())),
            Candidate::Dir {
                kind,
                dir,
                prefix,
                suffix,
            } => files.extend(
                matching_files(Path::new(dir), prefix, suffix)
                    .into_iter()
                    .map(|p| (*kind, p)),
            ),
            Candidate::Subdirs {
                kind,
                parent,
                prefixes,
                suffix,
            } => {
                let Ok(entries) = std::fs::read_dir(parent) else {
                    continue;
                };
                let mut dirs: Vec<_> = entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter(|e| {
                        let n = e.file_name().to_string_lossy().to_ascii_lowercase();
                        prefixes.iter().any(|p| n.starts_with(p))
                    })
                    .map(|e| e.path())
                    .collect();
                dirs.sort();
                for d in dirs {
                    files.extend(
                        matching_files(&d, "", suffix)
                            .into_iter()
                            .map(|p| (*kind, p)),
                    );
                }
            }
        }
    }
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for (kind, path) in files {
        let key = path.display().to_string().to_ascii_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if let Some((rec, src)) = read_log(kind, &path, since) {
            out.push(rec);
            sources.push(src);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_rmm_logs_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    #[test]
    fn anydesk_connection_trace_lines() {
        let c =
            parse_anydesk_line("Incoming    2024-03-01, 10:15    User    123456789    987654321")
                .unwrap();
        assert_eq!(c.ts, at(2024, 3, 1, 10, 15, 0));
        assert_eq!(c.remote_id, "123456789");
        assert_eq!(c.detail.as_deref(), Some("User"));
        let c = parse_anydesk_line(
            "\"Incoming\"\t\"2024-03-01, 10:15:30\"\t\"Passwd\"\t\"55\"\t\"55\"",
        )
        .unwrap();
        assert_eq!(c.ts, at(2024, 3, 1, 10, 15, 30));
        assert_eq!(c.detail.as_deref(), Some("Passwd"));
        for bad in [
            "",
            "Outgoing 2024-03-01, 10:15 User 1 2",
            "Incoming 01/03/2024 10:15 User 1 2",
            "Incoming 2024-03-01, 10:15 User",
        ] {
            assert!(parse_anydesk_line(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn teamviewer_incoming_lines() {
        let c = parse_teamviewer_line(
            "123456789\tHELPDESK-PC\t14-03-2024 10:15:42\t14-03-2024 10:45:10\tbob\tRemoteControl\t{1e2d}",
        )
        .unwrap();
        assert_eq!(c.ts, at(2024, 3, 14, 10, 15, 42));
        assert_eq!(c.remote_id, "123456789");
        assert_eq!(c.remote_name.as_deref(), Some("HELPDESK-PC"));
        assert_eq!(c.user.as_deref(), Some("bob"));
        assert_eq!(c.detail.as_deref(), Some("RemoteControl"));
        assert_eq!(
            parse_teamviewer_line("1 234 567 890\tX\t01-02-2024 00:00:01")
                .unwrap()
                .remote_id,
            "1234567890"
        );
        for bad in [
            "",
            "header line",
            "abc\tX\t14-03-2024 10:15:42",
            "1\tX\t2024-03-14 10:15",
        ] {
            assert!(parse_teamviewer_line(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn tail_parse_filters_by_since_and_caps() {
        let d = tmp("since");
        let p = d.join("connection_trace.txt");
        std::fs::write(
            &p,
            "Incoming 2024-01-01, 08:00 User 111 111\r\n\
             garbage\r\n\
             Incoming 2024-03-01, 10:15 User 222 222\r\n\
             Incoming 2024-03-02, 11:00 Token 333 333\r\n",
        )
        .unwrap();
        let since = at(2024, 2, 1, 0, 0, 0);
        let r = parse_tail(&p, since, MAX_TAIL_BYTES, parse_anydesk_line).unwrap();
        let ids: Vec<&str> = r.incoming.iter().map(|c| c.remote_id.as_str()).collect();
        assert_eq!(ids, vec!["222", "333"]);
        assert!(!r.truncated);
        // A small byte cap reads only the tail and drops the partial first line.
        let r = parse_tail(&p, DateTime::UNIX_EPOCH, 50, parse_anydesk_line).unwrap();
        let ids: Vec<&str> = r.incoming.iter().map(|c| c.remote_id.as_str()).collect();
        assert_eq!(ids, vec!["333"]);
        assert!(r.truncated);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tail_parse_keeps_the_newest_entries() {
        let d = tmp("entries");
        let p = d.join("Connections_incoming.txt");
        let mut text = String::new();
        for i in 0..(MAX_ENTRIES + 3) {
            let m = i % 60;
            let h = (i / 60) % 24;
            text.push_str(&format!(
                "{}\tPC\t01-03-2024 {h:02}:{m:02}:00\t01-03-2024 {h:02}:{m:02}:30\tbob\tRemoteControl\t{{g}}\n",
                100 + i
            ));
        }
        std::fs::write(&p, text).unwrap();
        let r = parse_tail(
            &p,
            DateTime::UNIX_EPOCH,
            MAX_TAIL_BYTES,
            parse_teamviewer_line,
        )
        .unwrap();
        assert_eq!(r.incoming.len(), MAX_ENTRIES);
        assert!(r.truncated);
        assert_eq!(r.incoming[0].remote_id, "103");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn utf16_logs_are_decoded() {
        let d = tmp("utf16");
        let p = d.join("Connections_incoming.txt");
        let line = "123\tPC\t01-03-2024 10:00:00\t01-03-2024 10:05:00\tbob\tRemoteControl\t{g}\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        for u in line.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&p, bytes).unwrap();
        let r = parse_tail(
            &p,
            DateTime::UNIX_EPOCH,
            MAX_TAIL_BYTES,
            parse_teamviewer_line,
        )
        .unwrap();
        assert_eq!(r.incoming.len(), 1);
        assert_eq!(r.incoming[0].user.as_deref(), Some("bob"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn candidates_cover_programdata_profiles_and_program_files() {
        let env = |v: &str| match v {
            "ProgramData" => Some(r"D:\PD".to_string()),
            _ => None,
        };
        let c = candidates(env, &[r"C:\Users\alice".to_string()]);
        let files: Vec<&str> = c
            .iter()
            .filter_map(|c| match c {
                Candidate::File(_, p) => Some(p.as_str()),
                _ => None,
            })
            .collect();
        for want in [
            r"D:\PD\AnyDesk\connection_trace.txt",
            r"D:\PD\AnyDesk\ad_svc.trace",
            r"C:\Users\alice\AppData\Roaming\AnyDesk\ad.trace",
            r"C:\Users\alice\AppData\Roaming\AnyDesk\connection_trace.txt",
            r"C:\Program Files\TeamViewer\Connections_incoming.txt",
            r"C:\Program Files (x86)\TeamViewer\Connections_incoming.txt",
        ] {
            assert!(files.contains(&want), "{want} missing: {files:?}");
        }
        assert!(c.iter().any(|c| matches!(c,
            Candidate::Subdirs { kind: RmmLogKind::ScreenConnectLog, parent, .. } if parent == r"C:\Program Files (x86)")));
    }

    #[test]
    fn collect_lists_existing_logs_with_sources() {
        let d = tmp("collect");
        let tv = d.join("TeamViewer");
        let sc = d.join("ScreenConnect Client (abc123)");
        std::fs::create_dir_all(&tv).unwrap();
        std::fs::create_dir_all(&sc).unwrap();
        std::fs::write(
            tv.join("Connections_incoming.txt"),
            "123\tPC\t01-03-2024 10:00:00\t01-03-2024 10:05:00\tbob\tRemoteControl\t{g}\n",
        )
        .unwrap();
        std::fs::write(tv.join("TeamViewer15_Logfile.log"), "x").unwrap();
        std::fs::write(tv.join("notes.txt"), "x").unwrap();
        std::fs::write(sc.join("client.log"), "x").unwrap();
        let root = d.display().to_string();
        let cands = vec![
            Candidate::File(
                RmmLogKind::TeamViewerIncoming,
                format!(r"{}/TeamViewer/Connections_incoming.txt", root),
            ),
            Candidate::File(
                RmmLogKind::AnyDeskConnectionTrace,
                format!("{root}/nope.txt"),
            ),
            Candidate::Dir {
                kind: RmmLogKind::TeamViewerLogfile,
                dir: tv.display().to_string(),
                prefix: "teamviewer",
                suffix: ".log",
            },
            Candidate::Subdirs {
                kind: RmmLogKind::ScreenConnectLog,
                parent: root.clone(),
                prefixes: SCREENCONNECT_DIRS,
                suffix: ".log",
            },
        ];
        let mut sources = Vec::new();
        let recs = collect(&cands, DateTime::UNIX_EPOCH, &mut sources);
        let _ = std::fs::remove_dir_all(&d);
        let kinds: Vec<RmmLogKind> = recs.iter().map(|r| r.log_kind).collect();
        assert_eq!(
            kinds,
            vec![
                RmmLogKind::TeamViewerIncoming,
                RmmLogKind::TeamViewerLogfile,
                RmmLogKind::ScreenConnectLog
            ]
        );
        assert_eq!(recs[0].incoming.len(), 1);
        assert!(recs[1].incoming.is_empty());
        assert_eq!(sources.len(), 3);
        assert_eq!(sources[0].method, PARSED_METHOD);
        assert_eq!(sources[1].method, METADATA_METHOD);
        assert!(sources.iter().all(|s| s.artifact == "dropscan:rmm_log"));
    }
}
