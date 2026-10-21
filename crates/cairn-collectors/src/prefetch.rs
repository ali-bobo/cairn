//! PrefetchCollector: parse C:\Windows\Prefetch\*.pf (Win10+ MAM-compressed) into
//! Record::Execution with real run_count + first/last run times. An offline-artifact
//! collector: std::fs reads (admin only, .pf is not OS-locked), compcol decompresses
//! the MAM (Xpress-Huffman) wrapper, a pure never-panic parser reads the header and the
//! filename-strings section (full executable path). Recognised format versions only
//! (Win10 v30, both file-information variants; Win11 v31); anything else ABSTAINS (NFR12).

use std::sync::atomic::{AtomicBool, Ordering};

use cairn_core::manifest::SourceEntry;
use cairn_core::record::{ExecutionRecord, Record};
use cairn_core::time::filetime_to_utc;
use cairn_core::traits::{CollectCtx, Collector};
use cairn_core::{CairnError, Result};
use chrono::{DateTime, Utc};

const MAM_MAGIC: &[u8; 4] = b"MAM\x04";

/// Hard ceiling on a single decompressed .pf (NFR10). Real prefetch files are well under
/// a few MB; 64 MiB is far above any legitimate .pf yet caps a malicious MAM size lie.
/// NOTE: compcol 0.6.5 decompress_to_vec_capped takes u64, not usize.
const PREFETCH_DECOMPRESS_CEILING: u64 = 64 * 1024 * 1024;

const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";

#[inline]
fn prefetch_err(reason: String) -> CairnError {
    CairnError::Collector {
        collector: "prefetch".into(),
        reason,
    }
}

/// Decompress a .pf outer container. A MAM file is `"MAM\x04"` (4 bytes) followed by the
/// compcol-framed Xpress-Huffman stream. Crucially, compcol's own frame begins with a
/// 4-byte LE uncompressed-length header — and that is EXACTLY the u32 that sits at MAM
/// offset 4. So the bytes compcol needs are `raw[4..]` (the MAM length header IS compcol's
/// length header; the MS-XCA bitstream follows it). We must NOT strip the length u32 —
/// passing `raw[8..]` would feed compcol the bare bitstream, and its decoder would misread
/// the first 4 bitstream bytes as the length and decode from the wrong position.
///
/// Decompression is capped (NFR10 — a malicious .pf cannot force an unbounded allocation).
/// Files without the MAM magic (older uncompressed .pf) are returned unchanged. A truncated
/// MAM container or a decompression failure (incl. exceeding the ceiling) yields Err (caller
/// abstains).
fn decompress_mam(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 4 || &raw[0..4] != MAM_MAGIC {
        return Ok(raw.to_vec()); // not MAM-compressed: pass through
    }
    if raw.len() < 8 {
        return Err(prefetch_err(
            "MAM header truncated (no length header)".into(),
        ));
    }
    // Keep the offset-4 u32 length header — it IS compcol's frame header.
    let stream = &raw[4..];
    compcol::vec::decompress_to_vec_capped::<compcol::xpress_huffman::XpressHuffman>(
        stream,
        PREFETCH_DECOMPRESS_CEILING,
    )
    .map_err(|e| prefetch_err(format!("MAM decompression failed: {e}")))
}

// ── Prefetch header layout (Win10 v30 / Win11 v31) ───────────────────────────
// These constants are the single fix-point for format offsets.
//
// Source: Joachim Metz, libscca "Windows Prefetch File (PF) format" documentation
// (github.com/libyal/libscca, documentation/Windows Prefetch File (PF) format.asciidoc),
// sections "File header" and "File information", cross-checked with Eric Zimmerman's
// Prefetch parser (PECmd) behaviour. Written from that documentation (not re-fetched
// here). The layout of the decompressed SCCA body:
//
//   0x00 u32  format version (30 = Win10, 31 = Win11)
//   0x04 [4]  "SCCA"
//   0x10 [60] executable name, UTF-16LE, NUL-terminated (truncated to 29 chars)
//   0x54      FILE INFORMATION begins (directly after the 84-byte header):
//   0x54 u32  metrics array offset        -- equals 0x54 + file-information size,
//   0x64 u32  filename strings offset        because the metrics array follows it
//   0x68 u32  filename strings size
//   0x6C u32  volumes information offset
//   0x70 u32  number of volumes
//   0x80 [64] last run times, 8 x FILETIME
//   run count u32: 0xD0 or 0xC8 depending on the variant below
//
// Version 30 has TWO file-information layouts (libscca: "version 30 variant 1/2"):
// the original Win10 one is 0xDC (220) bytes, so the metrics array starts at 0x130,
// with the run count at 0xD0; later Win10 builds shrank the file information to 0xD4
// (212) bytes — 8 bytes fewer before the run count — so the metrics array starts at
// 0x128 and the run count sits at 0xC8. The variant is detected from the metrics array
// offset at 0x54. The v31 (Win11) layout was VERIFIED on a real Windows 11 .pf
// (run count at 0xC8, cross-checked against the number of non-zero run times), which
// matches the 0xD4 variant.

/// Windows 10 prefetch format version.
const PF_V30: u32 = 30;
/// Windows 11 prefetch format version (verified on a real host).
const PF_V31: u32 = 31;

/// Byte offset of the NUL-terminated UTF-16LE executable name field in the header.
const EXE_NAME_OFFSET: usize = 16;

/// Maximum byte length of the name field (60 bytes = 30 UTF-16 code units).
const EXE_NAME_MAX_BYTES: usize = 60;

/// Header size; the file information follows it.
const FILE_INFO_OFFSET: usize = 0x54;
/// Metrics-array offset of the 0xDC-byte file information (run count at 0xD0).
const METRICS_OFFSET_FI_DC: u32 = 0x54 + 0xDC; // 0x130
/// Metrics-array offset of the 0xD4-byte file information (run count at 0xC8).
const METRICS_OFFSET_FI_D4: u32 = 0x54 + 0xD4; // 0x128

/// Filename strings offset / size (u32 each), relative to the start of the body.
const FILENAME_STRINGS_OFFSET: usize = 0x64;
const FILENAME_STRINGS_SIZE: usize = 0x68;

/// Byte offset of the run-times array (8 × u64 FILETIME slots). Same for v30 and v31.
const RUN_TIMES_OFFSET: usize = 0x80;

/// Byte offset of the u32 run-count field for `version`, given the metrics array
/// offset read at 0x54 (which encodes the file-information size, see above).
/// v30 with an unrecognised metrics offset abstains (None, NFR12); v31 falls back to
/// its verified 0xC8.
fn run_count_offset(version: u32, metrics_offset: Option<u32>) -> Option<usize> {
    match (version, metrics_offset) {
        (PF_V30 | PF_V31, Some(METRICS_OFFSET_FI_DC)) => Some(0xD0),
        (PF_V30 | PF_V31, Some(METRICS_OFFSET_FI_D4)) => Some(0xC8),
        (PF_V31, _) => Some(0xC8),
        _ => None,
    }
}

/// Parsed prefetch header — a pure value type; no parser internals exposed.
#[derive(Debug, PartialEq)]
struct PrefetchInfo {
    /// Executable name from the header NAME field (not a full path).
    exe_name: String,
    /// Full NT path of the executable from the filename-strings section, verbatim
    /// (e.g. `\VOLUME{01d...-b2c3}\WINDOWS\SYSTEM32\NOTEPAD.EXE`), when found.
    full_path: Option<String>,
    /// Device prefix of the system volume (the one holding `\WINDOWS\SYSTEM32\NTDLL.DLL`),
    /// used to turn `full_path` into a drive-letter path.
    system_volume: Option<String>,
    run_count: u32,
    /// Up to 8 run timestamps; zero-padded slots are filtered (ft==0 → None in filetime_to_utc).
    run_times: Vec<DateTime<Utc>>,
}

/// Bounds-checked little-endian u32 reader.
/// Returns None when `off..off+4` is out of bounds — never panics.
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// Bounds-checked little-endian u64 reader.
/// Returns None when `off..off+8` is out of bounds — never panics.
#[inline]
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// Read the NUL-terminated UTF-16LE executable name from the header.
/// Stops at the first NUL code unit or at `EXE_NAME_MAX_BYTES`, whichever comes first.
/// Lossy on bad surrogate pairs. Never panics.
fn read_exe_name(buf: &[u8]) -> String {
    let end = (EXE_NAME_OFFSET + EXE_NAME_MAX_BYTES).min(buf.len());
    let slice = match buf.get(EXE_NAME_OFFSET..end) {
        Some(s) => s,
        None => return String::new(),
    };
    let mut units = Vec::new();
    for pair in slice.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// The NUL-separated UTF-16LE strings of the filename-strings section. Bounds-checked;
/// a bad offset/size yields an empty list.
fn read_filename_strings(buf: &[u8]) -> Vec<String> {
    let (Some(off), Some(size)) = (
        rd_u32(buf, FILENAME_STRINGS_OFFSET),
        rd_u32(buf, FILENAME_STRINGS_SIZE),
    ) else {
        return Vec::new();
    };
    let start = off as usize;
    let end = start.saturating_add(size as usize).min(buf.len());
    let Some(sect) = buf.get(start..end) else {
        return Vec::new();
    };
    let units: Vec<u16> = sect
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    units
        .split(|&u| u == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// The filename string that is the executable itself: its last path component equals
/// the header name (case-insensitive), or starts with it when the header name was
/// truncated (29 chars). First match wins.
fn find_exe_path(strings: &[String], exe_name: &str) -> Option<String> {
    if exe_name.is_empty() {
        return None;
    }
    let want = exe_name.to_ascii_uppercase();
    let truncated = exe_name.encode_utf16().count() >= 29;
    strings
        .iter()
        .find(|s| {
            let leaf = s.rsplit('\\').next().unwrap_or("").to_ascii_uppercase();
            leaf == want || (truncated && leaf.starts_with(&want))
        })
        .cloned()
}

/// Device prefix (`\VOLUME{...}` or `\DEVICE\HARDDISKVOLUMEn`) of the volume holding
/// `\WINDOWS\SYSTEM32\NTDLL.DLL` — every process maps ntdll, so it is in (nearly) every
/// prefetch file and identifies the system volume.
fn system_volume_prefix(strings: &[String]) -> Option<String> {
    const NTDLL: &str = r"\WINDOWS\SYSTEM32\NTDLL.DLL";
    strings.iter().find_map(|s| {
        let up = s.to_ascii_uppercase();
        up.ends_with(NTDLL)
            .then(|| s[..s.len() - NTDLL.len()].to_string())
            .filter(|p| !p.is_empty())
    })
}

/// Turn a device path on the system volume into a drive-letter path
/// (`\VOLUME{x}\WINDOWS\X.EXE` + `C:` -> `C:\WINDOWS\X.EXE`). Paths on any other volume
/// cannot be mapped without the live volume table and yield None.
fn to_drive_path(full: &str, system_volume: Option<&str>, system_drive: &str) -> Option<String> {
    let vol = system_volume?;
    let rest = full.get(vol.len()..)?;
    (full.get(..vol.len())?.eq_ignore_ascii_case(vol) && rest.starts_with('\\'))
        .then(|| format!("{}{rest}", system_drive.trim_end_matches('\\')))
}

/// Parse a decompressed prefetch body into a `PrefetchInfo`.
///
/// Win10 v30 (both file-information variants) / Win11 v31. Unrecognised version, or a
/// v30 file-information variant that is not recognised → `None` (abstain, NFR12).
/// Never panics: all reads are bounds-checked via `rd_u32`/`rd_u64` (Option-returning);
/// a truncated buffer returns `None` rather than indexing out of range.
fn parse_prefetch(buf: &[u8]) -> Option<PrefetchInfo> {
    let version = rd_u32(buf, 0)?;
    let rc_offset = run_count_offset(version, rd_u32(buf, FILE_INFO_OFFSET))?;
    // Buffer must reach at least rc_offset + 4 to be a plausible header.
    let run_count = rd_u32(buf, rc_offset)?;
    let exe_name = read_exe_name(buf);
    // Read up to 8 FILETIME slots; filetime_to_utc filters ft==0 (zero-padded slots).
    let mut run_times = Vec::new();
    for i in 0..8usize {
        if let Some(ft) = rd_u64(buf, RUN_TIMES_OFFSET + i * 8) {
            if let Some(dt) = filetime_to_utc(ft) {
                run_times.push(dt);
            }
        }
    }
    let strings = read_filename_strings(buf);
    Some(PrefetchInfo {
        full_path: find_exe_path(&strings, &exe_name),
        system_volume: system_volume_prefix(&strings),
        exe_name,
        run_count,
        run_times,
    })
}

/// PrefetchCollector: admin-only, read-only parse of C:\Windows\Prefetch\*.pf into
/// Record::Execution (source="prefetch") with real run_count + first/last run times.
#[derive(Default)]
pub struct PrefetchCollector {
    dir_unreadable: AtomicBool,
    file_read_errors: AtomicBool,
    decompress_errors: AtomicBool,
    unknown_version: AtomicBool,
}

impl PrefetchCollector {
    /// `path` is the drive-letter path when the executable sits on the system volume
    /// (mapped to `system_drive`), else the header name, so name-only joins keep
    /// working; `full_path` is the verbatim filename-strings path.
    fn to_record(info: PrefetchInfo, system_drive: &str) -> Record {
        let last_run = info.run_times.iter().max().copied();
        let first_run = info.run_times.iter().min().copied();
        let drive_path = info
            .full_path
            .as_deref()
            .and_then(|f| to_drive_path(f, info.system_volume.as_deref(), system_drive));
        Record::Execution(ExecutionRecord {
            source: "prefetch".into(),
            path: drive_path.unwrap_or(info.exe_name),
            first_run,
            last_run,
            run_count: Some(info.run_count),
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
            full_path: info.full_path,
        })
    }
}

impl Collector for PrefetchCollector {
    fn name(&self) -> &str {
        cairn_core::collectors::PREFETCH
    }

    fn collect(&self, ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        if !ctx.admin {
            return Err(CairnError::Privilege {
                what: "prefetch".into(),
                need: "Administrator".into(),
            });
        }

        let entries = match std::fs::read_dir(PREFETCH_DIR) {
            Ok(rd) => rd,
            Err(e) => {
                self.dir_unreadable.store(true, Ordering::Relaxed);
                tracing::warn!(err = %e, "prefetch: dir unreadable; abstaining");
                return Ok(Vec::new());
            }
        };

        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let mut records: Vec<Record> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("pf"))
                != Some(true)
            {
                continue;
            }
            let raw = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    self.file_read_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(file = ?path, err = %e, "prefetch: read failed; skipping");
                    continue;
                }
            };
            let decompressed = match decompress_mam(&raw) {
                Ok(b) => b,
                Err(e) => {
                    self.decompress_errors.store(true, Ordering::Relaxed);
                    tracing::warn!(file = ?path, err = %e, "prefetch: decompress failed; skipping");
                    continue;
                }
            };
            match parse_prefetch(&decompressed) {
                Some(info) => records.push(Self::to_record(info, &system_drive)),
                None => {
                    self.unknown_version.store(true, Ordering::Relaxed);
                    tracing::warn!(file = ?path, "prefetch: unrecognised/incomplete; skipping");
                }
            }
        }

        records.sort_by(|a, b| match (a, b) {
            (Record::Execution(x), Record::Execution(y)) => x.path.cmp(&y.path),
            _ => std::cmp::Ordering::Equal, // unreachable: only Execution emitted
        });

        tracing::info!(prefetch_entries = records.len(), "prefetch scan");
        Ok(records)
    }

    fn sources(&self) -> Vec<SourceEntry> {
        let mut errors = Vec::new();
        if self.dir_unreadable.load(Ordering::Relaxed) {
            errors.push("abstained: Prefetch directory absent or unreadable".to_string());
        }
        if self.file_read_errors.load(Ordering::Relaxed) {
            errors.push("partial: one or more .pf files unreadable".to_string());
        }
        if self.decompress_errors.load(Ordering::Relaxed) {
            errors.push("partial: one or more .pf files failed MAM decompression".to_string());
        }
        if self.unknown_version.load(Ordering::Relaxed) {
            errors.push(
                "abstained: one or more .pf files had an unrecognised or incomplete format (NFR12)"
                    .to_string(),
            );
        }
        vec![SourceEntry {
            collector: String::new(),
            artifact: "prefetch".into(),
            path: PREFETCH_DIR.into(),
            method: "file_api".into(),
            size: 0,
            sha256: String::new(),
            errors,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cairn_core::config::Config;
    use cairn_core::traits::{CollectCtx, Collector};
    use cairn_core::CairnError;
    use std::sync::atomic::Ordering;

    /// Pins the compcol xpress_huffman one-shot API. If this fails to COMPILE, the function
    /// path/signature below is wrong — fix it from the installed compcol source
    /// (~/.cargo/registry/src/.../compcol-*/src/) or `cargo doc`, and report the real API.
    ///
    /// Real confirmed API (compcol 0.6.5):
    ///   compress:   compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&[u8])
    ///                 -> Result<Vec<u8>, compcol::Error>
    ///   decompress: compcol::vec::decompress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&[u8])
    ///                 -> Result<Vec<u8>, compcol::Error>
    ///
    /// The compressed stream is self-delimiting: compcol prepends a 4-byte LE
    /// uncompressed-length header so decompress does NOT require the caller to
    /// supply the uncompressed size separately.
    #[test]
    fn compcol_xpress_huffman_round_trips() {
        let original = b"the quick brown fox jumps over the lazy dog, repeatedly. \
                         the quick brown fox jumps over the lazy dog, repeatedly.";
        let compressed =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(original)
                .expect("xpress_huffman compress");
        let restored =
            compcol::vec::decompress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&compressed)
                .expect("xpress_huffman decompress");
        assert_eq!(restored, original);
    }

    #[test]
    fn decompress_mam_passes_through_non_mam() {
        let raw = b"SCCA-ish uncompressed bytes".to_vec();
        assert_eq!(decompress_mam(&raw).expect("passthrough"), raw);
    }

    #[test]
    fn decompress_mam_decompresses_mam_container() {
        // A real MAM .pf is "MAM\x04" + the compcol-framed stream. compcol's frame ALREADY
        // begins with the 4-byte LE uncompressed-length header, so the MAM container is
        // exactly MAM_MAGIC ++ compcol_output (NO extra size field — the compcol header IS
        // the offset-4 length). decompress_mam must therefore hand compcol raw[4..].
        let original = b"prefetch decompressed body ".repeat(8);
        let compcol_stream =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&original)
                .expect("compress");
        let mut mam = Vec::new();
        mam.extend_from_slice(b"MAM\x04");
        mam.extend_from_slice(&compcol_stream); // compcol_stream[0..4] = LE length header
        assert_eq!(decompress_mam(&mam).expect("decompress"), original);
    }

    #[test]
    fn decompress_mam_slices_at_offset_4_not_8() {
        // Regression guard for the framing bug caught in review: compcol's frame starts with
        // a u32 LE length header, which sits at MAM offset 4. Feeding raw[8..] (dropping that
        // header) makes compcol misread the bitstream. This test pins raw[4..] by checking
        // that the bytes AT offset 4 are what compcol round-trips — i.e. MAM_MAGIC ++ frame
        // decompresses, and a wrongly-8-sliced variant (frame with its first 4 bytes chopped)
        // does NOT yield the original.
        let original = b"the regression vector body, distinct content here".to_vec();
        let frame =
            compcol::vec::compress_to_vec::<compcol::xpress_huffman::XpressHuffman>(&original)
                .expect("compress");
        // Correct container: MAM + full frame. decompress_mam uses raw[4..] == frame.
        let mut correct = b"MAM\x04".to_vec();
        correct.extend_from_slice(&frame);
        assert_eq!(
            decompress_mam(&correct).expect("correct decompresses"),
            original
        );
        // If decompress_mam had used raw[8..], it would have fed compcol `frame[4..]` (the
        // frame minus its length header) — prove that bytes are NOT a valid decode of original.
        let wrong_input = &frame[4..];
        let wrong = compcol::vec::decompress_to_vec_capped::<compcol::xpress_huffman::XpressHuffman>(
            wrong_input,
            PREFETCH_DECOMPRESS_CEILING,
        );
        // Either it errors, or it decodes to something other than the original — never equal.
        assert!(
            wrong.as_deref() != Ok(original.as_slice()),
            "dropping the length header must not coincidentally yield the original"
        );
    }

    #[test]
    fn decompress_mam_too_short_is_err_not_panic() {
        let raw = b"MAM\x04\x01".to_vec();
        assert!(decompress_mam(&raw).is_err());
    }

    // ── parse_prefetch tests (Task 3) ─────────────────────────────────────────

    // FILETIME for 2021-01-01T00:00:00Z (verified: 132_539_328_000_000_000).
    const FT_2021: u64 = 132_539_328_000_000_000;
    /// Build a minimal decompressed body: header, the metrics-array offset at 0x54
    /// (which selects the file-information variant), run_count at the offset the impl
    /// derives from it, run times, and an optional filename-strings section.
    fn build_pf_full(
        version: u32,
        metrics_off: u32,
        exe: &str,
        run_count: u32,
        run_times: &[u64],
        strings: &[&str],
    ) -> Vec<u8> {
        let rc_off = run_count_offset(version, Some(metrics_off))
            .expect("test version/variant must be recognised");
        let mut buf = vec![0u8; (metrics_off as usize).max(rc_off + 4)];
        buf[0..4].copy_from_slice(&version.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        let utf16: Vec<u8> = exe.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let cap = utf16.len().min(EXE_NAME_MAX_BYTES);
        buf[EXE_NAME_OFFSET..EXE_NAME_OFFSET + cap].copy_from_slice(&utf16[..cap]);
        buf[FILE_INFO_OFFSET..FILE_INFO_OFFSET + 4].copy_from_slice(&metrics_off.to_le_bytes());
        buf[rc_off..rc_off + 4].copy_from_slice(&run_count.to_le_bytes());
        for (i, ft) in run_times.iter().take(8).enumerate() {
            let off = RUN_TIMES_OFFSET + i * 8;
            buf[off..off + 8].copy_from_slice(&ft.to_le_bytes());
        }
        if !strings.is_empty() {
            let start = buf.len();
            for s in strings {
                buf.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
                buf.extend_from_slice(&[0, 0]);
            }
            let size = (buf.len() - start) as u32;
            buf[FILENAME_STRINGS_OFFSET..FILENAME_STRINGS_OFFSET + 4]
                .copy_from_slice(&(start as u32).to_le_bytes());
            buf[FILENAME_STRINGS_SIZE..FILENAME_STRINGS_SIZE + 4]
                .copy_from_slice(&size.to_le_bytes());
        }
        buf
    }

    /// v30 defaults to the original 0xDC file information, v31 to the verified 0xD4.
    fn build_pf(version: u32, exe: &str, run_count: u32, run_times: &[u64]) -> Vec<u8> {
        let metrics = if version == PF_V30 {
            METRICS_OFFSET_FI_DC
        } else {
            METRICS_OFFSET_FI_D4
        };
        build_pf_full(version, metrics, exe, run_count, run_times, &[])
    }

    #[test]
    fn v30_variant_detected_from_metrics_offset() {
        assert_eq!(run_count_offset(30, Some(0x130)), Some(0xD0));
        assert_eq!(run_count_offset(30, Some(0x128)), Some(0xC8));
        assert_eq!(
            run_count_offset(30, Some(0x0F0)),
            None,
            "v30 unknown variant abstains"
        );
        assert_eq!(run_count_offset(30, None), None);
        assert_eq!(run_count_offset(31, Some(0x128)), Some(0xC8));
        assert_eq!(
            run_count_offset(31, Some(0x999)),
            Some(0xC8),
            "v31 verified fallback"
        );
        assert_eq!(run_count_offset(26, Some(0x130)), None);

        // Both v30 layouts parse their own run count, and do not read the other slot.
        for metrics in [METRICS_OFFSET_FI_DC, METRICS_OFFSET_FI_D4] {
            let mut body = build_pf_full(30, metrics, "A.EXE", 7, &[FT_2021], &[]);
            let other = if metrics == METRICS_OFFSET_FI_DC {
                0xC8
            } else {
                0xD0
            };
            body[other..other + 4].copy_from_slice(&999u32.to_le_bytes());
            assert_eq!(
                parse_prefetch(&body).unwrap().run_count,
                7,
                "metrics {metrics:#x}"
            );
        }
    }

    const VOL: &str = r"\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}";

    #[test]
    fn full_path_from_filename_strings_and_system_volume_mapping() {
        let strings = [
            format!(r"{VOL}\WINDOWS\SYSTEM32\NTDLL.DLL"),
            format!(r"{VOL}\USERS\PUBLIC\EVIL.EXE"),
            r"\VOLUME{01d0000000000000-deadbeef}\TOOLS\EVIL.EXE.CFG".to_string(),
        ];
        let refs: Vec<&str> = strings.iter().map(String::as_str).collect();
        let body = build_pf_full(31, METRICS_OFFSET_FI_D4, "EVIL.EXE", 2, &[FT_2021], &refs);
        let info = parse_prefetch(&body).unwrap();
        assert_eq!(info.full_path.as_deref(), Some(strings[1].as_str()));
        assert_eq!(info.system_volume.as_deref(), Some(VOL));
        let Record::Execution(e) = PrefetchCollector::to_record(info, "C:") else {
            panic!("execution expected");
        };
        assert_eq!(e.path, r"C:\USERS\PUBLIC\EVIL.EXE");
        assert_eq!(e.full_path.as_deref(), Some(strings[1].as_str()));
    }

    #[test]
    fn non_system_volume_keeps_name_as_path_and_full_path_verbatim() {
        let other = r"\VOLUME{01d0000000000000-deadbeef}\TOOLS\X.EXE";
        let strings = [
            format!(r"{VOL}\WINDOWS\SYSTEM32\NTDLL.DLL"),
            other.to_string(),
        ];
        let refs: Vec<&str> = strings.iter().map(String::as_str).collect();
        let body = build_pf_full(30, METRICS_OFFSET_FI_DC, "X.EXE", 1, &[], &refs);
        let Record::Execution(e) =
            PrefetchCollector::to_record(parse_prefetch(&body).unwrap(), "C:")
        else {
            panic!("execution expected");
        };
        assert_eq!(e.path, "X.EXE");
        assert_eq!(e.full_path.as_deref(), Some(other));
    }

    #[test]
    fn truncated_header_name_still_finds_full_path() {
        let long = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.EXE"; // > 29 chars
        let header_name: String = long.chars().take(29).collect();
        let p = format!(r"{VOL}\APPS\{long}");
        let body = build_pf_full(31, METRICS_OFFSET_FI_D4, &header_name, 1, &[], &[&p]);
        let info = parse_prefetch(&body).unwrap();
        assert_eq!(info.full_path.as_deref(), Some(p.as_str()));
        assert_eq!(info.system_volume, None);
        assert_eq!(to_drive_path(&p, None, "C:"), None);
    }

    #[test]
    fn bad_filename_strings_offsets_never_panic() {
        let mut body = build_pf(31, "Y.EXE", 1, &[]);
        body[FILENAME_STRINGS_OFFSET..FILENAME_STRINGS_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        body[FILENAME_STRINGS_SIZE..FILENAME_STRINGS_SIZE + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let info = parse_prefetch(&body).unwrap();
        assert_eq!(info.full_path, None);
        // prefix mismatch / no separator after the volume -> None
        assert_eq!(
            to_drive_path(r"\VOLUME{a}X", Some(r"\VOLUME{a}"), "C:"),
            None
        );
        assert_eq!(
            to_drive_path(r"\volume{A}\x.exe", Some(r"\VOLUME{a}"), r"D:\"),
            Some(r"D:\x.exe".to_string())
        );
    }

    #[test]
    fn parse_v30_basic() {
        let body = build_pf(30, "NOTEPAD.EXE", 5, &[FT_2021, FT_2021 + 10_000_000]);
        let info = parse_prefetch(&body).expect("v30 parses");
        assert_eq!(info.exe_name, "NOTEPAD.EXE");
        assert_eq!(info.run_count, 5);
        assert_eq!(info.run_times.len(), 2);
    }

    #[test]
    fn parse_v31_basic() {
        // Win11 v31: run_count lives at 0xC8, not v30's 0xD0 (machine-verified).
        let body = build_pf(31, "AGENTS-CLI.EXE", 5, &[FT_2021, FT_2021 + 10_000_000]);
        let info = parse_prefetch(&body).expect("v31 parses");
        assert_eq!(info.exe_name, "AGENTS-CLI.EXE");
        assert_eq!(info.run_count, 5);
        assert_eq!(info.run_times.len(), 2);
    }

    #[test]
    fn parse_unknown_version_is_none() {
        let mut body = build_pf(30, "X.EXE", 1, &[FT_2021]);
        body[0..4].copy_from_slice(&26u32.to_le_bytes()); // Win8 v26 — unrecognised
        assert!(parse_prefetch(&body).is_none());
        // v29 (one below v30) and v32 (one above v31) must also abstain.
        body[0..4].copy_from_slice(&29u32.to_le_bytes());
        assert!(parse_prefetch(&body).is_none());
        body[0..4].copy_from_slice(&32u32.to_le_bytes());
        assert!(parse_prefetch(&body).is_none());
    }

    #[test]
    fn parse_truncated_is_none_no_panic() {
        assert!(parse_prefetch(&[30u8, 0, 0, 0]).is_none());
        assert!(parse_prefetch(&[31u8, 0, 0, 0]).is_none());
    }

    #[test]
    fn parse_all_zero_run_times_yields_empty_vec() {
        let body = build_pf(31, "Z.EXE", 0, &[]);
        let info = parse_prefetch(&body).expect("parses");
        assert!(info.run_times.is_empty());
    }

    // ── PrefetchCollector unit tests (Task 4) ────────────────────────────────

    #[test]
    fn collect_without_privilege_returns_err() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: false,
            se_backup: false,
            se_debug: false,
        };
        assert!(matches!(
            PrefetchCollector::default().collect(&ctx),
            Err(CairnError::Privilege { .. })
        ));
    }

    #[test]
    fn name_is_prefetch() {
        assert_eq!(PrefetchCollector::default().name(), "prefetch");
    }

    #[test]
    fn sources_clean_when_not_abstained() {
        let s = PrefetchCollector::default().sources();
        assert_eq!(s.len(), 1);
        assert!(s[0].errors.is_empty());
        assert_eq!(s[0].artifact, "prefetch");
    }

    #[test]
    fn sources_reports_dir_unreadable() {
        let c = PrefetchCollector::default();
        c.dir_unreadable.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("Prefetch directory")));
    }

    #[test]
    fn sources_reports_unknown_version() {
        let c = PrefetchCollector::default();
        c.unknown_version.store(true, Ordering::Relaxed);
        assert!(c.sources()[0]
            .errors
            .iter()
            .any(|e| e.contains("unrecognised or incomplete")));
    }

    #[test]
    fn sources_reports_partial_read_and_decompress() {
        let c = PrefetchCollector::default();
        c.file_read_errors.store(true, Ordering::Relaxed);
        c.decompress_errors.store(true, Ordering::Relaxed);
        let errs = c.sources()[0].errors.clone();
        assert!(errs.iter().any(|e| e.contains("unreadable")));
        assert!(errs.iter().any(|e| e.contains("MAM decompression")));
    }

    /// ELEVATED E2E (manual): run as Administrator:
    ///   cargo test -p cairn-collectors prefetch::tests::prefetch_e2e_real_dir -- --ignored --nocapture
    /// Proves the full chain: std::fs enumerate C:\Windows\Prefetch -> MAM decompress (compcol)
    /// -> parse v30 header -> Record::Execution. The any_run assertion verifies the v30 offset
    /// consts are correct (wrong offsets => zero/garbage run_count or run times).
    #[test]
    #[ignore = "requires Administrator and a real Windows C:\\Windows\\Prefetch"]
    fn prefetch_e2e_real_dir() {
        let cfg = Config::default();
        let ctx = CollectCtx {
            config: &cfg,
            admin: true,
            se_backup: false,
            se_debug: false,
        };
        let collector = PrefetchCollector::default();
        let recs = collector.collect(&ctx).expect("collect ok");
        // Diagnostic: surface WHY collect returned what it did, so a failure clearly
        // distinguishes "no real admin rights / dir unreadable" from a parse problem.
        let src = collector.sources();
        eprintln!(
            "prefetch_e2e diagnostics: {} records; sources errors = {:?}",
            recs.len(),
            src[0].errors
        );
        if recs.is_empty() {
            // The most common cause is running WITHOUT real OS Administrator rights:
            // ctx.admin=true passes the gate, but std::fs::read_dir(C:\Windows\Prefetch)
            // is still denied by the OS unless the PROCESS is elevated.
            panic!(
                "collect returned 0 records. If sources errors mention 'Prefetch directory \
                 absent or unreadable', this test was NOT run from an elevated (Administrator) \
                 terminal — re-run it as Administrator. Errors: {:?}",
                src[0].errors
            );
        }
        let mut any_run = false;
        for r in &recs {
            if let Record::Execution(e) = r {
                assert_eq!(e.source, "prefetch");
                assert!(!e.path.is_empty(), "every entry has an exe name");
                assert_eq!(e.execution_confirmed, Some(true));
                assert!(e.run_count.is_some(), "prefetch carries a run count");
                if e.last_run.is_some() {
                    any_run = true;
                }
            } else {
                panic!("prefetch must only emit Execution records");
            }
        }
        assert!(
            any_run,
            "at least one entry should have a real last_run (offset sanity)"
        );
        eprintln!("prefetch_e2e_real_dir: parsed {} entries", recs.len());
    }
}
