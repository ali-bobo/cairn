//! Raw volume reader: open `\\.\C:` READ-ONLY and present it as `Read + Seek`.
//!
//! This is Cairn's first raw volume read. The only goal of this module is to
//! provide a byte-accurate window into a live NTFS volume so that the `ntfs`
//! crate (wired in a later task) can parse $MFT and friends entirely in
//! user-space, without touching or modifying any on-disk data.
//!
//! ## Read-only guarantee
//! `CreateFileW` is called with `GENERIC_READ` only and `OPEN_EXISTING`.
//! No write, append, create, or truncate flag is ever set. The volume on-disk
//! state is never modified (CLAUDE.md golden rules 3 & 4).
//!
//! ## Sector alignment
//! Raw volume reads on Windows must be sector-aligned in both offset and
//! length. `VolumeReader` queries the actual sector size on open (falling back
//! to 4096 if the IOCTL fails) and handles alignment transparently: callers
//! can seek to any byte offset and read any byte count; the implementation
//! buffers the aligned window covering the request and returns the requested
//! sub-range.
//!
//! ## Safety surface
//! All `unsafe` blocks are in the `#[cfg(windows)]` impl module. Each block
//! carries a `// SAFETY:` comment. The `VolumeHandle` RAII guard ensures the
//! kernel handle is closed exactly once even on early return or panic.

use std::io;

// ── Platform-independent alignment helpers ────────────────────────────────────

/// Round `n` down to the nearest multiple of `align`.
/// `align` must be a power of two and non-zero; the result is `n` when
/// `n` is already aligned.
#[inline]
pub(crate) fn align_down(n: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    n & !(align - 1)
}

/// Round `n` up to the nearest multiple of `align`.
/// `align` must be a power of two and non-zero; the result is `n` when
/// `n` is already aligned.
///
/// Returns `None` if the addition overflows `u64`.
#[inline]
pub(crate) fn align_up_checked(n: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    n.checked_add(align - 1).map(|v| v & !(align - 1))
}

// ── Sub-range / alignment window helper ──────────────────────────────────────

/// Result of computing the sector-aligned window required for a logical read.
///
/// `FILE_FLAG_NO_BUFFERING` forces ReadFile to operate on sector-aligned
/// offset+length pairs. This struct captures the exact window to issue to the
/// kernel, and where within that window the caller's requested bytes begin.
pub(crate) struct AlignedWindow {
    /// Sector-aligned byte offset at which ReadFile must begin.
    pub aligned_start: u64,
    /// Sector-aligned byte offset at which ReadFile must end (exclusive).
    /// `aligned_end - aligned_start` is the number of bytes to read.
    pub aligned_end: u64,
    /// Byte offset within the aligned buffer where the caller's data begins.
    /// Slicing `buf[inner_offset .. inner_offset + requested]` yields exactly
    /// the bytes that live at `[pos .. pos + requested]` on the volume.
    pub inner_offset: usize,
    /// Number of caller bytes requested (already clamped to MAX_READ and the
    /// aligned window size by the caller before constructing this value).
    pub requested: usize,
}

/// Compute the sector-aligned window needed to satisfy a logical read.
///
/// Given a logical byte position `pos`, the number of bytes the caller wants
/// (`requested`), and the drive's physical `sector` size, returns an
/// [`AlignedWindow`] describing:
/// - The aligned `[aligned_start, aligned_end)` range to pass to ReadFile.
/// - The `inner_offset` into the resulting buffer where the caller's bytes begin.
///
/// Returns `None` if any arithmetic overflows `u64` (e.g. a corrupt or
/// adversarial volume presenting `pos = u64::MAX`). Callers must convert `None`
/// to an `io::Error` rather than panicking; this is the sole defence against
/// malformed seek targets coming from on-disk $MFT values (CLAUDE.md golden
/// rule 8 — graceful degrade on bad data).
///
/// This function is pure (no I/O, no host state) and is the sole place where
/// the alignment arithmetic lives, making it independently testable without a
/// real volume handle.
///
/// # Panics (debug only)
/// `sector` must be a power of two. Violating this triggers a `debug_assert!`
/// inside `align_down` / `align_up_checked`.
#[inline]
pub(crate) fn compute_aligned_window(
    pos: u64,
    requested: usize,
    sector: u64,
) -> Option<AlignedWindow> {
    // Guard: pos + requested must not overflow u64.
    let end = pos.checked_add(requested as u64)?;

    let aligned_start = align_down(pos, sector);
    // Guard: align_up(end, sector) must not overflow u64.
    let aligned_end = align_up_checked(end, sector)?;

    // aligned_start <= pos, so this subtraction is always safe.
    let inner_offset = (pos - aligned_start) as usize;

    // Invariant: aligned_end >= end >= pos >= aligned_start, so
    // aligned_end - aligned_start >= 0 always. Assert it holds in debug builds.
    debug_assert!(aligned_end >= aligned_start);

    Some(AlignedWindow {
        aligned_start,
        aligned_end,
        inner_offset,
        requested,
    })
}

// ── Partial-read extraction helper ────────────────────────────────────────────

/// Extract the caller-visible sub-range from the aligned read buffer.
///
/// Given:
/// - `tmp`: the raw bytes returned by ReadFile (length == aligned window size).
/// - `n`: the number of bytes actually written by ReadFile (may be less than
///   `tmp.len()` at end-of-volume).
/// - `w`: the [`AlignedWindow`] that describes the request.
///
/// Returns the slice of bytes in `tmp` that correspond to the caller's logical
/// range `[pos .. pos + min(w.requested, available)]`, where
/// `available = n.saturating_sub(w.inner_offset)`.
///
/// Returns an empty slice when the kernel returned fewer bytes than
/// `w.inner_offset` (i.e. `pos` is entirely past end-of-volume).
///
/// This helper is the single authoritative implementation of the copy-back /
/// end-of-volume clamping logic. Both `VolumeReader::read` and the unit tests
/// call this function, guaranteeing they exercise the same code path.
///
/// Correctness is proven by `volume::tests::extract_subrange_*` tests, which
/// cover: full window, zero bytes read, exactly inner_offset bytes read (empty
/// result), inner_offset-1 bytes (empty result), and partial fills of k bytes
/// (k < requested).
pub(crate) fn extract_subrange<'a>(tmp: &'a [u8], n: usize, w: &AlignedWindow) -> &'a [u8] {
    let available = n.saturating_sub(w.inner_offset);
    if available == 0 {
        return &tmp[..0];
    }
    let to_copy = w.requested.min(available);
    &tmp[w.inner_offset..w.inner_offset + to_copy]
}

// ── Non-Windows stub ──────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod imp {
    use super::io;
    use cairn_core::{CairnError, Result};

    /// Stub on non-Windows: every operation returns an unsupported error.
    pub struct VolumeReader;

    impl VolumeReader {
        /// Opening a raw volume is Windows-only; always returns `Err` on other platforms.
        pub fn open(_path: &str) -> Result<Self> {
            Err(CairnError::Collector {
                collector: "volume".into(),
                reason: "raw volume read is Windows-only".into(),
            })
        }

        /// Sector size is not meaningful on non-Windows; returns a default of 4096.
        pub fn sector_size(&self) -> u64 {
            4096
        }
    }

    impl io::Read for VolumeReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw volume read is Windows-only",
            ))
        }
    }

    impl io::Seek for VolumeReader {
        fn seek(&mut self, _pos: io::SeekFrom) -> io::Result<u64> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw volume seek is Windows-only",
            ))
        }
    }
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod imp {
    use super::{compute_aligned_window, extract_subrange, io};
    use cairn_core::{CairnError, Result};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, SetFilePointerEx, FILE_BEGIN, FILE_FLAG_NO_BUFFERING,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{DISK_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX};
    use windows::Win32::System::IO::DeviceIoControl;

    /// Alignment fallback when the IOCTL cannot be completed.
    /// 4096 is a multiple of 512 so it is safe for both 512-byte and 4096-byte
    /// physical-sector drives.
    const DEFAULT_BLOCK: u64 = 4096;

    /// Single-read cap (1 MiB). Prevents runaway allocations (NFR10 first brick).
    const MAX_READ: usize = 1024 * 1024;

    // ── RAII handle guard ─────────────────────────────────────────────────────

    /// RAII guard for a volume `HANDLE` obtained from `CreateFileW`.
    ///
    /// INVARIANT: `self.0` is a valid, open kernel handle returned by `CreateFileW`
    /// with `GENERIC_READ` access to a volume. `Drop` calls `CloseHandle` exactly
    /// once. Never construct with an invalid or already-closed handle.
    struct VolumeHandle(HANDLE);

    impl Drop for VolumeHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid handle stored at construction time;
            // Drop is called exactly once by the Rust drop machinery.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // ── Public type ───────────────────────────────────────────────────────────

    /// Read-only, sector-aligned view of a Windows volume (e.g. `\\.\C:`).
    ///
    /// Implements `Read + Seek` so the `ntfs` crate can parse it directly.
    /// Alignment is handled internally: callers may use arbitrary byte offsets
    /// and lengths; the implementation buffers the aligned window covering the
    /// request and returns the requested sub-range.
    pub struct VolumeReader {
        handle: VolumeHandle,
        /// Logical byte position as seen by the caller (unaligned).
        pos: u64,
        /// Physical sector size (bytes). Always a power of two, >= 512.
        sector: u64,
    }

    impl VolumeReader {
        /// Open `path` (e.g. `r"\\.\C:"`) read-only.
        ///
        /// Returns `Err` if the handle cannot be opened (insufficient privilege,
        /// path not found, etc.). On success, queries the physical sector size;
        /// falls back silently to [`DEFAULT_BLOCK`] if the IOCTL fails.
        pub fn open(path: &str) -> Result<Self> {
            // Encode the path as a NUL-terminated UTF-16 string.
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

            // SAFETY: `wide` is a valid NUL-terminated UTF-16 string living for the
            // duration of the call. We request GENERIC_READ only (no write access),
            // OPEN_EXISTING (never creates), and FILE_SHARE_READ|FILE_SHARE_WRITE so
            // we do not block concurrent access to the live volume. The returned handle
            // is wrapped in VolumeHandle immediately, so it is always closed on error.
            //
            // FILE_FLAG_NO_BUFFERING — deliberate forensic choice (golden rule 4):
            //   This flag tells the kernel to bypass the Windows file-system cache
            //   entirely. Raw volume reads therefore do NOT populate or pollute the
            //   target host's page cache — minimising our forensic footprint and
            //   preserving the cache state that a memory-forensics pass might examine.
            //   The trade-off is a strict kernel-level constraint: both the file
            //   offset and the read length passed to ReadFile MUST be exact multiples
            //   of the physical sector size (typically 512 B or 4096 B). This is
            //   exactly why every call goes through `compute_aligned_window` before
            //   reaching `read_aligned`: the helper computes the enclosing
            //   sector-aligned window and the byte offset within it where the
            //   caller's requested range begins, so we always issue sector-aligned
            //   ReadFile calls while returning the precise sub-range the caller asked
            //   for. The correctness of that alignment math is proven by the
            //   `volume::tests::subrange_*` unit tests; the correctness of the
            //   partial-read / end-of-volume clamping is proven by the
            //   `volume::tests::extract_subrange_*` unit tests, both exercising the
            //   same shared `extract_subrange` helper used by this `read` impl.
            let raw = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_NO_BUFFERING,
                    None,
                )
            }
            .map_err(|e| CairnError::Collector {
                collector: "volume".into(),
                reason: format!("CreateFileW({path}): {e}"),
            })?;

            // Wrap the handle immediately so it is always closed.
            let handle = VolumeHandle(raw);

            // Query the physical sector size; fall back silently if unavailable.
            let sector = query_sector_size(&handle).unwrap_or(DEFAULT_BLOCK);

            Ok(Self {
                handle,
                pos: 0,
                sector,
            })
        }

        /// Physical sector size in bytes (>= 512, always a power of two).
        pub fn sector_size(&self) -> u64 {
            self.sector
        }

        /// Issue a raw read from the given aligned offset for the given aligned length.
        /// Both `offset` and `len` MUST already be multiples of `self.sector`.
        fn read_aligned(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            debug_assert_eq!(offset % self.sector, 0, "offset must be sector-aligned");
            debug_assert_eq!(
                buf.len() as u64 % self.sector,
                0,
                "len must be sector-aligned"
            );

            // Seek to the aligned offset.
            // SAFETY: handle is valid; FILE_BEGIN = 0 means absolute seek.
            // SetFilePointerEx succeeds or returns an error; we never read the
            // out-of-bounds result because we check the return value.
            unsafe { SetFilePointerEx(self.handle.0, offset as i64, None, FILE_BEGIN) }
                .map_err(|e| io::Error::other(e.to_string()))?;

            let mut bytes_read = 0u32;
            // SAFETY: handle is valid; buf is a valid mutable slice for the duration
            // of the call; bytes_read receives the actual byte count written.
            // We pass buf.len() as u32 which is bounded by MAX_READ (< u32::MAX).
            unsafe { ReadFile(self.handle.0, Some(buf), Some(&mut bytes_read), None) }
                .map_err(|e| io::Error::other(e.to_string()))?;

            Ok(bytes_read as usize)
        }
    }

    // ── Read impl ─────────────────────────────────────────────────────────────

    impl io::Read for VolumeReader {
        /// Read up to `buf.len()` bytes from the current logical position.
        ///
        /// To satisfy sector-alignment constraints we:
        /// 1. Clamp the request to `MAX_READ`.
        /// 2. Compute the aligned window that covers [`self.pos`, `self.pos + clamped`).
        /// 3. Read that aligned window into a temporary buffer.
        /// 4. Use `extract_subrange` to identify the exact sub-range the caller
        ///    asked for, handling the end-of-volume partial-read case.
        ///
        /// This ensures callers receive the *correct* bytes regardless of alignment,
        /// and never panics — a corrupt or adversarial volume causing `pos` to wrap
        /// around `u64::MAX` is gracefully returned as `InvalidInput` (golden rule 8).
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let requested = buf.len().min(MAX_READ);

            // Delegate all alignment arithmetic to the pure helper so that
            // the window math can be tested independently of the I/O path.
            // A corrupt/adversarial on-disk seek target can produce pos values
            // near u64::MAX; return InvalidInput rather than panicking.
            let w = compute_aligned_window(self.pos, requested, self.sector).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "read position beyond addressable range",
                )
            })?;

            let aligned_len = (w.aligned_end - w.aligned_start) as usize;

            // Allocate the aligned window buffer (zeroed).
            let mut tmp = vec![0u8; aligned_len];
            let n = self.read_aligned(w.aligned_start, &mut tmp)?;

            if n == 0 {
                return Ok(0);
            }

            // Use the shared helper for the copy-back / end-of-volume clamping.
            // This is the SAME code exercised by extract_subrange_* tests.
            let src = extract_subrange(&tmp, n, &w);
            let to_copy = src.len();
            if to_copy == 0 {
                return Ok(0);
            }
            buf[..to_copy].copy_from_slice(src);
            self.pos += to_copy as u64;
            Ok(to_copy)
        }
    }

    // ── Seek impl ─────────────────────────────────────────────────────────────

    impl io::Seek for VolumeReader {
        /// Reposition the logical cursor.
        ///
        /// Supports `SeekFrom::Start` and `SeekFrom::Current`. `SeekFrom::End`
        /// is unsupported because the volume size is not tracked (it would require
        /// a separate IOCTL and has no use in the NTFS parser path).
        ///
        /// The underlying `SetFilePointerEx` is issued lazily (inside `read_aligned`)
        /// so this method only updates the logical `pos`.
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            match pos {
                io::SeekFrom::Start(n) => {
                    self.pos = n;
                }
                io::SeekFrom::Current(n) => {
                    if n >= 0 {
                        self.pos = self.pos.saturating_add(n as u64);
                    } else {
                        let back = (-n) as u64;
                        self.pos = self.pos.checked_sub(back).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "seek before start of volume",
                            )
                        })?;
                    }
                }
                io::SeekFrom::End(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "SeekFrom::End is not supported for raw volumes (size unknown)",
                    ));
                }
            }
            Ok(self.pos)
        }
    }

    // ── IOCTL sector-size query ───────────────────────────────────────────────

    /// Query the physical sector size of the volume using `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`.
    /// Returns `None` on any failure (permission, unsupported device); callers fall back to
    /// `DEFAULT_BLOCK`. This is best-effort: Cairn must not fail if the IOCTL is unavailable.
    fn query_sector_size(handle: &VolumeHandle) -> Option<u64> {
        let mut geo = DISK_GEOMETRY_EX::default();
        let mut returned = 0u32;

        // SAFETY: handle.0 is a valid open volume handle. We pass a correctly-sized
        // DISK_GEOMETRY_EX as the output buffer and its byte length. DeviceIoControl
        // writes at most `sizeof(DISK_GEOMETRY_EX)` bytes, which fit in `geo`.
        let ok = unsafe {
            DeviceIoControl(
                handle.0,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(&mut geo as *mut _ as *mut core::ffi::c_void),
                std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                Some(&mut returned),
                None,
            )
        };

        if ok.is_err() {
            return None;
        }

        let bytes_per_sector = geo.Geometry.BytesPerSector as u64;
        if bytes_per_sector >= 512 && bytes_per_sector.is_power_of_two() {
            Some(bytes_per_sector)
        } else {
            None
        }
    }
}

// ── Re-export the platform-appropriate type ───────────────────────────────────

pub use imp::VolumeReader;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{align_down, align_up_checked, compute_aligned_window, extract_subrange};

    // ── Alignment helpers ─────────────────────────────────────────────────────

    #[test]
    fn align_down_already_aligned() {
        assert_eq!(align_down(1024, 512), 1024);
        assert_eq!(align_down(512, 512), 512);
    }

    #[test]
    fn align_down_unaligned() {
        assert_eq!(align_down(513, 512), 512);
        assert_eq!(align_down(1023, 512), 512);
        assert_eq!(align_down(1025, 512), 1024);
    }

    #[test]
    fn align_down_zero() {
        assert_eq!(align_down(0, 512), 0);
        assert_eq!(align_down(0, 4096), 0);
    }

    #[test]
    fn align_up_already_aligned() {
        assert_eq!(align_up_checked(512, 512), Some(512));
        assert_eq!(align_up_checked(1024, 512), Some(1024));
    }

    #[test]
    fn align_up_unaligned() {
        assert_eq!(align_up_checked(1, 512), Some(512));
        assert_eq!(align_up_checked(513, 512), Some(1024));
        assert_eq!(align_up_checked(1023, 512), Some(1024));
    }

    #[test]
    fn align_up_zero() {
        assert_eq!(align_up_checked(0, 512), Some(0));
        assert_eq!(align_up_checked(0, 4096), Some(0));
    }

    #[test]
    fn align_up_overflow_returns_none() {
        // u64::MAX + (512 - 1) overflows; must return None not panic.
        assert_eq!(align_up_checked(u64::MAX, 512), None);
        // Any n where n + (align-1) wraps must return None.
        assert_eq!(align_up_checked(u64::MAX - 1, 512), None);
    }

    // ── Off-platform open returns Err ─────────────────────────────────────────

    #[cfg(not(windows))]
    #[test]
    fn open_off_platform_is_unsupported_error() {
        use super::VolumeReader;
        assert!(
            VolumeReader::open(r"\\.\C:").is_err(),
            "expected Err on non-Windows"
        );
    }

    // ── Overflow-safety: compute_aligned_window must never panic ──────────────
    //
    // FIX 1 regression guard. On a corrupt or adversarial volume the `ntfs`
    // crate may issue SeekFrom::Start(u64::MAX) causing pos to be near u64::MAX.
    // The old implementation used unchecked addition and would overflow (panic in
    // debug, silent wraparound in release producing aligned_end < aligned_start
    // and a subsequent underflow-panic at the subtraction site).
    //
    // compute_aligned_window must return None for such inputs so the caller can
    // surface a clean error rather than panicking.

    #[test]
    fn overflow_pos_near_max_returns_none() {
        // pos = u64::MAX - 10, requested = 4096: pos + requested overflows.
        let result = compute_aligned_window(u64::MAX - 10, 4096, 512);
        assert!(
            result.is_none(),
            "expected None for pos near u64::MAX, got Some"
        );
    }

    #[test]
    fn overflow_exact_max_returns_none() {
        // pos = u64::MAX: pos + any nonzero requested overflows.
        assert!(compute_aligned_window(u64::MAX, 1, 512).is_none());
        assert!(compute_aligned_window(u64::MAX, 4096, 4096).is_none());
    }

    #[test]
    fn overflow_end_near_max_align_up_overflows_returns_none() {
        // pos = 0, requested chosen so end is very close to u64::MAX:
        // align_up(end, 512) overflows even though end itself didn't.
        // u64::MAX = 18_446_744_073_709_551_615; sector = 512;
        // pick requested so end = u64::MAX - 2 (not overflow by add but align_up wraps).
        let pos: u64 = 0;
        let requested = (u64::MAX - 2) as usize; // this is enormous but tests the path
                                                 // Note: on 32-bit usize this would truncate; on 64-bit Windows it's fine.
                                                 // Guard: only run on 64-bit where usize can hold this value.
        if std::mem::size_of::<usize>() >= 8 {
            let result = compute_aligned_window(pos, requested, 512);
            assert!(
                result.is_none(),
                "expected None when align_up overflows, got Some"
            );
        }
    }

    #[test]
    fn valid_inputs_still_produce_correct_window() {
        // Regression: valid inputs must not be broken by the overflow guards.
        let w = compute_aligned_window(519, 100, 512).expect("valid input must produce Some");
        assert_eq!(w.aligned_start, 512);
        assert_eq!(w.aligned_end, 1024);
        assert_eq!(w.inner_offset, 7);
        assert_eq!(w.requested, 100);
    }

    // ── Sub-range / byte-correctness tests ───────────────────────────────────
    //
    // These tests exercise `compute_aligned_window` plus the slice extraction
    // logic used by `VolumeReader::read()` WITHOUT a real volume handle.
    //
    // Strategy: build a synthetic "volume" as a Vec<u8> filled with the pattern
    //   byte[i] = (i % 251) as u8
    // (251 is prime so the pattern has no accidental sector-sized period).
    // For each (pos, len, sector) case we:
    //   1. Call `compute_aligned_window` and assert the resulting window is
    //      sector-aligned.
    //   2. Slice the pattern at [aligned_start .. aligned_end] to simulate what
    //      ReadFile would return (a sector-aligned chunk of the "volume").
    //   3. Use `extract_subrange` (the same helper used by `VolumeReader::read`)
    //      and assert the result equals the pattern bytes at `[pos .. pos + len]`.
    //
    // This proves that the alignment arithmetic and inner-offset bookkeeping are
    // correct for arbitrary (pos, len) pairs, i.e. misaligned starts, requests
    // that span two sectors, and requests larger than one sector.

    // Volume size for the synthetic pattern: 4 MiB (enough for all cases below).
    const PATTERN_LEN: usize = 4 * 1024 * 1024;

    fn make_pattern() -> Vec<u8> {
        (0..PATTERN_LEN).map(|i| (i % 251) as u8).collect()
    }

    /// Simulate the "ReadFile returns aligned window" + "extract sub-range" step,
    /// modelling a FULL read (n == aligned_len).
    fn simulate_read(pattern: &[u8], pos: u64, len: usize, sector: u64) -> Vec<u8> {
        let w = compute_aligned_window(pos, len, sector)
            .expect("simulate_read: compute_aligned_window returned None for valid input");

        // --- structural assertions on the window itself ---
        assert_eq!(
            w.aligned_start % sector,
            0,
            "aligned_start must be sector-aligned (pos={pos}, len={len}, sector={sector})"
        );
        assert_eq!(
            w.aligned_end % sector,
            0,
            "aligned_end must be sector-aligned (pos={pos}, len={len}, sector={sector})"
        );
        assert!(w.aligned_start <= pos, "aligned_start must be <= pos");
        assert!(
            w.aligned_end >= pos + len as u64,
            "aligned_end must cover pos+len"
        );
        assert_eq!(w.requested, len, "requested must equal len");

        // Simulate the bytes ReadFile would hand back (aligned window from pattern).
        let as_ = w.aligned_start as usize;
        let ae = w.aligned_end as usize;
        assert!(ae <= pattern.len(), "pattern too short for this test case");
        let aligned_buf = &pattern[as_..ae];

        // Use the shared extract_subrange helper (full-read: n == aligned window len).
        let n = aligned_buf.len();
        extract_subrange(aligned_buf, n, &w).to_vec()
    }

    #[test]
    fn subrange_aligned_pos_aligned_len() {
        // pos and len are both on a sector boundary: inner_offset must be 0,
        // and the full aligned window is returned directly.
        let pattern = make_pattern();
        let sector: u64 = 512;
        let pos: u64 = 1024;
        let len: usize = 512;

        let got = simulate_read(&pattern, pos, len, sector);
        let want = &pattern[pos as usize..pos as usize + len];
        assert_eq!(got, want, "aligned pos+len: bytes must match pattern");

        // Inner offset should be zero for an already-aligned position.
        let w = compute_aligned_window(pos, len, sector).unwrap();
        assert_eq!(w.inner_offset, 0, "inner_offset must be 0 for aligned pos");
    }

    #[test]
    fn subrange_unaligned_pos_within_first_sector() {
        // pos is 7 bytes past a sector boundary; len fits within that sector.
        let pattern = make_pattern();
        let sector: u64 = 512;
        let pos: u64 = 512 + 7; // 519
        let len: usize = 100;

        let got = simulate_read(&pattern, pos, len, sector);
        let want = &pattern[pos as usize..pos as usize + len];
        assert_eq!(got, want);

        let w = compute_aligned_window(pos, len, sector).unwrap();
        assert_eq!(
            w.inner_offset, 7,
            "inner_offset must be the sub-sector offset"
        );
        assert_eq!(
            w.aligned_start, 512,
            "aligned_start is the sector boundary before pos"
        );
        assert_eq!(w.aligned_end, 1024, "single-sector window");
    }

    #[test]
    fn subrange_unaligned_pos_spanning_two_sectors() {
        // pos lands 400 bytes into a sector; len=200 crosses into the next sector.
        let pattern = make_pattern();
        let sector: u64 = 512;
        let pos: u64 = 512 + 400; // 912
        let len: usize = 200; // 912..1112 crosses the 1024 boundary

        let got = simulate_read(&pattern, pos, len, sector);
        let want = &pattern[pos as usize..pos as usize + len];
        assert_eq!(got, want, "cross-sector read must return correct bytes");

        let w = compute_aligned_window(pos, len, sector).unwrap();
        assert_eq!(w.aligned_start, 512);
        assert_eq!(w.aligned_end, 1536); // two sectors: 512..1024 and 1024..1536
        assert_eq!(w.inner_offset, 400);
    }

    #[test]
    fn subrange_len_larger_than_one_sector() {
        // len > sector: the window must span multiple sectors.
        let pattern = make_pattern();
        let sector: u64 = 512;
        let pos: u64 = 200; // unaligned start
        let len: usize = 2000; // spans 4+ sectors

        let got = simulate_read(&pattern, pos, len, sector);
        let want = &pattern[pos as usize..pos as usize + len];
        assert_eq!(got, want, "multi-sector span must return correct bytes");

        let w = compute_aligned_window(pos, len, sector).unwrap();
        // aligned_start = 0, aligned_end must cover 200+2000=2200, rounded up to 2560
        assert_eq!(w.aligned_start, 0);
        assert_eq!(w.aligned_end, 2560); // align_up(2200, 512) = 2560
        assert_eq!(w.inner_offset, 200);
    }

    #[test]
    fn subrange_4k_sector_unaligned() {
        // 4096-byte sectors (Advanced Format drives / emulated physical sector).
        let pattern = make_pattern();
        let sector: u64 = 4096;
        let pos: u64 = 4096 + 1337; // unaligned within second sector
        let len: usize = 500;

        let got = simulate_read(&pattern, pos, len, sector);
        let want = &pattern[pos as usize..pos as usize + len];
        assert_eq!(got, want, "4096-byte sector: bytes must match pattern");

        let w = compute_aligned_window(pos, len, sector).unwrap();
        assert_eq!(w.aligned_start, 4096);
        assert_eq!(w.aligned_end, 8192); // 4096+1337+500 = 5933; align_up(5933,4096) = 8192
        assert_eq!(w.inner_offset, 1337);
    }

    #[test]
    fn subrange_max_read_cap() {
        // Simulate what happens when len == MAX_READ (1 MiB). The window must
        // still be sector-aligned and the extracted bytes must match the pattern.
        // We use a small pos offset to exercise the unaligned-start path at scale.
        let pattern = make_pattern();
        let sector: u64 = 512;
        let max_read: usize = 1024 * 1024; // mirrors imp::MAX_READ
        let pos: u64 = 300;
        let len: usize = max_read;

        let w = compute_aligned_window(pos, len, sector).unwrap();
        assert_eq!(w.aligned_start % sector, 0, "aligned_start sector-aligned");
        assert_eq!(w.aligned_end % sector, 0, "aligned_end sector-aligned");

        // Verify the bytes (limit to first 8 KiB to keep the test fast).
        let sample_len = 8192_usize.min(len);
        let got = {
            let as_ = w.aligned_start as usize;
            let ae = w.aligned_end as usize;
            let aligned_buf = &pattern[as_..ae];
            let n = aligned_buf.len(); // full read
            extract_subrange(aligned_buf, n, &w)[..sample_len].to_vec()
        };
        let want = &pattern[pos as usize..pos as usize + sample_len];
        assert_eq!(got, want, "MAX_READ cap: sampled bytes must match pattern");
    }

    // ── extract_subrange: partial-read / end-of-volume coverage ──────────────
    //
    // FIX 2: These tests exercise the shared `extract_subrange` helper directly,
    // covering cases where ReadFile returns FEWER bytes than the aligned window —
    // i.e. exactly the end-of-volume clamping branch that the subrange_* tests
    // above do not reach (those all model n == aligned_len / full windows).
    //
    // Pattern: byte[i] = (i % 251) as u8 (same as above for consistency).
    // Window setup: pos=912, sector=512 → aligned_start=512, aligned_end=1536,
    // inner_offset=400, requested=200, aligned_len=1024.
    // We then vary `n` (simulated ReadFile return value) across all edge cases.

    fn make_extract_window() -> (Vec<u8>, super::AlignedWindow) {
        // pos=912, requested=200, sector=512
        // aligned_start=512, aligned_end=1536, inner_offset=400, requested=200
        // aligned_len = 1024
        let aligned_len: usize = 1024;
        let buf: Vec<u8> = (0..aligned_len).map(|i| (i % 251) as u8).collect();
        let w = super::AlignedWindow {
            aligned_start: 512,
            aligned_end: 1536,
            inner_offset: 400,
            requested: 200,
        };
        (buf, w)
    }

    #[test]
    fn extract_subrange_full_read_returns_correct_bytes() {
        // n == aligned_len: the normal, non-truncated case.
        let (buf, w) = make_extract_window();
        let n = buf.len(); // 1024 — full window
        let result = extract_subrange(&buf, n, &w);
        assert_eq!(result.len(), 200, "full read: must return requested bytes");
        // bytes at inner_offset..inner_offset+200 in the buffer
        let expected = &buf[400..600];
        assert_eq!(result, expected);
    }

    #[test]
    fn extract_subrange_zero_bytes_read_returns_empty() {
        // n == 0: ReadFile returned nothing (e.g. at EOF).
        let (buf, w) = make_extract_window();
        let result = extract_subrange(&buf, 0, &w);
        assert!(result.is_empty(), "n=0 must yield empty slice");
    }

    #[test]
    fn extract_subrange_n_equals_inner_offset_returns_empty() {
        // n == inner_offset: ReadFile reached exactly the start of our desired
        // range — zero useful bytes available.
        let (buf, w) = make_extract_window();
        let n = w.inner_offset; // 400
        let result = extract_subrange(&buf, n, &w);
        assert!(
            result.is_empty(),
            "n == inner_offset must yield empty (available = 0)"
        );
    }

    #[test]
    fn extract_subrange_n_less_than_inner_offset_returns_empty() {
        // n == inner_offset - 1: ReadFile fell short of even reaching our range.
        let (buf, w) = make_extract_window();
        let n = w.inner_offset - 1; // 399
        let result = extract_subrange(&buf, n, &w);
        assert!(
            result.is_empty(),
            "n < inner_offset must yield empty (saturating_sub gives 0)"
        );
    }

    #[test]
    fn extract_subrange_partial_k_bytes() {
        // n == inner_offset + k where k < requested: only k bytes available.
        let (buf, w) = make_extract_window();
        let k: usize = 73; // arbitrary k in (0, 200)
        let n = w.inner_offset + k; // 473
        let result = extract_subrange(&buf, n, &w);
        assert_eq!(result.len(), k, "partial read: must return exactly k bytes");
        let expected = &buf[400..400 + k];
        assert_eq!(result, expected, "partial read: bytes must match buffer");
    }

    #[test]
    fn extract_subrange_k_equals_one() {
        // Edge: k == 1 (minimum nonzero partial return).
        let (buf, w) = make_extract_window();
        let n = w.inner_offset + 1;
        let result = extract_subrange(&buf, n, &w);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], buf[400]);
    }

    #[test]
    fn extract_subrange_k_equals_requested_minus_one() {
        // Edge: k == requested - 1 (one byte short of the full request).
        let (buf, w) = make_extract_window();
        let k = w.requested - 1; // 199
        let n = w.inner_offset + k;
        let result = extract_subrange(&buf, n, &w);
        assert_eq!(result.len(), k);
        assert_eq!(result, &buf[400..400 + k]);
    }
}
