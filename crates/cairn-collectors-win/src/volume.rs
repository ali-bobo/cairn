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
//! buffers one aligned sector internally and returns the requested sub-range.
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
#[inline]
pub(crate) fn align_up(n: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    (n + align - 1) & !(align - 1)
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
    use super::{align_down, align_up, io};
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
    /// and lengths; the implementation buffers one aligned sector and returns
    /// the requested sub-range.
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
        /// 4. Copy the exact sub-range the caller asked for back into `buf`.
        ///
        /// This ensures callers receive the *correct* bytes regardless of alignment.
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let requested = buf.len().min(MAX_READ);
            let end = self.pos + requested as u64;

            let aligned_start = align_down(self.pos, self.sector);
            let aligned_end = align_up(end, self.sector);
            let aligned_len = (aligned_end - aligned_start) as usize;

            // Allocate the aligned window buffer (zeroed).
            let mut tmp = vec![0u8; aligned_len];
            let n = self.read_aligned(aligned_start, &mut tmp)?;

            if n == 0 {
                return Ok(0);
            }

            // Compute the byte offset within the aligned window where pos lives.
            let inner_start = (self.pos - aligned_start) as usize;

            // How many bytes are actually available from pos onward?
            let available = n.saturating_sub(inner_start);
            if available == 0 {
                return Ok(0);
            }

            let to_copy = requested.min(available);
            buf[..to_copy].copy_from_slice(&tmp[inner_start..inner_start + to_copy]);
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
    use super::{align_down, align_up};

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
        assert_eq!(align_up(512, 512), 512);
        assert_eq!(align_up(1024, 512), 1024);
    }

    #[test]
    fn align_up_unaligned() {
        assert_eq!(align_up(1, 512), 512);
        assert_eq!(align_up(513, 512), 1024);
        assert_eq!(align_up(1023, 512), 1024);
    }

    #[test]
    fn align_up_zero() {
        assert_eq!(align_up(0, 512), 0);
        assert_eq!(align_up(0, 4096), 0);
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
}
