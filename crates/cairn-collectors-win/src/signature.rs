//! Authenticode signature verification via WinTrust (WinVerifyTrust). Read-only: opens the
//! file only to verify its embedded signature; never writes. This is a NORMAL call to the
//! public verification API — not signing, hooking, or trust-provider patching (golden rule 1).
//!
//! `verify_file` is total (never panics, never errors): an unverifiable file yields None.
//! Mirrors the host.rs FFI pattern (non-Windows stub + cfg(windows) mod win + SAFETY notes).
use cairn_core::traits::FileVerifier;

/// Verify a file's embedded Authenticode signature.
/// - `Some(true)`  = WinVerifyTrust returned ERROR_SUCCESS (trusted).
/// - `Some(false)` = unsigned or untrusted (any non-zero status).
/// - `None`        = file missing / path unconvertible / off-platform (cannot verify).
#[cfg(not(windows))]
pub fn verify_file(_path: &str) -> Option<bool> {
    None
}

#[cfg(windows)]
pub fn verify_file(path: &str) -> Option<bool> {
    win::verify_file(path)
}

/// A `FileVerifier` backed by `verify_file`. The real default used on Windows.
pub struct WinSigVerifier;

impl FileVerifier for WinSigVerifier {
    fn verify(&self, path: &str) -> Option<bool> {
        verify_file(path)
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::w;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    use windows::Win32::Security::WinTrust::{WINTRUST_CATALOG_INFO, WTD_CHOICE_CATALOG};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };

    /// Encode a path to a NUL-terminated wide string (UTF-16).
    fn wide_nul(path: &str) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn verify_file(path: &str) -> Option<bool> {
        if path.is_empty() || !std::path::Path::new(path).exists() {
            return None;
        }
        let wide = wide_nul(path);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut wtd = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        // Writing a union variant is safe in Rust (only READING union fields is unsafe). The
        // pointer-lifetime guarantee for pFile is stated in the SAFETY comment on the call below.
        wtd.Anonymous.pFile = &mut file_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: wtd/file_info/wide all outlive this call; pcwszFilePath points into the
        // still-owned `wide`; pFile points at the live `file_info`. Null HWND = no UI.
        let status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                std::ptr::addr_of_mut!(wtd).cast(),
            )
        };

        // MUST free the provider state (CLOSE) regardless of the status above.
        // No fallible or panicking steps between VERIFY and CLOSE, so straight-line is correct.
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut close_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: same wtd opened by VERIFY; CLOSE frees its provider state data (hWVTStateData).
        unsafe {
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut close_action,
                std::ptr::addr_of_mut!(wtd).cast(),
            );
        }

        if status == 0 {
            return Some(true); // embedded-signed: fast path, no catalog lookup
        }
        verify_via_catalog(&wide)
    }

    /// RAII: releases a CryptCATAdmin context on drop. Held for the whole catalog lookup;
    /// must outlive any CatInfoCtx (release-catalog needs this admin handle still valid).
    struct CatAdminCtx(isize);
    impl Drop for CatAdminCtx {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid admin context from CryptCATAdminAcquireContext2;
            // released exactly once. dwflags must be 0.
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }

    /// RAII: releases a catalog context on drop. Stores the admin handle because
    /// CryptCATAdminReleaseCatalogContext requires it. Declared AFTER the admin guard so
    /// reverse-declaration drop order frees the catalog context first, then the admin.
    struct CatInfoCtx {
        admin: isize,
        info: isize,
    }
    impl Drop for CatInfoCtx {
        fn drop(&mut self) {
            // SAFETY: admin/info are the valid handles from acquire/enum; released once.
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(self.admin, self.info, 0);
            }
        }
    }

    /// RAII: closes a file handle on drop (mirrors proc.rs ProcHandle).
    struct FileHandle(HANDLE);
    impl Drop for FileHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid handle from CreateFileW; closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Catalog fallback (called when the embedded check failed): returns Some(true) if the
    /// file's hash is found in a system catalog AND that catalog verifies, Some(false) if the
    /// hash is in no catalog (genuinely unsigned) or the catalog rejects it, None on any
    /// infrastructure failure (cannot acquire context / open file / compute hash). Total:
    /// never panics. `wide` is the NUL-terminated UTF-16 file path (reused as the member path).
    fn verify_via_catalog(wide: &[u16]) -> Option<bool> {
        // 1) Acquire a SHA-256 catalog admin context.
        let mut admin_raw: isize = 0;
        // SAFETY: admin_raw is a valid out-param; w!("SHA256") is a 'static NUL-terminated
        // wide literal; other params None. On Err the context is not created (nothing to free).
        let acquired =
            unsafe { CryptCATAdminAcquireContext2(&mut admin_raw, None, w!("SHA256"), None, None) };
        if acquired.is_err() {
            return None;
        }
        let admin = CatAdminCtx(admin_raw);

        // 2) Open the file read-only to compute its hash. GENERIC_READ + SHARE_READ +
        //    OPEN_EXISTING: a read-only stat-and-read, never a write (golden rule 3).
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives this call; params are
        // the verified read-only/open-existing constants; returns an owned handle or Err.
        let hfile = match unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(h) => FileHandle(h),
            Err(_) => return None,
        };

        // 3) Two-stage hash: size probe (pbhash=None) then the actual hash buffer.
        let mut hash_len: u32 = 0;
        // SAFETY: admin.0/hfile.0 valid; pbhash None requests the length into hash_len.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.0, hfile.0, &mut hash_len, None, None)
        }
        .is_err()
            || hash_len == 0
        {
            return None;
        }
        let mut hash = vec![0u8; hash_len as usize];
        // SAFETY: admin.0/hfile.0 valid; hash has hash_len bytes; len is in/out.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.0,
                hfile.0,
                &mut hash_len,
                Some(hash.as_mut_ptr()),
                None,
            )
        }
        .is_err()
        {
            return None;
        }

        // 4) Look the hash up in the system catalog DB. 0 == not in any catalog == unsigned.
        // SAFETY: admin.0 valid; hash is a live slice; other params None.
        let info_raw = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, None, None) };
        if info_raw == 0 {
            return Some(false);
        }
        let catinfo = CatInfoCtx {
            admin: admin.0,
            info: info_raw,
        };

        // 5) Resolve the .cat file path for this catalog context.
        let mut ci = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        // SAFETY: catinfo.info is the valid catalog context; ci is a live out-param.
        if unsafe { CryptCATCatalogInfoFromContext(catinfo.info, &mut ci, 0) }.is_err() {
            return None;
        }

        // 6) Verify the member against its catalog via WinVerifyTrust(WTD_CHOICE_CATALOG).
        let member_tag = hash_to_member_tag(&hash);
        let mut cat_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: PCWSTR(ci.wszCatalogFile.as_ptr()),
            pcwszMemberTag: PCWSTR(member_tag.as_ptr()),
            pcwszMemberFilePath: PCWSTR(wide.as_ptr()),
            pbCalculatedFileHash: hash.as_mut_ptr(),
            // hash_len is the length CalcHashFromFileHandle2 reported; the buffer is sized to
            // it and the API leaves it unchanged on success, so it matches pbCalculatedFileHash.
            cbCalculatedFileHash: hash_len,
            hCatAdmin: catinfo.admin,
            ..Default::default()
        };

        let mut wtd = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_CATALOG,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        wtd.Anonymous.pCatalog = &mut cat_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: wtd/cat_info/ci/member_tag/hash/wide all outlive this call; pCatalog points
        // at the live cat_info; its PCWSTR/hash pointers point into still-owned buffers.
        let cat_status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                std::ptr::addr_of_mut!(wtd).cast(),
            )
        };

        // MUST free provider state (CLOSE) regardless of status — same as the embedded path.
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut close_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: same wtd opened by VERIFY; CLOSE frees its provider state.
        unsafe {
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut close_action,
                std::ptr::addr_of_mut!(wtd).cast(),
            );
        }

        Some(cat_status == 0)
    }

    /// Uppercase hex of the file hash, NUL-terminated UTF-16 — the catalog member tag.
    fn hash_to_member_tag(hash: &[u8]) -> Vec<u16> {
        let mut s = String::with_capacity(hash.len() * 2);
        for b in hash {
            use std::fmt::Write as _;
            let _ = write!(s, "{:02X}", b);
        }
        wide_nul(&s)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_none() {
        assert_eq!(verify_file(r"C:\does\not\exist\nope.exe"), None);
    }

    #[test]
    fn unsigned_junk_is_false() {
        let p = std::env::temp_dir().join(format!("cairn_s2d_unsigned_{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ not a real signed PE, just junk bytes").unwrap();
        let got = verify_file(&p.to_string_lossy());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, Some(false), "unsigned junk must verify as not-trusted");
    }

    #[test]
    fn known_os_binary_does_not_panic() {
        let candidates = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\notepad.exe",
        ];
        for c in candidates {
            if std::path::Path::new(c).exists() {
                let _ = verify_file(c);
                return;
            }
        }
    }

    #[test]
    fn win_verifier_delegates() {
        assert_eq!(WinSigVerifier.verify(r"C:\does\not\exist\nope.exe"), None);
    }

    /// The S2-G fix: a catalog-signed OS binary (svchost has NO embedded signature; it is
    /// catalog-signed) must verify as Some(true) via the catalog fallback. Before S2-G this
    /// returned Some(false) (the false-unsigned report). Guarded by exists() so environments
    /// without this exact path skip rather than fail.
    #[test]
    fn catalog_signed_os_binary_is_true() {
        let candidates = [
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\SearchIndexer.exe",
        ];
        for c in candidates {
            if std::path::Path::new(c).exists() {
                assert_eq!(
                    verify_file(c),
                    Some(true),
                    "catalog-signed OS binary {c} must verify true via the catalog fallback"
                );
                return;
            }
        }
        // No candidate present (unusual): nothing to assert, test passes vacuously.
    }
}
