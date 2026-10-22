//! Authenticode signature verification via WinTrust (WinVerifyTrust) plus signer-name
//! extraction from the embedded signature or, for catalog-signed files, from the system
//! catalog (.cat) that lists the file's hash. Read-only: files are opened only to verify or
//! hash them; nothing is written. These are NORMAL calls to the public verification APIs,
//! not signing, hooking, or trust-provider patching (golden rule 1).
//!
//! Every function here is total (never panics, never errors): an unverifiable file yields
//! None fields. [`SignatureCache`] memoizes [`check_signature`] per path so the proc and
//! persist collectors (which both go through [`WinSigVerifier`]) verify each binary once
//! per run.
use cairn_core::traits::FileVerifier;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub use cairn_core::record::SignerSource;

/// Result of one signature check on one path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureInfo {
    /// `Some(true)` trusted (embedded or catalog), `Some(false)` unsigned/untrusted,
    /// `None` could not verify (missing file, off-platform, API failure).
    pub signed: Option<bool>,
    /// Signer subject display name (certificate CN when present).
    pub signer: Option<String>,
    /// Where `signer` was read from. Always None when `signer` is None.
    pub signer_source: Option<SignerSource>,
}

/// What the catalog lookup found for a file whose embedded signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOutcome {
    /// Infrastructure failure (no admin context, file unreadable, hash failed).
    Unavailable,
    /// The file's hash is in no system catalog.
    NotListed,
    /// The hash is listed; `verified` is the catalog WinVerifyTrust result.
    Listed { verified: bool },
}

/// Decide the final [`SignatureInfo`] from the raw embedded and catalog observations. Pure.
///
/// - Trusted embedded signature: signed, signer from the embedded PKCS#7.
/// - Otherwise `signed` follows the catalog outcome (None / false / verified).
/// - Signer precedence: a verified catalog's signer, then the embedded signer (even if the
///   embedded signature is untrusted: who claims to have signed it is still evidence), then
///   an unverified catalog's signer.
pub fn combine_signature(
    embedded_trusted: bool,
    embedded_signer: Option<String>,
    catalog: CatalogOutcome,
    catalog_signer: Option<String>,
) -> SignatureInfo {
    let embedded = |s: Option<String>| {
        let src = s.as_ref().map(|_| SignerSource::Embedded);
        (s, src)
    };
    if embedded_trusted {
        let (signer, signer_source) = embedded(embedded_signer);
        return SignatureInfo {
            signed: Some(true),
            signer,
            signer_source,
        };
    }
    let signed = match catalog {
        CatalogOutcome::Unavailable => None,
        CatalogOutcome::NotListed => Some(false),
        CatalogOutcome::Listed { verified } => Some(verified),
    };
    let listed = matches!(catalog, CatalogOutcome::Listed { .. });
    let catalog_signer = catalog_signer.filter(|_| listed);
    let (signer, signer_source) = match (signed, catalog_signer, embedded_signer) {
        (Some(true), Some(c), _) => (Some(c), Some(SignerSource::Catalog)),
        (_, _, Some(e)) => embedded(Some(e)),
        (_, Some(c), None) => (Some(c), Some(SignerSource::Catalog)),
        (_, None, None) => (None, None),
    };
    SignatureInfo {
        signed,
        signer,
        signer_source,
    }
}

/// Verify a file's Authenticode signature (embedded, then catalog fallback).
/// - `Some(true)`  = trusted embedded signature, or listed in a catalog that verifies.
/// - `Some(false)` = unsigned or untrusted.
/// - `None`        = file missing / path unconvertible / off-platform (cannot verify).
#[cfg(not(windows))]
pub fn verify_file(_path: &str) -> Option<bool> {
    None
}

#[cfg(windows)]
pub fn verify_file(path: &str) -> Option<bool> {
    win::verify_file(path)
}

/// The EMBEDDED Authenticode signer's subject display name, or None (no embedded sig /
/// unreadable / off-platform). Catalog-signed files return None here; see
/// [`extract_catalog_signer`] and [`check_signature`]. Read-only; never panics.
#[cfg(not(windows))]
pub fn extract_signer(_path: &str) -> Option<String> {
    None
}

#[cfg(windows)]
pub fn extract_signer(path: &str) -> Option<String> {
    win::extract_signer(path)
}

/// The signer of the system catalog that lists this file's hash, or None (not
/// catalog-listed / unreadable / off-platform). Read-only; never panics.
#[cfg(not(windows))]
pub fn extract_catalog_signer(_path: &str) -> Option<String> {
    None
}

#[cfg(windows)]
pub fn extract_catalog_signer(path: &str) -> Option<String> {
    win::extract_catalog_signer(path)
}

/// Full uncached check: trust verdict + signer + where the signer came from.
#[cfg(not(windows))]
pub fn check_signature(_path: &str) -> SignatureInfo {
    SignatureInfo::default()
}

#[cfg(windows)]
pub fn check_signature(path: &str) -> SignatureInfo {
    win::check_signature(path)
}

/// Normalized cache key: Windows paths are case-insensitive and accept `/` as a separator.
pub fn cache_key(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// Thread-safe path -> [`SignatureInfo`] memo. The checker runs outside the lock (WinTrust
/// calls are slow and collectors may run in parallel); a racing duplicate check of the
/// same path is harmless because the result is deterministic.
pub struct SignatureCache {
    map: Mutex<HashMap<String, SignatureInfo>>,
    checker: fn(&str) -> SignatureInfo,
}

impl Default for SignatureCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureCache {
    /// A cache backed by the real [`check_signature`].
    pub fn new() -> Self {
        Self::with_checker(check_signature)
    }

    /// A cache backed by a custom checker (tests inject a fake).
    pub fn with_checker(checker: fn(&str) -> SignatureInfo) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            checker,
        }
    }

    /// The process-wide cache shared by every [`WinSigVerifier`] (proc + persist).
    pub fn global() -> &'static SignatureCache {
        static GLOBAL: OnceLock<SignatureCache> = OnceLock::new();
        GLOBAL.get_or_init(SignatureCache::new)
    }

    /// Cached check of `path`. Empty paths are never checked or cached.
    pub fn get(&self, path: &str) -> SignatureInfo {
        if path.is_empty() {
            return SignatureInfo::default();
        }
        let key = cache_key(path);
        if let Ok(m) = self.map.lock() {
            if let Some(hit) = m.get(&key) {
                return hit.clone();
            }
        }
        let info = (self.checker)(path);
        if let Ok(mut m) = self.map.lock() {
            m.insert(key, info.clone());
        }
        info
    }

    /// Number of distinct paths cached.
    pub fn len(&self) -> usize {
        self.map.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A `FileVerifier` backed by the shared [`SignatureCache::global`]. The real default
/// verifier used on Windows by both the proc and the persist collectors.
pub struct WinSigVerifier;

impl FileVerifier for WinSigVerifier {
    fn verify(&self, path: &str) -> Option<bool> {
        SignatureCache::global().get(path).signed
    }
    fn signer(&self, path: &str) -> Option<String> {
        SignatureCache::global().get(path).signer
    }
    fn signer_source(&self, path: &str) -> Option<SignerSource> {
        SignatureCache::global().get(path).signer_source
    }
}

#[cfg(windows)]
mod win {
    use super::{combine_signature, CatalogOutcome, SignatureInfo};
    use std::ffi::c_void;
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
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
        CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_CONTENT_TYPE_FLAGS,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
        CMSG_SIGNER_CERT_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
        WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows::Win32::Security::WinTrust::{WINTRUST_CATALOG_INFO, WTD_CHOICE_CATALOG};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };

    /// Provider flags for every WinVerifyTrust call: cached URL retrieval only and no
    /// revocation check, so verification never reaches the network.
    const NO_NETWORK_PROV_FLAGS: WINTRUST_DATA_PROVIDER_FLAGS =
        WINTRUST_DATA_PROVIDER_FLAGS(WTD_CACHE_ONLY_URL_RETRIEVAL.0 | WTD_REVOCATION_CHECK_NONE.0);

    /// Encode a path to a NUL-terminated wide string (UTF-16).
    fn wide_nul(path: &str) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Existing, non-empty, LOCAL path as a NUL-terminated wide string; None otherwise.
    /// A remote (UNC / network-share) path is never opened: probing it would make an
    /// SMB connection, which can stall for minutes and would send this host's
    /// credentials to whatever server a hostile persistence entry names.
    fn checkable(path: &str) -> Option<Vec<u16>> {
        if path.is_empty()
            || cairn_core::paths::is_remote_path(path)
            || !std::path::Path::new(path).exists()
        {
            return None;
        }
        Some(wide_nul(path))
    }

    pub fn verify_file(path: &str) -> Option<bool> {
        let wide = checkable(path)?;
        if embedded_trusted(&wide) {
            return Some(true); // embedded-signed: fast path, no catalog lookup
        }
        match catalog_lookup(&wide).0 {
            CatalogOutcome::Unavailable => None,
            CatalogOutcome::NotListed => Some(false),
            CatalogOutcome::Listed { verified } => Some(verified),
        }
    }

    pub fn extract_signer(path: &str) -> Option<String> {
        let wide = checkable(path)?;
        signer_from_file(&wide, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED)
    }

    pub fn extract_catalog_signer(path: &str) -> Option<String> {
        let wide = checkable(path)?;
        let (_, cat_path) = catalog_lookup(&wide);
        signer_from_file(&cat_path?, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED)
    }

    pub fn check_signature(path: &str) -> SignatureInfo {
        let Some(wide) = checkable(path) else {
            return SignatureInfo::default();
        };
        let trusted = embedded_trusted(&wide);
        let embedded_signer = signer_from_file(&wide, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED);
        if trusted {
            return combine_signature(true, embedded_signer, CatalogOutcome::Unavailable, None);
        }
        let (outcome, cat_path) = catalog_lookup(&wide);
        // A .cat file is a PKCS#7 SignedData message (wrapping a CTL), so it is queried as
        // PKCS7_SIGNED, not as an embedded PE signature.
        let catalog_signer = cat_path
            .as_deref()
            .and_then(|p| signer_from_file(p, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED));
        combine_signature(false, embedded_signer, outcome, catalog_signer)
    }

    /// WinVerifyTrust on the file's embedded signature. True only on ERROR_SUCCESS.
    fn embedded_trusted(wide: &[u16]) -> bool {
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
            // Never go to the network (AIA / CRL fetch): no outbound traffic from a
            // triage tool, and no multi-minute stall on a host with dead DNS.
            dwProvFlags: NO_NETWORK_PROV_FLAGS,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        // Writing a union variant is safe in Rust (only READING union fields is unsafe). The
        // pointer-lifetime guarantee for pFile is stated in the SAFETY comment on the call below.
        wtd.Anonymous.pFile = &mut file_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: wtd/file_info/wide all outlive this call; pcwszFilePath points into the
        // caller-owned `wide`; pFile points at the live `file_info`. Null HWND = no UI.
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
        status == 0
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

    /// Catalog lookup (called when the embedded check failed): hash the file, find the
    /// system catalog listing that hash, verify the member against it. Returns the outcome
    /// plus, when listed, the NUL-terminated wide path of the .cat file (copied out of
    /// CATALOG_INFO, so it stays valid after the catalog context is released). Total.
    /// `wide` is the NUL-terminated UTF-16 file path (reused as the member path).
    fn catalog_lookup(wide: &[u16]) -> (CatalogOutcome, Option<Vec<u16>>) {
        const UNAVAILABLE: (CatalogOutcome, Option<Vec<u16>>) = (CatalogOutcome::Unavailable, None);
        // 1) Acquire a SHA-256 catalog admin context.
        let mut admin_raw: isize = 0;
        // SAFETY: admin_raw is a valid out-param; w!("SHA256") is a 'static NUL-terminated
        // wide literal; other params None. On Err the context is not created (nothing to free).
        let acquired =
            unsafe { CryptCATAdminAcquireContext2(&mut admin_raw, None, w!("SHA256"), None, None) };
        if acquired.is_err() {
            return UNAVAILABLE;
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
            Err(_) => return UNAVAILABLE,
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
            return UNAVAILABLE;
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
            return UNAVAILABLE;
        }

        // 4) Look the hash up in the system catalog DB. 0 == not in any catalog == unsigned.
        // SAFETY: admin.0 valid; hash is a live slice; other params None.
        let info_raw = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, None, None) };
        if info_raw == 0 {
            return (CatalogOutcome::NotListed, None);
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
            return UNAVAILABLE;
        }
        // Owned copy of the .cat path, always NUL-terminated (the fixed array is
        // NUL-terminated by the API; we re-terminate defensively at the first NUL or end).
        let cat_len = ci
            .wszCatalogFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ci.wszCatalogFile.len());
        let mut cat_path: Vec<u16> = ci.wszCatalogFile[..cat_len].to_vec();
        cat_path.push(0);

        // 6) Verify the member against its catalog via WinVerifyTrust(WTD_CHOICE_CATALOG).
        let member_tag = hash_to_member_tag(&hash);
        let mut cat_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: PCWSTR(cat_path.as_ptr()),
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
            // Never go to the network (AIA / CRL fetch): no outbound traffic from a
            // triage tool, and no multi-minute stall on a host with dead DNS.
            dwProvFlags: NO_NETWORK_PROV_FLAGS,
            dwUnionChoice: WTD_CHOICE_CATALOG,
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        wtd.Anonymous.pCatalog = &mut cat_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: wtd/cat_info/cat_path/member_tag/hash/wide all outlive this call; pCatalog
        // points at the live cat_info; its PCWSTR/hash pointers point into still-owned buffers.
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

        (
            CatalogOutcome::Listed {
                verified: cat_status == 0,
            },
            Some(cat_path),
        )
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

    /// Signer subject display name of the PKCS#7 message in `wide` (a NUL-terminated
    /// UTF-16 path). `content` selects what the file is: PKCS7_SIGNED_EMBED for a PE's
    /// embedded Authenticode signature, PKCS7_SIGNED for a detached message such as a .cat
    /// catalog. None on any failure. Read-only.
    fn signer_from_file(wide: &[u16], content: CERT_QUERY_CONTENT_TYPE_FLAGS) -> Option<String> {
        let mut store: HCERTSTORE = HCERTSTORE::default();
        let mut msg: *mut c_void = std::ptr::null_mut();
        // SAFETY: wide outlives the call; pvObject points at the NUL-terminated wide path;
        // store/msg are valid out-params. Reads the PKCS#7 only; no write.
        let q = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide.as_ptr() as *const c_void,
                content,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                None,
                None,
                None,
                Some(&mut store),
                Some(&mut msg),
                None,
            )
        };
        if q.is_err() {
            return None; // no signature of the requested kind, or unreadable
        }
        let _store = StoreGuard(store);
        if msg.is_null() {
            return None;
        }
        let _msg = MsgGuard(msg);

        let mut len: u32 = 0;
        // SAFETY: msg valid; pvData None requests the size into len.
        if unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, None, &mut len) }.is_err()
            || len == 0
        {
            return None;
        }
        let mut info = vec![0u8; len as usize];
        // SAFETY: msg valid; info has len bytes; len is in/out.
        if unsafe {
            CryptMsgGetParam(
                msg,
                CMSG_SIGNER_CERT_INFO_PARAM,
                0,
                Some(info.as_mut_ptr() as *mut c_void),
                &mut len,
            )
        }
        .is_err()
        {
            return None;
        }

        // SAFETY: store valid; info holds a CERT_INFO for the duration of this call.
        let cert = unsafe {
            CertFindCertificateInStore(
                store,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(info.as_ptr() as *const c_void),
                None,
            )
        };
        if cert.is_null() {
            return None;
        }
        let _cert = CertGuard(cert as *const CERT_CONTEXT);

        // SAFETY: cert valid; None buffer returns the needed length (incl NUL).
        let n = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
        if n <= 1 {
            return None; // 1 = just the NUL (empty name)
        }
        let mut name = vec![0u16; n as usize];
        // SAFETY: cert valid; name has n u16 slots.
        let written = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name),
            )
        };
        if written <= 1 {
            return None;
        }
        let s = String::from_utf16_lossy(&name[..(written as usize - 1)]);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    struct StoreGuard(HCERTSTORE);
    impl Drop for StoreGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the store opened by CryptQueryObject; closed once.
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }
    struct MsgGuard(*mut c_void);
    impl Drop for MsgGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the non-null PKCS#7 msg handle from CryptQueryObject; closed
            // once. CryptMsgClose takes Option<*const c_void>, so cast from the stored *mut.
            unsafe {
                let _ = CryptMsgClose(Some(self.0 as *const c_void));
            }
        }
    }
    struct CertGuard(*const CERT_CONTEXT);
    impl Drop for CertGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the cert context from CertFindCertificateInStore; freed once.
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_embedded_uses_embedded_signer() {
        let i = combine_signature(
            true,
            Some("Vendor".into()),
            CatalogOutcome::Unavailable,
            None,
        );
        assert_eq!(i.signed, Some(true));
        assert_eq!(i.signer.as_deref(), Some("Vendor"));
        assert_eq!(i.signer_source, Some(SignerSource::Embedded));
    }

    #[test]
    fn verified_catalog_uses_catalog_signer() {
        let i = combine_signature(
            false,
            None,
            CatalogOutcome::Listed { verified: true },
            Some("Microsoft Windows".into()),
        );
        assert_eq!(i.signed, Some(true));
        assert_eq!(i.signer.as_deref(), Some("Microsoft Windows"));
        assert_eq!(i.signer_source, Some(SignerSource::Catalog));
    }

    #[test]
    fn untrusted_embedded_signer_is_kept_and_unsigned_is_empty() {
        let i = combine_signature(
            false,
            Some("Shady Co".into()),
            CatalogOutcome::NotListed,
            None,
        );
        assert_eq!(i.signed, Some(false));
        assert_eq!(i.signer.as_deref(), Some("Shady Co"));
        assert_eq!(i.signer_source, Some(SignerSource::Embedded));

        let none = combine_signature(false, None, CatalogOutcome::NotListed, None);
        assert_eq!(none.signed, Some(false));
        assert_eq!(none.signer, None);
        assert_eq!(none.signer_source, None);

        let unavailable = combine_signature(false, None, CatalogOutcome::Unavailable, None);
        assert_eq!(unavailable, SignatureInfo::default());
    }

    /// A catalog signer is only trusted as "catalog" when the catalog actually lists the
    /// file; an unverified listing still names its signer (signed=false).
    #[test]
    fn catalog_signer_requires_listing() {
        let stray = combine_signature(false, None, CatalogOutcome::NotListed, Some("X".into()));
        assert_eq!(stray.signer, None);
        let unverified = combine_signature(
            false,
            None,
            CatalogOutcome::Listed { verified: false },
            Some("X".into()),
        );
        assert_eq!(unverified.signed, Some(false));
        assert_eq!(unverified.signer_source, Some(SignerSource::Catalog));
    }

    #[test]
    fn cache_key_is_case_and_separator_insensitive() {
        assert_eq!(
            cache_key(r"C:\Windows\System32\CMD.EXE"),
            cache_key("c:/windows/system32/cmd.exe")
        );
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn counting_checker(path: &str) -> SignatureInfo {
        CALLS.fetch_add(1, Ordering::SeqCst);
        SignatureInfo {
            signed: Some(path.contains("good")),
            signer: None,
            signer_source: None,
        }
    }

    #[test]
    fn cache_checks_each_path_once() {
        let c = SignatureCache::with_checker(counting_checker);
        let before = CALLS.load(Ordering::SeqCst);
        assert_eq!(c.get(r"C:\good\a.exe").signed, Some(true));
        assert_eq!(c.get(r"c:\GOOD\A.EXE").signed, Some(true)); // same key
        assert_eq!(c.get(r"C:\bad\b.exe").signed, Some(false));
        assert_eq!(c.get("").signed, None); // never checked
        assert_eq!(CALLS.load(Ordering::SeqCst) - before, 2);
        assert_eq!(c.len(), 2);
        assert!(!c.is_empty());
    }

    /// Off Windows the real verifier abstains on everything.
    #[cfg(not(windows))]
    #[test]
    fn win_verifier_abstains_off_windows() {
        assert_eq!(WinSigVerifier.verify("/bin/sh"), None);
        assert_eq!(WinSigVerifier.signer("/bin/sh"), None);
        assert_eq!(WinSigVerifier.signer_source("/bin/sh"), None);
    }
}

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;

    #[test]
    fn missing_file_is_none() {
        assert_eq!(verify_file(r"C:\does\not\exist\nope.exe"), None);
        assert_eq!(
            check_signature(r"C:\does\not\exist\nope.exe"),
            SignatureInfo::default()
        );
    }

    #[test]
    fn unsigned_junk_is_false() {
        let p = std::env::temp_dir().join(format!("cairn_s2d_unsigned_{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ not a real signed PE, just junk bytes").unwrap();
        let got = verify_file(&p.to_string_lossy());
        let info = check_signature(&p.to_string_lossy());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, Some(false), "unsigned junk must verify as not-trusted");
        assert_eq!(info.signed, Some(false));
        assert_eq!(info.signer, None);
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
        assert_eq!(WinSigVerifier.signer(r"C:\does\not\exist\nope.exe"), None);
    }

    /// The S2-G fix: a catalog-signed OS binary must verify as Some(true) via the catalog
    /// fallback. Guarded by exists() so environments without this exact path skip.
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
    }

    #[test]
    fn extract_signer_missing_is_none() {
        assert_eq!(extract_signer(r"C:\does\not\exist\nope.exe"), None);
        assert_eq!(extract_catalog_signer(r"C:\does\not\exist\nope.exe"), None);
    }

    #[test]
    fn extract_signer_unsigned_junk_is_none() {
        let p = std::env::temp_dir().join(format!("cairn_s2j_{}.exe", std::process::id()));
        std::fs::write(&p, b"MZ junk, no PKCS7").unwrap();
        let got = extract_signer(&p.to_string_lossy());
        let cat = extract_catalog_signer(&p.to_string_lossy());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, None, "unsigned junk has no embedded signer");
        assert_eq!(cat, None, "unsigned junk is in no catalog");
    }

    /// notepad/SearchIndexer are catalog-signed (no embedded PKCS#7): the embedded signer
    /// is None but the full check names the catalog signer with source Catalog.
    /// (svchost.exe is not used: some Win11 builds embed a signature in it.)
    #[test]
    fn catalog_signed_os_binary_gets_catalog_signer() {
        for c in [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\SearchIndexer.exe",
        ] {
            if std::path::Path::new(c).exists() {
                assert_eq!(extract_signer(c), None, "catalog-signed -> no embedded");
                let info = check_signature(c);
                assert_eq!(info.signed, Some(true));
                assert!(info.signer.is_some(), "catalog signer expected for {c}");
                assert_eq!(info.signer_source, Some(SignerSource::Catalog));
                return;
            }
        }
    }
}
