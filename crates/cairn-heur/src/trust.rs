//! Centralized "this is normal" knowledge (spec §5b). Analyzers MUST use these
//! instead of re-deriving path/name trust locally — the whack-a-mole suppression
//! patches of S2 (TRUSTED_APPDATA, inbox-service, winlogon-default, correlation
//! matrix) all came from NOT having this module.
//!
//! Existing trust fns stay in score.rs and are re-exported here so analyzers have
//! ONE import surface: `use crate::trust::*;`.
pub use crate::score::{
    is_inbox_service_command, is_trusted_appdata_location, winlogon_value_is_default,
};

/// System-binary names an attacker plants outside C:\Windows to masquerade (S3).
/// Matched against the lowercased basename.
pub const PROTECTED_SYSTEM_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "rundll32.exe", "dllhost.exe",
    "taskhostw.exe",
];

/// Directories a non-admin user can write to — the drop zones (S2/S4 ingredient).
/// Deliberately excludes the broad `\appdata\` (legitimate per-user installs live in
/// `\AppData\Local\<vendor>\`); Roaming and Temp stay in.
pub const USER_WRITABLE_DIRS: &[&str] = &[
    r"\temp\",
    r"\appdata\roaming\",
    r"\appdata\local\temp\",
    r"\downloads\",
    r"\public\",
    r"\programdata\",
];

/// True if `path` (any case) contains a user-writable drop-zone segment.
pub fn is_user_writable_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    USER_WRITABLE_DIRS.iter().any(|d| lower.contains(d))
}

/// True if `path` is an absolute path under the Windows tree on ANY drive
/// (`X:\Windows\...`). Covers System32 / SysWOW64 / WinSxS / the Windows root —
/// all locations where system-named binaries legitimately live (explorer.exe sits
/// in C:\Windows directly, not System32).
pub fn is_under_windows_tree(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // position 1 == drive-colon form "x:\windows\"
    lower.get(1..).is_some_and(|rest| rest.starts_with(r":\windows\"))
}

/// True if `path` is under the Windows tree or Program Files (either bitness).
/// Both require admin to write — "system or vendor-installed" trust tier (S4 gate).
pub fn is_system_or_program_files(path: &str) -> bool {
    if is_under_windows_tree(path) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.get(1..).is_some_and(|rest| rest.starts_with(r":\program files"))
}

/// S3: a protected system name at an ABSOLUTE path outside the Windows tree.
/// Relative/bare paths return false — no location info means no masquerade verdict
/// (honest abstain; the winlogon default `explorer.exe` is a bare name).
pub fn is_masquerade(path: &str) -> bool {
    if !path.get(1..).is_some_and(|r| r.starts_with(":\\")) {
        return false; // not absolute — abstain
    }
    if is_under_windows_tree(path) {
        return false;
    }
    let base = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    PROTECTED_SYSTEM_NAMES.contains(&base.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_writable_hits_dropzones_not_vendor_appdata() {
        assert!(is_user_writable_path(r"C:\Users\a\AppData\Roaming\evil.exe"));
        assert!(is_user_writable_path(r"C:\Users\a\Downloads\x.exe"));
        assert!(is_user_writable_path(r"C:\ProgramData\x\evil.exe"));
        assert!(!is_user_writable_path(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"));
        assert!(!is_user_writable_path(r"C:\Program Files\X\x.exe"));
    }

    #[test]
    fn windows_tree_covers_root_system32_syswow64_any_drive() {
        assert!(is_under_windows_tree(r"C:\Windows\explorer.exe"));
        assert!(is_under_windows_tree(r"C:\WINDOWS\System32\svchost.exe"));
        assert!(is_under_windows_tree(r"D:\Windows\SysWOW64\svchost.exe"));
        assert!(!is_under_windows_tree(r"C:\Windows2\evil.exe"));
        assert!(!is_under_windows_tree("explorer.exe")); // relative — not under tree
    }

    #[test]
    fn system_or_pf_includes_both_program_files() {
        assert!(is_system_or_program_files(r"C:\Program Files\V\v.exe"));
        assert!(is_system_or_program_files(r"C:\Program Files (x86)\V\v.exe"));
        assert!(is_system_or_program_files(r"C:\Windows\System32\a.exe"));
        assert!(!is_system_or_program_files(r"C:\Users\a\AppData\Local\P\p.exe"));
    }

    #[test]
    fn masquerade_fires_only_on_absolute_paths_outside_windows() {
        assert!(is_masquerade(r"C:\Users\a\AppData\Roaming\svchost.exe"));
        assert!(is_masquerade(r"C:\ProgramData\lsass.exe"));
        assert!(!is_masquerade(r"C:\Windows\System32\svchost.exe"));
        assert!(!is_masquerade(r"C:\Windows\explorer.exe"));
        assert!(!is_masquerade("explorer.exe")); // bare name — abstain
        assert!(!is_masquerade(r"C:\Users\a\AppData\Roaming\notmalware.exe")); // not protected name
    }
}
