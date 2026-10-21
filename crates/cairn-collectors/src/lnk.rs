//! Minimal pure-Rust Shell Link (`.lnk`) reader: enough to say what a Startup-folder
//! shortcut actually launches. Format reference: [MS-SHLLINK] "Shell Link (.LNK)
//! Binary File Format" (Microsoft Open Specifications), sections 2.1 ShellLinkHeader,
//! 2.2 LinkTargetIDList, 2.3 LinkInfo, 2.4 StringData, 2.5.4
//! EnvironmentVariableDataBlock.
//!
//! What is read:
//! - LinkInfo `LocalBasePath` (+ `CommonPathSuffix`), preferring the Unicode variants
//!   when the LinkInfo header carries them; otherwise the network share
//!   (`CommonNetworkRelativeLink.NetName` + suffix).
//! - StringData `RELATIVE_PATH`, `WORKING_DIR` and `COMMAND_LINE_ARGUMENTS`.
//! - ExtraData `EnvironmentVariableDataBlock` target (e.g. `%windir%\system32\x.exe`),
//!   used when LinkInfo is absent (IDList-only shortcuts often carry it).
//!
//! The LinkTargetIDList (shell item IDs) is skipped, not decoded: it is optional per the
//! spec and the paths above cover real-world Startup shortcuts.
//!
//! PURE and never panics: every read is bounds-checked; malformed input yields `None`
//! or a partially filled [`LnkInfo`]. Collectors call it on bytes they read read-only.

/// `HeaderSize` must be 0x4C.
const HEADER_SIZE: usize = 0x4C;
/// LinkCLSID 00021401-0000-0000-C000-000000000046 as stored (little-endian GUID).
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// LinkFlags (MS-SHLLINK 2.1.1).
const HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const HAS_LINK_INFO: u32 = 0x0000_0002;
const HAS_NAME: u32 = 0x0000_0004;
const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
const HAS_WORKING_DIR: u32 = 0x0000_0010;
const HAS_ARGUMENTS: u32 = 0x0000_0020;
const HAS_ICON_LOCATION: u32 = 0x0000_0040;
const IS_UNICODE: u32 = 0x0000_0080;
const FORCE_NO_LINK_INFO: u32 = 0x0000_0100;

// LinkInfoFlags (MS-SHLLINK 2.3).
const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x1;
const COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX: u32 = 0x2;

/// EnvironmentVariableDataBlock signature (MS-SHLLINK 2.5.4).
const ENV_BLOCK_SIG: u32 = 0xA000_0001;

/// What a shortcut points at. Every field is optional: a shortcut may carry any subset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LnkInfo {
    /// Absolute target from LinkInfo (local path or `\\server\share\...`).
    pub link_info_path: Option<String>,
    /// StringData RELATIVE_PATH (relative to the .lnk's own folder).
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub arguments: Option<String>,
    /// EnvironmentVariableDataBlock target (unexpanded, e.g. `%ProgramFiles%\x.exe`).
    pub env_target: Option<String>,
}

impl LnkInfo {
    /// Best target path: LinkInfo, then the environment-variable target, then the
    /// relative path resolved against `lnk_dir` (the folder holding the .lnk).
    pub fn target(&self, lnk_dir: &str) -> Option<String> {
        if let Some(p) = &self.link_info_path {
            return Some(p.clone());
        }
        if let Some(p) = &self.env_target {
            return Some(p.clone());
        }
        self.relative_path
            .as_deref()
            .map(|rel| resolve_relative(lnk_dir, rel))
    }
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// NUL-terminated single-byte string at `off` (system code page in the spec; decoded as
/// UTF-8 when valid, else Latin-1 so no byte is lost).
fn cstr_ansi(b: &[u8], off: usize) -> Option<String> {
    let rest = b.get(off..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    Some(decode_ansi(&rest[..end]))
}

/// NUL-terminated UTF-16LE string at `off`.
fn cstr_utf16(b: &[u8], off: usize) -> Option<String> {
    let rest = b.get(off..)?;
    let mut units = Vec::new();
    for pair in rest.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(u);
    }
    None // unterminated
}

fn decode_ansi(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&c| c as char).collect(),
    }
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// Parse a Shell Link. Returns `None` when the header is not a Shell Link header; a
/// truncated body returns whatever was read before the truncation.
pub fn parse_lnk(b: &[u8]) -> Option<LnkInfo> {
    if rd_u32(b, 0)? as usize != HEADER_SIZE || b.get(4..20)? != LINK_CLSID {
        return None;
    }
    let flags = rd_u32(b, 0x14)?;
    let unicode = flags & IS_UNICODE != 0;
    let mut info = LnkInfo::default();
    let mut pos = HEADER_SIZE;

    // 2.2 LinkTargetIDList: IDListSize (u16) + IDList. Skipped.
    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        let Some(n) = rd_u16(b, pos) else {
            return Some(info);
        };
        pos += 2 + n as usize;
    }

    // 2.3 LinkInfo.
    if flags & HAS_LINK_INFO != 0 {
        let Some(size) = rd_u32(b, pos) else {
            return Some(info);
        };
        if let Some(li) = b.get(pos..pos.saturating_add(size as usize)) {
            if flags & FORCE_NO_LINK_INFO == 0 {
                info.link_info_path = non_empty(parse_link_info(li));
            }
        }
        pos = pos.saturating_add(size as usize);
    }

    // 2.4 StringData: CountCharacters (u16) + chars, in this fixed order.
    let read_string = |pos: &mut usize| -> Option<String> {
        let count = rd_u16(b, *pos)? as usize;
        let len = if unicode { count * 2 } else { count };
        let raw = b.get(*pos + 2..*pos + 2 + len)?;
        *pos += 2 + len;
        Some(if unicode {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            decode_ansi(raw)
        })
    };
    for (flag, slot) in [
        (HAS_NAME, 0u8),
        (HAS_RELATIVE_PATH, 1),
        (HAS_WORKING_DIR, 2),
        (HAS_ARGUMENTS, 3),
        (HAS_ICON_LOCATION, 4),
    ] {
        if flags & flag == 0 {
            continue;
        }
        let Some(s) = read_string(&mut pos) else {
            return Some(info); // truncated StringData: keep what we have
        };
        match slot {
            1 => info.relative_path = non_empty(Some(s)),
            2 => info.working_dir = non_empty(Some(s)),
            3 => info.arguments = non_empty(Some(s)),
            _ => {}
        }
    }

    // 2.5 ExtraData: BlockSize (u32) + BlockSignature (u32) + data; ends at size < 4.
    let mut guard = 0;
    while let Some(size) = rd_u32(b, pos) {
        guard += 1;
        if size < 8 || guard > 64 {
            break; // TerminalBlock (size < 4) or nonsense
        }
        if rd_u32(b, pos + 4) == Some(ENV_BLOCK_SIG) {
            // TargetAnsi: 260 bytes at +8; TargetUnicode: 520 bytes at +268.
            let uni = b
                .get(pos + 268..pos + 268 + 520)
                .and_then(|s| cstr_utf16(s, 0));
            let ansi = b.get(pos + 8..pos + 8 + 260).and_then(|s| cstr_ansi(s, 0));
            info.env_target = non_empty(uni).or_else(|| non_empty(ansi));
        }
        pos = pos.saturating_add(size as usize);
    }
    Some(info)
}

/// Resolve the LinkInfo structure (slice starts at LinkInfoSize) to a path.
fn parse_link_info(li: &[u8]) -> Option<String> {
    let header_size = rd_u32(li, 4)? as usize;
    let li_flags = rd_u32(li, 8)?;
    let local_off = rd_u32(li, 0x10)? as usize;
    let cnrl_off = rd_u32(li, 0x14)? as usize;
    let suffix_off = rd_u32(li, 0x18)? as usize;
    // Optional Unicode offsets exist when LinkInfoHeaderSize >= 0x24.
    let (local_off_u, suffix_off_u) = if header_size >= 0x24 {
        (
            rd_u32(li, 0x1C).map(|v| v as usize),
            rd_u32(li, 0x20).map(|v| v as usize),
        )
    } else {
        (None, None)
    };
    let suffix = suffix_off_u
        .filter(|&o| o != 0)
        .and_then(|o| cstr_utf16(li, o))
        .or_else(|| {
            (suffix_off != 0)
                .then(|| cstr_ansi(li, suffix_off))
                .flatten()
        })
        .unwrap_or_default();

    if li_flags & VOLUME_ID_AND_LOCAL_BASE_PATH != 0 {
        let base = local_off_u
            .filter(|&o| o != 0)
            .and_then(|o| cstr_utf16(li, o))
            .or_else(|| (local_off != 0).then(|| cstr_ansi(li, local_off)).flatten());
        if let Some(base) = base.filter(|s| !s.is_empty()) {
            return Some(join_suffix(&base, &suffix));
        }
    }
    if li_flags & COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX != 0 && cnrl_off != 0 {
        // CommonNetworkRelativeLink: Size, Flags, NetNameOffset, DeviceNameOffset,
        // NetworkProviderType, [NetNameOffsetUnicode, DeviceNameOffsetUnicode].
        let cnrl = li.get(cnrl_off..)?;
        let net_off = rd_u32(cnrl, 8)? as usize;
        let net = if net_off > 0x14 {
            rd_u32(cnrl, 0x14).and_then(|o| cstr_utf16(cnrl, o as usize))
        } else {
            None
        }
        .or_else(|| cstr_ansi(cnrl, net_off));
        if let Some(net) = net.filter(|s| !s.is_empty()) {
            return Some(join_suffix(&net, &suffix));
        }
    }
    None
}

fn join_suffix(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        base.to_string()
    } else if base.ends_with('\\') {
        format!("{base}{suffix}")
    } else {
        format!("{base}\\{suffix}")
    }
}

/// Lexically resolve a Windows relative path (`..\..\x.exe`, `.\y`) against `dir`.
/// An already-absolute `rel` (drive or UNC) is returned unchanged.
pub fn resolve_relative(dir: &str, rel: &str) -> String {
    let is_abs = rel.as_bytes().get(1) == Some(&b':') || rel.starts_with("\\\\");
    if is_abs {
        return rel.to_string();
    }
    let mut parts: Vec<&str> = dir.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
    let unc = dir.starts_with("\\\\");
    for seg in rel.split(['\\', '/']) {
        match seg {
            "" | "." => {}
            ".." => {
                // Never pop the drive (`C:`) or the UNC server/share.
                let floor = if unc { 2 } else { 1 };
                if parts.len() > floor {
                    parts.pop();
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("\\");
    if unc {
        format!("\\\\{joined}")
    } else {
        joined
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn utf16z(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }

    fn string_data(s: &str, unicode: bool) -> Vec<u8> {
        let mut v = Vec::new();
        if unicode {
            v.extend_from_slice(&(s.encode_utf16().count() as u16).to_le_bytes());
            v.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
        } else {
            v.extend_from_slice(&(s.len() as u16).to_le_bytes());
            v.extend_from_slice(s.as_bytes());
        }
        v
    }

    fn header(flags: u32) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_SIZE];
        h[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        h[4..20].copy_from_slice(&LINK_CLSID);
        h[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
        h
    }

    /// LinkInfo with an ANSI LocalBasePath (header size 0x1C, no Unicode offsets).
    fn link_info_ansi(local: &str) -> Vec<u8> {
        let hdr = 0x1Cusize;
        let vol_off = hdr;
        let volume_id = {
            // VolumeID: size(0x11), DriveType, DriveSerial, LabelOffset(0x10), label "\0"
            let mut v = Vec::new();
            v.extend_from_slice(&0x11u32.to_le_bytes());
            v.extend_from_slice(&3u32.to_le_bytes());
            v.extend_from_slice(&0x1234u32.to_le_bytes());
            v.extend_from_slice(&0x10u32.to_le_bytes());
            v.push(0);
            v
        };
        let local_off = vol_off + volume_id.len();
        let mut local_bytes = local.as_bytes().to_vec();
        local_bytes.push(0);
        let suffix_off = local_off + local_bytes.len();
        let total = suffix_off + 1;
        let mut li = Vec::new();
        li.extend_from_slice(&(total as u32).to_le_bytes());
        li.extend_from_slice(&(hdr as u32).to_le_bytes());
        li.extend_from_slice(&VOLUME_ID_AND_LOCAL_BASE_PATH.to_le_bytes());
        li.extend_from_slice(&(vol_off as u32).to_le_bytes());
        li.extend_from_slice(&(local_off as u32).to_le_bytes());
        li.extend_from_slice(&0u32.to_le_bytes()); // CNRL offset
        li.extend_from_slice(&(suffix_off as u32).to_le_bytes());
        li.extend_from_slice(&volume_id);
        li.extend_from_slice(&local_bytes);
        li.push(0); // empty CommonPathSuffix
        li
    }

    /// A shortcut built the way Explorer writes one: IDList + LinkInfo + Unicode
    /// StringData (relative path, working dir, arguments).
    pub(crate) fn sample_lnk(target: &str, args: &str) -> Vec<u8> {
        let flags = HAS_LINK_TARGET_ID_LIST
            | HAS_LINK_INFO
            | HAS_RELATIVE_PATH
            | HAS_WORKING_DIR
            | HAS_ARGUMENTS
            | IS_UNICODE;
        let mut b = header(flags);
        // IDList: size 4, one empty TerminalID (2 bytes) + 2 junk bytes we must skip.
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
        b.extend(link_info_ansi(target));
        b.extend(string_data(r"..\..\..\..\..\..\Temp\x.exe", true));
        b.extend(string_data(r"C:\Temp", true));
        b.extend(string_data(args, true));
        b.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        b
    }

    #[test]
    fn parses_link_info_local_path_and_unicode_string_data() {
        let b = sample_lnk(r"C:\Users\Public\evil.exe", "-w hidden -enc AAAA");
        let info = parse_lnk(&b).expect("valid lnk");
        assert_eq!(
            info.link_info_path.as_deref(),
            Some(r"C:\Users\Public\evil.exe")
        );
        assert_eq!(info.arguments.as_deref(), Some("-w hidden -enc AAAA"));
        assert_eq!(info.working_dir.as_deref(), Some(r"C:\Temp"));
        assert_eq!(
            info.target(r"C:\anything").as_deref(),
            Some(r"C:\Users\Public\evil.exe")
        );
    }

    /// No IDList, no LinkInfo: ANSI RELATIVE_PATH + arguments only.
    #[test]
    fn relative_path_only_resolves_against_lnk_dir() {
        let mut b = header(HAS_RELATIVE_PATH | HAS_ARGUMENTS);
        b.extend(string_data(r"..\..\Tools\run.bat", false));
        b.extend(string_data("/q", false));
        let info = parse_lnk(&b).unwrap();
        assert_eq!(info.link_info_path, None);
        assert_eq!(
            info.target(r"C:\Users\v\Start Menu\Startup").as_deref(),
            Some(r"C:\Users\v\Tools\run.bat")
        );
        assert_eq!(info.arguments.as_deref(), Some("/q"));
    }

    /// Unicode LinkInfo offsets (header size 0x24) win over the ANSI ones, and a
    /// CommonPathSuffix is appended.
    #[test]
    fn link_info_unicode_offsets_and_suffix() {
        let hdr = 0x24usize;
        let ansi_off = hdr;
        let ansi = b"C:\\WRONG\0".to_vec();
        let uni_off = ansi_off + ansi.len();
        let uni = utf16z(r"C:\Prog Files\Ünï");
        let suf_off_u = uni_off + uni.len();
        let suf = utf16z("app.exe");
        let total = suf_off_u + suf.len();
        let mut li = Vec::new();
        for v in [
            total as u32,
            hdr as u32,
            VOLUME_ID_AND_LOCAL_BASE_PATH,
            0, // VolumeIDOffset (unused by us)
            ansi_off as u32,
            0,
            0, // ANSI suffix offset 0 -> none
            uni_off as u32,
            suf_off_u as u32,
        ] {
            li.extend_from_slice(&v.to_le_bytes());
        }
        li.extend_from_slice(&ansi);
        li.extend_from_slice(&uni);
        li.extend_from_slice(&suf);
        let mut b = header(HAS_LINK_INFO | IS_UNICODE);
        b.extend(li);
        let info = parse_lnk(&b).unwrap();
        assert_eq!(
            info.link_info_path.as_deref(),
            Some(r"C:\Prog Files\Ünï\app.exe")
        );
    }

    /// IDList-only shortcut whose target is in an EnvironmentVariableDataBlock.
    #[test]
    fn environment_variable_block_target() {
        let mut b = header(HAS_LINK_TARGET_ID_LIST | HAS_ARGUMENTS | IS_UNICODE);
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend(string_data("-nop", true));
        let mut blk = vec![0u8; 0x314];
        blk[0..4].copy_from_slice(&0x314u32.to_le_bytes());
        blk[4..8].copy_from_slice(&ENV_BLOCK_SIG.to_le_bytes());
        let t = r"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe";
        blk[8..8 + t.len()].copy_from_slice(t.as_bytes());
        let tu = utf16z(t);
        blk[268..268 + tu.len()].copy_from_slice(&tu);
        b.extend(blk);
        b.extend_from_slice(&0u32.to_le_bytes());
        let info = parse_lnk(&b).unwrap();
        assert_eq!(info.target("C:\\x").as_deref(), Some(t));
        assert_eq!(info.arguments.as_deref(), Some("-nop"));
    }

    /// ForceNoLinkInfo makes the LinkInfo path ignored.
    #[test]
    fn force_no_link_info_ignores_link_info() {
        let mut b = header(HAS_LINK_INFO | FORCE_NO_LINK_INFO);
        b.extend(link_info_ansi(r"C:\x.exe"));
        assert_eq!(parse_lnk(&b).unwrap().link_info_path, None);
    }

    #[test]
    fn non_lnk_and_truncated_inputs_never_panic() {
        assert_eq!(parse_lnk(b""), None);
        assert_eq!(parse_lnk(b"not a shortcut at all, just text"), None);
        let full = sample_lnk(r"C:\a\b.exe", "x");
        for n in 0..full.len() {
            let _ = parse_lnk(&full[..n]);
        }
        // Absurd sizes in every length field must not panic or loop.
        let mut b = header(0xFFFF_FFFF);
        b.extend_from_slice(&[0xFF; 64]);
        let _ = parse_lnk(&b);
    }

    #[test]
    fn resolve_relative_never_climbs_above_root() {
        assert_eq!(resolve_relative(r"C:\a\b", r"..\..\..\x.exe"), r"C:\x.exe");
        assert_eq!(resolve_relative(r"C:\a", r".\y\z.exe"), r"C:\a\y\z.exe");
        assert_eq!(resolve_relative(r"C:\a", r"D:\abs.exe"), r"D:\abs.exe");
        assert_eq!(
            resolve_relative(r"\\srv\share\d", r"..\..\x"),
            r"\\srv\share\x"
        );
    }
}
