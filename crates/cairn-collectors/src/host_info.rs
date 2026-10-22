//! Host facts for the run manifest (golden rule 7: record host TZ). Read-only
//! registry reads on Windows; empty/offset-only elsewhere.

/// `"<ProductName> <CurrentBuild>.<UBR>"` from
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, e.g.
/// `"Windows 10 Pro 19045.4651"`. Empty when unreadable or off-Windows.
pub fn os_build() -> String {
    #[cfg(windows)]
    {
        win::os_build().unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        String::new()
    }
}

/// Host time zone as `"<TimeZoneKeyName> (UTC+hh:mm)"` on Windows, or just
/// `"UTC+hh:mm"` when the key name is unavailable. The offset is the host's current
/// local offset, so analysts can map UTC output back to the user's wall clock.
pub fn timezone() -> String {
    let offset = format_offset(chrono::Local::now().offset().local_minus_utc());
    #[cfg(windows)]
    {
        if let Some(name) = win::timezone_key_name() {
            return format!("{name} ({offset})");
        }
    }
    offset
}

/// Format a UTC offset in seconds as `UTC+hh:mm` / `UTC-hh:mm`.
fn format_offset(secs: i32) -> String {
    let sign = if secs < 0 { '-' } else { '+' };
    let abs = secs.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
}

#[cfg(windows)]
mod win {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    pub fn os_build() -> Option<String> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .ok()?;
        let product: String = key.get_value("ProductName").ok()?;
        let build: String = key.get_value("CurrentBuild").unwrap_or_default();
        let ubr: Option<u32> = key.get_value("UBR").ok();
        Some(match ubr {
            Some(u) => format!("{product} {build}.{u}"),
            None => format!("{product} {build}"),
        })
    }

    pub fn timezone_key_name() -> Option<String> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
            .ok()?;
        let name: String = key.get_value("TimeZoneKeyName").ok()?;
        let name = name.trim_end_matches('\0').trim().to_string();
        (!name.is_empty()).then_some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_formats_positive_negative_and_zero() {
        assert_eq!(format_offset(8 * 3600), "UTC+08:00");
        assert_eq!(format_offset(-(5 * 3600 + 30 * 60)), "UTC-05:30");
        assert_eq!(format_offset(0), "UTC+00:00");
    }

    #[test]
    fn timezone_always_carries_an_offset() {
        assert!(timezone().contains("UTC"));
    }
}
