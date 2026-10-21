//! Counts the volume shadow copies on the host (`root\cimv2` `Win32_ShadowCopy`).
//!
//! Why: ransomware deletes shadow copies before encrypting (ATT&CK T1490). A client
//! with System Restore turned on but zero shadow copies is worth a look. Read-only WMI
//! query: no shadow copy is created, modified or deleted, and only the `ID` property is
//! requested.
//!
//! Reuses the COM initialization and query helpers of [`crate::wmi`]; failures are
//! errors naming the step and its HRESULT, so the manifest records why the count is
//! missing instead of reporting zero.

use cairn_core::Result;

/// Collector name stamped into errors from this module.
const WHO: &str = "dropscan";

/// Non-Windows: there are no shadow copies to count.
#[cfg(not(windows))]
pub fn shadow_copy_count() -> Result<u32> {
    Err(cairn_core::CairnError::Collector {
        collector: WHO.into(),
        reason: "shadow copy count: unsupported platform".into(),
    })
}

/// Windows: number of `Win32_ShadowCopy` instances. Err (step + HRESULT) on any COM
/// failure; Ok(0) only when WMI answered with no instances.
#[cfg(windows)]
pub fn shadow_copy_count() -> Result<u32> {
    win::shadow_copy_count().map_err(relabel)
}

/// The shared WMI helpers label their errors as the WMI-subscription collector;
/// re-label them as this collector's.
#[cfg(windows)]
fn relabel(e: cairn_core::CairnError) -> cairn_core::CairnError {
    match e {
        cairn_core::CairnError::Collector { reason, .. } => cairn_core::CairnError::Collector {
            collector: WHO.into(),
            reason: format!("shadow copy count: {reason}"),
        },
        other => other,
    }
}

#[cfg(windows)]
mod win {
    use crate::wmi::win::{init_com, query_all};
    use crate::wmi::wmi_error;
    use cairn_core::Result;
    use windows::core::{BSTR, GUID};
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
    use windows::Win32::System::Wmi::{IWbemLocator, IWbemServices};

    const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

    pub fn shadow_copy_count() -> Result<u32> {
        let _com_guard = init_com()?;

        // SAFETY: CLSID_WBEM_LOCATOR is the well-known WbemLocator CLSID; None = no
        // aggregation; CLSCTX_INPROC_SERVER is the standard locator activation context.
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&CLSID_WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| wmi_error("CoCreateInstance(WbemLocator)", e.code().0))?;

        let namespace = BSTR::from(r"root\cimv2");
        let empty = BSTR::new();
        // SAFETY: locator is a valid IWbemLocator; empty BSTRs are the documented
        // "use defaults" for user/password/locale/authority; None for pctx.
        let services: IWbemServices =
            unsafe { locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None) }
                .map_err(|e| wmi_error(r"ConnectServer(root\cimv2)", e.code().0))?;

        let objects = query_all(&services, "SELECT ID FROM Win32_ShadowCopy")?;
        Ok(u32::try_from(objects.len()).unwrap_or(u32::MAX))
    }

    #[cfg(test)]
    mod tests {
        /// Smoke test: the query never panics. An unelevated run may get an access
        /// error, which is an Err, not a panic.
        #[test]
        fn shadow_copy_count_does_not_panic() {
            let _ = super::shadow_copy_count();
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn off_windows_is_an_error_not_zero() {
        assert!(super::shadow_copy_count().is_err());
    }
}
