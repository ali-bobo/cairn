//! Reads WMI permanent event subscriptions (`root\subscription` namespace):
//! __EventFilter, __EventConsumer (CommandLineEventConsumer /
//! ActiveScriptEventConsumer), and __FilterToConsumerBinding.
//!
//! Why: WMI event subscriptions are a common fileless persistence mechanism —
//! a filter (WQL trigger condition) bound to a consumer (action taken) survives
//! reboots without any file on disk. This is read-only WMI querying; no
//! subscriptions are created, modified, or deleted.
//!
//! Hand-rolled COM call chain (CoInitializeEx -> CoCreateInstance -> ConnectServer
//! -> ExecQuery -> IWbemClassObject::Get) rather than the `wmi` crate — see
//! docs/dev-history/2026-07-16-wmi-persistence-research.md for why (the `wmi`
//! crate has a known, unresolved (WONTFIX) UB issue mixing its own COM lifecycle
//! management with windows-rs's).

use cairn_core::Result;

/// One WMI event consumer bound to a filter, as read from the OS.
#[derive(Debug, Clone)]
pub struct RawWmiSubscription {
    pub filter_name: String,
    pub filter_query: String,
    pub consumer_name: String,
    /// "CommandLineEventConsumer" | "ActiveScriptEventConsumer" | other consumer class name
    pub consumer_type: String,
    /// CommandLineTemplate (CommandLineEventConsumer) or ScriptText (ActiveScriptEventConsumer)
    pub command: Option<String>,
}

/// Non-Windows: empty (WMI is Windows-only).
#[cfg(not(windows))]
pub fn enumerate_subscriptions() -> Result<Vec<RawWmiSubscription>> {
    Ok(vec![])
}

#[cfg(windows)]
pub fn enumerate_subscriptions() -> Result<Vec<RawWmiSubscription>> {
    win::enumerate_subscriptions()
}

#[cfg(windows)]
mod win {
    use super::RawWmiSubscription;
    use cairn_core::Result;
    use windows::core::{BSTR, GUID, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoUninitialize,
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE,
    };

    const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

    /// RAII guard: calls CoUninitialize on drop. Every `enumerate_subscriptions`
    /// call owns exactly one Initialize/Uninitialize pair on this thread — never
    /// assumes the caller's thread has already initialized COM, and never leaves
    /// COM initialized after returning (whether success or failure).
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            // SAFETY: CoUninitialize must be called once per successful
            // CoInitializeEx on the same thread; ComGuard is only constructed
            // after a successful CoInitializeEx call (see init_com below).
            unsafe {
                CoUninitialize();
            }
        }
    }

    /// Initializes COM on this thread (COINIT_MULTITHREADED) and installs
    /// process-wide default security. Returns None (abstain) rather than panic
    /// on any failure — WMI querying is best-effort inventory, not critical path.
    fn init_com() -> Option<ComGuard> {
        // SAFETY: pvreserved must be None per the Windows API contract; return
        // value is a bare HRESULT where S_FALSE (already initialized on this
        // thread) is not an error condition, only genuine failure HRESULTs are.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() {
            return None;
        }
        let guard = ComGuard;

        // SAFETY: all Option-typed params are documented as nullable; called
        // exactly once per process per Microsoft's API contract (best-effort:
        // if a prior call already set security, this returns an error we
        // tolerate rather than abstain on, since querying can still proceed).
        let _ = unsafe {
            CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            )
        };
        Some(guard)
    }

    /// Reads a BSTR property from a WMI object by name. None on any failure
    /// (missing property, wrong VARIANT type, empty value) — never panics.
    fn get_bstr_prop(obj: &IWbemClassObject, name: &str) -> Option<String> {
        let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut val = VARIANT::default();
        // SAFETY: obj is a valid IWbemClassObject from a successful ExecQuery
        // enumeration; wname is NUL-terminated; val is a local out-param.
        let ok = unsafe { obj.Get(PCWSTR(wname.as_ptr()), 0, &mut val, None, None) };
        if ok.is_err() {
            return None;
        }
        let bstr: windows::core::Result<BSTR> = (&val).try_into();
        bstr.ok().map(|b| b.to_string())
    }

    pub fn enumerate_subscriptions() -> Result<Vec<RawWmiSubscription>> {
        let Some(_com_guard) = init_com() else {
            // Graceful degrade: COM unavailable on this host/thread -> empty
            // result, not an error (golden rule 8). The caller's manifest
            // should record this via the Collector::sources() error path.
            return Ok(vec![]);
        };

        // SAFETY: CLSID_WBEM_LOCATOR is a valid, well-known WMI CLSID; None
        // means no aggregation; CLSCTX_INPROC_SERVER requests an in-process
        // COM server, the standard WMI locator activation context.
        let locator: IWbemLocator =
            match unsafe { CoCreateInstance(&CLSID_WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER) } {
                Ok(l) => l,
                Err(_) => return Ok(vec![]), // abstain: WMI locator unavailable
            };

        let namespace = BSTR::from(r"root\subscription");
        let empty = BSTR::new();
        // SAFETY: locator is a valid IWbemLocator from CoCreateInstance above;
        // all BSTR params are valid (empty BSTR is a documented way to pass
        // "use defaults" for user/password/locale/authority); None for pctx.
        let services: IWbemServices = match unsafe {
            locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None)
        } {
            Ok(s) => s,
            Err(_) => return Ok(vec![]), // abstain: namespace unavailable/access denied
        };

        let mut out = Vec::new();
        out.extend(query_bindings(&services)?);
        Ok(out)
    }

    /// Queries __FilterToConsumerBinding, then for each binding resolves the
    /// bound __EventFilter and consumer object to build a RawWmiSubscription.
    fn query_bindings(services: &IWbemServices) -> Result<Vec<RawWmiSubscription>> {
        let wql = BSTR::from("SELECT * FROM __FilterToConsumerBinding");
        let query_lang = BSTR::from("WQL");
        let flags = WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY;
        // SAFETY: services is a valid IWbemServices from ConnectServer above;
        // query_lang/wql are valid BSTRs; None for pctx.
        let enumerator = match unsafe { services.ExecQuery(&query_lang, &wql, flags, None) } {
            Ok(e) => e,
            Err(_) => return Ok(vec![]), // abstain: query failed
        };

        let mut out = Vec::new();
        loop {
            let mut objects: [Option<IWbemClassObject>; 1] = [None];
            let mut returned: u32 = 0;
            // SAFETY: enumerator is valid; objects is a 1-element buffer sized
            // to match apobjects.len(); returned is a valid out-param.
            let hr = unsafe { enumerator.Next(-1, &mut objects, &mut returned) };
            if hr.is_err() || returned == 0 {
                break;
            }
            let Some(binding_obj) = objects[0].take() else {
                break;
            };

            let Some(filter_ref) = get_bstr_prop(&binding_obj, "Filter") else {
                continue; // abstain on this one binding, keep scanning others
            };
            let Some(consumer_ref) = get_bstr_prop(&binding_obj, "Consumer") else {
                continue;
            };

            if let Some(sub) = resolve_subscription(services, &filter_ref, &consumer_ref) {
                out.push(sub);
            }
        }
        Ok(out)
    }

    /// Resolves a binding's Filter/Consumer path references (WMI relative-path
    /// strings like `__EventFilter.Name="X"`) into a full RawWmiSubscription by
    /// re-querying each referenced object directly.
    fn resolve_subscription(
        services: &IWbemServices,
        filter_ref: &str,
        consumer_ref: &str,
    ) -> Option<RawWmiSubscription> {
        let filter_obj = get_object_by_path(services, filter_ref)?;
        let filter_name = get_bstr_prop(&filter_obj, "Name").unwrap_or_default();
        let filter_query = get_bstr_prop(&filter_obj, "Query").unwrap_or_default();

        let consumer_obj = get_object_by_path(services, consumer_ref)?;
        let consumer_name = get_bstr_prop(&consumer_obj, "Name").unwrap_or_default();
        // consumer_ref looks like: CommandLineEventConsumer.Name="X"
        let consumer_type = consumer_ref
            .split('.')
            .next()
            .unwrap_or("unknown")
            .to_string();
        let command = get_bstr_prop(&consumer_obj, "CommandLineTemplate")
            .or_else(|| get_bstr_prop(&consumer_obj, "ScriptText"));

        Some(RawWmiSubscription {
            filter_name,
            filter_query,
            consumer_name,
            consumer_type,
            command,
        })
    }

    /// GetObject by a WMI relative path string (e.g. `__EventFilter.Name="X"`).
    ///
    /// Real signature (verified against windows-0.62.2 source, differs from
    /// the initial guess): `GetObject` returns `Result<()>`, not
    /// `Result<IWbemClassObject>` — the resolved object comes back through an
    /// out-param pointer `ppobject: Option<*mut Option<IWbemClassObject>>`,
    /// and `lflags` is the typed `WBEM_GENERIC_FLAG_TYPE`, not a bare `i32`
    /// (see `windows::Win32::System::Wmi::mod.rs:8492`).
    fn get_object_by_path(services: &IWbemServices, path: &str) -> Option<IWbemClassObject> {
        let wpath = BSTR::from(path);
        let mut out: Option<IWbemClassObject> = None;
        // SAFETY: services valid; wpath is a valid BSTR; `out` is a valid
        // local out-param pointer; None for context/call-result.
        let hr = unsafe {
            services.GetObject(
                &wpath,
                WBEM_GENERIC_FLAG_TYPE(0),
                None,
                Some(&mut out),
                None,
            )
        };
        if hr.is_err() {
            return None;
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Smoke test: enumerate_subscriptions never panics and returns
        /// Ok(...) even on a machine with zero WMI subscriptions configured
        /// (the common case — this must not be misread as a failure).
        #[test]
        fn enumerate_subscriptions_does_not_panic() {
            let result = enumerate_subscriptions();
            assert!(
                result.is_ok(),
                "enumerate_subscriptions must not error on a clean host"
            );
        }
    }
}
