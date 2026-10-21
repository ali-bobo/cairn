//! Reads WMI permanent event subscriptions (`root\subscription` namespace):
//! __EventFilter, __EventConsumer (CommandLineEventConsumer /
//! ActiveScriptEventConsumer / ...), and __FilterToConsumerBinding.
//!
//! Why: WMI event subscriptions are a common fileless persistence mechanism —
//! a filter (WQL trigger condition) bound to a consumer (action taken) survives
//! reboots without any file on disk. This is read-only WMI querying; no
//! subscriptions are created, modified, or deleted.
//!
//! All filters, all consumers and all bindings are listed with three WQL queries and
//! joined by the pure [`join_subscriptions`]: bound pairs come out with `bound: true`,
//! and filters or consumers that no binding references (orphaned leftovers, or a
//! half-installed subscription) come out on their own with `bound: false`.
//!
//! Failures are errors, not empty results: every COM / ConnectServer / ExecQuery /
//! enumeration failure returns `Err` naming the step and its HRESULT, so the manifest
//! records why WMI produced nothing instead of looking like a clean host.
//!
//! Hand-rolled COM call chain (CoInitializeEx -> CoCreateInstance -> ConnectServer
//! -> ExecQuery -> IWbemClassObject::Get) rather than the `wmi` crate, because the
//! `wmi` crate has a known, unresolved (WONTFIX) UB issue mixing its own COM lifecycle
//! management with windows-rs's.

use cairn_core::{CairnError, Result};

/// One WMI subscription entry as read from the OS: a bound filter+consumer pair, or an
/// unbound filter (consumer fields empty) or unbound consumer (filter fields empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWmiSubscription {
    pub filter_name: String,
    pub filter_query: String,
    pub consumer_name: String,
    /// "CommandLineEventConsumer" | "ActiveScriptEventConsumer" | other consumer class name;
    /// empty for an unbound filter.
    pub consumer_type: String,
    /// CommandLineTemplate / ExecutablePath (CommandLineEventConsumer) or ScriptText /
    /// ScriptFileName (ActiveScriptEventConsumer).
    pub command: Option<String>,
    /// True when a __FilterToConsumerBinding joins this filter and consumer.
    pub bound: bool,
}

/// One __EventFilter instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFilter {
    pub name: String,
    pub query: String,
}

/// One __EventConsumer-derived instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawConsumer {
    /// The concrete class (`__CLASS`), e.g. "CommandLineEventConsumer".
    pub class: String,
    pub name: String,
    pub command: Option<String>,
}

/// One __FilterToConsumerBinding: its Filter and Consumer reference paths, e.g.
/// `__EventFilter.Name="X"` and `CommandLineEventConsumer.Name="Y"` (possibly prefixed
/// by `\\HOST\root\subscription:`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBinding {
    pub filter_ref: String,
    pub consumer_ref: String,
}

/// Split a WMI object reference path into (class, Name key). Accepts an optional
/// `\\server\namespace:` prefix and unescapes `\"` / `\\` inside the quoted name.
/// None when the path has no `.Name="..."` key. Pure.
pub fn parse_object_ref(path: &str) -> Option<(String, String)> {
    let key_at = path.find(".Name=\"")?;
    let head = &path[..key_at];
    let class = head.rsplit(':').next().unwrap_or(head).trim();
    let rest = &path[key_at + ".Name=\"".len()..];
    let mut name = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '\\' => name.push(chars.next()?),
            '"' => break,
            c => name.push(c),
        }
    }
    if class.is_empty() {
        return None;
    }
    Some((class.to_string(), name))
}

/// Join filters, consumers and bindings. Bound pairs (in binding order) first, then
/// unbound filters, then unbound consumers. Names compare case-insensitively (WMI key
/// values are case-insensitive). A binding whose filter or consumer instance was not
/// listed is still emitted from its reference path (query/command unknown). Pure.
pub fn join_subscriptions(
    filters: &[RawFilter],
    consumers: &[RawConsumer],
    bindings: &[RawBinding],
) -> Vec<RawWmiSubscription> {
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let mut filter_used = vec![false; filters.len()];
    let mut consumer_used = vec![false; consumers.len()];
    let mut out = Vec::new();

    for b in bindings {
        let Some((_, fname)) = parse_object_ref(&b.filter_ref) else {
            continue;
        };
        let Some((cclass, cname)) = parse_object_ref(&b.consumer_ref) else {
            continue;
        };
        let fi = filters.iter().position(|f| eq(&f.name, &fname));
        let ci = consumers
            .iter()
            .position(|c| eq(&c.name, &cname) && eq(&c.class, &cclass));
        if let Some(i) = fi {
            filter_used[i] = true;
        }
        if let Some(i) = ci {
            consumer_used[i] = true;
        }
        let f = fi.map(|i| &filters[i]);
        let c = ci.map(|i| &consumers[i]);
        out.push(RawWmiSubscription {
            filter_name: f.map(|f| f.name.clone()).unwrap_or(fname),
            filter_query: f.map(|f| f.query.clone()).unwrap_or_default(),
            consumer_name: c.map(|c| c.name.clone()).unwrap_or(cname),
            consumer_type: c.map(|c| c.class.clone()).unwrap_or(cclass),
            command: c.and_then(|c| c.command.clone()),
            bound: true,
        });
    }
    for (f, _) in filters.iter().zip(&filter_used).filter(|(_, used)| !**used) {
        out.push(RawWmiSubscription {
            filter_name: f.name.clone(),
            filter_query: f.query.clone(),
            consumer_name: String::new(),
            consumer_type: String::new(),
            command: None,
            bound: false,
        });
    }
    for (c, _) in consumers
        .iter()
        .zip(&consumer_used)
        .filter(|(_, used)| !**used)
    {
        out.push(RawWmiSubscription {
            filter_name: String::new(),
            filter_query: String::new(),
            consumer_name: c.name.clone(),
            consumer_type: c.class.clone(),
            command: c.command.clone(),
            bound: false,
        });
    }
    out
}

/// The collector error for a failed WMI step, carrying the step name and HRESULT. Pure.
pub fn wmi_error(step: &str, hresult: i32) -> CairnError {
    CairnError::Collector {
        collector: "wmi_subscription".into(),
        reason: format!("{step} failed: HRESULT 0x{:08X}", hresult as u32),
    }
}

/// Non-Windows: empty (WMI is Windows-only).
#[cfg(not(windows))]
pub fn enumerate_subscriptions() -> Result<Vec<RawWmiSubscription>> {
    Ok(vec![])
}

/// Windows: list filters, consumers and bindings in `root\subscription` and join them.
/// Err (step + HRESULT) on any COM failure; Ok(empty) only for a host that genuinely has
/// no subscriptions.
#[cfg(windows)]
pub fn enumerate_subscriptions() -> Result<Vec<RawWmiSubscription>> {
    win::enumerate_subscriptions()
}

#[cfg(windows)]
mod win {
    use super::RawWmiSubscription;
    use super::{join_subscriptions, wmi_error, RawBinding, RawConsumer, RawFilter};
    use cairn_core::Result;
    use windows::core::{BSTR, GUID, PCWSTR};
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoUninitialize,
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY,
    };

    const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

    /// RAII guard: calls CoUninitialize on drop. Constructed ONLY after a CoInitializeEx
    /// call that succeeded (S_OK or S_FALSE), so every guard matches exactly one
    /// successful initialize on this thread and COM is never left initialized by us.
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            // SAFETY: one CoUninitialize per successful CoInitializeEx on the same thread
            // (see the construction invariant above).
            unsafe {
                CoUninitialize();
            }
        }
    }

    /// Initializes COM on this thread (COINIT_MULTITHREADED) and installs process-wide
    /// default security. Ok(None) when the thread already has an incompatible apartment
    /// (RPC_E_CHANGED_MODE): COM is usable but the initialize is not ours to undo.
    fn init_com() -> Result<Option<ComGuard>> {
        // SAFETY: pvreserved must be None per the API contract. S_FALSE (already
        // initialized in this mode) is success and still owes a CoUninitialize.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let guard = if hr == RPC_E_CHANGED_MODE {
            None
        } else if hr.is_err() {
            return Err(wmi_error("CoInitializeEx", hr.0));
        } else {
            Some(ComGuard)
        };

        // SAFETY: all Option-typed params are documented as nullable. Best-effort: if a
        // prior call already set process security this returns RPC_E_TOO_LATE, which we
        // tolerate because querying can still proceed with the existing settings.
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
        Ok(guard)
    }

    /// Reads a BSTR property from a WMI object by name. None on any failure
    /// (missing property, NULL / non-string VARIANT, empty value) — never panics.
    fn get_bstr_prop(obj: &IWbemClassObject, name: &str) -> Option<String> {
        let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut val = VARIANT::default();
        // SAFETY: obj is a valid IWbemClassObject from a successful enumeration; wname is
        // NUL-terminated; val is a local out-param (VARIANT's Drop clears it).
        let ok = unsafe { obj.Get(PCWSTR(wname.as_ptr()), 0, &mut val, None, None) };
        if ok.is_err() {
            return None;
        }
        let bstr: windows::core::Result<BSTR> = (&val).try_into();
        bstr.ok().map(|b| b.to_string()).filter(|s| !s.is_empty())
    }

    /// Runs one WQL query and collects every returned object. Err names the step.
    fn query_all(services: &IWbemServices, wql: &str) -> Result<Vec<IWbemClassObject>> {
        let wql_b = BSTR::from(wql);
        let lang = BSTR::from("WQL");
        let flags = WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY;
        // SAFETY: services is a valid IWbemServices from ConnectServer; lang/wql_b are
        // valid BSTRs that outlive the call; None for pctx.
        let enumerator = unsafe { services.ExecQuery(&lang, &wql_b, flags, None) }
            .map_err(|e| wmi_error(&format!("ExecQuery({wql})"), e.code().0))?;

        let mut out = Vec::new();
        loop {
            let mut objects: [Option<IWbemClassObject>; 1] = [None];
            let mut returned: u32 = 0;
            // SAFETY: enumerator is valid; objects is a 1-element buffer matching the
            // slice length the binding passes; returned is a valid out-param.
            let hr = unsafe { enumerator.Next(-1, &mut objects, &mut returned) };
            if hr.is_err() {
                return Err(wmi_error(
                    &format!("IEnumWbemClassObject::Next({wql})"),
                    hr.0,
                ));
            }
            if returned == 0 {
                break; // WBEM_S_FALSE: enumeration complete
            }
            match objects[0].take() {
                Some(o) => out.push(o),
                None => break,
            }
        }
        Ok(out)
    }

    pub fn enumerate_subscriptions() -> Result<Vec<RawWmiSubscription>> {
        let _com_guard = init_com()?;

        // SAFETY: CLSID_WBEM_LOCATOR is the well-known WbemLocator CLSID; None = no
        // aggregation; CLSCTX_INPROC_SERVER is the standard locator activation context.
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&CLSID_WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| wmi_error("CoCreateInstance(WbemLocator)", e.code().0))?;

        let namespace = BSTR::from(r"root\subscription");
        let empty = BSTR::new();
        // SAFETY: locator is a valid IWbemLocator; empty BSTRs are the documented
        // "use defaults" for user/password/locale/authority; None for pctx.
        let services: IWbemServices =
            unsafe { locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None) }
                .map_err(|e| wmi_error(r"ConnectServer(root\subscription)", e.code().0))?;

        let filters: Vec<RawFilter> = query_all(&services, "SELECT * FROM __EventFilter")?
            .iter()
            .filter_map(|o| {
                Some(RawFilter {
                    name: get_bstr_prop(o, "Name")?,
                    query: get_bstr_prop(o, "Query").unwrap_or_default(),
                })
            })
            .collect();
        let consumers: Vec<RawConsumer> = query_all(&services, "SELECT * FROM __EventConsumer")?
            .iter()
            .filter_map(|o| {
                Some(RawConsumer {
                    class: get_bstr_prop(o, "__CLASS").unwrap_or_else(|| "unknown".into()),
                    name: get_bstr_prop(o, "Name")?,
                    command: get_bstr_prop(o, "CommandLineTemplate")
                        .or_else(|| get_bstr_prop(o, "ExecutablePath"))
                        .or_else(|| get_bstr_prop(o, "ScriptText"))
                        .or_else(|| get_bstr_prop(o, "ScriptFileName")),
                })
            })
            .collect();
        let bindings: Vec<RawBinding> =
            query_all(&services, "SELECT * FROM __FilterToConsumerBinding")?
                .iter()
                .filter_map(|o| {
                    Some(RawBinding {
                        filter_ref: get_bstr_prop(o, "Filter")?,
                        consumer_ref: get_bstr_prop(o, "Consumer")?,
                    })
                })
                .collect();

        Ok(join_subscriptions(&filters, &consumers, &bindings))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Smoke test: enumerate_subscriptions never panics and returns Ok(...) on a
        /// normal host (zero subscriptions is the common, non-error case).
        #[test]
        fn enumerate_subscriptions_does_not_panic() {
            let result = enumerate_subscriptions();
            assert!(result.is_ok(), "enumerate_subscriptions failed: {result:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_relative_and_full_refs() {
        assert_eq!(
            parse_object_ref(r#"__EventFilter.Name="Evil""#),
            Some(("__EventFilter".into(), "Evil".into()))
        );
        assert_eq!(
            parse_object_ref(
                r#"\\WS01\ROOT\subscription:CommandLineEventConsumer.Name="Up\"d\\ater""#
            ),
            Some(("CommandLineEventConsumer".into(), r#"Up"d\ater"#.into()))
        );
        assert_eq!(parse_object_ref("garbage"), None);
        assert_eq!(parse_object_ref(r#".Name="x""#), None);
        assert_eq!(
            parse_object_ref(r#"__EventFilter.Name="unterminated"#),
            None
        );
    }

    fn filter(n: &str, q: &str) -> RawFilter {
        RawFilter {
            name: n.into(),
            query: q.into(),
        }
    }
    fn consumer(class: &str, n: &str, cmd: &str) -> RawConsumer {
        RawConsumer {
            class: class.into(),
            name: n.into(),
            command: Some(cmd.into()),
        }
    }

    #[test]
    fn joins_bound_and_emits_unbound() {
        let filters = vec![
            filter("BootTrigger", "SELECT * FROM __InstanceModificationEvent"),
            filter("Orphan", "SELECT * FROM Win32_ProcessStartTrace"),
        ];
        let consumers = vec![
            consumer("CommandLineEventConsumer", "Runner", r"C:\evil.exe"),
            consumer("ActiveScriptEventConsumer", "Leftover", "WScript.Echo 1"),
        ];
        let bindings = vec![RawBinding {
            filter_ref: r#"__EventFilter.Name="boottrigger""#.into(),
            consumer_ref: r#"CommandLineEventConsumer.Name="Runner""#.into(),
        }];
        let out = join_subscriptions(&filters, &consumers, &bindings);
        assert_eq!(out.len(), 3);

        assert!(out[0].bound);
        assert_eq!(out[0].filter_name, "BootTrigger");
        assert_eq!(out[0].filter_query, filters[0].query);
        assert_eq!(out[0].consumer_type, "CommandLineEventConsumer");
        assert_eq!(out[0].command.as_deref(), Some(r"C:\evil.exe"));

        assert!(!out[1].bound);
        assert_eq!(out[1].filter_name, "Orphan");
        assert!(out[1].consumer_name.is_empty());

        assert!(!out[2].bound);
        assert_eq!(out[2].consumer_name, "Leftover");
        assert_eq!(out[2].consumer_type, "ActiveScriptEventConsumer");
        assert!(out[2].filter_name.is_empty());
    }

    /// A binding whose instances were not listed still yields a bound entry from its refs.
    #[test]
    fn binding_to_unlisted_objects_is_kept() {
        let bindings = vec![RawBinding {
            filter_ref: r#"__EventFilter.Name="F""#.into(),
            consumer_ref: r#"NTEventLogEventConsumer.Name="C""#.into(),
        }];
        let out = join_subscriptions(&[], &[], &bindings);
        assert_eq!(out.len(), 1);
        assert!(out[0].bound);
        assert_eq!(out[0].filter_name, "F");
        assert_eq!(out[0].consumer_type, "NTEventLogEventConsumer");
        assert_eq!(out[0].command, None);
    }

    #[test]
    fn wmi_error_names_step_and_hresult() {
        let e = wmi_error("ConnectServer", 0x8004_1003u32 as i32);
        let s = e.to_string();
        assert!(
            s.contains("ConnectServer failed: HRESULT 0x80041003"),
            "{s}"
        );
        assert!(s.contains("wmi_subscription"), "{s}");
    }
}
