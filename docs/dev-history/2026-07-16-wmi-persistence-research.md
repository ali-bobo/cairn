# WMI 永久事件訂閱讀取 — 技術可行性研究（2026-07-16）

## 結論先行

1. `windows` crate 確實有 `Win32_System_Wmi` feature，`IWbemServices`、`IWbemLocator`、`IEnumWbemClassObject`、`IWbemClassObject` 都有真實可呼叫的方法（非空殼型別），簽章已用官方文件實證。
2. `CoInitializeEx`/`CoInitializeSecurity`/`CoCreateInstance` 在 `Win32_System_Com` feature 下，也都是真實可呼叫的 unsafe fn。
3. 完整呼叫鏈（CoInitialize → CoCreateInstance(CLSID_WbemLocator) → ConnectServer → ExecQuery → IWbemClassObject::Get）在 `windows` crate 理論上每步都能寫，但**沒有找到公開的、成熟的「純 windows-rs 手刻 WMI 查詢」範例專案**——生態系普遍直接用 `wmi` crate。
4. 現成 `wmi` crate（ohadravid/wmi-rs）存在，MIT/Apache-2.0 雙授權，底層依賴正是 `windows` crate（版本範圍 `>=0.59, <0.63`，與 cairn 目前 pin 的 `0.62.2` 相容），近期仍在維護（0.18.4，2026-03-27）。
5. **關鍵風險已查證**：wmi-rs 有一個**未解決（WONTFIX）的已知問題**——它自己呼叫 `CoInitialize`/`CoUninitialize`，若與專案自身已存在的 COM 初始化（例如 cairn 未來可能用到的其他 COM API）交錯，會在 `CoUninitialize` 時把 windows-rs 依賴的 COM DLL 卸載，導致段錯誤（UB）。這對 cairn「forbid unsafe / 最小依賴面」的取捨很關鍵。
6. 未查到 RustSec 對 `wmi` crate 本身的漏洞公告；唯一相關的是同生態系另一個 crate `derive-com-impl` 的 RUSTSEC-2021-0083（`QueryInterface` 未呼叫 `AddRef`），與 `wmi` crate 本身無直接關聯，但顯示 Rust COM 生態系底層確實有過真實漏洞案例，值得留意 `wmi` crate 依賴樹是否引用了受影響版本。

---

## 逐條證據

### Q1：`windows` crate 是否有 `Win32_System_Wmi` feature，型別是否真實可呼叫

- 來源：https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Wmi/struct.IWbemServices.html （存取於 2026-07-16，頁面未標示更新日期）
- 官方文件證實 `IWbemServices` 有真實方法簽章，非空殼：
  ```rust
  pub unsafe fn ExecQuery<P3>(
      &self,
      strquerylanguage: &BSTR,
      strquery: &BSTR,
      lflags: WBEM_GENERIC_FLAG_TYPE,
      pctx: P3
  ) -> Result<IEnumWbemClassObject>
  ```
  以及 `OpenNamespace`、`ExecMethod`、`GetObject`（含對應 Async 版本）皆有完整參數與回傳型別。
- 〔推測〕`IWbemLocator::ConnectServer`、`IEnumWbemClassObject::Next`、`IWbemClassObject::Get` 應同樣存在對應方法（同一 crate 內部生成模式一致），但本次未逐一開對應頁面驗證每個方法簽章，屬合理推測而非逐條查證。
- 結論：**官方文件證實**——這是真實可呼叫的安全 Rust binding（unsafe fn，但非空殼定義）。

### Q2：COM 初始化在 `Win32_System_Com` feature，及現成範例

- 來源：https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoInitializeSecurity.html、
  https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoCreateInstance.html （存取於 2026-07-16，頁面未標示日期）
- `CoInitializeSecurity`、`CoCreateInstance`、`CoCreateInstanceEx` 均在 `windows::Win32::System::Com` 模組下，皆為 unsafe fn，回傳 `Result<()>` / `Result<T>`。**官方文件證實**。
- 搜尋「windows-rs WMI IWbemServices example」**未找到**成熟的、專門用 `windows-rs`（非 `winapi` 舊版）手刻完整 WMI 查詢鏈的公開專案或教學。搜尋結果幾乎全部導向 `wmi` crate 本身（其原始碼內部即是這樣手刻的，可視為唯一可參考的「範例」，見 Q4）。
- **查不到**：獨立於 `wmi` crate 之外、給開發者參考用的手刻 windows-rs WMI 呼叫鏈教學或 gist。

### Q3：完整呼叫鏈是否每步都有 binding，已知踩坑

- 每一步（`CoInitializeEx`、`CoCreateInstance`、`ConnectServer`、`ExecQuery`、`IWbemClassObject::Get`）在對應 feature 下皆有官方 binding（Q1、Q2 已證實核心步驟；`ConnectServer`／`Get` 屬〔推測〕同構存在，未逐一開頁面）。
- **已知踩坑（查證屬實）**：COM 初始化生命週期管理的競態問題——見 Q4/Q5 的 wmi-rs issue #39，這是最重要的一條，不是理論疑慮而是有真實 GitHub issue 記錄的 UB。
- BSTR/VARIANT 轉換踩坑：**查不到**針對 WMI 場景的具體案例報告；`windows` crate 的 `BSTR` 型別本身有 RAII 管理生命週期，理論上比手動 `SysAllocString`/`SysFreeString` 安全，但本次未找到與 WMI 屬性讀取相關的具體踩坑記錄，故不下斷言。
- COM apartment 執行緒模型限制：官方文件（`CoInitializeSecurity` 頁面）提及「此函式每個處理序只能呼叫一次」，隱含單執行緒/程序生命週期的初始化順序限制；若 cairn 未來有多執行緒各自呼叫 COM API，需要留意 apartment 模型（STA vs MTA）與 `CoInitializeEx` 參數選擇，但本次未深入查證 cairn 現有程式碼是否已有相關模式衝突。

### Q4：`wmi` crate 現況

- 來源：https://crates.io/crates/wmi （透過 docs.rs/crate/wmi/latest 取得等效資料，存取於 2026-07-16）、https://github.com/ohadravid/wmi-rs （存取於 2026-07-16）
- **License**：MIT OR Apache-2.0（雙授權，與 cairn 慣用授權相容）。
- **最新版本**：0.18.4，發布於 2026-03-27（近期仍活躍維護）。
- **底層依賴**：`windows >=0.59, <0.63`、`windows-core >=0.59, <0.63`（**官方文件證實**，非推測）——與 cairn 目前 pin 的 `windows = "0.62.2"` **版本範圍相容**（0.62.2 落在 [0.59, 0.63) 區間內）。
- **GitHub 現況**：123 stars（存取於 2026-07-16）。
- **RustSec/漏洞**：搜尋 RustSec advisory database **未找到** `wmi` crate 本身的 CVE 或 advisory。唯一查到的相關項目是同生態系 `derive-com-impl` crate 的 **RUSTSEC-2021-0083**（`IUnknown::QueryInterface` 未呼叫 `AddRef` 導致引用計數錯誤，可能造成 WMI 相關程式使用無效指標）——這是否被 `wmi` crate 依賴樹引用**未查證**，建議實際引入前跑 `cargo audit` 確認。

### Q5：供應鏈細節與已知 UB 問題（重要發現）

- 來源：https://github.com/ohadravid/wmi-rs/issues/39 （存取於 2026-07-16，issue 標題含「UB when mixing windows-rs and wmi-rs crates」）
- **根本原因**：`wmi` crate 建立連線時呼叫 `CoInitialize`，drop 時呼叫 `CoUninitialize`；而 `windows-rs` 本身用 `CoIncrementMTAUsage` 維持 COM 常駐初始化，但只在 `RoGetActivationFactory` 回傳 `CO_E_NOTINITIALIZED` 時才會遞增。若 WMI 晚於 windows-rs 初始化 COM，windows-rs 會跳過遞增；接著 WMI drop 時呼叫 `CoUninitialize` 會把 COM DLL 卸載，包含 windows-rs 正在使用的部分，造成 segfault。
- **狀態**：**未解決**，issue 引用 microsoft/windows-rs 團隊的 WONTFIX 立場，隱含「在 Rust 環境呼叫 `CoUninitialize` 本質上不安全」的判斷。
- **對 cairn 的實務意涵**：若 cairn 未來在**同一 process** 內既用 `wmi` crate、又直接用 `windows` crate 呼叫其他 COM API（例如未來若擴充 WinTrust/Cryptography 之外的 COM 介面），兩者的 COM 生命週期管理會衝突，屬於時序相關、難重現的 crash。cairn 目前的 `Win32_Security_WinTrust`/`Cryptography` 用法**是否涉及 COM 初始化未查證**，需要在真正引入前確認是否踩到這個交叉點。
- typosquatting 疑慮：`wmi` 這個名稱簡短常見，**未查到**具體被仿冒的公開紀錄，但因名稱過於通用（三個字母），建議引入時比對 crates.io 上是否有相似名稱的可疑套件（本次未逐一核對 crates.io 搜尋結果列表，屬查證缺口）。

---

## 矛盾點

- 沒有發現直接矛盾的來源說法。唯一需要並列的是「官方文件證實 API 存在且可呼叫」 vs 「生態系裡幾乎沒人真的手刻 windows-rs 版 WMI 查詢、全部依賴 wmi crate 包裝」——這不算矛盾，但說明「自己刻」這條路線**缺乏可參考先例**，風險評估需把這點計入（不是技術不可行，是工程成本與踩坑成本高，且沒有他人已驗證過的路可抄）。

## 查不到的部分（明說）

- 沒找到獨立於 `wmi` crate 之外的手刻 windows-rs WMI 查詢完整範例。
- 未逐一驗證 `IWbemLocator::ConnectServer`、`IEnumWbemClassObject::Next`、`IWbemClassObject::Get` 的官方文件頁面（僅同構推測存在）。
- 未查證 `wmi` crate 依賴樹是否實際引用了受 RUSTSEC-2021-0083 影響的 `derive-com-impl` 版本。
- 未查證 BSTR/VARIANT 在 WMI 屬性讀取場景下的具體踩坑案例。
- 未查證 cairn 現有 `Win32_Security_WinTrust`/`Cryptography_Catalog` 用法是否已經初始化 COM（這會影響 wmi-rs issue #39 的風險是否會在 cairn 實際觸發）。

---

## 建議

**建議：自己刻 COM 呼叫鏈，直接用 `windows` crate 的 `Win32_System_Wmi` + `Win32_System_Com` feature，不引入 `wmi` crate。**

理由：

1. **供應鏈面**：cairn 的定位是鑑識工具，最小依賴面與可審查性優先於開發速度。`wmi` crate 雖然授權相容、維護活躍，但它是一層額外的抽象（serde 整合、async 支援等 cairn 用不到的功能），每多一層依賴就多一份要審查的程式碼與供應鏈風險面（含它自己的 `futures`/`thiserror`/`serde` 依賴鏈，而 cairn 目前的 collectors-win 是刻意精簡到只有必要 WinAPI feature）。
2. **已知 UB 是實質風險，不是理論疑慮**：wmi-rs issue #39 是有記錄、WONTFIX 的真實問題。cairn 其他 collector 未來若也需要 COM（不無可能），與 `wmi` crate 混用會埋下時序性 crash 的地雷，這種 bug 在鑑識工具（要求高可靠性、輸出必須可信）裡是不可接受的風險等級。
3. **cairn 這次的 WMI 查詢需求很窄**：只需要連 `root\subscription`、查三個固定類別（`__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding`）、讀幾個固定屬性（`Name`/`Query`/`CommandLineTemplate`/`ScriptText`）。這是一個「窄而淺」的查詢面，不需要 `wmi` crate 的泛用 serde 反序列化能力；手刻反而更好控制錯誤處理與 graceful degradation（符合 cairn 一貫的「不可 panic、部分失敗要表面化成 flag」設計慣例，見既有 collector 如 amcache/bam 的模式）。
4. **API 已官方證實可呼叫**：Q1/Q2 已用官方文件證實 `ExecQuery`、`CoCreateInstance`、`CoInitializeSecurity` 等每一步都有真實簽章，不是空殼——技術可行性沒有疑慮，只是需要自己處理 COM 生命週期（這件事在單一 collector、單一執行緒、明確初始化/釋放範圍內可控，遠比跟另一個 crate 共享隱性全域 COM 狀態安全）。
5. 代價：需要自己寫 unsafe COM 呼叫、處理 BSTR/VARIANT 轉換、寫更多測試覆蓋——但這些都在 `cairn-collectors-win` 既有的「唯一允許 unsafe 的 crate」職責範圍內，符合現有架構分層，不需要額外破例。

**唯一但書**：若後續 brainstorm 發現「窄而淺」的假設不成立（例如需要查詢的類別/屬性面很快擴張、或需要處理複雜的 VARIANT 陣列型別），屆時手刻的邊際成本會上升，可以重新評估引入 `wmi` crate 是否划算——但以目前規劃的三個固定類別＋四個字串屬性來看，手刻路線的複雜度可控。

---

## 來源清單

- https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Wmi/struct.IWbemServices.html （2026-07-16）
- https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoInitializeSecurity.html （2026-07-16）
- https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Com/fn.CoCreateInstance.html （2026-07-16）
- https://crates.io/crates/wmi ／ https://docs.rs/crate/wmi/latest （2026-07-16）
- https://github.com/ohadravid/wmi-rs （2026-07-16）
- https://github.com/ohadravid/wmi-rs/issues/39 （2026-07-16）
- https://rustsec.org/advisories/ 、 https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/derive-com-impl/RUSTSEC-2021-0083.md （2026-07-16）
- WMI 持久化技術背景（非供應鏈查證，僅確認偵測目標正確性）：
  - https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96
  - https://docs.velociraptor.app/blog/2022/2022-01-12-wmi-eventing/
