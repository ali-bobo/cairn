# 段 4-塊A：WMI 持久化偵測（Observation-first 重設計）— 設計 Spec

- 日期：2026-07-16
- 基準：main HEAD `6fec010`
- 對應 backlog：`docs/REMAINING-WORK.md` 段 4 塊 A
- 前身設計：`docs/dev-history/specs/2026-07-03-fileless-attack-coverage-design.md`
  §4（塊A原始設計，2026-07-08 附註已標記需重設計，本 spec 是重設計後的完整版本）

## 背景與動機

原始 fileless-attack-coverage spec 塊 A 設計了讀取 WMI 永久事件訂閱的 collector，
但 §4.4「復用 S9 gate」有已記錄的設計缺陷（2026-07-08 BYOVD brainstorm 時發現）：
S9（`crates/cairn-heur/src/persist.rs::script_persistence_signal`）只看命令列首
token 是否落在 `INTERPRETERS` 清單，抓不到 `ActiveScriptEventConsumer` 內嵌
`ScriptText`（純腳本文字，沒有被呼叫的執行檔可供比對）的情況——這是 WMI 持久化
最常見的型態，目前是完全的偵測盲區。

本次 brainstorm 重新查證確認：現有 `persist.rs` 的 `analyze()`/`observe()` 是
兩個獨立互斥的掃描（同一筆記錄二選一進 Finding 或 Observation），並非「先進
Observation、事後用其他訊號佐證再升級」的兩階段流程。使用者確認 WMI 這段沿用
既有互斥模式，不新增二階段升級機制。

真正需要修的根本缺口不是「WMI 沒被涵蓋」，而是 S9 gate 的判斷維度本身缺一項：
無法辨識「內嵌腳本內容」這種沒有被呼叫執行檔的持久化型態。解法是新增一條
**針對性**的 heuristic 信號，不修改 S9 本身、不影響其他持久化機制。

## 範圍

### WMI 資料讀取（新依賴：`windows` crate 的 Wmi/Com feature）

**技術可行性已查證**（`docs/dev-history/2026-07-16-wmi-persistence-research.md`，
本次 brainstorm 產出，含完整來源 URL/存取日期）：`windows` crate（cairn 目前 pin
`0.62.2`）的 `Win32_System_Wmi` feature 有官方文件證實的真實 `IWbemServices`
方法簽章（`ExecQuery` 等），`Win32_System_Com` feature 有 `CoInitializeSecurity`/
`CoCreateInstance` 等真實可呼叫的 unsafe fn。

**決策：自己刻 COM 呼叫鏈，不引入現成 `wmi` crate**。理由：
1. `wmi` crate（ohadravid/wmi-rs）有一個**已查證、WONTFIX** 的已知 UB 問題
   （GitHub issue #39）——它自行管理 `CoInitialize`/`CoUninitialize` 生命週期，
   與 `windows-rs` 自身的 COM 初始化機制（`CoIncrementMTAUsage`）交錯時，
   `CoUninitialize` 可能卸載 windows-rs 正在使用的 COM DLL，導致 segfault。
   microsoft/windows-rs 團隊對此問題的立場是 WONTFIX。這種時序性、難重現的
   UB 對鑑識工具（要求高可靠性、輸出必須可信）是不可接受的風險等級。
2. cairn 這次的查詢面很窄——只需連 `root\subscription`、查三個固定類別
   （`__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding`）、讀四個
   固定字串屬性（`Name`/`Query`/`CommandLineTemplate`/`ScriptText`）。不需要
   `wmi` crate 的泛用 serde 反序列化能力，手刻更能控制錯誤處理、符合 cairn
   一貫的 graceful degrade 慣例。
3. 符合 cairn 現有架構分層——`cairn-collectors-win` 本來就是唯一允許 unsafe
   的 crate，新增這個 unsafe COM 呼叫鏈不需要額外破例。

**已知查證缺口**（研究階段誠實標註，實作階段需留意）：
- `IWbemLocator::ConnectServer`、`IEnumWbemClassObject::Next`、
  `IWbemClassObject::Get` 的官方文件頁面本次未逐一開啟驗證（僅同構推測存在，
  因為同一 crate 內部生成模式一致）——實作 Task 開始前第一步應先驗證這三個
  方法的真實簽章，不可假設存在就直接寫程式碼。
- BSTR/VARIANT 在 WMI 屬性讀取場景下的具體踩坑案例未查到——實作時需要對
  `IWbemClassObject::Get` 回傳的 `VARIANT` 做防禦性處理（型別檢查、NULL
  檢查），不可假設一定拿到預期型別。
- cairn 現有 `Win32_Security_WinTrust`/`Cryptography_Catalog` 用法是否已經
  初始化 COM 未查證——這會影響本次新增的 COM 初始化是否與既有程式碼路徑有
  交互作用，實作前需要檢查這兩個現有模組是否呼叫過 `CoInitializeEx` 之類的
  API（若有，需確認呼叫順序與釋放時機不衝突）。

### 架構分層（沿用既有 collector 模式）

比照 `crates/cairn-collectors-win/src/net.rs` 的既有模式（raw WinAPI 查詢 →
plain struct → 上層轉 Record）：

1. **`crates/cairn-collectors-win/src/wmi.rs`**（新建，unsafe COM FFI 層）：
   `CoInitializeEx` → `CoInitializeSecurity` → `CoCreateInstance(CLSID_WbemLocator)`
   → `IWbemLocator::ConnectServer`（連 `root\subscription`）→
   `IWbemServices::ExecQuery`（WQL 查三個類別）→ 逐筆讀取屬性 → 回傳 plain
   struct（例如 `RawWmiFilter`/`RawWmiConsumer`/`RawWmiBinding`，非 `Record`）。
   `#[cfg(not(windows))]` 提供空實作 fallback（沿用既有 crate 慣例）。
2. **`crates/cairn-collectors/src/wmi_subscription.rs`**（新建，
   `#![forbid(unsafe_code)]` 安全 wrapper）：把 `wmi.rs` 的 plain struct
   關聯（filter↔consumer via binding）轉成 `Record::Persistence`。

### 資料模型（零 schema 變動）

**不新增 Record 變體**，複用既有 `Record::Persistence`（
`crates/cairn-core/src/record.rs:67-78`），`mechanism="wmi_subscription"`
（這個字串值已經在既有欄位 doc comment 裡預留）。三類 WMI 物件映射：

| WMI 類別 | 映射到 `PersistenceRecord` 欄位 |
|---|---|
| `__EventFilter` | `Name`+`Query`（WQL） → `location` |
| `CommandLineEventConsumer` | `CommandLineTemplate` → `command`；解析出的 exe（若有）→ `binary_path` |
| `ActiveScriptEventConsumer` | `ScriptText` → `command`；`binary_path=None`（純腳本，無被呼叫執行檔——這是本 spec 要修的根本情境） |
| `__FilterToConsumerBinding` | 不單獨出 record，僅用於關聯 filter↔consumer |

`signed`/`binary_sha256` 交下游既有驗章邏輯（若 `binary_path` 有值）；
`last_write=None`（WMI 訂閱物件沒有對應的檔案系統時間戳，誠實留空，NFR12，
不謊報）。

### 偵測邏輯（兩處）

**1. 沿用既有 persist gate 機制**：`evaluate_gate` 對 `mechanism="wmi_subscription"`
的記錄比照其他機制處理——命中既有信號（S1-S9 任一項，例如 `binary_path` 指向
使用者可寫路徑且未簽章）→ Finding；未命中 → 進 `observe()` 產生 Observation。
與現有 persist 模式完全一致，不新增二階段升級。

**2. 新增 WMI ActiveScript 內容信號**（填補根本缺口，最小範圍變動）：在
`evaluate_gate` 新增一條信號，條件：`mechanism=="wmi_subscription"` 且
`binary_path.is_none()`（代表是純 `ActiveScriptEventConsumer`，沒有被呼叫的
執行檔可供 S9 判斷）→ 直接檢查 `command`（即 ScriptText 內容）是否含可疑模式：
- 編碼/混淆跡象（Base64 長字串、`Chr()`/`Eval()`/`ExecuteGlobal()` 等 VBScript
  動態執行函式）
- 遠端下載跡象（`XMLHTTP`、`WinHttp.WinHttpRequest`、URL 字串樣式）

命中任一模式 → High（比照其他持久化機制的既有 severity 慣例）。這條信號**只**
影響 `mechanism=="wmi_subscription"` 且無 `binary_path` 的記錄，不修改 S9
本身、不影響其他既有持久化機制的判定。

## 驗收原則

1. **COM 初始化失敗、WMI 命名空間不存在（例如非 Windows 或極簡安裝）、逐筆
   查詢失敗**：全部 graceful degrade——收集器回傳空結果或部分結果，記錄
   error/flag 到 manifest，不 panic，不中止整個掃描（golden rule 8）。
2. **`#![forbid(unsafe_code)]` 邊界**：`wmi.rs` 屬於 `cairn-collectors-win`
   （crate 層級已 `#![allow(unsafe_code)]`）；`wmi_subscription.rs` 屬於
   `cairn-collectors`（維持 `#![forbid(unsafe_code)]`）。
3. **零 schema 變動**：`Record::Persistence`/`PersistenceRecord` 欄位不變，
   只是新的 `mechanism` 字串值。
4. **零新增第三方 crate 依賴**：只新增 `windows` crate 的既有依賴上的兩個
   feature（`Win32_System_Wmi`/`Win32_System_Com`），不引入 `wmi` crate。
5. **新增的 ActiveScript 信號範圍最小化**：只在 `binary_path.is_none()` 且
   `mechanism=="wmi_subscription"` 時生效，不得誤觸其他機制的判定路徑。

## Out of scope

- 二階段 Observation→Finding 升級機制（使用者確認沿用既有互斥二選一模式）
- 引入 `wmi` crate（已知 UB 風險，見上）
- 即時 WMI 事件訂閱監控（本 spec 只讀取「已存在的訂閱設定」，不做即時事件流
  監聽——那是完全不同等級的機制，架構決策層級的另一個議題）
- BSTR/VARIANT 的通用型別轉換函式庫化（本次只處理 WMI 這四個固定字串屬性的
  讀取，不做通用抽象）
- 對 `derive-com-impl`（RUSTSEC-2021-0083）的直接處理——因為決定不引入
  `wmi` crate，這個間接風險不適用；但若本 spec 的手刻方案未來意外引入類似的
  COM helper crate，需要重新查證
