# AV 誤判緩解（合法工程優化，非規避）— 設計 Spec

- 日期：2026-07-15
- 基準：main HEAD `2130b9f`
- 對應 backlog：新段落（跟隨段9記憶提到的「SOC runbook 尚未說明 PEB 讀取 API 組合」殘留風險）

## 背景與動機

使用者測試打包後的 `cairn.exe` 時被 PC-cillin 本機 heuristic 攔截。診斷確認觸發
因子是靜態掃描到的 `OpenProcess`+`ReadProcessMemory`（PEB 讀取拿 cmdline）這組
跨行程記憶體讀取 API，以及 `proc.rs` 對同一 pid 分散呼叫四次 `OpenProcess`
（`full_image_path`/`read_integrity`/`read_start_time`/`read_cmdline` 各自獨立
開關 handle）。

**核心判準**：這次調整只做「改變 AV 怎麼分類這個行為」，不做「改變 AV 能不能觀察
到這個行為」——被觀察到的 API 呼叫種類與次數上限不變（甚至減少呼叫次數），只是
讓呼叫模式更合理（單次身份查驗而非反覆探測）並提高治理透明度（明確命名的模組+
SOC runbook 說明）。**明確排除** CLAUDE.md GOLDEN RULE 1 例外條款涵蓋的任何規避
手法（packing/obfuscation/entropy-reduction/anti-debug/延遲執行/行為拆分規避
關聯分析）——本次不使用該例外，因為這兩項改動本質是效能與治理優化。

## 範圍

### 調整1：合併 `OpenProcess` 呼叫（兩階段 fallback）

**現況**（`crates/cairn-collectors-win/src/proc.rs`，探查已確認）：`enumerate()`
的主迴圈（行370-417）對同一個 `pid` 依序呼叫四個各自獨立 `OpenProcess` 的函式：
- `full_image_path`（行80-110）：`PROCESS_QUERY_LIMITED_INFORMATION`
- `read_integrity`（行127-197）：`PROCESS_QUERY_LIMITED_INFORMATION` + `OpenProcessToken(TOKEN_QUERY)`
- `read_start_time`（行202-218）：`PROCESS_QUERY_LIMITED_INFORMATION`
- `read_cmdline`（行283-368）：`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`

**改法**：`enumerate()` 對每個 pid 改成兩階段開啟：
1. 先嘗試 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid)`
   （聯集權限，涵蓋全部四個函式的需求）。
2. 成功 → 這個 handle（包成 `ProcHandle`）傳給全部四個函式共用（函式簽名從
   `fn xxx(pid: u32)` 改成吃 `&ProcHandle` 或 `HANDLE` 參數，不再各自呼叫
   `OpenProcess`）。
3. 若步驟1失敗（例如受保護行程拒絕 `PROCESS_VM_READ`）→ fallback 再嘗試只用
   `PROCESS_QUERY_LIMITED_INFORMATION`（不含 VM_READ）開一次；成功則
   `full_image_path`/`read_integrity`/`read_start_time` 三項用這個 handle 取得，
   `cmdline` 直接記為 `None`（沿用既有「拿不到就 abstain」的 NFR12 語意，不謊報）。
4. 兩次都失敗 → 該 pid 全部欄位 `None`（與現況行為一致，未變差）。

**保留的既有不變量**：`ProcHandle` 的 `Drop` 仍是唯一的 `CloseHandle` 呼叫點；
`// SAFETY:` 註解慣例延續，且新增的「共用 handle」不變量需要在註解裡明確聲明
（「此 handle 在本次迴圈疊代內被多個查詢函式共用讀取，生命週期不超出當次
`enumerate()` 疊代」）。`read_integrity` 內部額外呼叫的 `OpenProcessToken` 不受
這次改動影響（它是對 proc handle 再開一個獨立的 token handle，本質不變）。

**效果**：正常情況下（未受保護行程）每個 pid 從 4 次 `OpenProcess` 降到 1 次；
受保護行程從「4 次呼叫、cmdline 那次可能失敗」變成「最多 2 次呼叫」。被觀察到的
API 呼叫**種類**不變（一樣是這四個函式邏輯上要做的事），只是**次數**大幅下降，
且行為模式從「對同一目標反覆嘗試不同權限」變成「一次到位或明確降級一次」，這是
更接近正常工具（如 Process Explorer 之類）行為模式的改動,不是隱藏行為。

### 調整2：cmdline 讀取邏輯獨立成新檔案

新建 `crates/cairn-collectors-win/src/cmdline_reader.rs`，把 `read_cmdline`
及其全部相關邏輯（`is_wow64`、PEB 結構讀取、`read_remote_struct`/
`ReadProcessMemory` 呼叫、`NtQueryInformationProcess` 呼叫）從 `proc.rs` 搬過去。

檔案開頭加說明性註解（非規避目的的偽裝，是誠實的用途說明）：
```
//! Reads a target process's full command line via its PEB (Process Environment
//! Block), using OpenProcess(PROCESS_VM_READ) + ReadProcessMemory.
//!
//! Why: DFIR triage needs the exact command line an attacker invoked (e.g. full
//! PowerShell -EncodedCommand payload), not just the process image name — this is
//! the single largest source of parentchild/persist heuristic signal (see
//! crates/cairn-heur/src/parentchild.rs).
//!
//! Guarantee: read-only. PROCESS_VM_READ carries no write capability; this module
//! never calls WriteProcessMemory or any handle-modifying API. Failures abstain
//! (return None) rather than guess (NFR12) — see cairn/CLAUDE.md golden rule 8.
```

`proc.rs` 改成 `use crate::cmdline_reader::read_cmdline;`，其餘呼叫點不變。

### 調整3：SOC runbook 補充說明

在 `docs/SOC-runbook-template.md` 新增一段（延續段9記憶提到的殘留風險L3：
「SOC pre-allowlist runbook 尚未說明 cairn 對每個程序做 read-only PEB 讀取取得
cmdline」），說明：
- cairn 對每個掃描到的行程會嘗試一次 `OpenProcess`+`ReadProcessMemory`（讀 PEB
  拿 cmdline）
- 這是 IR 鑑識標準需求（取得完整攻擊指令，而非只有行程名稱）
- 純唯讀，`PROCESS_VM_READ` 不含寫入能力，程式碼位置指向
  `crates/cairn-collectors-win/src/cmdline_reader.rs` 供稽核
- 這正是本工具最常觸發 AV/EDR 靜態 heuristic 的 API 組合之一，SOC 應預期看到
  這個行為並識別為授權掃描的一部分

## 驗收原則（不可退讓）

1. **不減少任何被觀察到的行為**：改動前後，對同一台機器掃描，`ProcessRecord`
   的 `image`/`cmdline`/`integrity`/`start_time` 四個欄位在同樣的權限/保護情境
   下，該有值時還是有值、該是 `None` 時還是 `None`（除了調整1新增的中間狀態：
   聯集權限失敗但基礎權限成功時，`cmdline` 從「可能成功」變成「明確 None」，
   這是 fallback 路徑刻意的降級，非缺陷）。
2. **既有 5 個測試不需修改**：`enumerate_includes_current_process`、
   `current_process_has_absolute_image_path`、
   `current_process_integrity_resolves`、`current_process_start_time_resolves`、
   `current_process_cmdline_resolves` 全部透過 `enumerate()` 進入（黑盒測試），
   不依賴內部函式簽名，行為不變則測試不用改。
3. **`// SAFETY:` 註解慣例延續**：任何新增/修改的 `unsafe` block 都要有對應
   註解，且明確聲明共用 handle 的生命週期不變量。
4. **`#![forbid(unsafe_code)]`/`#![allow(unsafe_code)]` 分界不變**：
   `cmdline_reader.rs` 屬於 `cairn-collectors-win`（crate 層級已 `allow`），
   不影響其他 crate 的 `forbid`。
5. **零新依賴、零 schema 變動**：`ProcessRecord`/`RawProc` 欄位不變。

## Out of scope

- 任何形式的 packing/obfuscation/entropy-reduction/anti-debug/延遲執行/行為
  拆分規避關聯分析——這些屬於 CLAUDE.md GOLDEN RULE 1 例外條款範圍，本次不
  使用該例外
- PE 版本資源（`build.rs`）——探查確認已經填得完整（`ProductName`/
  `FileDescription`/`CompanyName`/`LegalCopyright`/版本號/build SHA），不需要
  額外工作
- Authenticode 簽章——獨立議題，使用者已知悉需要走 SignPath.io（repo 已
  public），非本次範圍
- 移除 cmdline 讀取功能本身——這是拿掉能力換取安靜，不符合「讓工具正常使用」
  的目標，不採用
