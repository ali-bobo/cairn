# 段 9：live proc 資料補齊 + 進度回饋 + manifest 相容 + 關聯佐證修正 — 設計規格

- 日期：2026-07-10
- 狀態：已審（brainstorm 逐項技術決策定案）
- 基準 commit：`c37f43c`（六面向全架構深審合併後的 main）
- 對應審計：`docs/dev-history/2026-07-10-full-architecture-audit-summary.md`
  （段 8 F-1/F-8）+ `docs/dev-history/audit-2026-07-10/{A,B,D}-*.md`

## 動機

六面向深審發現：live proc collector 從不採集 `cmdline`/`integrity`/`start_time`
（`cairn-collectors-win/src/proc.rs:142-146` 恆 `None`），這是 parentchild
heuristic 一半訊號在 live 掃描下永不觸發的根因（段 8 F-1），**且面向 A 新發現
更深一層：`start_time` 恆 None 導致段 3 temporal-window-correlator 在 live 資料
下實質是 no-op**——這代表本段（段 9）必須先於段 3 完成。

此外三個獨立小問題一併修：無進度回饋（F-8）、`manifest.rs::RunInfo` 缺
`#[serde(default)]` 導致舊 manifest 讓 `cairn verify` 硬錯誤（面向 D）、
`persist.rs` 跨文物 join key 只看檔名導致誤判佐證（面向 A F-2）。

四項彼此低耦合（分屬 `cairn-collectors-win`、`cairn-core`、`cairn-heur` 三個
crate），適合放同一段但各自獨立 task。

---

## 一、F-1：live proc 補採集 cmdline / integrity / start_time

### 範圍

全部新增在 `crates/cairn-collectors-win/src/proc.rs`，沿用既有 `ProcHandle`
RAII 模式（`proc.rs:59-69`）。三個資料點各自獨立函式，任一步失敗都優雅降級
`None`，不影響其他欄位、不影響其他程序的列舉。

### 1a. cmdline（PEB 讀取）

流程：`OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` →
`NtQueryInformationProcess(ProcessBasicInformation)` 取得 `PROCESS_BASIC_INFORMATION.PebBaseAddress`
→ `ReadProcessMemory` 讀 `PEB.ProcessParameters`（取得
`RTL_USER_PROCESS_PARAMETERS` 的遠端指標）→ 再次 `ReadProcessMemory` 讀該結構的
`CommandLine`（`UNICODE_STRING`，得到 `Length` + 遠端 `Buffer` 指標）→ 第三次
`ReadProcessMemory` 讀 `Length` 位元組的實際字串內容。

**soundness 規則**（B 報告 §4c 逐條落實）：
1. 每一步 `ReadProcessMemory` 都視為可失敗，任一步失敗（含 `FALSE` 回傳或
   `lpNumberOfBytesRead` 不等於要求長度的部分讀）→ 整條回 `None`，不猜測、不用
   部分資料拼湊。
2. `UNICODE_STRING.Length` 先做上限檢查（≤ 32 KiB）才配置 buffer，防止目標
   程序被竄改 PEB 造成的 OOM/DoS（比照 `volume.rs::MAX_READ` 紀律）。
3. **WOW64 一律 abstain**：偵測到目標與本程序位元架構不同時直接回 `None`，
   不建立第二套 32-bit PEB 解析邏輯（YAGNI + NFR12「寧可 abstain 不猜」，
   比照 `logon.rs::client_address` 的既有先例）。判斷方式：
   `NtQueryInformationProcess(ProcessWow64Information)` 若回傳非零位址即為
   WOW64 目標。
4. 讀 PEB 型別一律用 `windows` crate 自帶的 `PEB`/`RTL_USER_PROCESS_PARAMETERS`
   結構（**不手刻任何 offset**——B 報告已確認這些結構雖大部分欄位是
   `Reserved1..N` padding，但 `ProcessParameters`/`ImagePathName`/`CommandLine`
   都是具名欄位，layout 由 crate 保證）。

### 1b. integrity（token 完整性等級）

流程：`OpenProcessToken(TOKEN_QUERY)`（沿用/共用 `privilege.rs::TokenHandle`
guard，不重複造一份）→ `GetTokenInformation(TokenIntegrityLevel)` 兩段式
（probe 長度 → 真讀）拿 `TOKEN_MANDATORY_LABEL` → 讀其 SID 最後一個
sub-authority（RID）→ 映射成 low/medium/high/system 標籤（沿用
`cairn-collectors/src/proc.rs::integrity_label` 現有映射表，不重複定義）。

**已知同 B-2 的 alignment 註記**：`Vec<u8>` reinterpret 成
`TOKEN_MANDATORY_LABEL` 時比照 `net.rs` 現況處理（用 `read_unaligned` 或过对齐
buffer；本段實作時選一種並記錄理由，不需要回頭修 net.rs 既有的 B-2，那不在
本段範圍）。

### 1c. start_time

`GetProcessTimes`（`windows 0.62.2` 已含此符號於 `Win32_System_Threading`
feature，**已啟用，零新增 feature flag**）拿 `lpCreationTime`（`FILETIME`）→
轉 `DateTime<Utc>`（沿用專案既有 FILETIME 轉換慣例，見
`cairn-core/src/time.rs`）。失敗（權限不足/程序已結束）→ `None`。

### 依賴新增

`crates/cairn-collectors-win/Cargo.toml` 新增 3 個 `windows` crate feature：
`Win32_System_Kernel`（PEB/`RTL_USER_PROCESS_PARAMETERS` 所在）、
`Win32_System_Diagnostics_Debug`（`ReadProcessMemory`）、
`Wdk_System_Threading`（`NtQueryInformationProcess`/`PROCESSINFOCLASS`）。
`Win32_Security`、`Win32_System_Threading` 已啟用，integrity/start_time 免加。
全部是既有 `windows` crate（已在依賴四關審過）自帶 feature，零新增供應鏈風險。

### Golden rule 檢查

- Rule 1（無 evasion）：全程唯讀（`PROCESS_VM_READ` 不能寫目標記憶體），讀取
  目標程序自己公開的 PEB 結構，屬合法鑑識讀取，與現有 `full_image_path` 同類。
- Rule 8（graceful degrade）：三個資料點任一失敗只影響該欄位為 `None`，不中止
  整個 collector、不影響同一程序的其他欄位、不影響其他程序。

---

## 二、F-8：orchestrator per-collector 進度回饋

### 範圍

`crates/cairn-core/src/orchestrator.rs` 的 collector 執行迴圈（現況約
第 40-48 行，只在失敗時 `tracing::warn!`）。

### 設計

```rust
for c in collectors {
    let started = std::time::Instant::now();
    tracing::info!(collector = c.name(), "執行中");
    match c.collect(&ctx) {
        Ok(recs) => {
            tracing::info!(
                collector = c.name(),
                records = recs.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "完成"
            );
            // 既有累加邏輯不變
        }
        Err(e) => {
            tracing::warn!(
                collector = c.name(),
                error = %e,
                elapsed_ms = started.elapsed().as_millis(),
                "失敗；跳過"
            );
            // 既有失敗記錄邏輯不變
        }
    }
}
```

不新增 JSON 結構化輸出、不改 launcher（launcher 本來就繼承子程序 stderr，
`tracing_subscriber` 的既有格式會自然透出）。這是本段刻意收斂的範圍：見
brainstorm 階段的 YAGNI 判斷——即時百分比進度條需要「總量預估」，但
raw-NTFS 掃描的總筆數在跑之前無法得知，強做百分比是虛假精確度，不誠實。

---

## 三、manifest.rs 全欄位 `#[serde(default)]` 稽核

### 範圍

`crates/cairn-core/src/manifest.rs` 全部 7 個 struct：`Manifest`、`RunInfo`、
`HostInfo`、`Privileges`、`OutputEntry`、`Counts`、`GovernanceReport`。

### 方法

逐一 struct、逐一欄位核對：對照 `docs/dev-history/INDEX.md` 找出每個欄位是
「型別誕生時就有」還是「後續某功能合併時才加的」（`GovernanceReport` 整個
struct 是 2026-06-20 governance 段落才加的，`RunInfo.profile`/
`.selected_modules` 是 S2-L 才加的——這兩處已知有問題）。凡是後加欄位缺
`#[serde(default)]` 一律補上；每補一處都要有一則測試：手造一份「缺這個欄位」
的 JSON 字串，反序列化成功且該欄位得到合理預設值（不是只測「加了 default
標籤」，是測「舊資料真的能載入」）。

不改欄位型別、不改語意，純粹補相容性標記——零風險的 additive 修復。

---

## 四、persist.rs 跨文物 join key 改路徑感知

### 範圍

`crates/cairn-heur/src/persist.rs` 的 `normalized_basename`（第 210-219 行）
與 `CrossIndex`/`build_cross_index`（第 221-248 行）。

### 設計

```rust
/// 跨文物比對鍵：有完整路徑就比對路徑，只有檔名（如多數 prefetch 來源）就
/// 降級比對檔名。降級佐證的 finding reason 必須註明「僅檔名相符」，
/// 與完整路徑相符的佐證信心度不同。
enum JoinKey {
    Path(String), // 正規化後的完整小寫路徑
    Name(String), // 僅檔名（來源缺路徑資訊）
}

fn join_key(path: &str) -> JoinKey {
    let normalized = path.trim().trim_matches('"').to_ascii_lowercase();
    if normalized.contains(['\\', '/']) && has_dir_component(&normalized) {
        JoinKey::Path(normalized)
    } else {
        JoinKey::Name(basename_only(&normalized))
    }
}
```

比對規則：`Path` vs `Path` → 要求路徑相符；`Path` vs `Name` 或
`Name` vs `Name` → 降級比對純檔名（去 `.exe`），佐證命中時在 finding reason
附註「（降級佐證：僅檔名相符，來源缺完整路徑）」。

這修正 A 面向 F-2（同名不同路徑誤判升級 severity）同時保留 prefetch 等
天生缺路徑的離線文物仍能提供佐證，只是佐證信心度誠實標示為較低。

`CrossIndex` 的 `HashMap<String, ...>` 鍵改成 `JoinKey` 需要
`Hash`/`Eq`/`PartialEq` 手動實作或 derive（`Path`/`Name` 是不同 variant，即使
內部字串相同也不視為相等鍵——這保證了「降級」不會被誤當成「完整路徑相符」）。

**具體判斷函式**（`has_dir_component`/`basename_only`）與現有
`normalized_basename`/`short_name_persist` 的關係、以及 `ExecutionRecord.path`
各 7 個來源（amcache/amcache_driver/shimcache/prefetch/userassist/bam/srum）
實際路徑完整度的逐一確認，留給 writing-plans 階段查證（需要讀各 collector
實際填入 `path` 欄位的程式碼，不是本 spec 該臆測的細節）。

---

## 跨段紀律

- 四個子項各自獨立 task，分屬三個 crate，subagent-driven 執行時避免混改
  不相關檔案進同一個 commit（delegation.md §7 反例 4：同檔案改動才集中，
  這裡是跨檔案獨立改動，適合各自 task）。
- 測試範圍：`cargo test -p cairn-collectors-win`（F-1）、
  `cargo test -p cairn-core`（F-8 + manifest defaults）、
  `cargo test -p cairn-heur`（persist join key）；finishing 階段做一次全
  workspace 權威驗證（跨 crate 邊界：`ProcessRecord`/`Record` schema 沒變、
  但 orchestrator 行為變了，值得跑一次全量）。
- Golden rules：rule 1（無 evasion）、rule 8（graceful degrade）為本段最相關
  的兩條，每個 task 的驗收條件都要明確核對。
- 零新依賴（三個新 feature flag 屬既有依賴自帶）；schema 不變（`ProcessRecord`
  三欄位已存在於 `cairn-core/src/record.rs`，只是從不被填值，本段補值不改
  schema）。

## 已知留給 writing-plans 階段查證的細節（非本 spec 該臆測）

- `ExecutionRecord.path` 各 7 個來源的實際路徑完整度逐一確認（決定 join key
  的 `has_dir_component` 判斷邏輯細節）
- `TOKEN_MANDATORY_LABEL` 的 `Vec<u8>` reinterpret 用哪種對齊安全寫法
  （`read_unaligned` vs 過對齊 buffer），plan 階段定案並附程式碼
- WOW64 偵測（`ProcessWow64Information`）的確切呼叫程式碼與回傳值判讀
