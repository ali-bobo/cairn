# Heuristic Gate Redesign — Design Spec

> **Date:** 2026-07-02
> **Status:** Approved direction — pending user spec review
> **Scope:** cairn-heur（全面重寫計分哲學）、cairn-core（Observation 型別 + Finding.evidence）、
> cairn-report（observations.jsonl + HTML）、cairn-cli（接線）
> **SRS refs:** §10（heuristics）、golden rule 6（explainability）、NFR12（誠實輸出）

---

## 1. 問題陳述（實測數據）

2026-06-28 在乾淨的個人機器（ASUS 筆電）上執行 `cairn run --target live`，
產出 60 個 findings，**誤報率 >90%**：

| 數量 | severity | 內容 | 誤報原因 |
|---|---|---|---|
| 25 | Low | service autostart persistence | 每個第三方服務光「存在」就發（base weight 20 ≥ 噪音下限 15）|
| 13 | Medium | service + 近期修改 | Windows Update 日整批刷新 last_write；per-user 服務實例（`cbdhsvc_XXXX`）每次登入重建、永遠「近期」|
| 12 | Medium | Confirmed persistence + execution | 每個正常自啟軟體（Chrome/Edge/Notion/NVIDIA…）都符合「持久化+執行過」|
| 2 | Medium | Winlogon Shell/Userinit | 兩個都是 Windows 出廠預設值 |
| 1 | **High** | correlation: explorer | winlogon `Shell=explorer.exe` 是預設值；registry 存相對路徑 → 簽章驗證器解析不到 → `signed=None` → 「fail-loud」規則誤判 High |

**根因：工具把「盤點（inventory）」當「偵測（detection)」輸出。**
在 100% 乾淨機器上都會觸發的信號，資訊量為零。現行「加權累分跨門檻」模型
讓常態存在的東西不斷跨過告警門檻。歷來的修補（TRUSTED_APPDATA_SUBPATH、
inbox-service 抑制、winlogon 預設抑制、correlation severity 矩陣）都是對同一
根因的特例補丁（whack-a-mole）。

**次要問題：輸出不直覺。** title 只有「Suspicious persistence: service」，
看不出是哪個程式、哪個路徑；調查者無法直接行動。

---

## 2. 目標與驗收標準

1. **乾淨機器掃描：High = 0、Medium = 0、Low < 5。**
   原 60 個 findings 中的盤點類項目全部轉入 `observations.jsonl`（不遺失資訊）。
2. **真陽性不漏**：每個 gate 信號（§4）配至少一正（合成惡意 fixture 觸發）
   一反（合法情境不觸發）單元測試。
3. **輸出直覺**：title 帶 binary 短名；details 第一行 = 完整路徑；
   Finding.evidence 列出每個佐證來源（artifact + 路徑 + 時間戳）。
4. EVTX-ATTACK-SAMPLES parity 測試不退步（Sigma 層零改動）。
5. workspace 測試全綠 + clippy 零警告（`--all-targets`）。

## 3. 非目標（YAGNI / 已否決）

- **基線快照比對**（baseline diff）：IR 情境到場時無乾淨基線可用；
  被入侵後建基線 = 把攻擊者狀態當正常。未來可做 optional `--baseline`，本次不做。
- **外部信譽資料庫**（NSRL / vendor hash 清單）：違反單一 binary 哲學。否決。
- Sigma 規則層改動：本次實測 Sigma 零誤報，不動。
- Config 化信號閾值：先用常數，未來擴充。

---

## 4. 核心設計：Gate 與 Severity 分離

### 4.1 兩層判定模型

**Gate（發不發）**：一個 heuristic Finding 必須命中至少一個
「乾淨機器上罕見」的**決定性信號（dispositive signal）**才能發出。
未命中者：持久化類 → `Observation`（盤點通道，§6）；
process/netconn 類 → 直接丟棄（無盤點價值）。

**Severity（多嚴重）**：由命中信號的種類決定（下表），
不再使用加權累分。多信號命中：取最高 severity 再升一級
（例 S2+S4 → High 升 Critical；Critical 封頂）。

### 4.2 決定性信號清單

| # | 信號 | 判定 | Severity |
|---|---|---|---|
| S1a | Winlogon 篡改 | `Shell`/`Userinit` 非出廠預設（複用 `winlogon_value_is_default`）| High |
| S1b | IFEO debugger 存在 | 一律過 gate；目標 binary 未簽章或在使用者可寫路徑 → **High**；已簽章且在系統/Program Files → **Medium**（Process Explorer/GFlags 等合法用途）| High/Medium |
| S2 | 明確未簽章 + 使用者可寫路徑 | `signed == Some(false)` **且**路徑含 Temp/Roaming/Downloads/ProgramData/Public（沿用 `CORRELATION_SUSPICIOUS_DIRS` 語義）| High |
| S3 | 系統名偽裝 | 受保護名單（svchost/lsass/csrss/winlogon/services/smss/wininit/explorer/rundll32/dllhost/taskhostw）的 binary 落在**整個 `C:\Windows\` 樹之外**（涵蓋 System32/SysWOW64/WinSxS/Windows 根目錄的合法位置）| High |
| S4 | 近期 + 無法驗證 + 非系統路徑 | last_write ≤ 7 天 **且** `signed == None` **且**路徑不在 `C:\Windows\`/`Program Files` 下——三條件同時成立（任兩個都不夠）| Medium |
| S5 | 近期帳號操作 | AccountHeuristic 現行邏輯（EID 4720/4726/4732/4728，≤90 天 High / 逾期 Medium）保留不動 | High/Medium |
| S6 | 時間戳矛盾 | TimestompHeuristic 現行 SI/FN delta 邏輯保留 | 現行 |
| S7 | 可疑外連組合 | netconn 現行強組合（unsigned + public IP + rare port 等）重述為 gate 信號；單一弱信號（僅 rare port、僅 public IP）不再發 | 現行強組合 |
| S8 | 異常父子行程 | parentchild 現行強組合（office→powershell、encoded、LOLBAS+http）重述為 gate 信號；單一路徑信號不再發 | 現行強組合 |
| S9 | 腳本型持久化 | 持久化 command 呼叫腳本直譯器（powershell / wscript / cscript / mshta / `cmd /c`）：帶編碼參數（`-enc`）或遠端 URL → **High**；指向本機腳本檔（.vbs/.js/.bat/.ps1）→ **Low** | High/Low |

**明確廢除的舊信號：**
- 「近期修改」單獨成立（修 13 個 Medium 誤報）——recency 只能作為 S4 的組成條件
- 「持久化 + 執行過」單獨成立（修 12 個 Medium 誤報）——見 §4.3
- 「service/run_key/startup/scheduled_task 機制存在」的 base weight——歸零，改走 Observation
- 「signed=None → High fail-loud」（修 explorer High 誤報）——見 §5

**Sigma findings 不經 gate**：規則本身即偵測邏輯，且實測零誤報。

### 4.3 CorrelationAnalyzer 併入 PersistHeuristic（刪除獨立 analyzer）

`Analyzer::analyze(&self, records: &[Record])` 本來就收到全部 records。
PersistHeuristic 在信號命中後，內部交叉比對 ExecutionRecord（prefetch/shimcache/
amcache/bam/userassist）與 ProcessRecord（正在執行）：

- 交叉命中 → **severity 升級因子**（+1 級，與多信號升級規則共用封頂邏輯）
  \+ 對應 `EvidenceItem` 附入 Finding
- 交叉本身**永不單獨成立** Finding

`crates/cairn-heur/src/correlation.rs` 移除出 analyzer 清單；
其 binary-name 正規化與分組邏輯移入 persist 的交叉比對 helper。
`main.rs` analyzers vec 移除 `CorrelationAnalyzer`。

---

## 5. `signed` 語義修正

1. **驗章前解析相對路徑**（persist collector，`cairn-collectors`）：
   遇相對路徑（如 winlogon 的 `explorer.exe`）按 Windows 標準搜尋序解析
   （`C:\Windows\System32` → `C:\Windows`）成絕對路徑再驗章。
   解析成功 → 正常驗章結果；解析不到 → 維持 `None`。
2. **`None` 在 gate 中性化**：`None` = 「無法驗證」，既不構成信號
   （只有 `Some(false)` 才是 S2 要素），也不授予豁免（S4 的組成要素之一）。
   2026-06-28 的「None → High」correlation 矩陣廢除。
3. **已知殘留風險（記錄，不本次修）**：簽章驗證用 `WTD_CHOICE_FILE`，
   catalog-signed 檔案（Windows 內建元件常見簽法）會被回報 `Some(false)`。
   S2 因要求「使用者可寫路徑」天然屏蔽大多數 catalog-signed 系統檔；
   未來改進項：補 `WTD_CHOICE_CATALOG`/CryptCATAdmin 驗證。

## 5b. 抑制知識集中化（trust module）

新建 `crates/cairn-heur/src/trust.rs`（或擴充 score.rs），集中所有
「這是正常的」判斷，各 analyzer 共用、禁止在 analyzer 內重寫：

- `winlogon_value_is_default`（自 score.rs 遷入或 re-export）
- `is_inbox_service_command`（自 persist.rs 遷入）
- `is_user_writable_path`（S2/S4 用；取代散落的 SUSPICIOUS_DIRS 判斷）
- `is_under_windows_tree` / `is_system_or_program_files`（S3/S4 用）
- `PROTECTED_SYSTEM_NAMES`（S3 名單）
- `is_trusted_appdata_location`（保留）

---

## 6. Observation 通道（盤點）

### 6.1 型別（cairn-core）

```rust
pub struct Observation {
    pub schema: String,        // "cairn.observation/1"（新 schema 常數）
    pub ts: DateTime<Utc>,     // 該項目自身時間（如 last_write），無則 run 時間
    pub host: String,
    pub category: String,      // "service" | "run_key" | "scheduled_task" | "startup" | "winlogon_default"
    pub title: String,         // 例："服務 AsusAppService → AsusAppService.exe"
    pub path: Option<String>,  // binary 完整路徑
    pub details: String,       // 位置（registry key / 資料夾）、簽章狀態、last_write
    pub source_artifact: String, // "persistence"
}
```

### 6.2 產生與輸出

- `Analyzer` trait 加 default method
  `fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> { Ok(vec![]) }`
  ——現有 implementor 零改動；PersistHeuristic override（gate 未命中者落此）。
- `OutputSink` 加 `write_observations()`（default no-op；DirSink 實作 → `observations.jsonl`）。
- HTML 報告底部新增**折疊**區塊「主機盤點（Host Inventory）」，
  依 category 分組，預設收合，不與 findings 混排。
- Manifest 加 `observation_count: u64`（serde default，向後相容）。

---

## 7. Finding.evidence 結構化來源（原待辦 A 併入）

### 7.1 型別（cairn-core::finding）

```rust
pub struct EvidenceItem {
    pub artifact: String,          // "prefetch" | "shimcache" | "run_key" | "evtx:Security" | …
    pub path: Option<String>,      // 該來源見到的完整路徑（prefetch 僅檔名，見 §7.3）
    pub ts: Option<DateTime<Utc>>, // 該來源的時間戳（last_run / last_write / event ts）
    pub detail: String,            // 人讀描述："prefetch: 執行 12 次，最後 2026-06-27T23:31Z"
}
// Finding 加欄位：
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub evidence: Vec<EvidenceItem>,
```

schema 字串維持 `cairn.finding/1`（additive、向後相容；舊 JSON 反序列化得空 Vec）。

### 7.2 輸出格式規範（直覺性要求）

- **title**：`<信號描述>: <binary 短名>`，例
  `未簽章執行檔於使用者可寫路徑: evil.exe`
- **details 第一行 = binary 完整路徑**（無路徑時 = 持久化位置全名），
  之後才是機制、簽章狀態、時間等；HTML 不展開即可見路徑。
- **evidence**：每個佐證來源一條（persistence 位置、各執行 artifact、正在執行的 pid）。
- HTML findings 表格每列可展開 evidence 清單。

### 7.3 誠實標注

prefetch 的 `path` 是檔名粒度（格式限制），該 EvidenceItem 的 `detail`
註明「prefetch 僅記錄檔名，完整路徑見 shimcache/amcache 條目」。

---

## 8. 資料流（重設計後）

```
records ──► SigmaAnalyzer ────────────────► Findings（不經 gate）
        ──► PersistHeuristic ─ gate 命中 ─► Findings（title/details/evidence 規範化）
        │                    └ 未命中 ────► Observations（服務/自啟/排程/winlogon 預設清單）
        ──► NetConn/ParentChild ─ 強組合 ─► Findings；弱信號 → 丟棄
        ──► Account/Timestomp ────────────► Findings（現行邏輯，補 evidence）
Findings ► findings.jsonl / timeline.csv / report.html（現行）
Observations ► observations.jsonl / report.html 折疊區塊 / manifest 計數（新）
```

## 9. 測試矩陣（摘要）

| 類別 | 案例 |
|---|---|
| Gate 正向 | S1a winlogon 篡改、S1b IFEO 未簽章目標、S2 unsigned+Roaming run key、S3 svchost 在 AppData、S4 三條件齊、S9 `-enc`/遠端 URL |
| Gate 反向（乾淨情境不發）| winlogon 預設值、IFEO→簽章 procexp（Medium 非 High）、簽章 Chrome 自啟、update 日整批服務 recency、per-user svchost 實例、`explorer.exe` 相對路徑解析後簽章 OK、signed+Downloads |
| 升級 | S2+S4 → Critical；S2 + 執行交叉 → 升一級；Critical 封頂 |
| Observation | 未命中服務落 observations、count 進 manifest、winlogon 預設值落 observation 非 finding |
| Evidence | correlation 交叉附 prefetch/shimcache 條目、details 首行 = 完整路徑、舊 JSON 反序列化空 evidence |
| 相對路徑解析 | `explorer.exe` → `C:\Windows\explorer.exe`；解析不到維持 None |
| 回歸 | EVTX-ATTACK-SAMPLES parity 全過；`cairn run --target live` 真機 e2e：High=0、Medium=0 |

## 10. 分段建議（交 writing-plans 展開）

1. **段 1（地基）**：cairn-core（Observation + EvidenceItem + manifest 欄位 + trait default methods）
   \+ trust.rs 集中化 + persist collector 相對路徑解析。
2. **段 2（gate 重寫）**：persist gate + correlation 併入 + S1-S4/S9 信號 + 測試矩陣。
3. **段 3（輸出）**：netconn/parentchild gate 化 + observations.jsonl + HTML + evidence 填充
   \+ 真機 e2e 驗收。

## 11. 殘留風險登記

- catalog-signed 誤報 `Some(false)`（§5 第 3 點）——S2 的路徑條件屏蔽大多數；未來補 catalog 驗證。
- 有效簽章的惡意軟體（偷來的憑證）+ 正常路徑 → 不觸發 S1-S4/S9 → 僅 Observation。
  屬所有靜態工具的共同盲區，由 Sigma/行為層（S7/S8）部分覆蓋。接受。
- `Program Files` 視為可信路徑：需要 admin 才能寫入；已被提權的攻擊者可利用。接受
  （提權後有更隱蔽的選項，此非主要防線）。
