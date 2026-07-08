# HTML Report Filtering & Aggregation — Design Spec

> **Date:** 2026-07-08
> **Status:** Approved direction — pending user spec review
> **Scope:** REMAINING-WORK.md segment 1 (revised scope): client-side filtering for the
> Findings table (severity/artifact/keyword), a same-source-binary aggregation summary,
> and two small leftover fixes from ir-snapshot-panels (`state_active` display, netconn
> panel title). **Not in scope**: evidence detail display (already exists, gate-redesign
> merge `068983e`).
>
> **⚠️ 2026-07-08 自我審查更正**：REMAINING-WORK.md 殘留風險登記表原寫
> 「`WtsSession.state_active` 已收集但無面板讀取」——**查證後這個描述不準確**。
> `LogonSessionRecord`（`cairn-core/src/record.rs:131-137`）根本沒有 `state_active`
> 欄位；`logon_session.rs:19-34` 對映 collector 內部的 `WtsSession` 到
> `LogonSessionRecord` 時，直接丟棄了 `s.state_active`（collector 有算出這個值，
> 但從未進入 schema）。因此本段**新增一個 additive schema 欄位**
> （`LogonSessionRecord.state_active: bool`），這是唯一涉及 schema 的部分，其餘
> （篩選、聚合、netconn 標題）仍是純 `html.rs` 呈現層改動、schema 不變。
> **Depends on:** gate-redesign (Finding.evidence exists), ir-snapshot-panels (panel
> pattern + the two leftover items being fixed here).
> **SRS refs:** golden rule 4 (report is read-only artifact, no network), security.md §1.5
> (XSS via `esc()`), CLAUDE.md report must be openable offline with zero external resources.

---

## 1. 問題陳述

`report.html`（`crates/cairn-report/src/html.rs`）目前是純伺服器端字串拼接的靜態
HTML，零 JavaScript。Findings 表格已有 evidence 折疊明細（`<details>`，gate-redesign
時做的），但調查者在大量 findings 時無法：
1. 只看某個 severity（例如只看 Critical/High，暫時濾掉 Medium/Low/Info 雜訊）
2. 只看某個 artifact 來源（例如只看 Sigma 命中，濾掉 heuristic）
3. 用關鍵字快速定位（例如搜尋某個檔名）
4. 一眼看出「同一個執行檔在多筆 finding 裡反覆出現」——目前每筆 finding 是獨立
   row，同一個 binary 造成的多筆 finding 彼此沒有視覺關聯。

此外 ir-snapshot-panels 遺留兩個小殘留：`LogonSessionRecord.state_active` 已收集但
沒有任何面板顯示；「對外連線」面板標題涵蓋 listener（入站）與所有 UDP（無 state），
語意比實際內容寬。

## 2. 目標與非目標

**目標**
1. Findings 表格的每個 `<tr>` 可依 severity（多選）、artifact（單選下拉）、關鍵字
   （比對 title + details）即時顯示/隱藏，三個條件 AND 組合，純前端不重新整理頁面。
2. 新增「相同來源多次出現」摘要區塊：掃描所有 finding 的 `evidence[].path`，取
   basename 去重計數，只列出現 ≥2 次的 basename，格式比照既有 `.inventory` 面板
   （`<details>` 預設收合），一筆都沒有就不輸出整個區塊。
3. `logon_panel` 新增一欄顯示 `state_active`（Yes/No，`None` 顯示 `-`）。
4. `netconn_panel` 標題「對外連線」改名「網路連線」（不再暗示全部是對外/建立中）。

**非目標**
- 不做 evidence 明細顯示——已存在。
- 不改 Finding/Record schema——聚合摘要是純衍生呈現，不新增欄位。
- 不做伺服器端分頁或伺服器端篩選——資料量在單機報告場景下（實測最大幾百筆
  finding）前端字串比對足夠，不需要虛擬滾動等複雜度（YAGNI）。
- 不做跨 session 篩選狀態記憶（localStorage 等）——報告是一次性產物，開啟時重置
  是合理預期。
- 不做正規表示式搜尋——純子字串（substring）比對，避免使用者輸入無效 regex 導致
  JS 例外。

## 3. 架構設計

### 3.1 資料屬性（無 JS 也能 render，JS 只負責顯示/隱藏）
現有 findings row 產生迴圈（`html.rs:401-451`）在 `<tr>` 加兩個 `data-*` 屬性：
```html
<tr data-severity="high" data-artifact="evtx:security" ...>
```
- `data-severity`：`sev_label()` 小寫版本（`critical`/`high`/`medium`/`low`/`info`）。
- `data-artifact`：`esc(&f.artifact)`（沿用既有 `f.artifact` 欄位，非 `f.source`
  的 Sigma/啟發式二分類——`artifact` 是實際來源字串如 `evtx:Security`、
  `persist:run_key`，篩選細粒度更有意義）。

**沒有 JS 時**（例如使用者用純文字檢視器打開）：所有 row 仍然完整輸出在 HTML
裡，只是不能互動篩選——不影響資料完整性，符合「報告是唯讀鑑識產物」的定位。

### 3.2 篩選列 UI（Findings 卡片內，表格上方）
```html
<div class="filter-bar">
  <div class="filter-group">
    <label><input type="checkbox" class="sev-filter" value="critical" checked> Critical</label>
    <label><input type="checkbox" class="sev-filter" value="high" checked> High</label>
    <label><input type="checkbox" class="sev-filter" value="medium" checked> Medium</label>
    <label><input type="checkbox" class="sev-filter" value="low" checked> Low</label>
    <label><input type="checkbox" class="sev-filter" value="info" checked> Info</label>
  </div>
  <select id="artifact-filter">
    <option value="">全部來源</option>
    <!-- 動態產生：從 sorted findings 的 f.artifact 去重排序 -->
  </select>
  <input type="text" id="keyword-filter" placeholder="搜尋標題或說明...">
  <span id="filter-count"></span>
</div>
```
- Artifact `<option>` 清單由 Rust 端產生（`BTreeSet<&str>` 去重排序，同
  `execution_panel` 已有的 `sources` 模式），**不是** JS 動態掃 DOM 產生——避免
  JS 重複實作 Rust 已經算好的集合，且無 JS 環境下拉選單仍完整可見。
- 若 `sorted.is_empty()`（無 finding），不輸出篩選列（比照其他面板「無資料不顯示」
  的一貫哲學）。

### 3.3 JS（單一 `<script>`，檔案末尾，findings 表格之後）
```js
(function() {
  var checkboxes = document.querySelectorAll('.sev-filter');
  var artifactSel = document.getElementById('artifact-filter');
  var keywordInput = document.getElementById('keyword-filter');
  var rows = document.querySelectorAll('#findings-tbody tr[data-severity]');
  var countEl = document.getElementById('filter-count');
  if (!rows.length) return;

  function applyFilter() {
    var activeSevs = Array.prototype.filter.call(checkboxes, function(cb) { return cb.checked; })
                          .map(function(cb) { return cb.value; });
    var artifact = artifactSel.value;
    var keyword = keywordInput.value.toLowerCase();
    var visible = 0;
    rows.forEach(function(row) {
      var sevOk = activeSevs.indexOf(row.dataset.severity) !== -1;
      var artOk = !artifact || row.dataset.artifact === artifact;
      var kwOk = !keyword || row.textContent.toLowerCase().indexOf(keyword) !== -1;
      var show = sevOk && artOk && kwOk;
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    countEl.textContent = '顯示 ' + visible + ' / ' + rows.length + ' 筆';
  }
  checkboxes.forEach(function(cb) { cb.addEventListener('change', applyFilter); });
  artifactSel.addEventListener('change', applyFilter);
  keywordInput.addEventListener('input', applyFilter);
  applyFilter();
})();
```
- IIFE 包裹避免污染全域命名空間；`rows.length === 0` 時提早 return（無 finding
  時腳本不必做任何事，也對應 3.2 的「無資料不輸出篩選列」——`querySelector` 找不到
  控制項時 IIFE 一樣安全提早返回）。
- `row.textContent` 天然是已 `esc()` 過的文字內容之逆向（瀏覽器解析 HTML 後
  `.textContent` 拿到的是解碼後的純文字），關鍵字比對不會受 HTML escape 影響。
- 沒有任何 `innerHTML` 賦值、沒有 `eval`、沒有外部請求——純讀取 DOM + 切換
  `style.display`，不引入新的 XSS 面（security.md §1.5：現有 `esc()` 仍是唯一
  的資料→HTML 邊界，JS 不繞過它）。

### 3.4 同來源聚合摘要（新函式 `evidence_source_summary_panel`）
```rust
fn evidence_source_summary_panel(findings: &[&Finding]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        let mut seen_in_this_finding: BTreeSet<String> = BTreeSet::new();
        for ev in &f.evidence {
            if let Some(path) = &ev.path {
                let base = basename(path); // 複用或新增小工具函式
                seen_in_this_finding.insert(base);
            }
        }
        for base in seen_in_this_finding {
            *counts.entry(base).or_insert(0) += 1;
        }
    }
    let mut repeated: Vec<(&String, &usize)> = counts.iter().filter(|(_, &c)| c >= 2).collect();
    if repeated.is_empty() { return String::new(); }
    repeated.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0))); // 次數多的優先
    // ... 組出 <details class="inventory"> 表格，欄位：檔名 / 出現次數
}
```
- **basename 萃取**：以 `\` 與 `/` 兩種分隔符切割取最後一段（Windows 路徑為主，
  但誠實處理正斜線，避免 UNC/正斜線路徑被誤判成完整路徑當作檔名——呼應
  REMAINING-WORK.md 殘留風險登記表裡 `trust.rs` 同類問題，這裡直接兩種都處理，
  不留同樣的坑）。
- **同一筆 finding 內去重再計數**（`seen_in_this_finding`）：避免單一 finding
  自己有 3 筆 evidence 都指向同一個 basename 時被誤算成「出現 3 次」——語意上
  「出現次數」應該是「幾筆不同 finding 提到它」，不是「evidence 筆數」。
- 呼叫點：`html_report()` 內，在 findings 表格之後、`{netconn_html}` 之前插入
  `{evidence_summary_html}`。

### 3.5 兩個小修

**3.5.1 `state_active`（涉及 schema，additive 變動）**
- `cairn-core/src/record.rs`：`LogonSessionRecord` 新增欄位
  `pub state_active: bool`。**Additive 變動**：新增非 `Option` 的 `bool` 欄位在
  serde 反序列化舊 JSON 時會失敗（無 `#[serde(default)]` 則缺欄位即錯），故必須
  加 `#[serde(default)]`（預設 `false`——若舊資料沒有這欄位，保守假設 session
  非 active 狀態，不誇大;`schema` 版本字串本身不需變動，因為是 additive-with-default
  的相容變更，同 `Finding.evidence` 當初的作法）。
- `crates/cairn-collectors/src/logon_session.rs:19-34`：對映時補上
  `state_active: s.state_active`（collector 內部 `WtsSession.state_active` 本來
  就存在，`cairn-collectors-win/src/logon.rs:10,139`，只是先前沒接進 Record——
  這行是把既有資料接上，不是新收集邏輯）。
- `html.rs` `logon_panel`（`:309-349`）：`<tr>` 加一欄
  `esc(if s.state_active { "是" } else { "否" })`（欄位確認是 `bool` 非
  `Option<bool>`，不需要處理 `None` 分支）；表頭加對應 `<th>狀態</th>`。

**3.5.2 netconn 標題（純呈現層，schema 不變）**
- `netconn_panel`（`html.rs:76-129`）：`"對外連線 ({} 條..."` 改為
  `"網路連線 ({} 條..."`；函式名稱、變數名不動（避免無謂改動面，只改顯示字串）。

## 4. 錯誤處理與安全

- 篩選 UI 與 JS 完全是呈現層附加物，資料本身（`records.jsonl`/`findings.jsonl`）
  不受影響——這是「report.html 是衍生視圖，權威資料在別處」既有原則的延伸。
- JS 不做任何網路請求、不用 `eval`/`Function`/`innerHTML` 賦值，只用
  `textContent` 讀取與 `style.display` 寫入，離線開啟零外部資源（golden rule
  對應 CLAUDE.md「報告需能離線開」）。
- 所有既有 `esc()` XSS 防線不變動；`data-severity`/`data-artifact` 屬性值來自
  程式內部枚舉（`sev_label()` 小寫化）與 `esc()` 過的 artifact 字串，不會被
  HTML 屬性注入破壞（severity 是封閉列舉，artifact 走既有 escape）。

## 5. 測試策略

| 項目 | 單元測試 |
|---|---|
| data 屬性存在 | finding 的 `<tr>` 含正確的 `data-severity`/`data-artifact` 值（斷言字串包含） |
| Artifact 下拉選項 | 多筆不同 artifact 的 finding → `<option>` 清單含全部去重值；空 findings → 不輸出篩選列 |
| 同來源聚合：計數邏輯 | 兩筆 finding 各自 evidence 指向同一 basename → 聚合區塊顯示「2」；只有 1 筆提及 → 不列入（`< 2` 過濾）；單一 finding 內同 basename 出現 3 次 evidence → 仍算 1（不重複計） |
| 同來源聚合：basename 萃取 | 反斜線路徑、正斜線路徑、純檔名（無分隔符）三種輸入都能正確取到檔名 |
| 同來源聚合：空狀態 | 沒有任何 basename 重複 → 區塊不輸出（`html` 不含該區塊標題文字） |
| `LogonSessionRecord` 新欄位 | 舊格式 JSON（無 `state_active` 鍵）反序列化成功且 `state_active` 預設 `false`（`#[serde(default)]` 回歸測試）；新序列化輸出含 `state_active` 鍵 |
| logon state_active 顯示 | `state_active=true` 顯示「是」、`false` 顯示「否」，表頭含新欄位 |
| netconn 標題 | `html` 含「網路連線」，不含「對外連線」 |
| JS 語法完整性（有限） | 生成的 `<script>` 內容作為純文字斷言包含關鍵片段（`addEventListener`、無 `eval(`、無 `innerHTML =`）——**不**用無頭瀏覽器做真的 JS 執行測試（YAGNI，這個專案沒有既有的瀏覽器測試基礎設施，加一個超出本段範圍） |

**真機驗收**：跑一次真機掃描，開啟 `report.html`：
1. 手動勾掉/勾選 severity checkbox，確認對應 row 顯示/隱藏且計數正確。
2. 用 artifact 下拉切換，確認篩選正確。
3. 關鍵字框輸入已知存在於某 finding title 的字串，確認只留下相符 row。
4. 若機器上有重複出現的執行檔痕跡（不一定會有），確認聚合區塊正確；若沒有，
   確認區塊不出現。
5. 登入 session 面板（若本機有 session）顯示 state_active 欄；網路連線面板標題
   正確。

## 6. 已知約束與殘留風險

1. **關鍵字搜尋是純子字串比對，非全文檢索**——大小寫不敏感（JS `toLowerCase()`），
   但不支援萬用字元或 regex。對單機 IR 報告的資料量（通常數十到數百筆 finding）
   這已足夠；未來若真的需要更複雜查詢，屬於獨立 spec（可能改用完整的
   client-side 搜尋庫，但那會引入外部資源或大量 inline 程式碼，與目前「報告
   保持輕量」的定位衝突，非本次範圍）。
2. **同來源聚合只看 `evidence[].path`**——不會納入沒有 evidence 或 evidence
   全部 `path=None` 的 finding（例如某些 heuristic 的 evidence 可能只有
   `detail` 文字沒有 `path`）。這是誠實的範圍限制，不是 bug：沒有 path 就無法
   算 basename。
3. **basename 萃取是簡化啟發式**——不處理如 `C:\a\b\..\c.exe` 這類含 `..` 的
   路徑正規化（YAGNI，實務上收集到的路徑極少出現這種型態，出現時只是聚合計數
   略微失準，不影響 Finding 本身的正確性）。
4. **三個篩選條件目前無法「反選」**（例如「排除某 artifact」）——只有「包含」
   語意，符合 REMAINING-WORK.md 原始需求措辭，未來若有需要可加，不在此次範圍。

## 7. 分段建議（交 writing-plans）

單一段落即可完成，涉及 `cairn-core`（schema additive 變動）+
`cairn-collectors`（映射補線）+ `cairn-report`（呈現層主體）三個 crate：
1. **schema 先行**：`cairn-core::record::LogonSessionRecord` 加
   `state_active: bool`（`#[serde(default)]`）+ 舊格式反序列化回歸測試；
   `logon_session.rs` 補映射 + 單元測試（`state_active` 隨 `WtsSession` 正確
   傳遞）。這步驟改了三個 crate 共用的型別，是本段唯一需要指揮官（非 subagent
   scoped 測試）跑 `cargo test --workspace` 確認無跨 crate 破壞的步驟。
2. `data-severity`/`data-artifact` 屬性 + artifact 下拉選項生成 + 單元測試。
3. 篩選列 HTML + JS `<script>` 區塊 + 單元測試（字串斷言）。
4. `evidence_source_summary_panel` 函式 + `basename` 小工具函式 + 呼叫點接線 +
   單元測試（含計數邏輯、basename 萃取、空狀態）。
5. `logon_panel` 顯示 state_active 欄 + `netconn_panel` 標題改名 + 對應測試更新。
6. 真機驗收（見 §5）。

跨段共通紀律：`cairn-collectors`/`cairn-report` 維持 `#![forbid(unsafe_code)]`
（本段不涉 unsafe）；schema 變動僅限 §3.5.1 的 additive 欄位（`#[serde(default)]`
向後相容，`schema` 版本字串不需變動）；Cargo.lock 零變動（零新依賴，純 inline
JS 字串）；本機驗證三件套（`cargo fmt --check` + `cargo clippy --workspace
--all-targets -- -D warnings` + task 1 用 `cargo test --workspace`、其餘 task
可用 `cargo test -p cairn-report`）；merge 走 GitHub PR、CI 綠才 merge
（2026-07-08 新增紀律）。
