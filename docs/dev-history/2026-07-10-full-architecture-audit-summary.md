# Cairn 全架構深審總覽（2026-07-10）

基準：main HEAD `4dbc628`（段 8 已 merge）。六面向獨立 fresh-context 審計，各自完整報告見
`docs/dev-history/audit-2026-07-10/{A,B,C,D,E,F}-*.md`。本檔是合併後的優先序總表，供決策用；
細節與行號證據一律以各分報告為準。

三個 opus 面向（A/B/C）逐一經 controller 抽驗屬實；三個 sonnet 面向（D/E/F）逐一 spot-check
關鍵 finding 屬實（E 的 G-1 prefetch tautology 已親自讀碼確認）。

## 總計

| 面向 | 報告 | Finding 數 | 最高嚴重度 |
|---|---|---|---|
| A 關聯/分析層架構 | A-correlation-architecture.md | 8（高1中5低2） | 高 |
| B unsafe crate 健全性 | B-unsafe-soundness.md | 3（低1資訊2） | 低 |
| C 並行正確性/determinism | C-concurrency-determinism.md | 3（低2資訊1） | 低 |
| D schema 向後相容 | D-schema-compat.md | 4（中1低2資訊1） | 中 |
| E 測試品質（fixture vs 真實資料鏈） | E-test-fixture-gaps.md | 6+13（見下）| 高 |
| F 錯誤處理/graceful degrade | F-error-handling.md | 1（低） | 低 |

段 8 審計（2026-07-10 稍早，`docs/dev-history/2026-07-10-resilience-audit.md`）的 F-1/F-8
已納入本輪 A/E 的交叉驗證範圍，不重複計數。

## 最高優先（跨面向交叉指向同一根因）

**live proc collector 資料缺口是本輪最大的單一根因**，被 A、E 兩個獨立面向從不同角度指向同一處：

- （A）`proc.rs:142-146` cmdline/integrity/start_time 恆 None → parentchild 半數訊號 live 下不觸發
  （段 8 F-1 已知），**且 A 新發現：段 3 temporal-correlator 因 start_time 恆 None 而在 live 模式
  下實質是 no-op**——這代表段 3 若在段 9 之前實作，等於白做。
- （E）同一缺口的下游效應：`parentchild.rs:203` 的 `Finding.ts` 因 start_time None 而靜默退回
  `Utc::now()`，**汙染 live finding 的時間軸排序**，且該模組零測試斷言檢查過 `f.ts`。

**結論：段 9（F-1 修補：cmdline/integrity/start_time 採集）必須排在段 3（temporal-correlator）
之前**，這改變了原本 REMAINING-WORK 建議的執行順序（原順序是段 2→段4塊C→段3→段9系列）。

## 高/中優先 finding（按面向）

1. **（A-高）** 見上——已併入「最高優先」。
2. **（A-中）F-2** `persist.rs` 跨文物 join key 只取檔名 basename（去 `.exe`），不看路徑 → 同名
   不同路徑會誤佐證升級 severity；command-only 持久化又漏佐證。已讀碼確認（
   `normalized_basename` 函式，persist.rs:210-219）。
3. **（A-中）F-3** 關聯單向：只從 persistence 側撈 exec/proc 佐證，process 側無反查自己的持久化
   /落地/執行歷史。
4. **（A-中，另 3 條）** timestomp/account/logon/UsnEvent/MotW 五類記錄彼此孤立無關聯；
   UsnEvent 零消費者、Zone.Identifier（MotW）已採集卻無人使用——白白浪費已收集的資料。
5. **（E-高）G-1** `prefetch.rs` v30 run_count offset（`0xD0`）從未真機驗證，但單元測試
   `parse_v30_basic` 的 fixture 用同一個 `run_count_offset()` 函式產生預期值 → **同一常數自證
   自己，offset 若真的錯，測試永遠不會發現**。已讀碼確認（prefetch.rs:400-424）。
6. **（E-中）G-2** Sigma parity harness 只測手造 JSON EventRecord，真實 EVTX 解析與規則比對是
   兩條不相交的測試路徑，從未端到端測過「真實 EVTX bytes → 規則命中」。
7. **（D-中）** `manifest.rs::RunInfo.profile`/`.selected_modules`（S2-L 後加，`1c4a1bf`）缺
   `#[serde(default)]` → **舊 manifest 檔案會讓 `cairn verify` 直接 hard-fail**，不是 graceful
   degrade 而是硬錯誤。這是本輪唯一「會讓既有功能真的壞掉」的 finding，建議與段 9 一起修（改動
   極小：兩個欄位加 default）。

## 低/資訊優先（值得記錄，不急）

- （C）CLAUDE.md 宣稱「Parallelism via rayon」與實況不符：執行緒池建了但零 `par_iter`/
  `par_bridge` 呼叫，全序列執行。不是 bug，但文件失準——已讀碼確認零使用。
- （C）Determinism 實際靠「`run_live` 序列 + 各 collector 自排序 + stable sort」達成，不是
  CLAUDE.md 寫的「sort by (ts, record_id)」；`record_id` 實際上不是任何輸出的排序鍵。
- （B）`net.rs` 對 `MIB_*TABLE_OWNER_PID` 做 `Vec<u8>` 裸轉型，對齊需求 4 但 Vec 只保證 1——
  靠 allocator 實務行為僥倖不炸，語言層無保證。golden rule 1 檢查：**未發現 evasion 手法**。
  PEB cmdline 讀取可行性結論：**可行且低風險**，`windows 0.62.2` 已含所需符號，六個陷阱已列
  於 B 報告 §4，供段 9 實作參考。
- （F）**零真正的 golden-rule-8 違規**；7 個 raw-NTFS/hive collector 的 graceful degrade 模式
  高度一致（try→flag→warn→continue）；NFR9/10 資源上限確認真的被遵守，非虛設參數。唯一軟性
  問題：`CairnError::Other` 在多個 crate 被當 catch-all 用，限制未來錯誤分支能力。

## Sigma/heuristic 分工盲區（A 面向新發現，非段 4 已追蹤項目）

- UsnEvent record 完全零消費者（採集了但沒有 analyzer/Sigma 用）
- Zone.Identifier（Mark-of-the-Web）已被採集但無人讀取比對
- timestomp/account/logon 三類記錄彼此孤立，無跨類型關聯

## 對 REMAINING-WORK.md 執行順序的建議調整

原順序（見 REMAINING-WORK.md「建議執行順序」）：段0→段1→段2→段4塊C→段3→段4塊A/5/6→段7。

**建議改為**：段9（F-1系列：cmdline/integrity/start_time 採集 + manifest RunInfo default 修復
+ persist join key 改路徑感知）優先於段3（temporal-correlator），理由是 A 面向證實段3在段9
完成前對 live 資料是 no-op。段2（Sigma擴充）與段9可平行，彼此無資料依賴。

## 明確：本輪未發現的問題類別

- 面向 B：無 evasion 手法、無 handle 洩漏、無 golden-rule-1 違規
- 面向 C：無資料競爭、無 atomic ordering 錯誤、無共享可變狀態問題
- 面向 F：無真正的 panic-prone unwrap、無資源上限虛設、無 NFR12 abstain 缺失
- 面向 D：schema 字串常數使用一致無 drift（除 `schema::RECORD` 零呼叫點外）
