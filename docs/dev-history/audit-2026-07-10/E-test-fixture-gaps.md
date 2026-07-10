# Cairn 測試 Fixture 真實性審計（交付物 E）

- 日期：2026-07-10
- 審計者：獨立 fresh-context 稽核（未參與實作，未修改任何程式碼/文件）
- 範圍：`crates/cairn-heur/src/*.rs`、`crates/cairn-collectors/src/*.rs`、
  `crates/cairn-collectors-win/src/*.rs`、`crates/cairn-sigma/tests/parity.rs`、
  `crates/cairn-cli/src/main.rs` 的整合測試、`tests/fixtures/`。
- 校準基準：`docs/dev-history/2026-07-10-resilience-audit.md` 的 F-1
  （live proc collector 不採集 `cmdline`/`integrity`，導致 parentchild 一半訊號
  在 live 掃描下永不觸發，47 個測試全綠卻毫無訊號揭露此落差）。

## 摘要

| 嚴重度 | 數量 |
|---|---|
| 高 | 2 |
| 中 | 2 |
| 低 | 2 |
| 合計 | 6 |

與 F-1 同等級（heuristic 假設某欄位有意義、但 live/real 資料來源從不產生該資料，
且測試對此毫無訊號）的**新案例**：**1 個**——G-1（prefetch v30 run_count offset
`0xD0`，見下）。另有 1 個同構但風險較低的變體（G-2，Sigma 規則從未對真實 EVTX
位元組跑過），以及沿續 F-1 本身在其他欄位上的下游效應（G-3，account/timestomp/
netconn 的時間戳輸入鏈）。

---

## 1. 對照表：heuristic → 依賴欄位 → live collector 是否真填值 → 落差等級

| Heuristic | 依賴欄位 | 填值位置（live） | 是否真填值 | 落差等級 |
|---|---|---|---|---|
| parentchild (`parentchild.rs`) | `ProcessRecord.cmdline` | `cairn-collectors-win/src/proc.rs:142` 恆 `None`→`collectors/src/proc.rs:101` 正規化為 `""` | **否** | **F-1（已知，高）**：encoded-PS(+40)/LOLBAS(+30) 對空字串全回 false，live 掃描永不觸發 |
| parentchild | `ProcessRecord.integrity` | `proc.rs:143` `integrity_raw` 恆 `None` | **否** | **F-1（已知，高）**：unsigned-high-integrity(+15) 永不觸發 |
| parentchild | `ProcessRecord.signed` | `collectors/src/proc.rs:27-34 apply_signatures`，僅絕對路徑（`is_absolute_path`） | 部分：絕對路徑有填，OpenProcess 失敗留短檔名則 `None` | 已知殘留（F-1 表已記） |
| parentchild | `ProcessRecord.start_time` | `proc.rs:146` 恆 `None`；`parentchild.rs:203` `f.ts = p.start_time.unwrap_or_else(Utc::now)` | **否** | 已知（F-1 表已記，`user`/`start_time` 列），下游影響 Finding.ts 失真，非本審計新發現 |
| netconn (`netconn.rs`) | `NetConnRecord`（無 ts 欄位，設計如此，`netconn.rs:119-121` 註解已誠實標示） | schema 本身無此欄位 | N/A（誠實不採集，非漏採） | 此類未發現問題——netconn.rs:119-121 已主動註解說明為何 `f.ts` 用預設收集時間 |
| netconn | `ProcessRecord.image`/`signed`（owner 查找） | 同上 proc.rs 鏈 | 部分（同 F-1 表） | 沿用 F-1 的殘留，netconn 本身邏輯對 None 值優雅降級（測試 `unsigned_owner_alone_does_not_amplify` 等已覆蓋） |
| account (`account.rs`) | `EventRecord.data`（EVTX 4720/4726/4732/4728 的 TargetUserName 等） | `crates/cairn-collectors/src/evtx.rs`（真實 EVTX 解析，或 `evtx_live.rs` 讀 winevt Logs） | **是**——EVTX 是 Security channel 的官方稽核資料，欄位由 Windows 稽核子系統填，非本工具自行採集缺口 | 此類未發現問題 |
| timestomp (`timestomp.rs`) | `FileMetaRecord.si_btime/fn_btime/si_mtime/fn_mtime` | raw-NTFS `$MFT` 屬性讀取（mft.rs），需 SeBackupPrivilege | 需權限才真填；無權限時 collector 整體不產生記錄（graceful skip，非部分填值） | 此類未發現「heuristic 假設有值但 collector 給假值」的問題——是全有全無的權限閘門，不是欄位語意落差 |
| byovd (`byovd.rs`) | `ExecutionRecord.sha1`（來源 `amcache_driver`） | `crates/cairn-collectors/src/amcache.rs`（raw-NTFS hive，需 SeBackupPrivilege），SHA1 嚴格解析 FileId，格式不符則誠實 `None`（NFR12） | 需權限；格式解析邏輯本身經審查（見既有 memory 記錄：T3 quality 審查抓到 per-subkey 錯誤處理漏洞並修正） | 此類未發現新問題——`byovd.rs:65-70` 已對 `None` sha1 誠實跳過，測試 `none_sha1_is_skipped_not_matched` 覆蓋 |
| persist (`persist.rs`) | `PersistenceRecord.signed`/`last_write`/`binary_path` | `crates/cairn-collectors/src/persist.rs`：`apply_signatures`（812-822 行）真的呼叫 `WinSigVerifier`；`key_last_write`（576-588 行）真的查 registry `query_info()` | **是**——與 parentchild/proc 不同，persist collector 確實填了這些欄位 | 此類未發現問題（本審計特別檢查了這個，因為 heur_persist 的 gate 高度依賴 `signed`/`last_write`，結果證實 collector 端有真實填值，非空殼） |
| LogonSession（無對應 heuristic） | `LogonSessionRecord.logon_time` | `cairn-collectors-win/src/logon_session.rs:30` 恆 `None`，註解誠實標示「WTS 無可靠的登入時間戳」 | **否**，但誠實揭露且**無 heuristic 消費此欄位做評分**（LogonSession 僅用於顯示/報告，不參與偵測邏輯） | 此類未發現問題——不構成 F-1 類型風險，因為沒有偵測邏輯建立在此欄位的錯誤假設上 |
| Sigma engine (`SigmaAnalyzer`) | `EventRecord.data`（真實 EVTX 位元組解析出的 JSON 欄位形狀/型別/缺失模式） | 規則比對測試只用手造 `json!({...})` fixture（`crates/cairn-sigma/tests/parity.rs`），從未對`parse_evtx` 解析真實 EVTX 檔案後的 `EventRecord` 跑過 Sigma 規則 | **否**——手造 fixture 直接假設欄位齊全、型別正確 | **G-2（新發現，中）**：見下方 Findings |
| prefetch (`prefetch.rs`) 的解析邏輯（非 heuristic，但屬同一「fixture 真實性」風險類型：v30 run_count offset） | Win10 v30 `.pf` 檔的 `run_count` 欄位 offset | `run_count_offset()`：v31=`0xC8`（machine-verified），v30=`0xD0`（**never machine-verified**，程式碼註解 67-69 行已自承） | 部分——offset 常數本身未經真機驗證，但單元測試用同一常數建構 fixture，測試對此邏輯錯誤沒有偵測能力 | **G-1（新發現，高，見下）** |

---

## 2. Findings

### G-1（高）prefetch v30 run_count offset 從未經真機驗證，且單元測試對此是同義反覆

- **檔案:行號**：`crates/cairn-collectors/src/prefetch.rs:67-69`（註解自承）、
  `crates/cairn-collectors/src/prefetch.rs:87-92`（`run_count_offset` 常數表）、
  `crates/cairn-collectors/src/prefetch.rs:418-420`（`parse_v30_basic` 測試）。
- **問題**：v31 offset `0xC8` 已用真機 `.pf` 解壓位元組交叉驗證（run-time 非零數量
  等於 run_count，見 memory 記錄的 bam/prefetch 開發史）。但 v30 offset `0xD0` 只是
  「文件記載的歷史值」，程式碼註解誠實承認「no v30 host was available」。**問題不在
  於該常數本身可能有誤**（這是已知殘留，程式碼已誠實揭露），而在於：`parse_v30_basic`
  單元測試用 `0xD0` 這個常數本身組出合成的 .pf body，再驗證解析器從 `0xD0` 讀出正確
  的 `run_count`——這是同義反覆（tautology）：如果真實 Win10 v30 的 offset 其實是
  `0xCC` 或別的值，這個測試依然 100% 通過，因為測試假設的 offset 與被測程式碼的
  offset 是同一個常數來源。這正是 F-1 案例的同構版本：測試證明的是「邏輯自洽」，
  不是「邏輯符合真實資料格式」。
  在真實 Windows 10（非 11）機器上執行 `cairn run`，若 `0xD0` 有誤，`run_count`
  會靜默讀出錯誤數值（不是 abstain、不是 None，是一個看起來合理但錯誤的整數），
  下游 `heur_persist` 的 execution-corroboration 邏輯（`persist.rs:307-332
  execution_evidence`）與分析師看到的 IR 報告都會呈現這個錯誤數字，且沒有任何
  現有測試或 CI 訊號能發現。
- **一行修法**：在 `run_count_offset` 的 v30 分支旁加一行 `// UNVERIFIED — see
  parse_v30_basic doc comment` 交叉引用；更重要的是為 `parse_v30_basic` 加一行
  doc-comment 明確標注「this test validates internal consistency with the assumed
  offset, NOT correctness against real Win10 v30 data — see prefetch.rs:67-69」，
  避免未來讀者誤以為測試綠燈=offset 正確。若要真正補上驗證能力，需要一台真實
  Win10（非 11）主機的 `.pf` 樣本做交叉核對（如 v31 當初做的那樣）。

### G-2（中）Sigma 規則比對測試完全未對「真實 EVTX 解析後的 EventRecord」跑過

- **檔案:行號**：`crates/cairn-sigma/tests/parity.rs:26-40`（`proc_creation` 手造
  `json!({...})` fixture）；對照 `crates/cairn-collectors/src/evtx.rs:126-147`
  （`parses_real_evtx_into_event_records`，唯一使用真實 EVTX 檔案的測試，但只驗證
  「有解析出記錄、channel/event_id 非空」，完全不驗證 Sigma 規則能否在這些記錄上
  正確比對）。
- **問題**：T8 parity harness（`parity.rs`）宣稱「Proves the bundled ... rule set
  ... fires correctly against synthetic EventRecords that stand in for the
  EVTX-ATTACK-SAMPLES techniques」——但這些「stand-in」全部是手造的 `json!({...})`
  Map，欄位型別、缺失模式、大小寫、Windows API 實際回傳的怪異格式（例如
  `ProcessId` 在真實 EVTX 中常是 `"0x1a2b"` 十六進位字串而非數字，`record.rs`
  的測試 `sample_event()` 本身也是這樣構造的）完全由開發者自行假設。真正的
  EVTX-ATTACK-SAMPLES 語料庫（`tests/fetch-fixtures.sh`）只餵給 `evtx.rs` 的解析器
  正確性測試，從未接上 `Engine::match_event`。也就是說：**解析器正確性**與
  **規則比對正確性**這兩層測試的資料來源完全不相交，中間可能存在的落差
  （例如某個欄位在真實 EVTX 中的實際大小寫/型別與 Sigma 規則的 `|endswith`/
  `|contains` 修飾符假設不符）沒有任何測試能發現。CLAUDE.md 也印證這點：
  `tests/` 目錄的兩個真實 fixture（`sysmon_compiledhtml.evtx`、`exec_msxsl.evtx`）
  被 `.gitignore`（不隨 repo 分發），且測試在檔案缺失時優雅跳過
  （`evtx.rs:128-131`、`154-157`），意味著這個「parses_real_evtx_into_event_records」
  測試本身在一般 CI 環境下大概率是被跳過的，而 Sigma 規則比對測試則從不觸碰真實
  位元組。
- **一行修法**：把 `evtx.rs` 已抓到的真實 `sysmon_compiledhtml.evtx`
  （含 CompiledHTML/T1218.001 攻擊樣本）接上 `Engine::match_event`，斷言真實解析出
  的記錄確實命中 `68c8acb4`（parity.rs 已有的同一條規則）——這樣至少一條規則有
  「真實位元組 → 真實解析 → 真實比對」的端到端驗證，而不是三層測試互不相交。

### G-3（中，F-1 下游延伸，非獨立新發現）ProcessRecord.start_time 恆 None 導致多個 Finding.ts 系統性失真

- **檔案:行號**：`crates/cairn-heur/src/parentchild.rs:203`
  `f.ts = p.start_time.unwrap_or_else(chrono::Utc::now)`；根因同 F-1 表，
  `cairn-collectors-win/src/proc.rs:146` `start_time: None` 恆定。
- **問題**：這是 F-1 已記錄根因的下游效應，2026-07-10 resilience audit 本身已提及
  （「f.ts 退回 Utc::now()，時間軸失真」），本審計獨立確認：`parentchild.rs` 的單元
  測試從未對 `f.ts` 做任何斷言（`analyzer_emits_finding_for_malicious_pair_only`
  等測試檢查 severity/mitre/entity/reason，唯獨不檢查 `ts`），所以即使
  `start_time` 恆 None 導致每個 live parentchild finding 的時間軸都是「分析執行
  時刻」而非「行程真實啟動時刻」，這個時間軸失真也沒有任何測試訊號會失敗。
  對 timeline.csv 排序（`determinism: sort output by (ts, record_id)`，CLAUDE.md
  coding conventions）而言，這意味著 live 掃描產生的 parentchild finding 在時間軸
  上會全部堆疊在「掃描執行的那一刻」，而非攻擊實際發生的時間——對 IR 分析師重建
  攻擊時間線是實質性的可用性缺陷，但目前只是 F-1 表格已記錄的已知殘留，非本審計
  獨立新發現的偵測邏輯 bug。列在此處是為了明確：**這個 F-1 下游效應在測試層也是
  完全不可見的**，補測試的價值同樣值得評估。
- **一行修法**：`parentchild.rs` 的分析測試加一條斷言：live-shaped fixture（
  `start_time: None`）產出的 finding，其 `f.ts` 應在測試執行窗口內（證明 fallback
  邏輯有效），並在 doc-comment 註明這是已知降級行為，避免未來重構意外「修正」成
  panic 或誤判。

### 低嚴重度觀察（不獨立列入統計但供參考）

- **`ProcessRecord.user` 恆 None**（`proc.rs:145`）：無任何 heuristic 消費此欄位
  做評分邏輯（僅用於顯示/報告，account.rs 走的是 EVTX SubjectUserName，不是這個
  欄位），故不構成 F-1 類型風險，僅是 IR 面板資訊量缺口（F-1/F-2 審計已涵蓋）。
- **`FileMetaRecord.path_complete`**：`timestomp.rs` 的 `EntityFile` 誠實傳遞
  `path_complete`（`timestomp.rs:143`），不偽裝完整路徑，測試
  `file_meta_path_complete_roundtrips_and_old_json_none`（`record.rs:294`）
  覆蓋了 schema 相容性；此類未發現問題。

---

## 3. Offline hive/raw-NTFS collector 合成測試嚴謹度評估

CLAUDE.md／REMAINING-WORK 已將「合成整合測試替代真機 e2e」記錄為 7 個 raw-NTFS
collector（amcache/mft/usn/shimcache/bam/userassist/srum）在一般開發迴圈下的既定
替代驗證法（SeBackupPrivilege 限制）。本審計評估這個替代法本身是否足夠嚴謹：

- **`mft.rs`（`crates/cairn-collectors/src/mft.rs:417-433`）**：**最誠實的案例**。
  程式碼明確承認「a fully ntfs-0.4-parseable $MFT with real SI/FN attributes is
  impractical to hand-craft deterministically」，並清楚劃分單元測試只覆蓋
  「return shape、cap bound、guard(a)/(b) regression」，SI/FN 時間填值與 FN
  命名空間偏好**完全依賴** ELEVATED e2e（T6）驗證，不假裝合成測試能涵蓋這塊。
  這是本次審計中對「fixture 無法代表真實格式」揭露最清楚的一份程式碼註解，
  值得作為其他 collector 的範本。
- **`prefetch.rs`**：見 G-1——v31 offset 有真機交叉驗證的紀錄，v30 offset 沒有，
  且程式碼**有**在常數旁自承此殘留，但單元測試本身（`parse_v30_basic`）並未
  同步標注「此測試對 offset 正確性是同義反覆」。合成測試嚴謹度：中——揭露了
  「offset 未驗證」，但沒揭露「測試無法檢測 offset 錯誤」這一層。
  E2E（`elevated_e2e_srum` 同構的 prefetch 版本）在真機上執行時能發現 offset 錯誤
  （若 run_count 恆為異常值），但依 SeBackupPrivilege 限制不是日常跑的路徑。
- **`srum.rs`**：e2e 測試（`elevated_e2e_srum`，320-357 行）斷言超越「不 panic」，
  明確檢查 `app_count > 0`、`net_count > 0`、`sources[0].errors.is_empty()`——
  對「有沒有真的抓到資料」給了實質信號，嚴謹度良好。
- **amcache/bam/userassist/shimcache**：依 memory 記錄的既有開發史，這些 collector
  的真機 e2e 在合併前都曾用「129 條真實 bam 零 abstain」「326 條真實 userassist
  零 abstain」這類具體計數斷言驗證過，且過程中曾抓到並修正真實 bug（value_name
  非 public 欄位、`sort+dedup` 未去 8.3 短檔名等）。這代表**歷史上**這條驗證路徑
  是有效的（真的抓到過真 bug），但這些驗證是一次性完成、merge 前跑過的，**不是
  CI 常駐的回歸防護**——若未來重構在 CI 只看得到的合成單元測試綠燈下悄悄破壞了
  真機路徑，CI 不會知道，需要下次手動真機 e2e 才會發現。這是本審計對第 2 點
  「offline collector 合成測試嚴謹度」的核心結論：**合成單元測試對已知格式的
  parsing logic 覆蓋良好，但對「格式假設是否仍然正確」這件事，除了 mft.rs 誠實
  承認做不到之外，其餘 collector 都隱含依賴「當初驗證過就假設永遠有效」，沒有
  持續的真實資料回歸機制**。

---

## 4. 恆真斷言清單

未發現字面意義上的恆真斷言（`assert!(true)`、`assert_eq!(x, x)` 同一運算式兩側等）。
針對性 grep（`crates/**/*.rs`）零命中。

發現**一個同義反覆性質的測試**（邏輯上不是恆真，但對其宣稱要驗證的性質是恆真）：
`prefetch.rs:418-420` 的 `parse_v30_basic`——已列為 G-1，不重複計入本節。

## 5. 沒問題的類別

- **timestomp.rs / persist.rs 的欄位填值鏈**：經逐一追蹤 collector 源頭，確認
  `signed`/`last_write`/`si_*`/`fn_*` 等欄位在對應 collector 中確實有實質填值邏輯
  （非恆定 None 的空殼），此類未發現問題。
- **account.rs**：資料源是 EVTX 官方稽核事件，欄位由 Windows 稽核子系統負責，
  不存在「本工具聲稱採集但實際不採集」的落差，此類未發現問題。
- **byovd.rs 的 sha1 None 處理**：collector 端對格式不符的 DriverId 誠實回傳
  `None`，heuristic 端對 `None` 誠實跳過而非誤判為不匹配，測試覆蓋完整，此類未
  發現問題。
- **LogonSessionRecord.logon_time 恆 None**：雖是未填欄位，但無任何偵測邏輯依賴
  它做評分，不構成 F-1 類型的「假訊號」風險，此類未發現問題。
- **恆真斷言（字面形式）**：全 workspace grep 零命中，此類未發現問題。
- **netconn.rs 缺少連線建立時間戳**：schema 層面就誠實不宣稱有這個欄位，程式碼
  註解主動解釋原因，不是「假裝有資料但實際沒有」的落差型態，此類未發現問題。

---

## 附：與已知 F-1 案例的關係總結

本次審計依 F-1 的分析深度（欄位→collector→失效模式→heuristic 行為 四段式）
對所有 6 個 heuristic 逐一覆核，結論：**F-1 是本 codebase 這類風險裡目前唯一
命中「heuristic 核心價值訊號被靜默清零」等級的案例**；其餘 heuristic 的欄位
填值鏈經查證都是實心的（persist/account/byovd）或欄位缺失有誠實文件化且無下游
評分依賴（LogonSession/netconn 的 ts）。真正新增的同構風險在**collector 內部
解析邏輯的格式假設**這一層被發現（G-1 prefetch v30 offset），以及**測試分層
之間的資料來源不相交**這一層（G-2 Sigma 規則比對從未見過真實 EVTX 位元組）。
