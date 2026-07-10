# 審計報告 A：跨程序關聯架構（Correlation Architecture）

> 審計者：獨立 fresh-context agent｜日期：2026-07-10｜對象：main HEAD `4dbc628`
> 範圍：cairn-heur 全部 analyzer、orchestrator/traits fan-in、persist 內建跨文物佐證、
> 段 3 temporal-window-correlator spec、Sigma/heuristic 分工盲區。
> 使用者關切：「程序之間的關聯性分析做確實了嗎」——高規格全審，不為「能用」壓縮品質。

---

## 0. 總結（一句話）

目前的「關聯」只有**兩種形狀**，且都不是時序因果：
(a) persist.rs 內建的**單一 join key = 檔名 basename** 的存在性佐證（persistence ↔ execution/process）；
(b) parentchild/netconn 各自在**同一快照內用 pid 反查**父行程 / owner 行程。
「程序 A→程序 B→外連→改檔」這種**跨實體、有時間先後**的攻擊鏈，目前**沒有任何 analyzer 會關聯**——這是刻意留白（等段 3），但段 3 就算實作也**只能補上「時間窗口存在性」的一半**，另一半（NetConn 無時間戳、USN 無 PID）是 Windows 平台限制，永遠補不齊。這個定位本身是誠實且正確的；真正的問題不在「關聯不夠聰明」，而在**餵給關聯層的原始資料在 live 掃描下是殘缺的**（見 F-1，最嚴重）。

---

## 1. 核心產出：關聯訊號 / 未覆蓋場景對照表

「實體」= Process / NetConn / Persistence / Execution / FileMeta(MFT) / UsnEvent / Event(EVTX) / LogonSession。

### 1a. 目前**有**的關聯訊號

| # | 關聯內容 | 連接的實體 | Join key | 時序? | 位置 |
|---|---|---|---|---|---|
| C1 | persistence 命中 gate 後，找同名 execution 佐證（「這個持久化項確實跑過」）並升級一級 | Persistence → Execution | 檔名 basename（`normalized_basename`，去 `.exe`） | 否（存在性） | persist.rs:227-248, 386-412 |
| C2 | 同上，找同名 running process 佐證（「現在正在跑」）並升級 | Persistence → Process | 檔名 basename | 否（存在性） | persist.rs:393-411 |
| C3 | 行程對其父行程評分（Office→shell、script-host→shell、masquerade） | Process → Process(parent) | pid → ppid（同快照） | 否（快照結構） | parentchild.rs:169-185 |
| C4 | 連線對其 owning process 評分（可疑路徑 / unsigned owner / listener） | NetConn → Process(owner) | pid（同快照） | 否（快照結構） | netconn.rs:87-102 |
| C5 | 驅動 SHA1 比對已知漏洞清單 | Execution(amcache_driver) → 靜態清單 | SHA1 | 否 | byovd.rs:58-98 |
| C6 | 同一 binary 在多個 Finding 出現的聚合（純呈現層，非 analyzer） | Finding ↔ Finding | binary 名 | 否 | report html（段 1，html-report-filtering `74aefba`） |

**觀察**：C1/C2 是唯一真正「跨文物」的關聯，且**只從 persistence 這一側發起**——只有已通過 persist gate 的項目才會去撈同名 exec/proc。反過來（一個可疑 process 去撈它的持久化 / 執行歷史 / 檔案落地）**不存在**。

### 1b. 完全**沒有**被覆蓋的關聯場景

| # | 攻擊場景 | 為何漏 | 應由誰補 | 缺口性質 |
|---|---|---|---|---|
| G1 | **A 生 B → B 外連 → 之後改敏感檔**（跨 process/netconn/file 三實體 + 時序） | 無任何 analyzer 跨這三種實體；C3/C4 只在快照內單跳 | 段 3（但只能補時間窗**存在性**，非因果） | 刻意留白 + 平台限制 |
| G2 | 可疑 process → 它的執行文物（prefetch/amcache first_run）→ 判斷「新出現」 | 無 process 側發起的 exec 反查；LiveExecHeuristic（段 5）未實作 | 段 5 | 已追蹤未做 |
| G3 | 可疑 process → 同名/同路徑的持久化項（反向 C1/C2） | 關聯只從 persistence 側單向發起 | 段 3 或新 heuristic | 未追蹤（本報告新增，見 F-3） |
| G4 | timestomp 命中的檔案 ↔ 建立它的 process / 對應 execution | timestomp 完全孤立，不 join 任何其他實體 | 未規劃 | 未追蹤（本報告新增，見 F-4） |
| G5 | account 事件（建帳號/加群組）↔ 執行它的 process / 登入 session | account heuristic 只看單一 EVTX 事件，不關聯 subject 到 process/logon | 未規劃 | 未追蹤（本報告新增，見 F-5） |
| G6 | USN 檔案事件 ↔ 任何行為 | UsnEventRecord 目前**沒有任何 analyzer 消費**（只進 records.jsonl / bodyfile） | 段 3（時間窗） | 平台限制（USN 無 PID） |
| G7 | LogonSession（誰在線）↔ 可疑 process / netconn source | logon session 只進 IR 面板，不與 findings 關聯 | 未規劃 | 未追蹤 |
| G8 | 跨 EVTX 事件序列（4688 鏈、登入後短時間 4720 等） | Sigma 是單事件 stateless 比對，無跨事件狀態 | 段 4 塊 C（登入爆破，有計數需求）目前也未做 | 已追蹤未做 |

**使用者問題的直接回答**：「A→B→外連→改檔」這條鏈（G1），今天**完全沒有關聯**。段 3 若實作，能把「B 外連（同 pid 存在性）」與「窗口內 USN 改檔（時間重疊，不限路徑）」附加為**已可疑 process 的旁證並升一級**——但它**不建立 A→B 的因果**，也**不歸因哪個 PID 改了檔**。這是 Windows 快照式 API 的硬限制，spec 已誠實承認。

---

## 2. Findings（依嚴重度排序）

### F-1〔高〕live proc 不採集 cmdline / integrity / start_time → 關聯與 heuristic 大面積靜默
- **位置**：`crates/cairn-collectors-win/src/proc.rs:142-146`（`cmdline: None, integrity_raw: None, start_time: None` 硬編）。
- **問題**：live 掃描下，`ProcessRecord.cmdline` 恆為空、`integrity` 恆 None、`start_time` 恆 None。連鎖後果：
  - parentchild 的 encoded-PowerShell(+40)、LOLBAS-args(+30)、unsigned-high-integrity(+15) 三個訊號在 live 掃描**永不觸發**（parentchild.rs:114-146 全依賴 cmdline/integrity）。live 下 parentchild 實際只剩 image-name 比對（masquerade / Office-parent / script-parent）。
  - 段 3 的整個時間窗口關聯**無法啟動**——窗口起點是 `start_time`，恆 None 表示每個行程都走 spec §4.2 的「跳過窗口擴充」路徑。**段 3 在 live 下等於 no-op，直到 F-1 修掉**。
- **註**：`signed` 有由 collector 端 WinVerifyTrust 回填（REMAINING-WORK 已對審計原文的高估做過修正），故 unsigned 放大器(+20)仍有效。
- **嚴重度理由**：這是「餵給關聯層的資料殘缺」的根因，比任何關聯邏輯缺陷都優先。已由段 9（`proc-cmdline-integrity`，INDEX.md:51）追蹤為規劃中。
- **修法建議**：段 9 落地 NtQueryInformationProcess 讀 PEB cmdline + OpenProcessToken 讀 integrity + GetProcessTimes 讀 start_time（後者正是段 3 Task 0）。**建議段 9 與段 3 Task 0 合併**，因為兩者動同一個 handle、同一段 unsafe。

### F-2〔中〕persist 跨文物 join 是純檔名 basename，去 `.exe` 且不看路徑 → 誤佐證 + 漏佐證
- **位置**：`persist.rs:210-219`（`normalized_basename`）。
- **問題**：join key 是「去掉 `.exe` 的小寫 basename」。後果雙向：
  - **誤佐證（false corroboration）**：任何同名不同路徑的 execution/process 都會被當佐證升級。例：持久化項是 `C:\Users\a\AppData\Roaming\update.exe`，機器上另有合法 `C:\Program Files\Vendor\update.exe` 的 prefetch → C1 誤判「持久化項確實跑過」並升一級。severity 被錯誤抬高。
  - **漏佐證**：`svchost` vs `svchost.exe` 已被 `.strip_suffix(".exe")` 對齊，但 `powershell.exe -enc ...` 這種 command-only 持久化，key 取自 `binary_path.or(command)`，會把整條 command 當路徑取 basename → 對不上真正的執行文物。
- **修法建議**：join 時附帶路徑相符度檢查（同 basename 且路徑相容才算強佐證；僅 basename 相符降為弱旁證、不升級）；command-only 項先抽出真正的 image 再取 basename。

### F-3〔中〕關聯單向：只從 persistence 撈 exec/proc，process 側無反查 → 可疑行程看不到自己的持久化/落地
- **位置**：架構層（persist.rs 是唯一 build_cross_index 的消費者；parentchild.rs / netconn.rs 無跨文物 join）。
- **問題**：對照表 G3。一個被 parentchild 判可疑的 process，不會去看「它是否有對應的持久化項 / 執行歷史 / 檔案落地」。調查者最想要的「這個可疑行程從哪來、留了什麼」反而沒串起來。C1/C2 只服務 persistence 起點。
- **修法建議**：段 3 或新 heuristic 增加 process→persistence / process→execution 的反向 join（沿用 build_cross_index，key 同步修 F-2）。

### F-4〔中〕timestomp finding 完全孤立，不關聯任何其他實體
- **位置**：`timestomp.rs:108-156`。
- **問題**：timestomp 命中一個檔案後，不去 join「這個路徑是否有 execution 記錄 / 是否某可疑 process 的 image / 窗口內是否有 USN 事件」。timestomp 是強訊號（T1070.006），孤立呈現讓調查者無法快速判斷「被 stomp 的是不是那支 dropper」。
- **修法建議**：段 3 時間窗 / cross-index 納入 FileMeta，讓 timestomp 命中能與同路徑 execution / 同窗口 process 相互佐證。

### F-5〔中〕account 事件不關聯 subject 到 process / logon session
- **位置**：`account.rs:95-187`。
- **問題**：4720/4732 等事件解析出 `subject`（執行操作的帳號）但不與任何 process 或 LogonSession 關聯。「哪個登入 session / 哪支行程建立了這個後門帳號」串不起來。
- **修法建議**：段 4 塊 C 實作時，把 account 事件的 subject/時間與 LogonSession、process 做同帳號/時間窗關聯。

### F-6〔中〕fan-in 假設全部 collector 跑完才分析；慢/失敗 collector 靜默削弱關聯完整性，不表面化
- **位置**：`orchestrator.rs:40-70`。
- **問題**：`run_live` 先序列跑完所有 collector 累積 `records`，再 fan-in analyzer。這對關聯正確性是**對的**（analyzer 需要完整快照，例如 netconn 要 process 已在 records 裡才能 owner 反查）。但：collector 失敗只記進 `sources[].errors`（graceful degrade），**analyzer 端無法得知輸入不完整**。例：proc collector 失敗 → netconn 的 owner 反查全部落空、C2 的 process 佐證全部消失 → 產出的 finding 看起來「乾淨」，實則是資料缺失造成的假陰性，且 finding 本身不帶「本次 process 資料缺失」的警示。
- **無執行順序依賴的隱患**：analyzer 彼此無順序依賴（各自獨立讀 records），這點是乾淨的。真正風險是**跨 collector 的資料完整性未傳遞到 analyzer 層**。
- **修法建議**：低成本修法——analyzer 產出時，若依賴的 record 類別在本次 run 完全缺席（如 netconn 分析時 records 內零 Process），在 finding.reason 或 manifest 標註「owner 反查不可用（proc 採集缺失）」。

### F-7〔低〕analyze/observe 各自取 `Utc::now()`，S4 七天邊界毫秒級可能重複/漏一筆
- **位置**：`persist.rs:353-363`（已有註解）、445-446。
- **問題**：已知殘留、已文件化、影響面（改 Analyzer trait 波及 6 個 analyzer）不成比例。維持接受。
- **修法建議**：無需修；保留註解即可。列此僅為完整性。

### F-8〔低〕pid reuse 時同 pid 後者覆蓋，父/owner 歸因可能錯
- **位置**：`parentchild.rs:167-175`、`netconn.rs:84-93`（均已註解）。
- **問題**：live 快照幾乎不會 pid 重用，只影響歸因準確度、不影響正確性/panic。已誠實註解。
- **修法建議**：無需修。

### 未發現問題的類別（明確聲明）
- **golden rule 8（graceful degrade）**：orchestrator 與各 analyzer 的失敗路徑均 skip+log/記 source，未發現「單點失敗中止整段」——**此類未發現問題**。
- **golden rule 6（可解釋 reason）**：每個 heuristic finding 都設 `reason`，未發現遺漏——**此類未發現問題**。
- **panic 安全**：cross-index、basename、scoring 全部 bounds-checked / saturating，未發現可 panic 路徑——**此類未發現問題**。
- **evasion（golden rule 1/2）**：關聯與分析層純唯讀邏輯，無任何 evasion——**此類未發現問題**。
- **analyzer 間執行順序依賴**：不存在隱含順序依賴（各自獨立讀同一 records 切片）——**此類未發現問題**。

---

## 3. 段 3 spec 評估（temporal-window-correlator）

**(a) 前提是否仍成立**：spec 自身於 2026-07-08 已對照程式碼複查三前提，我重新獨立驗證，**全部仍成立**：
- `ProcessRecord.start_time` 恆 None：`proc.rs:146` 硬編 ✓。
- `NetConnRecord` 無時間戳：`record.rs:56-65` 僅 pid，無 ts ✓。
- persist gate 對 mechanism 透明（僅 winlogon/ifeo/startup 特判）：`persist.rs:105/126/154` ✓。
- 補充：UsnEventRecord 確有 `ts` 但**無 PID**（`record.rs:98-104`），spec §1.3 的「USN 無法歸因 PID」屬實 ✓。

**(b) 現在實作能否補上第 3 點發現的關聯缺口**：**部分能，且有前置阻擋**。
- 能補：G1 的「B 外連（存在性）」+「窗口內 USN 改檔（時間重疊，不限路徑）」附加為旁證並升級——這正是段 3 目標。
- **不能補**：G1 的因果（A→B、誰改了檔）——平台限制，spec 明確排除，正確。
- **前置阻擋（關鍵）**：段 3 窗口起點是 `start_time`，而 F-1 使其恆 None → **段 3 在 live 下實質 no-op，直到段 9 / Task 0 把 start_time 填上**。spec §3 的 Task 0 本身就是修 start_time，但 REMAINING-WORK 把段 3 排在段 9 之後語焉不詳。**建議：段 3 Task 0 與段 9 合併為單一 unsafe 變更**（同 handle、同 GetProcessTimes），否則段 3 段 2 各做一次 OpenProcess 迭代。

**(c) spec 本身的設計問題**：
1. **未串到 F-2 的 join key 問題**：段 3 §4.4 用 `NetConnRecord.pid == 可疑行程 pid` 做 netconn 關聯——這比 persist 的 basename join 精確（用 pid），**好**。但 spec 沒指出 persist.rs 現有的 basename join（F-2）在段 3 併入後會與新的 pid-based join 並存，兩套 join 語義不一致。建議段 3 順手統一。
2. **§4.1 實作機制爭議**：spec 選擇「不新增獨立 Analyzer，而是塞進 persist/parentchild 的 analyze() 內部」。這維持「只服務已 gate 行程」的前提，但會讓 persist.rs 進一步膨脹（已 500+ 行），且 parentchild 目前**沒有** build_cross_index 基建，要另建。可接受，但需注意 F-3 的反向 join 若也要做，架構上更適合抽一個共享的 cross-index 層而非各 analyzer 各自為政。
3. **5 分鐘窗口 + 200 筆 USN 上限**：spec §6 已誠實標為人為預設。無異議，但建議至少 Config 化窗口寬度（一行 Config 欄位），避免寫死常數重蹈 severity 調參的覆轍。
4. **誠實用語測試**：spec §5 要求 evidence detail 含「非確認因果」字樣並寫回歸測試——這是好設計，保留。

**段 3 一句話結論**：方向與誠實定位正確、前提全成立，但**在 F-1/段 9 修好 `start_time` 之前實作段 3 等於 live 下 no-op**；應先段 9（或把 Task 0 併入段 9），且順手統一 join key 語義（F-2）與考慮反向 join（F-3）。

---

## 4. Sigma / heuristic 分工盲區清單

Sigma 覆蓋（ruleset.toml 43 條，全部單事件 stateless）：process_creation（LOLBAS/PowerShell/procdump/recon）、Security（帳戶/服務安裝/PtH/DCSync/RDP）、NTLM、PowerShell classic。
heuristic 覆蓋：parentchild、persist、netconn、account、timestomp、byovd。

**已知盲區（REMAINING-WORK 已追蹤，不重複計算）**：WMI 訂閱持久化（段 4 塊 A）、互動登入爆破（段 4 塊 C）、Sysmon 規則缺席（無 Sysmon 環境定位，設計取捨非缺陷）。

**新發現盲區（兩邊都不管）**：
| # | 攻擊面 | Sigma 側 | heuristic 側 | 說明 |
|---|---|---|---|---|
| B1 | **UsnEvent 完全無消費者** | N/A（非 EVTX） | 無 analyzer 讀 UsnEventRecord | 檔案建立/刪除/改名事件只進 bodyfile，零偵測邏輯。段 3 是第一個消費者。刪除大量檔案（ransomware）、payload 落地在 USN 有痕跡卻無告警。 |
| B2 | **SRUM / BAM / userassist 執行文物零 heuristic** | N/A | byovd 只讀 amcache_driver；其餘 execution source 無 analyzer | 「近期首次執行的 unsigned 程式」（LiveExecHeuristic 段 5）未做 → 執行文物僅供 persist 佐證，本身不獨立產訊號。 |
| B3 | **RegValue 記錄無消費者** | 部分 Security 註冊表事件有 Sigma | 無 heuristic 讀 RegValueRecord | 若有 collector 產 RegValue（非 persistence 特化的），無分析。 |
| B4 | **時序型 EVTX 攻擊（登入後短時間建帳號、4688 父子鏈跨事件）** | Sigma stateless 無法跨事件計數/排序 | account 只看單事件 | 段 4 塊 C 的爆破偵測會碰到同樣的「Sigma 無狀態」問題——需 heuristic 側做跨事件聚合，目前無此基建。 |
| B5 | **Zone.Identifier（MotW）已採集卻無 analyzer** | N/A | FileMetaRecord.zone_identifier 有欄位，無 heuristic 讀 | 「從網路下載且被執行」是高價值訊號（下載檔帶 MotW + 有 execution 記錄），資料已在 record 內卻無人關聯。**本報告新增建議**。 |

B5 特別值得一提：`zone_identifier` 欄位已存在（record.rs:90），與 execution 文物 join 即可得「下載即執行」訊號，成本低、價值高，目前完全未利用。

---

## 5. 沒問題的類別彙整（明確聲明）
- golden rule 8 graceful degrade：**此類未發現問題**。
- golden rule 6 可解釋性：**此類未發現問題**。
- panic / bounds 安全：**此類未發現問題**。
- evasion（golden rule 1/2）：**此類未發現問題**。
- analyzer 間執行順序依賴：**此類未發現問題**（無隱含依賴）。
- Sigma logsource gate 正確性：fail-open 設計對 triage 偏向正確，**此類未發現問題**。

---

## 附：關鍵位置索引
- 唯一跨文物 join：`persist.rs:227-248`（build_cross_index）、`persist.rs:386-412`（C1/C2 升級）
- 同快照 pid 反查：`parentchild.rs:169-185`、`netconn.rs:87-102`
- fan-in：`orchestrator.rs:40-81`（collector 全跑完 → analyze fan-in → observe fan-in）
- F-1 根因：`cairn-collectors-win/src/proc.rs:142-146`
- 段 3 spec：`docs/dev-history/specs/2026-07-04-temporal-window-correlator-design.md`
- UsnEvent 無 PID：`record.rs:98-104`｜NetConn 無 ts：`record.rs:56-65`
