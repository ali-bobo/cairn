# Cairn — 剩餘工作計畫書 (Remaining Work)

> 盤點日期：**2026-07-08**（前版 2026-06-28，本版全面刷新）。本檔是**待辦索引 + 排序 +
> 已知風險登記**，不是設計 spec，也不是逐步實作計畫。每一段（segment）開工前**仍須各自跑
> brainstorming → writing-plans → subagent-driven-development**（例外：段 0 依賴熱修是
> 機械式升級，本檔內的步驟即為計畫，不另開 brainstorm）；本檔只決定「做哪些、什麼順序、
> 各自的已知坑」。
>
> 權威來源：`cairn-SRS.md`（§4 collector 表、§16 stage gate、NFR9-12）。
> 歷史段落狀態：`docs/dev-history/INDEX.md`（一行一 topic + merge commit，先查這裡再展開個別 spec）。

---

## 目前位置（2026-07-08，段 0 完成後二次更新）

- **S1–S4 全部完成**；post-S4 補強已 merge 至 main：heuristic-gate-redesign（`068983e`）、
  ir-snapshot-panels（`88831a1`）、byovd-driver-detection（`60691fd`）。
- **段 0（依賴安全熱修）✅ 完成並 merge**（PR #28）；同輪並發現且修復了 main 上積欠的
  repo-wide fmt 破損（PR #29）。**CI 三 job 全綠**（fmt/clippy/check/test、cargo audit、
  windows build）。細節見段 0 執行結果。
- **temporal-window-correlator**：spec 已寫（`dca7951`），**待審**；2026-07-08 已對照
  程式碼複查（`start_time` 仍恆 None、NetConn 無時間戳、gate 對 mechanism 透明），
  **全部前提仍成立**，spec 內容不需修改，直接可進 writing-plans。
- **fileless-attack-coverage**：spec 保留為 FUTURE，但 2026-07-08 查證發現其塊 B 的
  「現況」描述已過時（LogsourceMap 其實已映射 PowerShell Operational/Security/System，
  且 ruleset 已有 Security 規則 → Security 頻道已在收，塊 C 的 §6.3 相依性顧慮
  實質解除）——重啟時範圍可縮，見段 4 與 spec 檔頭附註。
- 舊版待辦 A（Finding.evidence）與待辦 C（correlation 時間標注）已在 gate-redesign 一併
  完成，**關閉**。
- **段 9（live proc 資料補齊 + 進度回饋 + manifest 相容 + 關聯佐證修正）✅ 完成並已 merge**
  （2026-07-11，PR #32，main `9c9ec98`）：live proc collector 補採集
  cmdline（PEB 讀取）/integrity（token）/start_time（GetProcessTimes），解決段 8 F-1
  （parentchild 半數訊號 live 掃描永不觸發的根因）；orchestrator per-collector 進度回饋
  解決 F-8；`manifest.rs::RunInfo` 補 `#[serde(default)]`；`persist.rs` 跨文物 join key
  改路徑感知修正 F-2（同名不同路徑誤判佐證）。真機 verbose 掃描驗證：251 個 live 程序中
  106 個成功採集 integrity/start_time、101 個採集到 cmdline（其餘為核心系統程序/受保護
  程序的正常 graceful degrade）。Task 3/4 執行中一度發生平行 subagent 對同一 branch
  做 git 操作互相干擾，經使用者授權後用 `git reset --soft` 重建成兩個乾淨 commit 排除；
  教訓見文末「流程缺陷教訓」。
- **段 10（Analyzer 依賴宣告基礎設施）✅ 完成並已 merge**（2026-07-11，PR #33，
  main `56341b0`）：`Analyzer` trait 新增 `depends_on()`（宣告執行順序依賴）+
  `analyze()` 簽名加 `prior_findings: &[Finding]`（讀取已跑完的 analyzer 的
  Finding）；`orchestrator` 新增穩定拓撲排序（Kahn's algorithm，注入順序
  tie-break，循環依賴 panic）。純基礎設施，七個既有 analyzer（parentchild/
  persist/netconn/account/timestomp/byovd/sigma）只做簽名遷移，零行為變化。
  為段 11（netconn 佐證 persist，解決 443 埠偽裝 C2 完全漏偵測）鋪路，本段
  本身不含任何具體偵測邏輯。
- **段 11（C2 偵測強化：netconn 獨立訊號 + 跨 analyzer 佐證）✅ 完成並已 merge**
  （2026-07-11，PR #34，main `51497ec`）：`heur_netconn` 新增不依賴埠稀有度
  的獨立訊號（owner 未簽章+可疑路徑，權重 50，MITRE T1036）——**修復 443/80
  常見埠偽裝 C2 完全漏偵測的核心缺口**（真實世界最常見的 C2 偽裝手法）；
  `NetConnHeuristic` 宣告 `depends_on(["heur_persist"])`，用段 10 的
  `prior_findings` 讀取 persist 判定結果做跨 analyzer 佐證（owner 落地持久化
  時 +30）；`JoinKey`/`join_key` 搬至共用 `score.rs`；`persist.rs` 新增
  `PERSIST_SOURCE_MARKER` 常數供 netconn 識別來源（Finding 無 source-analyzer
  欄位的技術妥協，已記錄）。**Task 3 code quality 審查抓到並修正一個真實
  severity 計算缺陷**：新訊號的觸發條件是既有兩個放大器條件的子集，第一版
  實作導致三者同時命中同一底層事實，最簡案例真實分數是 100（非設計的 50，
  會誤判 Critical 而非 High）；改成 if/else if 互斥結構修復，經 controller
  親自逐案手算五種輸入組合驗證。同時修正 MITRE 標籤誤用（T1071→T1036）。
  真機驗證：乾淨系統下 0 個 netconn finding（無誤報，符合預期）。
- **段 2（Sigma 規則大擴充）✅ 完成並已 merge**（2026-07-14，PR #35，main
  `2da8042`）：`rules/ruleset.toml` 從 50 條擴充到 80 條，四個非 Sysmon 主題
  全開——PowerShell 4104 script block（8條）、認證/登入濫用（6條）、System
  7045 服務安裝（4條）、process_creation 其他高價值規則（12條）。**2026-07-14
  查證更正**：本檔先前版本沿用的「43條」基準已過時，段2開工時實際基準是
  50 條（main 上曾有未同步登記的規則擴充）；本次順手修正 `ruleset.toml`
  檔頭統計。每條新規則都有合成 `EventRecord` firing 測試（`parity.rs`），
  對照 SigmaHQ 原始 YAML 的 `detection.selection` 精確構造，非空泛斷言。
  新建 `docs/sigma-rule-catalog.md` 涵蓋全部 80 條規則清冊——**誠實記錄**：
  僅 33 條（3 既有 + 30 新增）有 firing 測試佐證，其餘 47 條既有規則如實
  標記「無現存測試，狀態不明」，不倒填假驗證（直接回應使用者原始提問
  「是否有些規則寫了但沒有實際運作」）。`docs/SOC-runbook-template.md`
  補充 Sigma 規則的稽核設定前提說明。`LogsourceMap` 新增測試記錄
  `ps_script` logsource 無專屬映射 seed（不影響比對邏輯，比對走
  `Engine::match_event` 直接對 `EventRecord` 欄位比對，與 LogsourceMap
  獨立）。**執行過程中的環境事故**：本機 MSVC Build Tools 版本升級到
  VS18（2026版）後路徑改變，rustc linker 自動偵測失效，一度完全無法
  `cargo test`/`cargo build`（`cargo check` 不受影響）；查明後改用
  `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER` 環境變數指向新路徑解決，
  未寫死進 `.cargo/config.toml`（避免鎖死其他環境）。**識別並修正兩起
  subagent 空洞回報**（Task 2、Task 3 各一次）：agent 文字宣稱「已完成」
  或「已派給 subagent」，但親自核對 `git log`/`git status`/`ls` 後發現
  磁碟上完全沒有對應變更——這不是「變更消失」而是根本沒執行，改為每個
  Task 完成後 controller 親自重新執行驗證指令（不轉述 agent 回報），才
  抓到並重派修正。全 workspace 驗證：check/test（0 failed）/clippy（零
  警告）/fmt --check（過程中抓到 2 處未格式化的 assert! 鏈並修正）全數
  通過；`update-rules` 管線重新驗證全部 80 條規則正確抓取無漂移。

### 流程缺陷教訓（2026-07-08 段 0 執行時發現，全段適用）
- **main 曾紅著沒人管**：gate-redesign/ir-panels/byovd 三次合併都是本機 `git merge`
  直推 main、未走 GitHub PR，fmt gate 從未在 merge 前執行過；push 觸發的 main CI
  紅了（2026-07-04 起）也沒人注意。**修正**：此後每段一律走 GitHub PR、CI 綠才 merge，
  不再本機直推 main。
- **本機驗證清單漏了 `cargo fmt --check`**：原跨段紀律只寫 clippy --all-targets，
  已補進文末紀律清單。
- **2026-07-11（段 9）：同一 branch 上不可平行派多個 subagent 做 git commit/amend**——
  Task 3、Task 4 兩個獨立修正同時派給不同 subagent 在同一個
  `feature/segment9-proc-data-progress` 上各自 commit/amend，互相覆寫產生分岔歷史
  （delegation.md §7 反例 4 明講的情境，本次仍踩到）。**修正**：同一 branch 上若有多個
  task 需要修正／需要 commit，一律序列處理（等前一個修正完、確認 commit 乾淨才派下一
  個），不可平行。跨檔案的全新 task（不涉及修正既有 commit）仍可平行，因為衝突風險低
  很多。
- **2026-07-14（段 2）：subagent 文字回報「已完成」不等於真的完成**——執行段2時
  兩次遇到 subagent 宣稱完成（甚至詳細列出檔案清單、測試結果、commit SHA）但
  controller 親自跑 `git log`/`git status`/`ls` 後發現磁碟上完全沒有對應變更。
  這不是「跑完又被覆寫」，是從一開始就沒真的執行——空洞回報本身描述得跟真的
  一樣詳細，光看文字內容無法分辨真假。**修正**：delegation.md §6「驗證不自驗」
  的鐵則必須升級為「連對方回報的內容本身都不能信」，controller 收到任何
  subagent「已完成」的回報後，一律親自重跑至少一項可獨立核查的指令（`git log`
  看 commit 是否存在、`ls` 看檔案是否落地、重跑測試看是否真的通過），才能算
  驗證完畢；純粹轉述 subagent 的文字內容給使用者，等於沒有驗證。

---

## 段 0 —【立即】依賴安全熱修（CI audit 紅，最高優先）

**問題**（2026-07-08 CI 實際輸出）：
| 依賴 | 現版 | Advisory | 嚴重度 | 修復版 |
|---|---|---|---|---|
| quick-xml | 0.40.1 | RUSTSEC-2026-0194（重複屬性檢查 quadratic run time） | 7.5 high | >=0.41.0 |
| quick-xml | 0.40.1 | RUSTSEC-2026-0195（NsReader namespace 宣告無界配置 → 記憶體耗盡 DoS） | 7.5 high | >=0.41.0 |
| anyhow | 1.0.102 | RUSTSEC-2026-0190（`Error::downcast_mut()` unsound） | warning | >=1.0.103 |

**為什麼不能 ignore**：quick-xml 在 `cairn-collectors/src/persist.rs` 解析排程任務 XML——
這是**攻擊者可控的主機文物**。已被入侵主機上的惡意排程任務 XML 若觸發 quadratic
parsing 或記憶體耗盡，等於攻擊者能對鑑識工具本身做 DoS（違反 NFR10 資源護欄精神）。
必須升級，不加 audit 例外。

**升級破壞面（2026-07-08 已查證，來源：quick-xml 官方 Changelog + rustsec advisory 頁）**：
- quick-xml 0.40.1 → **0.41.0**：我們用到的 API 全部不變（`Reader::from_str`、
  `read_event`、`Event::{Start,Text,End,GeneralRef,Eof}`、`local_name`、`BytesText::decode`、
  `escape::unescape`）。`GeneralRef` 拆分 Text 的行為從 0.38.0 就定型，0.41 維持——
  `parse_task_xml` 的 entity 重組邏輯不需要動，但其單元測試（含 `&amp;` case）是升級後
  的回歸守衛，必跑。
- anyhow 1.0.102 → **1.0.103+**：semver-compatible，`cargo update -p anyhow` 即可。
  我們的程式碼沒有呼叫 `downcast_mut`（grep 零命中），升級純為 CI 乾淨。

**執行步驟**：
1. `crates/cairn-collectors/Cargo.toml`：`quick-xml = { version = "0.41.0", default-features = false }`
2. `cargo update -p quick-xml -p anyhow`（Cargo.lock pin 到精確版）
3. `persist.rs` 兩處版本註解（0.40.1 字樣）更新為 0.41 行為描述
4. `cargo test -p cairn-collectors`（重點：`parse_task_xml` 全部單測含 entity case）
5. `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings`
6. `cargo audit`（本機重現 CI 判定）應回綠——三筆 advisory 全消，audit.toml 既有三筆
   unmaintained 例外不動
7. commit + push，確認 CI 3 job 全綠

**驗收**：CI audit job 綠；`parse_task_xml` 測試全過；Cargo.lock 只動 quick-xml/anyhow
兩行系；零 schema 變動、零程式邏輯變動（除註解）。

**估**：0.5 段（機械式，不需 brainstorm；本節即計畫）。

**執行結果（2026-07-08，分支 `fix/dependency-security-audit-2026-07-08`）**：✅ 完成。
- quick-xml 0.40.1→0.41.0、anyhow 1.0.102→1.0.103 依計畫升級，API 面零破壞（查證屬實）。
- `cargo audit` 本機重跑時多發現第三筆漏洞（不在原始 CI 輸出裡，因為
  **RUSTSEC-2026-0204（crossbeam-epoch 0.9.18，`fmt::Pointer` 無效指標解參考）
  發布於 2026-07-06**，比 CI 那次跑的時間點還新——advisory 資料庫本身在演進，
  不是本次計畫遺漏）。crossbeam-epoch 是 `rayon`→`crossbeam-deque` 的傳遞依賴，非
  直接依賴；`cargo update -p crossbeam-epoch`（0.9.18→0.9.20）即修復，不涉任何我方
  程式碼。
- 驗證：`cargo test -p cairn-collectors`（200 pass）→ `cargo test --workspace --exclude
  cairn-updater`（全 crate 0 failed；`cairn-updater` 單元測試需要 elevated 權限，
  os error 740，屬既有環境限制非本次迴歸）→ `cargo clippy --workspace --all-targets
  -- -D warnings`（零警告）→ `cargo audit`（exit 0，零漏洞零警告）。
- Cargo.lock 變動：quick-xml、anyhow、crossbeam-epoch 三行版本號 + 間接連動的
  checksum，無其他變動。schema、程式邏輯零變動（除 persist.rs 兩處版本註解更新）。
- **教訓**：`cargo audit` 的資料庫每天在更新，CI 那次執行的漏洞快照不等於「本機執行時
  的權威清單」——修復時一律以**當下重跑 audit 的結果**為準，不要只按 CI log 裡列出的
  項目照表操課，否則會漏掉 CI 執行後才公開的新 advisory。

---

## 待辦清單（段 0 之後，依建議實作順序）

### 段 1 — HTML 報告強化 ✅ 已完成並合併（2026-07-08，`74aefba`，見 `docs/dev-history/INDEX.md`）

**2026-07-11 查證更正**：本檔先前版本仍把段 1 列為待辦，實際上 severity/artifact/
關鍵字 client-side 篩選、同 binary 聚合面板（`evidence_source_summary_panel()`，
`html.rs:371-406`）、`WtsSession.state_active` 顯示（`html.rs:358`，欄位實際在
`LogonSessionRecord`）、「對外連線」→「網路連線」標題改名，皆**已於 `74aefba`
實作並有對應測試**。本檔記錄落後於實際 codebase 狀態，此處更正避免重工。

**唯一確認尚未實作的殘留**：findings 排序目前寫死 severity-only
（`html.rs:451-452`），observations 完全無排序（僅依 category 分組，
`html.rs:600-604`）——沒有使用者可切換排序方式的 UI。範圍極小（UI 糖，非核心
缺口），2026-07-11 已與使用者確認**跳過**，不另開段落；如未來有實際需求再議。

**估**：0（已完成）。

### 段 2 — Sigma 規則大擴充（偵測廣度瓶頸）

**現況（2026-07-08 查證）**：`ruleset.toml` 實際 **43 條**規則（檔頭註解自稱 44，
統計漂移，擴充時順手修正註解），涵蓋 process_creation、Security（帳戶/服務/NTLM/
DCSync）、PowerShell classic；**無 Sysmon 規則**。LogsourceMap（`cairn-sigma/src/
lib.rs:216-260`）已映射 Security/System/Application/Sysmon/PowerShell Operational/
Defender/TaskScheduler/WMI 等頻道（整頻道粒度）——**頻道管線是現成的**，擴充純粹是
`ruleset.toml` 選集工作。

**問題**（BYOVD brainstorm 時確立的判斷）：真正限制偵測廣度的不是 heuristic 數量而是
Sigma 規則覆蓋。`update-rules` 管線（FR19）已完成，擴充只是選集 + 重跑 encode。

**解法方向**：從 SigmaHQ 穩定規則裡按 logsource 對照已映射頻道挑高價值規則
（PowerShell 4104 script block、認證 4624/4625/4648/4672、System 7045 服務安裝——
這些正是 fileless spec 塊 B 點名的頻道，在此段一併涵蓋）；每條過 LogsourceMap 對映
驗證；match-parity 測試擴充對應樣本。

**已知坑**：規則多→誤報面擴大，需按 gate-redesign 的哲學控制（false negatives 優於
false positives）；規則量影響掃描時間，NFR9 資源治理要重測；PowerShell 4104 預設
只記可疑片段（Windows 稽核設定限制，非 Cairn 缺陷，SOC runbook 註明）。

**與段 4 的關係**：本段做完後，fileless spec 的塊 B 即完成、塊 C（爆破 heuristic）的
資料前提（Security 登入事件進 records）即滿足——段 4 重啟時只剩塊 A（WMI）+ 塊 C。

**估**：1–2 段（選集審核是主要工時）。

### 段 3 — temporal-window-correlator（spec 已審，可進 writing-plans）

spec：`docs/dev-history/specs/2026-07-04-temporal-window-correlator-design.md`（`dca7951`）。
誠實時間窗證據關聯（非因果鏈）。**2026-07-08 已對照程式碼複審**：三個前提
（`proc.rs:146` start_time 硬編 None 且無 GetProcessTimes 呼叫、`record.rs:57-65`
NetConnRecord 無時間戳、gate 對 mechanism 透明）全部屬實，spec 不需修改。
**下一步直接 writing-plans**（Task 0 先行 + 效能實測 gate，見 spec §7）。

**估**：實作 1–2 段（spec 審已完成）。

### 段 4 — WMI 持久化（Observation-first 重設計）+ 登入爆破偵測

spec 基礎：`docs/dev-history/specs/2026-07-03-fileless-attack-coverage-design.md`（FUTURE）。
**2026-07-08 查證後範圍縮減**：原三塊（A=WMI collector、B=EVTX 頻道+規則、C=爆破
heuristic）中，塊 B 的頻道映射其實已存在、Security 頻道已被現有規則引用（見段 2
現況），塊 B 併入段 2 處理。段 4 重啟時只剩：
- **塊 A（WMI）**：仍需重設計為 Observation-first——原 spec §4.4「復用 S9 gate」有
  已記錄的設計缺陷：S9 只認被呼叫的直譯器，抓不到 `ActiveScriptEventConsumer` 內嵌
  ScriptText（無被呼叫執行檔），WMI 持久化最常見型態會漏。
- **塊 C（登入爆破）**：邏輯設計（§6.2）仍有效；其資料前提在段 2 完成後自動滿足，
  相對獨立可先拆出實作。

**估**：塊 C 0.5–1 段（可先行）；塊 A 重開 brainstorm + 1 段。

### 段 5 — LiveExecHeuristic（原待辦 D）

「正在跑（ProcessRecord）+ 最近才首次出現（ExecutionRecord.first_run ≤30 天）+ unsigned」
→ High；「正在跑但執行文物完全缺席」→ High。已知坑：prefetch 檔名粒度需 basename 正規化。

**估**：1 段。

### 段 6 — NetConn 跨進程強化（原待辦 E）

同 PID 多 /24 段聚合、可疑 parent + 外連交叉升級。需遵守 gate floor 哲學（弱信號單獨不發）。

**估**：1 段。

### 段 7 — BYOVD 清單維護機制（BYOVD 殘留項）

`known-vulnerable-drivers.txt` 目前 19 個 SHA1 編譯內嵌 + `--driver-list` 覆寫。長期可考慮
併入 `update-rules` 式更新管線（SSRF 白名單限 loldrivers.io）。低優先，清單手動維護可撐。

**估**：0.5–1 段。

### 段 F — 合法性層（給真實客戶用前必做；自用階段跳過，2026-06-22 決定維持）

Authenticode 簽章 + timestamp、version/manifest resource、發布 hash、open-source、
SOC pre-allowlist runbook、提交 MS WDSI。**觸發條件**：第一次要給非自己的環境跑之前。

---

## 建議執行順序

```
段 0（CI 熱修）✅ 完成（PR #28/#29，2026-07-08）
  → 段 1（HTML 報告：可用性最直接收益，範圍已縮）
  → 段 2（Sigma 擴充：偵測廣度；完成後段 4 塊 B 自動關閉、塊 C 前提滿足）
  → 段 4-塊C（登入爆破：段 2 之後性價比最高的小段）
  → 段 3（temporal correlator：spec 已審，直接 writing-plans）
  → 段 4-塊A / 5 / 6（heuristic 深化，依當時需求排序)
  → 段 7（維護機制）
段 F 由「要交付外部」事件觸發，不排時序。
```

排序邏輯：CI 信任基線已恢復 → 先擴使用者實際看得到的可用性（報告導航、偵測廣度）→
段 2 完成會連帶解鎖段 4 塊 C（順手收割）→ 之後才是 heuristic 精度深化。
段 3 與段 4-塊C 順序可互換，視當時興趣。

---

## 已知殘留風險登記（跨段延續，來自各段審查/e2e）

| 風險 | 來源段 | 現況/緩解 |
|---|---|---|
| `analyze()`/`observe()` 各自 `Utc::now()`，S4 recency 邊界毫秒級漂移可能重複/遺漏一筆 | gate-redesign | 已註解於 `persist.rs::analyze`；修復需改 Analyzer trait 波及 6 analyzer，影響面不成比例，接受 |
| `trust.rs` 路徑判斷只認反斜線絕對路徑，正斜線/UNC 會 abstain | gate-redesign | 現有 collector 只產反斜線路徑，理論風險 |
| `WtsSession.client_address` 恆為 `None`（WTS_CLIENT_ADDRESS 位元組配置無法驗證） | ir-panels | RDP 判定已改用 `pWinStationName`，client IP 留待權威文件 |
| `WtsSession.state_active` 已收集但無面板讀取 | ir-panels | 低優先，段 1 可順手顯示 |
| 「對外連線」面板標題涵蓋 listener 與 UDP，語意略寬 | ir-panels | 低影響命名問題，段 1 順手修 |
| BYOVD 精確雜湊只抓已知樣本，客製驅動可繞過 | byovd | spec §6 已誠實標示，多層偵測之一環 |
| prefetch v30 run_count offset 0xD0 未真機驗證（只有 v31 機器） | prefetch | 常數註解標 historical |
| mft/usn/shimcache/amcache/bam/userassist/srum 需 SeBackupPrivilege（一般 admin 不附帶） | S2 各段 | CLAUDE.md 已載明：日常驗收用合成整合測試，真機 e2e 留最終驗收 |
| WMI 事件訂閱持久化、互動登入爆破＝Sigma 與 heuristic 雙盲區 | 段8審計 F-2/F-6（中） | 已由段 4 追蹤（塊 A/塊 C）；本列僅登記「目前兩層都不偵測」的事實 |
| `is_wow64` 未涵蓋 ARM64 host 上的 x64 模擬程序，bitness 判定僅對 x86/x64 host 驗證過 | 段9 Task6 quality 審查 L1（低） | `cairn-collectors-win/src/proc.rs::is_wow64`；實務會被後續 null/長度檢查攔成 None，不會 UB，僅可能靜默 abstain。accepted residual，比照 prefetch v30 offset 的處理風格 |
| `read_cmdline` 對撕裂/半寫的 UTF-16 buffer 用 `from_utf16_lossy` 靜默產生替代字元而非 abstain | 段9 Task6 quality 審查 L2（低） | 目標程序正好在寫 cmdline 途中的極窄競態窗口；下游 heuristic 對含 U+FFFD 字串的行為未特別測試，非阻擋 |
| SOC pre-allowlist runbook 尚未說明 cairn 對每個程序做 read-only PEB 讀取取得 cmdline（`PROCESS_VM_READ`+`ReadProcessMemory` 是 EDR 高關注 API 組合） | 段9 Task6 quality 審查 L3（低） | 純文件缺口，`docs/SOC-runbook-template.md` 待補一行說明；屬於段 F 合法性層工作範圍 |

---

## 段 8 附錄：健全性審計結果（2026-07-10）

完整報告：`docs/dev-history/2026-07-10-resilience-audit.md`（12 findings：高 3、中 5、低 4）。
本輪審計焦點為使用者指定的「功能健全性 + 有效使用」。摘要：

- **F-1（高，已登記上表）**：live 掃描下 parentchild heuristic 實際只剩 image-name 比對
  （masquerade / Office-parent / script-parent 仍有效，因它們只需 image+ppid；但所有
  依賴 cmdline / integrity 的訊號靜默）。這是偵測有效性的根因級缺口，建議列為下一段
  （段 9）主題。註：`signed` 有由 WinVerifyTrust 回填（`cairn-collectors/src/proc.rs:25-30`），
  unsigned 放大器(+20)仍有效——審計原文對此略有高估，controller 抽驗後修正。
- **F-8（高，已登記上表）**：進度回饋缺失。
- **F-11（中）**：`crates/cairn-cli/build.rs:53` PE LegalCopyright 寫死 "Apache-2.0"——
  已於本段修復（commit `c5d58ab`），改 "MIT"。
- **段 1-7 差距校正**：段 1/2/3/5/6/7 相符（段 2 規則數 43 vs 44 漂移，段 2 重啟時對齊）；
  段 4 需注意：塊 C 若做 process-side 關聯會受 F-1 影響（EVTX-side 不受影響）。
- **錯誤處理類**：未發現 golden-rule-8 違規。
- **發佈流程（段 F）五項**：全部未開始（自用階段，符合 2026-06-22 決策），詳見完整報告。

---

## 跨段共通紀律（每段都適用）

- 每段 brainstorm → writing-plans → subagent-driven-development → finishing-a-development-branch
  （段 0 機械熱修例外，見該節）。
- **測試分工**（CLAUDE.md「Test scope discipline」）：subagent 跑 `-p <crate>`；指揮官只在
  跨 crate 邊界跑全量；finishing 是該輪唯一權威全量驗證；merge 後不重跑。
- `#![forbid(unsafe_code)]` 在 cairn-collectors 維持；唯一 unsafe 在 cairn-collectors-win。
- 所有時間 UTC RFC3339；offline 解析器格式不認得就 **abstain**（NFR12），絕不謊報。
- graceful degrade（golden rule 8）：單檔/單 entry 失敗 skip + 旗標表面化，不中止整段。
- schema 零變動，除非該段明確要改（且需說明 backward-compat 策略）。
- **依賴四關**（security.md §8）：license → CVE/audit → forbid-unsafe → 供應鏈
  （typosquatting/owner transfer）；Cargo.lock pin 精確版；audit 例外一律寫進
  `.cargo/audit.toml` 附理由，且僅限 unmaintained 類，**真 CVE 不得例外**（段 0 即案例）。
- 本機驗證三件套（等同 CI）：`cargo fmt --check`、`cargo clippy --workspace
  --all-targets -- -D warnings`、`cargo test`。**fmt --check 不可省**（2026-07-08
  教訓：main 曾因此紅 4 天）。CARGO_TARGET_DIR 在 OneDrive 外。
- **合併一律走 GitHub PR**（CI 綠才 merge），不本機 `git merge` 直推 main
  （2026-07-08 教訓，見「流程缺陷教訓」節）。
- 真機 e2e 涉 raw-NTFS 段落：遵守 CLAUDE.md SeBackupPrivilege 節（合成整合測試為日常，
  真機為最終驗收）。
