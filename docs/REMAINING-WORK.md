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

## 目前位置（2026-07-08）

- **S1–S4 全部完成**；post-S4 補強已 merge 至 main：heuristic-gate-redesign（`068983e`）、
  ir-snapshot-panels（`88831a1`）、byovd-driver-detection（`60691fd`）。
- **temporal-window-correlator**：spec 已寫（`dca7951`），**待審**，尚未進 writing-plans。
- **fileless-attack-coverage**：spec 保留為 FUTURE（WMI 需重設計為 Observation-first）。
- **CI 現況：audit job 紅**（2 vulnerabilities + 1 denied warning）→ 段 0 立即處理。
- 舊版待辦 A（Finding.evidence）與待辦 C（correlation 時間標注）已在 gate-redesign 一併
  完成，**關閉**。

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

### 段 1 — HTML 報告強化（原待辦 B；evidence 資料已就緒，依賴解除）

**問題**：`Finding.evidence: Vec<EvidenceItem>` 已在 gate-redesign 落地且有資料，但
`report.html` 仍是靜態表格：無法展開 Finding 看 evidence 明細、無法依 severity/artifact/
關鍵字篩選、無法跨 Finding 看同一 binary 出現在哪幾處。

**解法**：
1. Finding 展開/收合（accordion）——點 row 展開 evidence 清單
2. severity / artifact / 標題關鍵字 client-side 篩選
3. 「同 binary 出現次數」摘要欄

**安全護欄**：所有 record 衍生字串進 HTML 前必過既有的 escape 路徑（XSS，security.md §1.5）；
JS 全部 inline 零外部資源（報告檔要能離線開）。

**可用性收益**：直接回應「跑完看不到有用資訊」的使用者反饋主軸——IR panels 解決了
「資料在哪」，本段解決「怎麼在 findings 之間導航」。

**估**：1 段。

### 段 2 — Sigma 規則大擴充（偵測廣度瓶頸）

**問題**（BYOVD brainstorm 時確立的判斷）：目前 bundled 規則子集小，真正限制偵測廣度的
不是 heuristic 數量而是 Sigma 規則覆蓋。`update-rules` 管線（FR19）已完成，擴充只是
`rules/ruleset.toml` 選集 + 重跑 encode 的工作。

**解法方向**：從 SigmaHQ 穩定規則裡按 logsource 對照我們實際收集的 EVTX channel
（Security/System/Sysmon 若在）挑高價值規則；每條過 LogsourceMap 對映驗證；
match-parity 測試擴充對應樣本。

**已知坑**：規則多→誤報面擴大，需按 gate-redesign 的哲學控制（false negatives 優於
false positives）；規則量影響掃描時間，NFR9 資源治理要重測。

**估**：1–2 段（選集審核是主要工時）。

### 段 3 — temporal-window-correlator（spec 已寫待審）

spec：`docs/dev-history/specs/2026-07-04-temporal-window-correlator-design.md`（`dca7951`）。
誠實時間窗證據關聯（非因果鏈）。**下一步是審 spec → writing-plans**，非直接實作。

**估**：spec 審 0.5 + 實作 1–2 段。

### 段 4 — WMI 持久化（Observation-first 重設計）+ 登入爆破偵測

spec 基礎：`docs/dev-history/specs/2026-07-03-fileless-attack-coverage-design.md`（FUTURE）。
原設計缺陷已記錄：gate 的 S9 腳本信號抓不到 `ActiveScriptEventConsumer` 內嵌 ScriptText，
需重設計為 Observation-first（WMI 訂閱一律進 observations，佐證升級才成 Finding）。
登入爆破（4625 聚合）相對獨立可先拆出。

**估**：重開 brainstorm + 1–2 段。

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
段 0（CI 熱修，立即）
  → 段 1（HTML 報告：可用性最直接收益）
  → 段 2（Sigma 擴充：偵測廣度）
  → 段 3（temporal correlator：spec 已在手）
  → 段 4 / 5 / 6（heuristic 深化，依當時需求排序)
  → 段 7（維護機制）
段 F 由「要交付外部」事件觸發，不排時序。
```

排序邏輯：先讓 CI 回綠（信任基線），再擴使用者實際看得到的可用性（報告導航、偵測廣度），
最後才是 heuristic 精度深化。

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
- 本機 clippy 必加 `--all-targets`（等同 CI）。CARGO_TARGET_DIR 在 OneDrive 外。
- 真機 e2e 涉 raw-NTFS 段落：遵守 CLAUDE.md SeBackupPrivilege 節（合成整合測試為日常，
  真機為最終驗收）。
