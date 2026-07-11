# 段 2：Sigma 規則大擴充 — 設計 Spec

- 日期：2026-07-11
- 基準：main HEAD `509cb99`
- 對應 backlog：`docs/REMAINING-WORK.md` 段 2

## 背景與動機

`ruleset.toml` 現有 43 條規則（檔頭註解寫「44」，統計漂移，本段順手修正），涵蓋
process_creation、Security（帳戶/服務/NTLM/DCSync）、PowerShell classic。
`LogsourceMap`（`crates/cairn-sigma/src/lib.rs:216-269`）已映射 Security/System/
Application/Sysmon/PowerShell Operational/PowerShell classic/Defender/
TaskScheduler/WMI/NTLM 等頻道（整頻道粒度）——頻道管線是現成的，`update-rules`
管線（FR19）也已完成，擴充純粹是 `ruleset.toml` 選集工作。

真正限制目前偵測廣度的不是 heuristic 數量而是 Sigma 規則覆蓋（BYOVD brainstorm
時確立的判斷）。本段做完後：
- fileless-attack-coverage spec（`docs/dev-history/specs/2026-07-03-fileless-attack-coverage-design.md`）
  的塊 B（EVTX 頻道+規則）即完成
- 段 4 塊 C（登入爆破 heuristic）的資料前提（Security 登入事件進 records）即滿足

## 範圍

**不加 Sysmon**。`ruleset.toml` 檔頭已自陳「Scope: no-Sysmon environments」，Sysmon
規則依賴主機實際安裝並設定 Sysmon（非 Windows 預設內建組件）——若加入，在多數
未部署 Sysmon 的環境下這些規則永遠不會觸發，只會膨脹 ruleset 拖慢 NFR9 掃描時間
卻無實際偵測收益。維持現有定位，Sysmon 留為未來獨立段落。

四個主題全開，不設數量上限（以高價值為標準，非湊數）：
1. PowerShell 4104 script block 規則（`logsource: windows/ps_script`）
2. 認證/登入規則（`service: security`，涉及 Kerberoasting/AS-REP Roasting/
   ADMIN$ 存取/SecretDump/隱藏帳號/LSASS 存取等）
3. System 7045 服務安裝規則（`service: system`，`service_control_manager` 子目錄）
4. 其他 process_creation 高價值規則（LOLBAS 擴充、持久化、防禦規避）

## 候選規則清單（已逐條查證，來源 commit `98781da19cf60c48ce6e7f2d3ad11c9ba389191a`）

30 條候選，每條皆已用 WebFetch 讀取實際檔案內容確認：(a) 有 `author:` 欄位
（DRL 1.1 強制要求）(b) logsource 不需要 Sysmon (c) 非 `status: deprecated`/
`unsupported` (d) 與現有 43 條無重複。完整清單見
`docs/dev-history/2026-07-11-sigma-candidate-rules.md`（本 spec 提交時一併移入
版控，原始查證檔案由 subagent 產出於 scratchpad）。

摘要統計：
- PowerShell 4104 Script Block：8 條（AMSI bypass、Mimikatz invoke、Rubeus、
  清除歷史紀錄、建立本機使用者、COM 下載跳板等）
- 認證/登入規則：6 條（Kerberoasting、AS-REP Roasting、ADMIN$ 存取、
  Impacket SecretDump、隱藏帳號建立、LSASS 非系統存取）
- System 7045 服務安裝：4 條（HackTool 服務註冊、可疑服務安裝、罕見映像路徑、
  KrbRelayUp）
- Process Creation 其他：12 條（certutil decode、Tor、cloudflared tunnel、
  7-Zip 密碼壓縮外洩、BITS 持久化、AMSI 登錄竄改、auditpol 竄改、AT 互動式
  工作、EventLog autologger 竄改、cdb.exe 代理執行、AdPlus 記憶體傾印、
  certreq 下載）

排除：`win_security_pass_the_hash_2.yml`（與現有 43 條路徑完全相同）；所有需要
Sysmon 的候選在查證階段已先過濾，未逐條記錄。

## 驗證策略（雙層）

沿用現有 match-parity 測試模式（`tests/` 下 EVTX-ATTACK-SAMPLES fixture 比對），
但不強制每條規則都要有 fixture 才能收錄：

1. **優先層**：查 EVTX-ATTACK-SAMPLES repo 是否有對應樣本，走現有比對測試模式
   （實際 EVTX 事件 → sigma 引擎 → 斷言 Finding 產生）。
2. **後備層**：EVTX-ATTACK-SAMPLES 沒有對應樣本的規則，改為**合成最小 EVTX
   事件**——建構符合該規則 `logsource` + `detection` 條件的最小事件（手寫測試
   fixture，非依賴外部樣本庫），餵給 `cairn-sigma` 引擎，程式化斷言真的產生
   Finding。這比「只驗證 logsource 對映」更嚴格：驗證的是規則的 detection 邏輯
   真的會 match，不是規則的頻道歸屬正確而已。

兩層都要求「該規則被證實會 fire」——不允許只做 logsource 對映驗證就收錄規則，
避免出現「寫了但實際上不會運作」的規則躺在 ruleset 裡。

## 規則清冊文件（新產出，含新增 30 條 + 既有 43 條）

新建 `docs/sigma-rule-catalog.md`，一行一條規則，欄位：
- 規則 path（`ruleset.toml` 內的相對路徑）
- 標題
- 觸發情境（一句話：對應什麼行為）
- 資料前提（需要哪個稽核設定，例如「需啟用 Process Creation 稽核 + 命令列記錄」
  「PowerShell Script Block Logging 需開啟」「4104 預設只記可疑片段，非完整
  逐字稿」）
- 驗證方式（fixture 檔名 / 合成事件測試函式名）
- 是否確認過會 fire（是/否，若否註明原因——本段不允許有「否」的新規則進
  ruleset，但既有 43 條若補登記時發現有規則從未被驗證過，如實記錄現況，不
  倒填假驗證）

這份文件回答使用者原始要求：「是否有些規則寫了但沒有實際運作」。既有 43 條
全部補登記（使用者 2026-07-11 明確要求一併補上，非只覆蓋新增規則）——多數
應該已有 match-parity 測試覆蓋（可從現有 `tests/` 比對回填），少數若查無對應
測試，如實標記「驗證方式：無現存測試，狀態不明」，不假裝已驗證。

## 已知坑（沿用 REMAINING-WORK.md 既有記錄）

- **誤報面擴大**：規則量增加，需按 gate-redesign 哲學控制（false negatives
  優於 false positives，即偏好漏報也不要濫報）——新規則若引入 sigma 引擎層級
  的判定，不額外疊加 cairn 自己的 heuristic 分數放大，維持 Sigma Finding 本身
  的 severity 語意。
- **掃描時間**：規則量從 43→約 73 條（+30，未排除待驗證失敗的），影響 NFR9
  資源治理，需實測掃描時間變化，若顯著劣化需在計畫階段考慮批次驗證/快取策略
  （但不預先假設會劣化到需要處理，先實測）。
- **PowerShell 4104 限制**：預設稽核設定下只記錄「可疑」片段，非完整逐字稿
  （Windows 稽核設定限制，非 Cairn 缺陷）——規則清冊文件需註明此限制，SOC
  runbook（`docs/SOC-runbook-template.md`）需補一行說明資料前提。

## 對 update-rules 管線的影響

`ruleset.toml` 只是選集清單，實際規則內容仍由 `cairn update-rules` 從 SigmaHQ
在指定 pin commit 抓取、XOR 編碼、寫入 PROVENANCE（FR19 既有機制，本段不改動
`crates/cairn-updater` 邏輯）。本段只新增 30 行 `[[rules]]` 區塊到
`ruleset.toml`，並執行一次 `cargo run --bin cairn -- update-rules`（或對應測試
路徑）驗證新規則能被管線正確抓取、編碼、通過 DRL 1.1 author 檢查。

## Out of scope

- Sysmon 規則（維持現有定位，未來獨立段）
- 段 4 塊 C 登入爆破 heuristic 本身的實作（本段只補資料前提，heuristic 邏輯是
  下一段的工作）
- `cairn-sigma` 引擎邏輯改動（純規則選集，不動比對引擎）
- 既有 43 條規則的內容修改（只做清冊登記，不重寫既有規則的偵測邏輯）
