# Fileless Attack Coverage — Design Spec (Spec 1 of the IR-triage expansion)

> **Date:** 2026-07-03
> **Status:** Approved direction — pending user spec review
> **Scope:** WMI event-subscription collector + EVTX channel expansion (PowerShell /
> authentication / lateral movement) + matching Sigma rules + one cross-event heuristic.
> **Depends on:** heuristic gate redesign (merged to main `068983e`, 2026-07-02) —
> reuses the persist dispositive-signal gate and the Observation channel.
> **SRS refs:** §4 (collectors), §10 (heuristics), FR9 (persistence), FR12, golden rules 1/6/8.

---

## 1. 問題陳述

Cairn 目前所有的持久化偵測信號（gate S2/S3/S4）都建立在
「binary_path + 簽章狀態」這條**檔案軸**上。無檔案（fileless）攻擊的定義正是
「payload 不落地成傳統 exe」，因此對這條軸**天生失明**。三個具體盲區：

1. **WMI event subscription** — 無檔案持久化的頭號手法（`__EventFilter` +
   `CommandLineEventConsumer`/`ActiveScriptEventConsumer` + `__FilterToConsumerBinding`）。
   payload 是 WMI repository 裡的一段命令/腳本字串，**完全不在檔案系統**。
   查證：現有 `PersistCollector` 只有 5 個 reader（run_key/service/scheduled_task/
   startup/winlogon/ifeo），**WMI 訂閱完全沒收**。
2. **無檔案執行痕跡** — PowerShell script block（4104）、`powershell -enc`、反射載入等，
   這些痕跡只存在 EVTX（PowerShell Operational 頻道），不在檔案系統。查證：現有
   `LogsourceMap` 有 powershell 頻道映射，但 `ruleset.toml` 只有 49 條規則，涵蓋薄。
3. **認證 / 橫向移動** — 誰登入了（4624）、爆破（4625）、顯式憑證登入（4648）、
   特權指派（4672）、遠端 service 安裝（7045）。這回答「還有沒有異常使用者在使用」
   與「有沒有橫向擴散」。查證：現有 EVTX 收集靠 `--since`（預設 24h），但沒有規則
   引用這些認證/橫向頻道，故實際上不會被收集。

## 2. 目標與非目標

**目標**
1. WMI event subscription 進 `Record::Persistence`（mechanism="wmi_subscription"），
   **復用上一個 spec 剛建好的 persist gate**（S9 腳本 / S2 未簽章）分析，零新持久化 heuristic。
2. PowerShell 4104/4103、認證 4624/4625/4648/4672、System 7045 進 EVTX 收集，
   主偵測靠擴充後的 Sigma 規則集。
3. 一個跨事件 heuristic：登入爆破（多次 4625 後成功 4624）——Sigma 單事件引擎的結構盲區。
4. 乾淨機器驗收：不引入新誤報（High/Medium 維持 0，除非機器真有可疑 WMI 訂閱/爆破）。

**非目標（spec 明確排除，避免範圍爆炸）**
- 記憶體 injection / process hollowing 偵測 —— **golden rule 1 禁止**，交給 Volatility 類工具。
- WMI repository（OBJECTS.DATA）離線二進位解析 —— 本 spec 只做 **live WMI API**；
  離線映像的 WMI 訂閱留給未來 spec。
- COM hijack / AppInit_DLLs / netsh helper 等其他無檔案持久化 —— 留給後續 spec。
- 完整封包捕捉 / DNS collector —— 屬「IR 快照面板」spec 2，不在此。
- PowerShell script block 的深度去混淆（base64 解碼後再分析）—— Sigma 規則層處理到哪算哪，
  不自寫解碼器。

## 3. 架構總覽

```
塊 A: WMI 訂閱 collector
  cairn-collectors-win/src/wmi.rs      (unsafe FFI: WMI/COM 查詢 root\subscription)
    └─ 安全 wrapper → cairn-collectors/src/wmi_subscription.rs (#![forbid(unsafe_code)])
         └─ Record::Persistence { mechanism="wmi_subscription", ... }
              └─ 【復用】現有 persist gate (S9/S2) → Finding 或 Observation

塊 B: EVTX 頻道擴充
  cairn-sigma/src/lib.rs  LogsourceMap  ← 新增 powershell/security-auth/system 頻道
  rules/ruleset.toml                    ← 拉進對應 SigmaHQ 規則 (update-rules 管線)
    └─ EvtxLiveCollector 依 sa.channels() 自動收集 → 現有 SigmaAnalyzer 偵測

塊 C: 跨事件 heuristic
  cairn-heur/src/logon_bruteforce.rs    ← 4625×N + 4624 序列 → Finding
```

## 4. 塊 A：WMI event subscription collector

### 4.1 讀取方式（已定：live WMI API）
- 透過 WMI/COM 查詢 `root\subscription` 命名空間，官方 API、讀取不拖主機、
  EDR 完全看得見（符合 golden rule 1）。**不**解析 OBJECTS.DATA 二進位。
- **依賴變更**：`cairn-collectors-win/Cargo.toml` 的 `windows` crate 需新增 features
  `Win32_System_Wmi` + `Win32_System_Com`（查證：目前 features 清單無此二者）。
  新依賴走 license/CVE/供應鏈四關（windows crate 本身已是既有依賴，只是開新 feature，風險低）。

### 4.2 收集的三類物件
| WMI 類別 | 意義 | 對應欄位 |
|---|---|---|
| `__EventFilter` | 觸發條件（WQL query，通常綁登入/開機/計時器） | → `location`（filter name + query） |
| `CommandLineEventConsumer` | 觸發時執行的命令列 | → `command`（CommandLineTemplate）|
| `ActiveScriptEventConsumer` | 觸發時執行的 VBScript/JScript | → `command`（ScriptText，前綴標示語言）|
| `__FilterToConsumerBinding` | 綁定 filter↔consumer | → 用於關聯，不單獨出 record |

### 4.3 映射到 Record::Persistence
- 每個「已綁定的 consumer」出一筆 `Record::Persistence`：
  - `mechanism = "wmi_subscription"`
  - `location` = filter 名稱 + WQL query（如 `EventFilter=X; query=SELECT * FROM __InstanceModificationEvent...`）
  - `command` = consumer 的 CommandLineTemplate 或 ScriptText
  - `binary_path` = 從 command 解析出的執行檔（若 CommandLineEventConsumer 呼叫 exe），
    否則 `None`（ActiveScript 是純腳本，無 binary_path）
  - `signed` = 若解析出 binary_path 則交下游驗章；否則 `None`
  - `value` = consumer 名稱
  - `last_write` = `None`（WMI 訂閱無可靠時間戳；誠實留空，NFR12）

### 4.4 為何不需要新 heuristic（架構驗證點）
WMI 訂閱一旦是 `Record::Persistence`，**現有 persist gate 直接分析**：
- consumer 命令是 `powershell -enc ...` / `mshta http://...` → 命中 **S9**（腳本 gate）→ High
- CommandLineEventConsumer 指向未簽章 exe 在使用者可寫路徑 → 命中 **S2** → High
- 良性的 WMI 訂閱（如防毒/管理軟體裝的）→ 不命中任何信號 → 進 **Observation**（盤點）
- **新增 mechanism 對 gate 是透明的**：`evaluate_gate` 不看 mechanism 名稱（除了 startup 豁免與
  winlogon 特判），S2/S9 對 wmi_subscription 自動適用。`observe()` 的 category 用 mechanism 字串，
  自動歸為 `wmi_subscription` 分類。

### 4.5 graceful degrade（golden rule 8）
- WMI 服務不可用 / COM 初始化失敗 → collector 回 Err，orchestrator skip + 記 manifest，
  不中止整段。
- 單一 consumer 解析失敗 → skip 該筆 + 旗標，繼續其餘（per-entry graceful）。

## 5. 塊 B：EVTX 頻道擴充

### 5.1 LogsourceMap 新增頻道（cairn-sigma/src/lib.rs）
- PowerShell：`Microsoft-Windows-PowerShell/Operational`（4104 script block、4103 module）
- 認證：`Security`（4624 logon / 4625 failed / 4648 explicit-cred / 4672 special-priv）
  ——Security 頻道映射查證已存在（4720 等帳號事件已用），確認登入事件的 logsource 別名也映射到位。
- 服務安裝：`System`（7045 service install）

### 5.2 收集機制（沿用現有，零新機制）
- `EvtxLiveCollector` 收哪些頻道由 `SigmaAnalyzer.channels()`（= 引擎引用的頻道）決定。
- **關鍵約束（查證得出，必須釘死）**：頻道只有在**至少一條 Sigma 規則引用它**時才會被收集。
  因此塊 B 的頻道擴充**必須**伴隨塊 B 的 Sigma 規則擴充——否則頻道映射加了也是空的。
  且塊 C 的爆破 heuristic 需要 Security 認證事件，**依賴塊 B 確實引用了 Security 登入頻道**
  （見 §6.3 的相依性處理）。
- 時間窗口沿用 `--since`（預設 24h）。

### 5.3 Sigma 規則擴充（rules/ruleset.toml + update-rules）
- 透過現有 `cairn update-rules` 管線，把 `ruleset.toml` 的規則子集擴充，拉進 SigmaHQ 對應規則：
  - PowerShell：encoded command、suspicious script block、download cradle、AMSI bypass 樣式
  - 認證：異常 logon type、pass-the-hash 樣式、可疑 4648 顯式憑證
  - 服務：可疑 7045 service install（LOLBAS 路徑、臨時目錄）
- 規則仍是 DRL 1.1（每條帶 rule_author）、XOR 編碼、version pin —— 現有機制不動。
- **不自寫規則內容**：全部來自 SigmaHQ，品質外包給社群（本 spec 的核心決策）。

## 6. 塊 C：登入爆破 heuristic（唯一新 heuristic）

### 6.1 為何只做這一個
Sigma 是**單事件**規則引擎，做不到「跨多個事件的頻率/序列」分析。登入爆破的本質是
「短時間內 N 次失敗（4625）後接一次成功（4624），來自同一來源/同一目標帳號」——
這是 Sigma 結構上做不到、而 heuristic 天生適合的。其餘單事件判斷（單一可疑登入類型、
單一異常命令）全部交給 Sigma。

### 6.2 邏輯（cairn-heur/src/logon_bruteforce.rs）
- 輸入：`Record::Event`（channel=Security，event_id ∈ {4624, 4625}）。
- 分組鍵：`(TargetUserName, IpAddress)` 或 `(TargetUserName, WorkstationName)`（來源識別）。
- 信號：同組在時間窗（預設 5 分鐘）內 ≥ N 次 4625（預設 5）**且**其後有一次 4624（成功）
  → **High**（爆破成功）；只有失敗無成功 → **Medium**（爆破嘗試）。
- 每個 Finding 帶 `reason`（golden rule 6）+ evidence（列出失敗次數、來源、成功時間戳）。
- 常數（窗口/次數）先寫死，未來可 Config 化（YAGNI）。
- graceful：欄位缺失（無 IpAddress）→ 用 WorkstationName fallback；都無 → skip 該事件不 panic。

### 6.3 相依性處理（塊 B ↔ 塊 C）
爆破 heuristic 需要 Security 登入事件進到 records，而 §5.2 的約束是「頻道要有 Sigma 規則引用
才會被收集」。兩個解法，**採第一個**：
- **（採用）** 確保塊 B 拉進的 Sigma 規則集**包含至少一條引用 Security 登入事件（4624/4625）
  的規則**（SigmaHQ 有現成的 failed-logon / suspicious-logon 規則），這樣 Security 登入頻道
  自然被收集，爆破 heuristic 就有資料。實作時在驗收步驟明確檢查「Security 登入事件有進 records」。
- （備案，不採用）給 EvtxLiveCollector 加一組「heuristic 需要的頻道」獨立於 Sigma channels——
  增加機制複雜度，違反「零新機制」原則，不做。

## 7. 資料流（本 spec 完成後）

```
live WMI API ──► wmi_subscription collector ──► Record::Persistence(wmi_subscription)
                                                     └─► 現有 persist gate ─► Finding / Observation
winevt\Logs ──► EvtxLiveCollector (Sigma channels 含新頻道) ──► Record::Event
                     ├─► SigmaAnalyzer (擴充規則集) ─────────► Finding
                     └─► LogonBruteforceHeuristic ──────────► Finding (跨事件)
```

## 8. 測試策略

| 塊 | 單元測試 | 真機 e2e |
|---|---|---|
| A | 純函式：WQL/命令解析、consumer→Record 映射、graceful（缺欄位不 panic）；用合成 WMI 物件 fixture | 真機列舉本機 WMI 訂閱（防毒/管理軟體通常有幾筆）→ 確認進 Observation、格式正確、零 panic |
| B | LogsourceMap 新頻道映射往返、channel_to_filename 正確 | 確認 Security 登入事件 + PowerShell 4104 有進 records（§6.3 驗收點）；Sigma 規則在 EVTX-ATTACK-SAMPLES 上仍亮 |
| C | 純邏輯：爆破序列（N 次 4625 + 4624）→ High、只失敗 → Medium、正常登入 → 無、欄位缺失 graceful | 真機：正常機器無爆破 → 零誤報 |

**跨塊真機驗收**：乾淨機器掃描，High/Medium 維持 0（除非機器真有可疑 WMI 訂閱或爆破痕跡）；
WMI 訂閱盤點進 observations.jsonl 的 wmi_subscription 分類。

## 9. 已知約束與殘留風險（實作前必讀）

1. **EVTX 頻道收集依賴 Sigma 規則引用**（§5.2）——頻道映射必須伴隨規則擴充，否則空收。
   塊 B/C 相依性見 §6.3。
2. **windows crate 需新增 WMI/COM features**（§4.1）——目前 features 清單無此二者。
3. **WMI 訂閱無可靠時間戳**——`last_write=None`（NFR12 誠實），故對 wmi_subscription
   S4（recency）天生不觸發；靠 S2/S9 分析，這是正確的（WMI payload 的風險在命令內容，不在時間）。
4. **PowerShell 4104 預設只記可疑片段**——除非目標機器開了全量 script block logging，
   否則 4104 覆蓋不完整。這是 Windows 稽核設定問題，非 Cairn 缺陷；spec 誠實標示、
   SOC runbook 可建議開啟。
5. **爆破 heuristic 的來源識別依賴 IpAddress/WorkstationName 欄位**——本機登入（非網路）
   這些欄位可能是 `-`，此時 fallback WorkstationName，仍無則 skip（不誤判本機互動登入為爆破）。
6. **catalog-signed 誤報**（延續上一個 spec 的殘留）——WMI CommandLineEventConsumer 指向的
   系統 exe 可能被 WinVerifyTrust 誤報未簽章；S2 的「使用者可寫路徑」條件屏蔽大多數。

## 10. 分段建議（交 writing-plans）

1. **段 1（塊 A 地基）**：windows crate WMI features + `wmi.rs` unsafe FFI +
   `wmi_subscription.rs` 安全包裝 + Record 映射 + 接進 collector 選擇清單 + 真機 e2e。
   驗證「WMI 訂閱復用現有 gate」這個架構點。
2. **段 2（塊 B）**：LogsourceMap 頻道擴充 + ruleset.toml 規則擴充（含 §6.3 的 Security
   登入規則）+ 確認新頻道有進收集 + EVTX-ATTACK-SAMPLES parity 不退步。
3. **段 3（塊 C）**：LogonBruteforceHeuristic + 接線 + 相依性驗收（Security 登入事件確有進
   records）+ 乾淨機器零誤報驗收。

每段沿用跨段共通紀律（見 REMAINING-WORK.md）：forbid-unsafe 維持（僅 wmi.rs 在 cairn-collectors-win
的既有 unsafe 邊界內）、UTC RFC3339、graceful degrade、schema 零變動（wmi_subscription 只是
mechanism 字串新值，Record 結構不變）、Cargo.lock pin、本機 clippy --all-targets。
