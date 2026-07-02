# IR Snapshot Panels — Design Spec

> **Date:** 2026-07-03
> **Status:** Approved direction — pending user spec review
> **Scope:** 把已收集但目前埋在 records.jsonl 的 IR 關鍵資料，攤成 report.html 的
> 快照面板（對外連線 / 執行中程序 / 近期執行證據 / 可疑檔案活動）+ 新增登入 session collector。
> **Depends on:** heuristic gate redesign (merged to main `068983e`, 2026-07-02) —
> 沿用 report.html 與 Observation 通道地基。
> **SRS refs:** §5.2（timeline/報告）、§4（collectors）、FR18（報告可讀性）、golden rules 3/6/8。

---

## 1. 問題陳述（回到使用者最初的痛）

使用者最初的核心需求是「24 小時內鑑識行動要能看到：還有沒有異常程式在跑、對外連線、
近期執行了什麼、誰在使用、可疑檔案」。實測反饋是「跑完看不到有用資訊」。

**根因不是資料沒收集，是報告沒呈現。** 查證現況：
- report.html 目前只有四塊：verdict banner + 主機資訊卡 + findings 表格 + 主機盤點（僅持久化）。
- `html_report(findings, observations, manifest)` 的簽名**根本拿不到 records**——
  proc / net / execution / USN 全在 records.jsonl，report.html 看不到它們。
- proc collector（image/ppid/signed/integrity/cmdline）、net collector（raddr/rport/pid/state）、
  prefetch/shimcache/amcache/bam/userassist（ExecutionRecord）、USN $J（檔案 create/delete/rename）、
  MFT MOTW（zone_identifier）—— **全部已經在收集，只是沒有出口讓調查者看見**。

所以本 spec 不新增偵測邏輯，而是**把已收集的 IR 關鍵資料呈現出來**（使用者要求：
「重點結果整合進 report.html，細節仍保留在文件」）。加一個小的新收集：登入 session 列舉
（回答「誰**正在**使用」的即時面，現有 4624 只能回答「誰登入**過**」）。

## 2. 目標與非目標

**目標**
1. report.html 新增四個純呈現面板（資料已在 records，零新收集）：
   對外連線 / 執行中程序 / 近期執行證據 / 可疑檔案活動。
2. 新增登入 session collector（`Record::LogonSession`），report.html 呈現「現有登入 session」面板。
3. 面板是**摘要/重點**（report.html 一眼可見），完整細節仍在 records.jsonl / findings.jsonl
   （使用者要求：重點進 HTML、細節留文件）。
4. 面板預設折疊、依 IR 優先度排序，不干擾既有 findings/盤點區塊。
5. 乾淨機器：面板正常顯示主機現況，不產生任何新 finding（純呈現，不是偵測）。

**非目標**
- 不新增任何 heuristic / gate 信號 / Sigma 規則（純呈現 + 一個 collector）。
- 不做 DNS 快取 collector（連線 IP 不回解域名）—— 留給後續。
- 不做 MOTW × 執行的交叉偵測信號（那是偵測，屬 FUTURE 進入向量 spec）—— 本 spec 只**呈現** MOTW 標記。
- 不改 Finding/Observation schema（LogonSession 是新 Record 種類，Record 是內部 bus，非持久化 schema）。
- 不動無檔案 spec（已改名 `FUTURE-fileless-attack-coverage-design.md`，之後再做）。

## 3. 架構總覽

```
現有 records（已收集，只差呈現）              新收集
  NetConnRecord   ─┐                          LogonSessionCollector
  ProcessRecord   ─┤                            (cairn-collectors-win/src/logon.rs unsafe FFI
  ExecutionRecord ─┤                             + cairn-collectors 安全 wrapper)
  UsnEventRecord  ─┤                              └─► Record::LogonSession
  FileMetaRecord  ─┘                                        │
        │                                                   │
        └──────────────┬────────────────────────────────────┘
                       ▼
        html_report(findings, observations, records, manifest)   ← 簽名新增 records
                       ▼
        report.html：verdict + 主機卡 + findings + 【五個新面板】+ 主機盤點
```

**核心改動**：`html_report` 簽名加一個 `records: &[Record]` 參數。這是本 spec 的關鍵解鎖——
report.html 從此看得到 records。純函式維持（records 進去、HTML 出來）。

## 4. 五個面板（依 IR 優先度排序）

每個面板：預設折疊（`<details>`）、摘要行顯示數量、表格呈現重點欄位、XSS escape、
空資料時顯示「無」。所有面板放在 findings 表格之後、主機盤點之前。

### 4.1 對外連線（NetConnRecord）
- 只列 established + listening（過濾 CLOSED/TIME_WAIT 噪音）。
- 欄位：proto / 本地 addr:port / 遠端 addr:port / state / owning PID。
- **排序**：有遠端公網 IP 的排前（`is_public_ipv4`，複用 score.rs）。
- 摘要：「對外連線 (N 條，其中 M 條連往公網)」。

### 4.2 執行中程序（ProcessRecord）
- 欄位：PID / PPID / image 完整路徑 / 簽章狀態 / integrity / cmdline（截斷顯示）。
- **排序**：未簽章（`signed==Some(false)`）排前，其次簽章未知。
- 摘要：「執行中程序 (N 個，其中 M 個未簽章)」。

### 4.3 近期執行證據（ExecutionRecord）
- 欄位：source（prefetch/shimcache/…）/ path / run_count / first_run / last_run。
- **排序**：last_run 最新排前。
- prefetch 誠實標示「僅檔名」（複用既有 evidence 的誠實標註慣例）。
- 摘要：「近期執行證據 (N 筆，來自 K 種來源)」。

### 4.4 可疑檔案活動（UsnEventRecord + FileMetaRecord MOTW）
- 兩部分合併呈現：
  - USN 近期檔案事件：只列 create / rename（過濾大量的 overwrite/close 噪音），欄位 ts / reason / path。
  - MOTW 標記檔案：FileMetaRecord 中 `zone_identifier.is_some()` 的（從網路下載），欄位 path / zone。
- **排序**：MOTW 檔案排前（下載來源是進入向量的強信號），USN 事件依 ts 新到舊。
- 摘要：「可疑檔案活動 (N 個 MOTW 檔案 / M 筆近期檔案事件)」。
- **量控**：USN 事件可能上千筆，面板只顯示前 200 筆（依 ts），完整在 records.jsonl；摘要註明總數。

### 4.5 登入 session（新 LogonSessionCollector）
- 見 §5。欄位：使用者 / session 類型（Interactive/RemoteInteractive/Network/…）/ 登入時間 / 來源。
- **排序**：RemoteInteractive（RDP）排前（遠端登入是 IR 重點）。
- 摘要：「登入 session (N 個，其中 M 個遠端)」。

## 5. 新收集：LogonSessionCollector

### 5.1 讀取方式
- 透過 Windows API 列舉目前的登入 session（`LsaEnumerateLogonSessions` +
  `LsaGetLogonSessionData`，或 `WTSEnumerateSessions` 取互動 session）。官方 API、
  唯讀、不拖主機、EDR 看得見（golden rule 1/3）。
- **依賴變更**：`windows` crate 需新增對應 feature（如 `Win32_Security_Authentication_Identity`
  / `Win32_System_RemoteDesktop`）。查證後於 plan 釘死確切 feature 名。

### 5.2 新 Record 種類
```rust
// cairn-core/src/record.rs：Record enum 新增變體
LogonSession(LogonSessionRecord)

pub struct LogonSessionRecord {
    pub user: String,           // domain\username
    pub logon_type: String,     // Interactive|RemoteInteractive|Network|Service|...
    pub logon_time: Option<DateTime<Utc>>,
    pub source: Option<String>, // 來源主機/IP（網路/RDP session）
    pub session_id: Option<u32>,
}
```
- Record 是內部 bus 型別（無 inline schema，SRS §5 契約），新增變體不影響 Finding/Manifest schema。
- serde 加變體：舊 records.jsonl（無此變體）反序列化不受影響（tagged enum，只影響能否解析新 tag）。

### 5.3 graceful degrade
- LSA/WTS API 失敗 → collector 回 Err、orchestrator skip + 記 manifest，不中止。
- 單一 session 資料讀取失敗 → skip 該筆 + 繼續。

## 6. html_report 簽名變更的連鎖處理

`html_report` 加 `records` 參數會 breaking 所有 caller。查證：caller 是
`DirSink::write_html_report`（cairn-report/src/lib.rs），而 `write_html_report` 這個
OutputSink trait 方法目前簽名是 `(findings, observations, manifest)`。

**處理**：`OutputSink::write_html_report` 簽名加 `records: &[Record]`，連帶更新：
- trait 定義（cairn-core/src/traits.rs）
- DirSink 實作（cairn-report/src/lib.rs）
- cairn-cli 兩處 caller：live 路徑傳 `&outcome.records`；evtx 路徑傳 `&[]`（evtx 模式無 live records）
- 其他 sink（Zip/Age/DryRun）靠 trait default no-op，不受影響（同上個 spec 的模式）
- 相關測試同步更新（機械性加參數）

## 7. 資料流（本 spec 完成後）

```
collectors（含新 LogonSessionCollector）─► records（含 LogonSession）
                                              ├─► analyzers ─► findings（不變）
                                              └─► html_report(findings, observations, records, manifest)
                                                       └─► report.html：+5 面板
records.jsonl / findings.jsonl / observations.jsonl：完整細節（不變，使用者要求細節留文件）
```

## 8. 測試策略

| 面板/collector | 單元測試 | 真機 e2e |
|---|---|---|
| html_report 五面板 | 純函式：給定含各種 Record 的 fixture → HTML 含對應面板標題、數量、XSS escape、空資料顯示「無」、排序正確（公網連線/未簽章程序/RDP session 排前） | 真機掃描 → report.html 五面板都有內容且數字合理 |
| LogonSession collector | 純邏輯：session 資料 → Record 映射、logon_type 字串化、graceful（缺欄位不 panic） | 真機列舉本機 session（至少有當前互動 session）→ 進 records、格式正確 |
| USN 量控 | 純函式：>200 筆 USN → 面板只顯示 200、摘要註明總數 | — |

**跨面板真機驗收**：乾淨機器掃描，report.html 呈現完整主機現況（連線/程序/執行/檔案/session），
findings 維持 0（純呈現不產生 finding），使用者能一眼看到「現在在跑什麼、連去哪、誰登入著」。

## 9. 已知約束與殘留風險

1. **html_report 簽名 breaking**（§6）——連鎖更新所有 caller，機械性但需完整。
2. **windows crate 新 feature**（§5.1）——LSA/WTS session 列舉需新 feature，plan 釘死。
3. **USN 事件量大**（§4.4）——面板截斷 200 筆，完整在 records.jsonl。這是呈現取捨，非資料遺失。
4. **登入 session「來源」欄位**——本機互動登入無來源 IP，`source=None`（誠實留空）。
5. **MOTW 只呈現不偵測**——本 spec 只把 zone_identifier 標記顯示出來，不做「MOTW+執行+未簽章」
   的交叉 gate 信號（那屬 FUTURE 進入向量 spec）。誠實標示：面板是「線索」不是「告警」。
6. **report.html 體積**——五面板 + 現有內容可能讓 HTML 變大（USN/程序多時）。截斷 + 折疊控制。

## 10. 分段建議（交 writing-plans）

1. **段 1（解鎖 records 進報告 + 前三面板）**：html_report 簽名加 records（含全 caller 連鎖）
   + 對外連線 / 執行中程序 / 近期執行證據三個純呈現面板 + 單元測試。這段做完就解決使用者
   最直接的痛（跑完看得到在跑什麼、連去哪、執行了什麼），先見效。
2. **段 2（可疑檔案面板）**：USN 近期檔案活動 + MOTW 標記面板 + 量控（200 筆截斷）+ 測試。
3. **段 3（登入 session collector + 面板）**：windows feature + logon.rs unsafe FFI +
   安全 wrapper + LogonSessionRecord + 接進 collector 清單 + 面板呈現 + 真機 e2e。

每段沿用跨段共通紀律（REMAINING-WORK.md）：forbid-unsafe 維持（僅 logon.rs 在 cairn-collectors-win
既有 unsafe 邊界）、UTC RFC3339、graceful degrade、Finding/Manifest schema 零變動（LogonSession
只加 Record 內部變體）、Cargo.lock pin、本機 clippy --all-targets。
