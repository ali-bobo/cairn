# 段 4-塊C：登入爆破偵測 — 設計 Spec

- 日期：2026-07-15
- 基準：main HEAD `51bbd4c`
- 對應 backlog：`docs/REMAINING-WORK.md` 段 4 塊 C
- 前身設計：`docs/dev-history/specs/2026-07-03-fileless-attack-coverage-design.md` §6.2（邏輯核心沿用，範圍本次擴大）

## 背景與動機

原始 fileless-attack-coverage spec §6.2 設計了「同帳號多來源」爆破偵測邏輯，但當時
的資料前提（Security 頻道要有 Sigma 規則引用才會被收集）尚未滿足。段 2（Sigma 規則
大擴充，PR #35）新增了認證/登入類規則（Kerberoasting、AS-REP Roasting、ADMIN$ 存取
等），連帶確保 Security 頻道被收集——資料前提現已滿足。

本次 brainstorm 重新檢視 §6.2 的分組鍵設計時，發現原設計「`(TargetUserName,
IpAddress)`，缺失 fallback `(TargetUserName, WorkstationName)`」只能偵測「同一來源
針對同一帳號」的爆破，抓不到 password spraying（同一來源 IP 對多個不同帳號做低頻嘗
試，規避單帳號鎖定機制的常見手法）。使用者決定本段一併擴充涵蓋 spraying。

## 範圍

新建 `crates/cairn-heur/src/logon_bruteforce.rs`，實作 `Analyzer` trait（
`crates/cairn-core::traits::Analyzer`），讀取 `Record::Event`（`channel: "Security"`,
`event_id ∈ {4624, 4625}`）。這是 `cairn-heur` 裡第一個需要跨事件時間窗分組計數的
heuristic——沒有直接前例，`persist.rs` 的 `CrossIndex` 只是路徑/名稱交叉比對索引，
不含時間窗概念（brainstorm 階段已查證確認）。

**兩種偵測模式，各自獨立分組鍵與閘值**：

1. **帳號爆破**（原 §6.2 設計）：分組鍵 `(TargetUserName, IpAddress)`，IpAddress
   缺失時 fallback `(TargetUserName, WorkstationName)`。閘值：時間窗 5 分鐘內同一
   分組鍵出現 ≥5 次 4625（失敗）。
2. **Password spraying**（本次新增）：分組鍵 `IpAddress`（缺失 fallback
   `WorkstationName`）。閘值：時間窗 1 分鐘內同一分組鍵對 ≥10 個不同
   `TargetUserName` 發起登入嘗試（成功或失敗皆計入嘗試次數，因為 spraying 的訊號
   是「廣度」而非「失敗率」）。

兩模式各自產生獨立的 Finding，不互相抑制（同一批事件理論上可能同時觸發兩種模式，
例如一個 IP 對同一帳號連續爆破、又順便對其他帳號做低頻嘗試——這是合理的雙重訊號，
不視為 double-counting）。

## Severity 邏輯（兩模式共用同一原則）

- 純失敗、時間窗內分組鍵沒有任何成功登入（4624）接續 → **Medium**
- 時間窗內分組鍵最終出現至少一次成功登入（4624）→ **High**（代表爆破/spraying
  可能已得手，需要立即關注）

## 分組聚合的通用結構

兩種模式共用同一個聚合函式：先按 `Record::Event` 逐筆解析出
`(ts, target_user, ip_or_workstation, event_id)` 四元組（缺失欄位 graceful skip，
不 panic，沿用 `account.rs` 的 `extract_str` pattern），再依各自分組鍵分桶進
`HashMap<GroupKey, Vec<LogonAttempt>>`，桶內用時間窗滑動比對（非全域排序後掃描，
避免大量事件時的效能問題——時間窗小，可用簡單的「以任一事件為錨點，往後找窗內
事件」線性做法，不需要真正的滑動窗資料結構，因為單機單次觸發的登入事件量級不會
大到需要優化）。

`GroupKey` 對兩模式不同（帳號爆破是 `(String, String)` 二元組，spraying 是
`String` 單一鍵），用 enum 或分開兩個 `HashMap` 皆可，實作階段依程式碼簡潔度決定。

## 閘值管理

四個閘值（帳號爆破的時間窗+次數、spraying 的時間窗+次數）都放進
`cairn_core::Config`，比照既有 `timestomp_threshold_hours`（`config.rs:118-119`）
的模式：具名欄位、doc comment 說明用途、有 default 值、**不開 CLI flag**（YAGNI，
使用者未來若有實際調整需求再開）。

預設值：
- `logon_bruteforce_window_minutes: i64 = 5`
- `logon_bruteforce_threshold: u32 = 5`
- `password_spraying_window_minutes: i64 = 1`
- `password_spraying_threshold: u32 = 10`

## Finding 內容（golden rule 6：每個 heuristic 必須設定 reason）

- **帳號爆破 Finding**：`reason` 說明「帳號 X 在時間窗內從來源 Y 收到 N 次失敗登入
  嘗試」（+ 若 High，補充「並於 HH:MM:SS 出現成功登入」）；`evidence` 附失敗事件
  時間戳列表、來源、（若適用）成功登入的時間戳。
- **Spraying Finding**：`reason` 說明「來源 X 在時間窗內對 N 個不同帳號發起登入
  嘗試」（+ 若 High，補充哪個帳號成功）；`evidence` 附嘗試涉及的帳號清單、來源、
  （若適用）成功帳號與時間戳。

兩者的 `entity` 使用現有 `Entity` 型別中最貼近的變體（沿用既有 Finding 型別，
不新增 entity 子類型——`crates/cairn-core/src/finding.rs:25-34` 目前的變體種類
在 writing-plans 階段核對是否有合適的既有變體可用，若無則用最泛用的變體 + details
欄位承載，不為此新增 schema）。

## 資料前提

不依賴 Sigma Finding，直接讀 `Record::Event` 原始 EVTX 事件——只要 Security 頻道
被收集即可（段 2 已確保這點，因為 `ruleset.toml` 現有多條規則引用該頻道），不需要
任何規則真的命中。

## Out of scope

- 不做跨主機關聯（多台主機的登入嘗試彙整）——cairn 是單機鑑識工具，範圍限單一
  掃描目標主機的本地 Security 事件
- 不做地理位置/ASN 類的 IP 信譽判斷——IpAddress 只用作分組鍵，不查外部資料庫
  （SSRF/外部依賴風險，且 cairn 是離線鑑識工具）
- 不開 CLI flag 調整閘值（YAGNI，見上）
- 不新增 Finding/Entity schema（沿用既有型別）
