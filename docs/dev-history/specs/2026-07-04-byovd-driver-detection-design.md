# BYOVD Driver Detection — Design Spec

> **Date:** 2026-07-04
> **Status:** Approved direction — pending user spec review
> **Scope:** Match `amcache_driver` SHA1s against a bundled high-confidence
> known-vulnerable/known-malicious driver hash list; emit a High finding on a hit.
> **Depends on:** amcache_driver collector (already on main — collects
> `Record::Execution { source: "amcache_driver", sha1, path, ... }`).
> **SRS refs:** §4 (collectors), §10 (heuristics), FR12, golden rules 1/6/8.
> **Priority rationale:** Highest value/cost ratio in the backlog — the driver SHA1
> is ALREADY collected but no analyzer consumes it. Zero unsafe, zero new collection,
> pure-logic heuristic + a bundled side-file. One of the three fileless-coverage
> blocks was re-prioritized to front this because BYOVD is a current, high-impact
> technique (privilege escalation / EDR-kill) and the data is already in hand.

---

## 1. 問題陳述

`amcache_driver` collector（已在 main）解析 Amcache `InventoryDriverBinary` 鍵，
產出 `Record::Execution { source: "amcache_driver", path, sha1, ... }`——記錄系統上
曾載入過的每個驅動及其 SHA1（自 `DriverId` 解析，小寫 40 hex）。

**但下游沒有任何 analyzer 使用這個 SHA1。** 資料躺著沒用。

BYOVD（Bring Your Own Vulnerable Driver，T1068）是當紅的提權 / EDR-kill 技術：
攻擊者載入一個**合法簽章但含已知漏洞**的驅動（如 `RTCore64.sys`、`gdrv.sys`、
`dbutil_2_3.sys`），透過它的漏洞取得核心權限、關閉防護、抹除痕跡。因為驅動本身簽章
合法，S2/S3/S4（檔案軸）和簽章檢查都抓不到——**唯一可靠的偵測是雜湊比對已知清單**。

這是全專案投入產出比最高的補強：雜湊、Record、collector 全已到位，只差一份比對清單
和一個純邏輯 heuristic。

## 2. 目標與非目標

**目標**
1. 一份高信心的 known-vulnerable/known-malicious 驅動 SHA1 側檔，隨 binary 打包
   （同 `rules/` 哲學，不硬編進程式碼）。
2. 一個純邏輯 heuristic（`cairn-heur/src/byovd.rs`）比對 `amcache_driver` 的 SHA1
   與該清單，命中 → **High** finding（T1068 + T1211）。
3. 乾淨機器驗收：驅動 SHA1 都不在清單 → 零 finding（除非機器真載過已知惡意驅動）。

**非目標（明確排除）**
- **不做 LOLDrivers 全清單**——只納入高信心子集。LOLDrivers 含大量低信心或
  「合法但可濫用」條目，全塞會製造誤報。寧可漏報也不誤報（延續 gate 重構的哲學）。
- **不做簽章時間戳 / 憑證撤銷檢查**——那是另一層（驗證驅動簽章是否被撤銷），本 spec
  只做雜湊比對。
- **不做 runtime 網路抓清單**——golden rule（除 update-rules 外無網路行為）。清單走側檔。
- **不做變種/模糊雜湊比對**——只做精確 SHA1 比對（見 §6 殘留風險 1）。
- **不改 Record/Finding/Manifest schema**——heuristic 純消費既有 `Record::Execution`。

## 3. 架構總覽

```
rules/loldrivers/known-vulnerable-drivers.txt   ← 側檔：小寫 40-hex SHA1，一行一個
        │                                           （隨 binary 打包，載入機制仿 Sigma bundled）
        ▼
   load_driver_hashes(path) → HashSet<String>   ← 載入 + 正規化 + 格式驗證（純函式）
        │
        ▼
   ByovdHeuristic (cairn-heur/src/byovd.rs)      ← 純邏輯 analyzer
        │   掃 Record::Execution where source=="amcache_driver" && sha1.is_some()
        │   比對 HashSet
        ▼
   Finding { severity: High, mitre: [T1068, T1211], reason, evidence }
```

## 4. 側檔：驅動雜湊清單

### 4.1 位置與格式
- 路徑：`rules/loldrivers/known-vulnerable-drivers.txt`
- 格式：**每行一個小寫 40 字元 SHA1**（對齊 `ExecutionRecord.sha1` 的格式——
  collector 已 `to_ascii_lowercase()`，清單也必須小寫，否則字串比對永遠 miss）。
- 允許：`#` 開頭的註解行、空行（載入時跳過）。行尾建議加 `# <driver name>` 註記來源。
- **高信心子集**：只納入 LOLDrivers 專案中標記 known-vulnerable 或 known-malicious、
  且有明確 CVE / 實際攻擊使用記錄的驅動。初版納入業界公認的高頻 BYOVD 驅動雜湊
  （RTCore64/gdrv/dbutil/mhyprot/…），plan 階段列出具體條目與來源註記。

### 4.2 載入（純函式，`load_driver_hashes`）
- 讀檔 → 逐行處理：trim → 跳過空行與 `#` 開頭 → 取 `#` 前的內容再 trim
  （容許行內註記）→ 小寫 → **驗證恰好 40 個 ASCII hex 字元**，符合才加入 HashSet，
  不符合的行 **skip（不讓一行壞資料炸掉整份清單）**，可選擇記一個 warn。
- 回傳 `HashSet<String>`（O(1) 比對）。
- 檔案不存在 / 讀不到 → 回空 HashSet（heuristic 空手而回，graceful，golden rule 8）。

### 4.3 打包（bundled）
- 側檔隨 `dist/` 打包（同 `rules/`）。載入路徑解析仿現有 bundled Sigma 規則的作法
  （相對於 binary 或 rules 目錄）——plan 階段對照現有 rules 載入程式碼釘死確切路徑解析。

## 5. Heuristic（`cairn-heur/src/byovd.rs`）

### 5.1 邏輯
```
for r in records:
    let Record::Execution(e) = r else continue
    if e.source != "amcache_driver": continue
    let Some(sha1) = &e.sha1 else continue      // None（格式不符）→ 跳過，不誤判
    if hashset.contains(sha1):
        emit Finding {
            severity: High,
            title: "已知漏洞/惡意驅動: <basename>",
            mitre: ["T1068", "T1211"],
            reason: "driver SHA1 <sha1> matches the bundled known-vulnerable/malicious driver list (BYOVD)",
            artifact: "byovd",
            evidence: [EvidenceItem { artifact: "amcache_driver", path: Some(e.path), ts: e.last_run.or(e.first_run), detail: "SHA1=<sha1>" }],
            ts: e.last_run.or(e.first_run).unwrap_or(now),
        }
```
- **只比對 `sha1.is_some()`**——collector 對不符格式的 DriverId 留 `sha1=None`（NFR12），
  這些直接跳過。
- 命中即 **High**（不分級）：一個已知漏洞驅動被載入過，本身就是高風險事實，
  不需要組合其他信號。
- Finding 帶 `reason`（golden rule 6）+ evidence（驅動路徑 + SHA1 + 載入時間）。
- 清單為空（載不到）→ 迴圈比對永遠 miss → 零 finding，不 panic。

### 5.2 為何不進 gate / 不走 Observation
BYOVD 是明確的偵測（雜湊命中已知惡意清單），不是盤點——所以直接出 Finding，
不經 persist gate（那是給持久化記錄的），也不進 Observation 通道。它是獨立 analyzer，
與 gate 正交。

## 6. 已知約束與殘留風險

1. **精確雜湊比對只抓已知樣本**——攻擊者改一個 byte 就換 SHA1 規避。這是雜湊比對的
   先天限制，非缺陷。BYOVD 驅動通常是**原封不動**使用合法簽章的漏洞驅動（改了就破壞
   簽章，失去 BYOVD 的意義），所以精確比對對真實 BYOVD 有效；但完全客製的惡意驅動
   會漏。這正是為何偵測要**多層**（雜湊 + 未來的簽章撤銷 + 行為）。spec 誠實標示。
2. **清單覆蓋率 = 偵測上限**——只抓清單裡有的。高信心子集刻意窄（避免誤報），
   代價是覆蓋不全。清單維護是持續工作（未來可考慮納入 update-rules 式的更新機制）。
3. **amcache_driver 依賴 Amcache 存在且驅動曾登記**——Amcache 是 Windows 的
   相容性遙測，驅動載入通常會登記，但非即時、非保證。這是既有 collector 的特性，
   非本 spec 引入。且 amcache collector 需要 admin + SeBackupPrivilege（既有限制）。
4. **DriverId 可能非標準格式**——collector 已處理（不符 → sha1=None），heuristic 跳過。

## 7. 測試策略

| 層 | 單元測試 | 真機 e2e |
|---|---|---|
| `load_driver_hashes` | 純函式：正常清單 → 正確 HashSet；含註解/空行/大寫/行內註記 → 正確正規化；壞行（非 40 hex、含空白）→ skip 不炸；檔案不存在 → 空 HashSet | — |
| `ByovdHeuristic` | 合成 fixture：一個 amcache_driver SHA1 在清單內 → High + T1068 + evidence；一個不在 → 無；sha1=None → 跳過；source≠amcache_driver → 忽略；空清單 → 零 finding | 真機掃描（admin+SeBackup）→ 本機驅動 SHA1 都不在清單 → 零 finding（乾淨機器正確行為）|

## 8. 分段建議（交 writing-plans）

單一 spec，範圍小，建議 **1 段**（或至多拆 2 個 task）：
1. **側檔 + 載入純函式**：建 `rules/loldrivers/known-vulnerable-drivers.txt`（高信心條目 +
   來源註記）+ `load_driver_hashes` 純函式 + 格式驗證單元測試。
2. **ByovdHeuristic + 接線 + 驗收**：`byovd.rs` analyzer + lib.rs re-export +
   main.rs analyzers vec 接線 + 清單載入接進 CLI + 單元測試 + 真機零誤報驗收。

沿用跨段共通紀律：forbid-unsafe 維持（byovd.rs 純邏輯，零 unsafe）、UTC RFC3339、
graceful degrade（清單載不到 → 空手而回）、schema 零變動、Cargo.lock 零變動
（零新依賴）、本機 clippy --all-targets。

## 9. 與後續 spec 的關係

本 spec 是重新配置後的三個 fileless-coverage spec 的第一個（最高性價比先做）：
1. **（本 spec）BYOVD 驅動偵測** — 雜湊已收，只差比對。
2. **Sigma 規則大擴充 + EVTX 頻道** — 偵測廣度的頭號瓶頸，49→數百條 curated 規則。
3. **WMI 訂閱（重設計為 Observation-first）+ 登入爆破 heuristic** — WMI/COM FFI 最貴，殿後。

原 `2026-07-03-fileless-attack-coverage-design.md` 的塊 A（WMI）在 brainstorm 中驗出
`ActiveScriptEventConsumer` 假陰性缺陷（gate 的 S9 只認被呼叫的直譯器，抓不到內嵌
ScriptText），故 WMI 改為「一律進 Observation、鐵證才升 Finding」的設計，與塊 C（爆破）
併入第三個 spec；塊 B（Sigma 擴充）獨立為第二個 spec 並具體化。
