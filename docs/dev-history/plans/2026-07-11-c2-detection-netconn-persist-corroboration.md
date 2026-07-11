# C2 偵測強化：netconn 獨立訊號 + 跨 analyzer 佐證 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 解決 443/80 常見埠偽裝 C2 完全漏偵測的問題（netconn owner 身分訊號獨立成立），並讓 netconn 利用段 10 剛建好的依賴管道讀取 persist 的判定結果做跨 analyzer 佐證。

**Architecture:** `JoinKey`/`join_key` 從 `persist.rs` 搬到共用的 `score.rs`；`netconn.rs` 新增一個不依賴連線埠稀有度的獨立評分路徑（owner 未簽章+可疑路徑）；`netconn.rs` 宣告依賴 `heur_persist`，用 `prior_findings` 參數讀取 persist 的 Finding，透過字串標記（因為 `Finding` 沒有 source-analyzer 欄位）識別來源並比對 `evidence` 路徑做佐證加分。

**Tech Stack:** Rust，無新依賴，無 schema 變動。

---

## 檔案結構總覽

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-heur/src/score.rs` | 修改 | 新增 `JoinKey`/`join_key`/`basename_from_normalized`/`strip_exe_suffix`（從 persist.rs 搬入，改 `pub`）+ 搬入的 4 個測試 |
| `crates/cairn-heur/src/persist.rs` | 修改 | 移除搬走的 4 項定義 + 4 個測試；改用 `use crate::score::{join_key, JoinKey}`；reason 組裝處加入 `"source: heur_persist"` 標記 |
| `crates/cairn-heur/src/netconn.rs` | 修改 | 新增獨立訊號（owner 未簽章+可疑路徑，權重 50）；新增 `depends_on()`；`analyze()` 內新增跨 analyzer 佐證邏輯（+30） |

---

## Task 1：`JoinKey` 從 `persist.rs` 搬到 `score.rs`

**Files:**
- Modify: `crates/cairn-heur/src/score.rs`（新增內容，插入於第 165-166 行之間，即 `is_inbox_service_command` 函式結束、`Score` struct 定義之前）
- Modify: `crates/cairn-heur/src/persist.rs:208-254`（移除搬走的定義）、`persist.rs:1099-1137`（移除搬走的 4 個測試）

**明確不搬**：`CrossIndex`（persist.rs 第 264-302 行附近）、`build_cross_index`
（第 304-338 行附近）、以及測試
`cross_index_full_paths_with_same_basename_never_collide_via_degraded`
（persist.rs 第 1139 行之後）——這些是 persist 專用的索引結構，netconn
不需要，留在原地不動。

- [ ] **Step 1: 在 `score.rs` 新增 `JoinKey` 及相關函式（先寫成 `pub`，讓後續 Task 3 能從 `netconn.rs` 使用）**

用 Read 工具讀 `crates/cairn-heur/src/score.rs` 第 140-170 行確認插入點
（`is_inbox_service_command` 函式結尾在第 165 行，`Score` struct 定義從
第 168 行開始），在兩者之間插入：

```rust
/// 跨文物比對鍵：有完整路徑（含目錄分隔符）就用正規化後的完整路徑比對；
/// 只有檔名（來源本身缺路徑資訊，如多數 prefetch 條目、srum 的 "id:<n>" 回退）
/// 就降級成純檔名比對。降級佐證的信心度低於完整路徑相符，呼叫端在組
/// finding reason 時必須標註「降級佐證」。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JoinKey {
    /// 正規化（trim + 去引號 + 小寫）後的完整路徑，含目錄。
    Path(String),
    /// 僅檔名（去 `.exe` 尾綴），來源缺路徑資訊。
    Name(String),
}

impl JoinKey {
    /// 兩個 JoinKey 是否應視為同一佐證目標：Path 對 Path 要求完全相同；
    /// 任一方是 Name（降級）就退回比對雙方的 basename。
    pub fn degraded_key(&self) -> String {
        match self {
            JoinKey::Path(p) => basename_from_normalized(p),
            JoinKey::Name(n) => n.clone(),
        }
    }
}

/// 從一個原始路徑/檔名字串建立 JoinKey：trim + 去引號 + 小寫，再判斷是否含
/// 目錄分隔符（`\` 或 `/`）。不含分隔符（如純檔名、或 srum 的 "id:42" 回退）
/// 一律視為 Name（降級）鍵。
pub fn join_key(raw: &str) -> JoinKey {
    let normalized = raw.trim().trim_matches('"').to_ascii_lowercase();
    if normalized.contains('\\') || normalized.contains('/') {
        JoinKey::Path(normalized)
    } else {
        JoinKey::Name(strip_exe_suffix(&normalized))
    }
}

/// 從一個已正規化（小寫、trim 過）的完整路徑取出檔名（去 `.exe` 尾綴）。
fn basename_from_normalized(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    strip_exe_suffix(base)
}

/// 去掉 `.exe` 尾綴（若有）。
fn strip_exe_suffix(s: &str) -> String {
    s.strip_suffix(".exe")
        .map(String::from)
        .unwrap_or_else(|| s.to_string())
}
```

**注意**：`basename_from_normalized`/`strip_exe_suffix` 維持 private（不加
`pub`）——它們只是 `join_key`/`degraded_key` 的內部依賴，外部呼叫者
（`persist.rs`、`netconn.rs`）不需要直接使用它們。

- [ ] **Step 2: 把 4 個 `join_key_*` 測試搬到 `score.rs` 的 `#[cfg(test)] mod tests`**

用 Read 工具讀 `crates/cairn-heur/src/persist.rs` 第 1099-1137 行，確認以下
四個測試的完整內容（列出供比對，這是要被搬走、不是要新寫的內容）：

```rust
    #[test]
    fn join_key_full_path_requires_path_match_not_just_basename() {
        // Two ProcessRecords with the same basename but different directories must
        // NOT be treated as the same join key when both sides have full paths.
        let a = join_key(r"C:\Windows\System32\evil.exe");
        let b = join_key(r"C:\Users\x\AppData\Local\Temp\evil.exe");
        assert_ne!(a, b, "same basename, different full paths must not collide");
    }

    #[test]
    fn join_key_full_path_matches_identical_path_case_insensitive() {
        let a = join_key(r"C:\Windows\System32\evil.exe");
        let b = join_key(r"c:\windows\system32\EVIL.EXE");
        assert_eq!(a, b, "identical path differing only by case must match");
    }

    #[test]
    fn join_key_name_only_source_degrades_to_basename_match() {
        // prefetch-style source: bare filename, no directory component.
        let prefetch_side = join_key("NOTEPAD.EXE");
        let live_side = join_key(r"C:\Windows\System32\notepad.exe");
        // Degraded match: both reduce to the same basename-level key.
        assert_eq!(
            prefetch_side.degraded_key(),
            live_side.degraded_key(),
            "basename-only source must still corroborate via degraded match"
        );
    }

    #[test]
    fn join_key_srum_id_fallback_is_name_only() {
        // srum's resolve_app_name falls back to "id:<n>" when unmapped — must be
        // treated as a Name key (no directory component), not misparsed as a path.
        let k = join_key("id:42");
        assert!(
            matches!(k, JoinKey::Name(_)),
            "id: fallback must be a Name key"
        );
    }
```

在 `crates/cairn-heur/src/score.rs` 的 `#[cfg(test)] mod tests` 內（第 203-206
行附近，`use super::*;` 之後、第一個既有測試 `suspicious_path_matches_each_dir_case_insensitively`
之前），插入這四個測試（逐字相同，直接複製上方內容）。

- [ ] **Step 3: 從 `persist.rs` 移除搬走的定義與測試**

用 Read 工具讀 `crates/cairn-heur/src/persist.rs` 第 200-256 行確認範圍，
把第 208-254 行（`JoinKey` enum 定義到 `strip_exe_suffix` 函式結尾，即
「跨文物比對鍵」doc comment 開始、到 `strip_exe_suffix` 函式的 `}` 結束）
整段刪除。

刪除後緊接著的是 `CrossIndex` 的 doc comment（原第 256 行「Index execution
+ process records...」），確認這段與其後的 `CrossIndex`/`build_cross_index`
維持不動。

在 `persist.rs` 檔案開頭新增 import（原本 `persist.rs` 內部定義
`JoinKey`/`join_key` 時不需要 import 自己，搬走後才需要）：

修改 `crates/cairn-heur/src/persist.rs` 第 4-13 行的 `use` 區塊，在
`use crate::trust::{...}` 這行附近新增一行：

```rust
use crate::score::{join_key, JoinKey};
```

用 Read 工具讀 `crates/cairn-heur/src/persist.rs` 第 1099-1137 行（此時
行號可能因為 Step 3 前半刪除了 46 行而整體往前偏移約 46 行，用搜尋
`join_key_full_path_requires_path_match_not_just_basename` 字串定位實際
位置），把這四個測試函式整段刪除（已經搬到 `score.rs`，不能兩邊都留，
否則測試名稱重複會編譯錯誤或造成混淆）。

- [ ] **Step 4: 執行測試確認搬遷正確**

Run: `cargo test -p cairn-heur`
Expected: 全部通過，測試總數與段 10 合併後的基準相同（純搬遷，不增不減——
4 個測試從 persist.rs 的計數移到 score.rs 的計數，總數不變）

- [ ] **Step 5: 執行 clippy 確認無警告**

Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`
Expected: 無警告（尤其注意 `persist.rs` 若有任何 unused import 警告，代表
Step 3 的 `use crate::score::{join_key, JoinKey};` 沒有被正確使用——不會
發生，因為 `persist.rs` 的 `CrossIndex`/`build_cross_index`/`analyze()`
內都還在用 `join_key`/`JoinKey`，只是定義位置換了）

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-heur/src/score.rs crates/cairn-heur/src/persist.rs
git commit -m "refactor(heur): move JoinKey/join_key from persist.rs to score.rs

Pure relocation to make this cross-artifact join-key utility available to
netconn.rs for segment 11's cross-analyzer corroboration. No behavior
change; CrossIndex/build_cross_index (persist-specific) stay in persist.rs.
4 existing join_key tests move with the code, no test count change."
```

---

## Task 2：`persist.rs` reason 加入來源標記（供 netconn 識別）

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs`（reason 組裝處，約在 Task 1
  完成後、原第 530 行 `f.reason = Some(reasons.join("; "));` 附近，實際
  行號因 Task 1 刪除 46+ 行測試與定義而整體偏移，用搜尋
  `f.reason = Some(reasons.join` 字串定位）

**動機**：`Finding` 型別沒有「來源 analyzer」欄位，netconn 要在 `prior_findings`
裡識別「哪些 Finding 來自 heur_persist」，唯一的辦法是在 reason 字串裡放一個
可辨識的標記（spec 第三節「來源追溯的技術限制」已說明這個技術取捨）。

- [ ] **Step 1: 寫失敗測試 — persist Finding 的 reason 含來源標記**

用 Read 工具讀 `crates/cairn-heur/src/persist.rs` 的 `#[cfg(test)] mod tests`
區塊，找到既有測試 `analyzer_emits_finding_for_malicious_only`（測試名稱
搜尋確認，這是驗證 persist 基本 finding 產出的既有測試），在它附近新增：

```rust
    /// Every persist Finding's reason carries a "source: heur_persist" marker so
    /// other analyzers (netconn, segment 11) can identify persist-originated
    /// findings in prior_findings without a dedicated source-analyzer field on
    /// Finding (see spec's "來源追溯的技術限制" for the tradeoff rationale).
    #[test]
    fn finding_reason_carries_source_marker_for_cross_analyzer_lookup() {
        let now = Utc::now();
        let bad = Record::Persistence(rec(
            "ifeo",
            Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"),
            Some(now),
        ));
        let findings = PersistHeuristic.analyze(&[bad], &[]).expect("analyze");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("source: heur_persist")),
            "reason must carry the source marker: {:?}",
            findings[0].reason
        );
    }
```

**注意**：呼叫 `PersistHeuristic.analyze(&[bad], &[])` 時第二個引數是
`&[]`（空的 `prior_findings`，因為段 10 已把 `analyze()` 簽名改成三參數）
——若既有測試呼叫點沒有這個第二引數會編譯失敗，這代表你正在對照的是段
10 合併後的現況，不是段 10 之前的舊簽名。

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-heur finding_reason_carries_source_marker_for_cross_analyzer_lookup`
Expected: FAIL（`reason` 字串裡目前沒有 `"source: heur_persist"` 字樣）

- [ ] **Step 3: 實作 — reason 組裝時加入來源標記**

用 Read 工具讀 `crates/cairn-heur/src/persist.rs` 找到
`f.reason = Some(reasons.join("; "));` 這一行（Task 1 完成後的行號，用
字串搜尋定位，原第 530 行附近，Task 1 刪除了約 46 行後大致落在第 484 行
附近，但務必用 Read 確認實際行號不要憑空假設），**在這行之前**插入一行：

```rust
            reasons.push("source: heur_persist".to_string());
```

修改後這段程式碼的順序會是（示意，實際上下文以 Read 工具讀到的為準）：

```rust
            // ...既有的 reasons.push(...) 邏輯（S1-S9 訊號、跨文物佐證訊號等）都在這之前...
            reasons.push("source: heur_persist".to_string());
            let top = hits
                .iter()
                .max_by_key(|h| sev_rank(h.severity))
                .unwrap_or(&hits[0]);
            // ...
            f.reason = Some(reasons.join("; "));
```

**插入位置的精確要求**：必須在 `reasons.join("; ")` 呼叫**之前**、且在
所有其他 `reasons.push(...)` 呼叫**之後**（確保標記出現在 reason 字串
最後，不影響既有測試裡對 reason 開頭部分做 `.contains()` 比對的斷言）。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-heur`
Expected: 全部通過，含新增的 1 個測試，且既有測試無回歸（因為新增的標記
只是 append 在 reasons 陣列尾端，既有的 `.contains()` 斷言不受影響——
本 task 不需要修改任何既有測試斷言，這點在 spec 撰寫時已用
`grep -n "f\.reason\s*=="` 查證過 persist.rs 沒有任何嚴格相等比對）

- [ ] **Step 5: 執行 clippy 確認無警告**

Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "feat(heur): persist Finding.reason carries a source marker

Adds 'source: heur_persist' to the end of every persist Finding's reason
string, enabling netconn (segment 11) to identify persist-originated
findings in prior_findings without a dedicated source-analyzer field on
Finding. Appended last so it doesn't disturb any existing reason-prefix
assertions."
```

---

## Task 3：netconn owner 身分獨立訊號（解決 443 埠偽裝漏偵測）

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs:16-73`（`score_conn` 函式）

- [ ] **Step 1: 寫失敗測試 — 未簽章+可疑路徑連 443 埠單獨過 gate**

用 Read 工具讀 `crates/cairn-heur/src/netconn.rs` 的 `#[cfg(test)] mod tests`
區塊（第 159 行之後），找到既有的 `conn`/`owner` 測試 helper 函式，在
`signed_browser_https_scores_below_floor` 測試附近新增：

```rust
    /// An unsigned process running from a suspicious path (Temp), connecting to a
    /// public IP on port 443 (common port — the real-world C2 disguise this segment
    /// fixes), must now score independently of port rarity: suspicious-path(30) +
    /// unsigned(20) as a single combined signal = 50, clearing the gate floor.
    #[test]
    fn unsigned_suspicious_path_owner_scores_independently_of_port_443() {
        let c = conn(
            "tcp",
            51000,
            Some("104.18.0.1"),
            Some(443), // common port — must NOT suppress this signal
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", Some(false));
        let s = score_conn(&c, Some(&o));
        assert!(
            s.weight >= NETCONN_GATE_FLOOR,
            "weight {} must clear the gate floor even on a common port",
            s.weight
        );
        assert!(s
            .reasons
            .iter()
            .any(|r| r.contains("unsigned") && r.contains("suspicious path")));

        let findings = NetConnHeuristic
            .analyze(&[Record::NetConn(c), Record::Process(o)], &[])
            .expect("analyze");
        assert!(
            !findings.is_empty(),
            "a 443-port C2 disguise with an unsigned+suspicious-path owner must be flagged"
        );
    }

    /// A signed, normal-path owner connecting on port 443 must still stay quiet —
    /// this proves the new independent signal doesn't fire on legitimate browsing
    /// (the regression case the existing signed_browser_https_scores_below_floor
    /// test already covers for the OLD signal set; this test re-confirms it holds
    /// for the NEW independent signal too).
    #[test]
    fn signed_normal_path_owner_on_443_still_scores_zero() {
        let c = conn(
            "tcp",
            51000,
            Some("104.18.0.1"),
            Some(443),
            Some("established"),
            Some(2),
        );
        let o = owner(r"C:\Program Files\browser\b.exe", Some(true));
        let s = score_conn(&c, Some(&o));
        assert_eq!(
            s.weight, 0,
            "signed, normal-path owner on a common port must score zero"
        );
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-heur unsigned_suspicious_path_owner_scores_independently_of_port_443`
Expected: FAIL（目前 `score_conn` 在冷門埠判斷（`rare`）沒觸發時，owner
訊號的放大器邏輯永遠不會走到，weight 停在 0）

- [ ] **Step 3: 實作 — 新增獨立訊號**

用 Read 工具讀 `crates/cairn-heur/src/netconn.rs` 第 39-71 行的
`if let Some(o) = owner { ... }` 區塊確認現況，在
`let mut owner_path_suspicious = false;` 這行之後（第 40 行之後）插入：

```rust
        // 獨立訊號（段 11）：owner 未簽章 + 執行於可疑路徑的組合本身就是強訊號
        // （比照 parentchild.rs 的 masquerade 設計哲學），不需要連線本身先觸發
        //任何訊號。真實世界 C2 最常見的偽裝手法正是用常見埠（443/80）混在
        // 正常流量裡——不能因為埠是常見埠就假設這是正常流量。權重 50 = 現有
        // 可疑路徑(30) + unsigned 放大器(20) 相加，沿用既有權重體系。這是
        // 新增的第二條命中路徑，與下方既有的「連線訊號觸發後 owner 訊號放大」
        // 邏輯並存，兩者可能同時命中（Score::add 用 saturating_add 疊加）。
        if is_suspicious_path(&o.image) && o.signed == Some(false) {
            s.add(
                50,
                format!(
                    "owning process is unsigned and runs from a suspicious path: {}",
                    o.image
                ),
                &["T1071"],
            );
        }
```

**注意**：這段新邏輯**不設定** `owner_path_suspicious` 旗標——那個旗標只
服務既有的「未簽章高埠監聽器」複合判斷（第 60-70 行），新訊號是獨立路徑，
不應該與那段邏輯互相影響。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-heur`
Expected: 全部通過，含新增的 2 個測試。**特別確認既有測試
`unsigned_owner_alone_does_not_amplify`（第 385-398 行附近）是否受影響**
——這個既有測試用的 owner 是 `r"C:\Windows\System32\svchost.exe"`（正常
路徑，非可疑路徑），所以新訊號的 `is_suspicious_path(&o.image)` 判斷會是
`false`，不會被新訊號觸發，這個既有測試應該維持原本的 `assert_eq!(s.weight, 0)`
不變。若這個測試失敗，代表新訊號的判斷條件寫錯了，需要重新檢查。

- [ ] **Step 5: 執行 clippy 確認無警告**

Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-heur/src/netconn.rs
git commit -m "feat(heur): netconn owner-identity signal fires independently of port rarity

Addresses segment-8/11 finding: an unsigned process in a suspicious path
(Temp/AppData/etc.) connecting on a COMMON port (443/80) previously scored
zero, because the owner-identity amplifiers only fired after a rare-port
signal. Real-world C2 most commonly disguises itself on port 443 — this
closes that detection gap. Weight 50 (existing suspicious-path 30 +
unsigned 20 combined), a new independent path alongside the existing
rare-port-triggered amplifier logic, which is untouched."
```

---

## Task 4：netconn ↔ persist 跨 analyzer 佐證

**Files:**
- Modify: `crates/cairn-heur/src/netconn.rs`（`NetConnHeuristic` 的
  `depends_on()` + `analyze()`）

此 task 依賴 Task 1（`join_key` 在 `score.rs` 且已是 `pub`）與 Task 2
（`persist.rs` 的 Finding.reason 含 `"source: heur_persist"` 標記）都已完成。

- [ ] **Step 1: 寫失敗測試 — `depends_on()` 回傳正確值**

用 Read 工具讀 `crates/cairn-heur/src/netconn.rs` 的 `impl Analyzer for
NetConnHeuristic` 區塊（第 78-81 行附近），在 `#[cfg(test)] mod tests`
內新增：

```rust
    #[test]
    fn depends_on_returns_heur_persist() {
        assert_eq!(NetConnHeuristic.depends_on(), &["heur_persist"]);
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-heur depends_on_returns_heur_persist`
Expected: FAIL（`NetConnHeuristic` 尚未實作 `depends_on()`，會使用 trait
的預設空陣列，斷言 `&["heur_persist"]` 不成立）

- [ ] **Step 3: 實作 `depends_on()`**

用 Read 工具讀 `crates/cairn-heur/src/netconn.rs` 第 78-81 行的
`impl Analyzer for NetConnHeuristic` 開頭部分，在 `fn name(&self) -> &str { "heur_netconn" }`
之後新增：

```rust
    fn depends_on(&self) -> &[&str] {
        &["heur_persist"]
    }
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-heur depends_on_returns_heur_persist`
Expected: PASS

- [ ] **Step 5: 寫失敗測試 — 跨 analyzer 佐證命中時 severity/reason 正確**

在 `#[cfg(test)] mod tests` 內新增（沿用既有的 `conn`/`owner` helper 函式）：

```rust
    /// A connection whose owner also appears in a prior_findings entry sourced from
    /// heur_persist (same image path) gets a +30 corroboration bonus, which can push
    /// a below-floor connection over the gate.
    #[test]
    fn netconn_corroborated_by_persist_finding_clears_gate() {
        // Connection alone: public+rare (25+20=45) — below the 50 gate floor.
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", None);
        let proc_rec = Record::Process(o);

        // A prior_findings entry from heur_persist, whose evidence includes the SAME
        // image path as the netconn owner.
        let mut persist_finding = Finding::new(
            cairn_core::Severity::High,
            "Persistence: evil.exe".into(),
            FindingSource::Heuristic,
        );
        persist_finding.reason = Some("some persist reason; source: heur_persist".into());
        persist_finding.evidence = vec![cairn_core::finding::EvidenceItem {
            artifact: "run_key".into(),
            path: Some(r"C:\Users\a\AppData\Local\Temp\evil.exe".into()),
            ts: None,
            detail: "".into(),
        }];

        let findings = NetConnHeuristic
            .analyze(&[Record::NetConn(c), proc_rec], &[persist_finding])
            .expect("analyze");
        assert_eq!(
            findings.len(),
            1,
            "45 (connection-only) + 30 (corroboration) = 75 must clear the gate floor"
        );
        assert!(
            findings[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("heur_persist")),
            "reason must mention the corroborating source: {:?}",
            findings[0].reason
        );
    }

    /// Without a matching prior_findings entry, the connection's score is unaffected
    /// (regression: corroboration logic must not fire spuriously).
    #[test]
    fn netconn_without_persist_corroboration_unaffected() {
        let c = conn(
            "tcp",
            50000,
            Some("104.18.0.1"),
            Some(4444),
            Some("established"),
            Some(1),
        );
        let o = owner(r"C:\Users\a\AppData\Local\Temp\evil.exe", None);
        let proc_rec = Record::Process(o);

        let findings = NetConnHeuristic
            .analyze(&[Record::NetConn(c), proc_rec], &[])
            .expect("analyze");
        assert!(
            findings.is_empty(),
            "45 (connection-only, no corroboration) must stay below the gate floor"
        );
    }
```

- [ ] **Step 6: 執行測試確認失敗**

Run: `cargo test -p cairn-heur netconn_corroborated_by_persist_finding_clears_gate`
Expected: FAIL（`analyze()` 目前完全忽略 `prior_findings` 參數，佐證邏輯
還沒實作，第一個測試的連線分數停在 45，過不了 gate floor）

- [ ] **Step 7: 實作跨 analyzer 佐證邏輯**

用 Read 工具讀 `crates/cairn-heur/src/netconn.rs` 的 `analyze()` 方法完整
內容（Task 3 完成後的現況），確認 `score_conn(c, owner)` 呼叫的位置（原
第 103 行附近）。在 `let score = score_conn(c, owner);` 這行**之後**、
`if score.weight < NETCONN_GATE_FLOOR { continue; }` 這行**之前**，插入
佐證邏輯：

```rust
            let mut score = score_conn(c, owner);
            // 跨 analyzer 佐證（段 11）：owner 若同時是 heur_persist 判定為落地
            // 持久化的程式，這是強烈的獨立佐證（不同資料來源、不同 analyzer
            // 各自判斷出同一個結論）。+30，與 persist.rs 內部同級跨文物佐證
            // 權重一致（那邊是直接 escalate() 一個 severity 級，這裡是分數制，
            // +30 大致對應 High(50..=69) 到 Critical(70..) 這個常見躍遷）。
            if let Some(o) = owner {
                let owner_key = join_key(&o.image);
                let corroborated = prior_findings.iter().any(|f| {
                    f.reason
                        .as_deref()
                        .is_some_and(|r| r.contains("heur_persist"))
                        && f.evidence.iter().filter_map(|e| e.path.as_deref()).any(|p| {
                            let ev_key = join_key(p);
                            ev_key == owner_key || ev_key.degraded_key() == owner_key.degraded_key()
                        })
                });
                if corroborated {
                    score.add(
                        30,
                        format!(
                            "owning process {} also has a persistence finding (source: heur_persist)",
                            o.image
                        ),
                        &["T1547"],
                    );
                }
            }
```

**重要**：原本的 `let score = score_conn(c, owner);` 要改成
`let mut score = score_conn(c, owner);`（因為 `score.add(...)` 需要可變
借用）——用 Read 工具確認這行原本是不可變綁定，修改時務必加上 `mut`。

在檔案頂端的 `use` 區塊（第 3-8 行）新增 `join_key` 的 import：

```rust
use crate::score::{is_public_ipv4, is_rare_port, is_suspicious_path, join_key, severity_for, Score};
```

（原本第 3 行是 `use crate::score::{is_public_ipv4, is_rare_port, is_suspicious_path, severity_for, Score};`，
只需要在清單中插入 `join_key`。）

- [ ] **Step 8: 執行測試確認通過**

Run: `cargo test -p cairn-heur`
Expected: 全部通過，含 Task 3、Task 4 新增的全部測試，且既有測試無回歸

- [ ] **Step 9: 執行 clippy 確認無警告**

Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 10: Commit**

```bash
git add crates/cairn-heur/src/netconn.rs
git commit -m "feat(heur): netconn corroborates with persist findings via prior_findings

NetConnHeuristic now declares depends_on() = [\"heur_persist\"], so segment
10's dependency-ordering plumbing guarantees persist runs first. When a
connection's owner image matches (path-aware, via score::join_key) the
evidence path of a prior_findings entry sourced from heur_persist
(identified via the 'source: heur_persist' reason marker), netconn adds
+30 — a below-floor connection with independent corroboration can now
clear the gate."
```

---

## Task 5：跨 crate 整合驗證（controller 執行，非獨立 subagent task）

此 task 不派 subagent——這是 finishing-a-development-branch 前，controller
親自確認四個改動（跨越 `score.rs`/`persist.rs`/`netconn.rs` 三個檔案、涉及
段 10 剛建的依賴管道實際被使用）沒有互相干擾的最後一關。

- [ ] **Step 1: 全 workspace 建置與測試**

Run: `cargo check --workspace && cargo test --workspace --exclude cairn-updater`

Expected: 全部通過（`cairn-updater` 需要提權，照專案慣例排除）

- [ ] **Step 2: 全 workspace clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

Expected: 無警告、fmt 乾淨

- [ ] **Step 3: 確認 main.rs 的 analyzer 建構順序不受影響（依賴排序是 orchestrator 內部處理，main.rs 陣列順序不需要調整）**

Run: `grep -n "Box::new(cairn_heur::NetConnHeuristic)\|Box::new(cairn_heur::PersistHeuristic)" crates/cairn-cli/src/main.rs`

確認 `cairn-cli/src/main.rs` 裡 `NetConnHeuristic`/`PersistHeuristic` 的
建構語法本身不需要修改（拓撲排序在 `orchestrator::run_live` 內部處理，
`main.rs` 陣列裡的順序只是「注入順序」，不代表「執行順序」，這是段 10
已經解決的問題，本段不需要改動 `main.rs`）。

- [ ] **Step 4: 真機/合成驗證（依 spec 驗收條件，合成整合測試已足夠覆蓋，不需要真機 e2e）**

Task 4 的 `netconn_corroborated_by_persist_finding_clears_gate` 測試已經是
合成整合測試（構造 `prior_findings` 模擬 persist 的輸出，餵進
`NetConnHeuristic.analyze()`），涵蓋了跨 analyzer 佐證的端到端行為。不需要
額外的真機驗證步驟——這是純邏輯層面的互動，合成測試已完整覆蓋（spec 驗收
條件明確這樣要求）。

---

## Self-Review 完成度檢查

**Spec coverage：**
- 第一節（`JoinKey` 搬遷，明確排除 `CrossIndex`）→ Task 1 ✓
- 第二節（netconn owner 身分獨立訊號，權重 50，插入位置說明）→ Task 3 ✓
- 第三節（跨 analyzer 佐證，`depends_on()`、來源追溯技術限制、+30 佐證）→
  Task 2（reason 標記）+ Task 4（依賴宣告 + 佐證邏輯）✓
- 第四節（測試策略總覽表）→ 每個 Task 的測試步驟逐一對應 ✓
- 「明確不做的事」（不加 source_analyzer 欄位、不做 beaconing、不搬
  CrossIndex、不改 COMMON_PORTS、其餘 analyzer 不宣告依賴）→ 本 plan 全程
  遵守，Task 1 明確排除 CrossIndex，Task 4 只動 netconn.rs 一個 analyzer
  的 depends_on() ✓
- 驗收條件全部八項 → Task 5 涵蓋前四項（測試/clippy/fmt/全量）；
  「443 埠現在會產生 finding」「已簽章仍不產生」由 Task 3 的兩個測試涵蓋；
  「netconn 佐證 persist 實際運作」由 Task 4 的合成測試涵蓋；
  「零 schema/CLI/collector 變動」由本 plan 範圍本身保證

**Placeholder scan：** 無 TBD/TODO；每個 Step 都有完整可執行的程式碼與
確切指令。多處明確標註「行號因前面 Task 刪除/新增行數而偏移，用字串搜尋
定位，不要憑空假設」——這不是模糊指示，是誠實揭露 Rust 檔案在連續多個
task 修改後行號會漂移的事實，並給出具體的搜尋字串定位方式。

**Type consistency：** `JoinKey`/`join_key`/`degraded_key` 在 Task 1 定義
於 `score.rs`（`pub enum`/`pub fn`/`pub fn`），Task 4 的
`netconn.rs::analyze()` 呼叫 `join_key(&o.image)` 與 `join_key(p)`、
`.degraded_key()`，型別與可見性完全對應。`Finding.evidence: Vec<EvidenceItem>`、
`EvidenceItem.path: Option<String>` 在 Task 4 Step 5 的測試裡正確建構
（`cairn_core::finding::EvidenceItem { artifact, path, ts, detail }` 四欄位
與 `crates/cairn-core/src/finding.rs` 定義一致）。`NetConnHeuristic::depends_on()`
在 Task 4 Step 3 定義回傳 `&["heur_persist"]`，與 Task 4 Step 1 測試的
`assert_eq!(NetConnHeuristic.depends_on(), &["heur_persist"])` 一致。
`score_conn` 回傳型別 `Score`（含 `weight`/`reasons`/`mitre`），Task 4 Step 7
的 `let mut score = score_conn(c, owner);` 與後續 `score.add(...)` 呼叫符合
`Score::add(&mut self, weight: u32, reason: impl Into<String>, mitre: &[&str])`
簽名（`score.rs` 第 178 行）。
