# C2 偵測強化：netconn 獨立訊號 + netconn↔persist 跨 analyzer 佐證 — 設計規格（段 11）

- 日期：2026-07-11
- 狀態：已審（brainstorm 逐項技術決策定案）
- 基準 commit：main HEAD `2243633`（段 10 已合併：`Analyzer::depends_on()` +
  `analyze()` 的 `prior_findings` 參數 + orchestrator 拓撲排序）
- 動機來源：C2 偵測能力盤點（見對話記錄）——確認現有 `heur_netconn` 對
  443/80 等常見埠的連線完全不評分（`is_rare_port` 排除），即使 owner 未簽章
  且執行於可疑路徑，這代表用常見埠偽裝的 C2（真實世界最常見手法）被系統性
  漏掉。本段用段 10 剛建好的依賴管道，讓 netconn 額外參考 persist 的判定
  結果做跨文物佐證。

## 動機

`crates/cairn-heur/src/netconn.rs::score_conn` 目前的訊號模型：「owner 未
簽章」與「owner 可疑路徑」都是**放大器**——必須先有連線本身的訊號（公網 IP
+ 冷門埠）觸發，才會疊加。這代表一支未簽章、跑在 `%TEMP%` 的程式，連到
443 埠的公網 IP（真實 C2 最常見的偽裝手法：混在正常 HTTPS 流量裡），**目前
完全不會被標記**，因為連線本身的訊號（`is_rare_port(443) == false`）從一
開始就沒觸發，後面的放大器邏輯永遠不會被走到。

同時，`heur_netconn` 與 `heur_persist` 是兩個完全獨立的 analyzer，彼此看
不到對方的判定結果——一個可疑連線的 owner，如果同時在 `heur_persist` 找到
對應的持久化落地機制（例如同一支程式被登記在開機啟動項），這是很強的
佐證訊號，但現有架構下這兩者無法互相參考。段 10 剛建好
`Analyzer::depends_on()` + `prior_findings` 管道，本段是第一個實際使用
這個管道的消費者。

---

## 一、`JoinKey` 從 `persist.rs` 搬到 `score.rs`（共用基礎設施）

### 範圍

`crates/cairn-heur/src/persist.rs` 第 208-254 行的四項：

```rust
enum JoinKey { Path(String), Name(String) }
impl JoinKey { fn degraded_key(&self) -> String { ... } }
fn join_key(raw: &str) -> JoinKey { ... }
fn basename_from_normalized(path: &str) -> String { ... }
fn strip_exe_suffix(s: &str) -> String { ... }
```

**明確不搬**：`CrossIndex`（第 264-302 行）與 `build_cross_index`
（第 304-338 行）——這兩者是 `persist.rs` 專用的、針對
`ExecutionRecord`/`ProcessRecord` 建索引的結構，netconn 不需要整套索引，
只需要 `JoinKey`/`join_key` 本身去比對字串路徑（見下方第三節）。搬過頭
（連 `CrossIndex` 一起搬）會引入 netconn 用不到的複雜度，違反 YAGNI。

### 做法

搬到 `crates/cairn-heur/src/score.rs`，四項全部改成 `pub`（`JoinKey` 的
`Path`/`Name` variant 保持 `pub`，因為呼叫端需要 match 或建構它）。
`persist.rs` 改成 `use crate::score::{join_key, JoinKey}`（`persist.rs`
內部只用到 `join_key`/`JoinKey`/`degraded_key`，`basename_from_normalized`/
`strip_exe_suffix` 是 `join_key`/`degraded_key` 的內部依賴，維持 private
於 `score.rs`，不需要對外公開）。

**行為零變化**——純位置搬遷。原本 `persist.rs` 內測試 `JoinKey`/`join_key`
行為的既有測試（4 個，`join_key_full_path_requires_path_match_not_just_basename`
等，段 9 建立）一併搬到 `score.rs` 的 `#[cfg(test)] mod tests`。

### 驗證

`cargo test -p cairn-heur` 全部通過，測試總數不變（純搬遷，只是測試從
`persist.rs` 的 `mod tests` 移到 `score.rs` 的 `mod tests`，不增不減）。

---

## 二、netconn owner 身分訊號獨立成立（解決 443 偽裝漏偵測）

### 範圍

`crates/cairn-heur/src/netconn.rs::score_conn`（第 16-73 行）。

### 設計

新增一個**不依賴連線本身訊號**的獨立訊號：

```rust
// 獨立訊號（不需要連線本身先觸發）：owner 未簽章 + 執行於可疑路徑的組合本身
// 就是強訊號（比照 parentchild.rs 的 masquerade 設計哲學）——不能因為連線埠
// 是常見埠（443/80）就假設這是正常流量。真實世界 C2 最常見的偽裝手法正是
// 用常見埠混在正常 HTTPS/HTTP 流量裡。權重 50 = 現有可疑路徑(30) + unsigned
// 放大器(20) 相加，沿用既有權重體系，不新增魔術數字。
if let Some(o) = owner {
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
}
```

**與既有邏輯的關係**：這是**新增的第二條命中路徑**，不是取代。原本「連線
訊號觸發 → owner 訊號放大」的路徑（第 39-70 行既有邏輯）完全保留不動。新
訊號與既有訊號可能同時觸發（例如未簽章可疑路徑的程式連到冷門埠的公網
IP）——`Score::add` 本身用 `saturating_add` 累加，兩條路徑同時命中時分數
會疊加，不會互斥判斷，這是既有 `Score` 機制的既有行為，本段不需要新增
互斥邏輯。

**插入位置**：這段新邏輯放在 `score_conn` 現有的 `if let Some(o) = owner`
區塊內（第 39-70 行），作為該區塊內第一個判斷（在既有的
`is_suspicious_path` 放大器判斷之前或之後皆可，兩者是獨立的 if 陳述式，
不影響彼此）。實作時緊接在 `let mut owner_path_suspicious = false;` 之後
插入，讓新訊號與既有的 `owner_path_suspicious` 標記邏輯不互相干擾（新訊號
不設定 `owner_path_suspicious`，那個旗標只服務既有的高埠監聽器複合判斷）。

### MITRE ATT&CK 標籤

用 `T1071`（Application Layer Protocol，C2 通訊協定濫用的標準分類），比
現有訊號沒有標任何 MITRE tag（第 25-32、35-37 行的 `&[]`）更精確——這個
新訊號的判斷依據本質就是「疑似 C2 通訊」，值得標註。

### 驗證

新增測試（詳見第四節）確認：(a) 未簽章+可疑路徑的程式連 443 埠公網 IP，
單獨觸發並過 gate floor；(b) 已簽章正常路徑的程式連 443 埠，仍不觸發任何
訊號（確認沒有破壞既有的「正常瀏覽器流量保持安靜」行為）。

---

## 三、netconn ↔ persist 跨 analyzer 佐證

### 範圍

`crates/cairn-heur/src/netconn.rs`：`NetConnHeuristic` 的 `depends_on()`
實作 + `analyze()` 內部邏輯擴充。

### 設計

**依賴宣告**：

```rust
impl Analyzer for NetConnHeuristic {
    fn name(&self) -> &str {
        "heur_netconn"
    }
    fn depends_on(&self) -> &[&str] {
        &["heur_persist"]
    }
    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>> {
        // ...
    }
}
```

**佐證邏輯**：在 `analyze()` 內，對每個已經確定要產生 finding 的連線（即
`score.weight >= NETCONN_GATE_FLOOR` 判斷之後、组 `Finding` 之前），若該
連線有已知 owner，用 `join_key(&owner.image)` 與 `prior_findings` 中每個
`source == FindingSource::Heuristic` 且能追溯自 `heur_persist`（見下方
「來源追溯」的技術限制）的 Finding 的 `evidence` 逐一比對：

```rust
// 跨 analyzer 佐證（段 11）：owner 若同時是 heur_persist 判定為落地持久化的
// 程式，這是強烈的獨立佐證（不同資料來源、不同 analyzer 各自判斷出同一個
// 結論）。command +30，與 persist.rs 內部的同級跨文物佐證權重一致
// （persist.rs 的 execution/process 佐證是直接 escalate() 一個 severity
// 級，這裡用固定分數是因為 netconn 是分數制而非級別制，+30 大致對應
// High(50..=69) 到 Critical(70..) 這個常見的躍遷）。
if let Some(o) = owner {
    let owner_key = join_key(&o.image);
    let corroborated = prior_findings.iter().any(|f| {
        f.reason
            .as_deref()
            .is_some_and(|r| r.contains("heur_persist"))
            && f.evidence
                .iter()
                .filter_map(|e| e.path.as_deref())
                .any(|p| join_key(p) == owner_key || join_key(p).degraded_key() == owner_key.degraded_key())
    });
    if corroborated {
        s.add(
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

**來源追溯的技術限制（重要，實作時必須遵守）**：`Finding` 型別本身沒有
「這是哪個 analyzer 產生的」欄位——`FindingSource` 只有 `Heuristic`/
`Sigma` 兩種粗粒度分類，不到 analyzer 名稱的細粒度。要判斷一個
`prior_findings` 裡的項目是否來自 `heur_persist`，本段用「`Finding.reason`
字串裡是否含有 `"heur_persist"` 字樣」這個 hack 來識別——**這需要
`persist.rs` 的 Finding reason 組字串時明確帶上 `"heur_persist"`
這個標記**（目前 `persist.rs` 的 reason 不含這個字串，需要在 persist.rs
的 finding 組裝處加上，例如在 `reasons.push` 的某處加一句
`"source: heur_persist"` 或等效字樣）。這是本段唯一需要同時修改
`persist.rs` 的地方（一行新增，不影響 persist.rs 既有測試斷言，除非那些
斷言對 reason 全文做嚴格相等比對——若有，需要一併更新）。

**設計取捨說明**：更乾淨的做法是給 `Finding` 加一個
`source_analyzer: Option<String>` 欄位，但那是 schema 變動，會牽動
`cairn-report`（HTML/CSV 輸出）與序列化相容性，對本段「單一依賴對」的
範圍不成比例（呼應段 10 spec 的同款判斷）。若未來有第二、第三個跨
analyzer 佐證消費者出現，屆時應該把這個字串 hack 升級成正式欄位——本段
先用最小成本的方式驗證這個模式是否有價值。

**佐證命中的位置**：這段邏輯插入在 `analyze()` 現有的迴圈內、
`score_conn(c, owner)` 呼叫之後、`if score.weight < NETCONN_GATE_FLOOR`
判斷之前——讓佐證分數也能影響是否過 gate floor（一個原本 45 分沒過 gate
的連線，若佐證命中 +30，會變成 75 分過 gate）。

### 驗證

新增測試（詳見第四節）確認：(a) `depends_on()` 回傳 `&["heur_persist"]`；
(b) owner 在 prior_findings 有對應 persist finding 時，severity 提升且
reason 含佐證說明；(c) owner 沒有對應 persist finding 時，不受影響
（維持原本分數）；(d) 降級比對（僅檔名）也能佐證命中，但沿用
`join_key`/`degraded_key` 既有的降級語意，不特別區分佐證是否為降級命中
（YAGNI：這個區分在 persist.rs 內部佐證有意義，是因為那邊要決定 reason
文字要不要加註「降級佐證」；netconn 這邊佐證只是加分，不需要在 reason
文字上做這個區分，除非未來發現需要）。

---

## 四、測試策略總覽

| 檔案 | 新增/搬遷測試 |
|---|---|
| `score.rs` | 段 9 建立的 4 個 `JoinKey`/`join_key` 測試從 `persist.rs` 搬過來，原樣通過 |
| `netconn.rs` | (a) 未簽章+可疑路徑連 443 埠單獨過 gate；(b) 已簽章正常路徑連 443 埠仍不觸發；(c) `depends_on()` 回傳正確值；(d) 跨 analyzer 佐證命中時 severity/reason 正確；(e) 無佐證時行為不變（回歸測試，確認新邏輯不影響既有路徑） |
| `persist.rs` | 若既有測試對 reason 全文做嚴格比對，因新增 `"heur_persist"` 標記字串而失敗的測試，逐一更新斷言（純文字調整，不改變測試意圖） |

---

## 明確不做的事（YAGNI，避免範圍蔓延）

- **不**新增 `Finding.source_analyzer` 正式欄位（用 reason 字串 hack 識別
  來源，見第三節設計取捨說明）。
- **不**做 beaconing（週期性心跳）偵測——那需要 `NetConnRecord` 新增時間
  戳/連線頻率欄位，是獨立的段（背景討論中已識別，不在本段範圍）。
- **不**搬遷 `CrossIndex`/`build_cross_index`——那是 persist 專用的索引，
  netconn 不需要。
- **不**修改 `is_rare_port`/`COMMON_PORTS` 的定義本身——常見埠清單維持
  不變，本段是新增一條不依賴埠稀有度的獨立命中路徑，不是修改埠判定邏輯。
- **不**讓其餘既有五個 analyzer（parentchild/account/timestomp/byovd/
  sigma）宣告任何依賴——本段只動 `netconn.rs`（依賴宣告）與 `persist.rs`
  （加一行 reason 標記），其餘 analyzer 不受影響。

## 驗收條件

- [ ] `cargo test -p cairn-heur` 全部通過，含新增/搬遷的測試
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` 無警告
- [ ] `cargo fmt --check` 通過
- [ ] 全 workspace `cargo test --workspace --exclude cairn-updater` 無回歸
- [ ] 未簽章+可疑路徑的程式連 443 埠公網 IP，現在會產生 finding（此前不會）
- [ ] 已簽章正常路徑連 443 埠，仍不產生 finding（既有行為未被破壞）
- [ ] netconn 佐證 persist 的機制實際運作（用合成整合測試驗證，不需要真機
      e2e——這是純邏輯層面的跨 analyzer 互動，合成測試即可完整覆蓋）
- [ ] 零 schema 變動、零 CLI 變動、零 collector 邏輯變動
