# Analyzer 依賴宣告基礎設施 — 設計規格（段 10）

- 日期：2026-07-11
- 狀態：已審（brainstorm 逐項技術決策定案）
- 基準 commit：main HEAD（段 9 已合併，`9c9ec98` 之後）
- 動機來源：C2 偵測能力盤點（見對話記錄）——netconn 想在評分時參考 persist 的
  判定結果做跨 analyzer 佐證，但現有 `Analyzer` trait 沒有管道讓一個 analyzer
  看到另一個 analyzer 的輸出。本段只建管道，**不實作任何具體的跨 analyzer
  偵測邏輯**（netconn 佐證 persist 是段 11，不在本段範圍）。

## 動機

`cairn-core::orchestrator::run_live` 目前對七個 `Analyzer` 實作
（parentchild/persist/netconn/account/timestomp/byovd/sigma，逐一確認於
`crates/cairn-heur/src/*.rs` 與 `crates/cairn-heur/src/sigma.rs`）完全平行呼叫：

```rust
for a in analyzers {
    match a.analyze(&records) {
        Ok(mut fs) => findings.append(&mut fs),
        Err(e) => tracing::warn!(...),
    }
}
```

`analyze(&self, records: &[Record])` 只吃原始 Record，不吃任何其他 analyzer
已經產出的 Finding。要讓 analyzer 之間能互相參考彼此的判定結果（例如段 11
要做的「netconn 佐證 persist」），必須先解決兩個問題：(a) 讓後執行的
analyzer 能拿到先執行的 analyzer 的 Finding；(b) 讓「誰先誰後」變成可宣告、
可驗證的關係，而不是 `main.rs` 裡陣列元素順序這種隱含約定。

---

## 設計

### 1. `Analyzer` trait 擴充

修改 `crates/cairn-core/src/traits.rs`：

```rust
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;

    /// `prior_findings` 是本次 run 中，依 `depends_on()` 排序後、已經跑完的
    /// analyzer 的 Finding 累加結果（不含尚未執行的 analyzer）。未宣告依賴的
    /// analyzer 會收到目前為止累加的全部 Finding（不只是自己依賴的那幾個）——
    /// 這是刻意的簡化：過濾成「只給宣告依賴的那幾個 analyzer 的 Finding」需要
    /// 額外追蹤每個 Finding 的來源 analyzer 並在傳遞前做過濾，增加的複雜度對
    /// 目前唯一的消費場景（段 11 單一依賴對）不成比例；未依賴的 analyzer 本來
    /// 就不會去讀 `prior_findings`，多傳的內容是死代碼路徑，不影響行為。
    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>>;

    fn observe(&self, _records: &[Record]) -> Result<Vec<Observation>> { Ok(vec![]) }

    /// 依賴的其他 analyzer 名稱清單（對應各自 `name()` 的回傳值）。orchestrator
    /// 保證這些 analyzer 在自己之前執行完畢。預設空陣列（無依賴）。
    fn depends_on(&self) -> &[&str] { &[] }
}
```

**`observe()` 不擴充參數**——它產生的是「未過 gate 的庫存」（Observation），
不是 Finding，段 11 的佐證需求只針對 Finding 層級，`observe()` 維持現況。

### 2. Orchestrator 拓撲排序

修改 `crates/cairn-core/src/orchestrator.rs` 的 analyzer 執行段：

1. 依 `analyzers` 陣列建依賴圖：每個 analyzer 的 `depends_on()` 回傳的名稱，
   對照其餘 analyzer 的 `name()` 找出對應節點（名稱在陣列中找不到視為無此
   依賴，不視為錯誤——允許宣告一個「將來才會加入」的依賴而不立即崩潰，
   保守選擇：忽略找不到的依賴名稱，不阻擋執行）。
2. **穩定拓撲排序**：以 `analyzers` 陣列的原始索引為 tie-break，保證同一份
   輸入永遠得到同一個執行順序（呼應 CLAUDE.md「Determinism」慣例）。實作
   方式——Kahn's algorithm，入度為零的節點按「原始索引」由小到大的順序
   加入處理佇列，而非用 `HashSet`/`HashMap` 迭代順序（那是非決定性的）。
3. **循環依賴**：排序完成後若仍有節點入度非零（代表存在環），`panic!`
   並在訊息中列出涉及環的 analyzer 名稱。這是開發期配置錯誤（依賴關係是
   編譯時就寫死的靜態資料，不是執行時輸入），不透過 `Result` 傳遞——與
   `Config::default()` 這類「寫錯就是寫錯」的既有慣例一致，不套用
   golden rule 8 的 graceful-degrade（那是給執行環境的不確定性用的，不是
   給程式碼本身的邏輯錯誤用的）。
4. 依排序後的順序執行，每個 analyzer 跑完後把它的 Finding 累加進
   `prior_findings`，傳給下一個。

```rust
let order = topo_sort(analyzers); // Vec<usize>，analyzers 的索引，已排序
let mut findings = Vec::new();
for &idx in &order {
    let a = &analyzers[idx];
    match a.analyze(&records, &findings) {
        Ok(mut fs) => findings.append(&mut fs),
        Err(e) => tracing::warn!(analyzer = a.name(), error = %e, "analyzer failed; skipping"),
    }
}
```

`topo_sort` 是新的私有函式，簽名大略為
`fn topo_sort(analyzers: &[Box<dyn Analyzer>]) -> Vec<usize>`，內部用
`name()`/`depends_on()` 建圖、跑 Kahn's algorithm、偵測環後 panic。

### 3. 既有七個 Analyzer 實作的簽名遷移

`parentchild.rs`/`persist.rs`/`netconn.rs`/`account.rs`/`timestomp.rs`/
`byovd.rs`/`sigma.rs`：每個檔案的 `fn analyze(&self, records: &[Record])`
改成 `fn analyze(&self, records: &[Record], _prior_findings: &[Finding])`
（底線前綴：本段不使用這個參數，只是接受新簽名；`use` 語句需要新增
`cairn_core::Finding` 若該檔案尚未 import）。**邏輯一律不變**——這是純簽名
遷移，不是行為修改。`depends_on()` 全部沿用 trait 預設（空陣列），不寫。

### 4. 測試策略

`crates/cairn-core/src/orchestrator.rs` 的 `#[cfg(test)]` 區塊：

1. 擴充既有 `FakeAnalyzer`：`analyze` 簽名加 `prior_findings` 參數；新增
   `FakeAnalyzer::with_deps(name, deps: &[&str], findings)` 建構子讓測試能
   宣告依賴。
2. 新測試涵蓋：
   - 依賴關係被遵守：B 依賴 A 時，B 收到的 `prior_findings` 包含 A 的
     Finding（用一個會把 `prior_findings.len()` 記錄下來的 `FakeAnalyzer`
     變體驗證，或直接讓 B 的 fake 邏輯回傳「看到了幾筆」當作它自己的
     Finding 內容來斷言）。
   - 無依賴關係時保持注入順序穩定（多次呼叫 `topo_sort` 同一份輸入，
     斷言回傳的索引序列每次相同）。
   - 循環依賴（A 依賴 B、B 依賴 A）呼叫 `run_live` 會 panic——用
     `#[should_panic]` 測試，panic 訊息包含兩個 analyzer 的名稱。
   - 宣告依賴一個不存在的 analyzer 名稱：不 panic，正常執行（驗證第 2
     節第 1 點的保守選擇）。
3. 既有兩個測試（`analyzers_findings_are_collected`、
   `failing_analyzer_is_skipped_run_continues`）行為不變，只需要把
   `FakeAnalyzer` 呼叫端跟著新簽名調整（若建構子介面因為新增
   `prior_findings` 欄位而變動）。

---

## 明確不做的事（YAGNI，避免範圍蔓延）

- **不**實作任何具體的跨 analyzer 偵測邏輯（netconn 佐證 persist 是段 11）。
- **不**改 `observe()` 的簽名或依賴排序（Observation 不參與這套機制）。
- **不**做「只給宣告依賴的那幾個 analyzer 過濾後的 Finding」——見第 1 節的
  簡化理由。
- **不**支援依賴的動態/執行期變化——`depends_on()` 是純函式，回傳值假設
  在同一個 binary 版本內是常數。
- **不**改變任何 collector 邏輯、schema、CLI 介面。

## 驗收條件

- [ ] `cargo test -p cairn-core` 全部通過，含新增的依賴排序測試
- [ ] `cargo test -p cairn-heur` 全部通過（七個 analyzer 簽名遷移後行為不變）
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` 無警告
- [ ] `cargo fmt --check` 通過
- [ ] 全 workspace `cargo test --workspace --exclude cairn-updater` 無回歸
- [ ] 循環依賴確實 panic 且訊息可讀；無依賴時排序確定性可重現
- [ ] 零 schema 變動、零 CLI 變動、零 collector 邏輯變動
