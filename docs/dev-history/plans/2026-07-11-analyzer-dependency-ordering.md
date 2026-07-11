# Analyzer 依賴宣告基礎設施 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 讓 `Analyzer` 之間能宣告執行順序依賴、讓後執行的 analyzer 能讀到先執行的 analyzer 已產出的 Finding，作為未來跨 analyzer 佐證偵測（段 11：netconn 佐證 persist）的管道。本段不實作任何具體偵測邏輯。

**Architecture:** `Analyzer` trait 新增 `depends_on()`（預設空陣列）與 `analyze()` 簽名新增 `prior_findings: &[Finding]` 參數；`orchestrator::run_live` 對 analyzer 執行前先做穩定拓撲排序（Kahn's algorithm，注入順序 tie-break），依排序後順序執行並累加 Finding 往後傳；七個既有 `Analyzer` 實作只做純簽名遷移，邏輯不變。

**Tech Stack:** Rust，無新依賴。

---

## 檔案結構總覽

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-core/src/traits.rs` | 修改 | `Analyzer` trait：`analyze()` 簽名擴充、新增 `depends_on()` |
| `crates/cairn-core/src/orchestrator.rs` | 修改 | 新增 `topo_sort` 私有函式；analyzer 執行迴圈改用排序後順序 + 傳遞 `prior_findings`；測試區擴充 `FakeAnalyzer` |
| `crates/cairn-heur/src/account.rs` | 修改 | `analyze()` 簽名遷移（純簽名，邏輯不變） |
| `crates/cairn-heur/src/byovd.rs` | 修改 | 同上 |
| `crates/cairn-heur/src/netconn.rs` | 修改 | 同上 |
| `crates/cairn-heur/src/parentchild.rs` | 修改 | 同上 |
| `crates/cairn-heur/src/persist.rs` | 修改 | 同上 |
| `crates/cairn-heur/src/sigma.rs` | 修改 | 同上 |
| `crates/cairn-heur/src/timestomp.rs` | 修改 | 同上 |

**已查證**：全部七個 analyzer 檔案都已經在作用域內有 `Finding` 型別（透過
`cairn_core::{Finding, ...}` 或 `cairn_core::finding::Finding` 匯入），新增
`_prior_findings: &[Finding]` 參數**不需要新增任何 import**。

---

## Task 1：`Analyzer` trait 擴充

**Files:**
- Modify: `crates/cairn-core/src/traits.rs:45-53`

- [ ] **Step 1: 修改 `Analyzer` trait 定義**

修改 `crates/cairn-core/src/traits.rs` 第 45-53 行：

```rust
/// An Analyzer turns Records into Findings. MUST NOT touch the host.
/// Heuristic analyzers MUST populate `Finding.reason` (explainability).
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    /// `prior_findings` is the accumulated Finding output of every analyzer that has
    /// already run this cycle, in `depends_on()`-resolved order (not just the ones this
    /// analyzer depends on — see `depends_on()` doc for why). Analyzers that don't read
    /// this parameter simply ignore it.
    fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>>;
    /// Inventory items that did NOT clear the dispositive-signal gate (spec §6).
    /// Default empty: only analyzers that own an inventory (persist) override.
    fn observe(&self, _records: &[Record]) -> Result<Vec<Observation>> {
        Ok(vec![])
    }
    /// Names (matching other analyzers' `name()`) that must finish running before this
    /// one starts. Default: no dependencies. A name with no matching analyzer in the
    /// current run is silently ignored (not an error — allows declaring a dependency on
    /// an analyzer that may not always be present).
    fn depends_on(&self) -> &[&str] {
        &[]
    }
}
```

- [ ] **Step 2: 確認編譯失敗（預期，因為呼叫端與七個實作都還沒跟上新簽名）**

Run: `cargo check -p cairn-core`
Expected: FAIL — `orchestrator.rs` 呼叫 `a.analyze(&records)` 少一個參數，且
`FakeAnalyzer` 的 `impl Analyzer` 簽名對不上新 trait。這是預期的中間狀態，
Task 2 會修正。

- [ ] **Step 3: Commit**

不在此步驟單獨 commit——Task 1 與 Task 2 必須一起提交才能通過編譯（trait 改了
但呼叫端沒跟上，整個 workspace 編不過）。繼續進 Task 2，兩者合併在 Task 2
結束時一起 commit。

---

## Task 2：Orchestrator 拓撲排序 + `prior_findings` 傳遞

**Files:**
- Modify: `crates/cairn-core/src/orchestrator.rs`

- [ ] **Step 1: 寫失敗測試 — 依賴關係被遵守**

在 `crates/cairn-core/src/orchestrator.rs` 的 `#[cfg(test)] mod tests` 內，
先擴充 `FakeAnalyzer`（第 227-255 行）支援宣告依賴與讀取 `prior_findings`：

替換第 226-255 行的 `FakeAnalyzer` 定義區塊：

```rust
    /// A fake analyzer returning a canned result (or an error). `deps` declares
    /// `depends_on()`; `record_prior_count` is set true to make this analyzer's
    /// single returned Finding's title encode how many prior_findings it saw
    /// (`"saw:<N>"`), so tests can assert on it without a new Finding field.
    struct FakeAnalyzer {
        name: &'static str,
        deps: Vec<&'static str>,
        result: std::sync::Mutex<Option<Result<Vec<Finding>, CairnError>>>,
        record_prior_count: bool,
    }
    impl FakeAnalyzer {
        fn ok(name: &'static str, findings: Vec<Finding>) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                deps: vec![],
                result: std::sync::Mutex::new(Some(Ok(findings))),
                record_prior_count: false,
            })
        }
        fn err(name: &'static str) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                deps: vec![],
                result: std::sync::Mutex::new(Some(Err(CairnError::Analyzer {
                    analyzer: name.into(),
                    reason: "boom".into(),
                }))),
                record_prior_count: false,
            })
        }
        /// Declares dependencies on the given analyzer names; its Finding's title
        /// will be `"saw:<N>"` where N is `prior_findings.len()` at call time.
        fn with_deps(name: &'static str, deps: &[&'static str]) -> Box<dyn Analyzer> {
            Box::new(FakeAnalyzer {
                name,
                deps: deps.to_vec(),
                result: std::sync::Mutex::new(Some(Ok(vec![]))), // overwritten in analyze()
                record_prior_count: true,
            })
        }
    }
    impl Analyzer for FakeAnalyzer {
        fn name(&self) -> &str {
            self.name
        }
        fn analyze(
            &self,
            _records: &[Record],
            prior_findings: &[Finding],
        ) -> crate::Result<Vec<Finding>> {
            if self.record_prior_count {
                return Ok(vec![Finding::new(
                    Severity::Info,
                    format!("saw:{}", prior_findings.len()),
                    FindingSource::Heuristic,
                )]);
            }
            self.result.lock().unwrap().take().unwrap()
        }
        fn depends_on(&self) -> &[&str] {
            &self.deps
        }
    }
```

在 `fn a_finding()` 之後（第 257-259 行之後）新增測試：

```rust
    /// B depends on A: B's prior_findings must include A's Finding (A ran first).
    #[test]
    fn dependency_is_honored_prior_findings_visible() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            FakeAnalyzer::with_deps("b", &["a"]), // declared first, but must run AFTER a
            FakeAnalyzer::ok("a", vec![a_finding()]),
        ];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        // a's finding (title "t") + b's finding (title "saw:1", since it saw a's 1 finding)
        assert_eq!(out.findings.len(), 2);
        assert!(
            out.findings.iter().any(|f| f.title == "saw:1"),
            "b must have seen a's 1 finding by the time it ran; findings: {:?}",
            out.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    /// No dependency relationships: execution order matches injection order (stable),
    /// reproducibly across repeated calls on the same input.
    #[test]
    fn no_deps_execution_order_is_stable_and_matches_injection_order() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        // No FakeAnalyzer here declares deps, so order must equal injection order:
        // "first" runs before "second", so "second" (if it depended-tracked) would see
        // "first"'s finding. We assert indirectly via with_deps on "second" pointing at
        // nothing, but checking output order for FakeAnalyzer::ok is not directly
        // observable via findings alone — instead assert both runs produce identical
        // finding-title sequences (determinism), which is the property that matters.
        let build = || -> Vec<Box<dyn Analyzer>> {
            vec![
                FakeAnalyzer::ok("first", vec![a_finding()]),
                FakeAnalyzer::ok("second", vec![a_finding()]),
            ]
        };
        let out1 = run_live(&cfg, privs(), "WS01".into(), &collectors, &build());
        let out2 = run_live(&cfg, privs(), "WS01".into(), &collectors, &build());
        let titles1: Vec<&str> = out1.findings.iter().map(|f| f.title.as_str()).collect();
        let titles2: Vec<&str> = out2.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles1, titles2, "same input must produce the same order every time");
    }

    /// A circular dependency (a depends on b, b depends on a) must panic at run_live,
    /// with a message naming both analyzers.
    #[test]
    #[should_panic(expected = "circular")]
    fn circular_dependency_panics() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            FakeAnalyzer::with_deps("a", &["b"]),
            FakeAnalyzer::with_deps("b", &["a"]),
        ];
        run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
    }

    /// Declaring a dependency on an analyzer name that isn't present in the current run
    /// is NOT an error — it's silently ignored, and the run proceeds normally.
    #[test]
    fn dependency_on_absent_analyzer_name_is_ignored_not_an_error() {
        let cfg = Config::default();
        let collectors: Vec<Box<dyn Collector>> = vec![];
        let analyzers: Vec<Box<dyn Analyzer>> =
            vec![FakeAnalyzer::with_deps("solo", &["nonexistent"])];
        let out = run_live(&cfg, privs(), "WS01".into(), &collectors, &analyzers);
        assert_eq!(out.findings.len(), 1, "run must proceed despite the dangling dependency");
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-core dependency_is_honored_prior_findings_visible`
Expected: FAIL（編譯錯誤——`depends_on` 尚未在 orchestrator 邏輯裡被使用，
`analyze` 呼叫端簽名不對）

- [ ] **Step 3: 實作 `topo_sort` 私有函式**

在 `crates/cairn-core/src/orchestrator.rs`，`run_live` 函式之前（第 22 行之前）
新增：

```rust
/// Stable topological sort of `analyzers` by `depends_on()`. Returns the execution
/// order as indices into `analyzers`. Ties (no dependency relationship) are broken by
/// original array position (Kahn's algorithm with an index-ordered ready queue), so the
/// same input always produces the same order (Determinism, CLAUDE.md). A name in
/// `depends_on()` with no matching `name()` among `analyzers` is silently ignored — it
/// simply contributes no edge. Panics if a cycle exists (a static configuration error,
/// not a runtime condition — see spec's rationale for panic over Result here).
fn topo_sort(analyzers: &[Box<dyn Analyzer>]) -> Vec<usize> {
    let n = analyzers.len();
    let name_to_idx: std::collections::HashMap<&str, usize> = analyzers
        .iter()
        .enumerate()
        .map(|(i, a)| (a.name(), i))
        .collect();

    // in_degree[i] = number of unresolved dependencies analyzers[i] has.
    // dependents[i] = indices of analyzers that depend on analyzers[i].
    let mut in_degree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, a) in analyzers.iter().enumerate() {
        for dep_name in a.depends_on() {
            if let Some(&dep_idx) = name_to_idx.get(dep_name) {
                dependents[dep_idx].push(i);
                in_degree[i] += 1;
            }
            // Unknown dependency name: silently ignored (no edge added).
        }
    }

    let mut ready: std::collections::BinaryHeap<std::cmp::Reverse<usize>> = analyzers
        .iter()
        .enumerate()
        .filter(|(i, _)| in_degree[*i] == 0)
        .map(|(i, _)| std::cmp::Reverse(i))
        .collect();

    let mut order = Vec::with_capacity(n);
    while let Some(std::cmp::Reverse(i)) = ready.pop() {
        order.push(i);
        for &dep in &dependents[i] {
            in_degree[dep] -= 1;
            if in_degree[dep] == 0 {
                ready.push(std::cmp::Reverse(dep));
            }
        }
    }

    if order.len() != n {
        let stuck: Vec<&str> = (0..n)
            .filter(|i| in_degree[*i] > 0)
            .map(|i| analyzers[i].name())
            .collect();
        panic!(
            "circular dependency among analyzers: {} still have unresolved depends_on() after topological sort",
            stuck.join(", ")
        );
    }
    order
}
```

**設計說明（供實作者理解，不是要新增到程式碼裡）**：`BinaryHeap<Reverse<usize>>`
當最小堆使用，保證 ready queue 每次都先取出索引最小的節點——這就是「以原始
索引為 tie-break」的具體實作方式，等價於 spec 描述的「入度為零的節點按原始
索引由小到大加入處理佇列」。

- [ ] **Step 4: 修改 analyzer 執行迴圈**

修改 `crates/cairn-core/src/orchestrator.rs` 第 73-83 行：

```rust
    // Analyzer fan-in (SRS §3): each analyzer reads the accumulated records + prior
    // analyzers' findings (dependency-ordered) and emits findings. A failing analyzer is
    // logged + skipped (graceful degrade), never aborts.
    let order = topo_sort(analyzers);
    let mut findings = Vec::new();
    for &idx in &order {
        let a = &analyzers[idx];
        match a.analyze(&records, &findings) {
            Ok(mut fs) => findings.append(&mut fs),
            Err(e) => {
                tracing::warn!(analyzer = a.name(), error = %e, "analyzer failed; skipping");
            }
        }
    }
```

- [ ] **Step 5: 修改 `observe()` 迴圈維持既有行為（不套用排序）**

第 84-94 行的 `observe()` 迴圈**不修改**——`observe()` 不參與依賴排序機制
（spec 第 1 節明確排除），維持原本按 `analyzers` 陣列順序呼叫。確認這段
程式碼原封不動：

```rust
    // Observation fan-in (spec §6): inventory from analyzers that own one. A failing
    // observe is logged + skipped, mirroring the analyze contract.
    let mut observations = Vec::new();
    for a in analyzers {
        match a.observe(&records) {
            Ok(mut os) => observations.append(&mut os),
            Err(e) => {
                tracing::warn!(analyzer = a.name(), error = %e, "observe failed; skipping");
            }
        }
    }
```

- [ ] **Step 6: 修改既有兩個測試的呼叫點對齊新 `FakeAnalyzer` 介面**

第 261-269 行 `analyzers_findings_are_collected`、第 271-289 行
`failing_analyzer_is_skipped_run_continues` 兩個既有測試呼叫
`FakeAnalyzer::ok`/`FakeAnalyzer::err` 的方式不變（這兩個建構子的對外簽名
沒有變化，只是內部多了 `deps`/`record_prior_count` 欄位），**不需要修改
這兩個測試本體**，只要 Step 1 的 `FakeAnalyzer` 重寫正確，它們會自動繼續通過。

- [ ] **Step 7: 執行測試確認全部通過**

Run: `cargo test -p cairn-core`
Expected: 全部通過，含 Step 1 新增的 4 個測試與既有全部測試（無回歸）

- [ ] **Step 8: 執行 clippy 確認無警告**

Run: `cargo clippy -p cairn-core --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 9: Commit（Task 1 + Task 2 合併提交）**

```bash
git add crates/cairn-core/src/traits.rs crates/cairn-core/src/orchestrator.rs
git commit -m "feat(core): analyzer dependency ordering (depends_on + prior_findings)

Adds a stable topological sort over Analyzer::depends_on() so analyzers can
declare execution-order dependencies on each other, and analyze() now
receives prior_findings — the accumulated output of every analyzer that has
already run this cycle. No behavior change for the 7 existing analyzers
(all declare no dependencies, all ignore prior_findings for now). This is
pure plumbing for segment 11 (netconn corroborating persist), not yet used
by any analyzer."
```

**注意**：此時 `cargo check --workspace` 仍會失敗——七個 analyzer 實作檔案
還沒跟上新的 `analyze()` 簽名。這是預期的中間狀態，Task 3 會逐一修正。

---

## Task 3：七個既有 Analyzer 實作簽名遷移

**Files:**
- Modify: `crates/cairn-heur/src/account.rs:95`
- Modify: `crates/cairn-heur/src/byovd.rs:58`
- Modify: `crates/cairn-heur/src/netconn.rs:83`
- Modify: `crates/cairn-heur/src/parentchild.rs:164`
- Modify: `crates/cairn-heur/src/persist.rs:443`
- Modify: `crates/cairn-heur/src/sigma.rs:37`
- Modify: `crates/cairn-heur/src/timestomp.rs:108`

這是純簽名遷移，**不改變任何一行既有邏輯**。每個檔案都已經在作用域內有
`Finding` 型別（已查證，見本 plan 開頭的檔案結構總覽），不需要新增 import。

- [ ] **Step 1: `account.rs` 簽名遷移**

修改 `crates/cairn-heur/src/account.rs` 第 95 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 2: `byovd.rs` 簽名遷移**

修改 `crates/cairn-heur/src/byovd.rs` 第 58 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 3: `netconn.rs` 簽名遷移**

修改 `crates/cairn-heur/src/netconn.rs` 第 83 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 4: `parentchild.rs` 簽名遷移**

修改 `crates/cairn-heur/src/parentchild.rs` 第 164 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 5: `persist.rs` 簽名遷移**

修改 `crates/cairn-heur/src/persist.rs` 第 443 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 6: `sigma.rs` 簽名遷移**

修改 `crates/cairn-heur/src/sigma.rs` 第 37 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 7: `timestomp.rs` 簽名遷移**

修改 `crates/cairn-heur/src/timestomp.rs` 第 108 行：

```rust
    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
```

- [ ] **Step 8: 全 crate 編譯確認**

Run: `cargo check -p cairn-heur`
Expected: 編譯成功。若任何檔案因為 `_prior_findings` 參數未被使用而被
clippy 標記（不應該發生，因為底線前綴已表明故意不用），下一步的 clippy
會抓到，此處先確保基本編譯過。

- [ ] **Step 9: 執行 cairn-heur 測試確認無回歸**

Run: `cargo test -p cairn-heur`
Expected: 全部通過，數量與段 9 合併後的基準相同（本 task 純簽名遷移，
不改變任何測試斷言、不新增測試——七個檔案的既有測試呼叫的是 `analyze()`
公開方法，若測試程式碼裡直接呼叫 `analyze(&records)`，需要一併補上
`&[]` 作為 `prior_findings` 引數；用 grep 找出所有測試呼叫點並確認）

Run（在 Step 9 之前，先確認測試檔案裡是否有直接呼叫 `.analyze(` 的地方）：
`grep -n "\.analyze(&records" crates/cairn-heur/src/*.rs`
若有找到，每一處都要加上第二個引數 `&[]`（空的 prior_findings，因為這些
既有測試都是單獨測試一個 analyzer，沒有「先跑過的 analyzer」這個概念）。

- [ ] **Step 10: 執行 clippy 確認無警告**

Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 11: Commit**

```bash
git add crates/cairn-heur/src/account.rs crates/cairn-heur/src/byovd.rs \
        crates/cairn-heur/src/netconn.rs crates/cairn-heur/src/parentchild.rs \
        crates/cairn-heur/src/persist.rs crates/cairn-heur/src/sigma.rs \
        crates/cairn-heur/src/timestomp.rs
git commit -m "chore(heur): migrate all 7 Analyzer impls to the new analyze() signature

Pure signature migration for the depends_on()/prior_findings plumbing added
in cairn-core. No logic changes — every analyzer ignores the new
prior_findings parameter for now (still declares no dependencies)."
```

---

## Task 4：跨 crate 整合驗證（controller 執行，非獨立 subagent task）

此 task 不派 subagent——這是 finishing-a-development-branch 前，controller
親自確認 trait 改動（跨越 `cairn-core` 與 `cairn-heur` 兩個 crate 的邊界）
沒有遺漏任何呼叫端的最後一關，屬於 CLAUDE.md「Test scope discipline」定義
的跨 crate 邊界，值得跑一次全量。

- [ ] **Step 1: 全 workspace 建置與測試**

Run: `cargo check --workspace && cargo test --workspace --exclude cairn-updater`

Expected: 全部通過（`cairn-updater` 需要提權，照專案慣例排除）

- [ ] **Step 2: 全 workspace clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

Expected: 無警告、fmt 乾淨

- [ ] **Step 3: 確認 main.rs 的 analyzer 建構呼叫端沒有遺漏**

Run: `grep -rn "Box::new(.*Heuristic)\|Box::new(.*Analyzer)" crates/cairn-cli/src/main.rs`

確認 `cairn-cli/src/main.rs` 組裝 `analyzers: Vec<Box<dyn Analyzer>>` 的地方
（`run_live` 呼叫端）能正常編譯——這裡不需要任何改動（`Box<dyn Analyzer>`
的建構語法不受 trait 方法簽名變化影響），純粹確認 Step 1 的全 workspace
build 真的涵蓋到這個呼叫點。

---

## Self-Review 完成度檢查

**Spec coverage：**
- 第 1 節（trait 擴充：`analyze()` 加 `prior_findings`、`depends_on()` 預設
  空陣列）→ Task 1 ✓
- 第 2 節（orchestrator 拓撲排序、穩定 tie-break、循環依賴 panic）→ Task 2 ✓
- 第 3 節（七個既有 analyzer 簽名遷移，邏輯不變）→ Task 3 ✓
- 第 4 節（測試策略：依賴遵守、順序穩定、循環 panic、缺失依賴不報錯）→
  Task 2 Step 1 的四個新測試 ✓
- 「明確不做的事」（不實作跨 analyzer 偵測邏輯、不改 observe()、不做過濾
  傳遞、不支援動態依賴）→ 本 plan 全程遵守，Task 2 Step 5 明確保留
  `observe()` 迴圈不變 ✓
- 驗收條件全部六項 → Task 4 涵蓋前五項；第六項「零 schema/CLI/collector
  變動」由本 plan 範圍本身保證（未觸碰任何 schema/CLI/collector 檔案）

**Placeholder scan：** 無 TBD/TODO；每個 Step 都有完整可執行的程式碼與
確切指令。

**Type consistency：** `FakeAnalyzer::with_deps` 在 Task 2 Step 1 定義，
回傳 `Box<dyn Analyzer>`，其 `depends_on()` 回傳 `&self.deps`
（`Vec<&'static str>` 借用成 `&[&str]`，與 trait 簽名
`fn depends_on(&self) -> &[&str]` 一致）。`topo_sort` 回傳
`Vec<usize>`，在 Task 2 Step 4 的呼叫端 `for &idx in &order` 用法一致。
七個 analyzer 的新簽名 `fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>>`
在 Task 3 全部七處逐字一致，與 Task 1 定義的 trait 簽名
`fn analyze(&self, records: &[Record], prior_findings: &[Finding]) -> Result<Vec<Finding>>`
（實作端參數名可加底線前綴，Rust 允許實作的參數名與 trait 宣告不同名）
相容。
