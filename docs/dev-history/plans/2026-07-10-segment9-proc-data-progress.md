# 段 9：live proc 資料補齊 + 進度回饋 + manifest 相容 + 關聯佐證修正 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 補上 live proc collector 缺採集的 cmdline/integrity/start_time（修 parentchild heuristic 半數訊號 live 下不觸發、段 3 correlator 的資料前提）、加 orchestrator 進度回饋、修 manifest 向後相容缺口、修 persist.rs 跨文物佐證的路徑誤判。

**Architecture:** 四個獨立子系統改動，分屬 3 個 crate（`cairn-collectors-win`、`cairn-core`、`cairn-heur`），彼此無資料依賴，各自一組 task。全部延用既有的 RAII/graceful-degrade 模式，不引入新架構。

**Tech Stack:** Rust、`windows` crate 0.62.2（新增 3 個既有 feature flag）、serde、tracing。

---

## 檔案結構總覽

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-collectors-win/Cargo.toml` | 修改 | 新增 3 個 `windows` feature flag |
| `crates/cairn-collectors-win/src/proc.rs` | 修改 | 新增 `read_cmdline`、`read_integrity`、`read_start_time` 三個 best-effort 函式 |
| `crates/cairn-core/src/orchestrator.rs` | 修改 | collector 迴圈加開始/完成進度日誌 |
| `crates/cairn-core/src/manifest.rs` | 修改 | `RunInfo.profile`/`selected_modules` 加 `#[serde(default)]` |
| `crates/cairn-heur/src/persist.rs` | 修改 | `normalized_basename`/`CrossIndex` 改用路徑感知的 `JoinKey` |

---

## Task 1：`RunInfo` 缺欄位補 `#[serde(default)]`（manifest 相容修復，最小風險，先做建立信心）

**Files:**
- Modify: `crates/cairn-core/src/manifest.rs:36-40`（`RunInfo.profile`/`selected_modules`）
- Test: `crates/cairn-core/src/manifest.rs`（同檔 `#[cfg(test)] mod tests`）

- [ ] **Step 1: 寫失敗測試 — 缺 `profile`/`selected_modules` 的舊 JSON 仍可反序列化**

在 `crates/cairn-core/src/manifest.rs` 的 `#[cfg(test)] mod tests` 內，`manifest_without_governance_field_deserializes` 測試之後新增：

```rust
    #[test]
    fn run_info_missing_profile_and_modules_defaults_on_old_json() {
        // Pre-S2-L manifest JSON lacks `profile`/`selected_modules` (added in S2-L).
        let json = r#"{
            "started_utc":"2026-06-10T12:00:00Z",
            "finished_utc":null,
            "cmdline":"cairn evtx Security.evtx",
            "operator":"",
            "case_id":""
        }"#;
        let ri: RunInfo = serde_json::from_str(json).unwrap();
        assert_eq!(ri.profile, "");
        assert!(ri.selected_modules.is_empty());
    }

    #[test]
    fn manifest_missing_run_profile_field_deserializes() {
        // Full pre-S2-L manifest: `run.profile`/`run.selected_modules` absent entirely.
        let m = sample_manifest();
        let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
        v["run"].as_object_mut().unwrap().remove("profile");
        v["run"].as_object_mut().unwrap().remove("selected_modules");
        let back: Manifest = serde_json::from_value(v).unwrap();
        assert_eq!(back.run.profile, "");
        assert!(back.run.selected_modules.is_empty());
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-core run_info_missing_profile_and_modules_defaults_on_old_json`
Expected: FAIL（`missing field \`profile\`` serde 錯誤，因為目前沒有 `#[serde(default)]`）

- [ ] **Step 3: 實作 — 加 `#[serde(default)]`**

修改 `crates/cairn-core/src/manifest.rs` 第 29-41 行的 `RunInfo`：

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub started_utc: DateTime<Utc>,
    pub finished_utc: Option<DateTime<Utc>>,
    pub cmdline: String,
    pub operator: String,
    pub case_id: String,
    /// The active run profile (minimal|standard|verbose) — transparency (FR6).
    /// Additive (S2-L); `#[serde(default)]` keeps pre-S2-L manifests parseable.
    #[serde(default)]
    pub profile: String,
    /// The collector modules actually selected for this run (S2-L). Empty is honest:
    /// e.g. `--only nonexistent` ran no collectors. Additive; defaults on old JSON.
    #[serde(default)]
    pub selected_modules: Vec<String>,
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-core`
Expected: 全部通過，含新增的 2 個測試

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-core/src/manifest.rs
git commit -m "fix(core): RunInfo.profile/selected_modules default on missing JSON keys

Pre-S2-L manifests lack these two fields entirely, which previously made
cairn verify hard-fail on them instead of degrading gracefully."
```

---

## Task 2：orchestrator per-collector 進度回饋

**Files:**
- Modify: `crates/cairn-core/src/orchestrator.rs`（collector 執行迴圈）

- [ ] **Step 1: 讀取現有迴圈結構確認插入點**

Run: 用 Read 工具讀 `crates/cairn-core/src/orchestrator.rs` 第 1-90 行，確認 `run_live` 函式內 collector 迴圈的確切現況（本 plan 撰寫時讀到的結構如下，若程式碼已變動以實際讀到的為準，但欄位/函式簽名不應有破壞性差異）。

- [ ] **Step 2: 寫失敗測試 — 進度日誌不影響現有累加行為（回歸保護）**

在 `crates/cairn-core/src/orchestrator.rs` 的 `#[cfg(test)] mod tests` 內找到 `accumulates_all_successful_collectors` 測試（約第 176 行），本步驟不新增測試斷言進度日誌內容（`tracing` 輸出不易在單元測試斷言，這是已知的合理限制），而是**確認現有測試在改動後仍通過**——這一步先跑一次基準：

Run: `cargo test -p cairn-core accumulates_all_successful_collectors failing_collector_is_recorded_and_run_continues`
Expected: PASS（改動前的基準線，確認這兩個既有測試在你改動 orchestrator.rs 之前就是綠的）

- [ ] **Step 3: 實作 — collector 迴圈加開始/完成/失敗進度日誌**

修改 `crates/cairn-core/src/orchestrator.rs` 的 collector 迴圈（現況約第 40-48 行，結構為 `for c in collectors { match c.collect(&ctx) { Ok(recs) => {...}, Err(e) => { tracing::warn!(...) } } }`），改成：

```rust
    for c in collectors {
        let started = std::time::Instant::now();
        tracing::info!(collector = c.name(), "執行中");
        match c.collect(&ctx) {
            Ok(recs) => {
                tracing::info!(
                    collector = c.name(),
                    records = recs.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "完成"
                );
                // (下方既有的 records/sources 累加邏輯不變，原樣保留)
```

在既有的 `Err(e) => { tracing::warn!(...) }` 分支裡，於 `tracing::warn!` 呼叫中新增 `elapsed_ms` 欄位：

```rust
            Err(e) => {
                tracing::warn!(
                    collector = c.name(),
                    error = %e,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "失敗；跳過"
                );
                // (下方既有的失敗記錄邏輯不變，原樣保留)
```

**重要**：這一步只在既有的 `match` 分支開頭/`tracing` 呼叫裡插入程式碼，不改動 `Ok`/`Err` 分支內既有的 records/sources 累加邏輯、不改函式簽名、不改 `Collector` trait。

- [ ] **Step 4: 執行既有測試確認無回歸**

Run: `cargo test -p cairn-core`
Expected: 全部通過，數量與 Step 2 基準相同（本 task 不新增測試——tracing 輸出的斷言價值低於維護成本，這是刻意的範圍收斂，見 spec「YAGNI」判斷）

- [ ] **Step 5: 手動驗證進度輸出真的顯示（最低驗證梯度，見 judgment.md §5）**

Run: `cd crates/cairn-cli && cargo run -- run --target live --profile minimal --output /tmp/seg9-progress-check 2>&1 | head -20`

（Windows 環境請用等效 PowerShell 路徑，例如 `--output C:\temp\seg9-progress-check`）

Expected: stderr 出現形如 `執行中 collector="proc"` 與 `完成 collector="proc" records=N elapsed_ms=M` 的交錯行，每個 collector 各一組開始/完成（或失敗）訊息。

- [ ] **Step 6: Commit**

```bash
git add crates/cairn-core/src/orchestrator.rs
git commit -m "feat(core): per-collector start/finish progress logging in run_live

Addresses F-8 (segment-8 resilience audit): a verbose/raw-NTFS scan gave no
signal distinguishing 'still running' from 'hung'. Success/failure now both
log elapsed_ms; no new structured output format, launcher inherits stderr."
```

---

## Task 3：`persist.rs` 跨文物 join key 改路徑感知

**Files:**
- Modify: `crates/cairn-heur/src/persist.rs:210-248`（`normalized_basename`、`CrossIndex`、`build_cross_index`）
- 呼叫端：`crates/cairn-heur/src/persist.rs` 內使用 `CrossIndex.exec`/`CrossIndex.proc` 查找的地方（本 task 的 Step 5 會定位並更新）

已查證的 7 個 `ExecutionRecord.path` 來源路徑完整度（決定 `JoinKey` 分類的判斷依據，無需逐一特判 source，統一用「含 `\` 或 `/`」判斷即可涵蓋全部情況）：

| source | 路徑完整度 |
|---|---|
| amcache / amcache_driver | `LowerCaseLongPath`（完整路徑）或退回 `Name`（檔名），視 registry 值而定 |
| shimcache | 完整路徑（AppCompatCache entry） |
| prefetch | **只有檔名**（header 限制，`prefetch.rs:190` 註解「NAME only」） |
| userassist | 完整路徑（rot13 解碼的 UIST 路徑） |
| bam | 完整路徑（NT 裝置路徑形式，如 `\Device\HarddiskVolume3\...`） |
| srum | `resolve_app_name` 回傳值格式不定：可能是路徑，也可能是 `id:<app_id>`（找不到映射時） |

`ProcessRecord.image`（live 程序）恆為完整路徑。

- [ ] **Step 1: 寫失敗測試 — 完整路徑相符才佐證，同名不同路徑不誤判**

在 `crates/cairn-heur/src/persist.rs` 的既有測試模組內（先用 Read 工具讀該檔案的
`#[cfg(test)]` 區塊找到適合插入的位置，緊鄰其他 `CrossIndex`/join 相關測試），新增：

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
        assert!(matches!(k, JoinKey::Name(_)), "id: fallback must be a Name key");
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-heur join_key_`
Expected: FAIL（`join_key` 函式與 `JoinKey` 型別尚不存在）

- [ ] **Step 3: 實作 `JoinKey` 型別與 `join_key` 函式**

修改 `crates/cairn-heur/src/persist.rs`，替換第 208-219 行的 `normalized_basename`：

```rust
/// 跨文物比對鍵：有完整路徑（含目錄分隔符）就用正規化後的完整路徑比對；
/// 只有檔名（來源本身缺路徑資訊，如多數 prefetch 條目、srum 的 "id:<n>" 回退）
/// 就降級成純檔名比對。降級佐證的信心度低於完整路徑相符，呼叫端在組
/// finding reason 時必須標註「降級佐證」（見 gate_details 呼叫處）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum JoinKey {
    /// 正規化（trim + 去引號 + 小寫）後的完整路徑，含目錄。
    Path(String),
    /// 僅檔名（去 `.exe` 尾綴），來源缺路徑資訊。
    Name(String),
}

impl JoinKey {
    /// 兩個 JoinKey 是否應視為同一佐證目標：Path 對 Path 要求完全相同；
    /// 任一方是 Name（降級）就退回比對雙方的 basename。
    fn degraded_key(&self) -> String {
        match self {
            JoinKey::Path(p) => basename_from_normalized(p),
            JoinKey::Name(n) => n.clone(),
        }
    }
}

/// 從一個原始路徑/檔名字串建立 JoinKey：trim + 去引號 + 小寫，再判斷是否含
/// 目錄分隔符（`\` 或 `/`）。不含分隔符（如純檔名、或 srum 的 "id:42" 回退）
/// 一律視為 Name（降級）鍵。
fn join_key(raw: &str) -> JoinKey {
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
    s.strip_suffix(".exe").map(String::from).unwrap_or_else(|| s.to_string())
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-heur join_key_`
Expected: 全部 4 個新測試通過

- [ ] **Step 5: 改寫 `CrossIndex`/`build_cross_index` 改用 `JoinKey`，並更新查找邏輯**

先用 Read 工具讀 `crates/cairn-heur/src/persist.rs` 完整檔案，定位所有呼叫
`build_cross_index`/`CrossIndex.exec`/`CrossIndex.proc` 的地方（原本用
`HashMap<String, ...>` 按 `normalized_basename` 查找），確認呼叫端目前怎麼組
finding reason（原本應該是直接命中就當完整命中，沒有分級）。

修改第 221-248 行的 `CrossIndex`/`build_cross_index`：

```rust
/// Index execution + process records for corroboration lookups. 用兩層索引：
/// exact（JoinKey 完全相等，Path 對 Path 或 Name 對 Name 且字串相同）優先；
/// 找不到 exact 命中時，用 degraded_key()（純 basename）再查一次，並標記
/// 該次命中為「降級佐證」。
struct CrossIndex<'a> {
    exec_exact: HashMap<JoinKey, Vec<&'a ExecutionRecord>>,
    exec_degraded: HashMap<String, Vec<&'a ExecutionRecord>>,
    proc_exact: HashMap<JoinKey, Vec<&'a ProcessRecord>>,
    proc_degraded: HashMap<String, Vec<&'a ProcessRecord>>,
}

impl<'a> CrossIndex<'a> {
    /// 查找 exec 佐證：先試 exact key；沒有的話退回 degraded（僅檔名）比對，
    /// 回傳 (命中清單, 是否為降級命中)。
    fn lookup_exec(&self, key: &JoinKey) -> (Vec<&'a ExecutionRecord>, bool) {
        if let Some(hits) = self.exec_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        let degraded = self.exec_degraded.get(&key.degraded_key());
        (degraded.cloned().unwrap_or_default(), true)
    }

    /// 同 lookup_exec，查 process 側。
    fn lookup_proc(&self, key: &JoinKey) -> (Vec<&'a ProcessRecord>, bool) {
        if let Some(hits) = self.proc_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        let degraded = self.proc_degraded.get(&key.degraded_key());
        (degraded.cloned().unwrap_or_default(), true)
    }
}

fn build_cross_index(records: &[Record]) -> CrossIndex<'_> {
    let mut exec_exact: HashMap<JoinKey, Vec<&ExecutionRecord>> = HashMap::new();
    let mut exec_degraded: HashMap<String, Vec<&ExecutionRecord>> = HashMap::new();
    let mut proc_exact: HashMap<JoinKey, Vec<&ProcessRecord>> = HashMap::new();
    let mut proc_degraded: HashMap<String, Vec<&ProcessRecord>> = HashMap::new();
    for r in records {
        match r {
            Record::Execution(e) => {
                let k = join_key(&e.path);
                if !k.degraded_key().is_empty() {
                    exec_degraded.entry(k.degraded_key()).or_default().push(e);
                    exec_exact.entry(k).or_default().push(e);
                }
            }
            Record::Process(p) => {
                let k = join_key(&p.image);
                if !k.degraded_key().is_empty() {
                    proc_degraded.entry(k.degraded_key()).or_default().push(p);
                    proc_exact.entry(k).or_default().push(p);
                }
            }
            _ => {}
        }
    }
    CrossIndex { exec_exact, exec_degraded, proc_exact, proc_degraded }
}
```

**在呼叫端**（Read 工具找到的實際查找位置，替換原本 `cross.exec.get(&normalized_basename(...))`
這類呼叫）改用 `cross.lookup_exec(&join_key(...))`/`cross.lookup_proc(&join_key(...))`，
並在組 finding reason 字串時，若回傳的 `bool`（是否降級）為 `true`，在 reason
文字附加「（降級佐證：僅檔名相符，來源缺完整路徑）」。**這個呼叫端的精確位置與
既有 reason 組字串邏輯需要在實作時用 Read 工具讀出來再改，不可憑空猜測既有
程式碼結構**——若發現既有呼叫邏輯與本步驟描述的介面對不上，以維持
「佐證命中與否 + 是否降級」這個語意契約為準，呼叫端的整合方式可依實際程式碼
調整。

- [ ] **Step 6: 執行完整測試確認通過且無回歸**

Run: `cargo test -p cairn-heur`
Expected: 全部通過，含 Step 1 新增的 4 個測試，且既有 persist.rs 測試（跨文物
佐證相關）全部維持通過

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-heur/src/persist.rs
git commit -m "fix(heur): persist cross-artifact join key is path-aware, not basename-only

Addresses correlation-architecture-audit F-2: same-basename-different-path
binaries no longer collide into a false corroboration. Sources that only
ever provide a bare filename (prefetch) still get a degraded basename-only
match, clearly labeled as such in the finding reason."
```

---

## Task 4：live proc 補採集 — integrity（token，先做，比 cmdline 單純）

**Files:**
- Modify: `crates/cairn-collectors-win/src/proc.rs`（新增 `read_integrity` 函式）
- 不需要新增 Cargo.toml feature（`Win32_Security` 已啟用）

- [ ] **Step 1: 寫失敗測試 — 自己的程序能讀到 integrity 等級**

在 `crates/cairn-collectors-win/src/proc.rs` 的 `#[cfg(all(test, windows))] mod tests`
內新增：

```rust
    /// Our own process's token integrity level should resolve to a known non-empty
    /// RID (typically "medium" for a non-elevated session, "high" if elevated).
    #[test]
    fn current_process_integrity_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        assert!(
            mine.integrity_raw.is_some(),
            "expected an integrity RID for our own process"
        );
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-collectors-win current_process_integrity_resolves`
Expected: FAIL（`mine.integrity_raw` 恆 `None`，因為 `proc.rs:143` 目前硬編 `None`）

- [ ] **Step 3: 實作 — `read_integrity` 函式**

在 `crates/cairn-collectors-win/src/proc.rs` 的 `#[cfg(windows)] mod win` 區塊內，
`full_image_path` 函式之後新增：

```rust
    use windows::Win32::Security::{
        GetTokenInformation, TokenIntegrityLevel, GetSidSubAuthority,
        GetSidSubAuthorityCount, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::OpenProcessToken;

    /// RAII guard for a token HANDLE.
    /// INVARIANT: holds a valid token handle from OpenProcessToken; closed once on drop.
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: self.0 is the valid token handle; closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Best-effort token integrity RID for a pid. Returns None on any failure
    /// (privilege / pid 0 / exited process) — never panics. Read-only: TOKEN_QUERY
    /// cannot modify the target.
    fn read_integrity(pid: u32) -> Option<u32> {
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
        // QUERY_LIMITED_INFORMATION is sufficient to open a token for TOKEN_QUERY.
        let proc_handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let proc_guard = ProcHandle(proc_handle);

        let mut token = HANDLE::default();
        // SAFETY: proc_guard.0 valid; token is an out-param written only on success.
        unsafe { OpenProcessToken(proc_guard.0, TOKEN_QUERY, &mut token) }.ok()?;
        let token_guard = TokenHandle(token);

        // Two-stage size probe (same pattern as privilege.rs::GetTokenInformation use).
        let mut len: u32 = 0;
        // SAFETY: null buffer + 0 size is the documented probe form; return value
        // intentionally ignored (probe always "fails" with the required size in `len`).
        unsafe {
            let _ = GetTokenInformation(
                token_guard.0,
                TokenIntegrityLevel,
                None,
                0,
                &mut len,
            );
        }
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: buf sized to the probed `len`; token_guard.0 valid; out len re-passed.
        unsafe {
            GetTokenInformation(
                token_guard.0,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                len,
                &mut len,
            )
        }
        .ok()?;

        // SAFETY: buf is exactly `len` bytes as filled by the API above; read via
        // read_unaligned because a Vec<u8> only guarantees 1-byte alignment while
        // TOKEN_MANDATORY_LABEL requires pointer alignment (same caveat as the
        // existing net.rs MIB-table cast, documented there as finding B-2).
        let label: TOKEN_MANDATORY_LABEL =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };

        // SAFETY: label.Label.Sid is a valid PSID owned by `buf`'s lifetime (still in
        // scope here); GetSidSubAuthorityCount/GetSidSubAuthority are read-only queries.
        unsafe {
            let count = *GetSidSubAuthorityCount(label.Label.Sid);
            if count == 0 {
                return None;
            }
            let rid_ptr = GetSidSubAuthority(label.Label.Sid, (count - 1) as u32);
            Some(*rid_ptr)
        }
    }
```

**注意**：`GetSidSubAuthority`/`GetSidSubAuthorityCount` 回傳裸指標，需要確認
`windows` crate 0.62.2 的實際回傳型別是 `*mut u32`/`*mut u8`——若編譯器報型別
不符，依實際回傳型別調整解引用方式（例如 `count` 可能回傳 `*mut u8` 需要
`*(...)  as u32`）。這是實作時第一次 `cargo check` 會揭露的，不是可以事先臆測
到位的細節。

在 `enumerate()` 函式內（第 138-147 行附近），把硬編的 `integrity_raw: None,`
改為呼叫 `read_integrity(entry.th32ProcessID)`：

```rust
            out.push(RawProc {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                image,
                cmdline: None,     // Task 5/6 補
                integrity_raw: read_integrity(entry.th32ProcessID),
                signed: None,
                user: None,
                start_time: None, // Task 7 補
            });
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-collectors-win`
Expected: 全部通過，含 `current_process_integrity_resolves`

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors-win/src/proc.rs
git commit -m "feat(collectors-win): populate ProcessRecord.integrity_raw via token query

Addresses segment-8 F-1: unsigned-high-integrity amplifier in parentchild
heuristic previously never fired on live scans because integrity_raw was
hardcoded None. Best-effort: any failure (privilege/exited process) -> None,
never panics."
```

---

## Task 5：live proc 補採集 — start_time（GetProcessTimes，第二簡單）

**Files:**
- Modify: `crates/cairn-collectors-win/src/proc.rs`（新增 `read_start_time` 函式）
- 不需要新增 feature（`Win32_System_Threading` 已啟用，`GetProcessTimes` 已含其中）

- [ ] **Step 1: 寫失敗測試 — 自己的程序能讀到 start_time**

在同一個測試模組追加：

```rust
    /// Our own process's start_time should resolve to a real, past timestamp.
    #[test]
    fn current_process_start_time_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        let st = mine.start_time.expect("expected a start_time for our own process");
        assert!(st <= chrono::Utc::now(), "start_time must not be in the future");
    }
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p cairn-collectors-win current_process_start_time_resolves`
Expected: FAIL（`mine.start_time` 恆 `None`）

- [ ] **Step 3: 實作 — `read_start_time` 函式**

在 `crates/cairn-collectors-win/src/proc.rs` 的 `mod win` 區塊，`read_integrity`
之後新增：

```rust
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;

    /// Best-effort process creation time via GetProcessTimes. None on any failure
    /// (privilege / exited process) or on an all-zero FILETIME (API's documented
    /// failure signal for creation time on certain system processes).
    fn read_start_time(pid: u32) -> Option<DateTime<Utc>> {
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let guard = ProcHandle(handle);

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: guard.0 valid; all four out-params are valid mutable FILETIME refs.
        unsafe {
            GetProcessTimes(guard.0, &mut creation, &mut exit, &mut kernel, &mut user)
        }
        .ok()?;

        filetime_to_utc(creation)
    }

    /// Convert a Win32 FILETIME (100ns ticks since 1601-01-01 UTC) to chrono UTC.
    /// None for an all-zero FILETIME (no real timestamp) — never guesses.
    fn filetime_to_utc(ft: FILETIME) -> Option<DateTime<Utc>> {
        let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
        if ticks == 0 {
            return None;
        }
        // 1601-01-01 to 1970-01-01 offset in 100ns ticks.
        const EPOCH_DIFF_TICKS: u64 = 116_444_736_000_000_000;
        let unix_ticks = ticks.checked_sub(EPOCH_DIFF_TICKS)?;
        let secs = (unix_ticks / 10_000_000) as i64;
        let nanos = ((unix_ticks % 10_000_000) * 100) as u32;
        chrono::DateTime::from_timestamp(secs, nanos)
    }
```

**注意**：查一下 `cairn-core/src/time.rs` 是否已有等效的 FILETIME 轉換函式可以
直接複用而非重寫（spec 提到「沿用專案既有 FILETIME 轉換慣例」）——用 Read
工具讀 `crates/cairn-core/src/time.rs` 全文，若已有 `filetime_to_utc` 或同義
函式，改成呼叫該函式而非在 `proc.rs` 重寫一份（DRY）；`cairn-collectors-win`
若不能直接依賴 `cairn-core` 的私有函式，就把它視為兩個獨立實作但確保邏輯
一致（都用 checked_sub 防溢位、都對全零 FILETIME 回 None）。

在 `enumerate()` 函式內，把硬編的 `start_time: None,` 改為：

```rust
                start_time: read_start_time(entry.th32ProcessID),
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test -p cairn-collectors-win`
Expected: 全部通過，含 `current_process_start_time_resolves`

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors-win/src/proc.rs
git commit -m "feat(collectors-win): populate ProcessRecord.start_time via GetProcessTimes

Addresses segment-8 F-1 downstream effect (correlation-architecture-audit
F-1): parentchild.rs's Finding.ts silently fell back to Utc::now() and
segment-3 temporal-window-correlator was a no-op on live data because
start_time was hardcoded None. Best-effort; all-zero FILETIME -> None."
```

---

## Task 6：live proc 補採集 — cmdline（PEB 讀取，最複雜，最後做）

**Files:**
- Modify: `crates/cairn-collectors-win/Cargo.toml`（新增 3 個 feature flag）
- Modify: `crates/cairn-collectors-win/src/proc.rs`（新增 `read_cmdline` 函式）

- [ ] **Step 1: 新增 Cargo.toml feature flag**

修改 `crates/cairn-collectors-win/Cargo.toml`，在既有 `features = [...]` 陣列內
（第 16-22 行附近，`"Win32_System_Threading"`、`"Win32_Security"` 等所在的陣列）
新增三行：

```toml
  "Win32_System_Kernel",
  "Win32_System_Diagnostics_Debug",
  "Wdk_System_Threading",
```

- [ ] **Step 2: 執行 `cargo check` 確認新 feature 可編譯**

Run: `cargo check -p cairn-collectors-win`
Expected: 編譯成功（只加 feature flag，還沒用到新符號，此步驟純粹確認
Cargo.toml 語法與 feature 名稱正確）

- [ ] **Step 3: 寫失敗測試 — 自己的程序能讀到完整的 cmdline**

在同一個測試模組追加：

```rust
    /// Our own process's cmdline should be readable (we are not WOW64, not
    /// protected, and PROCESS_VM_READ against our own process always succeeds).
    #[test]
    fn current_process_cmdline_resolves() {
        let me = std::process::id();
        let procs = enumerate().expect("enumerate");
        let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
        assert!(
            mine.cmdline.is_some(),
            "expected a cmdline for our own process"
        );
    }
```

- [ ] **Step 4: 執行測試確認失敗**

Run: `cargo test -p cairn-collectors-win current_process_cmdline_resolves`
Expected: FAIL（`mine.cmdline` 恆 `None`）

- [ ] **Step 5: 實作 — `read_cmdline` 函式（PEB 讀取鏈）**

在 `crates/cairn-collectors-win/src/proc.rs` 的 `mod win` 區塊，`read_start_time`
之後新增：

```rust
    use windows::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessBasicInformation, ProcessWow64Information,
    };
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;

    /// Upper bound on a UNICODE_STRING.Length we will trust before allocating a
    /// read buffer — the value lives in the target's (potentially adversarial)
    /// memory, so it must be capped before use (mirrors volume.rs::MAX_READ).
    const MAX_CMDLINE_BYTES: usize = 32 * 1024;

    /// True if `pid` is a WOW64 (32-bit-on-64-bit) process. On query failure,
    /// conservatively returns `true` (abstain) rather than risk misreading a
    /// 32-bit PEB layout as a 64-bit one.
    fn is_wow64(handle: HANDLE) -> bool {
        let mut wow64_peb: usize = 0;
        // SAFETY: handle valid; wow64_peb is a valid out-param; ProcessWow64Information
        // on a 64-bit build returns the WOW64 PEB address (non-zero) or 0 if native.
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessWow64Information,
                &mut wow64_peb as *mut usize as *mut core::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status.is_err() {
            return true; // abstain-safe default
        }
        wow64_peb != 0
    }

    /// Best-effort full command line for `pid`, via PEB -> RTL_USER_PROCESS_PARAMETERS
    /// -> CommandLine (three chained ReadProcessMemory calls into the target's address
    /// space). None on ANY failure at ANY step (target exited mid-read, WOW64 mismatch,
    /// oversized/corrupt UNICODE_STRING.Length, partial read) — never guesses from a
    /// partial result. Read-only: PROCESS_VM_READ cannot modify the target (rule 1).
    fn read_cmdline(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            )
        }
        .ok()?;
        let guard = ProcHandle(handle);

        if is_wow64(guard.0) {
            return None; // native-width only; abstain on bitness mismatch (NFR12)
        }

        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        // SAFETY: guard.0 valid; pbi is a valid out-param sized correctly.
        let status = unsafe {
            NtQueryInformationProcess(
                guard.0,
                ProcessBasicInformation,
                &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut core::ffi::c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status.is_err() || pbi.PebBaseAddress.is_null() {
            return None;
        }

        // Step 1: read PEB.ProcessParameters (a pointer INTO the target's address
        // space; must not be dereferenced locally).
        let params_ptr = read_remote::<*mut core::ffi::c_void>(
            guard.0,
            pbi.PebBaseAddress as *const core::ffi::c_void,
            peb_process_parameters_offset(),
        )?;
        if params_ptr.is_null() {
            return None;
        }

        // Step 2: read RTL_USER_PROCESS_PARAMETERS.CommandLine (a UNICODE_STRING:
        // Length in bytes + a pointer, itself INTO the target's address space).
        let cmdline_unicode_string = read_remote_unicode_string(
            guard.0,
            params_ptr,
            command_line_offset_in_params(),
        )?;

        if cmdline_unicode_string.length as usize > MAX_CMDLINE_BYTES {
            return None; // adversarial/corrupt Length; abstain rather than OOM (NFR9)
        }
        if cmdline_unicode_string.length == 0 || cmdline_unicode_string.buffer.is_null() {
            return None;
        }

        // Step 3: read the actual UTF-16LE command-line bytes.
        let byte_len = cmdline_unicode_string.length as usize;
        let mut buf = vec![0u16; byte_len / 2];
        let mut bytes_read: usize = 0;
        // SAFETY: guard.0 valid; buf sized to byte_len (checked above); bytes_read
        // out-param checked below for a partial-read short-circuit.
        unsafe {
            ReadProcessMemory(
                guard.0,
                cmdline_unicode_string.buffer as *const core::ffi::c_void,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                byte_len,
                Some(&mut bytes_read),
            )
        }
        .ok()?;
        if bytes_read != byte_len {
            return None; // partial read: treat as failure, never truncate-and-guess
        }

        let s = String::from_utf16_lossy(&buf);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
```

**這個 Step 需要在實作時（不是 plan 撰寫時）查證並補上三個輔助項，因為它們
依賴 `windows` crate 內 `PEB`/`RTL_USER_PROCESS_PARAMETERS` 結構的確切欄位
offset，這在 spec 階段已確認欄位存在但精確 byte offset 需要編譯期用
`std::mem::offset_of!` 或等效方式取得，不能在 plan 文件裡憑空寫死數字**：

1. `read_remote<T>(handle, base_ptr, field_offset) -> Option<T>`：泛型的單次
   `ReadProcessMemory` helper，讀 `T` 大小的位元組到本地變數。實作時用
   `windows::Win32::System::Threading::PEB` 的 `ProcessParameters` 欄位（若
   crate 直接曝露這個具名欄位，優先用 `std::mem::offset_of!(PEB, ProcessParameters)`
   取得 offset，而非手刻魔術數字——這是 B 報告 §4b 強調的「不手刻 offset」
   要求）。

2. `peb_process_parameters_offset()`：回傳上述 offset 的函式，或直接在
   `read_cmdline` 內用 `offset_of!` inline 展開，視實作時哪種寫法更符合
   `windows` crate 曝露 `PEB` 結構的方式（若 `PEB` 是完整具名 struct 可以
   直接用 `read_remote_struct::<PEB>` 讀整個 PEB 再取 `.ProcessParameters`
   欄位，不必手算 offset——這其實是更簡單、更不會出錯的做法，實作時優先
   考慮這條路徑）。

3. `read_remote_unicode_string`：讀 `RTL_USER_PROCESS_PARAMETERS.CommandLine`
   這個 `UNICODE_STRING` 欄位（同上，優先讀整個
   `RTL_USER_PROCESS_PARAMETERS` struct 再取 `.CommandLine` 欄位，而非手算
   offset）。`UNICODE_STRING` 的 `Length`/`Buffer` 欄位名稱以 `windows` crate
   實際定義為準（可能是 `Length`/`Buffer` 或 `length`/`buffer`，snake_case
   或 PascalCase 取決於 crate 的 binding 風格，用 `cargo check` 的編譯錯誤
   訊息確認正確名稱）。

**實作原則重申**：優先用「整個 struct 一次 `ReadProcessMemory` 讀回本地，
再存取具名欄位」而非「手算單一欄位的 byte offset 分別讀」——前者利用
`windows` crate 保證的 struct layout，後者才是 B 報告警告要避免的手刻
offset 陷阱。上方虛擬碼中的 `peb_process_parameters_offset()`/
`command_line_offset_in_params()`/`read_remote::<T>()` 應該在實作時被替換成
「讀整個 `PEB`/`RTL_USER_PROCESS_PARAMETERS` struct」的版本，這是本 task
唯一允許偏離虛擬碼字面寫法的地方，因為凍結成 offset-based 寫法本身就違反
spec 的技術要求。

在 `enumerate()` 函式內，把硬編的 `cmdline: None,` 改為：

```rust
                cmdline: read_cmdline(entry.th32ProcessID),
```

- [ ] **Step 6: 執行測試確認通過**

Run: `cargo test -p cairn-collectors-win`
Expected: 全部通過，含 `current_process_cmdline_resolves`

- [ ] **Step 7: 執行 clippy 確認無新警告**

Run: `cargo clippy -p cairn-collectors-win --all-targets -- -D warnings`
Expected: 無警告（`unsafe` 區塊的 SAFETY 註解需完整，clippy 對裸指標操作的
lint 若觸發，依訊息調整寫法，不可用 `#[allow]` 消音——若真的觸發需要重新
檢視該行是否真的 sound）

- [ ] **Step 8: Commit**

```bash
git add crates/cairn-collectors-win/Cargo.toml crates/cairn-collectors-win/src/proc.rs
git commit -m "feat(collectors-win): populate ProcessRecord.cmdline via PEB read

Addresses segment-8 F-1 (root cause): encoded-PowerShell and LOLBAS-argument
heuristic signals in parentchild.rs never fired on live scans because
cmdline was hardcoded None. Three chained ReadProcessMemory calls
(PEB -> RTL_USER_PROCESS_PARAMETERS -> CommandLine bytes); any failure at
any step degrades to None. WOW64 targets abstain entirely (native-width
only, per NFR12). UNICODE_STRING.Length capped at 32KiB before allocation."
```

---

## Task 7：跨 crate 整合驗證（controller 執行，非獨立 subagent task）

此 task 不派 subagent——這是 finishing-a-development-branch 前，controller
親自確認四個獨立改動放在一起沒有互相干擾的最後一關（cairn-core 的
`Collector`/`Record` trait 形狀跨越了 `cairn-collectors-win`、`cairn-heur`
兩個消費端，屬於 CLAUDE.md「Test scope discipline」定義的跨 crate 邊界，
值得跑一次全量）。

- [ ] **Step 1: 全 workspace 建置與測試**

Run: `cargo check --workspace && cargo test --workspace --exclude cairn-updater`

Expected: 全部通過（`cairn-updater` 需要提權，照專案慣例排除）

- [ ] **Step 2: 全 workspace clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`

Expected: 無警告、fmt 乾淨

- [ ] **Step 3: 真機驗證 parentchild heuristic 的訊號真的復活（最低驗證梯度）**

Run（Windows 環境）：
```powershell
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\AppData\Local\cairn-target"
cargo run -p cairn-cli -- run --target live --profile verbose --output C:\temp\seg9-verify
```

檢查輸出目錄的 `findings.jsonl`，確認至少能找到一筆 `source` 為
`"heuristic"` 且 `rule_id`/`title` 與 parentchild 相關的 finding（若當下
系統狀態沒有真的觸發任何可疑程序模式，這一步改為檢查
`manifest.json` 的 `sources[].errors` 沒有新的非預期錯誤，且
`records` 計數 > 0，證明 proc collector 有正常跑完）。

---

## Self-Review 完成度檢查

**Spec coverage：**
- 一、F-1 cmdline → Task 6 ✓
- 一、F-1 integrity → Task 4 ✓
- 一、F-1 start_time → Task 5 ✓
- 二、F-8 進度回饋 → Task 2 ✓
- 三、manifest defaults → Task 1 ✓（spec 要求「全掃 manifest.rs」，已在
  writing-plans 階段親自讀完 `manifest.rs` 全部 7 個 struct，確認只有
  `RunInfo.profile`/`selected_modules` 缺 default，其餘欄位已正確處理，
  故 Task 1 範圍精確對應實際缺口，不需要額外 task）
- 四、persist.rs join key → Task 3 ✓
- 跨段紀律（測試範圍分工、golden rules）→ Task 7 + 各 task 內文

**Placeholder scan：** Task 6 的 Step 5 保留了三處「實作時查證」的說明文字
（`read_remote`/offset 相關），這不是規格模糊，而是明確指出「必須用整個
struct 讀取取代手算 offset」這個技術要求本身——已用粗體標註實作原則，
不是可以隨意跳過的 TODO。其餘 5 個 task 的每個 Step 都有完整可執行的程式碼
與指令。

**Type consistency：** `RawProc`（`proc.rs`）的 `cmdline`/`integrity_raw`/
`start_time` 欄位型別在 Task 4/5/6 全程保持
`Option<String>`/`Option<u32>`/`Option<DateTime<Utc>>`，與現有型別定義一致，
無新增/修改型別。`JoinKey` enum 在 Task 3 內部定義與使用一致
（`Path(String)`/`Name(String)`，`degraded_key()` 方法簽名前後一致）。
`CrossIndex` 從單一 `HashMap<String,...>` 改為四個欄位
（`exec_exact`/`exec_degraded`/`proc_exact`/`proc_degraded`），
`lookup_exec`/`lookup_proc` 回傳型別 `(Vec<&T>, bool)` 前後一致。
