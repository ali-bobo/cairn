# Correlation Severity Tuning — Design Spec

> **Date:** 2026-06-28
> **Status:** Approved — ready for implementation
> **Scope:** `crates/cairn-heur/src/correlation.rs` only. Zero schema changes.
> **Authoritative SRS:** `cairn-SRS.md` §10 (heuristics), §13 (golden rules).

---

## 1. 問題陳述

`CorrelationAnalyzer` 目前對所有「persistence + execution 同時存在」的 binary 一律發出
`Severity::High`，導致 Chrome、Notion、OneDrive 等合法已簽章常駐軟體被標為高風險，
嚴重影響調查工程師的信任度（alert fatigue）。

根本原因：correlation 沒有讀取 `PersistenceRecord.signed`，也沒有判斷路徑可信度。
而這兩個函式（`is_trusted_appdata_location`、`is_suspicious_path`）在 `score.rs` 已存在。

---

## 2. 設計目標

1. **降低誤報**：合法已簽章軟體不再觸發 High。
2. **保持偵測力**：路徑可疑或明確未簽章的 persistence 仍維持 High。
3. **資訊透明**：`Finding.reason` 必須說明 severity 為何被調降或維持。
4. **零破壞**：不動 schema（Record / Finding / Manifest），不動其他 analyzer。

---

## 3. Severity 決策矩陣

調查工程師視角的核心原則：
- 路徑可疑（Temp / Downloads / ProgramData 根目錄等）→ 本質就是紅旗，不降級。
- `signed == Some(false)` 明確未簽章 → 合法商業軟體幾乎百分百有簽章，未簽章是異常。
- `signed == None` → 資訊不足（EVTX-only / offline 模式），不能信任，不降級。
- `signed == Some(true)` + 路徑可信 → 合法常駐軟體的典型特徵，降為 Medium。

| 路徑 | signed | Severity | 說明 |
|------|--------|----------|------|
| 可疑（Temp/Downloads/ProgramData/Public） | 任何 | **High** | 路徑本身就是紅旗 |
| 正常 | `Some(false)` 明確未簽章 | **High** | 合法軟體沒理由沒簽章 |
| 正常 | `None` 資訊不足 | **High** | fail-loud：無法排除風險 |
| 正常 | `Some(true)` 已簽章 | **Medium** | 合法常駐軟體的典型特徵 |

> **`\AppData\Local\Programs\` 特例**：
> `score.rs` 的 `is_trusted_appdata_location()` 只信任 `\AppData\Local\Programs\`
> 這個子路徑（Notion/Warp/VS Code 的標準安裝位置）。
> `\AppData\Roaming\`、`\AppData\Local\Temp\` 等仍視為可疑路徑，維持 High。
> Chrome 安裝在 `\AppData\Local\Google\Chrome\`（非 Programs）→ 路徑不可疑（無 `\temp\` 等
> 可疑片段）且有簽章 → Medium。這是正確行為。

---

## 4. 實作細節

### 4.1 判斷函式（純函式，可測試）

```rust
/// 從 persist entries 取最具代表性的 binary path（best_path）與 signed 狀態。
/// 規則：任一 entry 明確未簽章 → Some(false)；全部已簽章 → Some(true)；其他 → None。
fn group_signed(group: &[&&PersistenceRecord]) -> Option<bool> {
    let mut any_false = false;
    let mut all_true = true;
    for p in group {
        match p.signed {
            Some(false) => any_false = true,
            Some(true) => {}
            None => all_true = false,
        }
    }
    if any_false { Some(false) }
    else if all_true { Some(true) }
    else { None }
}

/// 根據 best_path 與 signed 決定 severity，同時回傳 reason 補充說明。
fn correlation_severity(best_path: &str, signed: Option<bool>) -> (Severity, &'static str) {
    let suspicious = is_suspicious_path(best_path);
    // 已簽章 + 路徑可信 → trusted_appdata 或非可疑路徑
    let trusted = signed == Some(true) && !suspicious;
    if suspicious {
        (Severity::High, "binary path is in a suspicious directory")
    } else if signed == Some(false) {
        (Severity::High, "binary is explicitly unsigned; legitimate software is always signed")
    } else if signed.is_none() {
        (Severity::High, "signature status unknown (offline/EVTX-only mode); cannot exclude risk")
    } else {
        // signed == Some(true) && !suspicious
        let _ = trusted; // suppress unused warning
        (Severity::Medium, "signed binary in a normal path; consistent with legitimate autostart software")
    }
}
```

### 4.2 調用位置

在 `correlation.rs` 的 `analyze()` 主迴圈中，現有的 `Finding::new(Severity::High, ...)` 行，
改為呼叫 `correlation_severity(best_path, group_signed(&group))`，取得 `(severity, sev_reason)`，
並將 `sev_reason` 附加到 `f.reason`。

### 4.3 reason 格式

```
binary found in persistence (run_key: HKLM\...\Run) and execution records (prefetch, amcache); [sev_reason]
```

---

## 5. 可複用的 score.rs 函式

| 函式 | 用途 |
|------|------|
| `is_suspicious_path(path)` | 判斷路徑是否含 Temp/Downloads/ProgramData/Public 等可疑片段 |
| `is_trusted_appdata_location(path)` | 判斷是否在 `\AppData\Local\Programs\`（本 spec 不直接用，已透過 suspicious 涵蓋） |

> `is_trusted_appdata_location` 在本 spec 不需要額外呼叫，因為該路徑不含 SUSPICIOUS_DIRS
> 的任何片段，`is_suspicious_path` 已回傳 false，走到 `signed == Some(true)` → Medium 分支。

---

## 6. 不做的事（YAGNI）

- 不加廠商白名單（Chrome / Notion 等）— signed + 非可疑路徑已足夠，維護清單是負擔。
- 不加時間維度（last_write 年齡）— 留給後續 P2 任務，本 spec 只解 P0。
- 不動 heur_persist.rs — 它有自己完整的評分體系，不需要協調。
- 不動 schema — Finding.severity 已是 enum，無需新增欄位。

---

## 7. 測試矩陣（必須全通過）

| 測試名稱 | 場景 | 預期 severity |
|----------|------|---------------|
| `signed_trusted_path_is_medium` | signed=true + 正常路徑 | Medium |
| `signed_trusted_appdata_programs_is_medium` | signed=true + `\AppData\Local\Programs\` | Medium |
| `unsigned_normal_path_is_high` | signed=false + 正常路徑 | High |
| `unknown_signed_normal_path_is_high` | signed=None + 正常路徑 | High |
| `suspicious_path_signed_is_high` | signed=true + Temp 路徑 | High（路徑優先）|
| `suspicious_path_unsigned_is_high` | signed=false + Temp 路徑 | High |
| `reason_contains_severity_rationale` | 任一場景 | reason 含降/升級說明 |
| `existing_inbox_suppression_unchanged` | svchost System32 | 無 Finding（既有行為） |

---

## 8. 驗收門檻

- `cargo test --workspace` 全綠（包含上述新測試）
- `cargo clippy --workspace --all-targets -- -D warnings` 零警告
- Chrome / Notion 的 persistence finding 改為 Medium（手動執行 `cairn run` 確認）
- 路徑在 Temp 的 unsigned binary 維持 High（現有測試覆蓋）
- schema 零變動（`git diff -- crates/cairn-core/src/` 無輸出）
