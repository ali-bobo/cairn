# Correlation Severity Tuning — Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to execute this plan.

**Goal:** 修正 `CorrelationAnalyzer` 對合法已簽章常駐軟體（Chrome / Notion 等）發出誤報
High 的問題，改為根據路徑可信度 + 簽章狀態決定 severity。

**Architecture:** 在 `correlation.rs` 內新增兩個純函式 `group_signed` 與
`correlation_severity`，取代原本硬編的 `Severity::High`。複用 `score.rs` 的
`is_suspicious_path`。不動 schema、不動其他 analyzer。

**Tech Stack:** Rust / cairn-heur crate / score.rs primitives

**Spec:** `docs/dev-history/specs/2026-06-28-correlation-severity-tuning-design.md`

---

### Task 1: 新增純函式 `group_signed` 與 `correlation_severity`

**Files:**
- Modify: `crates/cairn-heur/src/correlation.rs`

- [ ] **Step 1: 在 `correlation.rs` 頂部 use 區塊加入 score 函式**

在現有的 `use crate::score::is_inbox_service_command;` 行改為：

```rust
use crate::score::{is_inbox_service_command, is_suspicious_path};
```

- [ ] **Step 2: 在 `mechanism_to_mitre` 函式之前新增兩個純函式**

```rust
/// 從一組 PersistenceRecord 取得代表性的 signed 狀態。
/// 任一 entry 明確未簽章 → Some(false)；全部已簽章 → Some(true)；其他 → None。
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
    if any_false {
        Some(false)
    } else if all_true {
        Some(true)
    } else {
        None
    }
}

/// 根據 best_path 與 signed 決定 correlation finding 的 severity 與 reason 補充說明。
/// 路徑可疑或未簽章/簽章未知 → High（fail-loud）。
/// 已簽章且路徑正常 → Medium（合法常駐軟體）。
fn correlation_severity(best_path: &str, signed: Option<bool>) -> (Severity, &'static str) {
    if is_suspicious_path(best_path) {
        (Severity::High, "binary path is in a suspicious directory")
    } else if signed == Some(false) {
        (
            Severity::High,
            "binary is explicitly unsigned; legitimate software is always signed",
        )
    } else if signed.is_none() {
        (
            Severity::High,
            "signature status unknown (offline/EVTX-only mode); cannot exclude risk",
        )
    } else {
        // signed == Some(true) && !suspicious
        (
            Severity::Medium,
            "signed binary in a normal path; consistent with legitimate autostart software",
        )
    }
}
```

- [ ] **Step 3: 在 `use` 區塊加入 Severity**

確認頂部已有 `use cairn_core::finding::{EntityFile, FindingSource, Severity};`（已存在，無需新增）。

- [ ] **Step 4: 執行 `cargo check -p cairn-heur`，確認無編譯錯誤**

```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
cargo check -p cairn-heur
```

期望：零錯誤，可能有 unused function 警告（Task 2 接線後消除）。

---

### Task 2: 在 `analyze()` 主迴圈中接線新函式

**Files:**
- Modify: `crates/cairn-heur/src/correlation.rs`

- [ ] **Step 1: 找到主迴圈中計算 `best_path` 的位置（約 L112–L119），在其後加入 severity 計算**

在 `let mitre = mechanism_to_mitre(mechanism);` 這行之前插入：

```rust
let signed = group_signed(&group);
let (sev, sev_reason) = correlation_severity(&best_path, signed);
```

- [ ] **Step 2: 把 `reason_parts` 最後一行改為附加 sev_reason**

找到：
```rust
let reason = reason_parts.join(" ");
```

改為：
```rust
let reason = format!("{} — {}", reason_parts.join(" "), sev_reason);
```

- [ ] **Step 3: 把 `Finding::new(Severity::High, ...)` 改用 `sev`**

找到：
```rust
let mut f = Finding::new(
    Severity::High,
    format!("Confirmed persistence + execution: {key}"),
    FindingSource::Heuristic,
);
```

改為：
```rust
let mut f = Finding::new(
    sev,
    format!("Confirmed persistence + execution: {key}"),
    FindingSource::Heuristic,
);
```

- [ ] **Step 4: 執行 `cargo check -p cairn-heur`，確認零錯誤零警告**

```powershell
cargo check -p cairn-heur
```

---

### Task 3: 撰寫新測試並執行全套

**Files:**
- Modify: `crates/cairn-heur/src/correlation.rs`（`#[cfg(test)]` 區塊）

- [ ] **Step 1: 在現有 `tests` mod 內加入以下測試**

```rust
#[test]
fn signed_normal_path_is_medium() {
    let records = vec![
        persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Users\bosen\AppData\Local\Google\Chrome\Application\chrome.exe",
            Some(r"C:\Users\bosen\AppData\Local\Google\Chrome\Application\chrome.exe"),
        ),
        exec(
            r"C:\Users\bosen\AppData\Local\Google\Chrome\Application\chrome.exe",
            "amcache",
        ),
    ];
    // patch signed = Some(true) via a helper that sets it
    let records = records
        .into_iter()
        .map(|r| match r {
            Record::Persistence(mut p) => {
                p.signed = Some(true);
                Record::Persistence(p)
            }
            other => other,
        })
        .collect::<Vec<_>>();
    let findings = CorrelationAnalyzer.analyze(&records).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        Severity::Medium,
        "signed binary in normal path must be Medium, got {:?}",
        findings[0].severity
    );
}

#[test]
fn signed_appdata_local_programs_is_medium() {
    let records = vec![
        persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
            Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"),
        ),
        exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
    ];
    let records = records
        .into_iter()
        .map(|r| match r {
            Record::Persistence(mut p) => {
                p.signed = Some(true);
                Record::Persistence(p)
            }
            other => other,
        })
        .collect::<Vec<_>>();
    let findings = CorrelationAnalyzer.analyze(&records).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn unsigned_normal_path_is_high() {
    let records = vec![
        persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Users\bosen\AppData\Local\Google\Chrome\Application\chrome.exe",
            Some(r"C:\Users\bosen\AppData\Local\Google\Chrome\Application\chrome.exe"),
        ),
        exec(
            r"C:\Users\bosen\AppData\Local\Google\Chrome\Application\chrome.exe",
            "amcache",
        ),
    ];
    let records = records
        .into_iter()
        .map(|r| match r {
            Record::Persistence(mut p) => {
                p.signed = Some(false);
                Record::Persistence(p)
            }
            other => other,
        })
        .collect::<Vec<_>>();
    let findings = CorrelationAnalyzer.analyze(&records).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn unknown_signed_normal_path_is_high() {
    // signed = None (EVTX-only / offline) — fail-loud
    let records = vec![
        persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Program Files\SomeApp\app.exe",
            Some(r"C:\Program Files\SomeApp\app.exe"),
        ),
        exec(r"C:\Program Files\SomeApp\app.exe", "prefetch"),
    ];
    // signed defaults to None in persist() helper
    let findings = CorrelationAnalyzer.analyze(&records).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn suspicious_path_signed_is_high() {
    // 路徑在 Temp，即使已簽章也應維持 High
    let records = vec![
        persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Users\x\AppData\Local\Temp\evil.exe",
            Some(r"C:\Users\x\AppData\Local\Temp\evil.exe"),
        ),
        exec(r"C:\Users\x\AppData\Local\Temp\evil.exe", "prefetch"),
    ];
    let records = records
        .into_iter()
        .map(|r| match r {
            Record::Persistence(mut p) => {
                p.signed = Some(true);
                Record::Persistence(p)
            }
            other => other,
        })
        .collect::<Vec<_>>();
    let findings = CorrelationAnalyzer.analyze(&records).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        Severity::High,
        "suspicious path must stay High even if signed"
    );
}

#[test]
fn reason_contains_severity_rationale() {
    let records = vec![
        persist(
            "run_key",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe",
            Some(r"C:\Users\bosen\AppData\Local\Programs\Notion\Notion.exe"),
        ),
        exec("NOTION.EXE-AABBCCDD.pf", "prefetch"),
    ];
    let records = records
        .into_iter()
        .map(|r| match r {
            Record::Persistence(mut p) => {
                p.signed = Some(true);
                Record::Persistence(p)
            }
            other => other,
        })
        .collect::<Vec<_>>();
    let findings = CorrelationAnalyzer.analyze(&records).unwrap();
    let reason = findings[0].reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("signed") || reason.contains("legitimate"),
        "reason must explain severity rationale: {reason}"
    );
}
```

- [ ] **Step 2: 執行 `cargo test -p cairn-heur` 確認所有測試通過**

```powershell
cargo test -p cairn-heur
```

期望：所有既有測試 + 6 個新測試全綠。

- [ ] **Step 3: 執行 workspace 全套測試**

```powershell
cargo test --workspace
```

期望：448+ tests pass，0 failures。

- [ ] **Step 4: 執行 clippy**

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

期望：零警告。

---

### Task 4: 手動驗證 + commit

**Files:** 無新檔案

- [ ] **Step 1: 執行 `cairn run`（需 Admin），確認 Chrome/Notion 改為 Medium**

```powershell
.\dist\cairn-forensics\cairn.exe run --out .\out-tune-test\
```

開啟 `out-tune-test\report.html`，確認：
- Chrome / Notion / OneDrive 的 correlation finding → `Medium`
- 路徑在 Temp 的項目（若有）→ 仍為 `High`

- [ ] **Step 2: git commit**

```powershell
git add crates/cairn-heur/src/correlation.rs docs/dev-history/specs/2026-06-28-correlation-severity-tuning-design.md docs/dev-history/plans/2026-06-28-correlation-severity-tuning.md
git commit -m "fix(heur): tune correlation severity by path trust and signature status

Chrome/Notion/OneDrive false-positive High findings reduced to Medium.
High maintained for: suspicious path, explicit unsigned, unknown signature.
Adds group_signed + correlation_severity pure fns; 6 new unit tests."
```

---

## 後續待辦（本 plan 不實作）

### P1 — heur_account.rs（帳號異動分析器）

從 EVTX EventRecord 中挑出近 90 天內的：
- EID 4720 — 建立本機帳號
- EID 4726 — 刪除本機帳號
- EID 4732 / 4728 — 加入本機 / 域 Admins 群組

每個事件發出獨立 Finding（High），附帶帳號名稱、操作者、時間。
這些事件目前靠 Sigma 規則命中，沒有「近 N 天內」的時間過濾啟發式。

**預估工作量：** 1 段，新建 `crates/cairn-heur/src/account.rs`。

### P2 — Correlation 時間維度

在 correlation finding 中加入 `last_write` 年齡判斷：
- persistence `last_write` ≤ 90 天 → 在 reason 中標注「近期建立」
- persistence `last_write` ≤ 90 天 + signed=None → 升一級

預估工作量：1 段，修改 `correlation.rs`。

### P3 — Process 首次出現 × 目前執行比對

從 execution records（prefetch `first_run`）找出「首次執行在 N 天內」且「目前仍在 process list」的程式，
發出「近期首次出現且仍在執行」Finding。

預估工作量：1 段，擴充 `correlation.rs` 或新建 `heur_recent_exec.rs`。
