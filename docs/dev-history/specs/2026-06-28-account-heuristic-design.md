# Account Activity Heuristic — Design Spec

> **Date:** 2026-06-28
> **Status:** Approved — ready for implementation
> **Scope:** New `crates/cairn-heur/src/account.rs` + wiring in `lib.rs` + `main.rs`
> **SRS refs:** §10 (heuristics), FR9 (persistence/account triage), golden rule 6/8

---

## 1. 問題陳述

目前帳號異動事件（建立、刪除、加入 Admins 群組）只靠 Sigma 規則偵測。
Sigma 規則沒有「時間過濾」能力：一個兩年前建立的本機帳號和昨天偷偷建立的帳號
對 Sigma 來說一樣，都靠規則本身的條件來決定要不要觸發。

調查工程師真正想看的是：**近期**（入侵事件可能發生的時間窗口內）有沒有帳號被建立、
刪除、或加入高權限群組——這是 post-exploitation 的標準手法（T1136.001、T1098.001）。

---

## 2. 目標事件

從 Security channel 的 EventRecord 中篩選：

| EID | 事件 | ATT&CK | Severity |
|-----|------|--------|----------|
| 4720 | 本機使用者帳號被建立 | T1136.001 | **High** |
| 4726 | 本機使用者帳號被刪除 | T1531 | **High** |
| 4732 | 成員被加入本機安全性群組（含 Administrators） | T1098.001 | **High** |
| 4728 | 成員被加入全域安全性群組（含 Domain Admins） | T1098.001 | **High** |

> 所有四個事件一律 High：帳號操作本身就是高風險動作，時間窗口是附加脈絡。
> 超過時間窗口的事件降為 Medium（背景資訊，不需立刻處理）。

---

## 3. 時間窗口

- **近期（recent）**：距離分析時間點 ≤ `ACCOUNT_RECENT_DAYS`（預設 **90 天**）→ High
- **歷史（historical）**：> 90 天 → **Medium**（仍輸出，讓調查者有完整圖像）

90 天是業界常見的「攻擊者活動回溯窗口」，涵蓋大多數 APT 駐留偵測需求。
可未來透過 Config 注入，本 spec 先用常數。

---

## 4. EventData 欄位映射

cairn 的 `EventRecord.data` 是 flattened JSON map，key 名對應 EVTX XML 的 `<Data Name="...">` 值。

### EID 4720 / 4726（帳號建立/刪除）
```
TargetUserName   → 被建立/刪除的帳號名稱
TargetDomainName → 帳號所屬網域（本機帳號為電腦名稱）
SubjectUserName  → 執行操作的帳號（操作者）
SubjectDomainName→ 操作者所屬網域
```

### EID 4732 / 4728（加入群組）
```
MemberName       → 被加入的帳號（格式：domain\username 或 SID）
MemberSid        → 被加入的帳號 SID
TargetUserName   → 群組名稱（4732: 本機群組；4728: 全域群組）
SubjectUserName  → 執行操作的帳號
```

---

## 5. Finding 結構

每個事件輸出一個 `Finding`，欄位如下：

| 欄位 | 值 |
|------|-----|
| `severity` | High（近期）/ Medium（歷史） |
| `title` | `"帳號建立: <name>"` / `"帳號刪除: <name>"` / `"加入群組: <group> ← <member>"` |
| `source` | `FindingSource::Heuristic` |
| `artifact` | `"account"` |
| `mitre` | 對應 ATT&CK ID |
| `reason` | 說明為何是 High 或 Medium（時間窗口） |
| `details` | 完整欄位：操作者 / 目標帳號 / 群組 / 時間 |
| `host` | 由 orchestrator 事後填入（同其他 analyzer） |
| `ts` | EventRecord.ts（事件發生時間） |

---

## 6. 設計決策

### 6.1 只看 Security channel
EventRecord.channel 必須是 `"Security"`，避免其他 channel 碰巧有相同 EID 的事件干擾。

### 6.2 SubjectUserName 過濾
- `SubjectUserName` 為 `"-"` 或空白 → 系統/匿名操作，不過濾，仍輸出（可能是 PsExec 或 SYSTEM 操作）
- `SubjectUserName` 為 `"SYSTEM"` → 仍輸出（攻擊者常用 SYSTEM context）

### 6.3 MemberName 解析（4732/4728）
MemberName 有兩種格式：
- `domain\username`（一般帳號）
- SID 字串（`S-1-5-...`，帳號已被刪除或本機）

解析時兩種都直接顯示原始值，不做額外 SID 解析（需要 SAM lookup，在 offline 模式不可行）。

### 6.4 不做的事（YAGNI）
- 不做 4733（從群組移除成員）——移除是可疑的降權，但調查優先度低，留後續
- 不做 4740（帳號鎖定）——需另一個 analyzer 處理暴力破解模式
- 不解析 SID → 名稱（需 live SAM lookup）
- 不加 `Config.account_recent_days` CLI flag（先用常數，未來擴充）

---

## 7. 架構

```
cairn-heur/src/account.rs
  └── AccountHeuristic (impl Analyzer)
        └── analyze(&[Record]) -> Vec<Finding>
              ├── 過濾 Record::Event + channel="Security" + EID in {4720,4726,4732,4728}
              ├── extract_account_event(EventRecord) -> Option<AccountEvent>
              │     ├── 4720/4726: target_name + subject_name
              │     └── 4732/4728: member_name + group_name + subject_name
              ├── 計算 is_recent(ts, now) → bool
              └── 組裝 Finding
```

---

## 8. 接線位置

1. `cairn-heur/src/lib.rs`：`pub mod account;` + `pub use account::AccountHeuristic;`
2. `cairn-cli/src/main.rs`：在 analyzers Vec 中加入 `Box::new(cairn_heur::AccountHeuristic)`
3. `main.rs` 測試 `live_analyzers_include_all_heuristics`：加入 `heur_account` 斷言

---

## 9. 測試矩陣

| 測試 | 場景 | 預期 |
|------|------|------|
| `create_account_recent_is_high` | EID 4720，30 天前 | High, mitre=T1136.001 |
| `create_account_old_is_medium` | EID 4720，120 天前 | Medium |
| `delete_account_recent_is_high` | EID 4726，7 天前 | High, mitre=T1531 |
| `add_to_local_group_is_high` | EID 4732，1 天前 | High, mitre=T1098.001 |
| `add_to_global_group_is_high` | EID 4728，1 天前 | High, mitre=T1098.001 |
| `non_security_channel_ignored` | EID 4720，但 channel=System | 空 Vec |
| `wrong_eid_ignored` | EID 4625（登入失敗），channel=Security | 空 Vec |
| `non_event_record_ignored` | Record::Process | 空 Vec |
| `reason_mentions_time_window` | 任意場景 | reason 含 "90" 或 "recent" |
| `finding_has_artifact_account` | 任意場景 | artifact == "account" |

---

## 10. 驗收門檻

- `cargo test --workspace` 全綠（含上述 10 個新測試）
- `cargo clippy --workspace --all-targets -- -D warnings` 零警告
- `cairn run` 執行後，若有近期帳號操作則出現在 HTML 報告的 High findings
- schema 零變動
