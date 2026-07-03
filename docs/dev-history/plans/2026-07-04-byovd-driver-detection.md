# BYOVD Driver Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 比對 `amcache_driver` 收集的驅動 SHA1 與一份內嵌的高信心 known-vulnerable/
malicious 驅動雜湊清單，命中即發 High finding（BYOVD 偵測）。

**Architecture:** 純邏輯，零 unsafe、零新收集、零新依賴。清單以 `include_str!` 內嵌
（`--driver-list` 可選覆寫），`parse_driver_hashes(text)` 純函式解析成 `HashSet<String>`，
`ByovdHeuristic::new(hashset)` 帶狀態 analyzer 掃 `Record::Execution` 比對。

**Tech Stack:** Rust（cairn-heur / cairn-core / cairn-cli）、std HashSet。零外部依賴。

**Spec:** `docs/dev-history/specs/2026-07-04-byovd-driver-detection-design.md`

**每個 task 開工前：**
```powershell
$env:CARGO_TARGET_DIR = "C:\Users\$env:USERNAME\AppData\Local\cairn-target"
```
**每個 task 驗收：**`cargo check --workspace` → task 指定測試 → `cargo clippy --workspace --all-targets -- -D warnings`。

---

## File Structure

| 檔案 | 動作 | 責任 |
|---|---|---|
| `crates/cairn-heur/src/known-vulnerable-drivers.txt` | Create | 高信心驅動 SHA1 清單（內嵌資料）|
| `crates/cairn-heur/src/byovd.rs` | Create | `parse_driver_hashes` + `ByovdHeuristic` |
| `crates/cairn-heur/src/lib.rs` | Modify | `pub mod byovd;` + re-export |
| `crates/cairn-cli/src/main.rs` | Modify | `--driver-list` arg + analyzers vec 接線 |

**參考範本**：`crates/cairn-heur/src/account.rs`（analyzer 結構 + evidence 組裝）、
`TimestompHeuristic::new(...)` 於 main.rs（帶狀態 analyzer 接線模式）。

---

### Task 1: 驅動清單 + `parse_driver_hashes` 純函式

**Files:**
- Create: `crates/cairn-heur/src/known-vulnerable-drivers.txt`
- Create: `crates/cairn-heur/src/byovd.rs`
- Modify: `crates/cairn-heur/src/lib.rs`

- [ ] **Step 1: 建清單檔 `crates/cairn-heur/src/known-vulnerable-drivers.txt`**

高信心 BYOVD 驅動 SHA1（小寫 40-hex，一行一個，行內 `#` 註記驅動名 + 來源）。
以下為業界公認、有 CVE / 實際攻擊記錄的高頻 BYOVD 驅動——實作者**必須逐一核對這些
SHA1 對得上對應驅動**（來源：LOLDrivers 專案 loldrivers.io、對應 CVE 公告）。若無法在
實作環境查證某個雜湊的真實性，**寧可移除該行也不要放一個未查證的雜湊**（NFR12 誠實：
清單裡每個雜湊都必須是真的已知惡意/漏洞驅動，否則會誤報）：

```text
# Cairn — high-confidence known-vulnerable / known-malicious driver SHA1 list (BYOVD).
# Format: one lowercase 40-hex SHA1 per line. '#' starts a comment (line or inline).
# Source: LOLDrivers project (loldrivers.io) — only entries with a CVE or documented
# in-the-wild BYOVD use are included (high-confidence subset; false negatives are
# preferred over false positives, per the gate-redesign philosophy).
# Each hash MUST be verified against its named driver before inclusion (NFR12).
# Maintained: 2026-07-04. Update via --driver-list or by editing + recompiling.

# --- RTCore64.sys (MSI Afterburner) — CVE-2019-16098, used by many EDR-killers ---
01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0  # RTCore64.sys
# --- gdrv.sys (Gigabyte) — CVE-2018-19320, arbitrary R/W ---
b0acfd85b1f88d0d84f68f7028dd0f13a29d3f7b  # gdrv.sys
# --- dbutil_2_3.sys (Dell) — CVE-2021-21551 ---
0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5  # (SHA256 example — REMOVE if not 40-hex SHA1; see note)
```

**實作者關鍵注意**：
- amcache DriverId 給的是 **SHA1（40 hex）**，不是 SHA256。上面第三筆是 SHA256（64 hex），
  **是故意放的錯誤範例**——它會被 `parse_driver_hashes` 的 40-hex 驗證 skip 掉，但你**不該
  依賴 parser 過濾**，而應在清單裡只放真正的 SHA1。核對 LOLDrivers 時取每個驅動的 **SHA1**
  欄位（loldrivers.io 的 JSON 每個 sample 同時列 MD5/SHA1/SHA256，取 SHA1）。
- 前兩筆的 SHA1 值是**佔位範例，實作者必須用 loldrivers.io 的真實 SHA1 取代**，並至少納入
  5–10 個已查證的高信心驅動（RTCore64/gdrv/dbutil/mhyprot2/procexp/…）。查不到就少放，
  絕不放未查證的。
- 清單至少要有 1 個真實有效的 SHA1，否則 Task 2 的正向真機測試無從談起（但零誤報驗收
  不受影響）。

- [ ] **Step 2: 建 `byovd.rs`，寫 `parse_driver_hashes` + 其單元測試（先只有純函式）**

```rust
#![forbid(unsafe_code)]

use cairn_core::finding::{EvidenceItem, FindingSource, Severity};
use cairn_core::record::Record;
use cairn_core::traits::Analyzer;
use cairn_core::{Finding, Result};
use chrono::Utc;
use std::collections::HashSet;

/// The default known-vulnerable/malicious driver SHA1 list, embedded at compile time.
/// Pure data (a text list), not hardcoded logic — see spec §4.3.
pub const BUNDLED_DRIVER_LIST: &str = include_str!("known-vulnerable-drivers.txt");

/// Parse a driver-hash list into a set of lowercase 40-hex SHA1 strings.
/// Tolerates blank lines, `#` comment lines, and inline `# ...` annotations.
/// A malformed line (not exactly 40 ASCII hex chars after normalization) is skipped,
/// never fatal — one bad line must not discard the whole list (golden rule 8).
pub fn parse_driver_hashes(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in text.lines() {
        // Strip an inline comment: keep everything before the first '#'.
        let body = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
        if body.is_empty() {
            continue;
        }
        if body.len() == 40 && body.chars().all(|c| c.is_ascii_hexdigit()) {
            set.insert(body);
        }
        // else: skip silently — malformed entry, not fatal.
    }
    set
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parses_valid_lowercases_and_dedups() {
        let text = "\
# header comment
AABBCCDDEEFF00112233445566778899AABBCCDD  # RTCore64.sys
aabbccddeeff00112233445566778899aabbccdd  # duplicate (diff case) -> deduped

  0011223344556677889900112233445566778899  # indented, valid
";
        let set = parse_driver_hashes(text);
        assert_eq!(set.len(), 2, "dup collapses, 2 distinct hashes");
        assert!(set.contains("aabbccddeeff00112233445566778899aabbccdd"));
        assert!(set.contains("0011223344556677889900112233445566778899"));
    }

    #[test]
    fn skips_malformed_lines_without_dropping_good_ones() {
        let text = "\
zzzz  # not hex
0123  # too short
0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5  # 64-hex SHA256, wrong length
0011223344556677889900112233445566778899  # the one good line
this line has spaces in the middle 00112233
";
        let set = parse_driver_hashes(text);
        assert_eq!(set.len(), 1);
        assert!(set.contains("0011223344556677889900112233445566778899"));
    }

    #[test]
    fn empty_and_comment_only_yields_empty_set() {
        assert!(parse_driver_hashes("").is_empty());
        assert!(parse_driver_hashes("# just a comment\n\n   \n").is_empty());
    }

    #[test]
    fn bundled_list_parses_and_is_nonempty() {
        // The shipped list must contain at least one valid SHA1 (else the whole
        // feature is a no-op). Guards against an accidentally-empty/all-malformed file.
        let set = parse_driver_hashes(BUNDLED_DRIVER_LIST);
        assert!(!set.is_empty(), "bundled driver list must have >=1 valid SHA1");
    }
}
```

- [ ] **Step 3: `lib.rs` 加 `pub mod byovd;`（字母序，`account` 前）+ 暫不 re-export（Task 2 加）**

在 mod 宣告區加 `pub mod byovd;`（放在 `pub mod account;` 前保持字母序）。

- [ ] **Step 4: 跑測試**

Run: `cargo test -p cairn-heur byovd::`
Expected: 4 個 parse 測試全綠。**特別確認 `bundled_list_parses_and_is_nonempty` 通過**
——若失敗代表清單檔全是佔位/壞資料，回 Step 1 補真實 SHA1。

Run: `cargo clippy -p cairn-heur --all-targets -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-heur/src/known-vulnerable-drivers.txt crates/cairn-heur/src/byovd.rs crates/cairn-heur/src/lib.rs
git commit -m "feat(heur): BYOVD driver hash list + parse_driver_hashes pure fn"
```

---

### Task 2: `ByovdHeuristic` analyzer + 接線 + 驗收

**Files:**
- Modify: `crates/cairn-heur/src/byovd.rs`
- Modify: `crates/cairn-heur/src/lib.rs`
- Modify: `crates/cairn-cli/src/main.rs`

- [ ] **Step 1: 在 `byovd.rs` 加 `ByovdHeuristic` struct + `Analyzer` impl（parse_tests mod 之前）**

```rust
/// Analyzer: flags any loaded driver whose SHA1 matches the known-vulnerable/malicious
/// list. Carries the hash set as state (injected at construction — the CLI parses the
/// bundled or --driver-list file once and hands it in).
pub struct ByovdHeuristic {
    hashes: HashSet<String>,
}

impl ByovdHeuristic {
    pub fn new(hashes: HashSet<String>) -> Self {
        ByovdHeuristic { hashes }
    }
}

impl Analyzer for ByovdHeuristic {
    fn name(&self) -> &str {
        "heur_byovd"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        let now = Utc::now();
        let mut findings = Vec::new();
        for r in records {
            let Record::Execution(e) = r else { continue };
            if e.source != "amcache_driver" {
                continue;
            }
            // Only compare when the collector produced a real SHA1 (None = malformed
            // DriverId, honestly skipped per NFR12 — never a false match).
            let Some(sha1) = e.sha1.as_deref() else { continue };
            if !self.hashes.contains(sha1) {
                continue;
            }
            let basename = e
                .path
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(e.path.as_str());
            let mut f = Finding::new(
                Severity::High,
                format!("已知漏洞/惡意驅動: {basename}"),
                FindingSource::Heuristic,
            );
            f.artifact = "byovd".into();
            f.mitre = vec!["T1068".into(), "T1211".into()];
            f.reason = Some(format!(
                "driver SHA1 {sha1} matches the known-vulnerable/malicious driver list (BYOVD)"
            ));
            f.ts = e.last_run.or(e.first_run).unwrap_or(now);
            f.evidence = vec![EvidenceItem {
                artifact: "amcache_driver".into(),
                path: Some(e.path.clone()),
                ts: e.last_run.or(e.first_run),
                detail: format!("SHA1={sha1}"),
            }];
            findings.push(f);
        }
        Ok(findings)
    }
}
```

- [ ] **Step 2: 在 `byovd.rs` 加 analyzer 單元測試（新 `#[cfg(test)] mod analyze_tests`）**

```rust
#[cfg(test)]
mod analyze_tests {
    use super::*;
    use cairn_core::record::{ExecutionRecord, Record};

    fn driver_exec(source: &str, path: &str, sha1: Option<&str>) -> Record {
        Record::Execution(ExecutionRecord {
            source: source.into(),
            path: path.into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: sha1.map(String::from),
            user_sid: None,
            execution_confirmed: Some(true),
        })
    }

    fn heur_with(hashes: &[&str]) -> ByovdHeuristic {
        ByovdHeuristic::new(hashes.iter().map(|h| h.to_string()).collect())
    }

    const KNOWN: &str = "aabbccddeeff00112233445566778899aabbccdd";

    #[test]
    fn known_driver_hash_is_high_with_mitre_and_evidence() {
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec("amcache_driver", r"C:\Windows\System32\drivers\rtcore64.sys", Some(KNOWN))];
        let findings = heur.analyze(&recs).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].artifact, "byovd");
        assert!(findings[0].mitre.contains(&"T1068".to_string()));
        assert!(findings[0].title.contains("rtcore64.sys"));
        assert!(findings[0].reason.as_deref().unwrap().contains(KNOWN));
        assert_eq!(findings[0].evidence[0].artifact, "amcache_driver");
        assert!(findings[0].evidence[0].detail.contains(KNOWN));
    }

    #[test]
    fn unknown_hash_yields_nothing() {
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec("amcache_driver", r"C:\x\clean.sys", Some("0000000000000000000000000000000000000000"))];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }

    #[test]
    fn none_sha1_is_skipped_not_matched() {
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec("amcache_driver", r"C:\x\d.sys", None)];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }

    #[test]
    fn non_amcache_driver_source_ignored() {
        // Same hash, but from a non-driver execution source -> not our concern.
        let heur = heur_with(&[KNOWN]);
        let recs = vec![driver_exec("prefetch", r"C:\x\app.exe", Some(KNOWN))];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }

    #[test]
    fn empty_list_never_matches() {
        let heur = heur_with(&[]);
        let recs = vec![driver_exec("amcache_driver", r"C:\x\d.sys", Some(KNOWN))];
        assert!(heur.analyze(&recs).unwrap().is_empty());
    }
}
```

- [ ] **Step 3: `lib.rs` 加 re-export**

在 `pub use` 區加（字母序，`account` 前）：
```rust
pub use byovd::ByovdHeuristic;
```

- [ ] **Step 4: `main.rs` 加 `--driver-list` CLI arg**

找到 `RunArgs`（或 live run 的 clap args struct——搜 `struct RunArgs` 或 `full_speed: bool`
所在的 struct）。在其中加一個欄位：
```rust
    /// Override the built-in known-vulnerable driver hash list (BYOVD detection).
    /// One lowercase 40-hex SHA1 per line; '#' comments allowed.
    #[arg(long)]
    driver_list: Option<std::path::PathBuf>,
```

- [ ] **Step 5: `main.rs` 載入清單 + 接進 analyzers vec**

在建構 analyzers vec（約 854 行，`let mut analyzers: Vec<...> = vec![...]`）**之前**，加載入邏輯：
```rust
            // BYOVD driver hash list: --driver-list override, else the bundled list.
            // Read failure falls back to bundled (graceful, golden rule 8).
            let driver_hashes = match args.driver_list.as_deref() {
                Some(p) => match std::fs::read_to_string(p) {
                    Ok(text) => cairn_heur::byovd::parse_driver_hashes(&text),
                    Err(e) => {
                        tracing::warn!(error = %e, path = %p.display(),
                            "driver-list read failed; using bundled list");
                        cairn_heur::byovd::parse_driver_hashes(cairn_heur::byovd::BUNDLED_DRIVER_LIST)
                    }
                },
                None => cairn_heur::byovd::parse_driver_hashes(cairn_heur::byovd::BUNDLED_DRIVER_LIST),
            };
```

在 analyzers vec 的 `Box::new(cairn_heur::AccountHeuristic),` 之後加：
```rust
                Box::new(cairn_heur::ByovdHeuristic::new(driver_hashes)),
```

（`args` 是該 match arm 的 RunArgs 綁定名——對照 `args.bodyfile`/`args.rules` 等既有用法
確認實際變數名；`driver_hashes` 在 vec 建構前算好，move 進 Box::new。）

- [ ] **Step 6: 更新 main.rs 的 collector/analyzer 清單測試（若有）**

搜 `live_analyzers_include_all_heuristics`（或斷言 analyzer 名稱集合的測試）。若存在，
加入 `heur_byovd` 的斷言，並在該測試建構 analyzers vec 處補
`Box::new(cairn_heur::ByovdHeuristic::new(std::collections::HashSet::new())),`
（空清單即可，測試只驗名稱在集合內）。若無此測試則跳過。

- [ ] **Step 7: 全 workspace 驗證**

```powershell
cargo test --workspace --exclude cairn-updater
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: 全綠、零警告（含 Task 1 的 4 個 parse 測試 + 本 task 的 5 個 analyze 測試）。

- [ ] **Step 8: 真機零誤報驗收**

```powershell
cargo build --release -p cairn-cli
Copy-Item "$env:CARGO_TARGET_DIR\release\cairn.exe" .\dist\cairn-forensics\cairn.exe -Force
# 需 admin + SeBackupPrivilege 才會有 amcache_driver records；一般 admin 亦可跑（該 collector graceful skip）
.\dist\cairn-forensics\cairn.exe run --target live --output .\out-byovd\
```

驗收：
1. `findings.jsonl`：**乾淨機器應無 `artifact=byovd` 的 finding**（本機驅動 SHA1 都不在
   清單裡——除非這台機器真的載過已知漏洞驅動，那會是真陽性，非誤報）。
   檢查：`python -c "import json; print([json.loads(l)['artifact'] for l in open('out-byovd/findings.jsonl',encoding='utf-8') if json.loads(l)['artifact']=='byovd'])"`
   → 預期 `[]`。
2. 若 amcache_driver collector 因 SeBackupPrivilege 缺失而 skip（manifest sources 有
   `insufficient privilege` 訊息），則 byovd 無輸入資料 → 零 finding，屬正確 graceful，
   非缺陷（記錄於驗收但不算失敗）。
3. `--driver-list` 覆寫路徑手動驗一次：造一個含「本機某真實驅動 SHA1」的臨時清單檔
   （從上次 records.jsonl 撈一個 amcache_driver 的 sha1），`--driver-list <該檔>` 重跑，
   確認該驅動被標成 High（證明比對管線真的通）。用完刪除臨時檔。

- [ ] **Step 9: 更新 REMAINING-WORK.md + 最終 commit**

在 REMAINING-WORK.md 記錄「BYOVD 驅動偵測完成」，並註明後續兩個 fileless spec（Sigma
擴充 / WMI+爆破）仍待做、以及清單維護是持續工作（未來可考慮 update-rules 式更新）。

```bash
git add -A
git commit -m "feat(heur): ByovdHeuristic — flag loaded drivers matching known-vulnerable list (BYOVD)

amcache_driver SHA1 x bundled high-confidence list -> High (T1068/T1211).
--driver-list overrides the built-in list. Pure logic, zero unsafe, zero
new deps. Clean-machine e2e: zero byovd findings.

Spec: docs/dev-history/specs/2026-07-04-byovd-driver-detection-design.md"
```

---

## Self-Review 紀錄（plan 完成後自查）

1. **Spec 覆蓋**：§4.1 清單（T1 S1）、§4.2 parse_driver_hashes（T1 S2）、§4.3 include_str!
   \+ --driver-list 覆寫（T1 S2 常數 + T2 S4/S5）、§5.1 heuristic 邏輯（T2 S1）、§5.1
   sha1.is_some 跳過（T2 S1 + none_sha1 測試）、§5.2 獨立 analyzer 不進 gate（T2 S1/S3 接線）、
   §7 測試矩陣（T1 4 測 + T2 5 測 + 真機）、§8 分段（T1/T2）。無缺口。
2. **Placeholder**：清單的真實 SHA1 標「實作者必須用 loldrivers.io 真實值取代 + 查證」
   ——這是刻意的、有明確查證指示的資料填充（不能在無網環境憑空生成真雜湊），非程式碼
   placeholder。第三筆 SHA256 是**故意的教學性錯誤範例**，測試 `skips_malformed` 已涵蓋。
3. **型別一致**：`parse_driver_hashes(&str)->HashSet<String>`、`ByovdHeuristic::new(HashSet)`、
   `BUNDLED_DRIVER_LIST` 常數、`artifact="byovd"`、`name()="heur_byovd"` 各處引用一致；
   evidence/finding 欄位對照 account.rs 範本；analyzers vec 接線用 `ByovdHeuristic::new`
   帶狀態模式（對齊 TimestompHeuristic::new）。
