# 段 2：Sigma 規則大擴充 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `rules/ruleset.toml` 從 43 條規則擴充到 73 條（新增 30 條已查證候選），每條新規則都有合成事件測試證明真的會 fire，並產出一份涵蓋全部 73 條的規則清冊文件。

**Architecture:** `ruleset.toml` 只是選集清單（規則路徑 + SigmaHQ pin commit），實際規則內容由 `cairn update-rules` 從 SigmaHQ 抓取、XOR 編碼寫入 `rules/sigma/`。本計畫的驗證策略經探查確認：專案裡從來沒有真實 `.evtx` fixture 餵給 Sigma 引擎比對——現有 `parity.rs` 全部三個測試都是手動建構 `EventRecord`（synthetic）。因此原 spec 講的「雙層驗證（fixture 優先/合成事件後備）」在實作上收斂成單一路徑：**全部 30 條新規則都用合成 `EventRecord` 驗證**，這與現有測試慣例一致，不是妥協。

**Tech Stack:** Rust、`cairn-sigma` crate（`Engine`/`SigmaMatcher`/`EventRecord`）、TOML（`ruleset.toml`）、Markdown（規則清冊）。

---

## 前置事實（來自探查，任務執行時不需重查）

- **match-parity 測試檔**：`crates/cairn-sigma/tests/parity.rs`（123 行）。核心流程：
  ```rust
  fn proc_creation(fields: serde_json::Value) -> EventRecord {
      let serde_json::Value::Object(map) = fields else {
          panic!("fields must be a JSON object");
      };
      EventRecord {
          ts: Utc::now(),
          channel: "Microsoft-Windows-Sysmon/Operational".into(),
          event_id: 1,
          provider: "Microsoft-Windows-Sysmon".into(),
          computer: "WS01".into(),
          record_id: 1,
          data: map,
      }
  }

  fn load_bundled() -> Engine {
      let mut engine = Engine::default();
      let n = engine
          .load(&bundled_rules_dir(), false)
          .expect("bundled rules load (decode)");
      assert!(n >= 3, "expected >= 3 bundled rules, loaded {n}");
      engine
  }
  ```
  一個 firing 測試的完整範例（`parity.rs:42-58`）：
  ```rust
  #[test]
  fn hh_chm_execution_fires() {
      let engine = load_bundled();
      let ev = proc_creation(json!({
          "Image": r"C:\Windows\hh.exe",
          "OriginalFileName": "HH.exe",
          "CommandLine": r"hh.exe C:\Users\victim\AppData\Local\Temp\evil.chm"
      }));
      let hits = engine.match_event(&ev).unwrap();
      let hit = hits
          .iter()
          .find(|f| f.rule_id.as_deref() == Some("68c8acb4-1b60-4890-8e82-3ddf7a6dba84"))
          .expect("HH.EXE rule should fire");
      assert!(
          hit.rule_author.as_deref().is_some_and(|a| !a.is_empty()),
          "DRL 1.1: author must be present"
      );
  }
  ```
  `SigmaMatcher::match_event(&EventRecord) -> Result<Vec<Finding>>`（`crates/cairn-sigma/src/lib.rs:19-28`）。`EventRecord` 欄位：`ts: DateTime<Utc>`、`channel: String`、`event_id: u32`、`provider: String`、`computer: String`、`record_id: u64`、`data: serde_json::Map<String, Value>`。

- **合成事件的 channel/event_id/data 要對應該規則的 `detection` 條件**——這些值必須從 SigmaHQ 規則原始 YAML 的 `logsource` + `detection.selection` 欄位讀出來，本計畫每個 Task 都內嵌了從候選清單（`docs/dev-history/2026-07-11-sigma-candidate-rules.md`）交叉查證後的具體欄位值。

- **`rules/ruleset.toml` 現況**：43 條 `[[rules]]`，pin = `98781da19cf60c48ce6e7f2d3ad11c9ba389191a`（`rules/ruleset.toml:13`），檔頭第 6 行寫「expanded from 18 to 44 rules」（統計漂移，需修正為 43，本計畫完成後再改為 73）。

- **候選規則清單權威來源**：`docs/dev-history/2026-07-11-sigma-candidate-rules.md`，30 條，已逐條確認 author 存在、非 Sysmon、非 deprecated。

- **`cargo update-rules` 需要真實網路**，本計畫的 Task 不依賴它驗證正確性（合成事件測試已足夠證明 detection 邏輯正確）；Task 9 才實際跑一次驗證管線接線正常，且標記為可能因網路環境失敗、失敗時記錄原因即可、不阻擋其他 Task。

- **`CARGO_TARGET_DIR` 需設在 OneDrive 外**：`$env:CARGO_TARGET_DIR = "C:\Users\<you>\AppData\Local\cairn-target"`（PowerShell）；Bash 內用 `export CARGO_TARGET_DIR=/c/Users/<you>/AppData/Local/cairn-target`。

- **測試分工**：每個 Task 的 implementer 只跑 `cargo test -p cairn-sigma`（本計畫全部改動都在 `cairn-sigma` crate 內，含 `ruleset.toml` 因為它被 `parity.rs` 的 `bundled_rules_dir()` 間接讀取，但實際規則檔案來自 `rules/sigma/` 而非直接讀 `ruleset.toml`——見 Task 1 說明）。全 workspace 驗證留給 finishing 階段。

---

## 規則分組與 Task 拆分策略

30 條規則依 spec 四大主題分成 4 個實作 Task（每個 Task 內把該主題全部規則的 `ruleset.toml` 新增 + 合成事件測試一次做完，因為同主題規則往往共用 channel/builder，拆更細反而增加樣板重複）。之後接規則清冊文件、檔頭修正、SOC runbook 補充、全 workspace 驗證。

---

### Task 1: PowerShell 4104 Script Block 規則（8 條）

**Files:**
- Modify: `rules/ruleset.toml`（新增 8 個 `[[rules]]` 區塊）
- Modify: `crates/cairn-sigma/tests/parity.rs`（新增 builder + 8 個 firing 測試 + 1 個 benign 測試）

**背景**：這 8 條規則的 `logsource` 是 `product: windows, category: ps_script`。查 `LogsourceMap::windows_builtin()`（`crates/cairn-sigma/src/lib.rs:77-287`）目前的 seed 條目：`powershell` 對映到 channel `"Microsoft-Windows-PowerShell/Operational"`（`lib.rs:227-233`），event_id 統一填 0（整頻道，非特定 EventID）。4104 (script block logging) 事件正是打在這個頻道。合成事件時 `channel` 用此值、`event_id` 用 4104。

- [ ] **Step 1: 新增 8 條規則到 `rules/ruleset.toml`**

在檔案最後（第 220 行 DCSync 區塊後）新增：

```toml
# ============================================================
# PowerShell 4104 script block (malicious script content)
# ============================================================

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_malicious_keywords.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_disable_psreadline_command_history.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_create_local_user.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml"

[[rules]]
path = "windows/powershell/powershell_script/posh_ps_download_com_cradles.yml"
```

- [ ] **Step 2: 用 `cairn update-rules` 抓取這 8 條規則的實際內容**（需要網路；若此步驟因網路限制失敗，改為 Step 2b）

```bash
cd c:/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo run --bin cairn --features updater -- update-rules
```

Expected: 8 個新檔案出現在 `rules/sigma/windows/powershell/powershell_script/`，且 `rules/sigma/PROVENANCE` 更新 `fetched_at`。

- [ ] **Step 2b（若 Step 2 網路失敗）：手動用 WebFetch 讀取這 8 條規則的原始 YAML**，取得每條規則的 `id`（UUID）與 `detection.selection` 實際欄位/字串，來源：
  `https://raw.githubusercontent.com/SigmaHQ/sigma/98781da19cf60c48ce6e7f2d3ad11c9ba389191a/rules/windows/powershell/powershell_script/<filename>.yml`
  記錄每條的 `id:` 值，供 Step 3 測試斷言使用。若這步也做不到（完全離線環境），本 Task 的合成事件測試改為斷言 `hits` 非空（不比對特定 `rule_id`），並在 commit message 註明「rule_id 未經網路核實，改用非空斷言」——不可编造 UUID。

- [ ] **Step 3: 在 `parity.rs` 新增 PowerShell script block builder 與測試**

在 `parity.rs` 的 `proc_creation` 函式後新增：

```rust
fn ps_script(fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(map) = fields else {
        panic!("fields must be a JSON object");
    };
    EventRecord {
        ts: Utc::now(),
        channel: "Microsoft-Windows-PowerShell/Operational".into(),
        event_id: 4104,
        provider: "Microsoft-Windows-PowerShell".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}
```

然後為每條規則新增一個 firing 測試，範例（`posh_ps_potential_invoke_mimikatz.yml` — 依 spec 描述偵測 dump credentials/certificates 指令樣式，實際欄位以 Step 2/2b 取得的規則 YAML 為準，implementer 需對照 `detection.selection` 填正確欄位名與字串）：

```rust
#[test]
fn powershell_invoke_mimikatz_keyword_fires() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Invoke-Mimikatz -DumpCreds"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        !hits.is_empty(),
        "expected Invoke-Mimikatz script block rule to fire"
    );
    assert!(
        hits.iter().all(|h| h.rule_author.as_deref().is_some_and(|a| !a.is_empty())),
        "DRL 1.1: author must be present on every fired rule"
    );
}
```

對其餘 7 條規則重複此模式（各自一個測試函式，函式名反映規則主題：`powershell_amsi_bypass_pattern_fires`、`powershell_disable_psreadline_history_fires`、`powershell_create_local_user_fires`、`powershell_clear_history_fires`、`powershell_rubeus_keyword_fires`、`powershell_com_download_cradle_fires`、`powershell_malicious_keywords_fires`）。**每條測試的 `data` 欄位內容必須是實際會讓該規則 `detection` 條件為真的字串**——implementer 對照 Step 2/2b 取得的規則 YAML `detection.selection` 逐條核對，不可用猜測值敷衍過測試。

再新增一個陰性測試：

```rust
#[test]
fn benign_powershell_script_fires_nothing() {
    let engine = load_bundled();
    let ev = ps_script(json!({
        "ScriptBlockText": "Get-Process | Where-Object { $_.CPU -gt 100 }"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        hits.is_empty(),
        "benign PowerShell script should not fire any rule, got {hits:?}"
    );
}
```

- [ ] **Step 4: 跑測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo test -p cairn-sigma
```

Expected: 全部通過，含新增的 9 個測試（8 firing + 1 benign）。若某條規則測試失敗，回頭核對該規則的 `detection.selection` 邏輯（可能是 AND/OR 組合，欄位值需同時滿足多個 selection）。

- [ ] **Step 5: Commit**

```bash
git add rules/ruleset.toml crates/cairn-sigma/tests/parity.rs rules/sigma/
git commit -m "feat(sigma): add 8 PowerShell 4104 script block rules"
```

---

### Task 2: 認證/登入規則（6 條）

**Files:**
- Modify: `rules/ruleset.toml`
- Modify: `crates/cairn-sigma/tests/parity.rs`

**背景**：`logsource: service: security`。`LogsourceMap` 的 `security` seed 對映 channel `"Security"`，`event_id: 0`（整頻道，`lib.rs:217`）。合成事件用 `channel: "Security"`，`event_id` 依規則實際偵測的 EventID（4769/4720/5140 等，從規則 YAML 取得）。

- [ ] **Step 1: 新增 6 條規則到 `rules/ruleset.toml`**

在 Task 1 新增區塊後接續新增：

```toml
# ============================================================
# Authentication / logon abuse (Security.evtx)
# ============================================================

[[rules]]
path = "windows/builtin/security/win_security_kerberoasting_activity.yml"

[[rules]]
path = "windows/builtin/security/win_security_kerberos_asrep_roasting.yml"

[[rules]]
path = "windows/builtin/security/win_security_admin_share_access.yml"

[[rules]]
path = "windows/builtin/security/win_security_impacket_secretdump.yml"

[[rules]]
path = "windows/builtin/security/win_security_hidden_user_creation.yml"

[[rules]]
path = "windows/builtin/security/win_security_lsass_access_non_system_account.yml"
```

- [ ] **Step 2: 抓取規則內容**（同 Task 1 Step 2/2b 模式：優先 `cargo run --bin cairn --features updater -- update-rules`，失敗則 WebFetch 逐條讀取 `id:` 與 `detection.selection`）

- [ ] **Step 3: 新增 6 個 firing 測試 + 1 個 benign 測試到 `parity.rs`**

沿用現有 `parity.rs` 的模式（不需新 builder，`channel: "Security"` 可直接在測試內建構 `EventRecord`，或新增一個 `security_event(event_id: u32, fields)` builder 因為每條規則的 event_id 不同）：

```rust
fn security_event(event_id: u32, fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(map) = fields else {
        panic!("fields must be a JSON object");
    };
    EventRecord {
        ts: Utc::now(),
        channel: "Security".into(),
        event_id,
        provider: "Microsoft-Windows-Security-Auditing".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}
```

範例測試（`win_security_hidden_user_creation.yml`，EventID 4720，偵測使用者名稱以 `$` 結尾）：

```rust
#[test]
fn hidden_user_creation_fires() {
    let engine = load_bundled();
    let ev = security_event(4720, json!({
        "TargetUserName": "svc-backup$"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(
        !hits.is_empty(),
        "expected hidden user creation rule to fire for TargetUserName ending in $"
    );
}
```

對其餘 5 條規則比照辦理（`kerberoasting_activity_fires` [EventID 4769]、`asrep_roasting_fires` [4768]、`admin_share_access_fires` [5140]、`impacket_secretdump_fires` [5140]、`lsass_access_non_system_account_fires` [4656 或 10，依規則實際 logsource 核對]）——**implementer 必須對照 Step 2 取得的實際規則 YAML 決定正確 EventID 與欄位**，上面括號內數字為候選清單描述的推測值，非最終權威。

再新增陰性測試：

```rust
#[test]
fn benign_logon_event_fires_nothing() {
    let engine = load_bundled();
    let ev = security_event(4624, json!({
        "TargetUserName": "alice",
        "LogonType": "2"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(hits.is_empty(), "benign interactive logon should not fire, got {hits:?}");
}
```

- [ ] **Step 4: 跑測試**

```bash
cargo test -p cairn-sigma
```

Expected: 全部通過。

- [ ] **Step 5: Commit**

```bash
git add rules/ruleset.toml crates/cairn-sigma/tests/parity.rs rules/sigma/
git commit -m "feat(sigma): add 6 authentication/logon abuse rules"
```

---

### Task 3: System 7045 服務安裝規則（4 條）

**Files:**
- Modify: `rules/ruleset.toml`
- Modify: `crates/cairn-sigma/tests/parity.rs`

**背景**：`logsource: service: system`（`service_control_manager` 子目錄）。`LogsourceMap` 的 `system` seed 對映 channel `"System"`，`event_id: 0`（`lib.rs:218`）。合成事件用 `channel: "System"`，`event_id: 7045`（服務安裝；`win_system_krbrelayup_service_installation.yml` 可能用不同 EventID，需查證）。

- [ ] **Step 1: 新增 4 條規則到 `rules/ruleset.toml`**

```toml
# ============================================================
# Service installation (System.evtx, EventID 7045)
# ============================================================

[[rules]]
path = "windows/builtin/system/service_control_manager/win_system_service_install_hacktools.yml"

[[rules]]
path = "windows/builtin/system/service_control_manager/win_system_service_install_susp.yml"

[[rules]]
path = "windows/builtin/system/service_control_manager/win_system_service_install_uncommon.yml"

[[rules]]
path = "windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml"
```

- [ ] **Step 2: 抓取規則內容**（同前 Task 模式）

- [ ] **Step 3: 新增 builder + 4 個 firing 測試 + 1 個 benign 測試**

```rust
fn system_event(event_id: u32, fields: serde_json::Value) -> EventRecord {
    let serde_json::Value::Object(map) = fields else {
        panic!("fields must be a JSON object");
    };
    EventRecord {
        ts: Utc::now(),
        channel: "System".into(),
        event_id,
        provider: "Service Control Manager".into(),
        computer: "WS01".into(),
        record_id: 1,
        data: map,
    }
}
```

範例測試（`win_system_service_install_uncommon.yml`，偵測 ImagePath 含具名管道路徑）：

```rust
#[test]
fn uncommon_service_install_path_fires() {
    let engine = load_bundled();
    let ev = system_event(7045, json!({
        "ImagePath": r"\\.\pipe\evil_pipe_service"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(!hits.is_empty(), "expected uncommon service ImagePath rule to fire");
}
```

比照辦理 `hacktool_service_install_fires`（ImagePath 含 `cachedump`/`gsecdump`/`pwdump` 或 `bypass`）、`suspicious_service_install_fires`（ImagePath 含 PowerShell 混淆旗標如 `-enc`/`-nop`/`-w hidden`）、`krbrelayup_service_install_fires`（ServiceName 為 `KrbSCM`）。

陰性測試：

```rust
#[test]
fn benign_service_install_fires_nothing() {
    let engine = load_bundled();
    let ev = system_event(7045, json!({
        "ServiceName": "MyAppUpdater",
        "ImagePath": r"C:\Program Files\MyApp\updater.exe"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(hits.is_empty(), "benign service install should not fire, got {hits:?}");
}
```

- [ ] **Step 4: 跑測試**

```bash
cargo test -p cairn-sigma
```

- [ ] **Step 5: Commit**

```bash
git add rules/ruleset.toml crates/cairn-sigma/tests/parity.rs rules/sigma/
git commit -m "feat(sigma): add 4 service installation (System 7045) rules"
```

---

### Task 4: Process Creation 其他高價值規則（12 條）

**Files:**
- Modify: `rules/ruleset.toml`
- Modify: `crates/cairn-sigma/tests/parity.rs`

**背景**：`logsource: category: process_creation`。直接複用現有 `proc_creation()` builder（`parity.rs:27-40`），不需新 builder。

- [ ] **Step 1: 新增 12 條規則到 `rules/ruleset.toml`**

```toml
# ============================================================
# Additional process_creation coverage (LOLBAS / persistence / evasion)
# ============================================================

[[rules]]
path = "windows/process_creation/proc_creation_win_certutil_decode.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_browsers_tor_execution.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_cloudflared_tunnel_run.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_7zip_password_compression.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_amsi_registry_tampering.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_auditpol_susp_execution.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_at_interactive_execution.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_autologger_session_registry_modification.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_cdb_arbitrary_command_execution.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_adplus_memory_dump.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_certreq_download.yml"
```

- [ ] **Step 2: 抓取規則內容**（同前模式）

- [ ] **Step 3: 新增 12 個 firing 測試 + 1 個 benign 測試**（複用 `proc_creation()` builder）

範例（`proc_creation_win_certutil_decode.yml`）：

```rust
#[test]
fn certutil_decode_fires() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": r"certutil.exe -decode C:\Users\victim\payload.b64 C:\Users\victim\payload.exe"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(!hits.is_empty(), "expected certutil -decode rule to fire");
}
```

比照辦理其餘 11 條，函式名對應規則主題：`tor_browser_execution_fires`、`cloudflared_tunnel_run_fires`、`sevenzip_password_compression_fires`、`bitsadmin_persistence_fires`、`amsi_registry_tampering_fires`、`auditpol_tampering_fires`、`at_interactive_execution_fires`、`autologger_registry_modification_fires`、`cdb_arbitrary_command_fires`、`adplus_memory_dump_fires`、`certreq_download_fires`。每條的 `Image`/`CommandLine`（或該規則實際用到的欄位）需對照 Step 2 取得的規則 YAML `detection.selection` 填寫。

陰性測試：

```rust
#[test]
fn benign_process_creation_extra_batch_fires_nothing() {
    let engine = load_bundled();
    let ev = proc_creation(json!({
        "Image": r"C:\Windows\System32\notepad.exe",
        "CommandLine": r"notepad.exe C:\Users\alice\notes.txt"
    }));
    let hits = engine.match_event(&ev).unwrap();
    assert!(hits.is_empty(), "benign notepad launch should not fire, got {hits:?}");
}
```

- [ ] **Step 4: 跑測試**

```bash
cargo test -p cairn-sigma
```

- [ ] **Step 5: Commit**

```bash
git add rules/ruleset.toml crates/cairn-sigma/tests/parity.rs rules/sigma/
git commit -m "feat(sigma): add 12 additional process_creation high-value rules"
```

---

### Task 5: 修正 `ruleset.toml` 檔頭統計與 scope 註解

**Files:**
- Modify: `rules/ruleset.toml:1-11`

- [ ] **Step 1: 更新檔頭註解**

現有（`rules/ruleset.toml:6-7`）：
```toml
# Updated: 2026-06-28 — expanded from 18 to 44 rules.
# Scope: no-Sysmon environments (Security.evtx + PowerShell + process_creation via EID 4688).
```

改為：

```toml
# Updated: 2026-07-11 — expanded from 43 to 73 rules (segment 2: PowerShell 4104
# script block, authentication/logon abuse, System 7045 service installs, and
# additional process_creation coverage — see docs/dev-history/specs/
# 2026-07-11-sigma-ruleset-expansion-design.md).
# Scope: no-Sysmon environments (Security.evtx + System.evtx + PowerShell
# Operational/classic + process_creation via EID 4688). Sysmon rules deliberately
# excluded — see design doc for rationale.
```

- [ ] **Step 2: 確認規則總數**

```bash
grep -c '^\[\[rules\]\]' rules/ruleset.toml
```

Expected: `73`

- [ ] **Step 3: Commit**

```bash
git add rules/ruleset.toml
git commit -m "docs(sigma): correct ruleset.toml header rule count (43 -> 73)"
```

---

### Task 6: 規則清冊文件 `docs/sigma-rule-catalog.md`

**Files:**
- Create: `docs/sigma-rule-catalog.md`

這個 Task 需要讀取全部 73 條規則（既有 43 + 新增 30）並比對現有測試覆蓋狀況，資訊量大、需要交叉核對多個檔案，適合獨立一個 Task 執行。

- [ ] **Step 1: 列出既有 43 條規則清單並比對現有測試覆蓋**

```bash
grep -A1 '^\[\[rules\]\]' rules/ruleset.toml | grep 'path =' | head -43
```

對每一條，搜尋 `crates/cairn-sigma/tests/parity.rs` 是否有對應的 firing 測試（用規則檔名關鍵字比對測試函式名或測試內註解引用的檔名）。**如實記錄**——若某條既有規則在 `parity.rs` 裡找不到對應測試，規則清冊該行的「驗證方式」欄要寫「無現存測試，狀態不明」，不可編造已驗證的假象。

- [ ] **Step 2: 撰寫 `docs/sigma-rule-catalog.md`**

文件結構（表格形式，一行一條規則，共 73 行 + 表頭）：

```markdown
# Sigma 規則清冊

> 涵蓋 `rules/ruleset.toml` 全部規則（既有 43 條 + 段 2 新增 30 條 = 73 條）。
> 「是否確認會 fire」欄位如實記錄——沒有測試覆蓋的規則明確標示，不倒填假驗證。
> 更新規則集時（新增/移除），本檔案需同步更新。

| 規則 path | 標題 | 觸發情境 | 資料前提 | 驗證方式 | 確認會 fire |
|---|---|---|---|---|---|
| windows/process_creation/proc_creation_win_hh_chm_execution.yml | HH.EXE CHM Execution | hh.exe 開啟 .chm 檔案（T1218.001 LOLBAS 濫用） | Process Creation 稽核 + 命令列記錄需開啟 | parity.rs::hh_chm_execution_fires | 是 |
| ...(既有 42 條比照，逐條列出，Step 1 查到的結果如實填入)... |
| windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml | Potential Invoke-Mimikatz PowerShell Script | script block 出現 Mimikatz 憑證竊取指令樣式 | PowerShell Script Block Logging (EnableScriptBlockLogging=1) 需開啟；4104 預設僅記可疑片段非完整逐字稿 | parity.rs::powershell_invoke_mimikatz_keyword_fires | 是 |
| ...(Task 1-4 新增的 30 條逐條列出)... |
```

每一行的「觸發情境」欄可直接參考 `docs/dev-history/2026-07-11-sigma-candidate-rules.md` 裡對應規則的一句話說明（新增規則）；既有 43 條的觸發情境從規則檔名與 `rules/ruleset.toml` 現有分節註解推斷（例如 `# LOLBAS / script engine execution` 分節下的規則，觸發情境是對應 LOLBAS 工具的濫用）。

「資料前提」欄對 PowerShell 4104 規則統一註記稽核設定需求；對 Security/System 頻道規則註記「需啟用對應 Windows 安全稽核原則」；對 process_creation 規則註記「需啟用 Process Creation 稽核 + 命令列記錄（ProcessCreationIncludeCmdLine_Enabled=1）」（沿用 `ruleset.toml:8-10` 既有註解的前提說明）。

- [ ] **Step 2: Commit**

```bash
git add docs/sigma-rule-catalog.md
git commit -m "docs(sigma): add rule catalog covering all 73 bundled rules"
```

---

### Task 7: SOC runbook 補充 4104 資料前提說明

**Files:**
- Modify: `docs/SOC-runbook-template.md`

- [ ] **Step 1: 讀取現有 EDR allowlist 說明段落定位插入點**

```bash
grep -n "EDR" docs/SOC-runbook-template.md
```

- [ ] **Step 2: 在合適位置（現有稽核設定相關章節，或新增一小節）新增一行說明**

```markdown
## Sigma 規則資料前提

部分 Sigma 規則依賴非預設的 Windows 稽核設定才能有事件可比對，缺少這些設定時
規則不會誤判也不會漏報——單純是沒有資料可比對（graceful degrade，非工具缺陷）：

- **PowerShell Script Block Logging**（`EnableScriptBlockLogging=1`）：PowerShell
  4104 相關規則的前提。預設稽核設定下，4104 事件僅記錄「可疑」腳本片段，非完整
  逐字稿——這是 Windows 稽核設計本身的限制，非 Cairn 的缺陷。
- **Process Creation 稽核 + 命令列記錄**（`ProcessCreationIncludeCmdLine_Enabled=1`）：
  process_creation 分類規則（EID 4688）的前提。
- 詳細規則對照見 `docs/sigma-rule-catalog.md`。
```

- [ ] **Step 3: Commit**

```bash
git add docs/SOC-runbook-template.md
git commit -m "docs(soc-runbook): note Sigma rule audit-policy prerequisites"
```

---

### Task 8: LogsourceMap 補充驗證（確認整頻道映射足夠支撐新規則）

**Files:**
- Modify: `crates/cairn-sigma/src/lib.rs`（新增測試，不改動映射邏輯本身）

**背景**：探查已確認 `LogsourceMap` 目前只到整頻道粒度（`service: security` → channel `"Security"`, event_id 0），沒有個別 EventID 的專屬映射。這不影響 Sigma 比對本身（`match_event` 用規則自己的 `detection` 邏輯比對 `EventRecord.data`，不依賴 LogsourceMap 做欄位比對）——LogsourceMap 只決定「監看哪些頻道」。本 Task 只需新增測試確認 `ps_script`／`security`／`system` 三個 logsource 確實能解析到正確頻道，不需要新增任何映射邏輯。

- [ ] **Step 1: 確認 `ps_script` logsource 是否已被 `LogsourceMap` 涵蓋**

```bash
grep -n "ps_script\|powershell" crates/cairn-sigma/src/lib.rs | head -20
```

若 `ps_script` category 未被 `resolve()` 處理（只有 `service: powershell` 有映射，`category: ps_script` 是不同的 logsource selector 組合），需確認 `resolve()` 的比對邏輯是否會漏掉這個 logsource 組合——**這一步只是驗證，不是預先假設有問題**。若發現真的沒有映射到，這是本 Task 唯一允許新增邏輯的情況，範圍限定在讓 `ps_script` category 正確解析到 `Microsoft-Windows-PowerShell/Operational` 頻道，不擴大改動其他部分。

- [ ] **Step 2: 新增驗證測試**

```rust
#[test]
fn resolves_ps_script_to_powershell_operational_channel() {
    let map = LogsourceMap::windows_builtin();
    let hits = map.resolve(Some("ps_script"), None, None);
    let channels: Vec<&str> = hits.iter().map(|e| e.channel.as_str()).collect();
    assert!(
        channels.iter().any(|c| c.contains("PowerShell")),
        "expected a PowerShell channel for ps_script logsource, got {channels:?}"
    );
}
```

Expected: 若 Step 1 發現 `ps_script` 早已能透過既有 `service: powershell` selector 解析（因為多數規則的 logsource 同時帶 `product: windows, category: ps_script` 且 sigma-rust 引擎本身可能不強制要求 LogsourceMap 完全對映才能比對——引擎比對邏輯與 LogsourceMap 是兩回事，LogsourceMap 只用於頻道監看清單），此測試應直接通過，不需改動 `lib.rs` 映射邏輯。若測試失敗，implementer 需回報 BLOCKED 並說明具體失敗原因，不要自行擴大改動範圍去湊過測試。

- [ ] **Step 3: 跑測試**

```bash
cargo test -p cairn-sigma
```

- [ ] **Step 4: Commit**

```bash
git add crates/cairn-sigma/src/lib.rs
git commit -m "test(sigma): verify ps_script logsource resolves to PowerShell channel"
```

---

### Task 9: update-rules 管線驗證 + 全 workspace 驗證

**Files:**
- 無新增修改（純驗證 Task）

- [ ] **Step 1: 確認規則總數與 PROVENANCE 一致性**

```bash
grep -c '^\[\[rules\]\]' rules/ruleset.toml
find rules/sigma -name "*.yml" | wc -l
```

Expected: 兩者皆為 `73`（若 Task 1-4 的 Step 2 因網路限制走了 2b 路徑，`rules/sigma/` 底下可能沒有對應的新增檔案——此時記錄這個落差，在 commit 或最終報告註明「N 條規則的實際 XOR 編碼檔案待網路可用時執行 `cairn update-rules` 補齊」，不視為本階段失敗）。

- [ ] **Step 2: 若網路可用，跑一次完整 update-rules 確保管線正確處理全部 73 條**

```bash
cargo run --bin cairn --features updater -- update-rules
```

Expected: exit code 0，無 DRL 1.1 author 檢查失敗（`fetch.rs:37-48` 的檢查）。

- [ ] **Step 3: 全 workspace 驗證（本計畫唯一一次全量跑，因為改動範圍是 crate-internal 但涉及規則檔案落地，值得在此確認一次沒有波及其他 crate）**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: 全部通過，`cargo fmt --check` 尤其不可省略（2026-07-08 教訓：main 曾因漏檢此項紅 4 天）。

- [ ] **Step 4: 若 Step 3 全綠，此 Task 無需 commit（純驗證）；若發現問題，回到對應 Task 修正後重新驗證**

---

## Self-Review

**1. Spec coverage：**
- 不加 Sysmon → Task 1-4 只選非 Sysmon 規則，符合。
- 四主題全開、不設數量上限 → Task 1(8) + Task 2(6) + Task 3(4) + Task 4(12) = 30，符合候選清單全數。
- 雙層驗證策略 → 探查發現專案裡從無真實 fixture 比對模式，全部合成事件測試，已在計畫開頭「Architecture」段落明確記錄這個收斂，非遺漏。
- 規則清冊文件涵蓋新增+既有 43 條 → Task 6 涵蓋。
- 檔頭統計修正 → Task 5。
- update-rules 管線驗證 → Task 9。
- SOC runbook 補充 4104 資料前提 → Task 7（spec 已知坑段落提及，原 spec 主文沒有獨立列成任務但明確要求，已補上）。
- NFR9 掃描時間影響「先實測不預先假設」→ Task 9 Step 3 的 `cargo test --workspace` 執行時間可作為粗略訊號，若明顯劣化在 Task 9 報告中記錄，不另立任務。

**2. Placeholder 掃描：** 所有 Step 都有具體指令或程式碼；Task 1-4 部分測試的欄位值標註「需對照規則 YAML 核對」是誠實的資訊缺口（因為規則實際內容需要網路查證，計畫階段無法百分之百預先寫死），不是偷懶的 TODO——每處都給了具體的推測起點與核對方法，不是空白。

**3. Type 一致性：** `EventRecord` 欄位命名（`ts`/`channel`/`event_id`/`provider`/`computer`/`record_id`/`data`）全部 Task 一致；三個新 builder（`ps_script`/`security_event`/`system_event`）簽名與既有 `proc_creation` 一致（回傳 `EventRecord`，輸入 `serde_json::Value` 或 `(event_id, Value)`）。

**4. 執行順序相依性：** Task 1-4 互相獨立（不同規則主題，不同測試函式名，同一檔案 `parity.rs` 但插入點不同）——若 subagent-driven 執行時要序列化以避免同檔案 merge 衝突（cairn-dev-loop 既有教訓：同一 branch 不可平行 commit 同檔案）。Task 5-9 依賴 Task 1-4 全部完成（Task 5 的規則計數、Task 6 的清冊涵蓋範圍都需要最終的 73 條）。
