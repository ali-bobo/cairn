# Cairn pre-engagement SOC allow-listing runbook (template)

Goal: before running Cairn on a client endpoint, get it recognized as benign by the
client's EDR/AV so it is not blocked or misclassified. Being allow-listed is part of
the engagement, not an evasion measure. Fill the bracketed fields per engagement.

## 1. Artifacts to provide the client SOC
- Binary name: `cairn.exe`, version `[x.y.z]`, build `[build_sha]`.
- SHA-256 of the exact binary: `[hash]` (publish; must match what you run).
- Authenticode signer: `[publisher / cert thumbprint]`, timestamped — **note: releases
  are UNSIGNED until a signing service is provisioned; until then allow-list by hash,
  not certificate** (see `docs/verifying-a-release.md`).
- Link to source + release notes: `[repo URL]`.
- Statement of intent and scope: `docs/threat-model.md` + this runbook.

> How to obtain the hash / version / (eventual) signer for the boxes above:
> see **`docs/verifying-a-release.md`**. The build commit is also embedded in the
> binary (`cairn --version`) and in every run's `manifest.tool.build_sha`.

## 2. Allow-list mechanisms (client applies, per their EDR)
- Microsoft Defender for Endpoint: add allow indicator by **file hash** AND by
  **signing certificate**; submit to MS WDSI as "software developer - false positive"
  if flagged.
- Other EDR (CrowdStrike/SentinelOne/etc.): hash and/or certificate allow rule,
  scoped to the IR window and the specific host(s).
- Prefer **certificate-based** allow when running multiple releases.

## 3. Authorization & scope (record before running)
- Authorizing party: `[name/role]`; date/time window: `[UTC range]`.
- In-scope hosts: `[list]`. Out-of-scope: `[list]`.
- Privileges granted: Administrator? `[y/n]` SeBackupPrivilege? `[y/n]`.
- Output destination (off-target): `[share/USB/SFTP]`. Encryption pubkey: `[id]`.

## 4. Run record (filled by analyst, goes to manifest too)
- Operator: `[name]`  Case ID: `[id]`
- Exact command line: `[...]`
- Start/finish UTC: `[...]`  Host clock skew noted: `[...]`

## 5. Expected EDR behavior
Cairn WILL generate telemetry (file reads, raw volume handle, process/registry
enumeration). This is expected and correct. Coordinate so the SOC distinguishes
Cairn's authorized activity from real threat activity during the window.

## 6. Sigma 規則資料前提

部分 Sigma 規則依賴非預設的 Windows 稽核設定才能有事件可比對，缺少這些設定時
規則不會誤判也不會漏報——單純是沒有資料可比對（graceful degrade，非工具缺陷）：

- **PowerShell Script Block Logging**（`EnableScriptBlockLogging=1`）：PowerShell
  4104 相關規則的前提。預設稽核設定下，4104 事件僅記錄「可疑」腳本片段，非完整
  逐字稿——這是 Windows 稽核設計本身的限制，非 Cairn 的缺陷。
- **Process Creation 稽核 + 命令列記錄**（`ProcessCreationIncludeCmdLine_Enabled=1`）：
  process_creation 分類規則（EID 4688）的前提。
- **對應 Windows 安全稽核原則**：`service: security`/`service: system` 類規則
  （認證/登入事件、服務安裝事件等）需要主機已啟用對應的稽核子類別。
- 詳細規則對照見 `docs/sigma-rule-catalog.md`。

## 7. Cairn 對每個行程做的記憶體讀取（PEB cmdline 擷取）

Cairn 掃描到的每個 Windows 行程，會嘗試一次 `OpenProcess`
（`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`）+ `ReadProcessMemory`
讀取該行程的 PEB（Process Environment Block），取得完整命令列。

**為什麼需要**：IR 鑑識需要攻擊者實際下達的完整指令（例如完整的
PowerShell `-EncodedCommand` 內容），只有行程名稱不足以判斷是否為惡意。這是
`heur_parentchild`/`heur_persist` 等多個 heuristic 的主要訊號來源。

**保證**：純唯讀。`PROCESS_VM_READ` 不含任何寫入能力，Cairn 不會呼叫
`WriteProcessMemory` 或任何會修改目標行程的 API。程式碼位置：
`crates/cairn-collectors-win/src/cmdline_reader.rs`（供 SOC/資安人員逕行稽核）。

**對 AV/EDR 的影響**：`OpenProcess`+`ReadProcessMemory` 這組 API 組合是多數
EDR/AV 靜態與行為 heuristic 高度關注的訊號（跨行程記憶體讀取是常見的
credential-dumping/infostealer 手法）。這正是本工具最常觸發防禦軟體誤判的
行為之一——SOC 應預期在授權掃描期間看到這個行為，並將其識別為 Cairn 的正常
運作，而非入侵指標。

**已知限制**：受保護行程（PPL、防毒/EDR 自身行程等）會拒絕 `PROCESS_VM_READ`，
此時 Cairn 會 fallback 拿基本身分資訊（image path、integrity、start_time），
`cmdline` 欄位留空——這是預期的優雅降級，不是錯誤。
