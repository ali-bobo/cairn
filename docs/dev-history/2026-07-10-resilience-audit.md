# Cairn 獨立健全性審計報告

- 日期：2026-07-10
- 分支：`feature/usability-governance`
- 審計者：獨立 fresh-context 稽核（未參與實作）
- 本輪優先考量（使用者指定）：**偵測有效性**與**能否被有效使用**，配重最高。
- 範圍：只審查，未修改任何程式碼或文件。

## 摘要（findings 分佈）

| 嚴重度 | 數量 |
|---|---|
| 高 | 3 |
| 中 | 5 |
| 低 | 4 |
| 合計 | 12 |

最重要 5 條：
1. （高）**live 行程的 `cmdline`／`integrity` 永遠為空** → parentchild 一半訊號在 live 掃描下永不觸發。
2. （高）**live 行程無法取得 `cmdline`/`integrity`/`user`/`start_time`** → IR 面板與 details 對分析師價值大減。
3. （高）**掃描無進度回饋、無資源足跡、無逾時**——大型 raw-NTFS 掃描下使用者無從得知卡在哪。
4. （中）**版本資源授權字串與實際授權不符**（PE resource 寫死 Apache-2.0，實際已改 MIT）。
5. （中）**Sigma 與 heuristic 對「排程任務 / WMI / 服務直接濫用」存在雙盲區**。

REMAINING-WORK 段 1-7 校正結論（詳見文末專節）：段 1、2、3、5、6、7 描述**相符**；段 4 **需更新**（塊 A/C 前提仍成立但應補記 live proc 欄位缺口對塊 C 的影響）。此外「已知殘留風險登記」漏列本報告 F-1/F-2 兩個高風險，建議補登。

---

## 1. 偵測有效性（本輪核心）

### 1a. 資料來源鏈：欄位 → collector → 失效模式

parentchild heuristic（`crates/cairn-heur/src/parentchild.rs`）評分依賴 `ProcessRecord` 的
`ppid`／`image`／`cmdline`／`signed`／`integrity`。實際資料來源鏈如下：

| 欄位 | 填值位置 | 失效模式 | heuristic 行為 |
|---|---|---|---|
| `pid`/`ppid`/`image` | `cairn-collectors-win/src/proc.rs:138-146`（Toolhelp 快照 + `QueryFullProcessImageNameW`）| 開不了行程時 `image` 退回 Toolhelp 短檔名（非絕對路徑）；`proc.rs:137` | 短檔名 → `is_masquerade`/`is_suspicious_path` 一律 abstain（`trust.rs:74`）。fail-open（漏報），非誤報 |
| `cmdline` | **從不填**：`proc.rs:143` 恆 `None`；`collectors/src/proc.rs:101` 把 `None` 正規化成 `""` | 永遠為空字串 | **F-1**：`has_encoded_powershell`、`lolbas_suspicious`、`has_base64_token` 對空字串全回 false → encoded-PS(+40)、LOLBAS(+30) 訊號在 **live 掃描永不觸發**。fail-open |
| `integrity` | **從不填**：`proc.rs:144` `integrity_raw` 恆 `None`；`collectors/src/proc.rs:105` map 成 `None` | 永遠 `None` | **F-1**：`parentchild.rs:143` unsigned-high-integrity(+15) 永不觸發。fail-open |
| `signed` | 有填：`collectors/src/proc.rs:77` `apply_signatures` 經 `WinSigVerifier`（僅絕對路徑，`proc.rs:29`）| 短檔名 image 留 `None`；catalog-signed OS binary 被 `WTD_CHOICE_FILE` 報 unsigned（程式碼註解 `parentchild.rs:137` 已知）| unsigned 只當放大器，需先有其他訊號才計入，設計正確 |
| `user`/`start_time` | **從不填**：`proc.rs:145-146` 恆 `None` | 永遠空 | `f.ts` 退回 `Utc::now()`（`parentchild.rs:203`），時間軸失真；temporal-correlator 段 3 的已知前提之一 |

**F-1（高）**：`crates/cairn-collectors-win/src/proc.rs:143-146` — live proc collector 不採集
`cmdline` 與 `integrity`。後果是 parentchild 在 **live 模式下實際只剩三個訊號**：masquerade（S3）、
Office/script-host→shell 的 image-name 配對、以及依賴它們的 path/unsigned 放大器。使用者質疑的
「parentchild 實戰有效性」在此得到印證：**改名 binary + 空 cmdline 的真實 live 快照，parentchild
幾乎只能靠 image-name 白名單命中**，encoded-PS / LOLBAS-args 這些最有價值的行為訊號全數靜默。
（註：`cmdline`/`integrity` 欄位在 EVTX 4688 路徑另有來源，故 offline EVTX 分析不受此限；缺口專屬 live proc。）
一行修法：在 `cairn-collectors-win/src/proc.rs` 補 `NtQueryInformationProcess`(PEB→ProcessParameters)
讀 cmdline、`GetTokenInformation(TokenIntegrityLevel)` 讀 integrity RID，best-effort 缺值仍 graceful。

### 1b. 寫死清單覆蓋缺口（已排除其他偵測層涵蓋後）

`OFFICE_PARENTS`/`SCRIPT_PARENTS`/`LOLBAS_WATCH`（`parentchild.rs:17-41`）與 `trust.rs`
`PROTECTED_SYSTEM_NAMES`（`trust.rs:14-26`）對照 ATT&CK 高頻手法，**在排除 Sigma ruleset 與其他
heuristic 已涵蓋者後**，仍完全偵測不到：

- **F-2（中）WMI 事件訂閱持久化（T1546.003）**：無 collector、無 heuristic、ruleset 也無 WMI logsource
  規則（`ruleset.toml` 無 `wmi_` 規則）。REMAINING-WORK 段 4 塊 A 已知，但屬「目前完全偵測不到」。
- **F-3（中）排程任務內容濫用（T1053.005）的直接偵測**：`schtasks.exe` 建立有 Sigma 規則
  （`ruleset.toml:109`）與 persist S9，但**經 COM/直接 XML 寫入**（不經 schtasks.exe）的排程任務，
  persist collector 雖解析 XML，其惡意判定仍走 S9 script-interpreter gate（`persist.rs:41`），
  對「合法直譯器跑本地 .exe payload」不編碼/不遠端者不 gate。
- **F-4（低）改名的 LOLBAS/system binary**：`file_name()` 僅比對 basename（`parentchild.rs:44`，
  程式碼註解 `parentchild.rs:12-15` 已誠實標示）。`rundll32.exe` 改名成 `svc.exe` 即繞過 LOLBAS_WATCH；
  masquerade 只認**受保護名稱**放錯位置，抓不到「非系統名改名」。無 hash/signer enrichment 補位。
- **F-5（低）WMI/CIM 執行（T1047）**：`wmic.exe`/`WmiPrvSE.exe` 子行程不在任何清單。

其中 F-4/F-5 屬「清單粒度」限制，程式碼已誠實標示為 future signal；F-2/F-3 屬結構性盲區。

### 1c. Sigma 規則面

`rules/ruleset.toml` 實際 pin **43 條**規則（檔頭註解自稱 44，統計漂移仍未修——REMAINING-WORK 段 2
已載明「檔頭自稱 44」，但這裡實數是 43，兩處都需對齊）。logsource 涵蓋：process_creation（EID 4688，
最大宗）、Security builtin（帳戶/服務/NTLM/DCSync/RDP/PtH）、PowerShell classic 1 條。

**與 heuristic 的雙盲區**：
- **無 Sysmon 規則**（檔頭已聲明，設計取捨）。
- **無 PowerShell 4104 script-block 規則**：ruleset 只有 classic channel 1 條
  （`ruleset.toml:64`），fileless spec 塊 B 點名的 4104 尚未納入 → PowerShell 混淆腳本內容
  （非 process_creation cmdline 可見者）heuristic 與 Sigma **兩邊都不管**。
- **F-6（中）登入爆破無偵測**：NTLM brute（`ruleset.toml:207`）有 Sigma，但**互動/RDP 登入
  4625 計數爆破**無 heuristic（段 4 塊 C，未實作）；account heuristic 只看帳戶建立/群組變更。

### 1d. heuristic 交互與執行順序

`crates/cairn-core/src/orchestrator.rs:63-81`：所有 analyzer 讀**同一份累積 records**，彼此不
消費對方輸出。persist gate（`persist.rs:100 evaluate_gate`）的跨文物佐證來自
`build_cross_index`（`persist.rs:227`），索引建自 records 內的 Execution/Process 記錄，**不依賴
其他 analyzer 的 Finding**。因此 **analyzer 執行順序不影響正確性**，此類未發現問題。
唯一時間敏感點是 `analyze()`/`observe()` 各自取 `Utc::now()`（`persist.rs:363` 註解已標），
S4 7 天邊界毫秒級漂移，屬已登記可接受殘留。

---

## 2. 可用性（能否被有效使用）

### 2a. 非資深使用者雙擊 launcher 後的判斷力

摘要框（`crates/cairn-launcher/src/menu.rs:66 print_summary`）給出 verdict（Clean/Alert）、
top 5 critical/high 標題、medium/low 計數，Alert 時明確指示「請立即聯絡資安工程師」
（`menu.rs:92`）。**對「要不要升級」這個判斷，這個設計是足夠的**——二元 verdict + 明確行動指示。

但兩處雜訊/缺失影響判斷品質：
- **F-1 的下游效應（高，計入 2b 不重複計數）**：live 掃描下 parentchild 半數訊號靜默，代表
  摘要框的 Alert 覆蓋率被低估——一個真實 encoded-PS 攻擊在 live 快照可能不進 critical/high，
  使用者看到 Clean 而誤判不需升級。這是可用性層最嚴重的問題，根因是偵測層 F-1。
- **F-7（低）管理員權限不足時的靜默降級未在摘要框凸顯**：`menu.rs:74` 只印「否（部分功能受限）」，
  但未說明**哪 7 個 raw-NTFS collector 因缺 SeBackupPrivilege 產出 0 筆**（CLAUDE.md 已載明此限制）。
  非資深使用者會把「因權限跳過」誤讀為「乾淨」。一行修法：摘要框讀 manifest `sources[].errors`／
  privileges，列出被跳過模組數。

### 2b. 進度回饋、資源足跡、失敗定位

- **F-8（高）無進度回饋與逾時**：`runner::run_scan`（`runner.rs:51-60`）以繼承 stdout 的
  `Command::status()` 阻塞等待，launcher 只印一句「執行掃描中，請稍候...」（`main.rs:82`）。
  raw-NTFS/verbose profile 掃描可能數分鐘，期間**無百分比、無當前模組、無逾時中斷**；使用者無從
  分辨「還在跑」與「卡死」。cairn.exe 自身若有 stdout log 會透出，但 launcher 未做結構化進度。
  一行修法：cairn.exe 對 launcher 輸出 per-collector 進度行（stderr JSON lines），launcher 解析顯示。
- **資源足跡**：governance（`manifest.governance`：effective_threads/low_priority/truncations）
  有記錄進 manifest，但**摘要框未顯示**耗時或 truncation 警告——truncation 代表資料被截斷、可能漏抓，
  對分析師是重要信號卻只埋在 manifest。此類部分覆蓋。
- **失敗定位**：collector 失敗經 `orchestrator.rs:46-57` graceful 記入 `sources[].errors`，
  launcher 的 `run_scan` 若 exit code 非 0 會 `bail`（`runner.rs:56`），主迴圈印錯誤
  （`main.rs:215`）。單一 collector 失敗不會讓 exit 非 0（graceful），故**部分失敗使用者不會被告知**，
  需自行開 manifest 看 errors——非資深使用者做不到。

### 2c. `cairn verify` 對收 zip 的分析師是否可操作

`docs/verifying-a-release.md` 完整：hash 比對（§1）、版本/commit（§2）、簽章（§3，誠實標示
UNSIGNED）、`cairn verify out/manifest.json --rules rules/sigma`（§4，chain of custody）。
指令具體可照做，SOC runbook（`docs/SOC-runbook-template.md`）交叉引用清楚。**此類未發現阻擋性問題**。
唯一小缺口：**F-9（低）** verify 文件假設分析師手上有 `rules/sigma` 目錄，但 launcher 打包的 zip
（`package::zip_output`）是否含 rules 未在本審計確認；若 zip 不含規則，`--rules` 步驟分析師無法執行。
建議文件註明 zip 內容清單。

---

## 3. 錯誤處理缺口（unwrap/expect/吞 Err）

逐一檢視非測試程式碼路徑：

- `cairn-collectors-win/src/proc.rs:54,66` `let _ = CloseHandle(...)`：Drop 中忽略關閉錯誤，
  **合理**（RAII 清理，無可行動處理）。
- `cairn-launcher/src/menu.rs` 多處 `let _ = io::stdout().flush()`／`read_line`：**合理**
  （終端 I/O，失敗無意義補救）。
- `cairn-launcher/src/main.rs:191` 的 `since_from_hours` 等：正常 Result 傳播。
- `volume.rs` 的 `.unwrap()`/`.expect()`：**全數在 `#[cfg(test)]` 內**（`volume.rs:619-796`），
  非生產路徑。
- `summary.rs` 的 `serde_json` 解析：`load_summary`（`summary.rs:26`）用 `?` 傳播、逐欄
  `unwrap_or` 提供預設，findings 逐行 `match ... continue`（`summary.rs:79`）容錯——**設計良好**。
- **F-10（低）** `main.rs:194`：`detect_env` 失敗時 `return Ok(())`（吞掉錯誤只印訊息不回非零
  exit code）。launcher 作為互動工具尚可接受（使用者看得到訊息），但若被腳本呼叫會誤判成功。屬邊界。

**結論：未發現違反 golden rule 8 的生產路徑 unwrap/expect**。所有 `let _ = Err` 均為合理的 I/O
或 RAII 清理場景。此類整體健康。

---

## 4. 發佈流程缺口（Legitimacy work 逐項）

| 項目 | 狀態 | 證據 |
|---|---|---|
| Authenticode 簽章 + timestamp | **未完成（已佈線）** | `docs/verifying-a-release.md:38-48` 明載「releases are currently UNSIGNED，release.yml 已佈線但 gated 待簽章服務」 |
| 版本/manifest 資源嵌入 | **已完成（但有 bug）** | `crates/cairn-cli/build.rs:41-68` 用 winresource 嵌 PE version-info；build_sha 進 manifest。**F-11（中）：`build.rs:53` `LegalCopyright` 寫死 "Apache-2.0 licensed"，但實際授權已改 MIT**（`Cargo.toml:19` `license = "MIT"`、`LICENSE:1` 為 MIT License）→ 授權字串不一致，發佈前必修 |
| hash 發佈 | **部分完成** | `verifying-a-release.md:9` 描述 `cairn.exe.sha256` 發佈機制；實際 release workflow 未在本審計驗證產出 |
| open-source | **已完成** | `LICENSE`（MIT）存在；README intent statement（CLAUDE.md 標 done） |
| SOC pre-allowlist runbook | **已完成** | `docs/SOC-runbook-template.md` 存在且內容完整（§1 artifacts、§2 allow-list 機制） |
| MS WDSI 送審 | **未開始** | 全 repo 無 WDSI 提交紀錄或腳本（grep `WDSI` 僅命中 CLAUDE.md/SRS 的待辦描述） |

發佈流程與 REMAINING-WORK 段 F 一致（「給真實客戶用前必做，自用階段跳過」）；**唯 F-11 授權字串
不一致是已合併程式碼裡的實際 bug，非待辦**，應優先修。

---

## 5. REMAINING-WORK.md 段 1-7 差距校正

| 段 | 結論 | 原因 |
|---|---|---|
| 段 1（HTML 報告強化）| **相符** | INDEX.md:48 記 `html-report-filtering` 已合併（`74aefba`），篩選/聚合/state_active/netconn 改名皆已做；段 1 描述的待辦已落地 |
| 段 2（Sigma 擴充）| **相符（小數字漂移）** | ruleset 現況與段 2 描述吻合（無 Sysmon、頻道管線現成）；唯段 2 稱「檔頭自稱 44」，實際 pin 數為 43、檔頭也是 44——兩處數字都待對齊，但屬註解層 |
| 段 3（temporal-correlator）| **相符** | spec 待審狀態不變；三前提（start_time 恆 None、NetConn 無時間戳、gate 對 mechanism 透明）經本審計覆核仍成立（`proc.rs:146`、orchestrator 無時間關聯）|
| 段 4（WMI + 登入爆破）| **需更新** | 塊 A（WMI）/塊 C（爆破）前提仍成立，但應補記：**塊 C 的登入爆破資料前提除段 2 的 Security 規則外，若要做 process-side 爆破關聯還受 F-1（live proc 欄位缺）影響**；且 F-2 應與「已知殘留風險登記」對齊登錄 |
| 段 5（LiveExecHeuristic）| **相符** | 未實作；其依賴的 ExecutionRecord.first_run/prefetch 檔名粒度限制屬實，描述準確 |
| 段 6（NetConn 跨進程強化）| **相符** | 未實作；netconn heuristic 現況與描述一致 |
| 段 7（BYOVD 清單維護）| **相符** | `known-vulnerable-drivers.txt` 內嵌 + `--driver-list` 覆寫機制存在，描述準確 |

**額外建議**：REMAINING-WORK「已知殘留風險登記」表應新增 F-1（live proc cmdline/integrity 缺）
與 F-8（無進度回饋）兩列——這兩者是本輪審計新發現的高風險，目前未在登記表中。

---

## 附：各審查類別涵蓋聲明

- 偵測有效性：資料來源鏈已給完整「欄位→collector→失效模式」對應（§1a）；覆蓋缺口已先排除
  Sigma/其他 heuristic 涵蓋者（§1b/§1c）。
- 可用性：launcher 三檔（main/menu/runner/summary）全讀，判斷力/進度/verify 三面向皆覆蓋。
- 錯誤處理：非測試路徑 unwrap/expect/`let _ =` 逐類判定，**未發現 golden-rule-8 違規**。
- 發佈流程：五項（實為六項含版本資源）逐項給狀態與證據。
- REMAINING-WORK 段 1-7：逐段給「相符/需更新」結論。
</content>
</invoke>
