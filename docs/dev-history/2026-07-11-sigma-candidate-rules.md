# SigmaHQ 候選規則清單

- 來源 commit：`98781da19cf60c48ce6e7f2d3ad11c9ba389191a`
- 過濾條件：必有 `author:`；logsource 落在 process_creation / ps_script / security / system(service_control_manager) 範圍內，不需 Sysmon；排除與現有 43 條重複或高度相似主題；排除 `status: deprecated` / `status: unsupported`。
- 每條均已用 WebFetch 實際讀取 raw.githubusercontent.com 內容驗證 author/logsource/status。

## 1. PowerShell 4104 Script Block

- `rules/windows/powershell/powershell_script/posh_ps_malicious_keywords.yml` — Malicious PowerShell Keywords — logsource: windows/ps_script — author: 有
  - 偵測 script block 內出現 Metasploit/Mimikatz 等關鍵字與 token 操作相關 API 常數。
- `rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml` — AMSI Bypass Pattern Assembly GetType — logsource: windows/ps_script — author: 有
  - 偵測透過 `[Ref].Assembly.GetType` + `SetValue($null,$true)` + `NonPublic,Static` 組合繞過 AMSI。
- `rules/windows/powershell/powershell_script/posh_ps_disable_psreadline_command_history.yml` — Disable Powershell Command History — logsource: windows/ps_script — author: 有
  - 偵測 `Remove-Module`+`psreadline` 組合，用以移除 PowerShell 指令歷史紀錄。
- `rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml` — PowerShell Create Local User — logsource: windows/ps_script — author: 有
  - 偵測透過 `New-LocalUser` cmdlet 建立本機使用者帳號。
- `rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml` — Potential Invoke-Mimikatz PowerShell Script — logsource: windows/ps_script — author: 有
  - 偵測 PowerShell 腳本中與 Mimikatz 憑證竊取相關的指令樣式（dump credentials/certificates/加密存放區）。
- `rules/windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml` — Clear PowerShell History - PowerShell — logsource: windows/ps_script — author: 有
  - 偵測刪除 PowerShell 歷史檔案路徑或關閉 PSReadlineOption 歷史紀錄功能的行為。
- `rules/windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml` — HackTool - Rubeus Execution - ScriptBlock — logsource: windows/ps_script — author: 有
  - 偵測 script block 中出現與 Rubeus（Kerberos 票證竊取工具）相關的命令列參數。
- `rules/windows/powershell/powershell_script/posh_ps_download_com_cradles.yml` — Potential COM Objects Download Cradles Usage - PS Script — logsource: windows/ps_script — author: 有
  - 偵測利用 COM 物件 `GetTypeFromCLSID`（特定惡意 CLSID）下載檔案的下載跳板手法。

## 2. 認證/登入規則（service: security）

- `rules/windows/builtin/security/win_security_kerberoasting_activity.yml` — Kerberoasting Activity - Initial Query — logsource: windows/service:security（EventID 4769） — author: 有
  - 偵測短時間內單一主機對多個服務帳號發出 RC4 加密的 Kerberos 票證請求，疑似 Kerberoasting。
- `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml` — Potential AS-REP Roasting via Kerberos TGT Requests — logsource: windows/service:security — author: 有（status: experimental，未 deprecated，可留）
  - 偵測停用 Kerberos 預先驗證且使用 RC4-HMAC 加密的 TGT 請求，疑似 AS-REP Roasting。
- `rules/windows/builtin/security/win_security_admin_share_access.yml` — Access To ADMIN$ Network Share — logsource: windows/service:security（EventID 5140） — author: 有
  - 偵測存取 ADMIN$ 系統管理共用資源夾（排除機器帳號合法存取）。
- `rules/windows/builtin/security/win_security_impacket_secretdump.yml` — Possible Impacket SecretDump Remote Activity — logsource: windows/service:security — author: 有
  - 偵測 impacket secretdump 工具透過 ADMIN$ 共用資源夾搭配 SYSTEM32 暫存檔案萃取 AD 憑證的行為模式。
- `rules/windows/builtin/security/win_security_hidden_user_creation.yml` — Hidden Local User Creation — logsource: windows/service:security（EventID 4720） — author: 有
  - 偵測建立以 `$` 結尾（隱藏）的本機使用者帳號（排除合法 HomeGroupUser$）。
- `rules/windows/builtin/security/win_security_lsass_access_non_system_account.yml` — LSASS Access From Non System Account — logsource: windows/service:security — author: 有
  - 偵測非系統帳號以可疑存取遮罩存取 LSASS 行程（排除已知合法 AV/EDR）。

**已排除**：`win_security_pass_the_hash_2.yml` — 與現有 43 條路徑完全相同（`windows/builtin/security/account_management/win_security_pass_the_hash_2.yml`），不列入。

## 3. System 7045 服務安裝規則

- `rules/windows/builtin/system/service_control_manager/win_system_service_install_hacktools.yml` — HackTool Service Registration or Execution — logsource: windows/service:system（EventID 7045/7036） — author: 有
  - 偵測與 cachedump/gsecdump/pwdump 等憑證傾印工具，或映像路徑含 "bypass" 字樣的服務安裝/執行。
- `rules/windows/builtin/system/service_control_manager/win_system_service_install_susp.yml` — Suspicious Service Installation — logsource: windows/service:system（EventID 7045） — author: 有
  - 偵測服務安裝事件中含 PowerShell 混淆旗標、隱藏視窗、暫存目錄或指令注入樣式等可疑指標。
- `rules/windows/builtin/system/service_control_manager/win_system_service_install_uncommon.yml` — Uncommon Service Installation Image Path — logsource: windows/service:system（EventID 7045） — author: 有
  - 偵測服務 ImagePath 出現具名管道路徑、暫存目錄或編碼 PowerShell 指令等異常特徵。
- `rules/windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml` — KrbRelayUp Service Installation — logsource: windows/service:system — author: 有
  - 偵測 KrbRelayUp 提權工具在缺乏 LDAP 簽章強制的網域環境中安裝名為 `KrbSCM` 的惡意服務。

## 4. Process Creation 其他高價值規則

- `rules/windows/process_creation/proc_creation_win_certutil_decode.yml` — File Decoded From Base64/Hex Via Certutil.EXE — logsource: windows/process_creation — author: 有
  - 偵測濫用 certutil `-decode`/`-decodehex` 參數還原混淆過的 payload（與現有 encode/download 規則互補、非重複）。
- `rules/windows/process_creation/proc_creation_win_browsers_tor_execution.yml` — Tor Client/Browser Execution — logsource: windows/process_creation — author: 有
  - 偵測執行 Tor 或 Tor Browser，可能用於 C2 通訊的洋蔥路由。
- `rules/windows/process_creation/proc_creation_win_cloudflared_tunnel_run.yml` — Cloudflared Tunnel Execution — logsource: windows/process_creation — author: 有
  - 偵測執行 cloudflared 連回既有 tunnel，屬於持久化與遠端存取管道。
- `rules/windows/process_creation/proc_creation_win_7zip_password_compression.yml` — Compress Data and Lock With Password for Exfiltration With 7-ZIP — logsource: windows/process_creation — author: 有
  - 偵測用 7-ZIP 以密碼保護方式壓縮資料，常見於外洩前置動作。
- `rules/windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.yml` — Monitoring For Persistence Via BITS — logsource: windows/process_creation — author: 有
  - 偵測濫用 BITS 下載完成後執行後續命令以建立持久化的行為（與現有 bitsadmin download 規則互補、非重複主題）。
- `rules/windows/process_creation/proc_creation_win_amsi_registry_tampering.yml` — Windows AMSI Related Registry Tampering Via CommandLine — logsource: windows/process_creation — author: 有（status: experimental）
  - 偵測透過命令列修改登錄機碼以停用 AMSI 掃描。
- `rules/windows/process_creation/proc_creation_win_auditpol_susp_execution.yml` — Audit Policy Tampering Via Auditpol — logsource: windows/process_creation — author: 有
  - 偵測利用 auditpol.exe 竄改稽核原則以停用偵測機制。
- `rules/windows/process_creation/proc_creation_win_at_interactive_execution.yml` — Interactive AT Job — logsource: windows/process_creation — author: 有
  - 偵測 `at.exe` 搭配 "interactive" 參數執行，可能用於權限提升。
- `rules/windows/process_creation/proc_creation_win_autologger_session_registry_modification.yml` — Windows EventLog Autologger Session Registry Modification Via CommandLine — logsource: windows/process_creation — author: 有（status: experimental）
  - 偵測修改 EventLog autologger session 登錄設定以規避開機初期活動的監控。
- `rules/windows/process_creation/proc_creation_win_cdb_arbitrary_command_execution.yml` — Potential Binary Proxy Execution Via Cdb.EXE — logsource: windows/process_creation — author: 有
  - 偵測利用 cdb.exe（Windows 除錯工具）以 debugger script 參數執行未授權指令的代理執行手法。
- `rules/windows/process_creation/proc_creation_win_adplus_memory_dump.yml` — Potential Adplus.EXE Abuse — logsource: windows/process_creation — author: 有
  - 偵測濫用 AdPlus.exe（Windows SDK 工具）擷取行程記憶體內容或執行未授權指令（與現有 procdump/comsvcs dump 規則互補、非重複工具）。
- `rules/windows/process_creation/proc_creation_win_certreq_download.yml` — Suspicious CertReq Command to Download — logsource: windows/process_creation — author: 有（status: experimental）
  - 偵測濫用 certreq.exe 透過網路下載檔案（與現有 certutil download 規則互補、屬不同 LOLBAS 工具）。

## 已排除統計

- 需要 Sysmon（service:sysmon 或 image_load/pipe_created/driver_load/file_event[sysmon] 等 category）：查詢過程中已在選取候選前以目錄/檔名與 logsource 初篩排除，未列入逐條記錄。
- 與現有 43 條路徑相同或高度重複主題：1 條明確記錄（`win_security_pass_the_hash_2.yml`，見上）。
- 未發現 `status: deprecated` 或 `status: unsupported` 的候選（本次驗證的規則均為 test/experimental）。
