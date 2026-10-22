# Sigma 規則清冊

> 涵蓋 `rules/ruleset.toml` 全部規則（既有 50 條 + 段 2 新增 30 條 + 階段 3G 新增 6 條
> + 行程建立／Sysmon 補強 10 條 = 96 條）。
> 「是否確認會 fire」欄位如實記錄——沒有測試覆蓋的規則明確標示，不倒填假驗證。
> **既有 50 條規則的驗證現況**：`crates/cairn-sigma/tests/parity.rs` 目前只有 3 個
> 針對既有規則的專屬 firing 測試（`hh_chm_execution_fires`、`msxsl_execution_fires`、
> `mshta_suspicious_extension_fires`），另有 1 個既有規則集合的陰性測試
> （`benign_process_creation_fires_nothing`，證明良性事件不誤報，但不證明任何一條規則
> 會 fire）。其餘 47 條既有規則**沒有專屬測試**，只在載入時通過 DRL 1.1 author 檢查與
> Sigma YAML 語法解析，detection 邏輯本身是否真的會在對應事件上 fire **未經驗證**。
> 段 2 新增的 30 條規則（Task 1-4）每條都有專屬合成事件 firing 測試，已實測通過。
> 更新規則集時（新增/移除），本檔案需同步更新。

| 規則 path | 標題 | 觸發情境 | 資料前提 | 驗證方式 | 確認會 fire |
|---|---|---|---|---|---|
| windows/process_creation/proc_creation_win_hh_chm_execution.yml | HH.EXE CHM Execution | hh.exe 開啟 .chm 編譯說明檔（T1218.001 LOLBAS 濫用） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::hh_chm_execution_fires | 是 |
| windows/process_creation/proc_creation_win_msxsl_execution.yml | Msxsl Execution | msxsl.exe 執行 XSL 樣式表轉換，常見 LOLBAS 代理執行手法（T1220） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::msxsl_execution_fires | 是 |
| windows/process_creation/proc_creation_win_mshta_susp_execution.yml | Mshta Suspicious Execution | mshta.exe 執行帶可疑副檔名（如偽裝成圖片）的 HTA/腳本內容（T1218.005） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::mshta_suspicious_extension_fires | 是 |
| windows/process_creation/proc_creation_win_certutil_encode.yml | Certutil Encode | certutil.exe 以 `-encode` 參數編碼檔案，常見於惡意 payload 傳輸前置作業（LOLBAS） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_certutil_download.yml | Certutil Download | certutil.exe 以 `-urlcache`/`-verifyctl` 等參數從網路下載檔案（LOLBAS T1105） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_bitsadmin_download.yml | Bitsadmin Download | bitsadmin.exe 以 `/transfer` 等參數透過 BITS 服務下載檔案（LOLBAS T1197） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_iexpress_susp_execution.yml | Iexpress Suspicious Execution | iexpress.exe 以可疑參數執行，用於打包/安裝自解壓執行檔的 LOLBAS 濫用手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml | PowerShell Base64 Encoded Command | powershell.exe 以 `-enc`/`-EncodedCommand` 參數執行 Base64 編碼指令，常見混淆手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_powershell_download_iex.yml | PowerShell Download and IEX | powershell.exe 指令包含下載並以 `IEX`/`Invoke-Expression` 直接執行外部內容的下載跳板樣式 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml | PowerShell Suspicious Download Patterns | powershell.exe 指令列出現可疑下載函式呼叫樣式（如 `Net.WebClient`、`DownloadString`） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_powershell_susp_parent_process.yml | PowerShell Suspicious Parent Process | powershell.exe 由可疑父行程（如 Office 應用程式、指令碼引擎）啟動，疑似巨集/文件式攻擊鏈 | 需啟用 Process Creation 稽核 + 命令列記錄，且父子行程關係須完整記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_susp_web_request_cmd_and_cmdlets.yml | Suspicious Web Request Cmd and Cmdlets | 命令列中出現可疑網路請求指令/cmdlet 組合（如 `curl`/`Invoke-WebRequest` 搭配可疑目標） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_powershell_download_cradle_obfuscated.yml | PowerShell Obfuscated Download Cradle | powershell.exe 指令列出現混淆過的下載跳板樣式（字串拼接/反轉等規避手法） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml | PowerShell Delete Volume Shadow Copies | 透過 PowerShell classic 記錄偵測刪除磁碟區陰影複製（VSS），常見勒索軟體清除復原點手法 | Windows PowerShell（classic）日誌需啟用；此為 legacy channel 非 4104 script block | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/win_alert_mimikatz_keywords.yml | Mimikatz Keyword Alert | Security.evtx 事件中出現與 Mimikatz 憑證竊取工具相關的關鍵字 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml | Rundll32 Process Dump via comsvcs.dll | rundll32.exe 呼叫 comsvcs.dll 的 MiniDump 匯出函式傾印行程記憶體（常用於傾印 lsass.exe） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml | Sysinternals ProcDump Targeting LSASS | procdump.exe 指令列以 lsass.exe 為傾印目標，明確憑證竊取意圖 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_sysinternals_procdump.yml | Sysinternals ProcDump General Usage | procdump.exe 一般執行（含 EULA 接受旗標等特徵），非特定鎖定 lsass 的廣義覆蓋 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml | Renamed Sysinternals ProcDump | 執行檔名稱與 procdump.exe 不符但 OriginalFileName 仍為 procdump.exe，疑似重新命名規避偵測 | 需啟用 Process Creation 稽核 + 命令列記錄，且需記錄 OriginalFileName | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_net_user_add.yml | Net User Add | `net user /add` 建立新使用者帳號，常見於帳號濫用初期（T1136.001） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_nltest_recon.yml | Nltest Recon | nltest.exe 執行網域信任關係/網域控制站列舉，常見於橫向移動前置偵察（T1482） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_susp_whoami_as_param.yml | Whoami as Parameter | whoami.exe 被當作其他行程的命令列參數執行，疑似自動化偵察腳本 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_renamed_whoami.yml | Renamed Whoami | 執行檔名稱與 whoami.exe 不符但 OriginalFileName 為 whoami.exe，疑似重新命名規避偵測 | 需啟用 Process Creation 稽核 + 命令列記錄，且需記錄 OriginalFileName | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_schtasks_creation.yml | Scheduled Task Creation | schtasks.exe 建立排程工作，常見持久化手法（T1053.005） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_sc_create_service.yml | SC Create Service | sc.exe 建立新服務，常見持久化/橫向移動手法（T1543.003） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_reg_add_run_key.yml | Reg Add Run Key | reg.exe 新增登錄 Run/RunOnce 機碼，常見開機自啟持久化手法（T1547.001） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_user_added_to_local_administrators.yml | User Added to Local Administrators Group | Security.evtx EventID 4732，使用者被加入本機 Administrators 群組，疑似權限提升 | 需啟用對應 Windows 安全稽核原則（帳戶管理稽核） | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml | Suspicious Add User to Local Admin Group | `net localgroup administrators /add` 指令列樣式，將使用者加入本機管理員群組 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_reg_disable_sec_services.yml | Reg Disable Security Services | reg.exe 修改登錄機碼停用安全服務（如防毒/防火牆相關設定），防禦規避手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_reg_disable_defender_wmi_autologger.yml | Reg Disable Defender WMI Autologger | reg.exe 停用 Windows Defender 相關的 WMI autologger session，規避事件記錄 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_bcdedit_susp_execution.yml | BCDEdit Suspicious Execution | bcdedit.exe 以可疑參數執行，開機設定竄改前置手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml | BCDEdit Boot Configuration Tampering | bcdedit.exe 修改開機設定以停用修復模式/安全開機檢查，常見勒索軟體防禦規避手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_cipher_overwrite_deleted_data.yml | Cipher Overwrite Deleted Data | cipher.exe 以 `/w` 參數覆寫已刪除資料，常見勒索軟體清除鑑識痕跡手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_attrib_hiding_files.yml | Attrib Hiding Files | attrib.exe 以 `+h +s` 等參數隱藏檔案/系統屬性，常見於惡意程式自我隱藏 | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/process_creation/proc_creation_win_wbadmin_delete_backups.yml | Wbadmin Delete Backups | wbadmin.exe 刪除系統備份，常見勒索軟體阻止資料復原手法（T1490） | 需啟用 Process Creation 稽核 + 命令列記錄 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_cobaltstrike_service_installs.yml | Cobalt Strike Service Installs | Security.evtx 服務安裝事件符合 Cobalt Strike 常見服務命名/映像路徑特徵 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml | Metasploit/Impacket SMB PsExec Service Install | Security.evtx 服務安裝事件符合 Metasploit psexec 或 impacket psexec.py 常見服務命名特徵 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml | Meterpreter/Cobalt Strike GetSystem Service Install | Security.evtx 服務安裝事件符合 Meterpreter/Cobalt Strike getsystem 提權手法的服務命名特徵 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_service_install_remote_access_software.yml | Remote Access Software Installed as Service | Security.evtx 服務安裝事件涉及常見遠端存取軟體（AnyDesk/TeamViewer 等），可能是未授權遠端存取管道 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml | Suspicious Failed Logon Source | Security.evtx 記錄來自可疑來源的大量登入失敗事件，疑似暴力破解 | 需啟用對應 Windows 安全稽核原則（登入事件稽核） | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml | Suspicious Logon with New Credentials | Security.evtx LogonType 9（NewCredentials，常見於 `runas /netonly`）搭配可疑情境，常用於橫向移動時隱藏來源帳號 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_admin_rdp_login.yml | Admin RDP Login | Security.evtx 記錄管理員帳號透過 RDP（LogonType 10）登入，需結合情境判斷是否為授權操作 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml | Successful External Remote RDP Login | Security.evtx 記錄來自外部/非內網來源的成功 RDP 登入，疑似未授權遠端存取 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_pass_the_hash_2.yml | Pass the Hash Activity | Security.evtx 記錄符合 Pass-the-Hash 攻擊特徵的登入事件（LogonType 3 搭配 NTLM、特定帳號/工作站關聯樣式） | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_overpass_the_hash.yml | Overpass the Hash Activity | Security.evtx 記錄符合 Overpass-the-Hash（利用 NTLM hash 取得 Kerberos 票證）攻擊特徵的事件 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml | Suspicious Privilege Escalation via Kerberos Relay over LDAP | Security.evtx 記錄符合 Kerberos Relay over LDAP（如 KrbRelayUp）提權攻擊特徵的事件 | 需啟用對應 Windows 安全稽核原則 | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/ntlm/win_susp_ntlm_brute_force.yml | Suspicious NTLM Brute Force | NTLM 稽核記錄短時間內單一來源大量 NTLM 驗證失敗，疑似暴力破解 | 需啟用 NTLM 稽核（Audit NTLM Authentication） | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/ntlm/win_susp_ntlm_rdp.yml | Suspicious NTLM RDP | NTLM 稽核記錄 RDP 連線使用 NTLM 而非 Kerberos 驗證且來源可疑，可能繞過網域驗證政策 | 需啟用 NTLM 稽核（Audit NTLM Authentication） | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_ad_replication_non_machine_account.yml | AD Replication Request by Non-Machine Account | Security.evtx 記錄非機器帳號發出的目錄複寫請求，疑似 DCSync 攻擊（T1003.006） | 需啟用對應 Windows 安全稽核原則（目錄服務存取稽核） | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml | Account Backdoor via DCSync Rights Assignment | Security.evtx 記錄帳號被授予 DCSync 相關複寫權限（Replicating Directory Changes），疑似後門權限設置 | 需啟用對應 Windows 安全稽核原則（目錄服務變更稽核） | 無現存測試，狀態不明 | 否（無測試佐證，僅載入時通過 DRL 1.1 author 檢查，未驗證 detection 邏輯實際觸發） |
| windows/powershell/powershell_script/posh_ps_malicious_keywords.yml | Malicious PowerShell Keywords | script block 內出現 Metasploit/Mimikatz 等關鍵字與 token 操作相關 API 常數 | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟；4104 預設僅記可疑片段非完整逐字稿 | parity.rs::powershell_malicious_keywords_fires | 是 |
| windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml | AMSI Bypass Pattern Assembly GetType | 透過 `[Ref].Assembly.GetType` + `SetValue($null,$true)` + `NonPublic,Static` 組合繞過 AMSI | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟 | parity.rs::powershell_amsi_bypass_pattern_fires | 是 |
| windows/powershell/powershell_script/posh_ps_disable_psreadline_command_history.yml | Disable Powershell Command History | `Remove-Module`+`psreadline` 組合，用以移除 PowerShell 指令歷史紀錄 | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟 | parity.rs::powershell_disable_psreadline_history_fires | 是 |
| windows/powershell/powershell_script/posh_ps_create_local_user.yml | PowerShell Create Local User | 透過 `New-LocalUser` cmdlet 建立本機使用者帳號 | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟 | parity.rs::powershell_create_local_user_fires | 是 |
| windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml | Potential Invoke-Mimikatz PowerShell Script | PowerShell 腳本中與 Mimikatz 憑證竊取相關的指令樣式（dump credentials/certificates/加密存放區） | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟；4104 預設僅記可疑片段非完整逐字稿 | parity.rs::powershell_invoke_mimikatz_keyword_fires | 是 |
| windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml | Clear PowerShell History - PowerShell | 刪除 PowerShell 歷史檔案路徑或關閉 PSReadlineOption 歷史紀錄功能的行為 | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟 | parity.rs::powershell_clear_history_fires | 是 |
| windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml | HackTool - Rubeus Execution - ScriptBlock | script block 中出現與 Rubeus（Kerberos 票證竊取工具）相關的命令列參數 | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟 | parity.rs::powershell_rubeus_keyword_fires | 是 |
| windows/powershell/powershell_script/posh_ps_download_com_cradles.yml | Potential COM Objects Download Cradles Usage - PS Script | 利用 COM 物件 `GetTypeFromCLSID`（特定惡意 CLSID）下載檔案的下載跳板手法 | PowerShell Script Block Logging（EnableScriptBlockLogging=1）需開啟 | parity.rs::powershell_com_download_cradle_fires | 是 |
| windows/builtin/security/win_security_kerberoasting_activity.yml | Kerberoasting Activity - Initial Query | 短時間內單一主機對多個服務帳號發出 RC4 加密的 Kerberos 票證請求（EventID 4769），疑似 Kerberoasting | 需啟用對應 Windows 安全稽核原則（Kerberos 服務票證操作稽核） | parity.rs::kerberoasting_activity_fires | 是 |
| windows/builtin/security/win_security_kerberos_asrep_roasting.yml | Potential AS-REP Roasting via Kerberos TGT Requests | 停用 Kerberos 預先驗證且使用 RC4-HMAC 加密的 TGT 請求（EventID 4768），疑似 AS-REP Roasting | 需啟用對應 Windows 安全稽核原則（Kerberos 驗證服務稽核） | parity.rs::asrep_roasting_fires | 是 |
| windows/builtin/security/win_security_admin_share_access.yml | Access To ADMIN$ Network Share | 存取 ADMIN$ 系統管理共用資源夾（EventID 5140，排除機器帳號合法存取） | 需啟用對應 Windows 安全稽核原則（檔案共用稽核） | parity.rs::admin_share_access_fires | 是 |
| windows/builtin/security/win_security_impacket_secretdump.yml | Possible Impacket SecretDump Remote Activity | impacket secretdump 工具透過 ADMIN$ 共用資源夾搭配 SYSTEM32 暫存檔案萃取 AD 憑證的行為模式（EventID 5145） | 需啟用對應 Windows 安全稽核原則（詳細檔案共用稽核） | parity.rs::impacket_secretdump_fires | 是 |
| windows/builtin/security/win_security_hidden_user_creation.yml | Hidden Local User Creation | 建立以 `$` 結尾（隱藏）的本機使用者帳號（EventID 4720，排除合法 HomeGroupUser$） | 需啟用對應 Windows 安全稽核原則（帳戶管理稽核） | parity.rs::hidden_user_creation_fires | 是 |
| windows/builtin/security/win_security_lsass_access_non_system_account.yml | LSASS Access From Non System Account | 非系統帳號以可疑存取遮罩存取 LSASS 行程（排除已知合法 AV/EDR） | 需啟用對應 Windows 安全稽核原則（處理程序存取稽核） | parity.rs::lsass_access_non_system_account_fires | 是 |
| windows/builtin/system/service_control_manager/win_system_service_install_hacktools.yml | HackTool Service Registration or Execution | 與 cachedump/gsecdump/pwdump 等憑證傾印工具，或映像路徑含 "bypass" 字樣的服務安裝/執行（EventID 7045/7036） | 需啟用對應 Windows 安全稽核原則（System.evtx 服務控制管理員記錄） | parity.rs::hacktool_service_install_fires | 是 |
| windows/builtin/system/service_control_manager/win_system_service_install_susp.yml | Suspicious Service Installation | 服務安裝事件中含 PowerShell 混淆旗標、隱藏視窗、暫存目錄或指令注入樣式等可疑指標（EventID 7045） | 需啟用對應 Windows 安全稽核原則（System.evtx 服務控制管理員記錄） | parity.rs::suspicious_service_install_fires | 是 |
| windows/builtin/system/service_control_manager/win_system_service_install_uncommon.yml | Uncommon Service Installation Image Path | 服務 ImagePath 出現具名管道路徑、暫存目錄或編碼 PowerShell 指令等異常特徵（EventID 7045） | 需啟用對應 Windows 安全稽核原則（System.evtx 服務控制管理員記錄） | parity.rs::uncommon_service_install_path_fires | 是 |
| windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml | KrbRelayUp Service Installation | KrbRelayUp 提權工具在缺乏 LDAP 簽章強制的網域環境中安裝名為 `KrbSCM` 的惡意服務 | 需啟用對應 Windows 安全稽核原則（System.evtx 服務控制管理員記錄） | parity.rs::krbrelayup_service_install_fires | 是 |
| windows/process_creation/proc_creation_win_certutil_decode.yml | File Decoded From Base64/Hex Via Certutil.EXE | 濫用 certutil `-decode`/`-decodehex` 參數還原混淆過的 payload（與既有 encode/download 規則互補、非重複） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::certutil_decode_fires | 是 |
| windows/process_creation/proc_creation_win_browsers_tor_execution.yml | Tor Client/Browser Execution | 執行 Tor 或 Tor Browser，可能用於 C2 通訊的洋蔥路由 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::tor_browser_execution_fires | 是 |
| windows/process_creation/proc_creation_win_cloudflared_tunnel_run.yml | Cloudflared Tunnel Execution | 執行 cloudflared 連回既有 tunnel，屬於持久化與遠端存取管道 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::cloudflared_tunnel_run_fires | 是 |
| windows/process_creation/proc_creation_win_7zip_password_compression.yml | Compress Data and Lock With Password for Exfiltration With 7-ZIP | 用 7-ZIP 以密碼保護方式壓縮資料，常見於外洩前置動作 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::sevenzip_password_compression_fires | 是 |
| windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.yml | Monitoring For Persistence Via BITS | 濫用 BITS 下載完成後執行後續命令以建立持久化的行為（與既有 bitsadmin download 規則互補、非重複主題） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::bitsadmin_persistence_fires | 是 |
| windows/process_creation/proc_creation_win_amsi_registry_tampering.yml | Windows AMSI Related Registry Tampering Via CommandLine | 透過命令列修改登錄機碼以停用 AMSI 掃描 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::amsi_registry_tampering_fires | 是 |
| windows/process_creation/proc_creation_win_auditpol_susp_execution.yml | Audit Policy Tampering Via Auditpol | 利用 auditpol.exe 竄改稽核原則以停用偵測機制 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::auditpol_tampering_fires | 是 |
| windows/process_creation/proc_creation_win_at_interactive_execution.yml | Interactive AT Job | `at.exe` 搭配 "interactive" 參數執行，可能用於權限提升 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::at_interactive_execution_fires | 是 |
| windows/process_creation/proc_creation_win_autologger_session_registry_modification.yml | Windows EventLog Autologger Session Registry Modification Via CommandLine | 修改 EventLog autologger session 登錄設定以規避開機初期活動的監控 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::autologger_registry_modification_fires | 是 |
| windows/process_creation/proc_creation_win_cdb_arbitrary_command_execution.yml | Potential Binary Proxy Execution Via Cdb.EXE | 利用 cdb.exe（Windows 除錯工具）以 debugger script 參數執行未授權指令的代理執行手法 | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::cdb_arbitrary_command_fires | 是 |
| windows/process_creation/proc_creation_win_adplus_memory_dump.yml | Potential Adplus.EXE Abuse | 濫用 AdPlus.exe（Windows SDK 工具）擷取行程記憶體內容或執行未授權指令（與既有 procdump/comsvcs dump 規則互補、非重複工具） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::adplus_memory_dump_fires | 是 |
| windows/process_creation/proc_creation_win_certreq_download.yml | Suspicious CertReq Command to Download | 濫用 certreq.exe 透過網路下載檔案（與既有 certutil download 規則互補、屬不同 LOLBAS 工具） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::certreq_download_fires | 是 |
| windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml | Shadow Copies Deletion Using Operating Systems Utilities | vssadmin/wmic/PowerShell/diskshadow 刪除陰影複製、wbadmin 刪除備份目錄、vssadmin 縮小陰影儲存區（勒索前兆 T1490） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::shadow_copy_deletion_fires_on_4688_with_matched_fields（4688 形狀） | 是 |
| windows/process_creation/proc_creation_win_powershell_shadowcopy_deletion.yml | Deletion of Volume Shadow Copies via WMI with PowerShell | 命令列以 Get-WmiObject/Get-CimInstance 取得 Win32_ShadowCopy 再刪除（T1490） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::powershell_wmi_shadow_copy_deletion_fires_on_4688_and_4104 | 是 |
| windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | 同上，從 PowerShell 指令碼區塊（4104）看到 | 需啟用 PowerShell Script Block Logging（4104） | parity.rs::powershell_wmi_shadow_copy_deletion_fires_on_4688_and_4104 | 是 |
| windows/process_creation/proc_creation_win_susp_eventlog_clear.yml | Suspicious Eventlog Clearing or Configuration Change Activity | wevtutil cl/sl、Clear-EventLog、ClearEventLog 等清除或縮小事件記錄（T1070.001；heur_eventlog 看的是清除後的 1102/104，這條看的是下指令的行程） | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::wevtutil_clear_log_fires_on_4688 | 是 |
| windows/process_creation/proc_creation_win_powershell_defender_exclusion.yml | Powershell Defender Exclusion | Add-/Set-MpPreference 加入 Defender 排除路徑、副檔名、行程或 IP | 需啟用 Process Creation 稽核 + 命令列記錄 | parity.rs::defender_exclusion_and_tamper_fire | 是 |
| windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml | Tamper Windows Defender - ScriptBlockLogging | Set-MpPreference 關閉即時保護、行為監控等，或把威脅預設動作設為 Allow | 需啟用 PowerShell Script Block Logging（4104） | parity.rs::defender_exclusion_and_tamper_fire | 是 |
| windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.yml | HackTool - Potential Impacket Lateral Movement Activity | Impacket wmiexec／dcomexec／smbexec 的 `cmd.exe /Q /c ... \\127.0.0.1\ADMIN$\__<時間> 2>&1`（父程序 WmiPrvSE／mmc／explorer／services），或 atexec 的 `cmd.exe /C ... Windows\Temp\... 2>&1`（T1047、T1021） | 需啟用 Process Creation 稽核 + 命令列記錄；4688 要 Windows 10 以後才有 `ParentProcessName`，或 Sysmon 1 | parity.rs::impacket_lateral_movement_fires；real_evtx.rs::impacket_wmiexec_and_dcomexec_sysmon_1（真實樣本） | 是 |
| windows/process_creation/proc_creation_win_wmiprvse_susp_child_processes.yml | Suspicious WmiPrvSE Child Process | WmiPrvSE 啟動 rundll32、regsvr32、mshta、wscript 等 LOLBin，或啟動帶 powershell／mshta 的 cmd（WMI 遠端執行，T1047） | 同上（需要父程序映像檔） | parity.rs::wmiprvse_suspicious_child_fires_benign_does_not；real_evtx.rs::wmi_handler_abuse_sysmon_1（真實樣本） | 是 |
| windows/process_access/proc_access_win_lsass_memdump.yml | Potential Credential Dumping Activity Via LSASS | 以 0x1038／0x1438／0x143a／0x1fffff 存取 LSASS 且呼叫堆疊經過 dbghelp／dbgcore 等（T1003.001） | **需要 Sysmon（事件 10）** | parity.rs::suspicious_access_mask_on_lsass_fires | 是（合成事件） |
| windows/process_access/proc_access_win_lsass_susp_access_flag.yml | Potentially Suspicious GrantedAccess Flags On LSASS | 非系統、非 Program Files 的程式以可讀記憶體的權限遮罩（0x1f1fff、0x1438 等）存取 LSASS（T1003.001） | **需要 Sysmon（事件 10）** | parity.rs::suspicious_access_mask_on_lsass_fires；real_evtx.rs::lsass_access_sysmon_10（真實樣本） | 是 |
| windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml | Lsass Memory Dump via Comsvcs DLL | rundll32 經 comsvcs.dll 存取 LSASS（MiniDump 傾印，T1003.001） | **需要 Sysmon（事件 10）** | parity.rs::suspicious_access_mask_on_lsass_fires | 是（合成事件） |
| windows/process_access/proc_access_win_lsass_dump_keyword_image.yml | LSASS Memory Access by Tool With Dump Keyword In Name | 檔名含 dump 的程式以讀取權限存取 LSASS（procdump、nanodump 等，T1003.001） | **需要 Sysmon（事件 10）** | parity.rs::suspicious_access_mask_on_lsass_fires | 是（合成事件） |
| windows/process_access/proc_access_win_hktl_generic_access.yml | HackTool - Generic Process Access | mimikatz、Rubeus、SafetyKatz、Impacket 編譯版等駭客工具的預設檔名存取其他行程（T1003.001） | **需要 Sysmon（事件 10）** | parity.rs::mimikatz_lsass_access_fires_hacktool_rule；real_evtx.rs::lsass_access_sysmon_10（真實樣本） | 是 |
| windows/wmi_event/sysmon_wmi_event_subscription.yml | WMI Event Subscription | 建立／修改／刪除 WMI 永久事件訂閱（filter、consumer、binding；T1546.003） | **需要 Sysmon（事件 19／20／21）** | parity.rs::wmi_consumer_creation_fires；real_evtx.rs::wmi_consumers_sysmon_19_20_21（真實樣本） | 是 |
| windows/wmi_event/sysmon_wmi_susp_scripting.yml | Suspicious Scripting in a WMI Consumer | WMI consumer 內容含下載執行、`-nop`、`-enc`、WScript.Shell 等（T1059.005） | **需要 Sysmon（事件 20）** | parity.rs::wmi_consumer_creation_fires | 是（合成事件） |
| windows/wmi_event/sysmon_wmi_susp_encoded_scripts.yml | Suspicious Encoded Scripts in a WMI Consumer | WMI consumer 內容藏有 base64 編碼的 PE 或 WriteProcessMemory（T1546.003） | **需要 Sysmon（事件 20）** | parity.rs::wmi_consumer_creation_fires | 是（合成事件） |

## 每次執行的可行性檢查（階段 3G）

上表的「資料前提」現在每次執行都會實際檢查。Sigma analyzer 為每條規則輸出一筆
`sigma_rule` observation（`observations.jsonl`），report.html 的「Sigma 規則這次能不能跑」
區塊列出能觸發／不可能觸發／無法確認的條數，以及缺少哪些記錄設定。判斷方式
（`crates/cairn-sigma/src/viability.rs`）：

- **靜態**：logsource 對到哪些頻道與事件 ID、各自需要哪個稽核設定。`process_creation`
  規則會對 4688 實際有的欄位做條件式推演：每個分支都需要 `OriginalFileName`、
  `Hashes`、`ParentCommandLine` 等欄位的規則只能靠 Sysmon 觸發；每個分支都需要
  `CommandLine` 的規則另外需要「在行程建立事件中包含命令列」。
- **主機**：用這次收集到的事件推斷。看到某條規則的事件就代表該設定有開；Security 有
  事件卻沒有任何 4688 代表行程建立稽核沒開；有 4688 但都沒有命令列代表命令列記錄沒開；
  沒有任何 Sysmon 事件代表沒有 Sysmon。預設開啟的稽核（登入、帳戶管理、群組管理）在
  讀得到 Security 時視為開啟。其他預設關閉、又沒看到事件的設定標為「無法確認」。
- Sysmon-only 規則：Renamed Whoami Execution（只比對 `OriginalFileName`），以及 5 條
  LSASS 存取規則（Sysmon 10）與 3 條 WMI 事件訂閱規則（Sysmon 19／20／21）。沒有裝
  Sysmon 的主機上這 9 條會標成不可能觸發；`wmi_event` 對到 Sysmon 19、20、21 三個事件。
  需要 NTLM 稽核、物件 SACL、詳細檔案共用稽核或網域控制站的規則也保留，這些規則
  在一般工作站上會被標成不可能觸發或無法確認，而不是默默不命中。

同一條規則在同一台主機命中超過 3 次時，合併成一筆 finding：`details` 寫命中次數與
起訖時間，`evidence` 逐筆列出前 20 筆命中的 record 與比對到的欄位值。每筆 Sigma finding
的 `details` 都會帶「matched fields: 欄位=值」。

## 統計摘要

- 規則總數：96 條（既有 50 條 + 段 2 新增 30 條 + 階段 3G 新增 6 條 + 行程建立／Sysmon
  補強 10 條）。
- **行程建立／Sysmon 補強 10 條**：每條都有專屬合成事件測試（含不誤報的陰性案例
  `benign_lsass_access_fires_nothing`、`wmi_rules_ignore_other_sysmon_events`），其中 5 條
  另以 EVTX-ATTACK-SAMPLES 真實樣本驗證（`crates/cairn-cli/src/real_evtx.rs`）。
- **既有 50 條規則測試覆蓋現況**：3 條有專屬 firing 測試（`hh_chm_execution_fires`、
  `msxsl_execution_fires`、`mshta_suspicious_extension_fires`），**47 條無現存測試**，
  狀態不明——僅通過載入時的 DRL 1.1 author 檢查與 YAML 語法解析，detection 邏輯
  實際觸發與否未經驗證。
- **段 2 新增 30 條規則測試覆蓋現況**：30 條全部有專屬 firing 測試，皆已實測通過
  （見 `crates/cairn-sigma/tests/parity.rs`）。
- 全域陰性測試（不誤報良性事件）：`benign_process_creation_fires_nothing`（既有規則集合，
  process_creation 類）、`benign_powershell_script_fires_nothing`、
  `benign_logon_event_fires_nothing`、`benign_service_install_fires_nothing`、
  `benign_process_creation_extra_batch_fires_nothing`（段 2 新增規則集合，各主題一個）。
