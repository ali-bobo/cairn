# Real EVTX test fixtures

Small, public Windows event-log samples recorded on lab machines while an attack
technique was run. The tests in `crates/cairn-collectors` (EVTX parser) and
`crates/cairn-cli` (`cairn evtx` analyzer pipeline, `real_evtx` tests) parse them and
assert which detections fire, so field names, nested `UserData`, `EventID`
qualifiers and timestamps are checked against what Windows really writes, not
against hand-made events.

These files are **data, never executed**. They contain only event records from
throw-away lab hosts (`example.corp`, `IEWIN7`, `DESKTOP-JR78RLP`, ...).
The `.evtx` files are **not committed**: run `tests/fetch-fixtures.sh` once on a fresh
checkout (CI does this before the tests). It downloads each file from upstream and
checks it against `SHA256SUMS`. A test that needs one of them fails (it does not
skip) when the file is missing.

## License

Every file here comes from one of two projects, both licensed under the
**GNU General Public License v3.0**. They are fetched unmodified, byte for byte (see
`SHA256SUMS`), as separate test data; they are not stored in this repository and
are not compiled into, linked with or shipped in the `cairn` binary.

| Source | Author | Upstream |
|---|---|---|
| EVTX-ATTACK-SAMPLES | Samir Bousseaden (@SBousseaden) | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (`LICENSE.GPL`) |
| DeepBlueCLI `evtx/` | Eric Conrad, SANS Blue Team | https://github.com/sans-blue-team/DeepBlueCLI (`LICENSE`) |

## Files

`tests/fetch-fixtures.sh` re-downloads every file from its upstream path and checks
it against `SHA256SUMS`.

| File | Source / upstream path | What it holds |
|---|---|---|
| `sysmon_compiledhtml.evtx` | EVTX-ATTACK-SAMPLES `Execution/Sysmon_Exec_CompiledHTML.evtx` | Sysmon 1 / 7 / 11, hh.exe CHM execution (parser tests) |
| `DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` | EVTX-ATTACK-SAMPLES `Command and Control/` | RemoteConnectionManager 1149 / 1136 / 1155 / 258 / 261: UserData `EventXML` `Param1..3` |
| `DE_RDP_Tunneling_4624.evtx` | EVTX-ATTACK-SAMPLES `Command and Control/` | 4624 type 10 from 127.0.0.1 (RDP through a local tunnel) |
| `DE_RDP_Tunnel_5156.evtx` | EVTX-ATTACK-SAMPLES `Command and Control/` | 4624 type 10 loopback, winlogon / lsass 4648 to localhost, 5156, 1102 |
| `LM_Remote_Service02_7045.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | 7045 with `EventID` `Qualifiers`, ImagePath `cmd.exe` / `calc.exe`; zero (1601) record header |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | 5140 / 5145 `ADMIN$` and `atsvc`, 4698 task XML, 4624, 1102 |
| `LM_renamed_psexecsvc_5145.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | 5145 on `ADMIN$` and the renamed PsExec pipe |
| `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | 4624 type 9 `seclogo` (sekurlsa::pth), 4688, 1102 |
| `kerberos_pwd_spray_4771.evtx` | EVTX-ATTACK-SAMPLES `Credential Access/` | Kerberos spray on a DC: 4768 `Status` 0x6, 4771 `Status` 0x18 |
| `DE_104_system_log_cleared.evtx` | EVTX-ATTACK-SAMPLES `Defense Evasion/` | System 104, UserData `LogFileCleared`; zero (1601) record header |
| `CA_DCSync_4662.evtx` | EVTX-ATTACK-SAMPLES `Credential Access/` | 4662 DS replication (DCSync) |
| `sysmon_10_1_memdump_comsvcs_minidump.evtx` | EVTX-ATTACK-SAMPLES `Credential Access/` | Sysmon 1 `rundll32 comsvcs.dll MiniDump` of lsass, Sysmon 7 / 10 / 11 |
| `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | EVTX-ATTACK-SAMPLES `Credential Access/` | Sysmon 10: mimikatz.exe opens lsass.exe (`GrantedAccess` 0x1010, `CallTrace`) |
| `CA_sysmon_hashdump_cmd_meterpreter.evtx` | EVTX-ATTACK-SAMPLES `Credential Access/` | Sysmon 10 / 8: Meterpreter hashdump, PROCESS_ALL_ACCESS (0x1f1fff) to lsass and other system processes from `\\VBOXSVR\...` |
| `LM_wmiexec_impacket_sysmon_whoami.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | Sysmon 1: Impacket wmiexec, WmiPrvSE -> `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<time> 2>&1`, then whoami |
| `LM_impacket_docmexec_mmc_sysmon_01.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | Sysmon 1 / 3: Impacket dcomexec (MMC20), mmc.exe -Embedding -> cmd.exe with the same ADMIN$ redirect |
| `LM_WMI_4624_4688_TargetHost.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | Windows 7 4688 without `ParentProcessName` and command line: WmiPrvSE.exe -> calc.exe (parent by `ProcessId`), 4624 type 3 |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | Sysmon 1 / 13 / 18: Metasploit psexec_psh, services.exe -> `cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni ...` |
| `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | Sysmon 1 / 10: IIS web shell, w3wp.exe -> `cmd.exe /c net user` -> net1 |
| `LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx` | EVTX-ATTACK-SAMPLES `Lateral Movement/` | Sysmon 1 / 13: WMI handler hijack, WmiPrvSE -> rundll32 url.dll / cmd / explorer `ms-browser://`; `OriginalFileName`; a `ParentImage` of `?` |
| `sysmon_20_21_1_CommandLineEventConsumer.evtx` | EVTX-ATTACK-SAMPLES `Persistence/` | Sysmon 19 / 20 / 21 create and delete a `CommandLineEventConsumer` (WMIC from python), WmiPrvSE -> cmd.exe as SYSTEM, Sysmon 10 |
| `wmighost_sysmon_20_21_1.evtx` | EVTX-ATTACK-SAMPLES `Persistence/` | Sysmon 20 / 21: WMIGhost `ActiveScriptEventConsumer` (JScript), scrcons.exe start |
| `metasploit-psexec-native-target-system.evtx` | DeepBlueCLI `evtx/` | Metasploit psexec: 7045 `%SYSTEMROOT%\<random>.exe`, getsystem `cmd.exe /c echo ... > \\.\pipe\...`, 7036 `param1` / `param2` / `Binary`, 104 |
| `metasploit-psexec-powershell-target-system.evtx` | DeepBlueCLI `evtx/` | Metasploit psexec_psh: 7045 `%COMSPEC% ... powershell ... FromBase64String`, 7009, 104 |
| `password-spray.evtx` | DeepBlueCLI `evtx/` | 294 x 4648, 41 accounts against one SMB server; TargetServerName = the local name, remote end in `IpAddress` |
| `smb-password-guessing-security.evtx` | DeepBlueCLI `evtx/` | 3,561 x 4625 against Administrator from one address (3.2 MB) |
| `new-user-security.evtx` | DeepBlueCLI `evtx/` | 4720 account created, 4728 / 4732 group adds (Administrators) |
| `disablestop-eventlog.evtx` | DeepBlueCLI `evtx/` | 7040 `EventLog` start type set to disabled and back, 104 |
| `many-events-system.evtx` | DeepBlueCLI `evtx/` | A lab host's real System log (4.2 MB): 42 driver / vendor service installs (7045) from System32\drivers and Program Files (VMware, Hyper-V, Bluetooth, .NET, Google Update, EMET), then 19 Metasploit psexec services; Windows 7 image events from 2009 |
| `wmi-event-filter-persistance.evtx` | DeepBlueCLI `evtx/` | WMI-Activity 5857 / 5858 / 5859 / 5860 / 5861, one `CommandLineEventConsumer` binding |
