#!/usr/bin/env bash
# Download the real-sample EVTX fixtures from their upstream projects and verify them
# against tests/fixtures/SHA256SUMS. The files are GPL-3.0 test data (sources in
# tests/fixtures/README.md) and are not committed to this MIT repo; CI runs this script
# before the tests. Tests never call it and never skip: a missing fixture is a test
# failure, so run this once before `cargo test` on a fresh checkout.
#
# Usage: tests/fetch-fixtures.sh           # fetch missing files, verify all
#        tests/fetch-fixtures.sh --force   # re-fetch every file, verify all
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)/fixtures"
mkdir -p "$dir"
force="${1:-}"
eas="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master"
dbc="https://raw.githubusercontent.com/sans-blue-team/DeepBlueCLI/master/evtx"

# fetch <local name> <url>
fetch() {
  local out="$1" url="$2"
  if [ -f "$dir/$out" ] && [ "$force" != "--force" ]; then
    return
  fi
  echo "fetching $out"
  curl -fsSL -o "$dir/$out.part" "$url"
  # sanity: EVTX files start with the "ElfFile\0" magic.
  local magic
  magic="$(head -c 8 "$dir/$out.part" | od -An -tx1 | tr -d ' \n')"
  [ "$magic" = "456c6646696c6500" ] || { echo "ERROR: $out is not a valid EVTX (magic=$magic)"; rm -f "$dir/$out.part"; exit 1; }
  mv "$dir/$out.part" "$dir/$out"
}

fetch sysmon_compiledhtml.evtx "$eas/Execution/Sysmon_Exec_CompiledHTML.evtx"
fetch DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx \
  "$eas/Command%20and%20Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx"
fetch DE_RDP_Tunneling_4624.evtx "$eas/Command%20and%20Control/DE_RDP_Tunneling_4624.evtx"
fetch DE_RDP_Tunnel_5156.evtx "$eas/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx"
fetch LM_Remote_Service02_7045.evtx "$eas/Lateral%20Movement/LM_Remote_Service02_7045.evtx"
fetch LM_ScheduledTask_ATSVC_target_host.evtx "$eas/Lateral%20Movement/LM_ScheduledTask_ATSVC_target_host.evtx"
fetch LM_renamed_psexecsvc_5145.evtx "$eas/Lateral%20Movement/LM_renamed_psexecsvc_5145.evtx"
fetch LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx \
  "$eas/Lateral%20Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx"
fetch kerberos_pwd_spray_4771.evtx "$eas/Credential%20Access/kerberos_pwd_spray_4771.evtx"
fetch DE_104_system_log_cleared.evtx "$eas/Defense%20Evasion/DE_104_system_log_cleared.evtx"
fetch CA_DCSync_4662.evtx "$eas/Credential%20Access/CA_DCSync_4662.evtx"
fetch sysmon_10_1_memdump_comsvcs_minidump.evtx "$eas/Credential%20Access/sysmon_10_1_memdump_comsvcs_minidump.evtx"
fetch metasploit-psexec-native-target-system.evtx "$dbc/metasploit-psexec-native-target-system.evtx"
fetch metasploit-psexec-powershell-target-system.evtx "$dbc/metasploit-psexec-powershell-target-system.evtx"
fetch password-spray.evtx "$dbc/password-spray.evtx"
fetch smb-password-guessing-security.evtx "$dbc/smb-password-guessing-security.evtx"
fetch new-user-security.evtx "$dbc/new-user-security.evtx"
fetch disablestop-eventlog.evtx "$dbc/disablestop-eventlog.evtx"
fetch wmi-event-filter-persistance.evtx "$dbc/wmi-event-filter-persistance.evtx"
fetch many-events-system.evtx "$dbc/many-events-system.evtx"

(cd "$dir" && sha256sum -c SHA256SUMS)
echo "done -> $dir"
