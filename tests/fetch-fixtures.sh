#!/usr/bin/env bash
# Fetch a few small EVTX fixtures for parser tests (T4). These are NOT committed
# (tests/fixtures/ is gitignored — size + we don't redistribute the corpus); this
# script makes them reproducible. The full EVTX-ATTACK-SAMPLES corpus for parity/perf
# is a T8 concern. Source: github.com/sbousseaden/EVTX-ATTACK-SAMPLES (CC-licensed).
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)/fixtures"
mkdir -p "$dir"
base="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master"

# name -> repo path
fetch() {
  local out="$1" path="$2"
  echo "fetching $out"
  curl -fsSL -o "$dir/$out" "$base/$path"
  # sanity: EVTX files start with the "ElfFile\0" magic.
  local magic
  magic="$(head -c 8 "$dir/$out" | od -An -tx1 | tr -d ' \n')"
  [ "$magic" = "456c6646696c6500" ] || { echo "ERROR: $out is not a valid EVTX (magic=$magic)"; exit 1; }
}

fetch sysmon_compiledhtml.evtx "Execution/Sysmon_Exec_CompiledHTML.evtx"
fetch exec_msxsl.evtx          "Execution/exec_msxsl_xsl_sysmon_1_7.evtx"

echo "done -> $dir"
