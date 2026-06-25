@echo off
cd /d "%~dp0"
set RULES=%~dp0rules\sigma
set OUTPUT=%~dp0out
echo [Cairn] Scanning Security.evtx ...
cargo run -p cairn-cli --release -- evtx "C:\Windows\System32\winevt\Logs\Security.evtx" --rules "%RULES%"
echo.
echo [Cairn] Done. Results in: %OUTPUT%
echo   timeline.csv   - detection timeline (open with Excel)
echo   findings.jsonl - detailed findings
echo   manifest.json  - integrity manifest
pause
