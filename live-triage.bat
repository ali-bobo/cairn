@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please run as Administrator (right-click, Run as administrator)
    pause
    exit /b 1
)
cd /d "%~dp0"
set RULES=%~dp0rules\sigma
set DATESTAMP=%date:~0,4%%date:~5,2%%date:~8,2%
set OUTPUT=%~dp0out\live-%DATESTAMP%
echo [Cairn] Starting live triage ...
echo Output: %OUTPUT%
echo.
cargo run -p cairn-cli --release -- run --target live --output "%OUTPUT%" --admin-features --rules "%RULES%" --case-id "case-%DATESTAMP%" --operator "%USERNAME%"
echo.
echo [Cairn] Done. Results in: %OUTPUT%
echo   timeline.csv   - detection timeline (open with Excel)
echo   findings.jsonl - detailed findings (with zh-TW descriptions)
echo   manifest.json  - integrity manifest
echo   run.log        - tool action log
pause
