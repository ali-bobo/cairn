@echo off
cd /d "%~dp0"
set RULES=%~dp0rules\sigma
set MANIFEST=%~dp0out\manifest.json
if not exist "%MANIFEST%" (
    echo [ERROR] Cannot find: %MANIFEST%
    echo Please run evtx-scan.bat or live-triage.bat first.
    pause
    exit /b 1
)
echo [Cairn] Verifying output integrity...
cargo run -p cairn-cli --release -- verify "%MANIFEST%" --rules "%RULES%"
if %errorlevel% equ 0 (
    echo.
    echo [OK] All outputs intact, no tampering detected.
) else (
    echo.
    echo [WARN] Integrity check FAILED.
)
pause
