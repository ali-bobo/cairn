# scripts/package.ps1
# 用途：建立可發佈的 cairn-forensics 套件
# 執行：在 cairn/ 根目錄執行 .\scripts\package.ps1

param(
    [string]$OutDir = "dist\cairn-forensics"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Building release binaries..." -ForegroundColor Cyan

if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = "$env:USERPROFILE\AppData\Local\cairn-target"
}

cargo build --release -p cairn-cli -p cairn-launcher
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

$TargetDir = "$env:CARGO_TARGET_DIR\release"

Write-Host "Packaging to $OutDir..." -ForegroundColor Cyan

if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force $OutDir | Out-Null

Copy-Item "$TargetDir\cairn.exe"          "$OutDir\cairn.exe"
Copy-Item "$TargetDir\cairn-launcher.exe" "$OutDir\cairn-launcher.exe"

Copy-Item -Recurse "rules" "$OutDir\rules"

Write-Host ""
Write-Host "Done! Package ready at: $OutDir" -ForegroundColor Green
Write-Host "Contents:"
Get-ChildItem $OutDir -Recurse | Select-Object FullName
