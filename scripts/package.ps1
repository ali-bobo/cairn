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
Copy-Item "USER-MANUAL.md" "$OutDir\USER-MANUAL.md"
Copy-Item "LICENSE"        "$OutDir\LICENSE"
Copy-Item "NOTICE"         "$OutDir\NOTICE"

Write-Host "Generating CHECKSUMS.txt..." -ForegroundColor Cyan
$checksumLines = Get-ChildItem $OutDir -Recurse -File |
    Where-Object { $_.Name -ne "CHECKSUMS.txt" } |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
        $relPath = $_.FullName.Substring($OutDir.Length + 1) -replace '\\', '/'
        "$hash  $relPath"
    }
$checksumLines | Set-Content "$OutDir\CHECKSUMS.txt" -Encoding utf8

Write-Host ""
Write-Host "Done! Package ready at: $OutDir" -ForegroundColor Green
Write-Host "Contents:"
Get-ChildItem $OutDir -Recurse | Select-Object FullName
