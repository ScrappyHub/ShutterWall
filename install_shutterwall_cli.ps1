param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$cliSource = Join-Path $RepoRoot "shutterwall.ps1"
if (-not (Test-Path -LiteralPath $cliSource)) {
  throw ("CLI_SOURCE_MISSING: " + $cliSource)
}

$userBin = Join-Path $HOME "bin"
if (-not (Test-Path -LiteralPath $userBin)) {
  [void](New-Item -ItemType Directory -Path $userBin -Force)
}

$shimPath = Join-Path $userBin "shutterwall.cmd"
$shim = @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$cliSource" %*
"@

$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($shimPath, (($shim -replace "`r`n","`n") -replace "`r","`n"), $enc)

Write-Host ("INSTALLED_SHIM: " + $shimPath) -ForegroundColor Green
Write-Host "Add $HOME\bin to PATH if it is not already there." -ForegroundColor Yellow
Write-Host "SHUTTERWALL_INSTALL_CLI_OK" -ForegroundColor Green
