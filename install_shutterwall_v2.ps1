param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$UserBin = Join-Path $HOME "bin"
$CliPath = Join-Path $RepoRoot "shutterwall.ps1"
$ShimPath = Join-Path $UserBin "shutterwall.cmd"

if (-not (Test-Path -LiteralPath $RepoRoot)) {
  throw ("REPO_ROOT_MISSING: " + $RepoRoot)
}

if (-not (Test-Path -LiteralPath $CliPath)) {
  throw ("CLI_MISSING: " + $CliPath)
}

if (-not (Test-Path -LiteralPath $UserBin)) {
  New-Item -ItemType Directory -Path $UserBin -Force | Out-Null
}

$shimLines = @(
  "@echo off",
  "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$CliPath"" %*"
)

$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ShimPath, (($shimLines -join "`r`n") + "`r`n"), $enc)

$currentUserPath = [Environment]::GetEnvironmentVariable("Path","User")
if ([string]::IsNullOrWhiteSpace($currentUserPath)) {
  $currentUserPath = ""
}

$parts = @($currentUserPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasPath = @($parts | Where-Object { $_ -ieq $UserBin }).Count -gt 0

if (-not $hasPath) {
  $newPath = if ([string]::IsNullOrWhiteSpace($currentUserPath)) { $UserBin } else { $currentUserPath.TrimEnd(";") + ";" + $UserBin }
  [Environment]::SetEnvironmentVariable("Path",$newPath,"User")
}

if (-not (($env:Path -split ";") -contains $UserBin)) {
  $env:Path = $env:Path + ";" + $UserBin
}

Write-Host ("SHIM_PATH: " + $ShimPath) -ForegroundColor Green
Write-Host ("USER_BIN: " + $UserBin) -ForegroundColor Green

Write-Host "Running ShutterWall doctor..." -ForegroundColor Cyan
& $PSExe -NoProfile -ExecutionPolicy Bypass -File $CliPath doctor

Write-Host ""
Write-Host "SHUTTERWALL_INSTALL_V2_OK" -ForegroundColor Green
Write-Host ""
Write-Host "Next commands:" -ForegroundColor Cyan
Write-Host "  shutterwall protect"
Write-Host "  shutterwall secure-force   # requires Administrator PowerShell"
Write-Host "  shutterwall restore        # requires Administrator PowerShell"
Write-Host ""
Write-Host "If this terminal does not recognize shutterwall, open a new PowerShell window." -ForegroundColor Yellow
