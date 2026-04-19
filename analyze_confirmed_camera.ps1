param(
  [Parameter(Mandatory=$true)][string]$Ip,
  [Parameter(Mandatory=$false)][string]$RunRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Get-LatestRunRoot {
  param([Parameter(Mandatory=$true)][string]$RepoRoot)
  $base = Join-Path $RepoRoot "proofs\runs\shutterwall"
  if (-not (Test-Path -LiteralPath $base)) { throw ("RUNS_ROOT_MISSING: " + $base) }
  $dirs = @(Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTimeUtc -Descending)
  if (@($dirs).Count -lt 1) { throw ("NO_RUN_DIRECTORIES: " + $base) }
  $dirs[0].FullName
}

function Read-JsonFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw ("JSON_INPUT_MISSING: " + $Path) }
  $raw = [System.IO.File]::ReadAllText($Path)
  if ([string]::IsNullOrWhiteSpace($raw)) { throw ("JSON_INPUT_EMPTY: " + $Path) }
  $raw | ConvertFrom-Json
}

if (-not $RunRoot) {
  $RunRoot = Get-LatestRunRoot -RepoRoot $RepoRoot
}

$devicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$devicesDoc = Read-JsonFile -Path $devicesPath
$devices = @($devicesDoc.devices)

$match = @($devices | Where-Object { [string]$_.ip -eq $Ip })
if (@($match).Count -lt 1) {
  throw ("TARGET_IP_NOT_IN_RUN: " + $Ip + " :: " + $RunRoot)
}

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_operator_review_v1.ps1") `
  -RepoRoot $RepoRoot `
  -RunRoot $RunRoot `
  -Ip $Ip `
  -Disposition confirmed_camera `
  -Note "One-click confirmed camera replay." `
  -OperatorId local_operator

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
  -RepoRoot $RepoRoot `
  -RunRoot $RunRoot

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v2.ps1") `
  -RepoRoot $RepoRoot `
  -RunRoot $RunRoot `
  -MinimumSeverity medium

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
  -RepoRoot $RepoRoot `
  -RunRoot $RunRoot `
  -WhatIf

Write-Host "SHUTTERWALL_CONFIRMED_CAMERA_ONE_CLICK_OK" -ForegroundColor Green
