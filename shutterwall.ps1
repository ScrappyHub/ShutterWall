param(
  [Parameter(Position=0)][string]$Command,
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Get-LatestRunRoot {
  param([string]$RepoRoot)
  $runs = Get-ChildItem (Join-Path $RepoRoot "proofs\runs\shutterwall") -Directory |
          Sort-Object LastWriteTime -Descending
  if(-not $runs){ throw "NO_RUNS_FOUND" }
  return $runs[0].FullName
}

switch ($Command) {

  "version" {
    Write-Host "SHUTTERWALL_VERSION: 0.3.1"
    return
  }

  "doctor" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
    Write-Host ("LATEST_RUN_ROOT: " + $latest)
    Write-Host "SHUTTERWALL_DOCTOR_OK"
    return
  }

  "secure-low" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile enterprise_strict

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -WhatIf

    return
  }

  "secure-enterprise" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile enterprise_strict

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -WhatIf

    return
  }

  "secure-force" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile enterprise_strict

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -Apply -Force

    return
  }

  "restore" {
    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_restore_v1.ps1") `
      -RepoRoot $RepoRoot
    return
  }

  "restore-force" {
    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_restore_v1.ps1") `
      -RepoRoot $RepoRoot -Force
    return
  }

  "protect" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot

    Write-Host "SHUTTERWALL PROTECT" -ForegroundColor Cyan
    Write-Host "Step 1/3: Analyze devices..." -ForegroundColor Cyan

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest

    Write-Host "Step 2/3: Build protection plan..." -ForegroundColor Cyan

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile enterprise_strict

    Write-Host "Step 3/3: Preview protection actions..." -ForegroundColor Cyan

    & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot -RunRoot $latest -WhatIf

    Write-Host ""
    Write-Host "To apply these protections, run an elevated PowerShell and use:" -ForegroundColor Yellow
    Write-Host "  shutterwall secure-force" -ForegroundColor Yellow
    Write-Host "To undo ShutterWall firewall rules later, use:" -ForegroundColor Yellow
    Write-Host "  shutterwall restore" -ForegroundColor Yellow
    Write-Host "SHUTTERWALL_PROTECT_OK" -ForegroundColor Green
    return
  }
  default {
    Write-Host "UNKNOWN_COMMAND"
    return
  }
}
