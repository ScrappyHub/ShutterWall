param(
  [Parameter(Position=0)][string]$Command,
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Get-LatestRunRoot {
  param([string]$RepoRoot)
  $runs = Get-ChildItem (Join-Path $RepoRoot "proofs\runs\shutterwall") -Directory | Sort-Object LastWriteTime -Descending
  if(-not $runs){ throw "NO_RUNS_FOUND" }
  return $runs[0].FullName
}

function Invoke-Protect {
  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
  Write-Host "SHUTTERWALL PROTECT" -ForegroundColor Cyan
  Write-Host "Step 1/3: Analyze devices..." -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") -RepoRoot $RepoRoot -RunRoot $latest
  Write-Host "Step 2/3: Build protection plan..." -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile enterprise_strict
  Write-Host "Step 3/3: Preview protection actions..." -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") -RepoRoot $RepoRoot -RunRoot $latest -WhatIf
  Write-Host ""
  Write-Host "To apply these protections, run an elevated PowerShell and use:" -ForegroundColor Yellow
  Write-Host "  shutterwall apply" -ForegroundColor Yellow
  Write-Host "To undo ShutterWall firewall rules later, use:" -ForegroundColor Yellow
  Write-Host "  shutterwall undo" -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_PROTECT_OK" -ForegroundColor Green
}

function Invoke-Apply {
  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") -RepoRoot $RepoRoot -RunRoot $latest
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile enterprise_strict
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") -RepoRoot $RepoRoot -RunRoot $latest -Apply -Force
}

function Invoke-Restore {
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_restore_v1.ps1") -RepoRoot $RepoRoot
}

switch ($Command) {
  "help" {
    Write-Host "ShutterWall commands:"
    Write-Host "  shutterwall scan       # preview protection actions"
    Write-Host "  shutterwall apply      # apply protections; Administrator required"
    Write-Host "  shutterwall undo       # restore ShutterWall firewall rules; Administrator required"
    Write-Host "  shutterwall protect    # same as scan"
    Write-Host "  shutterwall secure-force # same as apply"
    Write-Host "  shutterwall restore    # same as undo"
    Write-Host "  shutterwall doctor"
    Write-Host "  shutterwall version"
    return
  }
  "version" { Write-Host "SHUTTERWALL_VERSION: 0.3.2"; return }
  "doctor" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
    Write-Host ("LATEST_RUN_ROOT: " + $latest)
    Write-Host "SHUTTERWALL_DOCTOR_OK"
    return
  }
  "scan" { Invoke-Protect; return }
  "protect" { Invoke-Protect; return }
  "secure-low" { Invoke-Protect; return }
  "secure-enterprise" { Invoke-Protect; return }
  "apply" { Invoke-Apply; return }
  "secure-force" { Invoke-Apply; return }
  "undo" { Invoke-Restore; return }
  "restore" { Invoke-Restore; return }
  default {
    Write-Host "UNKNOWN_COMMAND"
    Write-Host "Run: shutterwall help"
    return
  }
}
