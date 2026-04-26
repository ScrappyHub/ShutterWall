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

function Invoke-Inspect {
  Write-Host "SHUTTERWALL INSPECT" -ForegroundColor Cyan
  Write-Host "Safe inspection only. No protection plan. No firewall changes." -ForegroundColor Yellow
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1") -RepoRoot $RepoRoot -StartHost 1 -EndHost 40 -ConnectTimeoutMs 100
  Write-Host "SHUTTERWALL_INSPECT_OK" -ForegroundColor Green
}
function Invoke-ProtectionPreview {
  param([string]$PolicyProfile)
  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
  Write-Host ("SHUTTERWALL PROTECT :: " + $PolicyProfile) -ForegroundColor Cyan
  Write-Host "Step 1/3: Analyze devices..." -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") -RepoRoot $RepoRoot -RunRoot $latest
  Write-Host "Step 2/3: Build protection plan..." -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile $PolicyProfile
  Write-Host "Step 3/3: Preview protection actions..." -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") -RepoRoot $RepoRoot -RunRoot $latest -WhatIf
  Write-Host ""
  Write-Host "To apply HOME-SAFE protections, run elevated PowerShell and use:" -ForegroundColor Yellow
  Write-Host "  shutterwall apply" -ForegroundColor Yellow
  Write-Host "For strict enterprise quarantine behavior, use:" -ForegroundColor Yellow
  Write-Host "  shutterwall apply-enterprise" -ForegroundColor Yellow
  Write-Host "To undo ShutterWall firewall rules later, use:" -ForegroundColor Yellow
  Write-Host "  shutterwall undo" -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_PROTECT_OK" -ForegroundColor Green
}

function Invoke-ProtectionApply {
  param([string]$PolicyProfile)
  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
  Write-Host ("SHUTTERWALL APPLY :: " + $PolicyProfile) -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") -RepoRoot $RepoRoot -RunRoot $latest
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile $PolicyProfile
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") -RepoRoot $RepoRoot -RunRoot $latest -Apply -Force
}

function Invoke-Restore {
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_restore_v1.ps1") -RepoRoot $RepoRoot
}

switch ($Command) {
  "help" {
    Write-Host "ShutterWall commands:"
    Write-Host "  shutterwall inspect           # safe discovery/fingerprint only"
    Write-Host "  shutterwall scan              # home-safe preview"
    Write-Host "  shutterwall scan-business     # small business preview"
    Write-Host "  shutterwall scan-enterprise   # enterprise strict preview"
    Write-Host "  shutterwall apply             # home-safe apply; Administrator required"
    Write-Host "  shutterwall apply-business    # small business apply; Administrator required"
    Write-Host "  shutterwall apply-enterprise  # enterprise strict apply; Administrator required"
    Write-Host "  shutterwall undo              # restore ShutterWall firewall rules; Administrator required"
    Write-Host "  shutterwall protect           # same as scan"
    Write-Host "  shutterwall secure-force      # same as apply-enterprise"
    Write-Host "  shutterwall restore           # same as undo"
    Write-Host "  shutterwall doctor"
    Write-Host "  shutterwall version"
    return
  }
  "version" { Write-Host "SHUTTERWALL_VERSION: 0.3.3"; return }
  "doctor" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
    Write-Host ("LATEST_RUN_ROOT: " + $latest)
    Write-Host "SHUTTERWALL_DOCTOR_OK"
    return
  }
  "inspect" { Invoke-Inspect; return }
  "scan" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "protect" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "secure-low" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "scan-business" { Invoke-ProtectionPreview -PolicyProfile "smallbiz_balanced"; return }
  "secure-smallbiz" { Invoke-ProtectionPreview -PolicyProfile "smallbiz_balanced"; return }
  "scan-enterprise" { Invoke-ProtectionPreview -PolicyProfile "enterprise_strict"; return }
  "secure-enterprise" { Invoke-ProtectionPreview -PolicyProfile "enterprise_strict"; return }
  "apply" { Invoke-ProtectionApply -PolicyProfile "home_safe"; return }
  "apply-business" { Invoke-ProtectionApply -PolicyProfile "smallbiz_balanced"; return }
  "apply-enterprise" { Invoke-ProtectionApply -PolicyProfile "enterprise_strict"; return }
  "secure-force" { Invoke-ProtectionApply -PolicyProfile "enterprise_strict"; return }
  "undo" { Invoke-Restore; return }
  "restore" { Invoke-Restore; return }
  default {
    Write-Host "UNKNOWN_COMMAND"
    Write-Host "Run: shutterwall help"
    return
  }
}
