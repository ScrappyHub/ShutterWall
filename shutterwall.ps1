param(
  [Parameter(Position=0)][string]$Command,
  [Parameter(Position=1)][string]$Arg1 = "",
  [Parameter(Position=2)][string]$Arg2 = "",
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$SelfPath = $MyInvocation.MyCommand.Path

function Test-IsAdministrator {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ElevatedSelf {
  param([string]$ElevatedCommand)
  $argText = "-NoProfile -ExecutionPolicy Bypass -File `"" + $SelfPath + "`" " + $ElevatedCommand + " -RepoRoot `"" + $RepoRoot + "`""
  Write-Host ("Requesting Administrator PowerShell for: " + $ElevatedCommand) -ForegroundColor Yellow
  Start-Process -FilePath $PSExe -Verb RunAs -ArgumentList $argText
}

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

function Invoke-Watch {
  $count = 3
  if(-not [string]::IsNullOrWhiteSpace($Arg1)){ $count = [int]$Arg1 }
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_watch_v1.ps1") -RepoRoot $RepoRoot -Count $count -IntervalSeconds 10
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
  Write-Host "To apply protections, use: shutterwall apply" -ForegroundColor Yellow
  Write-Host "To undo ShutterWall firewall rules, use: shutterwall undo" -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_PROTECT_OK" -ForegroundColor Green
}

function Invoke-ProtectionApply {
  param([string]$PolicyProfile,[string]$ElevatedCommand)
  if(-not (Test-IsAdministrator)){ Invoke-ElevatedSelf -ElevatedCommand $ElevatedCommand; return }
  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
  Write-Host ("SHUTTERWALL APPLY :: " + $PolicyProfile) -ForegroundColor Cyan
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") -RepoRoot $RepoRoot -RunRoot $latest
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") -RepoRoot $RepoRoot -RunRoot $latest -PolicyProfile $PolicyProfile
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") -RepoRoot $RepoRoot -RunRoot $latest -Apply -Force
}

function Invoke-Restore {
  if(-not (Test-IsAdministrator)){ Invoke-ElevatedSelf -ElevatedCommand "undo"; return }
  & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_restore_v1.ps1") -RepoRoot $RepoRoot -Force
}

function Invoke-Quickstart {
  Write-Host "SHUTTERWALL QUICKSTART" -ForegroundColor Cyan
  Write-Host "1) Inspect discovers devices only." -ForegroundColor Cyan
  Invoke-Inspect
  Write-Host ""
  Write-Host "2) Scan previews home-safe protections." -ForegroundColor Cyan
  Invoke-ProtectionPreview -PolicyProfile "home_safe"
  Write-Host ""
  Write-Host "Next: run shutterwall apply to request Administrator elevation and apply home-safe protections." -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_QUICKSTART_OK" -ForegroundColor Green
}

switch ($Command) {
  "help" {
    Write-Host "ShutterWall commands:"
    Write-Host "  shutterwall quickstart        # guided inspect + home-safe scan"
    Write-Host "  shutterwall inspect           # safe discovery/fingerprint only"
    Write-Host "  shutterwall watch [count]     # repeated safe device snapshots"
    Write-Host "  shutterwall baseline          # create trusted network baseline"
    Write-Host "  shutterwall diff              # compare current network to baseline"
    Write-Host "  shutterwall scan              # home-safe preview"
    Write-Host "  shutterwall scan-business     # small business preview"
    Write-Host "  shutterwall scan-enterprise   # enterprise strict preview"
    Write-Host "  shutterwall apply             # home-safe apply; auto-elevates"
    Write-Host "  shutterwall apply-business    # small business apply; auto-elevates"
    Write-Host "  shutterwall apply-enterprise  # enterprise strict apply; auto-elevates"
    Write-Host "  shutterwall undo              # restore ShutterWall firewall rules; auto-elevates"
    Write-Host "  shutterwall doctor"
    Write-Host "  shutterwall version"
    return
  }
  "version" { Write-Host "SHUTTERWALL_VERSION: 0.3.4"; return }
  "doctor" { $latest = Get-LatestRunRoot -RepoRoot $RepoRoot; Write-Host ("LATEST_RUN_ROOT: " + $latest); Write-Host "SHUTTERWALL_DOCTOR_OK"; return }
  "quickstart" { Invoke-Quickstart; return }
  "inspect" { Invoke-Inspect; return }
  "watch" { Invoke-Watch; return }
  "baseline" { & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_baseline_v1.ps1") -RepoRoot $RepoRoot; return }
  "diff" { & $PSExe -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_diff_v1.ps1") -RepoRoot $RepoRoot; return }
  "scan" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "protect" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "secure-low" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "scan-business" { Invoke-ProtectionPreview -PolicyProfile "smallbiz_balanced"; return }
  "scan-enterprise" { Invoke-ProtectionPreview -PolicyProfile "enterprise_strict"; return }
  "apply" { Invoke-ProtectionApply -PolicyProfile "home_safe" -ElevatedCommand "apply"; return }
  "apply-business" { Invoke-ProtectionApply -PolicyProfile "smallbiz_balanced" -ElevatedCommand "apply-business"; return }
  "apply-enterprise" { Invoke-ProtectionApply -PolicyProfile "enterprise_strict" -ElevatedCommand "apply-enterprise"; return }
  "secure-force" { Invoke-ProtectionApply -PolicyProfile "enterprise_strict" -ElevatedCommand "secure-force"; return }
  "undo" { Invoke-Restore; return }
  "restore" { Invoke-Restore; return }
  default { Write-Host "UNKNOWN_COMMAND"; Write-Host "Run: shutterwall help"; return }
}
