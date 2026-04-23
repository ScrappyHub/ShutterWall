param(
  [Parameter(Position=0)][string]$Command = "help",
  [Parameter(Position=1)][string]$Arg1 = "",
  [Parameter(Position=2)][string]$Arg2 = "",
  [Parameter(Position=3)][string]$Arg3 = "",
  [Parameter(Position=4)][string]$Arg4 = ""
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

function Show-Help {
  Write-Host "ShutterWall CLI" -ForegroundColor Cyan
  Write-Host "Commands:" -ForegroundColor Cyan
  Write-Host "  shutterwall help"
  Write-Host "  shutterwall version"
  Write-Host "  shutterwall doctor"
  Write-Host "  shutterwall quick-check"
  Write-Host "  shutterwall inspect"
  Write-Host "  shutterwall secure-home"
  Write-Host "  shutterwall secure-smallbiz"
  Write-Host "  shutterwall secure-enterprise"
  Write-Host "  shutterwall secure-force"
  Write-Host "  shutterwall replay-confirmed-camera <ip> [runroot]"
  Write-Host "  shutterwall live-whatif"
  Write-Host "  shutterwall live-apply"
}

switch ($Command.ToLowerInvariant()) {
  "help" { Show-Help }

  "version" {
    Write-Host "SHUTTERWALL_VERSION: 0.3.0" -ForegroundColor Green
  }

  "doctor" {
    $ok = $true
    $required = @(
      "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1",
      "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1",
      "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1",
      "scripts\_RUN_shutterwall_live_enforcement_v3.ps1",
      "scripts\_RUN_shutterwall_operator_review_v1.ps1",
      "inspect_shutterwall.ps1",
      "analyze_confirmed_camera.ps1",
      "shutterwall.ps1"
    )

    foreach ($rel in $required) {
      $p = Join-Path $RepoRoot $rel
      if (-not (Test-Path -LiteralPath $p)) {
        Write-Host ("MISSING: " + $p) -ForegroundColor Red
        $ok = $false
      }
    }

    $latestRun = $null
    try { $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot } catch {}
    if ($latestRun) { Write-Host ("LATEST_RUN_ROOT: " + $latestRun) -ForegroundColor Cyan }

    if ($ok) { Write-Host "SHUTTERWALL_DOCTOR_OK" -ForegroundColor Green } else { throw "SHUTTERWALL_DOCTOR_FAIL" }
  }

  "quick-check" {
    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "inspect_shutterwall.ps1")
  }

  "inspect" {
    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "inspect_shutterwall.ps1")
  }

  "secure-home" {
    $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -PolicyProfile home_safe

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -WhatIf
  }

  "secure-smallbiz" {
    $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -PolicyProfile smallbiz_balanced

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -WhatIf
  }

  "secure-enterprise" {
    $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -PolicyProfile enterprise_strict

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -WhatIf
  }

  "secure-force" {
    $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -PolicyProfile enterprise_strict

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -Apply
      -Force
  }

  "replay-confirmed-camera" {
    if ([string]::IsNullOrWhiteSpace($Arg1)) { throw "IP_REQUIRED" }
    $ip = $Arg1
    $runRoot = if ([string]::IsNullOrWhiteSpace($Arg2)) { Get-LatestRunRoot -RepoRoot $RepoRoot } else { $Arg2 }

    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "analyze_confirmed_camera.ps1") `
      -Ip $ip `
      -RunRoot $runRoot
  }

  "live-whatif" {
    $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot
    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -WhatIf
  }

  "live-apply" {
    $latestRun = Get-LatestRunRoot -RepoRoot $RepoRoot
    & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
      -RepoRoot $RepoRoot `
      -RunRoot $latestRun `
      -Apply
      -Force
  }

  default { throw ("UNKNOWN_COMMAND: " + $Command) }
}
