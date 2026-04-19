param(
  [Parameter(Mandatory=$true)][string]$Ip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_operator_review_v1.ps1") `
  -RepoRoot $RepoRoot `
  -Ip $Ip `
  -Disposition confirmed_camera `
  -Note "One-click confirmed camera replay." `
  -OperatorId local_operator

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
  -RepoRoot $RepoRoot

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enforcement_plan_v2.ps1") `
  -RepoRoot $RepoRoot `
  -MinimumSeverity medium

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_live_enforcement_v3.ps1") `
  -RepoRoot $RepoRoot `
  -WhatIf

Write-Host "SHUTTERWALL_CONFIRMED_CAMERA_ONE_CLICK_OK" -ForegroundColor Green