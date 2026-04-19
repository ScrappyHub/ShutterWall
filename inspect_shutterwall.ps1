param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1") `
  -RepoRoot $RepoRoot `
  -StartHost 1 `
  -EndHost 40 `
  -ConnectTimeoutMs 100

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1") `
  -RepoRoot $RepoRoot

Write-Host "SHUTTERWALL_INSPECT_ONE_CLICK_OK" -ForegroundColor Green