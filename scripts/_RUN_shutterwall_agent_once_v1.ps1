param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location $RepoRoot

$HeartbeatDir = Join-Path $RepoRoot "state\agent"
$ProofDir = Join-Path $RepoRoot "proofs\agent"
$HeartbeatPath = Join-Path $HeartbeatDir "heartbeat.latest.v1.json"

New-Item -ItemType Directory -Force -Path $HeartbeatDir,$ProofDir | Out-Null

function Invoke-AgentScript {
  param(
    [string]$Name,
    [string]$ScriptName,
    [int]$TimeoutMs = 120000
  )

  $scriptPath = Join-Path $RepoRoot $ScriptName
  if(-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)){
    throw ("AGENT_SCRIPT_MISSING: " + $Name + " :: " + $scriptPath)
  }

  Write-Host ("AGENT_STEP_START :: " + $Name)

  $argList = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $scriptPath,
    "-RepoRoot",
    $RepoRoot
  )

  $p = Start-Process `
    -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -ArgumentList $argList `
    -PassThru `
    -NoNewWindow

  if(-not $p.WaitForExit($TimeoutMs)){
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    throw ("AGENT_STEP_TIMEOUT: " + $Name)
  }

  if($null -ne $p.ExitCode -and [int]$p.ExitCode -ne 0){
    throw ("AGENT_STEP_FAILED: " + $Name + " :: exit=" + [string]$p.ExitCode)
  }

  Write-Host ("AGENT_STEP_OK :: " + $Name)
}

$started = [DateTime]::UtcNow

Invoke-AgentScript -Name "lab-scan" -ScriptName "scripts\_RUN_shutterwall_lab_scan_v1.ps1"
Invoke-AgentScript -Name "service-classify" -ScriptName "scripts\_RUN_shutterwall_service_classifier_v1.ps1"
Invoke-AgentScript -Name "service-promote" -ScriptName "scripts\_RUN_shutterwall_promote_service_profile_v1.ps1"

try {
  Invoke-AgentScript -Name "service-drift" -ScriptName "scripts\_RUN_shutterwall_service_drift_v1.ps1"
} catch {
  Write-Host ("AGENT_STEP_WARN :: service-drift :: " + $_.Exception.Message)
}

Invoke-AgentScript -Name "ids-hooks" -ScriptName "scripts\_RUN_shutterwall_ids_hooks_v1.ps1"
Invoke-AgentScript -Name "correlate" -ScriptName "scripts\_RUN_shutterwall_correlation_engine_v1.ps1"
Invoke-AgentScript -Name "review" -ScriptName "scripts\_RUN_shutterwall_review_v1.ps1"

$registryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$idsPath = Join-Path $RepoRoot "state\ids\ids_hooks.latest.v1.json"
$correlationPath = Join-Path $RepoRoot "state\correlation\correlation.latest.v1.json"
$reviewPath = Join-Path $RepoRoot "state\review\review.latest.v1.json"

$deviceCount = 0
$findingCount = 0
$riskDeviceCount = 0
$reviewDeviceCount = 0

if(Test-Path -LiteralPath $registryPath){
  $reg = Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json
  if($reg.PSObject.Properties.Name -contains "devices"){ $deviceCount = @($reg.devices).Count }
}

if(Test-Path -LiteralPath $idsPath){
  $ids = Get-Content -LiteralPath $idsPath -Raw | ConvertFrom-Json
  if($ids.PSObject.Properties.Name -contains "findings"){ $findingCount = @($ids.findings).Count }
}

if(Test-Path -LiteralPath $correlationPath){
  $corr = Get-Content -LiteralPath $correlationPath -Raw | ConvertFrom-Json
  if($corr.PSObject.Properties.Name -contains "correlations"){ $riskDeviceCount = @($corr.correlations).Count }
}

if(Test-Path -LiteralPath $reviewPath){
  $review = Get-Content -LiteralPath $reviewPath -Raw | ConvertFrom-Json
  if($review.PSObject.Properties.Name -contains "devices"){ $reviewDeviceCount = @($review.devices).Count }
}

$finished = [DateTime]::UtcNow

$heartbeat = [ordered]@{
  schema = "shutterwall.agent.heartbeat.v1"
  status = "ok"
  started_utc = $started.ToString("o")
  finished_utc = $finished.ToString("o")
  duration_seconds = [int][Math]::Round(($finished - $started).TotalSeconds)
  device_count = $deviceCount
  ids_finding_count = $findingCount
  correlation_device_count = $riskDeviceCount
  review_device_count = $reviewDeviceCount
  mode = "once"
}

($heartbeat | ConvertTo-Json -Depth 40) | Set-Content -Encoding UTF8 $HeartbeatPath

$stamp = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
$receiptPath = Join-Path $ProofDir ("agent_once_" + $stamp + ".receipt.json")
($heartbeat | ConvertTo-Json -Depth 40) | Set-Content -Encoding UTF8 $receiptPath

Write-Host ("AGENT_HEARTBEAT_PATH: " + $HeartbeatPath)
Write-Host ("AGENT_RECEIPT_PATH: " + $receiptPath)
Write-Host ("AGENT_DEVICE_COUNT: " + $deviceCount)
Write-Host ("AGENT_IDS_FINDING_COUNT: " + $findingCount)
Write-Host ("AGENT_REVIEW_DEVICE_COUNT: " + $reviewDeviceCount)
Write-Host "SHUTTERWALL_AGENT_ONCE_V1_OK"
