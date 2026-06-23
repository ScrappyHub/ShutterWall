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

function Invoke-ShutterWallStep {
  param(
    [string]$Name,
    [string[]]$Args
  )

  Write-Host ("AGENT_STEP_START :: " + $Name)

  & (Join-Path $RepoRoot "shutterwall.ps1") @Args

  if($LASTEXITCODE -ne 0){
    throw ("AGENT_STEP_FAILED: " + $Name)
  }

  Write-Host ("AGENT_STEP_OK :: " + $Name)
}

$started = [DateTime]::UtcNow

Invoke-ShutterWallStep -Name "lab-scan" -Args @("lab-scan")
Invoke-ShutterWallStep -Name "service-classify" -Args @("service-classify")
Invoke-ShutterWallStep -Name "service-promote" -Args @("service-promote")

try {
  Invoke-ShutterWallStep -Name "service-drift" -Args @("service-drift")
} catch {
  Write-Host ("AGENT_STEP_WARN :: service-drift :: " + $_.Exception.Message)
}

Invoke-ShutterWallStep -Name "ids-hooks" -Args @("ids-hooks")
Invoke-ShutterWallStep -Name "correlate" -Args @("correlate")
Invoke-ShutterWallStep -Name "review" -Args @("review")

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
  if($reg.PSObject.Properties.Name -contains "devices"){
    $deviceCount = @($reg.devices).Count
  }
}

if(Test-Path -LiteralPath $idsPath){
  $ids = Get-Content -LiteralPath $idsPath -Raw | ConvertFrom-Json
  if($ids.PSObject.Properties.Name -contains "findings"){
    $findingCount = @($ids.findings).Count
  }
}

if(Test-Path -LiteralPath $correlationPath){
  $corr = Get-Content -LiteralPath $correlationPath -Raw | ConvertFrom-Json
  if($corr.PSObject.Properties.Name -contains "correlations"){
    $riskDeviceCount = @($corr.correlations).Count
  }
}

if(Test-Path -LiteralPath $reviewPath){
  $review = Get-Content -LiteralPath $reviewPath -Raw | ConvertFrom-Json
  if($review.PSObject.Properties.Name -contains "devices"){
    $reviewDeviceCount = @($review.devices).Count
  }
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
