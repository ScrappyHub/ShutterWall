param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$HeartbeatPath = Join-Path $RepoRoot "state\agent\heartbeat.latest.v1.json"
$EnrollPath = Join-Path $RepoRoot "state\enrollment\enrolled_devices.v1.json"
$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$CorrelationPath = Join-Path $RepoRoot "state\correlation\correlation.latest.v1.json"

$heartbeat = $null
$enrolled = @()
$trusted = 0
$review = 0
$high = 0

if(Test-Path -LiteralPath $HeartbeatPath){
  $heartbeat = Get-Content -LiteralPath $HeartbeatPath -Raw | ConvertFrom-Json
}

if(Test-Path -LiteralPath $EnrollPath){
  $enrollDoc = Get-Content -LiteralPath $EnrollPath -Raw | ConvertFrom-Json
  if($enrollDoc.PSObject.Properties.Name -contains "devices"){ $enrolled = @($enrollDoc.devices) }
}

if(Test-Path -LiteralPath $RegistryPath){
  $reg = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
  foreach($d in @($reg.devices)){
    $trust = if($d.PSObject.Properties.Name -contains "trust_state"){ [string]$d.trust_state } else { "unknown" }
    if($trust -eq "trusted"){ $trusted += 1 } else { $review += 1 }
  }
}

if(Test-Path -LiteralPath $CorrelationPath){
  $corr = Get-Content -LiteralPath $CorrelationPath -Raw | ConvertFrom-Json
  foreach($c in @($corr.correlations)){
    if([string]$c.risk_level -eq "high"){ $high += 1 }
  }
}

Write-Host ("AGENT_HEARTBEAT_PATH: " + $HeartbeatPath)
if($null -ne $heartbeat){
  Write-Host ("AGENT_STATUS: " + [string]$heartbeat.status)
  Write-Host ("AGENT_LAST_RUN: " + [string]$heartbeat.finished_utc)
  Write-Host ("AGENT_DEVICE_COUNT: " + [string]$heartbeat.device_count)
  Write-Host ("AGENT_IDS_FINDING_COUNT: " + [string]$heartbeat.ids_finding_count)
} else {
  Write-Host "AGENT_STATUS: unknown"
}

Write-Host ("AGENT_ENROLLED_DEVICES: " + @($enrolled).Count)
Write-Host ("AGENT_TRUSTED_DEVICES: " + $trusted)
Write-Host ("AGENT_REVIEW_DEVICES: " + $review)
Write-Host ("AGENT_HIGH_RISK_DEVICES: " + $high)
Write-Host "SHUTTERWALL_AGENT_STATUS_V1_OK"
