param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$RegPath = Join-Path $RepoRoot "state\agent\agent.registration.v1.json"
$WatchPath = Join-Path $RepoRoot "state\watch\watch.status.v1.json"
$PosturePath = Join-Path $RepoRoot "state\posture\posture.v1.json"
$CorrelationPath = Join-Path $RepoRoot "state\correlation\correlation.latest.v1.json"
$OutPath = Join-Path $RepoRoot "state\agent\agent.status.v1.json"

if(-not (Test-Path -LiteralPath $RegPath)){ throw "AGENT_NOT_ENROLLED" }

$reg = Get-Content -LiteralPath $RegPath -Raw | ConvertFrom-Json

$watch = $null
if(Test-Path -LiteralPath $WatchPath){ $watch = Get-Content -LiteralPath $WatchPath -Raw | ConvertFrom-Json }

$posture = $null
if(Test-Path -LiteralPath $PosturePath){ $posture = Get-Content -LiteralPath $PosturePath -Raw | ConvertFrom-Json }

$corr = $null
if(Test-Path -LiteralPath $CorrelationPath){ $corr = Get-Content -LiteralPath $CorrelationPath -Raw | ConvertFrom-Json }

$riskMax = "unknown"
if($null -ne $corr){
  $levels = @($corr.correlations | ForEach-Object { [string]$_.risk_level })
  if($levels -contains "high"){ $riskMax = "high" }
  elseif($levels -contains "medium"){ $riskMax = "medium" }
  elseif($levels -contains "low"){ $riskMax = "low" }
  else { $riskMax = "normal" }
}

$status = [ordered]@{
  schema = "shutterwall.agent.status.v1"
  generated_utc = [DateTime]::UtcNow.ToString("o")
  device_label = [string]$reg.device_label
  mode = [string]$reg.mode
  ips_enabled = [bool]$reg.ips_enabled
  auto_block_enabled = [bool]$reg.auto_block_enabled
  watch_ok = if($null -ne $watch){ [bool]$watch.ok } else { $false }
  last_watch_finished_utc = if($null -ne $watch){ [string]$watch.finished_at_utc } else { "" }
  posture = if($null -ne $posture){ [string]$posture.posture_mode } else { "unknown" }
  max_risk = $riskMax
}

($status | ConvertTo-Json -Depth 20) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("AGENT_STATUS_PATH: " + $OutPath)
Write-Host ("AGENT_DEVICE_LABEL: " + $status.device_label)
Write-Host ("AGENT_MODE: " + $status.mode)
Write-Host ("AGENT_WATCH_OK: " + $status.watch_ok)
Write-Host ("AGENT_POSTURE: " + $status.posture)
Write-Host ("AGENT_MAX_RISK: " + $status.max_risk)
Write-Host "SHUTTERWALL_AGENT_STATUS_V1_OK"
