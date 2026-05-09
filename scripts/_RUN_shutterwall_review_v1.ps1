param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$PosturePath  = Join-Path $RepoRoot "state\posture\posture.v1.json"
$ReviewRoot   = Join-Path $RepoRoot "state\review"
$ReviewPath   = Join-Path $ReviewRoot "review.latest.v1.json"
$DiffRoot     = Join-Path $RepoRoot "proofs\diff"
$RunsRoot     = Join-Path $RepoRoot "proofs\runs\shutterwall"
$AlertsPath   = Join-Path $RepoRoot "state\alerts\alerts.ndjson"

$enc = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Read-JsonSafe {
  param([string]$Path)
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ return $null }
  try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) } catch { return $null }
}

$registry = Read-JsonSafe -Path $RegistryPath
$posture = Read-JsonSafe -Path $PosturePath

$devices = @()
if($registry -and $registry.devices){ $devices = @($registry.devices) }

$latestDiffPath = ""
$latestDiff = $null
if(Test-Path -LiteralPath $DiffRoot -PathType Container){
  $latestDiffFile = Get-ChildItem -LiteralPath $DiffRoot -Filter "diff_v1_*.json" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
  if($latestDiffFile){
    $latestDiffPath = $latestDiffFile.FullName
    $latestDiff = Read-JsonSafe -Path $latestDiffPath
  }
}

$latestRunRoot = ""
$lastScannedUtc = ""
if(Test-Path -LiteralPath $RunsRoot -PathType Container){
  $latestRun = Get-ChildItem -LiteralPath $RunsRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
  if($latestRun){
    $latestRunRoot = $latestRun.FullName
    $lastScannedUtc = $latestRun.LastWriteTimeUtc.ToString("o")
  }
}

$alertItems = @()
if(Test-Path -LiteralPath $AlertsPath -PathType Leaf){
  foreach($line in @(Get-Content -LiteralPath $AlertsPath -ErrorAction SilentlyContinue)){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    try { $alertItems += @($line | ConvertFrom-Json) } catch {}
  }
}

$reviewDevices = @()
foreach($d in $devices){
  $trust = [string]$d.trust_state
  if([string]::IsNullOrWhiteSpace($trust)){ $trust = "unknown" }

  $label = [string]$d.user_label
  if([string]::IsNullOrWhiteSpace($label)){ $label = [string]$d.engine_guess }
  if([string]::IsNullOrWhiteSpace($label)){ $label = "Unrecognized Device" }

  $action = "No action required."
  if($trust -eq "trusted"){ $action = "Recognized. Keep monitoring for fingerprint or baseline changes." }
  elseif($trust -eq "review"){ $action = "Verify this device before trusting it." }
  elseif($trust -eq "blocked"){ $action = "Marked suspicious. Confirm before enforcement." }
  else { $action = "Identify this device, then choose trusted, review, or suspicious." }

  $reviewDevices += [ordered]@{
    ip = [string]$d.ip
    label = $label
    trust_state = $trust
    engine_guess = [string]$d.engine_guess
    last_seen_utc = [string]$d.last_seen_utc
    change_count = [int]$d.change_count
    recommended_action = $action
  }
}

$doc = [ordered]@{
  schema = "shutterwall.review.v1"
  updated_at_utc = [DateTime]::UtcNow.ToString("o")
  posture_mode = if($posture){ [string]$posture.protection_mode } else { "Unknown" }
  recommended_action = if($posture){ [string]$posture.recommended_action } else { "Run posture." }
  device_count = @($reviewDevices).Count
  latest_run_root = $latestRunRoot
  last_scanned_utc = $lastScannedUtc
  latest_diff_path = $latestDiffPath
  latest_alert_count = if($posture){ [int]$posture.latest_alert_count } else { 0 }
  alert_history_count = @($alertItems).Count
  devices = @($reviewDevices)
}

Write-Utf8NoBomLf -Path $ReviewPath -Text ($doc | ConvertTo-Json -Depth 30)

Write-Host ("REVIEW_PATH: " + $ReviewPath)
Write-Host ("REVIEW_POSTURE: " + $doc.posture_mode)
Write-Host ("REVIEW_RECOMMENDED_ACTION: " + $doc.recommended_action)
Write-Host ("REVIEW_DEVICE_COUNT: " + $doc.device_count)
Write-Host ("REVIEW_LAST_SCANNED_UTC: " + $doc.last_scanned_utc)
Write-Host ("REVIEW_LATEST_DIFF_PATH: " + $doc.latest_diff_path)
Write-Host ("REVIEW_ALERT_HISTORY_COUNT: " + $doc.alert_history_count)

foreach($d in @($reviewDevices)){
  Write-Host ("REVIEW_DEVICE :: " + $d.ip + " :: " + $d.label + " :: trust=" + $d.trust_state + " :: changes=" + $d.change_count + " :: first_seen=" + $d.first_seen_utc + " :: last_seen=" + $d.last_seen_utc + " :: reviewed=" + $d.last_reviewed_utc + " :: source=" + $d.review_decision_source + " :: change=" + $d.last_change_type + " :: action=" + $d.recommended_action)
}

Write-Host "SHUTTERWALL_REVIEW_V1_OK"
