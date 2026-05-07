param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$BaselinePath = Join-Path $RepoRoot "proofs\baseline\baseline_v1.json"
$DiffRoot = Join-Path $RepoRoot "proofs\diff"
$PostureRoot = Join-Path $RepoRoot "state\posture"
$PosturePath = Join-Path $PostureRoot "posture.v1.json"

if(-not (Test-Path $PostureRoot)){
  New-Item -ItemType Directory -Path $PostureRoot -Force | Out-Null
}

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

$devices = @()
if(Test-Path -LiteralPath $RegistryPath){
  try {
    $registry = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
    $devices = @($registry.devices)
  } catch {
    $devices = @()
  }
}

$deviceCount = @($devices).Count
$labeledCount = @($devices | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.user_label) }).Count
$needsReviewCount = @($devices | Where-Object { ([string]$_.engine_guess) -eq "Needs Review" -and [string]::IsNullOrWhiteSpace([string]$_.user_label) }).Count
$unknownTrustCount = @($devices | Where-Object { ([string]$_.trust_state) -eq "unknown" }).Count
$changedDeviceCount = @($devices | Where-Object { [int]$_.change_count -gt 0 }).Count

$baselineExists = Test-Path -LiteralPath $BaselinePath

$latestDiffPath = ""
$latestAlertCount = 0
$latestNetworkState = "UNKNOWN"

if(Test-Path -LiteralPath $DiffRoot){
  $latestDiff = Get-ChildItem -LiteralPath $DiffRoot -Filter "diff_v1_*.json" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

  if($latestDiff){
    $latestDiffPath = $latestDiff.FullName
    try {
      $diffDoc = Get-Content -LiteralPath $latestDiff.FullName -Raw | ConvertFrom-Json
      if($diffDoc.alert_count -ne $null){ $latestAlertCount = [int]$diffDoc.alert_count }
      if($diffDoc.network_state){ $latestNetworkState = [string]$diffDoc.network_state }
    } catch {}
  }
}

$protectionMode = "Preview Only"
if(-not $baselineExists){
  $protectionMode = "Setup Needed"
}
elseif($latestAlertCount -gt 0){
  $protectionMode = "Review Needed"
}
elseif($needsReviewCount -gt 0){
  $protectionMode = "Monitoring With Unknowns"
}
else{
  $protectionMode = "Monitoring"
}

$recommended = "Run Quickstart"
if(-not $baselineExists){
  $recommended = "Create a baseline so ShutterWall can detect changes."
}
elseif($latestAlertCount -gt 0){
  $recommended = "Review the latest network change before re-baselining."
}
elseif($needsReviewCount -gt 0){
  $recommended = "Label recognized devices and review unknown devices."
}
elseif($deviceCount -gt 0){
  $recommended = "Run Diff or Watch periodically to check for changes."
}

$posture = [ordered]@{
  schema = "shutterwall.protection_posture.v1"
  updated_at_utc = [DateTime]::UtcNow.ToString("o")
  protection_mode = $protectionMode
  recommended_action = $recommended
  baseline_exists = [bool]$baselineExists
  device_count = [int]$deviceCount
  labeled_device_count = [int]$labeledCount
  needs_review_count = [int]$needsReviewCount
  unknown_trust_count = [int]$unknownTrustCount
  changed_device_count = [int]$changedDeviceCount
  latest_alert_count = [int]$latestAlertCount
  latest_network_state = $latestNetworkState
  latest_diff_path = $latestDiffPath
}

Write-Utf8NoBomLf -Path $PosturePath -Text ($posture | ConvertTo-Json -Depth 20)

Write-Host ("POSTURE_MODE: " + $posture.protection_mode)
Write-Host ("RECOMMENDED_ACTION: " + $posture.recommended_action)
Write-Host ("DEVICE_COUNT: " + $posture.device_count)
Write-Host ("LABELED_DEVICE_COUNT: " + $posture.labeled_device_count)
Write-Host ("NEEDS_REVIEW_COUNT: " + $posture.needs_review_count)
Write-Host ("UNKNOWN_TRUST_COUNT: " + $posture.unknown_trust_count)
Write-Host ("CHANGED_DEVICE_COUNT: " + $posture.changed_device_count)
Write-Host ("LATEST_ALERT_COUNT: " + $posture.latest_alert_count)
Write-Host ("BASELINE_EXISTS: " + $posture.baseline_exists)
Write-Host ("POSTURE_PATH: " + $PosturePath)
Write-Host "SHUTTERWALL_POSTURE_V1_OK"
