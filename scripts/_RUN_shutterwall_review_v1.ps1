param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ReviewRegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$ReviewRegistryDevices = @()

if(Test-Path -LiteralPath $ReviewRegistryPath){
  try {
    $ReviewRegistryState = Get-Content -LiteralPath $ReviewRegistryPath -Raw | ConvertFrom-Json
    if($ReviewRegistryState.PSObject.Properties.Name -contains "devices"){
      $ReviewRegistryDevices = @($ReviewRegistryState.devices)
    }
  } catch {
    $ReviewRegistryDevices = @()
  }
}

function Get-CanonicalReviewDevice {
  param(
    $Device,
    $RegistryDevices
  )

  if($null -eq $Device){ return $Device }

  $ip = ""
  if(@($Device.PSObject.Properties.Name) -contains "ip"){ $ip = [string]$Device.ip }

  if([string]::IsNullOrWhiteSpace($ip)){ return $Device }

  $match = @($RegistryDevices | Where-Object { [string]$_.ip -eq $ip }) | Select-Object -First 1

  if($null -ne $match){ return $match }

  return $Device
}

function Get-CanonicalReviewTrust {
  param($Device)

  if($null -eq $Device){ return "unknown" }

  if(@($Device.PSObject.Properties.Name) -contains "trust_state"){
    $v = [string]$Device.trust_state
    if(-not [string]::IsNullOrWhiteSpace($v)){ return $v }
  }

  if(@($Device.PSObject.Properties.Name) -contains "trust"){
    $v = [string]$Device.trust
    if(-not [string]::IsNullOrWhiteSpace($v)){ return $v }
  }

  return "unknown"
}

function Get-CanonicalReviewLabel {
  param($Device)

  $trust = Get-CanonicalReviewTrust $Device

  if($trust -eq "trusted"){
    if(@($Device.PSObject.Properties.Name) -contains "label" -and -not [string]::IsNullOrWhiteSpace([string]$Device.label) -and [string]$Device.label -ne "Needs Review"){
      return [string]$Device.label
    }
    return "Trusted Device"
  }

  if($trust -eq "review"){ return "Reviewed Device" }
  if($trust -eq "suspicious"){ return "Suspicious Device" }
  if($trust -eq "blocked"){ return "Blocked Device" }

  if(@($Device.PSObject.Properties.Name) -contains "label" -and -not [string]::IsNullOrWhiteSpace([string]$Device.label)){
    return [string]$Device.label
  }

  return "Needs Review"
}

function Get-CanonicalReviewPriority {
  param($Device)

  $trust = Get-CanonicalReviewTrust $Device

  if($trust -in @("trusted","review","suspicious","blocked")){ return "recognized" }

  if(@($Device.PSObject.Properties.Name) -contains "reviewed" -and [bool]$Device.reviewed){ return "recognized" }
  if(@($Device.PSObject.Properties.Name) -contains "review_required" -and -not [bool]$Device.review_required){ return "recognized" }
  if(@($Device.PSObject.Properties.Name) -contains "needs_review" -and -not [bool]$Device.needs_review){ return "recognized" }

  return "review_required"
}

function Is-ReviewDeviceKnown {
  param($Device)

  if($null -eq $Device){ return $false }

  $trust = ""
  if(@($Device.PSObject.Properties.Name) -contains "trust_state"){ $trust = [string]$Device.trust_state }
  elseif(@($Device.PSObject.Properties.Name) -contains "trust"){ $trust = [string]$Device.trust }

  if($trust -in @("trusted","review","suspicious","blocked")){ return $true }

  if(@($Device.PSObject.Properties.Name) -contains "reviewed" -and [bool]$Device.reviewed){ return $true }
  if(@($Device.PSObject.Properties.Name) -contains "review_required" -and -not [bool]$Device.review_required){ return $true }
  if(@($Device.PSObject.Properties.Name) -contains "needs_review" -and -not [bool]$Device.needs_review){ return $true }

  return $false
}

function Get-ReviewDeviceLabel {
  param($Device)

  if(Is-ReviewDeviceKnown $Device){
    $trust = ""
    if(@($Device.PSObject.Properties.Name) -contains "trust_state"){ $trust = [string]$Device.trust_state }
    elseif(@($Device.PSObject.Properties.Name) -contains "trust"){ $trust = [string]$Device.trust }

    if($trust -eq "trusted"){ return "Trusted Device" }
    if($trust -eq "review"){ return "Reviewed Device" }
    if($trust -eq "suspicious"){ return "Suspicious Device" }
    if($trust -eq "blocked"){ return "Blocked Device" }

    return "Reviewed Device"
  }

  return "Needs Review"
}

function Get-ReviewDevicePriority {
  param($Device)

  if(Is-ReviewDeviceKnown $Device){ return "recognized" }

  return "review_required"
}

function Get-ReviewTrustState {
  param($Device)

  if($null -eq $Device){ return "unknown" }
  if(@($Device.PSObject.Properties.Name) -contains "trust"){ return [string]$Device.trust }
  if(@($Device.PSObject.Properties.Name) -contains "trust_state"){ return [string]$Device.trust_state }

  return "unknown"
}

$ServiceProfilePath = Join-Path $RepoRoot "state\service_profiles\service_profile.latest.v1.json"
$serviceProfiles = @()
$CorrelationPath = Join-Path $RepoRoot "state\correlation\correlation.latest.v1.json"
$correlations = @()

if(Test-Path -LiteralPath $CorrelationPath){
  try {
    $corrState = Get-Content -LiteralPath $CorrelationPath -Raw | ConvertFrom-Json
    if($corrState.PSObject.Properties.Name -contains "correlations"){
      $correlations = @($corrState.correlations)
    }
  } catch {
    $correlations = @()
  }
}

if(Test-Path -LiteralPath $ServiceProfilePath){
  try {
    $svc = Get-Content -LiteralPath $ServiceProfilePath -Raw | ConvertFrom-Json
    if($svc.PSObject.Properties.Name -contains "profiles"){
      $serviceProfiles = @($svc.profiles)
    }
  } catch {
    $serviceProfiles = @()
$CorrelationPath = Join-Path $RepoRoot "state\correlation\correlation.latest.v1.json"
$correlations = @()

if(Test-Path -LiteralPath $CorrelationPath){
  try {
    $corrState = Get-Content -LiteralPath $CorrelationPath -Raw | ConvertFrom-Json
    if($corrState.PSObject.Properties.Name -contains "correlations"){
      $correlations = @($corrState.correlations)
    }
  } catch {
    $correlations = @()
  }
}
  }
}

function Get-ReviewProp {
  param(
    $Obj,
    [string]$Name,
    $Default = ""
  )

  if($null -eq $Obj){ return $Default }

  if(@($Obj.PSObject.Properties.Name) -contains $Name){
    $v = $Obj.$Name
    if($null -eq $v){ return $Default }
    return $v
  }

  return $Default
}


function Get-PropValue {
  param(
    $Obj,
    [string]$Name,
    $Default = $null
  )

  if($null -eq $Obj){ return $Default }

  if(@($Obj.PSObject.Properties.Name) -contains $Name){
    $value = $Obj.$Name
    if($null -eq $value){ return $Default }
    return $value
  }

  return $Default
}


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
  else { $action = "$(if((Get-CanonicalReviewTrust $d) -in @("trusted","review","suspicious","blocked")){ "Recognized. Keep monitoring for fingerprint or baseline changes." } else { "$(if((Get-CanonicalReviewTrust $d) -in @("trusted","review","suspicious","blocked")){ "Recognized. Keep monitoring for fingerprint or baseline changes." } else { "Identify this device, then choose trusted, review, or suspicious." })" })" }

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
  $priority = "normal"

$changes = 0

if($d.PSObject.Properties.Name -contains "changes"){
  $changes = [int]$d.changes
}

if($trust -eq "unknown"){
  $priority = "review_required"
}

if($changes -ge 3){
  $priority = "elevated"
}

$priority = Get-ReviewDevicePriority $d
$d = Get-CanonicalReviewDevice -Device $d -RegistryDevices $ReviewRegistryDevices
$priority = Get-CanonicalReviewPriority $d
Write-Host ("REVIEW_PRIORITY :: " + $priority)

$matchedRisk = @($correlations | Where-Object { [string]$_.ip -eq [string]$d.ip }) | Select-Object -First 1
if($null -ne $matchedRisk){
  Write-Host ("REVIEW_RISK :: " + $d.ip + " :: " + $matchedRisk.risk_level + " :: score=" + $matchedRisk.risk_score + " :: reasons=" + (@($matchedRisk.reasons) -join ","))
}

$serviceClass = ""
$serviceConfidence = ""
$servicePorts = ""

if($d.PSObject.Properties.Name -contains "service_class"){ $serviceClass = [string]$d.service_class }
if($d.PSObject.Properties.Name -contains "service_confidence_percent"){ $serviceConfidence = [string]$d.service_confidence_percent }
if($d.PSObject.Properties.Name -contains "open_ports"){ $servicePorts = (@($d.open_ports) -join ",") }

if(-not [string]::IsNullOrWhiteSpace($serviceClass)){
  Write-Host ("REVIEW_SERVICE :: " + $d.ip + " :: " + $serviceClass + " :: confidence=" + $serviceConfidence + "% :: ports=" + $servicePorts)
}

$matchedService = @($serviceProfiles | Where-Object { [string]$_.ip -eq [string]$d.ip }) | Select-Object -First 1

if($null -ne $matchedService){
  $svcPorts = (@($matchedService.open_ports) -join ",")
  Write-Host ("REVIEW_SERVICE :: " + $d.ip + " :: " + $matchedService.device_class + " :: confidence=" + $matchedService.confidence_percent + "% :: ports=" + $svcPorts)
  Write-Host "REVIEW_SERVICE_DIRECT_V1"
}

Write-Host ("REVIEW_DEVICE :: " + $d.ip + " :: " + (Get-CanonicalReviewLabel $d) + " :: trust=" + (Get-CanonicalReviewTrust $d) + " :: changes=" + $d.change_count + " :: first_seen=" + $(if($d.PSObject.Properties.Name -contains "first_seen_utc"){ (Get-PropValue $d "first_seen_utc" "") } else { "" }) + " :: last_seen=" + $d.last_seen_utc + " :: reviewed=" + $(if($d.PSObject.Properties.Name -contains "last_reviewed_utc"){ (Get-PropValue $d "last_reviewed_utc" "") } else { "" }) + " :: source=" + $(if($d.PSObject.Properties.Name -contains "review_decision_source"){ (Get-PropValue $d "review_decision_source" "") } else { "" }) + " :: change=" + $(if($d.PSObject.Properties.Name -contains "last_change_type"){ (Get-PropValue $d "last_change_type" "") } else { "" }) + " :: action=" + $d.recommended_action)
}

Write-Host "SHUTTERWALL_REVIEW_V1_OK"
