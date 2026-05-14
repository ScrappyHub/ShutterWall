param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
$TimelinePath = Join-Path $RepoRoot "state\device_timeline\device_timeline.v1.ndjson"
$SpoofPath    = Join-Path $RepoRoot "state\spoof_watch\spoof_watch.latest.v1.json"
$IdsRoot      = Join-Path $RepoRoot "state\ids"
$IdsPath      = Join-Path $IdsRoot "ids_hooks.latest.v1.json"
$AlertsPath   = Join-Path $RepoRoot "state\alerts\alerts.ndjson"

$enc = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [IO.File]::WriteAllText($Path,$norm,$enc)
}

function Append-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [IO.File]::AppendAllText($Path,$norm,$enc)
}

function Has-Prop {
  param($Obj,[string]$Name)
  if($null -eq $Obj){ return $false }
  return (@($Obj.PSObject.Properties.Name) -contains $Name)
}

$devices = @()
if(Test-Path -LiteralPath $RegistryPath){
  $doc = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
  if(Has-Prop $doc "devices"){ $devices = @($doc.devices) }
}

$timelineEvents = @()
if(Test-Path -LiteralPath $TimelinePath){
  foreach($line in @(Get-Content -LiteralPath $TimelinePath -ErrorAction SilentlyContinue)){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    try { $timelineEvents += @($line | ConvertFrom-Json) } catch {}
  }
}

$spoofFindings = @()
if(Test-Path -LiteralPath $SpoofPath){
  try {
    $spoof = Get-Content -LiteralPath $SpoofPath -Raw | ConvertFrom-Json
    if(Has-Prop $spoof "findings"){ $spoofFindings = @($spoof.findings) }
  } catch {}
}

$findings = @()

foreach($d in $devices){
  $ip = [string]$d.ip
  if([string]::IsNullOrWhiteSpace($ip)){ continue }

  $trust = if(Has-Prop $d "trust_state"){ [string]$d.trust_state } else { "unknown" }
  $label = if(Has-Prop $d "label"){ [string]$d.label } else { "Needs Review" }
  $changes = if(Has-Prop $d "change_count"){ [int]$d.change_count } else { 0 }

  if($trust -eq "unknown"){
    $findings += [ordered]@{
      severity = "low"
      type = "unknown_device_requires_review"
      ip = $ip
      label = $label
      explanation = "Device is present in memory but has not been trusted or reviewed."
      recommended_action = "Open Review and classify this device."
    }
  }

  if($changes -gt 0 -and $trust -eq "trusted"){
    $findings += [ordered]@{
      severity = "medium"
      type = "trusted_device_changed"
      ip = $ip
      label = $label
      explanation = "Trusted device has recorded change count greater than zero."
      recommended_action = "Review timeline and confirm the device still matches expectations."
    }
  }
}

foreach($sf in $spoofFindings){
  $findings += [ordered]@{
    severity = [string]$sf.severity
    type = "spoof_watch_signal"
    ip = [string]$sf.ip
    label = [string]$sf.label
    explanation = [string]$sf.explanation
    recommended_action = "Treat as suspicious until verified."
  }
}

$now = [DateTime]::UtcNow.ToString("o")
$docOut = [ordered]@{
  schema = "shutterwall.ids_hooks.v1"
  updated_at_utc = $now
  mode = "semi_active_defensive"
  device_count = @($devices).Count
  timeline_event_count = @($timelineEvents).Count
  spoof_finding_count = @($spoofFindings).Count
  finding_count = @($findings).Count
  findings = @($findings)
}

Write-Utf8NoBomLf -Path $IdsPath -Text ($docOut | ConvertTo-Json -Depth 40)

foreach($f in $findings){
  $alert = [ordered]@{
    schema = "shutterwall.alert.v1"
    timestamp_utc = $now
    severity = [string]$f.severity
    alert_type = "ids_hook_" + [string]$f.type
    ip = [string]$f.ip
    message = [string]$f.explanation
  }
  Append-Utf8NoBomLf -Path $AlertsPath -Text ($alert | ConvertTo-Json -Compress -Depth 20)
}

Write-Host ("IDS_HOOKS_PATH: " + $IdsPath)

$RegistryStatePath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"

$registry = @{
  devices = @()
}

if(Test-Path -LiteralPath $RegistryStatePath){

  $registryRaw = Get-Content -LiteralPath $RegistryStatePath -Raw

  if(-not [string]::IsNullOrWhiteSpace($registryRaw)){
    $registry = $registryRaw | ConvertFrom-Json
  }
}
# fingerprint drift detection
foreach($d in @(@($registry.devices))){

  $trust = "unknown"

  if($d.PSObject.Properties.Name -contains "trust"){
    $trust = [string]$d.trust
  }

  $changes = 0

  if($d.PSObject.Properties.Name -contains "changes"){
    $changes = [int]$d.changes
  }

  $lastFingerprint = ""

  if($d.PSObject.Properties.Name -contains "last_fingerprint"){
    $lastFingerprint = [string]$d.last_fingerprint
  }

  $currentFingerprint = ""

  if($d.PSObject.Properties.Name -contains "fingerprint_hash"){
    $currentFingerprint = [string]$d.fingerprint_hash
  }

  if(
    -not [string]::IsNullOrWhiteSpace($lastFingerprint) -and
    -not [string]::IsNullOrWhiteSpace($currentFingerprint) -and
    $lastFingerprint -ne $currentFingerprint
  ){

    $findings += [PSCustomObject]@{
      severity   = "medium"
      finding    = "fingerprint_drift_detected"
      ip          = $d.ip
      explanation = "Trusted or remembered device fingerprint changed from previous baseline."
    }
  }

  if(
    ($trust -eq "trusted") -and
    ($changes -ge 3)
  ){
    $findings += [PSCustomObject]@{
      severity   = "medium"
      finding    = "trusted_device_instability"
      ip          = $d.ip
      explanation = "Trusted device has repeated state or fingerprint changes."
    }
  }

  if(
    ($trust -eq "unknown") -and
    ($changes -ge 5)
  ){
    $findings += [PSCustomObject]@{
      severity   = "high"
      finding    = "persistent_unknown_activity"
      ip          = $d.ip
      explanation = "Unknown device repeatedly appearing or changing."
    }
  }
}

$lowCount = @($findings | Where-Object { $_.severity -eq "low" }).Count
$mediumCount = @($findings | Where-Object { $_.severity -eq "medium" }).Count
$highCount = @($findings | Where-Object { $_.severity -eq "high" }).Count

Write-Host ("IDS_HOOKS_FINDING_COUNT: " + @($findings).Count)
Write-Host ("IDS_HOOKS_SEVERITY_LOW: " + $lowCount)
Write-Host ("IDS_HOOKS_SEVERITY_MEDIUM: " + $mediumCount)
Write-Host ("IDS_HOOKS_SEVERITY_HIGH: " + $highCount)

foreach($f in $findings){
  Write-Host ("IDS_HOOK_FINDING :: " + $f.severity + " :: " + $f.type + " :: " + $f.ip + " :: " + $f.explanation)
}

Write-Host "SHUTTERWALL_IDS_HOOKS_V1_OK"
