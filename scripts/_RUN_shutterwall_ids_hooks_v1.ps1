param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$IdsSuppressHours = 24


function Test-IdsSuppressed {
  param(
    $Entry,
    [datetime]$NowUtc,
    [int]$SuppressHours
  )

  if($null -eq $Entry){ return $false }

  $last = ""
  if($Entry.PSObject.Properties.Name -contains "last_alerted_utc"){
    $last = [string]$Entry.last_alerted_utc
  }

  if([string]::IsNullOrWhiteSpace($last)){ return $false }

  try {
    $lastDt = [datetime]::Parse($last).ToUniversalTime()
    $delta = $NowUtc - $lastDt
    return ($delta.TotalHours -lt $SuppressHours)
  } catch {
    return $false
  }
}
function Get-FindingKey {
  param($Finding)
  $t = ""
  if($Finding.PSObject.Properties.Name -contains "type"){ $t = [string]$Finding.type }
  elseif($Finding.PSObject.Properties.Name -contains "alert_type"){ $t = [string]$Finding.alert_type }
  $ip = ""
  if($Finding.PSObject.Properties.Name -contains "ip"){ $ip = [string]$Finding.ip }
  return ($t + "|" + $ip)
}

function Load-IdsMemory {
  param([string]$Path)

  if(-not (Test-Path -LiteralPath $Path)){
    return [ordered]@{
      schema = "shutterwall.ids_alert_memory.v1"
      entries = @()
    }
  }

  try {
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  } catch {
    return [ordered]@{
      schema = "shutterwall.ids_alert_memory.v1"
      entries = @()
    }
  }
}

function Save-IdsMemory {
  param($Memory,[string]$Path)

  $txt = $Memory | ConvertTo-Json -Depth 50
  Write-Utf8NoBomLf -Path $Path -Text $txt
}

function Get-IdsMemoryEntry {
  param($Memory,[string]$Key)

  foreach($e in @($Memory.entries)){
    if([string]$e.key -eq $Key){ return $e }
  }

  return $null
}
function Test-AlertAlreadyWrittenToday {
  param(
    [string]$Path,
    [string]$AlertType,
    [string]$Ip,
    [string]$DayPrefix
  )

  if(-not (Test-Path -LiteralPath $Path)){ return $false }

  foreach($line in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    try {
      $a = $line | ConvertFrom-Json
      $ts = ""
      if($a.PSObject.Properties.Name -contains "timestamp_utc"){ $ts = [string]$a.timestamp_utc }
      elseif($a.PSObject.Properties.Name -contains "ts_utc"){ $ts = [string]$a.ts_utc }

      if(
        $ts.StartsWith($DayPrefix) -and
        ([string]$a.alert_type) -eq $AlertType -and
        ([string]$a.ip) -eq $Ip
      ){
        return $true
      }
    } catch {}
  }

  return $false
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
$TimelinePath = Join-Path $RepoRoot "state\device_timeline\device_timeline.v1.ndjson"
$SpoofPath    = Join-Path $RepoRoot "state\spoof_watch\spoof_watch.latest.v1.json"
$IdsRoot      = Join-Path $RepoRoot "state\ids"
$IdsPath      = Join-Path $IdsRoot "ids_hooks.latest.v1.json"
$IdsMemoryPath = Join-Path $IdsRoot "ids_alert_memory.v1.json"
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

$DiffEnginePath = Join-Path $RepoRoot "state\diff\diff.latest.v1.json"

if(Test-Path $DiffEnginePath){

  try {

    $diff = Get-Content $DiffEnginePath -Raw | ConvertFrom-Json

    foreach($f in @($diff.findings)){

      if(
        [int]$f.anomaly_score -ge 3 -or
        [int]$f.spoof_risk_score -ge 3
      ){

        $findings += [PSCustomObject]@{
          severity = [string]$f.severity
          alert_type = "behavioral_drift_detected"
          ip = [string]$f.ip
          message = "Behavioral drift exceeded safe threshold."
        }
      }
    }

  } catch {}

}

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
$idsMemory = Load-IdsMemory -Path $IdsMemoryPath
$memoryEntries = @($idsMemory.entries)
$escalatedFindings = @()
$suppressedCount = 0
$nowDt = [DateTime]::UtcNow
$docOut = [ordered]@{
  schema = "shutterwall.ids_hooks.v1"
  updated_at_utc = $now
  mode = "semi_active_defensive"
  device_count = @($devices).Count
  timeline_event_count = @($timelineEvents).Count
  spoof_finding_count = @($spoofFindings).Count
  finding_count = @($findings).Count
  escalated_count = @($escalatedFindings).Count
  memory_entry_count = @($memoryEntries).Count
  suppressed_count = $suppressedCount
  suppression_window_hours = $IdsSuppressHours
  findings = @($findings)
}

Write-Utf8NoBomLf -Path $IdsPath -Text ($docOut | ConvertTo-Json -Depth 40)

foreach($f in $findings){
  $key = Get-FindingKey -Finding $f
  $entry = Get-IdsMemoryEntry -Memory $idsMemory -Key $key

  if($null -eq $entry){
    $entry = [ordered]@{
      key = $key
      first_seen_utc = $now
      last_seen_utc = $now
      repeat_count = 1
      last_alerted_utc = ""
    }
    $memoryEntries += [PSCustomObject]$entry
  } else {
    $entry.last_seen_utc = $now
    $entry.repeat_count = [int]$entry.repeat_count + 1
  }

  $severity = [string]$f.severity
  if([int]$entry.repeat_count -ge 5 -and $severity -eq "low"){
    $severity = "medium"
    $escalatedFindings += @($f)
  }

  $alert = [ordered]@{
    schema = "shutterwall.alert.v1"
    timestamp_utc = $now
    severity = $severity
    alert_type = "ids_hook_" + [string]$f.type
    ip = [string]$f.ip
    message = ([string]$f.explanation + " repeat_count=" + [string]$entry.repeat_count)
  }

  $alertType = [string]$alert.alert_type
  $alertIp = [string]$alert.ip
  $dayPrefix = $now.Substring(0,10)

  if(Test-IdsSuppressed -Entry $entry -NowUtc $nowDt -SuppressHours $IdsSuppressHours){
    $suppressedCount += 1
  }
  else {
    if(-not (Test-AlertAlreadyWrittenToday -Path $AlertsPath -AlertType $alertType -Ip $alertIp -DayPrefix $dayPrefix)){
      Append-Utf8NoBomLf -Path $AlertsPath -Text ($alert | ConvertTo-Json -Compress -Depth 20)
      $entry.last_alerted_utc = $now
    }
    else {
      $suppressedCount += 1
    }
  }
}

$idsMemory = [ordered]@{
  schema = "shutterwall.ids_alert_memory.v1"
  updated_at_utc = $now
  entries = @($memoryEntries)
}

Save-IdsMemory -Memory $idsMemory -Path $IdsMemoryPath

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

foreach($d in @($devices)){
  $trust = ""
  if($d.PSObject.Properties.Name -contains "trust"){ $trust = [string]$d.trust }

  $ip = ""
  if($d.PSObject.Properties.Name -contains "ip"){ $ip = [string]$d.ip }

  $ports = @()
  if($d.PSObject.Properties.Name -contains "open_ports"){ $ports = @($d.open_ports | ForEach-Object { [int]$_ }) }

  $serviceClass = ""
  if($d.PSObject.Properties.Name -contains "service_class"){ $serviceClass = [string]$d.service_class }

  if(($trust -eq "unknown") -and (($ports -contains 80) -or ($ports -contains 443) -or ($ports -contains 8080) -or ($ports -contains 8443))){
    $findings += [PSCustomObject]@{
      severity = "medium"
      type = "unknown_device_exposes_http"
      ip = $ip
      explanation = "Unknown device exposes a web administration or HTTP service."
    }
  }

  if(($trust -eq "unknown") -and ($ports -contains 554)){
    $findings += [PSCustomObject]@{
      severity = "medium"
      type = "unknown_camera_service_detected"
      ip = $ip
      explanation = "Unknown device exposes RTSP camera streaming service."
    }
  }

  if(($trust -eq "unknown") -and (($ports -contains 445) -or ($ports -contains 3389))){
    $findings += [PSCustomObject]@{
      severity = "medium"
      type = "unknown_windows_service_detected"
      ip = $ip
      explanation = "Unknown device exposes Windows SMB or RDP service."
    }
  }

  if(($trust -eq "trusted") -and ($serviceClass -match "Router") -and (($ports -notcontains 53) -or (($ports -notcontains 80) -and ($ports -notcontains 443)))){
    $findings += [PSCustomObject]@{
      severity = "medium"
      type = "trusted_gateway_service_drift"
      ip = $ip
      explanation = "Trusted gateway service profile no longer matches expected DNS plus web-admin shape."
    }
  }
}

Write-Host ("IDS_HOOKS_FINDING_COUNT: " + @($findings).Count)
Write-Host ("IDS_HOOKS_ESCALATED_COUNT: " + @($escalatedFindings).Count)
Write-Host ("IDS_HOOKS_MEMORY_ENTRY_COUNT: " + @($memoryEntries).Count)
Write-Host ("IDS_HOOKS_SUPPRESSED_COUNT: " + $suppressedCount)
Write-Host ("IDS_HOOKS_SUPPRESSION_WINDOW_HOURS: " + $IdsSuppressHours)
Write-Host ("IDS_HOOKS_SEVERITY_LOW: " + $lowCount)
Write-Host ("IDS_HOOKS_SEVERITY_MEDIUM: " + $mediumCount)
Write-Host ("IDS_HOOKS_SEVERITY_HIGH: " + $highCount)

foreach($f in $findings){
  Write-Host ("IDS_HOOK_FINDING :: " + $f.severity + " :: " + $f.type + " :: " + $f.ip + " :: " + $f.explanation)
}

Write-Host "SHUTTERWALL_IDS_HOOKS_V1_OK"
