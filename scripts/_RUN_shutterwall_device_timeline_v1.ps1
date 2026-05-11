param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$TimelineRoot = Join-Path $RepoRoot "state\device_timeline"
$TimelinePath = Join-Path $TimelineRoot "device_timeline.v1.ndjson"
$LatestPath = Join-Path $TimelineRoot "device_timeline.latest.v1.json"
$enc = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir-and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
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

$existing = @{}
if(Test-Path -LiteralPath $TimelinePath){
  foreach($line in @(Get-Content -LiteralPath $TimelinePath -ErrorAction SilentlyContinue)){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    try {
      $e = $line | ConvertFrom-Json
      $key = ([string]$e.ip) + "|" + ([string]$e.event_type) + "|" + ([string]$e.event_key)
      $existing[$key] = $true
    } catch {}
  }
}

$newEvents = @()
$now = [DateTime]::UtcNow.ToString("o")

foreach($d in $devices){
  $ip = [string]$d.ip
  if([string]::IsNullOrWhiteSpace($ip)){ continue }

  $label = [string]$d.label
  $trust = [string]$d.trust_state
  $firstSeen = if(Has-Prop $d "first_seen_utc"){ [string]$d.first_seen_utc } else { $now }
  $lastSeen = if(Has-Prop $d "last_seen_utc"){ [string]$d.last_seen_utc } else { $now }
  $lastReviewed = if(Has-Prop $d "last_reviewed_utc"){ [string]$d.last_reviewed_utc } else { "" }
  $changeType = if(Has-Prop $d "last_change_type"){ [string]$d.last_change_type } else { "observed" }

  $events = @(
    [ordered]@{
      schema = "shutterwall.device_timeline.event.v1"
      created_at_utc = $now
      ip = $ip
      label = $label
      trust_state = $trust
      event_type = "first_seen"
      event_key = $firstSeen
      summary = "Device first observed by ShutterWall memory."
    },
    [ordered]@{
      schema = "shutterwall.device_timeline.event.v1"
      created_at_utc = $now
      ip = $ip
      label = $label
      trust_state = $trust
      event_type = "last_seen"
      event_key = $lastSeen
      summary = "Device observed in latest registry memory."
    },
    [ordered]@{
      schema = "shutterwall.device_timeline.event.v1"
      created_at_utc = $now
      ip = $ip
      label = $label
      trust_state = $trust
      event_type = "trust_state"
      event_key = $trust
      summary = "Current trust state recorded."
    },
    [ordered]@{
      schema = "shutterwall.device_timeline.event.v1"
      created_at_utc = $now
      ip = $ip
      label = $label
      trust_state = $trust
      event_type = "last_change"
      event_key = $changeType
      summary = "Latest registry change type recorded."
    }
  )

  if(-not [string]::IsNullOrWhiteSpace($lastReviewed)){
    $events += [ordered]@{
      schema = "shutterwall.device_timeline.event.v1"
      created_at_utc = $now
      ip = $ip
      label = $label
      trust_state = $trust
      event_type = "reviewed"
      event_key = $lastReviewed
      summary = "Device was reviewed by user or engine."
    }
  }

  foreach($ev in $events){
    $key = ([string]$ev.ip) + "|" + ([string]$ev.event_type) + "|" + ([string]$ev.event_key)
    if(-not $existing.ContainsKey($key)){
      $existing[$key] = $true
      $newEvents += $ev
      Append-Utf8NoBomLf -Path $TimelinePath -Text ($ev | ConvertTo-Json -Compress -Depth 20)
    }
  }
}

$latest = [ordered]@{
  schema = "shutterwall.device_timeline.latest.v1"
  updated_at_utc = $now
  device_count = @($devices).Count
  new_event_count = @($newEvents).Count
  timeline_path = $TimelinePath
  new_events = @($newEvents)
}

Write-Utf8NoBomLf -Path $LatestPath -Text ($latest | ConvertTo-Json -Depth 40)

Write-Host ("DEVICE_TIMELINE_PATH: " + $TimelinePath)
Write-Host ("DEVICE_TIMELINE_NEW_EVENT_COUNT: " + @($newEvents).Count)

foreach($ev in $newEvents){
  Write-Host ("DEVICE_TIMELINE_EVENT :: " + $ev.ip + " :: " + $ev.event_type + " :: " + $ev.summary)
}

Write-Host "SHUTTERWALL_DEVICE_TIMELINE_V1_OK"
