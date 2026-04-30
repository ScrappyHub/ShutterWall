param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$RunRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Get-LatestRunRoot {
  param([string]$RepoRoot)
  $root = Join-Path $RepoRoot "proofs\runs\shutterwall"
  $runs = Get-ChildItem -LiteralPath $root -Directory | Sort-Object LastWriteTimeUtc -Descending
  if(-not $runs){ throw "NO_RUN_ROOT_FOUND_RUN_INSPECT_FIRST" }
  return $runs[0].FullName
}

function Get-PropString {
  param($Obj,[string]$Name)
  if($null -eq $Obj){ return "" }
  $p = $Obj.PSObject.Properties[$Name]
  if($null -eq $p){ return "" }
  if($null -eq $p.Value){ return "" }
  return [string]$p.Value
}

function Get-TextBlob {
  param($Obj)
  if($null -eq $Obj){ return "" }
  return (($Obj | ConvertTo-Json -Depth 20) -as [string]).ToLowerInvariant()
}

function Add-Signal {
  param([System.Collections.ArrayList]$Signals,[string]$Signal)
  if(-not [string]::IsNullOrWhiteSpace($Signal)){ [void]$Signals.Add($Signal) }
}

function Infer-DeviceIdentity {
  param($Device,$Fingerprint)

  $signals = New-Object System.Collections.ArrayList
  $blob = ((Get-TextBlob $Device) + " " + (Get-TextBlob $Fingerprint)).ToLowerInvariant()
  $score = 20
  $kind = "unknown_device"
  $label = "Unknown Network Device"
  $vendor = "unknown"

  if($blob -match "rtsp|onvif|554|camera|surveillance|ipcam|hikvision|dahua|amcrest|reolink|axis"){
    $score += 45
    $kind = "camera_like"
    $label = "Likely Camera / Surveillance Device"
    Add-Signal $signals "camera_or_rtsp_signal"
  }

  if($blob -match "printer|ipp|cups|9100|515|631|brother|canon|epson|hp laser|hewlett"){
    $score += 35
    if($kind -eq "unknown_device"){ $kind = "printer_like"; $label = "Likely Printer" }
    Add-Signal $signals "printer_signal"
  }

  if($blob -match "router|gateway|dns|dhcp|upnp|192\.168\.[0-9]+\.1"){
    $score += 25
    if($kind -eq "unknown_device"){ $kind = "network_gateway_like"; $label = "Likely Router / Gateway" }
    Add-Signal $signals "gateway_signal"
  }

  if($blob -match "tv|roku|chromecast|cast|samsung|lg webos|androidtv|airplay"){
    $score += 30
    if($kind -eq "unknown_device"){ $kind = "media_iot_like"; $label = "Likely Smart TV / Media Device" }
    Add-Signal $signals "media_iot_signal"
  }

  if($blob -match "hikvision"){ $vendor = "hikvision-like"; $score += 15; Add-Signal $signals "vendor_hikvision_hint" }
  elseif($blob -match "dahua"){ $vendor = "dahua-like"; $score += 15; Add-Signal $signals "vendor_dahua_hint" }
  elseif($blob -match "amcrest"){ $vendor = "amcrest-like"; $score += 15; Add-Signal $signals "vendor_amcrest_hint" }
  elseif($blob -match "reolink"){ $vendor = "reolink-like"; $score += 15; Add-Signal $signals "vendor_reolink_hint" }
  elseif($blob -match "axis"){ $vendor = "axis-like"; $score += 15; Add-Signal $signals "vendor_axis_hint" }
  elseif($blob -match "canon"){ $vendor = "canon-like"; $score += 10; Add-Signal $signals "vendor_canon_hint" }
  elseif($blob -match "epson"){ $vendor = "epson-like"; $score += 10; Add-Signal $signals "vendor_epson_hint" }
  elseif($blob -match "brother"){ $vendor = "brother-like"; $score += 10; Add-Signal $signals "vendor_brother_hint" }

  $ip = Get-PropString $Device "ip"
  if([string]::IsNullOrWhiteSpace($ip)){ $ip = Get-PropString $Fingerprint "ip" }
  if(-not [string]::IsNullOrWhiteSpace($ip)){ Add-Signal $signals "ip_observed" }

  if($score -gt 95){ $score = 95 }
  if($score -lt 5){ $score = 5 }

  return [ordered]@{
    schema = "shutterwall.device.identity.v1"
    ip = $ip
    label = $label
    device_type_guess = $kind
    confidence = [math]::Round(($score / 100.0), 2)
    confidence_percent = $score
    vendor_hint = $vendor
    signals = @($signals)
  }
}

if([string]::IsNullOrWhiteSpace($RunRoot)){ $RunRoot = Get-LatestRunRoot -RepoRoot $RepoRoot }
if(-not (Test-Path -LiteralPath $RunRoot)){ throw ("RUN_ROOT_NOT_FOUND: " + $RunRoot) }

$DevicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$FingerprintsPath = Join-Path $RunRoot "devices.fingerprint.v1.json"
if(-not (Test-Path -LiteralPath $DevicesPath)){ throw ("DEVICES_JSON_MISSING: " + $DevicesPath) }
if(-not (Test-Path -LiteralPath $FingerprintsPath)){ throw ("FINGERPRINTS_JSON_MISSING: " + $FingerprintsPath) }

$devicesDoc = Get-Content -LiteralPath $DevicesPath -Raw | ConvertFrom-Json
$fingerprintsDoc = Get-Content -LiteralPath $FingerprintsPath -Raw | ConvertFrom-Json
$devices = @($devicesDoc.devices)
$fingerprints = @($fingerprintsDoc.fingerprints)

$fpByIp = @{}
foreach($fp in $fingerprints){
  $ip = Get-PropString $fp "ip"
  if(-not [string]::IsNullOrWhiteSpace($ip)){ $fpByIp[$ip] = $fp }
}

$identities = New-Object System.Collections.ArrayList
foreach($d in $devices){
  $ip = Get-PropString $d "ip"
  $fp = $null
  if((-not [string]::IsNullOrWhiteSpace($ip)) -and $fpByIp.ContainsKey($ip)){ $fp = $fpByIp[$ip] }
  [void]$identities.Add((Infer-DeviceIdentity -Device $d -Fingerprint $fp))
}

$outPath = Join-Path $RunRoot "devices.identity.v1.json"
$doc = [ordered]@{
  schema = "shutterwall.identity.collection.v1"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  run_root = $RunRoot
  device_count = @($identities).Count
  identities = @($identities)
}

Write-Utf8NoBomLf -Path $outPath -Text ($doc | ConvertTo-Json -Depth 30)

Write-Host ("IDENTITY_PATH: " + $outPath) -ForegroundColor Green
Write-Host ("IDENTITY_DEVICE_COUNT: " + @($identities).Count) -ForegroundColor Yellow
foreach($id in @($identities)){
  Write-Host ("DEVICE_IDENTITY :: " + $id.ip + " :: " + $id.label + " :: confidence=" + $id.confidence_percent + "% :: vendor=" + $id.vendor_hint) -ForegroundColor Cyan
}
Write-Host "SHUTTERWALL_IDENTITY_V1_OK" -ForegroundColor Green
