param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$Ip = "",
  [string]$Label = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($Ip)){ throw "MISSING_IP" }

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$EnrollDir = Join-Path $RepoRoot "state\enrollment"
$EnrollPath = Join-Path $EnrollDir "enrolled_devices.v1.json"

New-Item -ItemType Directory -Force -Path $EnrollDir | Out-Null

if(-not (Test-Path -LiteralPath $RegistryPath)){ throw "DEVICE_REGISTRY_MISSING" }

$reg = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
$device = @($reg.devices | Where-Object { [string]$_.ip -eq $Ip }) | Select-Object -First 1

if($null -eq $device){ throw ("DEVICE_NOT_FOUND_IN_REGISTRY: " + $Ip) }

$now = [DateTime]::UtcNow.ToString("o")
$deviceId = "swdev_" + ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Ip))).Substring(0,16).ToLowerInvariant())

if([string]::IsNullOrWhiteSpace($Label)){
  if($device.PSObject.Properties.Name -contains "label" -and -not [string]::IsNullOrWhiteSpace([string]$device.label)){
    $Label = [string]$device.label
  } else {
    $Label = $Ip
  }
}

foreach($p in @(
  @{n="device_id";v=$deviceId},
  @{n="label";v=$Label},
  @{n="trust_state";v="trusted"},
  @{n="trust";v="trusted"},
  @{n="enrolled";v=$true},
  @{n="enrollment_utc";v=$now},
  @{n="last_trust_update_utc";v=$now},
  @{n="reviewed";v=$true},
  @{n="needs_review";v=$false},
  @{n="review_required";v=$false},
  @{n="review_decision_source";v="device_enrollment"},
  @{n="last_change_type";v="manual_device_enrollment"}
)){
  if($device.PSObject.Properties.Name -contains $p.n){ $device.($p.n) = $p.v }
  else { $device | Add-Member -NotePropertyName $p.n -NotePropertyValue $p.v -Force }
}

($reg | ConvertTo-Json -Depth 100) | Set-Content -Encoding UTF8 $RegistryPath

$enrolled = @()
if(Test-Path -LiteralPath $EnrollPath){
  try {
    $doc = Get-Content -LiteralPath $EnrollPath -Raw | ConvertFrom-Json
    if($doc.PSObject.Properties.Name -contains "devices"){ $enrolled = @($doc.devices) }
  } catch { $enrolled = @() }
}

$existing = @($enrolled | Where-Object { [string]$_.ip -ne $Ip })

$existing += [ordered]@{
  device_id = $deviceId
  ip = $Ip
  label = $Label
  trust_state = "trusted"
  enrolled = $true
  enrollment_utc = $now
  agent_enabled = $true
}

$out = [ordered]@{
  schema = "shutterwall.enrolled_devices.v1"
  updated_utc = $now
  device_count = @($existing).Count
  devices = @($existing)
}

($out | ConvertTo-Json -Depth 50) | Set-Content -Encoding UTF8 $EnrollPath

Write-Host ("ENROLL_DEVICE_ID: " + $deviceId)
Write-Host ("ENROLL_DEVICE_IP: " + $Ip)
Write-Host ("ENROLL_DEVICE_LABEL: " + $Label)
Write-Host ("ENROLL_DEVICE_PATH: " + $EnrollPath)
Write-Host "SHUTTERWALL_ENROLL_DEVICE_V1_OK"
