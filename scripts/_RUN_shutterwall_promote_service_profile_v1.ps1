param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$ServicePath = Join-Path $RepoRoot "state\service_profiles\service_profile.latest.v1.json"
$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$OutPath = $RegistryPath

if(-not (Test-Path -LiteralPath $ServicePath)){ throw "SERVICE_PROFILE_MISSING" }
if(-not (Test-Path -LiteralPath $RegistryPath)){ throw "DEVICE_REGISTRY_MISSING" }

$svc = Get-Content -LiteralPath $ServicePath -Raw | ConvertFrom-Json
$reg = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json

$devices = @()
if(@($reg.PSObject.Properties.Name) -contains "devices"){
  $devices = @($reg.devices)
} else {
  $devices = @($reg)
}

$updated = 0

foreach($d in $devices){
  $ip = [string]$d.ip
  $profile = @($svc.profiles | Where-Object { [string]$_.ip -eq $ip }) | Select-Object -First 1

  if($null -ne $profile){
    $d | Add-Member -NotePropertyName service_class -NotePropertyValue ([string]$profile.device_class) -Force
    $d | Add-Member -NotePropertyName service_confidence_percent -NotePropertyValue ([int]$profile.confidence_percent) -Force
    $d | Add-Member -NotePropertyName service_reason -NotePropertyValue ([string]$profile.reason) -Force
    $d | Add-Member -NotePropertyName open_ports -NotePropertyValue @($profile.open_ports) -Force
    $d | Add-Member -NotePropertyName services -NotePropertyValue @($profile.services) -Force
    $d | Add-Member -NotePropertyName service_profiled_utc -NotePropertyValue ([DateTime]::UtcNow.ToString("o")) -Force

    if([string]$d.label -eq "Needs Review" -and [int]$profile.confidence_percent -ge 70){
      $d.label = [string]$profile.device_class
      $d | Add-Member -NotePropertyName label_source -NotePropertyValue "service_classifier_v1" -Force
    }

    $updated += 1
  }
}

$out = [ordered]@{
  schema = "shutterwall.device_registry.v1"
  updated_utc = [DateTime]::UtcNow.ToString("o")
  devices = @($devices)
}

($out | ConvertTo-Json -Depth 80) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("SERVICE_PROFILE_SOURCE: " + $ServicePath)
Write-Host ("DEVICE_REGISTRY_PATH: " + $RegistryPath)
Write-Host ("SERVICE_PROFILE_PROMOTED_COUNT: " + $updated)

foreach($d in @($devices)){
  if(@($d.PSObject.Properties.Name) -contains "service_class"){
    Write-Host ("SERVICE_DEVICE :: " + $d.ip + " :: " + $d.service_class + " :: confidence=" + $d.service_confidence_percent + "% :: ports=" + (@($d.open_ports) -join ","))
  }
}

Write-Host "SHUTTERWALL_SERVICE_PROFILE_PROMOTE_V1_OK"
