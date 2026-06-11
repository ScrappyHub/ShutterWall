param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$Ip = "",
  [string]$Trust = "trusted",
  [string]$Label = "",
  [string]$Reason = "user_review"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"
function Set-DevicePropSafe {
  param(
    $Obj,
    [string]$Name,
    $Value
  )

  if(@($Obj.PSObject.Properties.Name) -notcontains $Name){
    $Obj | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
  }
  else{
    $Obj.$Name = $Value
  }
}


if([string]::IsNullOrWhiteSpace($Ip)){ throw "DEVICE_IP_REQUIRED" }

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$AlertsPath = Join-Path $RepoRoot "state\alerts\alerts.ndjson"

if(-not (Test-Path -LiteralPath $RegistryPath)){ throw "DEVICE_REGISTRY_MISSING" }

$reg = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
$devices = @($reg.devices)

$d = @($devices | Where-Object { [string]$_.ip -eq $Ip }) | Select-Object -First 1
if($null -eq $d){ throw "DEVICE_NOT_FOUND: $Ip" }

if([string]::IsNullOrWhiteSpace($Label)){
  $Label = [string]$d.label
  if([string]::IsNullOrWhiteSpace($Label) -or $Label -eq "Needs Review"){
    $Label = "Registered Device"
  }
}

Set-DevicePropSafe -Obj $d -Name "trust_state" -Value $Trust
Set-DevicePropSafe -Obj $d -Name "trust" -Value $Trust
Set-DevicePropSafe -Obj $d -Name "label" -Value $Label
$d | Add-Member -NotePropertyName reviewed_utc -NotePropertyValue ([DateTime]::UtcNow.ToString("o")) -Force
$d | Add-Member -NotePropertyName review_decision_source -NotePropertyValue $Reason -Force
$d | Add-Member -NotePropertyName last_change_type -NotePropertyValue "manual_trust_enrollment" -Force
Set-DevicePropSafe -Obj $d -Name "reviewed" -Value $true
Set-DevicePropSafe -Obj $d -Name "needs_review" -Value $false
Set-DevicePropSafe -Obj $d -Name "review_required" -Value $false
Set-DevicePropSafe -Obj $d -Name "last_reviewed_utc" -Value ([DateTime]::UtcNow.ToString("o"))
Set-DevicePropSafe -Obj $d -Name "last_trust_update_utc" -Value ([DateTime]::UtcNow.ToString("o"))
Set-DevicePropSafe -Obj $d -Name "review_action" -Value "Recognized. Keep monitoring for fingerprint or baseline changes."

$out = [ordered]@{
  schema = "shutterwall.device_registry.v1"
  updated_utc = [DateTime]::UtcNow.ToString("o")
  devices = @($devices)
}

($out | ConvertTo-Json -Depth 100) | Set-Content -Encoding UTF8 $RegistryPath

$alert = [ordered]@{
  schema = "shutterwall.alert.v1"
  timestamp_utc = [DateTime]::UtcNow.ToString("o")
  severity = "low"
  alert_type = "device_trust_enrolled"
  ip = $Ip
  message = "Device trust state set to $Trust with label $Label."
}

($alert | ConvertTo-Json -Compress -Depth 20) | Add-Content -Encoding UTF8 $AlertsPath

Write-Host ("DEVICE_TRUST_ENROLLED :: " + $Ip + " :: trust=" + $Trust + " :: label=" + $Label)
Write-Host ("DEVICE_REGISTRY_PATH: " + $RegistryPath)
Write-Host "SHUTTERWALL_DEVICE_TRUST_ENROLL_V1_OK"
