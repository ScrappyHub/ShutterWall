param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("update","list","trust")]
  [string]$Mode,

  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$RunRoot,
  [string]$Ip = "",
  [string]$TrustState = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RegistryRoot = Join-Path $RepoRoot "state\device_registry"
$RegistryFile = Join-Path $RegistryRoot "device_registry.v1.json"

if(-not (Test-Path $RegistryRoot)){
  New-Item -ItemType Directory -Path $RegistryRoot -Force | Out-Null
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

function New-Registry {
  return [ordered]@{
    schema = "shutterwall.device_registry.v1"
    updated_at_utc = [DateTime]::UtcNow.ToString("o")
    devices = @()
  }
}

function Load-Registry {
  if(Test-Path -LiteralPath $RegistryFile){
    try { return (Get-Content -LiteralPath $RegistryFile -Raw | ConvertFrom-Json) }
    catch { return (New-Registry) }
  }
  return (New-Registry)
}

function Save-Registry {
  param($Registry)
  $Registry.updated_at_utc = [DateTime]::UtcNow.ToString("o")
  Write-Utf8NoBomLf -Path $RegistryFile -Text ($Registry | ConvertTo-Json -Depth 30)
}

function Get-LatestRunRoot {
  param([string]$RepoRoot)
  $root = Join-Path $RepoRoot "proofs\runs\shutterwall"
  $runs = Get-ChildItem -LiteralPath $root -Directory | Sort-Object LastWriteTimeUtc -Descending
  if(-not $runs){ throw "NO_RUN_ROOT_FOUND_RUN_INSPECT_FIRST" }
  return $runs[0].FullName
}

if([string]::IsNullOrWhiteSpace($RunRoot)){
  $RunRoot = Get-LatestRunRoot -RepoRoot $RepoRoot
}

$Registry = Load-Registry

if($Mode -eq "update"){
  $IdentityPath = Join-Path $RunRoot "devices.identity.v1.json"
  if(-not (Test-Path -LiteralPath $IdentityPath)){
    throw ("IDENTITY_FILE_MISSING_RUN_IDENTITY_FIRST: " + $IdentityPath)
  }

  $identityDoc = Get-Content -LiteralPath $IdentityPath -Raw | ConvertFrom-Json
  $now = [DateTime]::UtcNow.ToString("o")
  $existing = @{}

  foreach($d in @($Registry.devices)){
    if($d.ip){ $existing[[string]$d.ip] = $d }
  }

  $updated = New-Object System.Collections.ArrayList

  foreach($id in @($identityDoc.identities)){
    $ip = [string]$id.ip
    if([string]::IsNullOrWhiteSpace($ip)){ continue }

    if($existing.ContainsKey($ip)){
      $old = $existing[$ip]
      $changeCount = 0
      if($old.change_count){ $changeCount = [int]$old.change_count }

      if(($old.engine_guess -ne $id.label) -or ($old.confidence_percent -ne $id.confidence_percent) -or ($old.user_label -ne $id.user_label)){
        $changeCount++
      }

      $device = [ordered]@{
        ip = $ip
        user_label = [string]$id.user_label
        engine_guess = [string]$id.label
        confidence_percent = [int]$id.confidence_percent
        vendor_hint = [string]$id.vendor_hint
        trust_state = if($old.trust_state){ [string]$old.trust_state } else { "unknown" }
        first_seen_utc = if($old.first_seen_utc){ [string]$old.first_seen_utc } else { $now }
        last_seen_utc = $now
        change_count = $changeCount
        notes = if($old.notes){ [string]$old.notes } else { "" }
      }
    }
    else{
      $device = [ordered]@{
        ip = $ip
        user_label = [string]$id.user_label
        engine_guess = [string]$id.label
        confidence_percent = [int]$id.confidence_percent
        vendor_hint = [string]$id.vendor_hint
        trust_state = "unknown"
        first_seen_utc = $now
        last_seen_utc = $now
        change_count = 0
        notes = ""
      }
    }

    [void]$updated.Add($device)
  }

  $Registry.devices = @($updated | Sort-Object ip)
  Save-Registry -Registry $Registry

  Write-Host ("DEVICE_REGISTRY_PATH: " + $RegistryFile)
  Write-Host ("DEVICE_REGISTRY_COUNT: " + @($Registry.devices).Count)
  Write-Host "SHUTTERWALL_DEVICE_REGISTRY_UPDATE_OK"
  return
}


if($Mode -eq "trust"){
  if([string]::IsNullOrWhiteSpace($Ip)){
    throw "MISSING_IP"
  }

  if([string]::IsNullOrWhiteSpace($TrustState)){
    throw "MISSING_TRUST_STATE"
  }

  $allowed = @("trusted","review","blocked")
  if($allowed -notcontains $TrustState){
    throw ("INVALID_TRUST_STATE: " + $TrustState)
  }

  if(-not (Test-Path -LiteralPath $RegistryPath)){
    throw ("MISSING_REGISTRY: " + $RegistryPath)
  }

  $doc = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json

  foreach($device in @($doc.devices)){
    if(([string]$device.ip) -eq $Ip){
      $device.trust_state = $TrustState
      $device.last_trust_update_utc = [DateTime]::UtcNow.ToString("o")
    }
  }

  Write-Utf8NoBomLf -Path $RegistryPath -Text ($doc | ConvertTo-Json -Depth 20)

  Write-Host ("DEVICE_TRUST_SET :: " + $Ip + " :: " + $TrustState)
  Write-Host ("DEVICE_REGISTRY_PATH: " + $RegistryPath)
  Write-Host "SHUTTERWALL_DEVICE_TRUST_SET_OK"

  return
}
if($Mode -eq "list"){
  Write-Host ("DEVICE_REGISTRY_PATH: " + $RegistryFile)
  foreach($d in @($Registry.devices)){
    $name = if($d.user_label){ $d.user_label } else { $d.engine_guess }
    Write-Host ("DEVICE_REGISTRY :: " + $d.ip + " :: " + $name + " :: trust=" + $d.trust_state + " :: changes=" + $d.change_count + " :: last_seen=" + $d.last_seen_utc)
  }
  Write-Host "SHUTTERWALL_DEVICE_REGISTRY_LIST_OK"
  return
}
