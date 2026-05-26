param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$RunRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

function Get-Prop($Obj,[string]$Name,$Default=""){
  if($null -eq $Obj){ return $Default }
  if(@($Obj.PSObject.Properties.Name) -contains $Name){
    $v=$Obj.$Name
    if($null -eq $v){ return $Default }
    return $v
  }
  return $Default
}

function Sha256Text([string]$Text){
  $sha=[Security.Cryptography.SHA256]::Create()
  $bytes=[Text.Encoding]::UTF8.GetBytes($Text)
  return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-","").ToLowerInvariant()
}

$RunsRoot=Join-Path $RepoRoot "proofs\runs\shutterwall"

if([string]::IsNullOrWhiteSpace($RunRoot)){
  $latest=Get-ChildItem -LiteralPath $RunsRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTimeUtc -Descending |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "devices.discovery.v1.json") } |
    Select-Object -First 1

  if($null -eq $latest){ throw "IDENTITY_NO_DISCOVERY_RUN_FOUND" }
  $RunRoot=$latest.FullName
}

$DiscoveryPath=Join-Path $RunRoot "devices.discovery.v1.json"
$IdentityPath=Join-Path $RunRoot "devices.identity.v1.json"
$RegistryPath=Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"

if(-not (Test-Path -LiteralPath $DiscoveryPath)){ throw "DISCOVERY_MISSING: $DiscoveryPath" }

$disc=Get-Content -LiteralPath $DiscoveryPath -Raw | ConvertFrom-Json

$devices=@()
if(@($disc.PSObject.Properties.Name) -contains "devices"){ $devices=@($disc.devices) }
elseif(@($disc.PSObject.Properties.Name) -contains "candidates"){ $devices=@($disc.candidates) }
else { $devices=@($disc) }

$registryDevices=@()
if(Test-Path -LiteralPath $RegistryPath){
  $reg=Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
  if(@($reg.PSObject.Properties.Name) -contains "devices"){ $registryDevices=@($reg.devices) }
}

$identities=@()

foreach($d in $devices){
  $ip=[string](Get-Prop $d "ip" (Get-Prop $d "IP" ""))
  if([string]::IsNullOrWhiteSpace($ip)){ continue }

  $known=$registryDevices | Where-Object { [string]$_.ip -eq $ip } | Select-Object -First 1

  $userLabel=[string](Get-Prop $known "label" "")
  if($userLabel -eq "Needs Review"){ $userLabel="" }

  $mac=[string](Get-Prop $d "mac" "")
  $hostname=[string](Get-Prop $d "hostname" "")
  $vendor=[string](Get-Prop $d "vendor" (Get-Prop $d "vendor_hint" "unknown"))

  $label="Needs Review"
  $confidence=30

  if($ip.EndsWith(".1")){
    $label="Likely Router / Gateway"
    $confidence=55
  }

  $basis=$ip + "|" + $mac + "|" + $hostname + "|" + $vendor + "|" + $label
  $identityHash=Sha256Text $basis

  $identities += [ordered]@{
    ip=$ip
    label=$label
    kind="network_device"
    confidence_percent=$confidence
    vendor_hint=$vendor
    user_label=$userLabel
    identity_hash=$identityHash
    mac=$mac
    hostname=$hostname
  }
}

$out=[ordered]@{
  schema="shutterwall.device_identity.collection.v1"
  generated_utc=[DateTime]::UtcNow.ToString("o")
  run_root=$RunRoot
  identities=@($identities)
}

$txt=$out | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText($IdentityPath, (($txt -replace "`r`n","`n") -replace "`r","`n") + "`n", [Text.UTF8Encoding]::new($false))

Write-Host ("IDENTITY_PATH: " + $IdentityPath)
Write-Host ("IDENTITY_DEVICE_COUNT: " + @($identities).Count)

foreach($id in $identities){
  Write-Host ("DEVICE_IDENTITY :: " + $id.ip + " :: " + $id.label + " :: confidence=" + $id.confidence_percent + "% :: vendor=" + $id.vendor_hint + " :: user_label=" + $id.user_label)
}

& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_device_registry_v1.ps1") -Mode update -RepoRoot $RepoRoot -RunRoot $RunRoot

Write-Host "SHUTTERWALL_IDENTITY_V1_OK"
