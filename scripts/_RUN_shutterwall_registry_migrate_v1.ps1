param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$enc = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Has-Prop {
  param($Obj,[string]$Name)
  if($null -eq $Obj){ return $false }
  return (@($Obj.PSObject.Properties.Name) -contains $Name)
}

function Get-Prop {
  param($Obj,[string]$Name,$Default)
  if(Has-Prop $Obj $Name){
    $v = $Obj.$Name
    if($null -ne $v -and [string]$v -ne ""){ return $v }
  }
  return $Default
}

if(-not (Test-Path -LiteralPath $RegistryPath -PathType Leaf)){
  $doc = [ordered]@{
    schema = "shutterwall.device_registry.v1"
    updated_at_utc = [DateTime]::UtcNow.ToString("o")
    devices = @()
  }
  Write-Utf8NoBomLf -Path $RegistryPath -Text ($doc | ConvertTo-Json -Depth 40)
}

$raw = Get-Content -LiteralPath $RegistryPath -Raw
$doc = $raw | ConvertFrom-Json

$now = [DateTime]::UtcNow.ToString("o")
$devices = @()
if(Has-Prop $doc "devices"){
  $devices = @($doc.devices)
}

$outDevices = @()

foreach($d in $devices){
  $ip = [string](Get-Prop $d "ip" (Get-Prop $d "IP" ""))
  if([string]::IsNullOrWhiteSpace($ip)){ continue }

  $lastSeen = [string](Get-Prop $d "last_seen_utc" (Get-Prop $d "last_seen" $now))
  $firstSeen = [string](Get-Prop $d "first_seen_utc" $lastSeen)

  $outDevices += [ordered]@{
    ip = $ip
    label = [string](Get-Prop $d "label" (Get-Prop $d "user_label" "Needs Review"))
    user_label = [string](Get-Prop $d "user_label" (Get-Prop $d "label" ""))
    engine_guess = [string](Get-Prop $d "engine_guess" (Get-Prop $d "kind" "Needs Review"))
    confidence_percent = [int](Get-Prop $d "confidence_percent" 30)
    vendor_hint = [string](Get-Prop $d "vendor_hint" "unknown")
    trust_state = [string](Get-Prop $d "trust_state" (Get-Prop $d "trust" "unknown"))
    change_count = [int](Get-Prop $d "change_count" (Get-Prop $d "changes" 0))
    first_seen_utc = $firstSeen
    last_seen_utc = $lastSeen
    last_reviewed_utc = [string](Get-Prop $d "last_reviewed_utc" "")
    review_decision_source = [string](Get-Prop $d "review_decision_source" "engine_observed")
    baseline_generation = [int](Get-Prop $d "baseline_generation" 1)
    fingerprint_hash = [string](Get-Prop $d "fingerprint_hash" "")
    last_change_type = [string](Get-Prop $d "last_change_type" "schema_migrated")
    last_change_utc = [string](Get-Prop $d "last_change_utc" $now)
    last_trust_update_utc = [string](Get-Prop $d "last_trust_update_utc" "")
  }
}

$newDoc = [ordered]@{
  schema = "shutterwall.device_registry.v1"
  updated_at_utc = $now
  migration = "registry_memory_fields_v1"
  devices = @($outDevices)
}

Write-Utf8NoBomLf -Path $RegistryPath -Text ($newDoc | ConvertTo-Json -Depth 60)

Write-Host ("DEVICE_REGISTRY_PATH: " + $RegistryPath)
Write-Host ("DEVICE_REGISTRY_MIGRATED_COUNT: " + @($outDevices).Count)
Write-Host "SHUTTERWALL_REGISTRY_MIGRATE_V1_OK"
