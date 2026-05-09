param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$SpoofRoot = Join-Path $RepoRoot "state\spoof_watch"
$SpoofPath = Join-Path $SpoofRoot "spoof_watch.latest.v1.json"
$enc = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [IO.File]::WriteAllText($Path,$norm,$enc)
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

$neighbors = @()
try {
  $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
    $_.IPAddress -like "192.168.*" -and $_.LinkLayerAddress
  })
} catch {
  $neighbors = @()
}

$findings = @()

foreach($d in $devices){
  $ip = [string]$d.ip
  if([string]::IsNullOrWhiteSpace($ip)){ continue }

  $n = @($neighbors | Where-Object { $_.IPAddress -eq $ip }) | Select-Object -First 1
  $observedMac = ""
  if($n){ $observedMac = [string]$n.LinkLayerAddress }

  $storedMac = ""
  if(Has-Prop $d "mac_address"){ $storedMac = [string]$d.mac_address }
  if([string]::IsNullOrWhiteSpace($storedMac) -and (Has-Prop $d "link_layer_address")){ $storedMac = [string]$d.link_layer_address }

  if(-not [string]::IsNullOrWhiteSpace($storedMac) -and -not [string]::IsNullOrWhiteSpace($observedMac) -and $storedMac -ne $observedMac){
    $findings += [ordered]@{
      type = "possible_mac_drift"
      severity = "medium"
      ip = $ip
      label = [string]$d.label
      expected = $storedMac
      observed = $observedMac
      explanation = "The same remembered IP appears with a different observed link-layer address."
    }
  }

  if(([string]$d.trust_state) -eq "trusted" -and [string]::IsNullOrWhiteSpace($observedMac)){
    $findings += [ordered]@{
      type = "trusted_device_not_observed"
      severity = "low"
      ip = $ip
      label = [string]$d.label
      expected = "trusted_device_present"
      observed = "not_in_neighbor_table"
      explanation = "A trusted device was not visible in the current neighbor table. This may be normal if asleep/offline."
    }
  }
}

$docOut = [ordered]@{
  schema = "shutterwall.spoof_watch.v1"
  updated_at_utc = [DateTime]::UtcNow.ToString("o")
  registry_device_count = @($devices).Count
  neighbor_observation_count = @($neighbors).Count
  finding_count = @($findings).Count
  findings = @($findings)
}

Write-Utf8NoBomLf -Path $SpoofPath -Text ($docOut | ConvertTo-Json -Depth 40)

Write-Host ("SPOOF_WATCH_PATH: " + $SpoofPath)
Write-Host ("SPOOF_WATCH_FINDING_COUNT: " + @($findings).Count)

foreach($f in $findings){
  Write-Host ("SPOOF_WATCH_FINDING :: " + $f.severity + " :: " + $f.type + " :: " + $f.ip + " :: " + $f.explanation)
}

Write-Host "SHUTTERWALL_SPOOF_WATCH_V1_OK"
