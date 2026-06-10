param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$RegistryPath = Join-Path $RepoRoot "state\device_registry\device_registry.v1.json"
$IdsPath = Join-Path $RepoRoot "state\ids\ids_hooks.latest.v1.json"
$ServicePath = Join-Path $RepoRoot "state\service_profiles\service_profile.latest.v1.json"
$DriftPath = Join-Path $RepoRoot "state\service_drift\service_drift.latest.v1.json"
$OutDir = Join-Path $RepoRoot "state\correlation"
$OutPath = Join-Path $OutDir "correlation.latest.v1.json"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Get-Prop($Obj,[string]$Name,$Default=""){
  if($null -eq $Obj){ return $Default }
  if(@($Obj.PSObject.Properties.Name) -contains $Name){
    $v = $Obj.$Name
    if($null -eq $v){ return $Default }
    return $v
  }
  return $Default
}


function Get-TrustState {
  param($Obj)

  foreach($name in @("trust","trust_state","protection_state")){
    if($Obj.PSObject.Properties.Name -contains $name){
      $v = [string]$Obj.$name
      if(-not [string]::IsNullOrWhiteSpace($v)){
        return $v
      }
    }
  }

  return "unknown"
}
function Risk-Level([int]$Score){
  if($Score -ge 60){ return "high" }
  if($Score -ge 30){ return "medium" }
  if($Score -ge 10){ return "low" }
  return "normal"
}

if(-not (Test-Path -LiteralPath $RegistryPath)){ throw "DEVICE_REGISTRY_MISSING" }

$reg = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
$devices = @()
if(@($reg.PSObject.Properties.Name) -contains "devices"){ $devices = @($reg.devices) } else { $devices = @($reg) }

$idsFindings = @()
if(Test-Path -LiteralPath $IdsPath){
  try {
    $ids = Get-Content -LiteralPath $IdsPath -Raw | ConvertFrom-Json
    if($ids.PSObject.Properties.Name -contains "findings"){ $idsFindings = @($ids.findings) }
  } catch {}
}

$serviceProfiles = @()
if(Test-Path -LiteralPath $ServicePath){
  try {
    $svc = Get-Content -LiteralPath $ServicePath -Raw | ConvertFrom-Json
    if($svc.PSObject.Properties.Name -contains "profiles"){ $serviceProfiles = @($svc.profiles) }
  } catch {}
}

$driftFindings = @()
if(Test-Path -LiteralPath $DriftPath){
  try {
    $drift = Get-Content -LiteralPath $DriftPath -Raw | ConvertFrom-Json
    if($drift.PSObject.Properties.Name -contains "findings"){ $driftFindings = @($drift.findings) }
  } catch {}
}

$correlations = @()

foreach($d in @($devices)){
  $ip = [string](Get-Prop $d "ip" "")
  if([string]::IsNullOrWhiteSpace($ip)){ continue }

  $trust = Get-TrustState $d
  $changes = [int](Get-Prop $d "changes" 0)

  $score = 0
  $reasons = @()

  $svc = @($serviceProfiles | Where-Object { [string]$_.ip -eq $ip }) | Select-Object -First 1
  $ports = @()
  if($null -ne $svc){
    $ports = @($svc.open_ports | ForEach-Object { [int]$_ })
  } elseif(@($d.PSObject.Properties.Name) -contains "open_ports"){
    $ports = @($d.open_ports | ForEach-Object { [int]$_ })
  }

  if($trust -eq "unknown"){
    $score += 10
    $reasons += "unknown_trust"
  }

  if(($trust -eq "unknown") -and (($ports -contains 80) -or ($ports -contains 443) -or ($ports -contains 22) -or ($ports -contains 445) -or ($ports -contains 3389))){
    $score += 25
    $reasons += "unknown_service_host"
  }

  if($changes -gt 0){
    $score += 10
    $reasons += "device_changed"
  }

  if(($trust -eq "trusted") -and ($changes -gt 0)){
    $score += 15
    $reasons += "trusted_device_changed"
  }

  $myIds = @($idsFindings | Where-Object { [string]$_.ip -eq $ip })
  foreach($f in $myIds){
    $sev = [string](Get-Prop $f "severity" "low")
    if($sev -eq "high"){ $score += 35 }
    elseif($sev -eq "medium"){ $score += 15 }
    else { $score += 5 }

    $ft = [string](Get-Prop $f "type" "ids_finding")
    if(-not [string]::IsNullOrWhiteSpace($ft)){ $reasons += $ft }
  }

  $myDrift = @($driftFindings | Where-Object { [string]$_.ip -eq $ip })
  foreach($f in $myDrift){
    $score += 20
    $ft = [string](Get-Prop $f "type" "service_drift")
    if(-not [string]::IsNullOrWhiteSpace($ft)){ $reasons += $ft }
  }

  $level = Risk-Level $score

  $correlations += [ordered]@{
    ip = $ip
    label = [string](Get-Prop $d "label" "")
    trust = $trust
    risk_score = $score
    risk_level = $level
    reasons = @($reasons | Sort-Object -Unique)
    open_ports = @($ports)
  }
}

$out = [ordered]@{
  schema = "shutterwall.correlation.v1"
  generated_utc = [DateTime]::UtcNow.ToString("o")
  device_count = @($correlations).Count
  correlations = @($correlations)
}

($out | ConvertTo-Json -Depth 80) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("CORRELATION_PATH: " + $OutPath)
Write-Host ("CORRELATION_DEVICE_COUNT: " + @($correlations).Count)

foreach($c in @($correlations)){
  Write-Host ("CORRELATION_DEVICE :: " + $c.ip + " :: " + $c.risk_level + " :: score=" + $c.risk_score + " :: reasons=" + (@($c.reasons) -join ","))
}

Write-Host "SHUTTERWALL_CORRELATION_ENGINE_V1_OK"
