param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$BaselinePath = Join-Path $RepoRoot "state\service_baseline\service_baseline.v1.json"
$ServicePath = Join-Path $RepoRoot "state\service_profiles\service_profile.latest.v1.json"
$OutDir = Join-Path $RepoRoot "state\service_drift"
$OutPath = Join-Path $OutDir "service_drift.latest.v1.json"

if(-not (Test-Path -LiteralPath $BaselinePath)){ throw "SERVICE_BASELINE_MISSING" }
if(-not (Test-Path -LiteralPath $ServicePath)){ throw "SERVICE_PROFILE_MISSING" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
$current = Get-Content -LiteralPath $ServicePath -Raw | ConvertFrom-Json

$findings = @()

foreach($c in @($current.profiles)){
  $ip = [string]$c.ip
  $b = @($baseline.profiles | Where-Object { [string]$_.ip -eq $ip }) | Select-Object -First 1

  if($null -eq $b){
    $findings += [ordered]@{
      ip = $ip
      severity = "medium"
      type = "new_service_profile"
      explanation = "Device has service profile but was not present in the service baseline."
      baseline_ports = @()
      current_ports = @($c.open_ports)
    }
    continue
  }

  $basePorts = @($b.open_ports | ForEach-Object { [int]$_ } | Sort-Object -Unique)
  $curPorts = @($c.open_ports | ForEach-Object { [int]$_ } | Sort-Object -Unique)

  $added = @($curPorts | Where-Object { $basePorts -notcontains $_ })
  $removed = @($basePorts | Where-Object { $curPorts -notcontains $_ })

  if(@($added).Count -gt 0 -or @($removed).Count -gt 0){
    $sev = "low"
    if(($added -contains 445) -or ($added -contains 3389) -or ($added -contains 554)){
      $sev = "medium"
    }

    $findings += [ordered]@{
      ip = $ip
      severity = $sev
      type = "service_port_drift"
      explanation = "Open service port set changed from baseline."
      added_ports = @($added)
      removed_ports = @($removed)
      baseline_ports = @($basePorts)
      current_ports = @($curPorts)
    }
  }

  if([string]$b.device_class -ne [string]$c.device_class){
    $findings += [ordered]@{
      ip = $ip
      severity = "medium"
      type = "service_class_drift"
      explanation = "Service-derived device class changed from baseline."
      baseline_class = [string]$b.device_class
      current_class = [string]$c.device_class
      baseline_ports = @($basePorts)
      current_ports = @($curPorts)
    }
  }
}

foreach($b in @($baseline.profiles)){
  $ip = [string]$b.ip
  $c = @($current.profiles | Where-Object { [string]$_.ip -eq $ip }) | Select-Object -First 1

  if($null -eq $c){
    $findings += [ordered]@{
      ip = $ip
      severity = "low"
      type = "service_profile_missing"
      explanation = "Device service profile existed in baseline but was not observed in the latest service scan."
      baseline_ports = @($b.open_ports)
      current_ports = @()
    }
  }
}

$out = [ordered]@{
  schema = "shutterwall.service_drift.v1"
  generated_utc = [DateTime]::UtcNow.ToString("o")
  baseline_path = $BaselinePath
  service_profile_path = $ServicePath
  finding_count = @($findings).Count
  findings = @($findings)
}

($out | ConvertTo-Json -Depth 80) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("SERVICE_DRIFT_PATH: " + $OutPath)
Write-Host ("SERVICE_DRIFT_FINDING_COUNT: " + @($findings).Count)

foreach($f in @($findings)){
  Write-Host ("SERVICE_DRIFT_FINDING :: " + $f.severity + " :: " + $f.type + " :: " + $f.ip + " :: " + $f.explanation)
}

Write-Host "SHUTTERWALL_SERVICE_DRIFT_V1_OK"
