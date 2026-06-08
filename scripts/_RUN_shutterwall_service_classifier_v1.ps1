param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$ScanRoot = Join-Path $RepoRoot "proofs\runs\shutterwall_lab_scan"
$OutDir = Join-Path $RepoRoot "state\service_profiles"
$OutPath = Join-Path $OutDir "service_profile.latest.v1.json"

function Port-Name([int]$Port){
  switch($Port){
    22 { "SSH" }
    53 { "DNS" }
    80 { "HTTP" }
    135 { "MSRPC" }
    139 { "NetBIOS" }
    443 { "HTTPS" }
    445 { "SMB" }
    554 { "RTSP Camera Stream" }
    3389 { "RDP" }
    8080 { "HTTP Alt" }
    8443 { "HTTPS Alt" }
    default { "Unknown Service" }
  }
}

function Classify-Device($Ports){
  $p = @($Ports | ForEach-Object { [int]$_ })

  if(($p -contains 53) -and (($p -contains 80) -or ($p -contains 443))){
    return @{
      class = "Likely Router / Gateway"
      confidence = 72
      reason = "DNS plus web administration service detected."
    }
  }

  if(($p -contains 554) -and (($p -contains 80) -or ($p -contains 443))){
    return @{
      class = "Likely IP Camera / NVR"
      confidence = 76
      reason = "RTSP plus web interface detected."
    }
  }

  if(($p -contains 445) -or ($p -contains 139) -or ($p -contains 3389)){
    return @{
      class = "Likely Windows Workstation / Server"
      confidence = 68
      reason = "Windows file sharing or remote desktop service detected."
    }
  }

  if(($p -contains 22) -and (($p -contains 80) -or ($p -contains 443))){
    return @{
      class = "Likely Linux Appliance / Admin UI"
      confidence = 62
      reason = "SSH plus web service detected."
    }
  }

  if($p.Count -gt 0){
    return @{
      class = "Network Service Host"
      confidence = 40
      reason = "Open service ports detected but no stronger class rule matched."
    }
  }

  return @{
    class = "Unknown"
    confidence = 20
    reason = "No open service ports available for classification."
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$latest = Get-ChildItem -LiteralPath $ScanRoot -Directory -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTimeUtc -Descending |
  Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "lab_scan.results.v1.json") } |
  Select-Object -First 1

if($null -eq $latest){
  throw "LAB_SCAN_RESULTS_NOT_FOUND"
}

$ScanPath = Join-Path $latest.FullName "lab_scan.results.v1.json"
$scan = Get-Content -LiteralPath $ScanPath -Raw | ConvertFrom-Json

$byIp = @{}

foreach($r in @($scan.results)){
  $ip = [string]$r.ip
  if(-not $byIp.ContainsKey($ip)){
    $byIp[$ip] = @()
  }
  $byIp[$ip] += [int]$r.port
}

$profiles = @()

foreach($ip in @($byIp.Keys | Sort-Object)){
  $ports = @($byIp[$ip] | Sort-Object -Unique)
  $services = @()

  foreach($port in $ports){
    $services += [ordered]@{
      port = [int]$port
      service = Port-Name ([int]$port)
      state = "open"
    }
  }

  $classification = Classify-Device $ports

  $profiles += [ordered]@{
    ip = $ip
    open_ports = @($ports)
    services = @($services)
    device_class = [string]$classification.class
    confidence_percent = [int]$classification.confidence
    reason = [string]$classification.reason
  }
}

$out = [ordered]@{
  schema = "shutterwall.service_profile.v1"
  generated_utc = [DateTime]::UtcNow.ToString("o")
  source_scan_path = $ScanPath
  profile_count = @($profiles).Count
  profiles = @($profiles)
}

($out | ConvertTo-Json -Depth 50) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("SERVICE_PROFILE_PATH: " + $OutPath)
Write-Host ("SERVICE_PROFILE_COUNT: " + @($profiles).Count)

foreach($p in @($profiles)){
  Write-Host ("SERVICE_PROFILE :: " + $p.ip + " :: " + $p.device_class + " :: confidence=" + $p.confidence_percent + "% :: ports=" + (@($p.open_ports) -join ","))
}

Write-Host "SHUTTERWALL_SERVICE_CLASSIFIER_V1_OK"
