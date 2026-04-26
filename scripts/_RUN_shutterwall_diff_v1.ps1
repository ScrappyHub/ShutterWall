param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$BaselinePath = Join-Path $RepoRoot "proofs\baseline\baseline_v1.json"
$DiffRoot = Join-Path $RepoRoot "proofs\diff"
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"
New-Item -ItemType Directory -Path $DiffRoot -Force | Out-Null

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Append-NdjsonLine {
  param([string]$Path,$Object)
  $line = ($Object | ConvertTo-Json -Depth 20)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::AppendAllText($Path, ((($line -replace "`r`n","`n") -replace "`r","`n") + "`n"), $enc)
}

function Get-DeviceKey {
  param($Device)
  if($Device.device_id){ return [string]$Device.device_id }
  if($Device.ip){ return [string]$Device.ip }
  return ""
}

function Get-FingerprintKey {
  param($Fingerprint)
  if($Fingerprint.device_id){ return [string]$Fingerprint.device_id }
  if($Fingerprint.ip){ return [string]$Fingerprint.ip }
  return ""
}

function StableJson {
  param($Object)
  (($Object | ConvertTo-Json -Depth 30) -replace "`r`n","`n") -replace "`r","`n"
}

if(-not (Test-Path -LiteralPath $BaselinePath)){ throw "BASELINE_MISSING_RUN_SHUTTERWALL_BASELINE_FIRST" }

$Baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json

Write-Host "DIFF_STEP: inspect" -ForegroundColor Cyan
$stamp = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmssZ")
$out = Join-Path $DiffRoot ("diff_inspect_" + $stamp + ".stdout.txt")
$err = Join-Path $DiffRoot ("diff_inspect_" + $stamp + ".stderr.txt")
$args = @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1"),"-RepoRoot",$RepoRoot,"-StartHost","1","-EndHost","40","-ConnectTimeoutMs","100")
$p = Start-Process -FilePath $PSExe -ArgumentList $args -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$stdout = [System.IO.File]::ReadAllText($out)
if($p.ExitCode -ne 0){ Write-Host $stdout; Write-Host ([System.IO.File]::ReadAllText($err)); throw "DIFF_INSPECT_FAILED" }
if(-not $stdout.Contains("SHUTTERWALL_DISCOVERY_FINGERPRINT_V3_OK")){ Write-Host $stdout; throw "DIFF_INSPECT_TOKEN_MISSING" }

$runRootLine = @($stdout -split "`r?`n" | Where-Object { $_ -like "RUN_ROOT:*" }) | Select-Object -First 1
if(-not $runRootLine){ throw "RUN_ROOT_NOT_FOUND" }
$RunRoot = ($runRootLine -replace "^RUN_ROOT:\s*","").Trim()
$DevicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$FingerprintsPath = Join-Path $RunRoot "devices.fingerprint.v1.json"

$CurrentDevicesDoc = Get-Content -LiteralPath $DevicesPath -Raw | ConvertFrom-Json
$CurrentFingerprintsDoc = Get-Content -LiteralPath $FingerprintsPath -Raw | ConvertFrom-Json

$baselineDevices = @($Baseline.devices)
$currentDevices = @($CurrentDevicesDoc.devices)
$baselineFingerprints = @($Baseline.fingerprints)
$currentFingerprints = @($CurrentFingerprintsDoc.fingerprints)

$baselineDeviceMap = @{}
foreach($d in $baselineDevices){ $k = Get-DeviceKey $d; if($k){ $baselineDeviceMap[$k] = $d } }
$currentDeviceMap = @{}
foreach($d in $currentDevices){ $k = Get-DeviceKey $d; if($k){ $currentDeviceMap[$k] = $d } }

$baselineFpMap = @{}
foreach($f in $baselineFingerprints){ $k = Get-FingerprintKey $f; if($k){ $baselineFpMap[$k] = StableJson $f } }
$currentFpMap = @{}
foreach($f in $currentFingerprints){ $k = Get-FingerprintKey $f; if($k){ $currentFpMap[$k] = StableJson $f } }

$alerts = New-Object System.Collections.ArrayList

foreach($k in @($currentDeviceMap.Keys | Sort-Object)){
  if(-not $baselineDeviceMap.ContainsKey($k)){
    [void]$alerts.Add([ordered]@{ token="ALERT_NEW_DEVICE"; key=$k; ip=[string]$currentDeviceMap[$k].ip; message="Device appears in current scan but not baseline." })
  }
}

foreach($k in @($baselineDeviceMap.Keys | Sort-Object)){
  if(-not $currentDeviceMap.ContainsKey($k)){
    [void]$alerts.Add([ordered]@{ token="ALERT_DEVICE_MISSING"; key=$k; ip=[string]$baselineDeviceMap[$k].ip; message="Baseline device missing from current scan." })
  }
}

foreach($k in @($currentFpMap.Keys | Sort-Object)){
  if($baselineFpMap.ContainsKey($k)){
    if($baselineFpMap[$k] -ne $currentFpMap[$k]){
      $ip = ""
      if($currentDeviceMap.ContainsKey($k)){ $ip = [string]$currentDeviceMap[$k].ip }
      [void]$alerts.Add([ordered]@{ token="ALERT_FINGERPRINT_CHANGED"; key=$k; ip=$ip; message="Device fingerprint changed from baseline." })
    }
  }
}

$state = if(@($alerts).Count -gt 0){ "NETWORK_STATE_CHANGED" } else { "NETWORK_STATE_STABLE" }
$DiffPath = Join-Path $DiffRoot ("diff_v1_" + $stamp + ".json")
$diffDoc = [ordered]@{
  schema = "shutterwall.diff.v1"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  baseline_path = $BaselinePath
  current_run_root = $RunRoot
  current_devices_path = $DevicesPath
  current_fingerprints_path = $FingerprintsPath
  baseline_device_count = @($baselineDevices).Count
  current_device_count = @($currentDevices).Count
  alert_count = @($alerts).Count
  network_state = $state
  alerts = @($alerts)
}

Write-Utf8NoBomLf -Path $DiffPath -Text (($diffDoc | ConvertTo-Json -Depth 30))

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "diff_completed"
  diff_path = $DiffPath
  baseline_path = $BaselinePath
  current_run_root = $RunRoot
  network_state = $state
  alert_count = @($alerts).Count
})

Write-Host ("DIFF_PATH: " + $DiffPath) -ForegroundColor Green
Write-Host ("BASELINE_DEVICES: " + @($baselineDevices).Count) -ForegroundColor Yellow
Write-Host ("CURRENT_DEVICES: " + @($currentDevices).Count) -ForegroundColor Yellow
Write-Host ("ALERT_COUNT: " + @($alerts).Count) -ForegroundColor Yellow
Write-Host $state -ForegroundColor Green
foreach($a in @($alerts)){ Write-Host (($a.token) + " :: " + ($a.ip) + " :: " + ($a.message)) -ForegroundColor Yellow }
Write-Host "SHUTTERWALL_DIFF_V1_OK" -ForegroundColor Green
