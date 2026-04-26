param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [int]$Count = 3,
  [int]$IntervalSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$WatchId = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmssZ")
$WatchRoot = Join-Path $RepoRoot ("proofs\watch\watch_" + $WatchId)
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"
New-Item -ItemType Directory -Path $WatchRoot -Force | Out-Null

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

if($Count -lt 1){ throw "INVALID_COUNT" }
if($IntervalSeconds -lt 1){ throw "INVALID_INTERVAL" }

Write-Host ("WATCH_ROOT: " + $WatchRoot) -ForegroundColor Cyan
Write-Host ("WATCH_COUNT: " + $Count) -ForegroundColor Cyan
Write-Host ("WATCH_INTERVAL_SECONDS: " + $IntervalSeconds) -ForegroundColor Cyan

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "watch_started"
  watch_root = $WatchRoot
  count = $Count
  interval_seconds = $IntervalSeconds
})

$stableCount = 0
$changedCount = 0
$totalAlertCount = 0

for($i = 1; $i -le $Count; $i++){
  Write-Host ("WATCH_TICK: " + $i) -ForegroundColor Cyan
  $out = Join-Path $WatchRoot ("tick_" + $i + ".diff.stdout.txt")
  $err = Join-Path $WatchRoot ("tick_" + $i + ".diff.stderr.txt")

  $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "scripts\_RUN_shutterwall_diff_v1.ps1"),"-RepoRoot",$RepoRoot)
  $p = Start-Process -FilePath $PSExe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err

  $stdout = [System.IO.File]::ReadAllText($out)
  $stderr = [System.IO.File]::ReadAllText($err)

  if($p.ExitCode -ne 0){
    Write-Host $stdout
    Write-Host $stderr
    throw ("WATCH_DIFF_TICK_FAILED: " + $i)
  }

  if(-not $stdout.Contains("SHUTTERWALL_DIFF_V1_OK")){
    Write-Host $stdout
    throw ("WATCH_DIFF_TOKEN_MISSING: " + $i)
  }

  $state = "UNKNOWN"
  if($stdout.Contains("NETWORK_STATE_STABLE")){ $state = "NETWORK_STATE_STABLE"; $stableCount++ }
  elseif($stdout.Contains("NETWORK_STATE_CHANGED")){ $state = "NETWORK_STATE_CHANGED"; $changedCount++ }

  $alertLine = @($stdout -split "`r?`n" | Where-Object { $_ -like "ALERT_COUNT:*" }) | Select-Object -First 1
  $alertCount = 0
  if($alertLine){
    $raw = ($alertLine -replace "^ALERT_COUNT:\s*","").Trim()
    if($raw -match "^\d+$"){ $alertCount = [int]$raw }
  }
  $totalAlertCount += $alertCount

  Write-Host ("WATCH_TICK_STATE: " + $state) -ForegroundColor Green
  Write-Host ("WATCH_TICK_ALERTS: " + $alertCount) -ForegroundColor Yellow

  if($state -eq "NETWORK_STATE_CHANGED"){
    Write-Host "ALERT_NETWORK_STATE_CHANGED" -ForegroundColor Yellow
    $alertLines = @($stdout -split "`r?`n" | Where-Object { $_ -like "ALERT_*" })
    foreach($line in $alertLines){ Write-Host $line -ForegroundColor Yellow }
  }

  Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
    ts_utc = [DateTime]::UtcNow.ToString("o")
    schema = "shutterwall.receipt.v1"
    event = "watch_tick_completed"
    watch_root = $WatchRoot
    tick = $i
    network_state = $state
    alert_count = $alertCount
    stdout_path = $out
    stderr_path = $err
  })

  Write-Host ("WATCH_TICK_OK: " + $i) -ForegroundColor Green
  if($i -lt $Count){ Start-Sleep -Seconds $IntervalSeconds }
}

$finalState = if($changedCount -gt 0){ "NETWORK_STATE_CHANGED" } else { "NETWORK_STATE_STABLE" }

$summary = [ordered]@{
  schema = "shutterwall.watch.summary.v1"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  watch_root = $WatchRoot
  count = $Count
  interval_seconds = $IntervalSeconds
  stable_ticks = $stableCount
  changed_ticks = $changedCount
  total_alert_count = $totalAlertCount
  final_state = $finalState
}

$SummaryPath = Join-Path $WatchRoot "watch.summary.v1.json"
Write-Utf8NoBomLf -Path $SummaryPath -Text ($summary | ConvertTo-Json -Depth 20)

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "watch_completed"
  watch_root = $WatchRoot
  summary_path = $SummaryPath
  stable_ticks = $stableCount
  changed_ticks = $changedCount
  total_alert_count = $totalAlertCount
  final_state = $finalState
})

Write-Host ("SHUTTERWALL_WATCH_ROOT: " + $WatchRoot) -ForegroundColor Green
Write-Host ("WATCH_SUMMARY_PATH: " + $SummaryPath) -ForegroundColor Green
Write-Host ("STABLE_TICKS: " + $stableCount) -ForegroundColor Yellow
Write-Host ("CHANGED_TICKS: " + $changedCount) -ForegroundColor Yellow
Write-Host ("TOTAL_ALERT_COUNT: " + $totalAlertCount) -ForegroundColor Yellow
Write-Host $finalState -ForegroundColor Green
Write-Host "SHUTTERWALL_WATCH_V1_OK" -ForegroundColor Green
