param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [int]$IntervalSeconds = 60,
  [int]$MaxTicks = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$DaemonRoot = Join-Path $RepoRoot "proofs\daemon\watch"
$StopFile = Join-Path $DaemonRoot "watch_daemon.stop"
$LatestPath = Join-Path $DaemonRoot "watch_daemon.latest.json"
$EventsPath = Join-Path $DaemonRoot "watch_daemon.events.ndjson"
$NotifyPath = Join-Path $DaemonRoot "watch_daemon.notifications.ndjson"
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"
New-Item -ItemType Directory -Path $DaemonRoot -Force | Out-Null

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Append-NdjsonLine {
  param([string]$Path,$Object)
  $line = ($Object | ConvertTo-Json -Depth 30)
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::AppendAllText($Path, ((($line -replace "`r`n","`n") -replace "`r","`n") + "`n"), $enc)
}

if($IntervalSeconds -lt 10){ throw "INTERVAL_TOO_LOW_MIN_10_SECONDS" }

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "watch_daemon_started"
  daemon_root = $DaemonRoot
  interval_seconds = $IntervalSeconds
  max_ticks = $MaxTicks
  pid = $PID
})

$tick = 0
while($true){
  if(Test-Path -LiteralPath $StopFile){
    Remove-Item -LiteralPath $StopFile -Force
    break
  }

  $tick++
  $stamp = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmssZ")
  $out = Join-Path $DaemonRoot ("tick_" + $stamp + ".stdout.txt")
  $err = Join-Path $DaemonRoot ("tick_" + $stamp + ".stderr.txt")

  $args = @("-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "scripts\_RUN_shutterwall_diff_v1.ps1"),"-RepoRoot",$RepoRoot)
  $p = Start-Process -FilePath $PSExe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err

  $stdout = ""
  $stderr = ""
  if(Test-Path -LiteralPath $out){ $stdout = [System.IO.File]::ReadAllText($out) }
  if(Test-Path -LiteralPath $err){ $stderr = [System.IO.File]::ReadAllText($err) }

  $lines = @($stdout -split "`r?`n")
  $state = "UNKNOWN"
  if($stdout.Contains("NETWORK_STATE_CHANGED")){ $state = "NETWORK_STATE_CHANGED" }
  elseif($stdout.Contains("NETWORK_STATE_STABLE")){ $state = "NETWORK_STATE_STABLE" }

  $alertLine = @($lines | Where-Object { $_ -like "ALERT_COUNT:*" }) | Select-Object -First 1
  $alertCount = 0
  if($alertLine){
    $raw = ($alertLine -replace "^ALERT_COUNT:\s*","").Trim()
    if($raw -match "^\d+$"){ $alertCount = [int]$raw }
  }

  $alerts = @($lines | Where-Object { $_ -like "ALERT_*" -and $_ -notlike "ALERT_COUNT:*" })

  $latest = [ordered]@{
    schema = "shutterwall.watch_daemon.latest.v1"
    ts_utc = [DateTime]::UtcNow.ToString("o")
    pid = $PID
    tick = $tick
    network_state = $state
    alert_count = $alertCount
    alerts = @($alerts)
    stdout_path = $out
    stderr_path = $err
    exit_code = $p.ExitCode
  }

  Write-Utf8NoBomLf -Path $LatestPath -Text ($latest | ConvertTo-Json -Depth 30)
  Append-NdjsonLine -Path $EventsPath -Object $latest

  if($state -eq "NETWORK_STATE_CHANGED" -or $alertCount -gt 0){
    Append-NdjsonLine -Path $NotifyPath -Object ([ordered]@{
      schema = "shutterwall.notification.v1"
      ts_utc = [DateTime]::UtcNow.ToString("o")
      kind = "network_change"
      title = "ShutterWall detected a network change"
      network_state = $state
      alert_count = $alertCount
      alerts = @($alerts)
      latest_path = $LatestPath
    })
  }

  if($MaxTicks -gt 0 -and $tick -ge $MaxTicks){ break }
  Start-Sleep -Seconds $IntervalSeconds
}

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "watch_daemon_stopped"
  daemon_root = $DaemonRoot
  ticks = $tick
  pid = $PID
})
