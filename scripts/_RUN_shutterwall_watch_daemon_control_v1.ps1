param(
  [ValidateSet("start","stop","status","latest")]
  [string]$Mode = "status",
  [string]$RepoRoot = "C:\dev\shutterwall",
  [int]$IntervalSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$DaemonRoot = Join-Path $RepoRoot "proofs\daemon\watch"
$PidPath = Join-Path $DaemonRoot "watch_daemon.pid.json"
$StopFile = Join-Path $DaemonRoot "watch_daemon.stop"
$LatestPath = Join-Path $DaemonRoot "watch_daemon.latest.json"
$DaemonScript = Join-Path $RepoRoot "scripts\_RUN_shutterwall_watch_daemon_v1.ps1"
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

function Quote-Arg {
  param([string]$Value)
  return '"' + ($Value -replace '"','\"') + '"'
}

function Start-HiddenDetached {
  param([string]$FilePath,[string[]]$Arguments)

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.Arguments = (($Arguments | ForEach-Object { Quote-Arg $_ }) -join " ")
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  return $p
}

function Get-ExistingPid {
  if(-not (Test-Path -LiteralPath $PidPath)){ return 0 }
  try {
    $doc = Get-Content -LiteralPath $PidPath -Raw | ConvertFrom-Json
    return [int]$doc.pid
  } catch { return 0 }
}

if($Mode -eq "start"){
  if(Test-Path -LiteralPath $StopFile){ Remove-Item -LiteralPath $StopFile -Force }

  $existing = Get-ExistingPid
  if($existing -gt 0){
    $proc = Get-Process -Id $existing -ErrorAction SilentlyContinue
    if($proc){
      Write-Host ("WATCH_DAEMON_ALREADY_RUNNING: " + $existing) -ForegroundColor Yellow
      return
    }
  }

  $args = @(
    "-WindowStyle","Hidden",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy","Bypass",
    "-File",$DaemonScript,
    "-RepoRoot",$RepoRoot,
    "-IntervalSeconds",$IntervalSeconds
  )

  $p = Start-HiddenDetached -FilePath $PSExe -Arguments $args
  $doc = [ordered]@{
    schema="shutterwall.watch_daemon.pid.v1"
    pid=$p.Id
    started_at_utc=[DateTime]::UtcNow.ToString("o")
    interval_seconds=$IntervalSeconds
    daemon_root=$DaemonRoot
    silent=$true
  }

  Write-Utf8NoBomLf -Path $PidPath -Text ($doc | ConvertTo-Json -Depth 10)
  Write-Host ("WATCH_DAEMON_STARTED: " + $p.Id) -ForegroundColor Green
  Write-Host "SHUTTERWALL_WATCH_DAEMON_START_OK" -ForegroundColor Green
  return
}

if($Mode -eq "stop"){
  $watchPid = Get-ExistingPid
  Write-Utf8NoBomLf -Path $StopFile -Text "stop"
  Start-Sleep -Seconds 3
  if($watchPid -gt 0){
    $proc = Get-Process -Id $watchPid -ErrorAction SilentlyContinue
    if($proc){ Stop-Process -Id $watchPid -Force }
  }
  Write-Host "WATCH_DAEMON_STOP_REQUESTED" -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_WATCH_DAEMON_STOP_OK" -ForegroundColor Green
  return
}

if($Mode -eq "status"){
  $watchPid = Get-ExistingPid
  if($watchPid -gt 0){
    $proc = Get-Process -Id $watchPid -ErrorAction SilentlyContinue
    if($proc){
      Write-Host "WATCH_DAEMON_STATUS: RUNNING" -ForegroundColor Green
      Write-Host ("PID: " + $watchPid) -ForegroundColor Green
      Write-Host "SILENT: true" -ForegroundColor Green
      Write-Host "SHUTTERWALL_WATCH_DAEMON_STATUS_OK" -ForegroundColor Green
      return
    }
  }
  Write-Host "WATCH_DAEMON_STATUS: STOPPED" -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_WATCH_DAEMON_STATUS_OK" -ForegroundColor Green
  return
}

if($Mode -eq "latest"){
  if(Test-Path -LiteralPath $LatestPath){
    Get-Content -LiteralPath $LatestPath -Raw
    Write-Host "SHUTTERWALL_WATCH_DAEMON_LATEST_OK" -ForegroundColor Green
    return
  }
  Write-Host "WATCH_DAEMON_LATEST_MISSING" -ForegroundColor Yellow
  return
}
