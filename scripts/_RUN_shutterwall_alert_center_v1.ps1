param(
  [ValidateSet("emit","list","clear")]
  [string]$Mode = "list",

  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$AlertType = "",
  [string]$Severity = "info",
  [string]$Ip = "",
  [string]$Message = "",
  [string]$Source = "manual"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AlertRoot = Join-Path $RepoRoot "state\alerts"
$AlertPath = Join-Path $AlertRoot "alerts.ndjson"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if(-not (Test-Path -LiteralPath $AlertRoot -PathType Container)){
  New-Item -ItemType Directory -Path $AlertRoot -Force | Out-Null
}

function Add-Utf8NoBomLine {
  param([string]$Path,[string]$Line)

  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  [System.IO.File]::AppendAllText($Path, (($Line -replace "`r`n","`n") -replace "`r","`n") + "`n", $Utf8NoBom)
}

function Write-Utf8NoBomLf {
  param([string]$Path,[string]$Text)

  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$Utf8NoBom)
}

if($Mode -eq "clear"){
  Write-Utf8NoBomLf -Path $AlertPath -Text ""
  Write-Host ("ALERT_CENTER_PATH: " + $AlertPath)
  Write-Host "SHUTTERWALL_ALERT_CENTER_CLEAR_OK"
  return
}

if($Mode -eq "emit"){
  if([string]::IsNullOrWhiteSpace($AlertType)){ throw "ALERT_TYPE_REQUIRED" }
  if([string]::IsNullOrWhiteSpace($Message)){ $Message = $AlertType }

  $allowedSeverity = @("info","low","medium","high","critical")
  if($allowedSeverity -notcontains $Severity){ throw ("INVALID_ALERT_SEVERITY: " + $Severity) }

  $alert = [ordered]@{
    schema = "shutterwall.alert.v1"
    ts_utc = [DateTime]::UtcNow.ToString("o")
    severity = $Severity
    alert_type = $AlertType
    ip = $Ip
    message = $Message
    source = $Source
  }

  Add-Utf8NoBomLine -Path $AlertPath -Line ($alert | ConvertTo-Json -Compress)

  Write-Host ("ALERT_EMITTED :: " + $Severity + " :: " + $AlertType + " :: " + $Ip)
  Write-Host ("ALERT_CENTER_PATH: " + $AlertPath)
  Write-Host "SHUTTERWALL_ALERT_EMIT_OK"
  return
}

$items = @()
if(Test-Path -LiteralPath $AlertPath -PathType Leaf){
  $lines = Get-Content -LiteralPath $AlertPath -ErrorAction SilentlyContinue
  foreach($line in @($lines)){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    try {
      $items += @($line | ConvertFrom-Json)
    } catch {}
  }
}

Write-Host ("ALERT_CENTER_PATH: " + $AlertPath)
Write-Host ("ALERT_CENTER_COUNT: " + @($items).Count)

foreach($a in @($items | Sort-Object ts_utc -Descending | Select-Object -First 50)){
  Write-Host ("ALERT_CENTER :: " + $a.severity + " :: " + $a.alert_type + " :: " + $a.ip + " :: " + $a.message + " :: " + $a.ts_utc)
}

Write-Host "SHUTTERWALL_ALERT_CENTER_LIST_OK"
