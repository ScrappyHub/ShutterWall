param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$BaselineRoot = Join-Path $RepoRoot "proofs\baseline"
$BaselinePath = Join-Path $BaselineRoot "baseline_v1.json"
$BaselineHashPath = Join-Path $BaselineRoot "baseline_hash.txt"
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"
New-Item -ItemType Directory -Path $BaselineRoot -Force | Out-Null

function Get-Sha256Hex {
  param([byte[]]$Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
  (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

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
  Write-Utf8NoBomLf -Path $Path -Text ((($line -replace "`r`n","`n") -replace "`r","`n"))
}

Write-Host "BASELINE_STEP: inspect" -ForegroundColor Cyan
$out = Join-Path $BaselineRoot "baseline_inspect.stdout.txt"
$err = Join-Path $BaselineRoot "baseline_inspect.stderr.txt"
$args = @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1"),"-RepoRoot",$RepoRoot,"-StartHost","1","-EndHost","40","-ConnectTimeoutMs","100")
$p = Start-Process -FilePath $PSExe -ArgumentList $args -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$stdout = [System.IO.File]::ReadAllText($out)
if($p.ExitCode -ne 0){ Write-Host $stdout; Write-Host ([System.IO.File]::ReadAllText($err)); throw "BASELINE_INSPECT_FAILED" }
if(-not $stdout.Contains("SHUTTERWALL_DISCOVERY_FINGERPRINT_V3_OK")){ Write-Host $stdout; throw "BASELINE_INSPECT_TOKEN_MISSING" }

$runRootLine = @($stdout -split "`r?`n" | Where-Object { $_ -like "RUN_ROOT:*" }) | Select-Object -First 1
if(-not $runRootLine){ throw "RUN_ROOT_NOT_FOUND" }
$RunRoot = ($runRootLine -replace "^RUN_ROOT:\s*","").Trim()
$DevicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$FingerprintsPath = Join-Path $RunRoot "devices.fingerprint.v1.json"
$SummaryPath = Join-Path $RunRoot "run.summary.json"

$devices = Get-Content -LiteralPath $DevicesPath -Raw | ConvertFrom-Json
$fingerprints = Get-Content -LiteralPath $FingerprintsPath -Raw | ConvertFrom-Json
$summary = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json

$deviceCount = @($devices.devices).Count
$fingerprintCount = @($fingerprints.fingerprints).Count

$baseline = [ordered]@{
  schema = "shutterwall.baseline.v1"
  created_at_utc = [DateTime]::UtcNow.ToString("o")
  source_run_root = $RunRoot
  devices_path = $DevicesPath
  fingerprints_path = $FingerprintsPath
  summary_path = $SummaryPath
  device_count = $deviceCount
  fingerprint_count = $fingerprintCount
  devices = @($devices.devices)
  fingerprints = @($fingerprints.fingerprints)
}

$json = ($baseline | ConvertTo-Json -Depth 30)
$norm = ($json -replace "`r`n","`n") -replace "`r","`n"
if(-not $norm.EndsWith("`n")){ $norm += "`n" }
$enc = New-Object System.Text.UTF8Encoding($false)
$bytes = $enc.GetBytes($norm)
$hash = Get-Sha256Hex -Bytes $bytes

Write-Utf8NoBomLf -Path $BaselinePath -Text $norm
Write-Utf8NoBomLf -Path $BaselineHashPath -Text $hash

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "baseline_created"
  baseline_path = $BaselinePath
  baseline_hash = $hash
  source_run_root = $RunRoot
  device_count = $deviceCount
  fingerprint_count = $fingerprintCount
})

Write-Host ("BASELINE_PATH: " + $BaselinePath) -ForegroundColor Green
Write-Host ("BASELINE_HASH: " + $hash) -ForegroundColor Green
Write-Host ("DEVICE_COUNT: " + $deviceCount) -ForegroundColor Yellow
Write-Host ("FINGERPRINT_COUNT: " + $fingerprintCount) -ForegroundColor Yellow
Write-Host "SHUTTERWALL_BASELINE_V1_OK" -ForegroundColor Green
