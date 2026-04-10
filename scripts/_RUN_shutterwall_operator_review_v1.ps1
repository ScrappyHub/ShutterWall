param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$RunRoot,
  [Parameter(Mandatory=$false)][string]$DeviceId,
  [Parameter(Mandatory=$false)][string]$Ip,
  [Parameter(Mandatory=$false)][ValidateSet("confirmed_camera","not_camera","needs_review","ignored")][string]$Disposition = "needs_review",
  [Parameter(Mandatory=$false)][string]$Note = "",
  [Parameter(Mandatory=$false)][string]$OperatorId = "local_operator"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Utf8NoBomLf {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Text
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    [void](New-Item -ItemType Directory -Path $dir -Force)
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if (-not $norm.EndsWith("`n")) { $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Get-Sha256HexFromBytes {
  param([byte[]]$Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($Bytes)
  }
  finally {
    $sha.Dispose()
  }
  (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-Sha256HexFromText {
  param([string]$Text)
  $enc = New-Object System.Text.UTF8Encoding($false)
  [byte[]]$bytes = $enc.GetBytes([string]$Text)
  Get-Sha256HexFromBytes -Bytes $bytes
}

function Convert-ObjectToJsonStable {
  param(
    [Parameter(Mandatory=$true)]$InputObject,
    [Parameter(Mandatory=$false)][int]$Depth = 12
  )
  ($InputObject | ConvertTo-Json -Depth $Depth)
}

function Append-NdjsonLine {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Object
  )

  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    [void](New-Item -ItemType Directory -Path $dir -Force)
  }

  $line = Convert-ObjectToJsonStable -InputObject $Object -Depth 12
  $normalized = ($line -replace "`r`n","`n") -replace "`r","`n"
  $enc = New-Object System.Text.UTF8Encoding($false)
  [byte[]]$bytes = $enc.GetBytes([string]$normalized)

  $fs = [System.IO.File]::Open(
    $Path,
    [System.IO.FileMode]::Append,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::Read
  )
  try {
    $fs.Write($bytes,0,$bytes.Length)
    $fs.WriteByte([byte]10)
  }
  finally {
    $fs.Dispose()
  }
}

function Parse-GateFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  $tok = $null
  $err = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){
    $e = $err[0]
    throw ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function Read-JsonFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw ("JSON_INPUT_MISSING: " + $Path)
  }
  $raw = [System.IO.File]::ReadAllText($Path)
  if ([string]::IsNullOrWhiteSpace($raw)) {
    throw ("JSON_INPUT_EMPTY: " + $Path)
  }
  $raw | ConvertFrom-Json
}

function Get-LatestRunRoot {
  param([Parameter(Mandatory=$true)][string]$RepoRoot)
  $base = Join-Path $RepoRoot "proofs\runs\shutterwall"
  if (-not (Test-Path -LiteralPath $base)) {
    throw ("RUNS_ROOT_MISSING: " + $base)
  }
  $dirs = @(Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTimeUtc -Descending)
  if (@($dirs).Count -lt 1) {
    throw ("NO_RUN_DIRECTORIES: " + $base)
  }
  $dirs[0].FullName
}

$ScriptSelf = $MyInvocation.MyCommand.Path
Parse-GateFile -Path $ScriptSelf

if (-not (Test-Path -LiteralPath $RepoRoot)) {
  throw ("REPO_ROOT_MISSING: " + $RepoRoot)
}

if (-not $RunRoot) {
  $RunRoot = Get-LatestRunRoot -RepoRoot $RepoRoot
}

if (-not (Test-Path -LiteralPath $RunRoot)) {
  throw ("RUN_ROOT_MISSING: " + $RunRoot)
}

$DevicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$ReviewPath  = Join-Path $RunRoot "device.operator.review.collection.v1.json"
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"

$devicesDoc = Read-JsonFile -Path $DevicesPath
$devices = @($devicesDoc.devices)

if ((-not $DeviceId) -and (-not $Ip)) {
  throw "DEVICE_SELECTOR_REQUIRED: provide -DeviceId or -Ip"
}

$selected = $null
foreach ($d in $devices) {
  if ($DeviceId -and ([string]$d.device_id -eq $DeviceId)) {
    $selected = $d
    break
  }
  if ($Ip -and ([string]$d.ip -eq $Ip)) {
    $selected = $d
    break
  }
}

if ($null -eq $selected) {
  throw "SELECTED_DEVICE_NOT_FOUND"
}

$selectedDeviceId = [string]$selected.device_id
$selectedIp = [string]$selected.ip

$existingReviews = @()
if (Test-Path -LiteralPath $ReviewPath) {
  $existingDoc = Read-JsonFile -Path $ReviewPath
  if ($existingDoc.reviews) {
    $existingReviews = @($existingDoc.reviews)
  }
}

$reviewSeed = [ordered]@{
  device_id = $selectedDeviceId
  disposition = $Disposition
  operator_id = $OperatorId
  note = $Note
  run_root = $RunRoot
  ts_utc = [DateTime]::UtcNow.ToString("o")
}
$reviewId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $reviewSeed -Depth 8)

$newReview = [ordered]@{
  schema = "device.operator.review.v1"
  review_id = $reviewId
  source_run_root = $RunRoot
  device_id = $selectedDeviceId
  ip = $selectedIp
  disposition = $Disposition
  note = $Note
  operator_id = $OperatorId
  reviewed_at_utc = [DateTime]::UtcNow.ToString("o")
}

$allReviews = @($existingReviews + @($newReview))

$reviewDoc = [ordered]@{
  schema = "shutterwall.operator.review.collection.v1"
  source_run_root = $RunRoot
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  count = @($allReviews).Count
  reviews = @($allReviews)
}

Write-Utf8NoBomLf -Path $ReviewPath -Text (Convert-ObjectToJsonStable -InputObject $reviewDoc -Depth 20)

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "operator_review_recorded"
  review_id = $reviewId
  source_run_root = $RunRoot
  device_id = $selectedDeviceId
  ip = $selectedIp
  disposition = $Disposition
  operator_id = $OperatorId
})

Write-Host ("REVIEW_PATH: " + $ReviewPath) -ForegroundColor Green
Write-Host ("DEVICE_ID: " + $selectedDeviceId) -ForegroundColor Yellow
Write-Host ("IP: " + $selectedIp) -ForegroundColor Yellow
Write-Host ("DISPOSITION: " + $Disposition) -ForegroundColor Yellow
Write-Host "SHUTTERWALL_OPERATOR_REVIEW_V1_OK" -ForegroundColor Green
