param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$RunRoot,
  [Parameter(Mandatory=$false)][switch]$Apply,
  [Parameter(Mandatory=$false)][switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Apply -and -not $WhatIf) { $WhatIf = $true }
if ($Apply -and $WhatIf) { throw "INVALID_MODE: specify only one of -Apply or -WhatIf" }

function Write-Utf8NoBomLf {
  param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][string]$Text)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if (-not $norm.EndsWith("`n")) { $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Get-Sha256HexFromBytes {
  param([byte[]]$Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
  (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-Sha256HexFromText {
  param([string]$Text)
  $enc = New-Object System.Text.UTF8Encoding($false)
  [byte[]]$bytes = $enc.GetBytes([string]$Text)
  Get-Sha256HexFromBytes -Bytes $bytes
}

function Convert-ObjectToJsonStable {
  param([Parameter(Mandatory=$true)]$InputObject,[Parameter(Mandatory=$false)][int]$Depth = 12)
  ($InputObject | ConvertTo-Json -Depth $Depth)
}

function Append-NdjsonLine {
  param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)]$Object)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
  $line = Convert-ObjectToJsonStable -InputObject $Object -Depth 12
  $normalized = ($line -replace "`r`n","`n") -replace "`r","`n"
  $enc = New-Object System.Text.UTF8Encoding($false)
  [byte[]]$bytes = $enc.GetBytes([string]$normalized)
  $fs = [System.IO.File]::Open($Path,[System.IO.FileMode]::Append,[System.IO.FileAccess]::Write,[System.IO.FileShare]::Read)
  try {
    $fs.Write($bytes,0,$bytes.Length)
    $fs.WriteByte([byte]10)
  } finally {
    $fs.Dispose()
  }
}

function Parse-GateFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  $tok = $null; $err = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){
    $e = $err[0]
    throw ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function Read-JsonFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw ("JSON_INPUT_MISSING: " + $Path) }
  $raw = [System.IO.File]::ReadAllText($Path)
  if ([string]::IsNullOrWhiteSpace($raw)) { throw ("JSON_INPUT_EMPTY: " + $Path) }
  $raw | ConvertFrom-Json
}

function Get-LatestRunRoot {
  param([Parameter(Mandatory=$true)][string]$RepoRoot)
  $base = Join-Path $RepoRoot "proofs\runs\shutterwall"
  if (-not (Test-Path -LiteralPath $base)) { throw ("RUNS_ROOT_MISSING: " + $base) }
  $dirs = @(Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTimeUtc -Descending)
  if (@($dirs).Count -lt 1) { throw ("NO_RUN_DIRECTORIES: " + $base) }
  $dirs[0].FullName
}

function Test-IsAdministrator {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-EnforcementReceipt {
  param(
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Receipts,
    [Parameter(Mandatory=$true)][string]$ActionId,
    [Parameter(Mandatory=$true)][string]$TargetDeviceId,
    [Parameter(Mandatory=$true)][string]$TargetIp,
    [Parameter(Mandatory=$true)][string]$ActionType,
    [Parameter(Mandatory=$true)][string]$Mode,
    [Parameter(Mandatory=$true)][string]$Result,
    [Parameter(Mandatory=$true)][string]$Detail,
    [Parameter(Mandatory=$false)][string]$RuleName
  )
  $seed = [ordered]@{
    action_id = $ActionId
    target_ip = $TargetIp
    action_type = $ActionType
    mode = $Mode
    result = $Result
    detail = $Detail
    rule_name = $RuleName
  }
  $receiptId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $seed -Depth 8)
  $receipt = [ordered]@{
    schema = "device.enforcement.receipt.v3"
    receipt_id = $receiptId
    action_id = $ActionId
    target_device_id = $TargetDeviceId
    target_ip = $TargetIp
    action_type = $ActionType
    mode = $Mode
    result = $Result
    detail = $Detail
    rule_name = $RuleName
    ts_utc = [DateTime]::UtcNow.ToString("o")
  }
  [void]$Receipts.Add($receipt)
}

function Ensure-FirewallRule {
  param(
    [Parameter(Mandatory=$true)][string]$RuleName,
    [Parameter(Mandatory=$true)][ValidateSet("Inbound","Outbound")][string]$Direction,
    [Parameter(Mandatory=$true)][string]$RemoteAddress
  )

  $existing = @(Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)
  if (@($existing).Count -gt 0) { return "already_present" }

  New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction $Direction `
    -Action Block `
    -Enabled True `
    -Profile Any `
    -RemoteAddress $RemoteAddress | Out-Null

  "applied"
}

$ScriptSelf = $MyInvocation.MyCommand.Path
Parse-GateFile -Path $ScriptSelf

if (-not (Test-Path -LiteralPath $RepoRoot)) { throw ("REPO_ROOT_MISSING: " + $RepoRoot) }
if (-not $RunRoot) { $RunRoot = Get-LatestRunRoot -RepoRoot $RepoRoot }
if (-not (Test-Path -LiteralPath $RunRoot)) { throw ("RUN_ROOT_MISSING: " + $RunRoot) }

$PlanPath        = Join-Path $RunRoot "device.enforcement.plan.v2.json"
$LiveReceiptPath = Join-Path $RunRoot "device.enforcement.live.receipts.v3.json"
$ReceiptPath     = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"

$planDoc = Read-JsonFile -Path $PlanPath
$actions = @($planDoc.actions)
$mode = if ($Apply) { "apply" } else { "whatif" }

Write-Host ("MODE: " + $mode) -ForegroundColor Cyan
Write-Host ("RUN_ROOT: " + $RunRoot) -ForegroundColor Cyan
Write-Host ("PLAN_PATH: " + $PlanPath) -ForegroundColor Cyan
Write-Host ("ACTION_COUNT: " + @($actions).Count) -ForegroundColor Yellow

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "live_enforcement_v3_started"
  run_root = $RunRoot
  plan_path = $PlanPath
  mode = $mode
  action_count = @($actions).Count
})

if ($Apply -and -not (Test-IsAdministrator)) { throw "ADMIN_REQUIRED_FOR_APPLY" }

$liveReceipts = New-Object System.Collections.ArrayList

foreach ($action in $actions) {
  $actionId = [string]$action.action_id
  $targetDeviceId = [string]$action.target_device_id
  $targetIp = [string]$action.target_ip
  $actionType = [string]$action.action_type

  Write-Host ("PROCESS_ACTION: " + $actionId + " :: " + $actionType + " :: " + $targetIp) -ForegroundColor DarkCyan

  if ([string]::IsNullOrWhiteSpace($targetIp)) {
    Add-EnforcementReceipt -Receipts $liveReceipts -ActionId $actionId -TargetDeviceId $targetDeviceId -TargetIp $targetIp -ActionType $actionType -Mode $mode -Result "skipped" -Detail "Target IP missing; no live action performed." -RuleName ""
    continue
  }

  $outRule = ""
  $inRule  = ""
  $whatIfDetail = ""
  $supportsIsolation = $false

  switch ($actionType) {
    "plan_block_internet_egress" {
      $supportsIsolation = $true
      $outRule = "ShutterWall V3 Block Out " + $targetIp
      $whatIfDetail = "Would create outbound firewall block rule for target IP."
    }
    "plan_confirmed_camera_isolation_review" {
      $supportsIsolation = $true
      $outRule = "ShutterWall V3 Confirmed Cam Out " + $targetIp
      $inRule  = "ShutterWall V3 Confirmed Cam In " + $targetIp
      $whatIfDetail = "Would create paired outbound and inbound firewall block rules for confirmed camera isolation."
    }
    "plan_restrict_admin_surface" {
      $supportsIsolation = $true
      $outRule = "ShutterWall V3 Restrict Admin Out " + $targetIp
      $inRule  = "ShutterWall V3 Restrict Admin In " + $targetIp
      $whatIfDetail = "Would create paired firewall block rules for admin surface restriction."
    }
    "plan_restrict_stream_access" {
      $supportsIsolation = $true
      $outRule = "ShutterWall V3 Restrict Stream Out " + $targetIp
      $inRule  = "ShutterWall V3 Restrict Stream In " + $targetIp
      $whatIfDetail = "Would create paired firewall block rules for stream restriction."
    }
    default {
      $supportsIsolation = $false
    }
  }

  if (-not $supportsIsolation) {
    Add-EnforcementReceipt -Receipts $liveReceipts -ActionId $actionId -TargetDeviceId $targetDeviceId -TargetIp $targetIp -ActionType $actionType -Mode $mode -Result "skipped" -Detail "Action type not mapped to true isolation in v3." -RuleName ""
    continue
  }

  if ($WhatIf) {
    $ruleBundle = if ($inRule) { $outRule + " | " + $inRule } else { $outRule }
    Add-EnforcementReceipt -Receipts $liveReceipts -ActionId $actionId -TargetDeviceId $targetDeviceId -TargetIp $targetIp -ActionType $actionType -Mode $mode -Result "planned" -Detail $whatIfDetail -RuleName $ruleBundle
    continue
  }

  $results = @()

  if ($outRule) {
    $r = Ensure-FirewallRule -RuleName $outRule -Direction Outbound -RemoteAddress $targetIp
    $results += $r
  }

  if ($inRule) {
    $r = Ensure-FirewallRule -RuleName $inRule -Direction Inbound -RemoteAddress $targetIp
    $results += $r
  }

  $finalResult = if (@($results | Where-Object { $_ -eq "applied" }).Count -gt 0) { "applied" } else { "already_present" }
  $ruleBundle = if ($inRule) { $outRule + " | " + $inRule } else { $outRule }
  $detail = if ($finalResult -eq "applied") { "Created live isolation firewall rules." } else { "Live isolation firewall rules already existed." }

  Add-EnforcementReceipt -Receipts $liveReceipts -ActionId $actionId -TargetDeviceId $targetDeviceId -TargetIp $targetIp -ActionType $actionType -Mode $mode -Result $finalResult -Detail $detail -RuleName $ruleBundle
}

$receipts = @($liveReceipts)

$liveDoc = [ordered]@{
  schema = "shutterwall.enforcement.live.receipts.collection.v3"
  run_root = $RunRoot
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  mode = $mode
  plan_path = $PlanPath
  count = @($receipts).Count
  receipts = @($receipts)
}

Write-Utf8NoBomLf -Path $LiveReceiptPath -Text (Convert-ObjectToJsonStable -InputObject $liveDoc -Depth 20)

$appliedCount = @($receipts | Where-Object { $_.result -eq "applied" }).Count
$plannedCount = @($receipts | Where-Object { $_.result -eq "planned" }).Count
$skippedCount = @($receipts | Where-Object { $_.result -eq "skipped" }).Count
$alreadyCount = @($receipts | Where-Object { $_.result -eq "already_present" }).Count

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "live_enforcement_v3_completed"
  run_root = $RunRoot
  live_receipt_path = $LiveReceiptPath
  mode = $mode
  applied = $appliedCount
  planned = $plannedCount
  skipped = $skippedCount
  already_present = $alreadyCount
})

Write-Host ("LIVE_RECEIPT_PATH: " + $LiveReceiptPath) -ForegroundColor Green
Write-Host ("APPLIED: " + $appliedCount) -ForegroundColor Yellow
Write-Host ("PLANNED: " + $plannedCount) -ForegroundColor Yellow
Write-Host ("SKIPPED: " + $skippedCount) -ForegroundColor Yellow
Write-Host ("ALREADY_PRESENT: " + $alreadyCount) -ForegroundColor Yellow
Write-Host "SHUTTERWALL_LIVE_ENFORCEMENT_V3_OK" -ForegroundColor Green
