param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$RunRoot,
  [Parameter(Mandatory=$false)][ValidateSet("home_safe","smallbiz_balanced","enterprise_strict")][string]$PolicyProfile = "home_safe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Get-SeverityRank {
  param([Parameter(Mandatory=$true)][string]$Severity)
  switch ($Severity) {
    "critical" { 4; break }
    "high"     { 3; break }
    "medium"   { 2; break }
    "low"      { 1; break }
    default    { 0; break }
  }
}

function Get-MinimumSeverityForProfile {
  param([Parameter(Mandatory=$true)][string]$PolicyProfile)
  switch ($PolicyProfile) {
    "home_safe"           { "low"; break }
    "smallbiz_balanced"   { "low"; break }
    "enterprise_strict"   { "low"; break }
    default               { "medium"; break }
  }
}

function Add-PlanAction {
  param(
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Actions,
    [Parameter(Mandatory=$true)][string]$DeviceId,
    [Parameter(Mandatory=$true)][string]$Ip,
    [Parameter(Mandatory=$true)][string]$ActionType,
    [Parameter(Mandatory=$true)][string]$Reason,
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$FindingIds,
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$RuleIds,
    [Parameter(Mandatory=$true)][string]$PlannedChange,
    [Parameter(Mandatory=$true)][bool]$RollbackSupported
  )

  $seed = [ordered]@{
    device_id = $DeviceId
    action_type = $ActionType
    planned_change = $PlannedChange
    finding_ids = @($FindingIds)
    rule_ids = @($RuleIds)
  }
  $actionId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $seed -Depth 8)

  $action = [ordered]@{
    schema = "device.enforcement.plan.action.v4"
    action_id = $actionId
    target_device_id = $DeviceId
    target_ip = $Ip
    action_type = $ActionType
    reason = $Reason
    finding_ids = @($FindingIds)
    triggering_rule_ids = @($RuleIds)
    planned_change = $PlannedChange
    applied_change = $null
    result = "planned_only"
    rollback_supported = $RollbackSupported
  }

  [void]$Actions.Add($action)
}

$ScriptSelf = $MyInvocation.MyCommand.Path
Parse-GateFile -Path $ScriptSelf

if (-not (Test-Path -LiteralPath $RepoRoot)) { throw ("REPO_ROOT_MISSING: " + $RepoRoot) }
if (-not $RunRoot) { $RunRoot = Get-LatestRunRoot -RepoRoot $RepoRoot }
if (-not (Test-Path -LiteralPath $RunRoot)) { throw ("RUN_ROOT_MISSING: " + $RunRoot) }

$RiskPath    = Join-Path $RunRoot "device.risk.collection.v2.json"
$DevicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$ReviewPath  = Join-Path $RunRoot "device.operator.review.collection.v1.json"
$PlanPath    = Join-Path $RunRoot "device.enforcement.plan.v4.json"
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"

$riskDoc    = Read-JsonFile -Path $RiskPath
$devicesDoc = Read-JsonFile -Path $DevicesPath

$findings = @($riskDoc.findings)
$devices  = @($devicesDoc.devices)

$reviews = @()
if (Test-Path -LiteralPath $ReviewPath) {
  $reviewDoc = Read-JsonFile -Path $ReviewPath
  if ($reviewDoc.reviews) { $reviews = @($reviewDoc.reviews) }
}

$latestReviewByDevice = @{}
foreach ($review in $reviews) {
  $deviceId = [string]$review.device_id
  if (-not $deviceId) { continue }
  if (-not $latestReviewByDevice.ContainsKey($deviceId)) {
    $latestReviewByDevice[$deviceId] = $review
    continue
  }
  $existingTs = [string]$latestReviewByDevice[$deviceId].reviewed_at_utc
  $newTs = [string]$review.reviewed_at_utc
  if ($newTs -gt $existingTs) { $latestReviewByDevice[$deviceId] = $review }
}

$deviceById = @{}
foreach ($d in $devices) {
  if ($d -and $d.device_id) { $deviceById[[string]$d.device_id] = $d }
}

$minimumSeverity = Get-MinimumSeverityForProfile -PolicyProfile $PolicyProfile
$minimumRank = Get-SeverityRank -Severity $minimumSeverity

$planSeed = [ordered]@{
  run_root = $RunRoot
  policy_profile = $PolicyProfile
  minimum_severity = $minimumSeverity
  review_count = @($reviews).Count
  ts_utc = [DateTime]::UtcNow.ToString("o")
}
$planRunId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $planSeed -Depth 6)

Write-Host ("PLAN_RUN_ID: " + $planRunId) -ForegroundColor Cyan
Write-Host ("RUN_ROOT: " + $RunRoot) -ForegroundColor Cyan
Write-Host ("POLICY_PROFILE: " + $PolicyProfile) -ForegroundColor Cyan
Write-Host ("MINIMUM_SEVERITY: " + $minimumSeverity) -ForegroundColor Cyan
Write-Host ("INPUT_FINDING_COUNT: " + @($findings).Count) -ForegroundColor Yellow
Write-Host ("INPUT_REVIEW_COUNT: " + @($reviews).Count) -ForegroundColor Yellow

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "enforcement_plan_v4_started"
  plan_run_id = $planRunId
  run_root = $RunRoot
  risk_path = $RiskPath
  review_path = $ReviewPath
  policy_profile = $PolicyProfile
  minimum_severity = $minimumSeverity
})

$eligibleFindings = @($findings | Where-Object {
  (Get-SeverityRank -Severity ([string]$_.severity)) -ge $minimumRank
})

Write-Host ("ELIGIBLE_FINDINGS: " + @($eligibleFindings).Count) -ForegroundColor Yellow

$byDevice = @{}
foreach ($f in $eligibleFindings) {
  $deviceId = [string]$f.device_id

  if ($latestReviewByDevice.ContainsKey($deviceId)) {
    $disp = [string]$latestReviewByDevice[$deviceId].disposition
    if ($disp -eq "ignored" -or $disp -eq "not_camera") { continue }
  }

  if (-not $byDevice.ContainsKey($deviceId)) {
    $byDevice[$deviceId] = New-Object System.Collections.ArrayList
  }
  [void]$byDevice[$deviceId].Add($f)
}

$allActions = New-Object System.Collections.ArrayList
$devicePlanSummaries = @()

foreach ($deviceId in @($deviceById.Keys | Sort-Object)) {
  $device = $deviceById[$deviceId]
  $ip = [string]$device.ip

  $reviewDisposition = ""
  if ($latestReviewByDevice.ContainsKey($deviceId)) {
    $reviewDisposition = [string]$latestReviewByDevice[$deviceId].disposition
  }
  if ($reviewDisposition -eq "ignored") { continue }

  $deviceFindings = @()
  if ($byDevice.ContainsKey($deviceId)) { $deviceFindings = @($byDevice[$deviceId]) }

  $findingIds = @($deviceFindings | ForEach-Object { [string]$_.finding_id })
  $ruleIds    = @($deviceFindings | ForEach-Object { [string]$_.rule_id })
  $severities = @($deviceFindings | ForEach-Object { [string]$_.severity })

  $hasRtspAdmin      = @($ruleIds | Where-Object { $_ -eq "SW.RISK.RTSP_PLUS_ADMIN_SURFACE.V1" }).Count -gt 0
  $hasRtspOnly       = @($ruleIds | Where-Object { $_ -eq "SW.RISK.RTSP_SURFACE_PRESENT.V1" }).Count -gt 0
  $hasAltAdmin       = @($ruleIds | Where-Object { $_ -eq "SW.RISK.ALTERNATE_ADMIN_PORT.V1" }).Count -gt 0
  $hasConfirmed      = @($ruleIds | Where-Object { $_ -eq "SW.RISK.OPERATOR_CONFIRMED_CAMERA.V1" }).Count -gt 0
  $hasUnknownVendor  = @($ruleIds | Where-Object { $_ -eq "SW.RISK.UNKNOWN_VENDOR.V1" }).Count -gt 0
  $hasNoSurface      = @($ruleIds | Where-Object { $_ -eq "SW.RISK.NO_PROBED_SURFACE.V1" }).Count -gt 0
  $hasPossibleCamera = @($ruleIds | Where-Object { $_ -eq "SW.RISK.POSSIBLE_CAMERA_CLASS.V1" }).Count -gt 0

  $maxRank = 0
  foreach ($sev in $severities) {
    $rank = Get-SeverityRank -Severity $sev
    if ($rank -gt $maxRank) { $maxRank = $rank }
  }

  $plannedActionsForDevice = New-Object System.Collections.ArrayList

  if ($maxRank -ge 3) {
    Add-PlanAction -Actions $allActions `
      -DeviceId $deviceId `
      -Ip $ip `
      -ActionType "plan_quarantine_device" `
      -Reason "High or critical findings triggered quarantine." `
      -FindingIds $findingIds `
      -RuleIds $ruleIds `
      -PlannedChange "Quarantine device with inbound and outbound isolation rules." `
      -RollbackSupported $true
    [void]$plannedActionsForDevice.Add("plan_quarantine_device")
  }

  if ($hasRtspAdmin -and @($plannedActionsForDevice).Count -eq 0) {
    Add-PlanAction -Actions $allActions `
      -DeviceId $deviceId `
      -Ip $ip `
      -ActionType "plan_block_internet_egress" `
      -Reason "Combined stream and admin surfaces detected." `
      -FindingIds $findingIds `
      -RuleIds $ruleIds `
      -PlannedChange "Block broader egress while preserving explicit recovery path." `
      -RollbackSupported $true
    [void]$plannedActionsForDevice.Add("plan_block_internet_egress")
  }

  if ($hasRtspOnly -and -not $hasRtspAdmin) {
    Add-PlanAction -Actions $allActions `
      -DeviceId $deviceId `
      -Ip $ip `
      -ActionType "plan_restrict_stream_access" `
      -Reason "RTSP-style stream surface detected." `
      -FindingIds $findingIds `
      -RuleIds $ruleIds `
      -PlannedChange "Restrict stream access using paired firewall isolation rules." `
      -RollbackSupported $true
    [void]$plannedActionsForDevice.Add("plan_restrict_stream_access")
  }

  if ($hasAltAdmin) {
    Add-PlanAction -Actions $allActions `
      -DeviceId $deviceId `
      -Ip $ip `
      -ActionType "plan_restrict_admin_surface" `
      -Reason "Alternate admin surface detected." `
      -FindingIds $findingIds `
      -RuleIds $ruleIds `
      -PlannedChange "Restrict admin surface exposure using paired firewall isolation rules." `
      -RollbackSupported $true
    [void]$plannedActionsForDevice.Add("plan_restrict_admin_surface")
  }

  if ($hasConfirmed -and @($plannedActionsForDevice).Count -eq 0) {
    Add-PlanAction -Actions $allActions `
      -DeviceId $deviceId `
      -Ip $ip `
      -ActionType "plan_confirmed_camera_isolation_review" `
      -Reason "Operator confirmed camera-class device." `
      -FindingIds $findingIds `
      -RuleIds $ruleIds `
      -PlannedChange "Queue confirmed camera for live isolation path." `
      -RollbackSupported $false
    [void]$plannedActionsForDevice.Add("plan_confirmed_camera_isolation_review")
  }

  switch ($PolicyProfile) {
    "home_safe" {
      if ($reviewDisposition -eq "needs_review" -and @($plannedActionsForDevice).Count -eq 0) {
        Add-PlanAction -Actions $allActions `
          -DeviceId $deviceId `
          -Ip $ip `
          -ActionType "plan_manual_review_only" `
          -Reason "Operator review pending." `
          -FindingIds $findingIds `
          -RuleIds $ruleIds `
          -PlannedChange "Hold for operator review before live enforcement." `
          -RollbackSupported $false
        [void]$plannedActionsForDevice.Add("plan_manual_review_only")
      }

      if (@($plannedActionsForDevice).Count -eq 0 -and ($hasUnknownVendor -or $hasNoSurface)) {
        Add-PlanAction -Actions $allActions `
          -DeviceId $deviceId `
          -Ip $ip `
          -ActionType "plan_monitor_only" `
          -Reason "Low-severity evidence warrants monitoring but not isolation." `
          -FindingIds $findingIds `
          -RuleIds $ruleIds `
          -PlannedChange "Mark device for monitoring and repeated inspection." `
          -RollbackSupported $false
        [void]$plannedActionsForDevice.Add("plan_monitor_only")
      }
    }

    "smallbiz_balanced" {
      if ($reviewDisposition -eq "needs_review" -and @($plannedActionsForDevice).Count -eq 0) {
        Add-PlanAction -Actions $allActions `
          -DeviceId $deviceId `
          -Ip $ip `
          -ActionType "plan_manual_review_only" `
          -Reason "Operator review pending." `
          -FindingIds $findingIds `
          -RuleIds $ruleIds `
          -PlannedChange "Hold for operator review before live enforcement." `
          -RollbackSupported $false
        [void]$plannedActionsForDevice.Add("plan_manual_review_only")
      }

      if (@($plannedActionsForDevice).Count -eq 0 -and $hasUnknownVendor -and $hasNoSurface) {
        Add-PlanAction -Actions $allActions `
          -DeviceId $deviceId `
          -Ip $ip `
          -ActionType "plan_restrict_admin_surface" `
          -Reason "Unknown vendor plus no visible surface merits cautious admin restriction in small business mode." `
          -FindingIds $findingIds `
          -RuleIds $ruleIds `
          -PlannedChange "Apply cautious restriction profile for unmanaged device." `
          -RollbackSupported $true
        [void]$plannedActionsForDevice.Add("plan_restrict_admin_surface")
      }
      elseif (@($plannedActionsForDevice).Count -eq 0 -and ($hasUnknownVendor -or $hasPossibleCamera)) {
        Add-PlanAction -Actions $allActions `
          -DeviceId $deviceId `
          -Ip $ip `
          -ActionType "plan_monitor_only" `
          -Reason "Low-severity evidence merits monitoring in small business mode." `
          -FindingIds $findingIds `
          -RuleIds $ruleIds `
          -PlannedChange "Monitor device and re-check in future inspections." `
          -RollbackSupported $false
        [void]$plannedActionsForDevice.Add("plan_monitor_only")
      }
    }

    "enterprise_strict" {
      if (@($plannedActionsForDevice).Count -eq 0 -and ($hasUnknownVendor -or $hasPossibleCamera -or $hasNoSurface)) {
        Add-PlanAction -Actions $allActions `
          -DeviceId $deviceId `
          -Ip $ip `
          -ActionType "plan_quarantine_device" `
          -Reason "Enterprise strict mode escalates unmanaged or weakly understood devices to quarantine." `
          -FindingIds $findingIds `
          -RuleIds $ruleIds `
          -PlannedChange "Quarantine device with inbound and outbound isolation rules." `
          -RollbackSupported $true
        [void]$plannedActionsForDevice.Add("plan_quarantine_device")
      }
    }
  }

  if (@($plannedActionsForDevice).Count -gt 0) {
    $devicePlanSummaries += ,([ordered]@{
      device_id = $deviceId
      ip = $ip
      operator_disposition = $reviewDisposition
      source_finding_count = @($deviceFindings).Count
      planned_action_types = @($plannedActionsForDevice)
    })
  }
}

$actions = @($allActions)
$devicePlanSummaries = @($devicePlanSummaries)

$planDoc = [ordered]@{
  schema = "shutterwall.enforcement.plan.collection.v4"
  plan_run_id = $planRunId
  source_run_root = $RunRoot
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  policy_profile = $PolicyProfile
  minimum_severity = $minimumSeverity
  source_review_path = $ReviewPath
  eligible_finding_count = @($eligibleFindings).Count
  action_count = @($actions).Count
  device_plan_summaries = @($devicePlanSummaries)
  actions = @($actions)
}

Write-Utf8NoBomLf -Path $PlanPath -Text (Convert-ObjectToJsonStable -InputObject $planDoc -Depth 20)

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "enforcement_plan_v4_completed"
  plan_run_id = $planRunId
  run_root = $RunRoot
  plan_path = $PlanPath
  eligible_finding_count = @($eligibleFindings).Count
  action_count = @($actions).Count
  policy_profile = $PolicyProfile
  minimum_severity = $minimumSeverity
  review_count = @($reviews).Count
})

Write-Host ("PLAN_PATH: " + $PlanPath) -ForegroundColor Green
Write-Host ("ELIGIBLE_FINDING_COUNT: " + @($eligibleFindings).Count) -ForegroundColor Yellow
Write-Host ("ACTION_COUNT: " + @($actions).Count) -ForegroundColor Yellow
Write-Host ("REVIEW_COUNT: " + @($reviews).Count) -ForegroundColor Yellow
Write-Host "SHUTTERWALL_ENFORCEMENT_PLAN_V4_OK" -ForegroundColor Green
