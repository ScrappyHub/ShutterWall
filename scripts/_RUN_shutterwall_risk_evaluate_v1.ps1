param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$RunRoot
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

function Add-RiskFinding {
  param(
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Findings,
    [Parameter(Mandatory=$true)][string]$DeviceId,
    [Parameter(Mandatory=$true)][string]$Severity,
    [Parameter(Mandatory=$true)][string]$RuleId,
    [Parameter(Mandatory=$true)][string]$Title,
    [Parameter(Mandatory=$true)][string]$Reason,
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$EvidenceRefs,
    [Parameter(Mandatory=$true)][string]$RecommendedAction,
    [Parameter(Mandatory=$true)][bool]$Enforceable
  )

  if ($null -eq $Findings) {
    throw "FINDINGS_COLLECTION_NULL"
  }

  $seed = [ordered]@{
    device_id = $DeviceId
    severity = $Severity
    rule_id = $RuleId
    reason = $Reason
  }
  $findingId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $seed -Depth 8)

  $finding = [ordered]@{
    schema = "device.risk.v1"
    finding_id = $findingId
    device_id = $DeviceId
    severity = $Severity
    rule_id = $RuleId
    title = $Title
    evidence_refs = @($EvidenceRefs)
    reason = $Reason
    recommended_action = $RecommendedAction
    enforceable = $Enforceable
  }

  [void]$Findings.Add($finding)
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

$DevicesPath      = Join-Path $RunRoot "devices.discovery.v1.json"
$FingerprintsPath = Join-Path $RunRoot "devices.fingerprint.v1.json"
$SummaryPath      = Join-Path $RunRoot "run.summary.json"
$RiskPath         = Join-Path $RunRoot "device.risk.collection.v1.json"
$ReceiptPath      = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"

$devicesDoc      = Read-JsonFile -Path $DevicesPath
$fingerprintsDoc = Read-JsonFile -Path $FingerprintsPath
$summaryDoc      = Read-JsonFile -Path $SummaryPath

$devices = @($devicesDoc.devices)
$fingerprints = @($fingerprintsDoc.fingerprints)

$fpByDeviceId = @{}
foreach ($fp in $fingerprints) {
  if ($fp -and $fp.device_id) {
    $fpByDeviceId[[string]$fp.device_id] = $fp
  }
}

$riskRunSeed = [ordered]@{
  run_root = $RunRoot
  ts_utc = [DateTime]::UtcNow.ToString("o")
}
$riskRunId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $riskRunSeed -Depth 6)

Write-Host ("RISK_RUN_ID: " + $riskRunId) -ForegroundColor Cyan
Write-Host ("RUN_ROOT: " + $RunRoot) -ForegroundColor Cyan
Write-Host ("INPUT_DEVICE_COUNT: " + @($devices).Count) -ForegroundColor Yellow
Write-Host ("INPUT_FINGERPRINT_COUNT: " + @($fingerprints).Count) -ForegroundColor Yellow

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "risk_run_started"
  risk_run_id = $riskRunId
  run_root = $RunRoot
  devices_path = $DevicesPath
  fingerprints_path = $FingerprintsPath
})

$allFindings = New-Object System.Collections.ArrayList

foreach ($device in $devices) {
  $deviceId = [string]$device.device_id
  $ip = [string]$device.ip
  $cameraLikelihood = [string]$device.camera_likelihood
  $vendorGuess = [string]$device.vendor_guess

  $fp = $null
  if ($fpByDeviceId.ContainsKey($deviceId)) {
    $fp = $fpByDeviceId[$deviceId]
  }

  $openPorts = @()
  if ($fp -and $fp.open_tcp_ports) {
    $openPorts = @($fp.open_tcp_ports | ForEach-Object { [int]$_ })
  }

  $evidenceBase = @(
    ("device:" + $deviceId),
    ("ip:" + $ip)
  )

  if ($openPorts -contains 554 -and ($openPorts -contains 80 -or $openPorts -contains 443 -or $openPorts -contains 8080 -or $openPorts -contains 8443)) {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "high" `
      -RuleId "SW.RISK.RTSP_PLUS_ADMIN_SURFACE.V1" `
      -Title "RTSP and admin surface both exposed" `
      -Reason "Device exposes a stream surface and a likely admin surface at the same time." `
      -EvidenceRefs (@($evidenceBase + @("open_ports:" + (($openPorts -join ","))))) `
      -RecommendedAction "Restrict admin access to trusted devices and prepare internet egress blocking." `
      -Enforceable $true
  }
  elseif ($openPorts -contains 554) {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "medium" `
      -RuleId "SW.RISK.RTSP_SURFACE_PRESENT.V1" `
      -Title "RTSP surface present" `
      -Reason "Device exposes RTSP-style stream surface on port 554." `
      -EvidenceRefs (@($evidenceBase + @("open_ports:554"))) `
      -RecommendedAction "Evaluate whether the stream should be isolated or blocked from non-trusted viewers." `
      -Enforceable $true
  }

  if ($openPorts -contains 8000 -or $openPorts -contains 8080 -or $openPorts -contains 8443) {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "medium" `
      -RuleId "SW.RISK.ALTERNATE_ADMIN_PORT.V1" `
      -Title "Alternate admin surface present" `
      -Reason "Device exposes one or more alternate admin-style ports associated with management surfaces." `
      -EvidenceRefs (@($evidenceBase + @("open_ports:" + (($openPorts -join ","))))) `
      -RecommendedAction "Constrain management access to explicit trusted hosts only." `
      -Enforceable $true
  }

  if ($cameraLikelihood -eq "probable_camera") {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "medium" `
      -RuleId "SW.RISK.PROBABLE_CAMERA_CLASS.V1" `
      -Title "Probable camera-class device" `
      -Reason "Heuristics classify this device as a probable camera-class device." `
      -EvidenceRefs (@($evidenceBase + @("camera_likelihood:" + $cameraLikelihood, "vendor_guess:" + $vendorGuess))) `
      -RecommendedAction "Prioritize this device for explicit privacy control and internet egress review." `
      -Enforceable $true
  }
  elseif ($cameraLikelihood -eq "possible_camera") {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "low" `
      -RuleId "SW.RISK.POSSIBLE_CAMERA_CLASS.V1" `
      -Title "Possible camera-class device" `
      -Reason "Heuristics classify this device as a possible camera-class device." `
      -EvidenceRefs (@($evidenceBase + @("camera_likelihood:" + $cameraLikelihood, "vendor_guess:" + $vendorGuess))) `
      -RecommendedAction "Review this device manually before applying enforcement." `
      -Enforceable $false
  }

  if (@($openPorts).Count -eq 0) {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "low" `
      -RuleId "SW.RISK.NO_PROBED_SURFACE.V1" `
      -Title "No probed ports detected in bounded scan" `
      -Reason "The bounded fingerprint scan did not detect any of the currently probed ports." `
      -EvidenceRefs (@($evidenceBase + @("open_ports:none_detected"))) `
      -RecommendedAction "No immediate action from this scan; broaden scan later if needed." `
      -Enforceable $false
  }

  if ($vendorGuess -like "*unknown*") {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "low" `
      -RuleId "SW.RISK.UNKNOWN_VENDOR.V1" `
      -Title "Vendor remains unknown" `
      -Reason "Fingerprinting did not determine a more specific vendor identity." `
      -EvidenceRefs (@($evidenceBase + @("vendor_guess:" + $vendorGuess))) `
      -RecommendedAction "Collect more fingerprint evidence before stronger enforcement decisions." `
      -Enforceable $false
  }

  if ($vendorGuess -ne "unknown" -and $vendorGuess -ne "") {
    Add-RiskFinding -Findings $allFindings `
      -DeviceId $deviceId `
      -Severity "low" `
      -RuleId "SW.RISK.VENDOR_IDENTIFIED_REVIEW.V1" `
      -Title "Vendor-specific review recommended" `
      -Reason "A vendor-like fingerprint was detected, which can support a later targeted policy profile." `
      -EvidenceRefs (@($evidenceBase + @("vendor_guess:" + $vendorGuess))) `
      -RecommendedAction "Prepare vendor-specific review and policy templates later." `
      -Enforceable $false
  }
}

$findings = @($allFindings)
$deviceRiskSummaries = @()

foreach ($device in $devices) {
  $deviceId = [string]$device.device_id
  $deviceFindings = @($findings | Where-Object { $_.device_id -eq $deviceId })

  $maxRank = 0
  $maxSeverity = "none"
  foreach ($f in $deviceFindings) {
    $rank = Get-SeverityRank -Severity ([string]$f.severity)
    if ($rank -gt $maxRank) {
      $maxRank = $rank
      $maxSeverity = [string]$f.severity
    }
  }

  $deviceRiskSummaries += ,([ordered]@{
    device_id = $deviceId
    ip = [string]$device.ip
    highest_severity = $maxSeverity
    finding_count = @($deviceFindings).Count
  })
}

$criticalCount = @($findings | Where-Object { $_.severity -eq "critical" }).Count
$highCount     = @($findings | Where-Object { $_.severity -eq "high" }).Count
$mediumCount   = @($findings | Where-Object { $_.severity -eq "medium" }).Count
$lowCount      = @($findings | Where-Object { $_.severity -eq "low" }).Count

$riskDoc = [ordered]@{
  schema = "shutterwall.risk.collection.v1"
  risk_run_id = $riskRunId
  source_run_root = $RunRoot
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  source_summary_path = $SummaryPath
  count = @($findings).Count
  severity_totals = [ordered]@{
    critical = $criticalCount
    high = $highCount
    medium = $mediumCount
    low = $lowCount
  }
  device_risk_summaries = @($deviceRiskSummaries)
  findings = @($findings)
}

Write-Utf8NoBomLf -Path $RiskPath -Text (Convert-ObjectToJsonStable -InputObject $riskDoc -Depth 20)

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "risk_run_completed"
  risk_run_id = $riskRunId
  run_root = $RunRoot
  risk_path = $RiskPath
  finding_count = @($findings).Count
  critical = $criticalCount
  high = $highCount
  medium = $mediumCount
  low = $lowCount
})

Write-Host ("RISK_PATH: " + $RiskPath) -ForegroundColor Green
Write-Host ("FINDING_COUNT: " + @($findings).Count) -ForegroundColor Yellow
Write-Host ("CRITICAL: " + $criticalCount) -ForegroundColor Yellow
Write-Host ("HIGH: " + $highCount) -ForegroundColor Yellow
Write-Host ("MEDIUM: " + $mediumCount) -ForegroundColor Yellow
Write-Host ("LOW: " + $lowCount) -ForegroundColor Yellow
Write-Host "SHUTTERWALL_RISK_EVALUATE_V1_OK" -ForegroundColor Green
