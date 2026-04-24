param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Append-NdjsonLine {
  param([string]$Path,$Object)
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
  $line = ($Object | ConvertTo-Json -Depth 20)
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::AppendAllText($Path, (($line -replace "`r`n","`n") -replace "`r","`n") + "`n", $enc)
}

function Test-IsAdministrator {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) { throw "ADMIN_REQUIRED_FOR_RESTORE" }

$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
  $_.DisplayName -like "ShutterWall V3*"
})

Write-Host "=== SHUTTERWALL RESTORE PREVIEW ===" -ForegroundColor Yellow
Write-Host ("RULES_FOUND: " + @($rules).Count) -ForegroundColor Yellow
foreach($r in $rules){ Write-Host ("RESTORE_TARGET: " + $r.DisplayName) -ForegroundColor DarkCyan }

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "restore_preview"
  rule_count = @($rules).Count
  rule_names = @($rules | ForEach-Object { $_.DisplayName })
})

if (-not $Force) {
  $resp = Read-Host "Type RESTORE to remove ShutterWall firewall rules"
  if ($resp -ne "RESTORE") {
    Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
      ts_utc = [DateTime]::UtcNow.ToString("o")
      schema = "shutterwall.receipt.v1"
      event = "restore_cancelled_by_user"
      rule_count = @($rules).Count
    })
    Write-Host "RESTORE_CANCELLED_BY_USER" -ForegroundColor Yellow
    return
  }
}

$removed = 0
foreach($r in $rules){
  Remove-NetFirewallRule -Name $r.Name
  $removed++
  Write-Host ("REMOVED: " + $r.DisplayName) -ForegroundColor Yellow
}

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "restore_completed"
  removed = $removed
})

Write-Host ("REMOVED: " + $removed) -ForegroundColor Green
Write-Host "SHUTTERWALL_RESTORE_V1_OK" -ForegroundColor Green
