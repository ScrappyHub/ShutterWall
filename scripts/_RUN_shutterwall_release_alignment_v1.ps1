param()
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = "C:\dev\shutterwall"
Set-Location $RepoRoot

$PSExe = (Get-Command powershell.exe -ErrorAction Stop).Source
$Cli = Join-Path $RepoRoot "shutterwall.ps1"

function Invoke-ShutterWall {
  param([string[]]$CommandArgs)

  Write-Host ("RUNNING :: shutterwall " + ($CommandArgs -join " ")) -ForegroundColor Cyan

  $ArgList = @(
    "-NoProfile"
    "-ExecutionPolicy"
    "Bypass"
    "-File"
    $Cli
  ) + $CommandArgs

  & $PSExe @ArgList

  if($LASTEXITCODE -ne 0){
    throw ("SHUTTERWALL_COMMAND_FAILED :: " + ($CommandArgs -join " "))
  }
}

Write-Host "=== SHUTTERWALL RELEASE ALIGNMENT START ===" -ForegroundColor Green

# Discovery + identity
Invoke-ShutterWall -CommandArgs @("quickstart")
Invoke-ShutterWall -CommandArgs @("identity")

# Registry + review
Invoke-ShutterWall -CommandArgs @("registry")
Invoke-ShutterWall -CommandArgs @("registry-migrate")
Invoke-ShutterWall -CommandArgs @("timeline")
Invoke-ShutterWall -CommandArgs @("review")

# Alert + posture
Invoke-ShutterWall -CommandArgs @("alerts")
Invoke-ShutterWall -CommandArgs @("spoof-watch")
Invoke-ShutterWall -CommandArgs @("ids-hooks")
Invoke-ShutterWall -CommandArgs @("posture")

# Watch daemon
Invoke-ShutterWall -CommandArgs @("watch-cycle")
Invoke-ShutterWall -CommandArgs @("watch-start")

Write-Host ""
Write-Host "SHUTTERWALL_RELEASE_ALIGNMENT_OK" -ForegroundColor Green

