param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [int]$Minutes = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$TaskName = "ShutterWall Agent Watch"
$Cli = Join-Path $RepoRoot "shutterwall.ps1"
if(-not (Test-Path -LiteralPath $Cli)){ throw "SHUTTERWALL_CLI_MISSING" }

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Cli`" watch-cycle"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Runs ShutterWall watch-cycle for local IDS monitoring." -Force | Out-Null

Write-Host ("AGENT_TASK_NAME: " + $TaskName)
Write-Host ("AGENT_INTERVAL_MINUTES: " + $Minutes)
Write-Host "SHUTTERWALL_AGENT_INSTALL_V1_OK"
