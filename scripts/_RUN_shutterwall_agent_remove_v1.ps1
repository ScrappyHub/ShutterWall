param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$TaskName = "ShutterWall Agent Watch"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if($null -ne $task){
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host ("AGENT_TASK_REMOVED: " + $TaskName)
} else {
  Write-Host ("AGENT_TASK_NOT_FOUND: " + $TaskName)
}

Write-Host "SHUTTERWALL_AGENT_REMOVE_V1_OK"
