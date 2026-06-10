param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$Label = $env:COMPUTERNAME
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$OutDir = Join-Path $RepoRoot "state\agents"
$OutPath = Join-Path $OutDir "local_agent.v1.json"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$deviceId = [Guid]::NewGuid().ToString("N")

$out = [ordered]@{
  schema = "shutterwall.agent.enrollment.v1"
  device_id = $deviceId
  label = $Label
  hostname = $env:COMPUTERNAME
  username = $env:USERNAME
  enrolled_utc = [DateTime]::UtcNow.ToString("o")
  mode = "ids_observe_review_first"
  ips_enabled = $false
  auto_block_enabled = $false
}

($out | ConvertTo-Json -Depth 20) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("AGENT_ENROLLMENT_PATH: " + $OutPath)
Write-Host ("AGENT_DEVICE_ID: " + $deviceId)
Write-Host ("AGENT_LABEL: " + $Label)
Write-Host "SHUTTERWALL_AGENT_ENROLL_V1_OK"
