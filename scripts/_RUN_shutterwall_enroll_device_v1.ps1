param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$Label = $env:COMPUTERNAME
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$OutDir = Join-Path $RepoRoot "state\agent"
$OutPath = Join-Path $OutDir "agent.registration.v1.json"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$machine = [ordered]@{
  schema = "shutterwall.agent.registration.v1"
  device_label = $Label
  computer_name = $env:COMPUTERNAME
  user_name = $env:USERNAME
  os = (Get-CimInstance Win32_OperatingSystem).Caption
  repo_root = $RepoRoot
  mode = "ids_observe_review_first"
  enrolled_utc = [DateTime]::UtcNow.ToString("o")
  ips_enabled = $false
  auto_block_enabled = $false
  watch_command = "shutterwall watch-cycle"
}

($machine | ConvertTo-Json -Depth 20) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("AGENT_REGISTRATION_PATH: " + $OutPath)
Write-Host ("AGENT_DEVICE_LABEL: " + $Label)
Write-Host "SHUTTERWALL_AGENT_ENROLL_V1_OK"
