param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$AgentPath = Join-Path $RepoRoot "state\agents\local_agent.v1.json"
$OutDir = Join-Path $RepoRoot "state\heartbeats"
$OutPath = Join-Path $OutDir "heartbeat.latest.v1.json"

if(-not (Test-Path -LiteralPath $AgentPath)){ throw "AGENT_NOT_ENROLLED" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$agent = Get-Content -LiteralPath $AgentPath -Raw | ConvertFrom-Json

$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
  Select-Object -ExpandProperty IPAddress)

$out = [ordered]@{
  schema = "shutterwall.agent.heartbeat.v1"
  generated_utc = [DateTime]::UtcNow.ToString("o")
  device_id = [string]$agent.device_id
  label = [string]$agent.label
  hostname = $env:COMPUTERNAME
  username = $env:USERNAME
  ipv4 = @($ips)
  mode = [string]$agent.mode
  ips_enabled = [bool]$agent.ips_enabled
  auto_block_enabled = [bool]$agent.auto_block_enabled
}

($out | ConvertTo-Json -Depth 20) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("HEARTBEAT_PATH: " + $OutPath)
Write-Host ("HEARTBEAT_DEVICE_ID: " + $out.device_id)
Write-Host ("HEARTBEAT_IPV4: " + (@($ips) -join ","))
Write-Host "SHUTTERWALL_AGENT_HEARTBEAT_V1_OK"
