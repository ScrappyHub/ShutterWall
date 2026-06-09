param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$ServicePath = Join-Path $RepoRoot "state\service_profiles\service_profile.latest.v1.json"
$OutDir = Join-Path $RepoRoot "state\service_baseline"
$OutPath = Join-Path $OutDir "service_baseline.v1.json"

if(-not (Test-Path -LiteralPath $ServicePath)){ throw "SERVICE_PROFILE_MISSING" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$svc = Get-Content -LiteralPath $ServicePath -Raw | ConvertFrom-Json

$out = [ordered]@{
  schema = "shutterwall.service_baseline.v1"
  created_utc = [DateTime]::UtcNow.ToString("o")
  source_service_profile = $ServicePath
  profiles = @($svc.profiles)
}

($out | ConvertTo-Json -Depth 80) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("SERVICE_BASELINE_PATH: " + $OutPath)
Write-Host ("SERVICE_BASELINE_PROFILE_COUNT: " + @($svc.profiles).Count)
Write-Host "SHUTTERWALL_SERVICE_BASELINE_V1_OK"
