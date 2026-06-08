param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$Profile = "home"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$PolicyPath = Join-Path $RepoRoot "policy\scope_policy.v1.json"
$OutDir = Join-Path $RepoRoot "state\network_profiles"
$OutPath = Join-Path $OutDir "network_profile.latest.v1.json"

if(-not (Test-Path $PolicyPath)){ throw "SCOPE_POLICY_MISSING" }

$p = Get-Content $PolicyPath -Raw | ConvertFrom-Json
$scope = @($p.profiles | Where-Object { $_.name -eq $Profile }) | Select-Object -First 1
if($null -eq $scope){ throw "SCOPE_PROFILE_NOT_FOUND: $Profile" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$out = [ordered]@{
  schema = "shutterwall.network_profile.v1"
  profile = $scope.name
  network_label = $scope.network_label
  cidrs = @($scope.cidrs)
  mode = $scope.mode
  allow_remote_scan = [bool]$scope.allow_remote_scan
  generated_utc = [DateTime]::UtcNow.ToString("o")
}

($out | ConvertTo-Json -Depth 20) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("NETWORK_PROFILE_PATH: " + $OutPath)
Write-Host ("NETWORK_PROFILE: " + $scope.name)
Write-Host ("NETWORK_LABEL: " + $scope.network_label)
Write-Host "SHUTTERWALL_NETWORK_PROFILE_V1_OK"
