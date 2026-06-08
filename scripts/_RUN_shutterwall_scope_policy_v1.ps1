param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$Path = Join-Path $RepoRoot "policy\scope_policy.v1.json"
if(-not (Test-Path $Path)){ throw "SCOPE_POLICY_MISSING" }

$p = Get-Content $Path -Raw | ConvertFrom-Json

Write-Host ("SCOPE_POLICY_PATH: " + $Path)
foreach($s in @($p.profiles)){
  Write-Host ("SCOPE_PROFILE :: " + $s.name + " :: " + $s.network_label + " :: remote=" + $s.allow_remote_scan + " :: cidrs=" + (@($s.cidrs) -join ","))
}
Write-Host "SHUTTERWALL_SCOPE_POLICY_V1_OK"
