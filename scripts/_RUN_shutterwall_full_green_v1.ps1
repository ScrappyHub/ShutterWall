param(
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$ProofRoot = Join-Path $RepoRoot ("proofs\full_green\shutterwall_camera_slice_" + $RunId)
New-Item -ItemType Directory -Path $ProofRoot -Force | Out-Null

function Parse-GateFile {
  param([string]$Path)
  $tok=$null;$err=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)
  if($err -and $err.Count -gt 0){ throw $err[0].ToString() }
}

function Run-Step {
  param(
    [string]$Name,
    [string[]]$ChildArgs,
    [string]$RequiredToken,
    [int]$TimeoutSeconds = 90
  )

  Write-Host ("RUN_STEP: " + $Name) -ForegroundColor Cyan

  $out = Join-Path $ProofRoot ($Name + ".stdout.txt")
  $err = Join-Path $ProofRoot ($Name + ".stderr.txt")

  $cleanArgs = @($ChildArgs | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

  $p = Start-Process -FilePath $PSExe `
    -ArgumentList $cleanArgs `
    -Wait:$false `
    -PassThru `
    -RedirectStandardOutput $out `
    -RedirectStandardError $err

  $done = $p.WaitForExit($TimeoutSeconds * 1000)
  if(-not $done){
    try { $p.Kill() } catch {}
    throw ("STEP_TIMEOUT: " + $Name)
  }

  $stdout = [System.IO.File]::ReadAllText($out)
  $stderr = [System.IO.File]::ReadAllText($err)

  $exitCode = 0
  if($null -ne $exitCode){ $exitCode = [int]$p.ExitCode }
  if($exitCode -ne 0){
    Write-Host $stdout
    Write-Host $stderr
    throw ("STEP_FAILED_EXITCODE: " + $Name + " :: " + $exitCode)
  }

  if($RequiredToken -and -not $stdout.Contains($RequiredToken)){
    Write-Host $stdout
    throw ("STEP_TOKEN_MISSING: " + $Name + " :: " + $RequiredToken)
  }

  Write-Host ("STEP_OK: " + $Name) -ForegroundColor Green
}

$Scripts = @(
  "shutterwall.ps1",
  "inspect_shutterwall.ps1",
  "analyze_confirmed_camera.ps1",
  "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1",
  "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1",
  "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1",
  "scripts\_RUN_shutterwall_live_enforcement_v3.ps1",
  "scripts\_RUN_shutterwall_restore_v1.ps1",
  "scripts\_RUN_shutterwall_operator_review_v1.ps1"
)

foreach($rel in $Scripts){
  $path = Join-Path $RepoRoot $rel
  if(-not (Test-Path $path)){ throw ("SCRIPT_MISSING: " + $rel) }
  Parse-GateFile $path
}

Write-Host "PARSE_GATE_ALL_OK" -ForegroundColor Green

Run-Step -Name "version" -ChildArgs @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "shutterwall.ps1"),"version") -RequiredToken "SHUTTERWALL_VERSION"
Run-Step -Name "doctor" -ChildArgs @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "shutterwall.ps1"),"doctor") -RequiredToken "SHUTTERWALL_DOCTOR_OK"
Run-Step -Name "protect" -ChildArgs @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "shutterwall.ps1"),"protect") -RequiredToken "SHUTTERWALL_PROTECT_OK"
Run-Step -Name "secure_low" -ChildArgs @("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $RepoRoot "shutterwall.ps1"),"secure-low") -RequiredToken "SHUTTERWALL_LIVE_ENFORCEMENT_V3_OK"

$hashFile = Join-Path $ProofRoot "sha256sums.txt"
$lines = New-Object System.Collections.ArrayList

foreach($rel in $Scripts){
  $path = Join-Path $RepoRoot $rel
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
  $hex = (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
  [void]$lines.Add(($hex + "  " + $rel.Replace("\","/")))
}

[System.IO.File]::WriteAllText($hashFile, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("FULL_GREEN_PROOF_ROOT: " + $ProofRoot) -ForegroundColor Cyan
Write-Host "SHUTTERWALL_CAMERA_SLICE_FULL_GREEN_OK" -ForegroundColor Green
