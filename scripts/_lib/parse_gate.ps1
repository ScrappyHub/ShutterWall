param([Parameter(Mandatory=$true)][string]$Path)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$tok = $null
$err = $null

[void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tok,[ref]$err)

if($err -and $err.Count -gt 0){
  $e = $err[0]
  throw ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
}

Write-Host ("PARSE_OK: " + $Path) -ForegroundColor Green