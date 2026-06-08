param(
  [string]$RepoRoot = "C:\dev\shutterwall",
  [string]$Profile = "home",
  [string]$TargetPrefix = "192.168.4",
  [string]$HostRange = "1-40",
  [string]$Ports = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

$PolicyPath = Join-Path $RepoRoot "policy\scope_policy.v1.json"
$OutRoot = Join-Path $RepoRoot "proofs\runs\shutterwall_lab_scan"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

$p = Get-Content $PolicyPath -Raw | ConvertFrom-Json
$scope = @($p.profiles | Where-Object { $_.name -eq $Profile }) | Select-Object -First 1
if($null -eq $scope){ throw "SCOPE_PROFILE_NOT_FOUND: $Profile" }

if(-not [bool]$scope.allow_remote_scan){
  throw "REMOTE_SCAN_NOT_ALLOWED_FOR_SCOPE: $Profile"
}

$portList = @()
if([string]::IsNullOrWhiteSpace($Ports)){
  $portList = @($scope.default_ports | ForEach-Object { [int]$_ })
} else {
  $portList = @($Ports.Split(",") | ForEach-Object { [int]$_.Trim() })
}

$parts = $HostRange.Split("-")
$start = [int]$parts[0]
$end = [int]$parts[1]

$runId = [Guid]::NewGuid().ToString("N")
$RunRoot = Join-Path $OutRoot $runId
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

$results = @()

foreach($i in $start..$end){
  $ip = "$TargetPrefix.$i"
  foreach($port in $portList){
    $open = $false
    try {
      $client = New-Object Net.Sockets.TcpClient
      $iar = $client.BeginConnect($ip,$port,$null,$null)
      $ok = $iar.AsyncWaitHandle.WaitOne(350,$false)
      if($ok -and $client.Connected){ $open = $true }
      $client.Close()
    } catch {}

    if($open){
      $results += [ordered]@{
        ip = $ip
        port = $port
        state = "open"
        probe = "tcp_connect"
      }
      Write-Host ("LAB_SCAN_OPEN :: " + $ip + ":" + $port)
    }
  }
}

$out = [ordered]@{
  schema = "shutterwall.lab_scan.v1"
  run_id = $runId
  profile = $Profile
  target_prefix = $TargetPrefix
  host_range = $HostRange
  ports = @($portList)
  result_count = @($results).Count
  results = @($results)
  generated_utc = [DateTime]::UtcNow.ToString("o")
  safety = "connect_only_no_exploit_no_stealth"
}

$OutPath = Join-Path $RunRoot "lab_scan.results.v1.json"
($out | ConvertTo-Json -Depth 30) | Set-Content -Encoding UTF8 $OutPath

Write-Host ("LAB_SCAN_PATH: " + $OutPath)
Write-Host ("LAB_SCAN_RESULT_COUNT: " + @($results).Count)
Write-Host "SHUTTERWALL_LAB_SCAN_V1_OK"
