param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$SubnetPrefix,
  [Parameter(Mandatory=$false)][int]$StartHost = 1,
  [Parameter(Mandatory=$false)][int]$EndHost = 40,
  [Parameter(Mandatory=$false)][switch]$ActiveSweep,
  [Parameter(Mandatory=$false)][int]$ConnectTimeoutMs = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Utf8NoBomLf {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Text
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    [void](New-Item -ItemType Directory -Path $dir -Force)
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if (-not $norm.EndsWith("`n")) { $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function Get-Sha256HexFromBytes {
  param([byte[]]$Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($Bytes)
  }
  finally {
    $sha.Dispose()
  }
  (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-Sha256HexFromText {
  param([string]$Text)
  $enc = New-Object System.Text.UTF8Encoding($false)
  [byte[]]$bytes = $enc.GetBytes([string]$Text)
  Get-Sha256HexFromBytes -Bytes $bytes
}

function Convert-ObjectToJsonStable {
  param(
    [Parameter(Mandatory=$true)]$InputObject,
    [Parameter(Mandatory=$false)][int]$Depth = 12
  )
  ($InputObject | ConvertTo-Json -Depth $Depth)
}

function Append-NdjsonLine {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Object
  )

  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    [void](New-Item -ItemType Directory -Path $dir -Force)
  }

  $line = Convert-ObjectToJsonStable -InputObject $Object -Depth 12
  $normalized = ($line -replace "`r`n","`n") -replace "`r","`n"

  $enc = New-Object System.Text.UTF8Encoding($false)
  [byte[]]$bytes = $enc.GetBytes([string]$normalized)

  $fs = [System.IO.File]::Open(
    $Path,
    [System.IO.FileMode]::Append,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::Read
  )
  try {
    $fs.Write($bytes, 0, $bytes.Length)
    $fs.WriteByte([byte]10)
  }
  finally {
    $fs.Dispose()
  }
}

function Parse-GateFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if ($errors -and $errors.Count -gt 0) {
    $e = $errors[0]
    throw ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function Get-DefaultSubnetPrefix {
  $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.IPAddress -notlike '169.254*' -and
      $_.IPAddress -ne '127.0.0.1' -and
      $_.PrefixLength -le 30 -and
      $_.InterfaceAlias -notmatch 'Loopback|vEthernet|WSL'
    } |
    Sort-Object InterfaceMetric, SkipAsSource, PrefixLength)

  if (@($ips).Count -lt 1) {
    throw "NO_ACTIVE_IPV4_FOUND"
  }

  $ip = $ips[0].IPAddress
  if ($ip -notmatch '^(\d+\.\d+\.\d+)\.\d+$') {
    throw ("UNSUPPORTED_IPV4_FOR_PREFIX: " + $ip)
  }

  $Matches[1]
}

function Test-TcpPort {
  param(
    [Parameter(Mandatory=$true)][string]$Address,
    [Parameter(Mandatory=$true)][int]$Port,
    [Parameter(Mandatory=$true)][int]$TimeoutMs
  )

  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $client.BeginConnect($Address, $Port, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
    if (-not $ok) {
      try { $client.Close() } catch {}
      return $false
    }
    $client.EndConnect($iar) | Out-Null
    return $true
  }
  catch {
    return $false
  }
  finally {
    try { $client.Close() } catch {}
  }
}

function Get-ReverseDnsName {
  param([Parameter(Mandatory=$true)][string]$Ip)
  $null
}

function Get-MacAddressForIp {
  param([Parameter(Mandatory=$true)][string]$Ip)
  try {
    $n = Get-NetNeighbor -IPAddress $Ip -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($n -and $n.LinkLayerAddress) { return $n.LinkLayerAddress.ToUpperInvariant() }
  }
  catch {}
  $null
}

function Get-DiscoveryCandidates {
  param(
    [Parameter(Mandatory=$true)][string]$SubnetPrefix,
    [Parameter(Mandatory=$true)][int]$StartHost,
    [Parameter(Mandatory=$true)][int]$EndHost,
    [Parameter(Mandatory=$true)][bool]$DoActiveSweep
  )

  $map = @{}

  try {
    $neighbors = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object {
      $_.IPAddress -like ($SubnetPrefix + '.*') -and
      $_.IPAddress -notlike '169.254*' -and
      $_.IPAddress -ne '127.0.0.1'
    })

    foreach ($n in $neighbors) {
      if ($n.IPAddress -match '^\d+\.\d+\.\d+\.(\d+)$') {
        $hostNum = [int]$Matches[1]
        if ($hostNum -ge $StartHost -and $hostNum -le $EndHost) {
          $map[$n.IPAddress] = $true
        }
      }
    }
  }
  catch {}

  if ($DoActiveSweep) {
    for ($i = $StartHost; $i -le $EndHost; $i++) {
      $ip = $SubnetPrefix + "." + $i
      try {
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) {
          $map[$ip] = $true
        }
      }
      catch {}
    }
  }

  @($map.Keys | Sort-Object)
}

function Get-CameraLikelihood {
  param(
    [Parameter(Mandatory=$true)][string]$Ip,
    [Parameter(Mandatory=$false)][AllowNull()][string]$Hostname,
    [Parameter(Mandatory=$false)][int[]]$OpenPorts = @()
  )

  [int[]]$ports = @($OpenPorts)
  $score = 0
  $reasons = New-Object System.Collections.Generic.List[string]

  if ($ports -contains 554) {
    $score += 4
    [void]$reasons.Add("rtsp_port_554_open")
  }
  if ($ports -contains 8000) {
    $score += 2
    [void]$reasons.Add("common_camera_mgmt_port_8000_open")
  }
  if ($ports -contains 8080 -or $ports -contains 8443) {
    $score += 1
    [void]$reasons.Add("alternate_admin_port_open")
  }
  if ($Hostname) {
    $hn = $Hostname.ToLowerInvariant()
    if ($hn -match 'cam|camera|dvr|nvr|ipc|hik|dahua|wyze|ring|nest|arlo|reolink|amcrest|axis|unifi') {
      $score += 3
      [void]$reasons.Add("camera_like_hostname")
    }
  }

  $level = "unlikely"
  if ($score -ge 6) { $level = "probable_camera" }
  elseif ($score -ge 3) { $level = "possible_camera" }

  [ordered]@{
    level = $level
    score = $score
    reasons = @($reasons)
  }
}

function Get-VendorGuess {
  param(
    [Parameter(Mandatory=$false)][AllowNull()][string]$Hostname,
    [Parameter(Mandatory=$false)][int[]]$OpenPorts = @()
  )

  [int[]]$ports = @($OpenPorts)
  if (-not $Hostname) { $Hostname = "" }
  $hn = $Hostname.ToLowerInvariant()

  if ($hn -match 'hik') { return "hikvision_like" }
  if ($hn -match 'dahua') { return "dahua_like" }
  if ($hn -match 'wyze') { return "wyze_like" }
  if ($hn -match 'ring') { return "ring_like" }
  if ($hn -match 'nest') { return "nest_like" }
  if ($hn -match 'arlo') { return "arlo_like" }
  if ($hn -match 'reolink') { return "reolink_like" }
  if ($hn -match 'amcrest') { return "amcrest_like" }
  if ($hn -match 'axis') { return "axis_like" }
  if ($hn -match 'unifi|ubnt') { return "ubiquiti_like" }

  if ($ports -contains 554 -and $ports -contains 8000) {
    return "camera_vendor_unknown_rtsp_admin_like"
  }
  if ($ports -contains 554) {
    return "camera_vendor_unknown_rtsp_like"
  }

  "unknown"
}

function New-RunId {
  $raw = [ordered]@{
    ts_utc = [DateTime]::UtcNow.ToString("o")
    machine = $env:COMPUTERNAME
    pid = $PID
    repo = $RepoRoot
  }
  $json = Convert-ObjectToJsonStable -InputObject $raw -Depth 6
  Get-Sha256HexFromText -Text $json
}

$ScriptSelf = $MyInvocation.MyCommand.Path
Parse-GateFile -Path $ScriptSelf

if (-not (Test-Path -LiteralPath $RepoRoot)) {
  throw ("REPO_ROOT_MISSING: " + $RepoRoot)
}

if (-not $SubnetPrefix) {
  $SubnetPrefix = Get-DefaultSubnetPrefix
}

$RunId = New-RunId
$RunRoot = Join-Path $RepoRoot ("proofs\runs\shutterwall\" + $RunId)
$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\shutterwall.ndjson"
$DevicesPath = Join-Path $RunRoot "devices.discovery.v1.json"
$FingerprintsPath = Join-Path $RunRoot "devices.fingerprint.v1.json"
$SummaryPath = Join-Path $RunRoot "run.summary.json"

[void](New-Item -ItemType Directory -Path $RunRoot -Force)

Write-Host ("RUN_START: " + $RunId) -ForegroundColor Cyan
Write-Host ("SUBNET_PREFIX: " + $SubnetPrefix) -ForegroundColor Cyan
Write-Host ("ACTIVE_SWEEP: " + [bool]$ActiveSweep) -ForegroundColor Cyan
Write-Host ("HOST_RANGE: " + $StartHost + "-" + $EndHost) -ForegroundColor Cyan

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "run_started"
  run_id = $RunId
  subnet_prefix = $SubnetPrefix
  active_sweep = [bool]$ActiveSweep
  start_host = $StartHost
  end_host = $EndHost
})

$candidates = @(Get-DiscoveryCandidates -SubnetPrefix $SubnetPrefix -StartHost $StartHost -EndHost $EndHost -DoActiveSweep ([bool]$ActiveSweep))
Write-Host ("DISCOVERY_CANDIDATES: " + @($candidates).Count) -ForegroundColor Yellow

$portPlan = @(80,443,554,8000,8080,8443)
$devices = @()
$fingerprints = @()

foreach ($ip in $candidates) {
  Write-Host ("CHECKING_IP: " + $ip) -ForegroundColor DarkCyan

  $hostname = Get-ReverseDnsName -Ip $ip
  $mac = Get-MacAddressForIp -Ip $ip

  $openPorts = @()
  foreach ($port in $portPlan) {
    $open = Test-TcpPort -Address $ip -Port $port -TimeoutMs $ConnectTimeoutMs
    if ($open) {
      $openPorts += [int]$port
    }
  }

  [int[]]$openPortsArr = @($openPorts)
  $likelihood = Get-CameraLikelihood -Ip $ip -Hostname $hostname -OpenPorts $openPortsArr
  $vendorGuess = Get-VendorGuess -Hostname $hostname -OpenPorts $openPortsArr

  $deviceSeed = [ordered]@{
    ip = [string]$ip
    mac = $mac
    hostname = $hostname
  }
  $deviceId = Get-Sha256HexFromText -Text (Convert-ObjectToJsonStable -InputObject $deviceSeed -Depth 6)

  $deviceObj = [ordered]@{
    schema = "device.discovery.v1"
    device_id = $deviceId
    ip = [string]$ip
    mac = $mac
    hostname = $hostname
    vendor_guess = [string]$vendorGuess
    camera_likelihood = [string]$likelihood.level
    camera_likelihood_score = [int]$likelihood.score
    camera_reasons = @($likelihood.reasons)
    first_seen_utc = [DateTime]::UtcNow.ToString("o")
    last_seen_utc = [DateTime]::UtcNow.ToString("o")
  }

  $fpObj = [ordered]@{
    schema = "device.fingerprint.v1"
    device_id = $deviceId
    ip = [string]$ip
    probable_vendor = [string]$vendorGuess
    probable_model = $null
    open_tcp_ports = @($openPortsArr)
    exposed_services = @(
      foreach ($p in $openPortsArr) {
        switch ([int]$p) {
          80   { "http_admin_or_web" }
          443  { "https_admin_or_web" }
          554  { "rtsp_stream" }
          8000 { "camera_mgmt_alt" }
          8080 { "alt_http_admin" }
          8443 { "alt_https_admin" }
          default { "unknown" }
        }
      }
    )
    auth_surface = @(
      if ($openPortsArr -contains 80 -or $openPortsArr -contains 443 -or $openPortsArr -contains 8080 -or $openPortsArr -contains 8443) { "web_auth_possible" }
      if ($openPortsArr -contains 554) { "rtsp_auth_or_open_stream_possible" }
    )
    remote_access_indicators = @(
      if ($openPortsArr -contains 554) { "local_stream_surface_present" }
      if ($openPortsArr -contains 80 -or $openPortsArr -contains 443 -or $openPortsArr -contains 8080 -or $openPortsArr -contains 8443) { "local_admin_surface_present" }
    )
    cloud_dependency_level = "unknown"
    confidence = if ($likelihood.level -eq "probable_camera") { "medium" } elseif ($likelihood.level -eq "possible_camera") { "low" } else { "low" }
  }

  $devices += ,$deviceObj
  $fingerprints += ,$fpObj

  Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
    ts_utc = [DateTime]::UtcNow.ToString("o")
    schema = "shutterwall.receipt.v1"
    event = "device_observed"
    run_id = $RunId
    device_id = $deviceId
    ip = [string]$ip
    hostname = $hostname
    open_tcp_ports = @($openPortsArr)
    camera_likelihood = [string]$likelihood.level
    vendor_guess = [string]$vendorGuess
  })
}

$cameraLikeDevices = @($devices | Where-Object {
  $_.camera_likelihood -eq "probable_camera" -or $_.camera_likelihood -eq "possible_camera"
})

[int]$deviceCount = @($devices).Count
[int]$fingerprintCount = @($fingerprints).Count
[int]$cameraLikeCount = @($cameraLikeDevices).Count

$devicesDoc = [ordered]@{
  schema = "shutterwall.discovery.collection.v1"
  run_id = $RunId
  subnet_prefix = $SubnetPrefix
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  count = $deviceCount
  devices = @($devices)
}

$fingerprintsDoc = [ordered]@{
  schema = "shutterwall.fingerprint.collection.v1"
  run_id = $RunId
  subnet_prefix = $SubnetPrefix
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  count = $fingerprintCount
  fingerprints = @($fingerprints)
}

$summary = [ordered]@{
  schema = "shutterwall.run.summary.v1"
  run_id = $RunId
  subnet_prefix = $SubnetPrefix
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  candidate_hosts = $deviceCount
  camera_like_hosts = $cameraLikeCount
  receipt_path = $ReceiptPath
  devices_path = $DevicesPath
  fingerprints_path = $FingerprintsPath
}

Write-Utf8NoBomLf -Path $DevicesPath -Text (Convert-ObjectToJsonStable -InputObject $devicesDoc -Depth 12)
Write-Utf8NoBomLf -Path $FingerprintsPath -Text (Convert-ObjectToJsonStable -InputObject $fingerprintsDoc -Depth 12)
Write-Utf8NoBomLf -Path $SummaryPath -Text (Convert-ObjectToJsonStable -InputObject $summary -Depth 10)

Append-NdjsonLine -Path $ReceiptPath -Object ([ordered]@{
  ts_utc = [DateTime]::UtcNow.ToString("o")
  schema = "shutterwall.receipt.v1"
  event = "run_completed"
  run_id = $RunId
  candidate_hosts = $deviceCount
  camera_like_hosts = $cameraLikeCount
  run_root = $RunRoot
})

Write-Host ("RUN_ID: " + $RunId) -ForegroundColor Cyan
Write-Host ("RUN_ROOT: " + $RunRoot) -ForegroundColor Cyan
Write-Host ("SUBNET_PREFIX: " + $SubnetPrefix) -ForegroundColor Cyan
Write-Host ("CANDIDATE_HOSTS: " + $deviceCount) -ForegroundColor Yellow
Write-Host ("CAMERA_LIKE_HOSTS: " + $cameraLikeCount) -ForegroundColor Yellow
Write-Host ("DEVICES_JSON: " + $DevicesPath) -ForegroundColor Green
Write-Host ("FINGERPRINTS_JSON: " + $FingerprintsPath) -ForegroundColor Green
Write-Host ("SUMMARY_JSON: " + $SummaryPath) -ForegroundColor Green
Write-Host ("RECEIPTS_NDJSON: " + $ReceiptPath) -ForegroundColor Green
Write-Host "SHUTTERWALL_DISCOVERY_FINGERPRINT_V3_OK" -ForegroundColor Green
