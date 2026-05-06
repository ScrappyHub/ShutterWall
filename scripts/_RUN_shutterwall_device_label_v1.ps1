param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("set","get","list","remove")]
  [string]$Mode,

  [string]$Ip,
  [string]$Name,
  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LabelRoot = Join-Path $RepoRoot "proofs\labels"
$LabelPath = Join-Path $LabelRoot "device.labels.v1.json"

if(-not (Test-Path $LabelRoot)){
  New-Item -ItemType Directory -Path $LabelRoot -Force | Out-Null
}

function Save-Store {
  param($Store,[string]$Path)
  $json = $Store | ConvertTo-Json -Depth 20
  $enc = New-Object System.Text.UTF8Encoding($false)
  $norm = ($json -replace "`r`n","`n") -replace "`r","`n"
  if(-not $norm.EndsWith("`n")){ $norm += "`n" }
  [System.IO.File]::WriteAllText($Path,$norm,$enc)
}

function New-Store {
  return [ordered]@{
    schema = "shutterwall.device.labels.v1"
    labels = [ordered]@{}
  }
}

if(Test-Path $LabelPath){
  try {
    $raw = Get-Content $LabelPath -Raw
    $parsed = $raw | ConvertFrom-Json
    $Store = New-Store

    if($parsed.labels){
      foreach($p in $parsed.labels.PSObject.Properties){
        if($p.Name -notin @("IsReadOnly","IsFixedSize","IsSynchronized","Keys","Values","SyncRoot","Count")){
          $Store.labels[$p.Name] = [string]$p.Value
        }
      }
    }
  }
  catch {
    $Store = New-Store
  }
}
else{
  $Store = New-Store
}

switch($Mode){

  "set" {
    if([string]::IsNullOrWhiteSpace($Ip)){ throw "LABEL_SET_REQUIRES_IP" }
    if([string]::IsNullOrWhiteSpace($Name)){ throw "LABEL_SET_REQUIRES_NAME" }

    $Store.labels[$Ip] = $Name
    Save-Store -Store $Store -Path $LabelPath

    Write-Host ("DEVICE_LABEL_SET :: " + $Ip + " :: " + $Name)
    Write-Host ("LABEL_STORE_PATH: " + $LabelPath)
    Write-Host "SHUTTERWALL_DEVICE_LABEL_SET_OK"
    break
  }

  "get" {
    if([string]::IsNullOrWhiteSpace($Ip)){ throw "LABEL_GET_REQUIRES_IP" }

    if($Store.labels.Contains($Ip)){
      Write-Host ("DEVICE_LABEL :: " + $Ip + " :: " + $Store.labels[$Ip])
      Write-Host "SHUTTERWALL_DEVICE_LABEL_GET_OK"
    }
    else{
      Write-Host "DEVICE_LABEL_NOT_FOUND"
    }
    break
  }

  "remove" {
    if([string]::IsNullOrWhiteSpace($Ip)){ throw "LABEL_REMOVE_REQUIRES_IP" }

    if($Store.labels.Contains($Ip)){
      $Store.labels.Remove($Ip)
      Save-Store -Store $Store -Path $LabelPath

      Write-Host ("DEVICE_LABEL_REMOVED :: " + $Ip)
      Write-Host "SHUTTERWALL_DEVICE_LABEL_REMOVE_OK"
    }
    else{
      Write-Host "DEVICE_LABEL_NOT_FOUND"
    }
    break
  }

  "list" {
    Write-Host ("LABEL_STORE_PATH: " + $LabelPath)

    foreach($p in $Store.labels.GetEnumerator()){
      Write-Host ("DEVICE_LABEL :: " + $p.Key + " :: " + $p.Value)
    }

    Write-Host "SHUTTERWALL_DEVICE_LABEL_LIST_OK"
    break
  }
}
