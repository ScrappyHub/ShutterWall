param(
  [Parameter(Position=0)]
  [string]$Command = "help",

  [Parameter(ValueFromRemainingArguments=$true)]
  [string[]]$CommandArgs,

  [string]$RepoRoot = "C:\dev\shutterwall"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$SelfPath = $MyInvocation.MyCommand.Path

function Test-IsAdministrator {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Get-ShutterWallCommandTail {
  param([object[]]$CommandArgs)

  $items = @($CommandArgs)
  if($items.Count -eq 0){ return @() }

  # Handles both shapes:
  # 1) @("trust-device","192.168.4.1","Label")
  # 2) @("192.168.4.1","Label")
  if([string]$items[0] -in @("trust-device","review-device","suspicious-device")){
    return @($items | Select-Object -Skip 1)
  }

  return @($items)
}

function Invoke-ShutterWallDeviceTrustCommand {
  param(
    [string]$Trust,
    [object[]]$CommandArgs,
    [string]$RepoRoot
  )

  $tail = @(Get-ShutterWallCommandTail -CommandArgs $CommandArgs)

  $ip = if($tail.Count -ge 1){ [string]$tail[0] } else { "" }
  $label = if($tail.Count -ge 2){ [string](@($tail | Select-Object -Skip 1) -join " ") } else { "" }

  if([string]::IsNullOrWhiteSpace($ip)){
    throw "USAGE: shutterwall <trust-device|review-device|suspicious-device> <ip> [label]"
  }

  $params = @{
    RepoRoot = $RepoRoot
    Ip = $ip
    Trust = $Trust
  }

  if(-not [string]::IsNullOrWhiteSpace($label)){
    $params["Label"] = $label
  }

  & (Join-Path $RepoRoot "scripts\_RUN_shutterwall_device_trust_v1.ps1") @params
}

function Invoke-Script {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptName,
    [string[]]$ExtraArgs = @()
  )

  $ScriptPath = Join-Path $RepoRoot $ScriptName
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){
    throw ("MISSING_SCRIPT: " + $ScriptPath)
  }

  & $PSExe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @ExtraArgs
}

function Invoke-ElevatedSelf {
  param([string]$ElevatedCommand)

  $argText = "-NoProfile -ExecutionPolicy Bypass -File `"" + $SelfPath + "`" " + $ElevatedCommand + " -RepoRoot `"" + $RepoRoot + "`""
  Write-Host ("Requesting Administrator PowerShell for: " + $ElevatedCommand) -ForegroundColor Yellow
  Start-Process -FilePath $PSExe -Verb RunAs -ArgumentList $argText
}

function Get-LatestRunRoot {
  param([string]$RepoRoot)

  $RunRoot = Join-Path $RepoRoot "proofs\runs\shutterwall"
  if(-not (Test-Path -LiteralPath $RunRoot -PathType Container)){
    throw "NO_RUNS_FOUND"
  }

  $runs = Get-ChildItem -LiteralPath $RunRoot -Directory | Sort-Object LastWriteTimeUtc -Descending
  if(-not $runs){ throw "NO_RUNS_FOUND" }

  return $runs[0].FullName
}

function Invoke-Inspect {
  Write-Host "SHUTTERWALL INSPECT" -ForegroundColor Cyan
  Write-Host "Safe inspection only. No protection plan. No firewall changes." -ForegroundColor Yellow

  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_discovery_fingerprint_v3.ps1" -ExtraArgs @(
    "-RepoRoot", $RepoRoot,
    "-StartHost", "1",
    "-EndHost", "40",
    "-ConnectTimeoutMs", "100"
  )

  Write-Host "SHUTTERWALL_INSPECT_OK" -ForegroundColor Green
}

function Invoke-Watch {
  $count = 3
  if($CommandArgs.Count -ge 1 -and -not [string]::IsNullOrWhiteSpace($CommandArgs[0])){
    $count = [int]$CommandArgs[0]
  }

  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_watch_v1.ps1" -ExtraArgs @(
    "-RepoRoot", $RepoRoot,
    "-Count", ([string]$count),
    "-IntervalSeconds", "10"
  )
}

function Invoke-ProtectionPreview {
  param([string]$PolicyProfile)

  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot

  Write-Host ("SHUTTERWALL PROTECT :: " + $PolicyProfile) -ForegroundColor Cyan
  Write-Host "Step 1/3: Analyze devices..." -ForegroundColor Cyan
  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest)

  Write-Host "Step 2/3: Build protection plan..." -ForegroundColor Cyan
  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest,"-PolicyProfile",$PolicyProfile)

  Write-Host "Step 3/3: Preview protection actions..." -ForegroundColor Cyan
  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_live_enforcement_v3.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest,"-WhatIf")

  Write-Host ""
  Write-Host "To apply protections, use: shutterwall apply" -ForegroundColor Yellow
  Write-Host "To undo ShutterWall firewall rules, use: shutterwall undo" -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_PROTECT_OK" -ForegroundColor Green
}

function Invoke-ProtectionApply {
  param([string]$PolicyProfile,[string]$ElevatedCommand)

  if(-not (Test-IsAdministrator)){
    Invoke-ElevatedSelf -ElevatedCommand $ElevatedCommand
    return
  }

  $latest = Get-LatestRunRoot -RepoRoot $RepoRoot

  Write-Host ("SHUTTERWALL APPLY :: " + $PolicyProfile) -ForegroundColor Cyan
  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_risk_evaluate_v2.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest)
  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_enforcement_plan_v4.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest,"-PolicyProfile",$PolicyProfile)
  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_live_enforcement_v3.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest,"-Apply","-Force")
}

function Invoke-Restore {
  if(-not (Test-IsAdministrator)){
    Invoke-ElevatedSelf -ElevatedCommand "undo"
    return
  }

  Invoke-Script -ScriptName "scripts\_RUN_shutterwall_restore_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-Force")
}

function Invoke-Quickstart {
  Write-Host "SHUTTERWALL QUICKSTART" -ForegroundColor Cyan
  Write-Host "1) Inspect discovers devices only." -ForegroundColor Cyan
  Invoke-Inspect

  Write-Host ""
  Write-Host "2) Scan previews home-safe protections." -ForegroundColor Cyan
  Invoke-ProtectionPreview -PolicyProfile "home_safe"

  Write-Host ""
  Write-Host "Next: run shutterwall apply to request Administrator elevation and apply home-safe protections." -ForegroundColor Yellow
  Write-Host "SHUTTERWALL_QUICKSTART_OK" -ForegroundColor Green
}

function Show-Help {
  Write-Host "ShutterWall commands:"
  Write-Host "  shutterwall quickstart                         # guided inspect + home-safe scan"
  Write-Host "  shutterwall inspect                            # safe discovery/fingerprint only"
  Write-Host "  shutterwall watch [count]                      # repeated safe device snapshots"
  Write-Host "  shutterwall watch-start                        # disabled pending v2 silent worker"
  Write-Host "  shutterwall watch-stop                         # stop quiet background monitoring"
  Write-Host "  shutterwall watch-status                       # show monitor status"
  Write-Host "  shutterwall watch-latest                       # show latest monitor state"
  Write-Host "  shutterwall baseline                           # create trusted network baseline"
  Write-Host "  shutterwall diff                               # compare current network to baseline"
  Write-Host "  shutterwall identity                           # label devices with type/confidence hints"
  Write-Host "  shutterwall label-set <ip> <name>              # set user-owned device label"
  Write-Host "  shutterwall label-list                         # list user-owned device labels"
  Write-Host "  shutterwall label-remove <ip>                  # remove user-owned device label"
  Write-Host "  shutterwall registry                           # list persistent device registry"
  Write-Host "  shutterwall registry-migrate                   # normalize persistent device registry schema"
  Write-Host "  shutterwall review                             # review remembered devices, posture, diffs, and alerts"
  Write-Host "  shutterwall trust-set <ip> <trusted|review|blocked>"
  Write-Host "  shutterwall posture                            # show protection posture and next action"
  Write-Host "  shutterwall alerts                             # show persistent alert center"
  Write-Host "  shutterwall timeline                           # update device timeline memory"
  Write-Host "  shutterwall spoof-watch                        # detect possible local spoof/drift signals"
  Write-Host "  shutterwall ids-hooks                          # run semi-active IDS-ready anomaly hooks"
  Write-Host "  shutterwall scan                               # home-safe preview"
  Write-Host "  shutterwall scan-business                      # small business preview"
  Write-Host "  shutterwall scan-enterprise                    # enterprise strict preview"
  Write-Host "  shutterwall apply                              # home-safe apply; auto-elevates"
  Write-Host "  shutterwall apply-business                     # small business apply; auto-elevates"
  Write-Host "  shutterwall apply-enterprise                   # enterprise strict apply; auto-elevates"
  Write-Host "  shutterwall undo                               # restore ShutterWall firewall rules; auto-elevates"
  Write-Host "  shutterwall doctor"
  Write-Host "  shutterwall version"
}

switch ($Command) {
  "" { Show-Help; return }
  "help" { Show-Help; return }

  "version" { Write-Host "SHUTTERWALL_VERSION: 0.3.5"; return }

  "doctor" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
    Write-Host ("LATEST_RUN_ROOT: " + $latest)
    Write-Host "SHUTTERWALL_DOCTOR_OK"
    return
  }

  "quickstart" { Invoke-Quickstart; return }
  "inspect" { Invoke-Inspect; return }

  "enroll-device" {
    if($CommandArgs.Count -lt 2){ throw "USAGE: shutterwall enroll-device <ip> [label]" }

    $ip = [string]$CommandArgs[1]
    $label = ""

    if($CommandArgs.Count -ge 3){
      $label = [string]($CommandArgs[2..($CommandArgs.Count - 1)] -join " ")
    }

    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File (Join-Path $RepoRoot "scripts\_RUN_shutterwall_enroll_device_v1.ps1") `
      -RepoRoot $RepoRoot `
      -Ip $ip `
      -Label $label

    return
  }

  "agent-status" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_agent_status_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "agent-install" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_agent_install_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "agent-remove" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_agent_remove_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "agent-enroll" {
    $label = if($CommandArgs.Count -ge 2){ $CommandArgs[1] } else { $env:COMPUTERNAME }
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_agent_enroll_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-Label",$label)
    return
  }

  "agent-heartbeat" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_agent_heartbeat_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "watch-cycle" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_watch_cycle_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "watch-start" {
    Write-Host "WATCH_DAEMON_DISABLED_PENDING_V2_SILENT_WORKER" -ForegroundColor Yellow
    return
  }

  "watch-stop" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_watch_daemon_control_v1.ps1" -ExtraArgs @("-Mode","stop","-RepoRoot",$RepoRoot)
    return
  }

  "watch-status" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_watch_daemon_control_v1.ps1" -ExtraArgs @("-Mode","status","-RepoRoot",$RepoRoot)
    return
  }

  "watch-latest" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_watch_daemon_control_v1.ps1" -ExtraArgs @("-Mode","latest","-RepoRoot",$RepoRoot)
    return
  }

  "watch" { Invoke-Watch; return }

  "baseline" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_baseline_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "diff" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_diff_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "identity" {
    $latest = Get-LatestRunRoot -RepoRoot $RepoRoot
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_identity_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot,"-RunRoot",$latest)
    return
  }

  "label-set" {
    if($CommandArgs.Count -lt 2){ throw "USAGE: shutterwall label-set <ip> <name>" }

    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_device_label_v1.ps1" -ExtraArgs @(
      "-Mode","set",
      "-Ip",([string]$CommandArgs[0]),
      "-Name",([string]($CommandArgs[1..($CommandArgs.Count-1)] -join " ")),
      "-RepoRoot",$RepoRoot
    )
    return
  }

  "label-list" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_device_label_v1.ps1" -ExtraArgs @("-Mode","list","-RepoRoot",$RepoRoot)
    return
  }

  "label-remove" {
    if($CommandArgs.Count -lt 1){ throw "USAGE: shutterwall label-remove <ip>" }

    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_device_label_v1.ps1" -ExtraArgs @(
      "-Mode","remove",
      "-Ip",([string]$CommandArgs[0]),
      "-RepoRoot",$RepoRoot
    )
    return
  }

  "correlate" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_correlation_engine_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "agent-once" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_agent_once_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "review" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_review_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "review-latest" {
    $ReviewPath = Join-Path $RepoRoot "state\review\review.latest.v1.json"
    if(-not (Test-Path -LiteralPath $ReviewPath -PathType Leaf)){
      Invoke-Script -ScriptName "scripts\_RUN_shutterwall_review_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
      return
    }

    $doc = Get-Content -LiteralPath $ReviewPath -Raw | ConvertFrom-Json
    Write-Host ("REVIEW_PATH: " + $ReviewPath)
    Write-Host ("REVIEW_POSTURE: " + $doc.posture_mode)
    Write-Host ("REVIEW_RECOMMENDED_ACTION: " + $doc.recommended_action)
    Write-Host ("REVIEW_DEVICE_COUNT: " + $doc.device_count)
    Write-Host ("REVIEW_LAST_SCANNED_UTC: " + $doc.last_scanned_utc)
    Write-Host ("REVIEW_LATEST_DIFF_PATH: " + $doc.latest_diff_path)
    Write-Host ("REVIEW_ALERT_HISTORY_COUNT: " + $doc.alert_history_count)

    foreach($d in @($doc.devices)){
      Write-Host ("REVIEW_DEVICE :: " + $d.ip + " :: " + $d.label + " :: trust=" + $d.trust_state + " :: changes=" + $d.change_count + " :: last_seen=" + $d.last_seen_utc + " :: action=" + $d.recommended_action)
    }

    Write-Host "SHUTTERWALL_REVIEW_LATEST_OK"
    return
  }

  "registry-migrate" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_registry_migrate_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "trust-device" {
    Invoke-ShutterWallDeviceTrustCommand -Trust "trusted" -CommandArgs $CommandArgs -RepoRoot $RepoRoot
    return
  }

  "review-device" {
    Invoke-ShutterWallDeviceTrustCommand -Trust "review" -CommandArgs $CommandArgs -RepoRoot $RepoRoot
    return
  }

  "suspicious-device" {
    Invoke-ShutterWallDeviceTrustCommand -Trust "suspicious" -CommandArgs $CommandArgs -RepoRoot $RepoRoot
    return
  }
  "registry" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_device_registry_v1.ps1" -ExtraArgs @("-Mode","list","-RepoRoot",$RepoRoot)
    return
  }

  "trust-set" {
    if($CommandArgs.Count -lt 2){ throw "USAGE: shutterwall trust-set <ip> <trusted|review|blocked>" }

    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_device_registry_v1.ps1" -ExtraArgs @(
      "-Mode","trust",
      "-RepoRoot",$RepoRoot,
      "-Ip",([string]$CommandArgs[0]),
      "-TrustState",([string]$CommandArgs[1])
    )
    return
  }

  "timeline" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_device_timeline_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "ids-hooks" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_ids_hooks_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "spoof-watch" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_spoof_watch_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "alerts" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_alert_center_v1.ps1" -ExtraArgs @("-Mode","list","-RepoRoot",$RepoRoot)
    return
  }

  "scope" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_scope_policy_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "network-profile" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_network_profile_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "service-baseline" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_service_baseline_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "service-drift" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_service_drift_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "service-promote" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_promote_service_profile_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "service-classify" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_service_classifier_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "lab-scan" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_lab_scan_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "posture" {
    Invoke-Script -ScriptName "scripts\_RUN_shutterwall_posture_v1.ps1" -ExtraArgs @("-RepoRoot",$RepoRoot)
    return
  }

  "scan" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "protect" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "secure-low" { Invoke-ProtectionPreview -PolicyProfile "home_safe"; return }
  "scan-business" { Invoke-ProtectionPreview -PolicyProfile "smallbiz_balanced"; return }
  "scan-enterprise" { Invoke-ProtectionPreview -PolicyProfile "enterprise_strict"; return }

  "apply" { Invoke-ProtectionApply -PolicyProfile "home_safe" -ElevatedCommand "apply"; return }
  "apply-business" { Invoke-ProtectionApply -PolicyProfile "smallbiz_balanced" -ElevatedCommand "apply-business"; return }
  "apply-enterprise" { Invoke-ProtectionApply -PolicyProfile "enterprise_strict" -ElevatedCommand "apply-enterprise"; return }
  "secure-force" { Invoke-ProtectionApply -PolicyProfile "enterprise_strict" -ElevatedCommand "secure-force"; return }

  "undo" { Invoke-Restore; return }
  "restore" { Invoke-Restore; return }

  default {
    Write-Host "UNKNOWN_COMMAND"
    Write-Host "Run: shutterwall help"
    return
  }
}









