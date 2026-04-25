# ShutterWall Help

ShutterWall Camera CLI v0.1.0

Safe first command:
  shutterwall protect

If that command is not recognized immediately after install, either open a new PowerShell window or run:
  C:\Users\<you>\bin\shutterwall.cmd protect

What it does:
  - analyzes local camera-class / surveillance-risk devices
  - previews protection actions
  - applies firewall isolation only through explicit apply
  - restores ShutterWall firewall rules
  - writes receipts and proof outputs

Recommended flow:
  1. Open PowerShell
  2. Run: shutterwall doctor
  3. Run: shutterwall protect
  4. Review the target IPs and warnings
  5. Open PowerShell as Administrator
  6. Run: shutterwall secure-force
  7. If needed, run: shutterwall restore

Admin fallback commands:
  C:\Users\<you>\bin\shutterwall.cmd secure-force
  C:\Users\<you>\bin\shutterwall.cmd restore

Commands:
  shutterwall version
  shutterwall doctor
  shutterwall protect
  shutterwall secure-low
  shutterwall secure-enterprise
  shutterwall secure-force
  shutterwall restore

Quality check:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\dev\shutterwall\scripts\_RUN_shutterwall_full_green_v1.ps1 -RepoRoot C:\dev\shutterwall

Expected token:
  SHUTTERWALL_CAMERA_SLICE_FULL_GREEN_OK

Safety notes:
  - Do not run this on networks you do not own or manage.
  - Preview is safe.
  - Apply can block device connectivity.
  - Restore removes ShutterWall-created firewall rules.
