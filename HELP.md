# ShutterWall Help

ShutterWall Camera CLI v0.1.0

Safe first command:
  shutterwall scan

Policy tiers:
  home_safe: low findings stay monitor/preview-first
  smallbiz_balanced: stronger review posture for small businesses
  enterprise_strict: aggressive quarantine planning for unmanaged/weakly understood devices

Recommended home flow:
  1. shutterwall doctor
  2. shutterwall scan
  3. Review target IPs and warnings
  4. Open PowerShell as Administrator
  5. shutterwall apply
  6. If needed: shutterwall undo

Business flow:
  1. shutterwall scan-business
  2. Administrator: shutterwall apply-business
  3. If needed: shutterwall undo

Enterprise strict flow:
  1. shutterwall scan-enterprise
  2. Administrator: shutterwall apply-enterprise
  3. If needed: shutterwall undo

Compatibility aliases:
  shutterwall protect = shutterwall scan
  shutterwall secure-force = shutterwall apply-enterprise
  shutterwall restore = shutterwall undo

Direct fallback if PATH has not refreshed:
  C:\Users\<you>\bin\shutterwall.cmd scan

Quality check:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\dev\shutterwall\scripts\_RUN_shutterwall_full_green_v1.ps1 -RepoRoot C:\dev\shutterwall

Expected token:
  SHUTTERWALL_CAMERA_SLICE_FULL_GREEN_OK

Safety notes:
  - Do not run this on networks you do not own or manage.
  - Preview is safe.
  - Apply can block device connectivity.
  - Restore/undo removes ShutterWall-created firewall rules.
