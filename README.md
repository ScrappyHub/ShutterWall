# ShutterWall

ShutterWall is a deterministic local network protection instrument focused first on camera-class and surveillance-risk devices.

## Current camera slice

- discovery + fingerprint
- risk evaluation (v2)
- enforcement plan (v4)
- live enforcement (v3)
- restore
- CLI protect flow

## Commands

shutterwall version
shutterwall doctor
shutterwall protect
shutterwall secure-low
shutterwall secure-force
shutterwall restore

## Flow

protect -> preview -> secure-force -> restore
