# Ecosystem Integration — ShutterWall

## Canonical service identity

| Field | Value |
|---|---|
| Service ID | `shutterwall` |
| Canonical name | ShutterWall |
| Ecosystem layer | `protection.camera-exposure` |
| Standalone-first | `true` |

## Role

Local-first camera protection and exposure-governance instrument.

## This service owns

- Camera-class device discovery
- Device fingerprinting
- Camera risk evaluation
- Exposure analysis
- Operator review
- Enforcement planning
- Protective enforcement
- Append-only action receipts

## This service does not own

- General-purpose network inventory
- DNS filtering
- Identity creation
- Cloud camera hosting

## Upstream services

- `homegate`
- `covenant-gate`
- `neverlost`

## Downstream consumers or operators

- `watchtower`
- `live-state-surgeon`
- `operators`

## Contract families

- `device.*`
- `camera.*`
- `fingerprint.*`
- `risk.*`
- `review.*`
- `enforcement.*`
- `receipt.*`

## Integration rules

1. This repository must remain independently understandable, testable, buildable, and releasable.
2. Ecosystem integrations extend capability but do not replace standalone correctness.
3. Integrations use explicit, versioned schemas and receipts.
4. No undocumented database sharing, hidden filesystem coupling, or implicit trust is permitted.
5. Producer claims must be independently verified by the receiving boundary where verification is required.
6. Integration failure must not silently corrupt local authoritative state.
7. Missing upstream services must produce an explicit unavailable, unknown, deferred, or failed state according to the local contract.
8. This repository's current implementation must not be treated as the complete product definition.

## Authoritative ecosystem sources

- `C:\dev\Constellation\ecosystem\SERVICE_MAP.md`
- `C:\dev\Constellation\registry\services.json`
- `C:\dev\Constellation\ecosystem\AGENT_POLICY.md`
- `C:\dev\Constellation\ecosystem\SHARED_INVARIANTS.md`

## Change governance

Changes to this service's ecosystem role, ownership boundaries, upstream dependencies, or downstream responsibilities require:

1. A proposal under `docs\proposals`.
2. A documented compatibility impact.
3. Updated service-map and registry entries.
4. Updated positive and negative integration tests.
5. A new service-map receipt.
