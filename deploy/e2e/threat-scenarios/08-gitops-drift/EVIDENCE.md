# Scenario 08 — GitOps drift detection

**Engine:** `pkg/gitops.DetectDrift`.

**Result:** PASS

## Attack

An out-of-band actor edits `RoleBinding/platform-readers` after Argo CD synced
it from Git, changing the subject from a service-account to a different user
identity. The same scenario covers any attacker-driven RBAC tamper.

## Detection

The drift driver hashes the declared spec and the observed spec separately and
emits a `DriftFinding` per divergence:

```json
{
  "Source": "argocd",
  "Application": "platform-rbac",
  "Kind": "RoleBinding",
  "Name": "platform-readers",
  "Namespace": "platform",
  "DeclaredHash": "404eb2766e735bb79cc95bb3d0fe9bb8e2a0413405a333a75254999ce9143170",
  "ObservedHash": "ee4e566bc2ad33e08342db450eb9d78bc38f689161f9de787466dd22d425eefe",
  "DiffSummary": "declared sha=404eb2766e73 observed sha=ee4e566bc2ad"
}
```

Audit chain records a `gitops.drift.detected` event tied to the SHA pair.

## Evidence

| Item | File |
|---|---|
| DriftFinding JSON | `captures/drift-detection.json` |
| Audit chain insert | `captures/audit-event.txt` |

## UI surface

`/gitops/drift` (planned) or the federation timeline; in the meantime the
audit-events view shows the SHA pair under the event's `after` payload.

## Reproduce

```
./run.sh
```
