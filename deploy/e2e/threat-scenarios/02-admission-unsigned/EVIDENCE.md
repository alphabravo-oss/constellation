# Scenario 02 — Admission denial: unsigned image

**Engine:** `pkg/admission.PolicyEngine` — built-in `require-image-signature`
rule, flipped to enforce mode for this scenario.

**Result:** PASS

## Attack

A Pod referencing `attacker/evil:latest` is sent through the admission engine.
The Pod has no `constellation.alphabravo.io/image-signed: "true"` annotation
(which the production scanner mutates onto the Pod once a cosign trust policy
verifies the image signature).

## Detection chain

1. `pkg/admission.PolicyEngine.Evaluate` returns:
   ```json
   {
     "uid": "demo-uid",
     "allowed": false,
     "status": {"message": "denied by constellation policy \"require-image-signature\": missing constellation image-signed annotation"}
   }
   ```
2. The driver inserts a `policy_decisions` row:
   `subject_kind=admission, subject_id=default/evil-unsigned, verdict=deny`.
3. A `runtime.alert`-shaped audit event with action `admission.deny` is appended
   to the hash-chained audit log.
4. A `violations` row is inserted so `/api/v1/violations` surfaces this for the
   UI's deployment-risk timeline.

## Evidence files

| Surface | File |
|---|---|
| AdmissionReview request/response | `captures/admission-review.json` |
| `policy_decisions` row | `captures/policy-decisions-db.txt` |
| Audit event | `captures/audit-event.json` |
| `/api/v1/violations` | `captures/violations-api.json` |
| Cluster webhook payload mirror | `captures/admission-cluster-webhook.json` |

## Note on production rule mode

The shipped catalogue keeps `require-image-signature` in monitor mode by design
(it gives ops a 24h soak before flipping). For demo realism we promote it to
enforce in-process. The same code path runs in `cmd/constellation-admission`
once the rule's `mode` column flips in `policies` (Phase 3 hot-reload).

## UI surface

`/policies` shows the rule in enforce mode; `/violations` shows the deny;
`/audit` shows the hash-chained `admission.deny` event.

## Reproduce

```
./run.sh
```
