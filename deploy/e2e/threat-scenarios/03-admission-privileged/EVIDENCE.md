# Scenario 03 — Admission denial: privileged pod

**Engine:** `pkg/admission.PolicyEngine` — `block-privileged` rule (enforce).

**Result:** PASS

## Attack

Two AdmissionReview payloads:

1. A Pod with `securityContext.privileged: true`.
2. A Pod with `hostNetwork: true`.

Both are posted to `/validate` on the deployed `e2e-admission` Service via a
port-forward.

## Detection

```json
{"allowed": false,
 "status": {"message": "denied by constellation policy \"block-privileged\": container \"evil\" is privileged"}}
```

```json
{"allowed": false,
 "status": {"message": "denied by constellation policy \"block-host-network\": hostNetwork=true"}}
```

A `policy_decisions` row is persisted with `verdict=deny, reason=<rule>` so
`/api/v1/violations` and the deployment-risk view light up.

## Evidence

| Item | File |
|---|---|
| Privileged AdmissionReview response | `captures/admission-review.json` |
| hostNetwork AdmissionReview response | `captures/admission-hostnet.json` |
| `policy_decisions` row | `captures/policy-decisions-db.txt` |

## Cross-link to scenario 04

After TLS is wired (scenario 04), the same privileged pod is rejected by the
apiserver itself when applied with `kubectl apply -f` — no port-forward needed.
That capture lives at `04-admission-tls/captures/kubectl-apply-output.txt`.

## Reproduce

```
./run.sh
```
