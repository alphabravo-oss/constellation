# Scenario 06 — DLP catches PII exfil

**Engine:** `internal/runtime/dlp.Engine`, sensor pack
`constellation-default-dlp`.

**Result:** PASS

## Attack

A POST response from `payments.svc.cluster.local/api/v1/checkout` carries:

```json
{"order_id":"42","card":"4111 1111 1111 1111","total":"99.00"}
```

`4111111111111111` is the canonical Visa test PAN that passes Luhn.

Workload `payments/api` is in enforce mode.

## Detection

Pattern fires:

| PatternID | Msg | Severity | Action |
|---|---|---|---|
| **1001** | Credit card number (Luhn-valid) | critical | block |

The pattern's `Validator` runs Luhn after the regex match, so we don't trip on
random 16-digit strings.

Verdict (`captures/verdict.json`): `action=block, mode=enforce, matches=[1001]`.
Captured sample is redacted to `4111…1111` before persisting.

Audit chain (`captures/audit-event.json`): `runtime.alert.dlp` row appended.

## UI surface

`/dlp/sensors` shows the sensor; the alert lands at `/runtime/alerts`; the
hash-chained audit event surfaces under `/audit`.

## Reproduce

```
./run.sh
```
