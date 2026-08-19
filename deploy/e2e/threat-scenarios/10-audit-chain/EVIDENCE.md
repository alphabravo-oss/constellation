# Scenario 10 — End-to-end audit chain integrity

**Engine:** `pkg/audit.VerifyChain` (SHA-256 hash chain over append-only rows,
plus DB triggers `audit_events_no_{update,delete}` for in-engine
tamper-evidence).

**Result:** PASS

## What we proved

1. The chain verifies clean after all H3 scenarios ran:

   ```json
   {"status": "verified"}
   ```

2. Tampering one row (set `after = NULL` on the drift row) is detected on the
   next `VerifyChain` call:

   ```json
   {
     "status": "broken",
     "id": 4,
     "reason": "row hash mismatch",
     "expected": "4f8f0e32f6a616eee4c8b9c311efbf4740e8d6f3c76b2be31b792a76a9822aa3",
     "found":    "b98f07c5936293f584b339e816ee90d3046f4777d9eb1f4aa72a4e6339802eb0"
   }
   ```

3. After restoring the row the chain verifies clean again.

## H3 audit events generated

| Action | Count |
|---|---|
| `runtime.alert.waf` | 1 |
| `runtime.alert.dlp` | 1 |
| `admission.deny` | 1 |
| `gitops.drift.detected` | 1 |
| `runtime.alert.exec` | 1 |
| `scan-job.enqueue` | 1 |
| `network_policy.approve` | 1 |

Full table at `captures/events-by-action.txt`.

## Real bug fixed during this scenario

`pkg/audit.VerifyChain` selected `actor_ip::text`. Postgres renders the `inet`
type as `<addr>/<bits>` (`::1/128`, `10.0.0.1/32`). `net.ParseIP` rejects that
form and returns `nil`, so the verifier hashed `"<nil>"` for `actor_ip` even
though the writer hashed `::1`. **Any row with a non-NULL actor_ip silently
broke the chain.** Fix: use `host(actor_ip)` in the SELECT so the inet mask is
stripped before round-trip. See:

- `pkg/audit/audit.go` — `VerifyChain` query updated to
  `SELECT id, org_id, actor_id, host(actor_ip), …`.
- Integration test still passes: `DATABASE_URL=… go test -tags=integration ./pkg/audit/...`.

## Note on the live API binary

Wave H3 explicitly does not restart the running `constellation-api`. The
binary on disk still contains the old `VerifyChain`. The verification used here
is a dedicated tool `verify-driver/` linked against the fixed package; the
deployed API picks up the fix on next restart.

## Reproduce

```
./run.sh
```
