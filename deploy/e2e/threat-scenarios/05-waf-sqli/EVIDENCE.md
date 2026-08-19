# Scenario 05 — WAF blocks SQLi

**Engine:** `internal/runtime/waf.Engine`, sensor pack `owasp-crs-core`.

**Result:** PASS

## Attack

Synthetic L7Event modelling:

```
GET /api/v1/orders?id=1 OR 1=1-- HTTP/1.1
Host: checkout.svc.cluster.local
User-Agent: sqlmap/1.7.5#stable (https://sqlmap.org)
```

This is the canonical OR-tautology SQL injection probe. The workload
`checkout/api` is bound to baseline mode `enforce` so the engine must block.

## Detection

Rule fires:

| RuleID | Msg | Severity | Action |
|---|---|---|---|
| **942110** | SQL Injection Attempt (OR/AND tautology) | critical | block |
| 913100 | Suspicious scanner User-Agent (sqlmap) | warning | alert |

Verdict (`captures/verdict.json`): `action=block, mode=enforce`.

Audit chain (`captures/audit-event.json`): `runtime.alert.waf` row appended;
`chain_hash` printed and persisted.

## Real bug fixed during this scenario

The `942110` rule was failing to fire for the canonical
`?id=1 OR 1=1--` payload because its transformations included
`removeWhitespace`. After whitespace stripping the value becomes `1or1=1--`,
which neuters the `\bor\b` regex (no non-word character on either side of
`or`, so no word boundary). Fix: drop `removeWhitespace` from rule 942110
(keep `lowercase, urlDecode`). See:

- `internal/runtime/waf/rules_crs.go` — `Transformations: []string{"lowercase","urlDecode"}`
- WAF unit tests still pass: `go test ./internal/runtime/waf/...`.

## UI surface

`/runtime/alerts` shows the WAF row; `/waf/rules` shows rule 942110 in the
catalogue; `/audit` shows the hash-chained event.

## Reproduce

```
./run.sh
```
