# NeuVector Parity Re-Audit — Synthesis

_Re-audit date: 2026-06-30. Inputs: per-dimension verification results covering the original audit's 17 HIGH gaps. This supersedes all prior re-audit drafts, including the earlier draft that listed vuln-scanning G1 as open — G1 is now confirmed CLOSED (reachability is persisted into `risk_inputs.reachable_static` and surfaced via the findings API)._

## 1. Headline Verdict

**Is Constellation now AT LEAST PARITY (parity or better) in EVERY dimension, with ZERO unclosed/new HIGH gaps?**

**YES.**

Every audited dimension reaches verdict `parity` at `high` confidence, and every one of the original audit's 17 HIGH gaps is confirmed CLOSED with in-tree file:line evidence. No dimension is rated `worse`, and no new HIGH gap surfaced during re-verification.

- At-least-parity in EVERY dimension? **Yes.**
- Zero unclosed/new HIGH gaps? **Yes — 0 remain.**

## 2. Scorecard

| Dimension | Verdict | HIGH gaps still open |
|---|---|---|
| authn-authz-rbac | parity (high) | 0 |
| api-security-exposure | parity (high) | 0 |
| admission-control | parity (high) | 0 |
| config-surface | parity (high) | 0 |
| runtime-security | parity (high) | 0 |
| network-segmentation | parity (high) | 0 |
| api-surface | parity (high) | 0 |
| vuln-scanning | parity (high) | 0 |
| **Total** | **parity (8/8)** | **0** |

## 3. Gating Blockers

**None.** No dimension is rated `worse`, and no dimension carries an unclosed or newly discovered HIGH gap. There are zero gating blockers to a "parity confirmed" claim.

The previously gating item — vuln-scanning **G1** (govulncheck reachability computed but not persisted) — is now closed. Reachability is written into the findings detail and risk inputs and surfaced through the API:
- `internal/scanner/reachability.go:64-120` sets `Finding.Reachable`.
- `internal/handler/scanning/scanjobs.go:1799-1800` adds `reachable_static` to `detail_json`.
- `scanjobs.go:1401-1402,1419` merge `reachable_static` into the `risk_inputs` JSONB on INSERT/UPDATE; `:1471-1473` carries it through `promoteImageFindingsToWorkloads`.
- `internal/handler/findings/searchq.go` exposes the `reachable` filter via `risk_inputs->>'reachable_static'`; `pkg/risk/risk.go:59,89-90` consumes `ReachableStatic` in scoring.

## 4. Status of the Original Audit's 17 HIGH Gaps

This re-audit confirms the closure status of the original 17 HIGH gaps: **all 17 confirmed CLOSED** with in-tree code/test evidence, and **no new HIGH gaps introduced**.

### authn-authz-rbac
- A1 disabled-user + token revocation — `auth.go:357-380`, `server.go:1527`, `api_tokens.go:706` — CLOSED
- A2 brute-force lockout — `auth.go:299-341,171-179` — CLOSED
- A4 password policy + forced-reset — `argon.go:115-149`, `auth.go:442-573` — CLOSED
- A4b password max-age enforced at login — `auth.go:231-246`, `server.go:1583-1589` — CLOSED
- A5 session JWT RS256 — `jwt.go:116-131`, `sessionkeys.go:99-143` — CLOSED
- B4 DB-backed auth-provider CRUD + hot-reload — `auth_servers.go:17-277`, `auth.go:67-94` — CLOSED

### api-security-exposure
- A3 HTTP rate limiting + concurrent-session cap — `server.go:550-574,1541-1554`, `auth.go:382-429` — CLOSED
- A7 idle timeout + PAT lifetime cap — `server.go:57,61,1560-1572`, `api_tokens.go:683-702` — CLOSED
- A8 CORS no-wildcard + OIDC nonce — `server.go:505,536`, `oidc.go:182`, `auth.go:612` — CLOSED

### admission-control
- C1 Pod Security Standards engine — `pkg/admission/pss.go:1-470`, `pss_test.go`, `profiles.go:111-142` — CLOSED
- C2 controller kinds + PVC validation — `isPodTemplateKind:919`, `extractPodFromObject:934`, `evaluatePVC:506-558` — CLOSED
- C3 K8s-identity/RBAC criteria — `evalIdentityRule:616`, `rbac.go:66,256-282`, `rbac_resolver.go` — CLOSED

### config-surface
- B1 runtime-mutable system config — `internal/syscfg/syscfg.go:1-31`, `system_config.go:15-24`, `server.go:869-870` — CLOSED
- B1a dead ScannerAutoscale knobs removed (HPA-owned) — grep-confirmed zero matches — CLOSED
- B2 policy/rules as K8s CRDs — `policy_types.go:47-174`, `108_policy_operator_source.sql`, `store.go:120-182` — CLOSED
- B3 config-as-code export/import incl. response_rules — `configio.go:41-57`, `manifest.go:96-121`, `config_io.go:59-139` — CLOSED
- B4 external auth providers runtime CRUD + bootstrap — `auth_servers.go:17-28`, `authservers.go:487-499`, `cmd/constellation-bootstrap/main.go:99-254` — CLOSED

### runtime-security
- E1 enforcing event-driven response-rule engine — `events_ingest.go:540-606`, `scanjobs.go:933-939`, `scan_response_rules.go:120-172`, `audit_hook.go:20-253`, `response_rule_defs.go:263-279` — CLOSED

### network-segmentation
- F1 end-to-end FQDN-based network policy — `109_network_flows_fqdn.sql`, `hubble_flow.go:117-129`, `netpolicy.go:301-353`, `dp/fqdn.go` — CLOSED

### api-surface
- I1 OpenAPI completeness + enforced CI gate (363/363, 100%) — `openapi.go:28-59`, `openapi_test.go:69-144`, `ci.yml:90-98` — CLOSED

### vuln-scanning
- G1 govulncheck reachability computed AND persisted/surfaced — `reachability.go:64-120`, `scanjobs.go:1401-1473,1799-1800`, `risk.go:59,89-90` — CLOSED
- G2 per-layer vuln attribution + Dockerfile instruction — `layers.go:42-295`, `scanjobs.go:1072-1089` — CLOSED
- G3 serverless artifact scanner (zip-slip guarded) + registry repo/tag filters — `serverless.go:30,78-189`, `registries.go:264-271,1116-1156` — CLOSED

**New HIGH gaps surfaced during re-audit:** none.

## 5. Push-to-Main Recommendation (parity grounds)

**Safe to push to main on parity grounds.** All dimensions are at parity with zero unclosed or new HIGH gaps, and all 17 original HIGH gaps are confirmed closed with evidence. From a NeuVector-parity standpoint there are no gating blockers.
