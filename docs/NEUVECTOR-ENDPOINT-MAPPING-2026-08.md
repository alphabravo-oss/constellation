# NeuVector to Constellation API Mapping (2026-08)

Purpose: help NeuVector operators translate scripts and runbooks to
Constellation without reading source code. This document is scoped to the
primary endpoint families present in the local NeuVector API spec
(`/root/constellation-all/neuvector/controller/api/apis.yaml`) and the current
Constellation OpenAPI document (`internal/handler/openapi.json`).

The live Constellation OpenAPI document is available from the product at:

- Settings -> API Reference
- `GET /openapi.json`

## Authentication

Constellation API examples use bearer tokens:

```bash
export CONSTELLATION=https://constellation.example
export TOKEN='<bearer-token>'
export CLUSTER='<cluster-uuid>'

alias cx='curl -fsS -H "Authorization: Bearer $TOKEN"'
```

## Primary Endpoint Map

| NeuVector family | NeuVector examples | Constellation API | Constellation UI | Status |
| --- | --- | --- | --- | --- |
| Login/session | `POST /v1/auth` | `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, `POST /api/v1/auth/logout` | Auth flow | Implemented |
| Users/roles | `/v1/user`, `/v1/user_role`, `/v1/server/{name}/role/{role}` | `/api/v1/access-control`, `/api/v1/users`, `/api/v1/custom-roles`, `/api/v1/access-control/role-bindings` | Settings -> Access Control | Implemented; provider test and group-mapping preview remain planned |
| API keys | `/v1/api_key` | `/api/v1/api-tokens`, `/api/v1/api-tokens/{id}/rotate` | Settings -> API Tokens | Implemented |
| Password profile | `/v1/password_profile` | `/api/v1/auth/security-policy` | Settings -> Security Policy | Implemented |
| System config | `/v1/system/config`, `/v2/system/config` | `/api/v1/system/config`, `/api/v1/scanner/refresh` | Settings -> Effective Config, Network & Proxy, Scanner & CVE Sources | Implemented; redaction, diff, revision metadata, and per-component applied revision are visible; exact per-key backend provenance remains planned |
| Controllers | `/v1/controller`, `/v1/controller/{id}/stats` | `/api/v1/components?role=controller`, `/api/v1/components/{id}/diagnostics` | Components -> Controller filter | Implemented |
| Enforcers | `/v1/enforcer`, `/v1/enforcer/{id}/stats` | `/api/v1/components?role=enforcer`, `/api/v1/heartbeats` | Components -> Enforcer filter | Implemented |
| Scanners | `/v1/scan/scanner`, `/v1/scan/status`, `/v1/scan/cache_stat/{id}` | `/api/v1/scan/scanner`, `/api/v1/scan/status`, `/api/v1/scanner-cache/{scanner_id}/stat` | Scanner & CVE Sources, Components -> Scanner filter | Implemented; queue/capacity, cache, failed-job, retry ledger, and DB freshness views are live; autoscale cockpit remains planned |
| Hosts/nodes | `/v1/host`, `/v1/host/{id}` | `/api/v1/clusters/{id}/nodes`, `/api/v1/clusters/{id}/nodes/{node}` | Nodes | Implemented |
| Workloads/services | `/v1/workload`, `/v2/workload`, `/v1/service` | `/api/v1/deployments`, `/api/v1/deployments/{id}`, `/api/v1/assets` | Workloads, Assets | Implemented; UI aliases preserve NV names |
| Groups | `/v1/group`, `/v1/file/group` | `/api/v1/groups`, `/api/v1/groups/{id}/usage`, `/api/v1/groups:export`, `/api/v1/groups:import`, `/api/v1/groups:promote`, `/api/v1/migration/preview` | Groups, Group detail, Policy Center, Migration Imports | Implemented; concrete usage/conflict map covers group-rule edges and DLP/WAF bindings; migration preview/apply/rollback imports supported NeuVector group definitions and flags unsupported selectors; shared group picker is wired into network rule source/destination fields; remaining editors and broader reference-family coverage remain planned |
| Network activity | `/v1/service/config/network`, `/v1/log/violation`, `/v1/sniffer` | `/api/v1/network/map`, `/api/v1/network/conversations`, `/api/v1/network/sessions`, `/api/v1/runtime-pcap/start`, `/api/v1/runtime-threats` | Network Activity tabs | Implemented; per-user/per-cluster saved workspace filters cover Network Activity tab/time/namespace/group/verdict/protocol/visibility/scope, live-session filters, and PCAP/sniffer controls; map, conversations, sessions, runtime threats, PCAP capture lists, and Network Activity Rules lifecycle apply `group` by id or name and return selected-group metadata where applicable; sessions expose `total`/`limit`/`has_more` plus protocol/application/port/peer/workload/node filters; PCAP supports status/workload/group/protocol/source/destination/port list filters plus BPF/interface/rolling capture requests; threat drilldown PCAP capture defaults to attributed workload; session kill returns queued target/audit details in UI |
| Network policy rules | `/v1/policy/rule`, `/v1/policy/rules/promote` | `/api/v1/clusters/{id}/network-rules`, `/api/v1/clusters/{id}/network-rules:move-top`, `/api/v1/network/policies/lifecycle`, `/api/v1/migration/preview`, `/api/v1/migration/imports/{id}:apply`, `/api/v1/migration/imports/{id}/rollback-bundle` | Policy Center -> Network Rules, Network Activity -> Rules, Migration Imports | Implemented; REST `RESTPolicyRule` and `NvSecurityRule` ingress/egress allow rules migrate to `group_rule_edges` when both groups exist or are imported by the same preview; deny, disabled, L7 application-scoped, malformed-port, and missing-group rules remain structured unsupported rows for manual modeling |
| Admission | `/v1/admission/*`, `/v1/assess/admission/rule` | `/api/v1/policies/admission/options`, `/api/v1/policies/admission/rules`, `/api/v1/policies/admission/state`, `/api/v1/policies/assess`, `/api/v1/policies/admission/dry-runs` | Policy Center -> Admission Control | Implemented; retained dry-run history, criteria assess coverage, and native NV deny/exception migration are covered; fixture reconciliation remains planned |
| Process profile | `/v1/process_profile`, `/v1/process_rules/{uuid}` | `/api/v1/runtime/baselines`, `/api/v1/runtime/baselines/{workload_id}`, `/api/v1/migration/preview`, `/api/v1/migration/imports/{id}:apply` | Process Baselines, Migration Imports | Implemented; NeuVector process profile exports preview/apply into workload-scoped process baseline states and allow/deny rules when the referenced group resolves to discovered workloads; missing cluster/group/member mappings and unsafe wildcard rules remain structured unsupported rows |
| File monitor | `/v1/file_monitor`, `/v1/file/config` | `/api/v1/runtime/file-profiles`, `/api/v1/runtime/file-profiles/{workload_id}`, `/api/v1/migration/preview`, `/api/v1/migration/imports/{id}:apply` | File Monitor, Migration Imports | Implemented; NeuVector file monitor profile exports preview/apply into workload-scoped file profile states and rules when the referenced group resolves to discovered workloads; missing cluster/group/member mappings remain structured unsupported rows |
| DLP | `/v1/dlp/sensor`, `/v1/dlp/rule`, `/v1/file/dlp` | `/api/v1/runtime-dlp-rules`, `/api/v1/runtime/dpi-sensor-bindings`, `/api/v1/runtime/dlp-rules:bundle` | DLP Rules | Implemented for runtime rules and group detector scope; NeuVector DLP sensor/rule CRD and REST-style exports preview/apply into `runtime_dlp_rules` category `dlp`; source `dlp_group` scopes bind automatically when the target Constellation group already exists or is imported by the same migration preview, and otherwise remain structured unsupported rows |
| WAF/DPI | `/v1/waf/sensor`, `/v1/waf/rule`, `/v1/file/waf` | `/api/v1/runtime-signatures`, `/api/v1/runtime/dpi-sensor-bindings`, `/api/v1/policies/dpi-threats` | WAF / DPI Signatures | Implemented for custom signatures and shared detector scope; NeuVector WAF sensor/rule exports preview/apply into `runtime_dlp_rules` category `waf` and are visible in WAF/DPI Signatures; source `waf_group` scopes bind automatically when the target Constellation group already exists or is imported by the same migration preview, and otherwise remain structured unsupported rows |
| Response rules | `/v1/response/rule`, `/v1/file/response/rule` | `/api/v1/response-rules-v2`, `/api/v1/response-rule-defs`, `/api/v1/response-rules-v2:reorder` | Response Rules, Response Catalog | Implemented |
| Vulnerability profiles | `/v1/vulnerability/profile`, `/v1/file/vulnerability/profile` | `/api/v1/vuln-profiles`, `/api/v1/vuln-profiles:export`, `/api/v1/vuln-profiles:import` | Vuln Profiles | Implemented |
| Registry scans | `/v1/scan/registry`, `/v2/scan/registry`, `/v1/scan/registry/{name}/scan` | `/api/v1/registries`, `/api/v1/registries/{id}/sync-now`, `/api/v1/registries/{id}/cancel-scans`, `/api/v1/registries/{id}/images`, `/api/v1/scan-jobs` | Registries, Scanner & CVE Sources | Implemented; NV schedule knobs, active-scan cancel, retry attempts, and failed-job triage are live; seeded fixture field reconciliation remains planned |
| Image scan detail | `/v1/scan/image/{id}`, `/v1/scan/workload/{id}` | `/api/v1/image-scan-results`, `/api/v1/image-scan-results/{id}`, SBOM/VEX endpoints | Images, Image detail | Implemented and extends NV with SBOM/VEX |
| Compliance | `/v1/bench/*`, `/v1/compliance/profile`, `/v1/custom_check` | `/api/v1/compliance/*`, `/api/v1/reports/compliance.*` | Compliance | Implemented |
| Logs | `/v1/log/activity`, `/v1/log/audit`, `/v1/log/event`, `/v1/log/incident`, `/v1/log/threat`, `/v1/log/violation`, `/v1/log/security` | `/api/v1/security/timeline`, `/api/v1/audit/events`, `/api/v1/events:export` | Incident Timeline category tabs, advanced filters, saved views, detail drawers | Implemented; source-table count reconciliation remains planned |
| Config export/import | `/v1/file/*/config` families | `/api/v1/config/export`, `/api/v1/config/import`, `/api/v1/migration/preview`, `/api/v1/migration/imports/{id}:apply`, `/api/v1/migration/imports/{id}/rollback-bundle` | Settings -> Migration Imports | Partial; preview/apply/rollback cover admission, response, group definitions with supported selectors, safe network allow rules, process-profile and file-profile apply for resolved groups, DLP/WAF enforced rule conversion, source-count reconciliation fields, and persisted rollback-bundle downloads; more NV object conversions remain planned |
| Federation | `/v1/fed/healthcheck`, federated config files | `/api/v1/federation/state`, `/api/v1/federation/members`, `/api/v1/federation/join*`, `/api/v1/federation/sync` | Federation | Implemented for Constellation federation model |
| Support bundle | `/v1/csp/file/support` | `/api/v1/support/bundle` | Components diagnostics, System Health | Implemented; redacted JSON bundle with SHA-256 integrity and audit event is live; async signed artifact lifecycle remains planned |

## Common Runbook Translations

### Download OpenAPI

```bash
cx "$CONSTELLATION/openapi.json" > constellation-openapi.json
```

### Export Constellation Config

NeuVector operators often export file-backed config by family. In Constellation,
the canonical authored config export is one YAML document.

```bash
cx "$CONSTELLATION/api/v1/config/export" > constellation-config.yaml
```

### Import Config

Use `mode=merge` for additive cutovers. Use `mode=replace` only after reviewing
the exported artifact and rollback path.

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @constellation-config.yaml \
  "$CONSTELLATION/api/v1/config/import?mode=merge"
```

### Preview a NeuVector Export

```bash
jq -Rs --arg cluster "$CLUSTER" '{source:"neuvector", cluster_id:$cluster, export:.}' nv-export.json |
curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  "$CONSTELLATION/api/v1/migration/preview"
```

Apply and rollback are import-history operations:

```bash
export IMPORT_ID='<preview-import-id>'

curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$CONSTELLATION/api/v1/migration/imports/$IMPORT_ID:apply"

curl -fsS -H "Authorization: Bearer $TOKEN" \
  -o constellation-rollback-bundle.json \
  "$CONSTELLATION/api/v1/migration/imports/$IMPORT_ID/rollback-bundle"

curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$CONSTELLATION/api/v1/migration/imports/$IMPORT_ID:rollback"
```

### List and Export Groups

```bash
cx "$CONSTELLATION/api/v1/groups" | jq .
cx "$CONSTELLATION/api/v1/groups/<group-id>/usage?cluster_id=<cluster-id>" | jq .
cx "$CONSTELLATION/api/v1/groups:export" > groups.yaml
```

### Create or Override a Network Rule

NeuVector `RESTPolicyRule` maps to a Constellation network rule override:

```bash
curl -fsS -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "default/frontend",
    "to": "default/api",
    "ports": "443",
    "applications": ["HTTPS"],
    "action": "allow",
    "comment": "cutover allow rule"
  }' \
  "$CONSTELLATION/api/v1/clusters/$CLUSTER/network-rules"
```

Move a rule to the top:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from":"default/frontend","to":"default/api"}' \
  "$CONSTELLATION/api/v1/clusters/$CLUSTER/network-rules:move-top"
```

### Sync a Registry Now

```bash
export REGISTRY_ID='<registry-uuid>'

curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$CONSTELLATION/api/v1/registries/$REGISTRY_ID/sync-now"

cx "$CONSTELLATION/api/v1/scan-jobs?cluster_id=$CLUSTER" | jq .
```

### Test Admission for an Image

This is the Constellation equivalent of NeuVector admission assessment: it
evaluates rules without deploying the workload.

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image":"docker.io/library/nginx:latest","namespace":"default"}' \
  "$CONSTELLATION/api/v1/policies/assess?cluster_id=$CLUSTER" | jq .
```

### Export Logs

Use the unified timeline for investigation views and event export for raw runtime
events.

```bash
cx "$CONSTELLATION/api/v1/security/timeline?cluster_id=$CLUSTER&type=dpi_threat,runtime_event,network_violation&hours=24" | jq .
cx "$CONSTELLATION/api/v1/events:export?cluster_id=$CLUSTER&hours=24" > events.json
cx "$CONSTELLATION/api/v1/audit/events?limit=200" | jq .
```

## Better-Than-NV API Surfaces To Preserve In Runbooks

- SBOM export: `/api/v1/sbom/spdx/{asset_id}`,
  `/api/v1/sbom/cyclonedx/{asset_id}`.
- VEX export: `/api/v1/vex/openvex/{asset_id}`,
  `/api/v1/vex/cyclonedx/{asset_id}`.
- Repository scans and attestations:
  `/api/v1/repository-scans`, `/api/v1/repository-scan-attestations/{id}`.
- Serverless inventory and package evidence:
  `/api/v1/serverless-functions`, `/api/v1/serverless-packages:report`.
- Signed compliance artifacts:
  `/api/v1/reports/compliance.pdf`, `/api/v1/compliance/runs/{id}/artifact`.
- Config-as-code Git connector:
  `/api/v1/config/git-connector`, `/api/v1/config/git-connector/push`.

## Current Documentation Gaps

The runtime routes exist, but some OpenAPI operations still lack detailed
request/response schemas. Prioritize schemas for:

- `/api/v1/clusters/{id}/network-rules`
- `/api/v1/policies/assess`
- `/api/v1/registries/{id}/sync-now`
- `/api/v1/events:export`
- `/api/v1/runtime-pcap/start` and richer `/api/v1/runtime-pcap` query/response schemas

Until those are expanded, use the examples above and the TypeScript client in
`frontend/src/api/client.ts` as the DTO source of truth.
