# Constellation deep-ui diagnostics

Run at 2026-08-23T18:36:01.086Z

## Page summary

| Page | URL | Mounted | Data | Console errors | Failed /api requests |
| --- | --- | --- | --- | --- | --- |
| Dashboard | `/dashboard` | yes | yes | 0 | 0 |
| Findings | `/findings` | yes | yes | 0 | 0 |
| Assets | `/assets` | yes | yes | 0 | 0 |
| Clusters | `/clusters` | yes | n/a | 0 | 0 |
| Policies | `/policies` | yes | n/a | 0 | 0 |
| Compliance | `/compliance` | yes | n/a | 0 | 0 |
| Exceptions | `/exceptions` | yes | yes | 0 | 0 |
| Runtime | `/runtime` | yes | yes | 0 | 0 |
| Response (legacy) | `/response` | yes | yes | 0 | 0 |
| Response Rules | `/response-rules` | yes | yes | 0 | 0 |
| Vuln Profiles | `/vuln-profiles` | yes | yes | 0 | 0 |
| Groups | `/groups` | yes | yes | 0 | 0 |
| WAF Rules | `/waf` | yes | yes | 0 | 0 |
| DLP Sensors | `/dlp` | yes | yes | 0 | 0 |
| Network Map | `/network` | yes | n/a | 0 | 2 |
| Federation | `/federation` | yes | yes | 0 | 0 |
| CVE DB | `/cve` | yes | yes | 0 | 0 |
| Audit | `/audit` | yes | yes | 0 | 0 |
| Coverage | `/coverage` | yes | yes | 0 | 0 |
| System Health | `/system-health` | yes | n/a | 0 | 0 |
| Access Control | `/access-control` | yes | yes | 0 | 0 |
| Deployments (Risk) | `/deployments` | yes | yes | 0 | 0 |
| Settings | `/settings` | yes | n/a | 0 | 0 |
| Integrations | `/settings/integrations` | yes | yes | 0 | 0 |
| Connectors | `/settings/connectors` | yes | n/a | 0 | 0 |
| FindingDetail | `/findings/:id` | yes | yes | 0 | 0 |
| AssetDetail | `/assets/:id` | yes | yes | 0 | 0 |
| DeploymentDetail | `/deployments/:id` | yes | yes | 0 | 0 |
| PolicyWizard | `/policies/new` | yes | yes | 0 | 0 |
| RiskDetail | `/risk/asset/:id` | yes | yes | 0 | 0 |
| CVEDetail | `/cve/:id` | **NO** | yes | 0 | 2 |
| ScopeBar | `/timeline` | yes | yes | 0 | 0 |
| ResponseRules-create | `/response-rules` | yes | yes | 0 | 0 |

## Details

### Network Map (`/network`)
**failed /api requests:**
- GET 0 http://localhost:5179/api/v1/network/flows:stream?cluster_id=3dd7f29b-caeb-4a2c-9f22-4b658c4fdd3a
- GET 404 http://localhost:5179/api/v1/network/flows:stream?cluster_id=3dd7f29b-caeb-4a2c-9f22-4b658c4fdd3a

### CVEDetail (`/cve/:id`)
**failed /api requests:**
- GET 404 http://localhost:5179/api/v1/cve/CVE-2024-3094
- GET 400 http://localhost:5179/api/v1/clusters/CVE-2024-3094