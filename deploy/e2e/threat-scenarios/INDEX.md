# Constellation — From-Attack-to-Detection Portfolio (Wave H3)

Ten runnable threat scenarios that each pair a real attack with the engine
that detects it, the audit-chain row that records it, and the UI surface an
analyst would use to respond. Built against the running local stack:

- `constellation-api` on `:18080` (local binary; Wave H3 does not restart it).
- Postgres on `:5433`, schema as of migration 028.
- k3d cluster `constellation` (api + operator + admission + scanner + 3-node
  runtime-agent DaemonSet, plus the Wave F2 vulnerable workload fleet).
- `KUBECONFIG=/tmp/kubeconfig-constellation.yaml` for the cluster.

## Roster

| # | Scenario | Engine | Result | Evidence |
|---|---|---|---|---|
| 01 | Image vulnerability scan (`nginx:1.14.2`) | scanner (Syft+Trivy+Grype) | **PASS** | [01-image-scan/EVIDENCE.md](01-image-scan/EVIDENCE.md) |
| 02 | Admission deny — unsigned image | `pkg/admission` (enforce) | **PASS** | [02-admission-unsigned/EVIDENCE.md](02-admission-unsigned/EVIDENCE.md) |
| 03 | Admission deny — privileged + hostNetwork | `pkg/admission` (enforce) | **PASS** | [03-admission-privileged/EVIDENCE.md](03-admission-privileged/EVIDENCE.md) |
| 04 | Admission TLS plumbing + VWC registration | apiserver → webhook over TLS | **PASS** | [04-admission-tls/EVIDENCE.md](04-admission-tls/EVIDENCE.md) |
| 05 | WAF blocks SQLi (`?id=1 OR 1=1--`) | `internal/runtime/waf` | **PASS** | [05-waf-sqli/EVIDENCE.md](05-waf-sqli/EVIDENCE.md) |
| 06 | DLP catches Luhn-valid CC# in response body | `internal/runtime/dlp` | **PASS** | [06-dlp-pii/EVIDENCE.md](06-dlp-pii/EVIDENCE.md) |
| 07 | Suspicious exec inside pod → eBPF + MITRE | `internal/runtime/ebpf` | **PASS** | [07-runtime-exec/EVIDENCE.md](07-runtime-exec/EVIDENCE.md) |
| 08 | GitOps drift detection (declared vs live SHA) | `pkg/gitops.DetectDrift` | **PASS** | [08-gitops-drift/EVIDENCE.md](08-gitops-drift/EVIDENCE.md) |
| 09 | Network policy auto-gen (Cilium/Calico/native YAML) | `pkg/netpolicy` + lifecycle handler | **PASS** | [09-netpolicy-autogen/EVIDENCE.md](09-netpolicy-autogen/EVIDENCE.md) |
| 10 | Audit chain integrity (clean → tamper → restore) | `pkg/audit.VerifyChain` | **PASS** | [10-audit-chain/EVIDENCE.md](10-audit-chain/EVIDENCE.md) |

## Bugs fixed along the way

| Path | Why |
|---|---|
| `internal/runtime/waf/rules_crs.go` (rule 942110) | `removeWhitespace` transformation neutered the rule for the canonical `?id=1 OR 1=1--` payload because `\bor\b` needs a non-word boundary that whitespace stripping destroys. |
| `pkg/audit/audit.go` (`VerifyChain`) | Selected `actor_ip::text`, which Postgres renders as `<addr>/<bits>` — `net.ParseIP` returns nil on that form, so the verifier silently broke the chain for every row with a non-NULL actor IP. Fixed to use `host(actor_ip)`. |

## Demo runbook (90-second tour)

```bash
export TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@dev","password":"devpass123"}' \
  http://localhost:18080/api/v1/auth/login | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
echo "$TOKEN" > /tmp/h3-token

# 1. Scan a known-vuln image, show 200+ findings + dashboard tick.
./01-image-scan/run.sh

# 2. Pop the WAF + DLP scenarios; show the runtime.alert.* audit rows.
./05-waf-sqli/run.sh
./06-dlp-pii/run.sh

# 3. Show admission denials: in-engine + apiserver-mediated.
./02-admission-unsigned/run.sh
./03-admission-privileged/run.sh
./04-admission-tls/run.sh

# 4. Detection from the kernel: eBPF exec inside a pod with MITRE mapping.
./07-runtime-exec/run.sh

# 5. Drift + auto-policy: Argo CD style.
./08-gitops-drift/run.sh
./09-netpolicy-autogen/run.sh

# 6. The audit chain itself — tamper one row, watch verify go red.
./10-audit-chain/run.sh
```

## Shared harness

`waf-driver/` is a single Go binary (build tag `e2etools`) with three
subcommands — `waf-sqli`, `dlp-pii`, `admission` — that drive the in-process
engines + audit-log writer. The eBPF / drift / netpolicy / audit-chain
scenarios use one-shot drivers under each scenario's directory.

Build once:

```bash
go build -tags e2etools -o /tmp/scenario-driver ./deploy/e2e/threat-scenarios/waf-driver
```

## Limitations / out-of-scope

- The deployed `constellation-api` binary has not been restarted; the
  `actor_ip::text` fix in `pkg/audit` ships next deploy. Scenario 10 uses a
  stand-alone verifier linked against the fixed package.
- Scenario 04 scales the operator to 0 so the manual Deployment patch sticks.
  Promoting the TLS field into the `ConstellationCluster` CR is tracked as a
  follow-up.
- Scenario 05 / 06 use the engine via a Go driver, not via NFQUEUE on a node —
  that path requires a privileged DaemonSet and is left for the live-traffic
  Wave (the engine, sensor pack, and verdict shape are identical).
