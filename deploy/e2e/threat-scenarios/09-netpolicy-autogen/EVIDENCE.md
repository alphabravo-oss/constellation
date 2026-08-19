# Scenario 09 — Network policy auto-generation

**Engine:** `pkg/netpolicy` candidate generator + `handler.NetworkPolicies`
lifecycle.

**Result:** PASS

## Setup

The lifecycle API serves a seeded set of "stable for 24h" workload
observations — the same data shape the runtime agent emits on the live path.

## What we exercised

| Step | Endpoint | Evidence |
|---|---|---|
| List candidates | `GET /api/v1/network/policies/lifecycle` | `captures/lifecycle.json` (1 candidate for `default/api-service`, `candidate_hash=7767390faf3b1f9a`) |
| Generate previews | `POST /api/v1/network/policies/default%2Fapi-service/preview` | `captures/preview.json` |
| Approve candidate | `POST /api/v1/network/policies/default%2Fapi-service/approve` | `captures/approve.json` (writes `network_policy.approve` audit row) |

## Generated policy preview

The lifecycle response inlines the proposed YAML for **three** engines
(Cilium, Calico, native NetworkPolicy). Sample (Cilium):

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-service-cilium
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: api-service
  ingress:
    - fromEndpoints:
        - matchLabels: {k8s:app: frontend, k8s:io.kubernetes.pod.namespace: default}
      toPorts:
        - ports: [{port: "8443", protocol: TCP}]
  egress:
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: kube-system, k8s:k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}]
          rules:
            dns: [{matchPattern: '*'}]
    - toEndpoints:
        - matchLabels: {k8s:app: postgres, k8s:io.kubernetes.pod.namespace: data}
      toPorts:
        - ports: [{port: "5432", protocol: TCP}]
```

The summary carries the rationale: `8 total flows, 4 unique peers, 5 unique
port-proto`. Approve lands an audit row that **persists state but does not
apply cluster-side** — apply is gated to be opt-in.

## UI surface

`/network/policies` — three columns (preview, diff, audit_trail) per workload.

## Reproduce

```
./run.sh
```
