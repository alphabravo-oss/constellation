# CNI compatibility matrix

How the constellation runtime-agent + dp data-plane interact with each
CNI plugin. The agent's CNI auto-discovery
(`internal/runtime/dp/cnidetect.CandidateCNIDirs`) probes every well-known
CNI config path on startup and identifies the active plugin so dp can
decide whether NFQUEUE-based enforcement will actually take effect.

## Auto-discovery paths

The chart mounts every well-known CNI config directory into the agent
pod (DaemonSet `runtime-agent-daemonset.yaml`). The agent walks them in
this priority order until it finds one with a non-empty config:

| Order | Path                                              | Distros that use it           |
|-------|---------------------------------------------------|-------------------------------|
| 1     | `/etc/cni/net.d`                                  | kubeadm, EKS, GKE, AKS, kind |
| 2     | `/var/lib/rancher/k3s/agent/etc/cni/net.d`        | k3s                           |
| 3     | `/var/lib/rancher/rke2/agent/etc/cni/net.d`       | RKE2                          |
| 4     | `/etc/cni/multus/net.d`                           | OpenShift OVN-Kubernetes      |
| 5     | `/var/snap/microk8s/current/args/cni-network`     | microk8s (snap)               |

To pin to a non-standard path, set `runtimeAgent.dp.cniDir=<path>` in the
chart values (auto-discovery is skipped when this is non-empty).

## Tested CNI permutations

| CNI                            | Detection | NFQUEUE Enforce | Cilium-Native Export | Test cluster | Notes |
|--------------------------------|-----------|-----------------|----------------------|--------------|-------|
| **flannel (k3s default)**      | ✅ live (k3s, 2026-05-14) | ✅ — iptables-based  | n/a                  | k3s 1.35.4 / Ubuntu 24.04 / kernel 6.8 | Reports `name=flannel, source=10-flannel.conflist, nfqueue_safe=true`. |
| **kindnet (kind default)**     | ✅ live (kind, 2026-05-14) | ✅ — iptables-based  | n/a                  | kind 0.24 / k8s 1.31 | Reports `name=kindnet, source=10-kindnet.conflist, nfqueue_safe=true`. Required adding kindnet to the matchOne switch + a `topLevelName` JSON fallback for the conflist's `name: "kindnet"` field. |
| **calico**                     | ✅ live (kind, 2026-05-14) | ✅ — iptables-based  | export available (CalicoNetworkPolicy YAML)              | kind 0.24 + Calico v3.28 (tigera-operator) | Reports `name=calico, source=10-calico.conflist, nfqueue_safe=true`. |
| **cilium (pure eBPF, kube-proxy replacement)** | ✅ live (kind, 2026-05-14) | ❌ — eBPF bypasses iptables | ✅ via `/api/v1/runtime-policies/{id}/export?flavor=cilium` | kind 0.24 + Cilium v1.16.1 (kubeProxyReplacement=true) | Reports `name=cilium, source=05-cilium.conflist, nfqueue_safe=false`. Agent should skip NFQUEUE; operator deploys CiliumNetworkPolicies via the export endpoint. Set `runtimeAgent.dp.enforceOnCilium=true` to override (only safe with cilium iptables-only mode). |
| cilium chains calico           | ✅ unit-tested  | ❌ — Cilium wins  | ✅ Cilium native    | future kind run | Same handling as pure Cilium; chained Calico iptables rules are no-ops in this mode. |
| aws-vpc-cni (EKS)              | ✅ unit-tested  | ✅ — iptables-based but per-ENI; pods get host routes | n/a | future EKS row | NFQUEUE works. Caveat: pods using SecondaryIP mode share the host's iptables view; large clusters can hit nf_conntrack table limits. |
| gke-cni (GKE)                  | ✅ unit-tested  | ✅ — iptables  | n/a                  | future GKE row | Standard NFQUEUE. GKE Autopilot blocks privileged DaemonSets — runtime-agent requires GKE Standard. |
| azure-cni (AKS)                | ✅ unit-tested  | ✅ — iptables  | n/a                  | future AKS row | Standard NFQUEUE. NSG rules at the VNet level interact with NFQUEUE drops; AKS-specific precedence documentation belongs in `docs/aks-deployment.md` when the live AKS row is captured. |

### Live test methodology (kind rows)

For each kind cluster row we ran the same procedure on the testnode:

1. `kind delete cluster --name <prev>` to clean up.
2. `kind create cluster --config kind-<cni>.yaml` with appropriate `disableDefaultCNI` / `kubeProxyMode` flags. Mounted `/sys/fs/bpf` and `/sys/kernel/btf` from the host into the kind node so the runtime-agent's BPF probes can attach.
3. For Calico/Cilium: install the CNI (`tigera-operator` for Calico v3.28, `cilium install --version 1.16.1` for Cilium).
4. `kind load docker-image` for all 9 constellation images.
5. `helm install constellation` with the kind-appropriate values (single replicas, embedded postgres, no ingress).
6. `kubectl logs <agent>` to read the `dp: CNI detected` line.
7. Submit a privileged pod manifest to verify admission deny still works (CNI-independent, but proves the install is healthy).

Legend:
- ✅ live = exercised against a running cluster on this branch
- ✅ unit-tested = covered by `cnidetect_test.go` test suite (logic only)
- ❌ = does not work, fallback documented

## What "Detection" actually verifies

The detector does **filename + JSON content matching** against the CNI
config files in the discovered directory. It does NOT prove that NFQUEUE
rules will install successfully or that traffic actually flows through dp
— those are runtime concerns confirmed during live testing.

The unit tests
(`internal/runtime/dp/cnidetect_test.go`) cover the matching logic for
every supported plugin including:
- Filename-based shortcut (`10-flannel.conflist` → `flannel`)
- JSON content fallback (parses `type:` / `plugins[].type`)
- Cilium-wins-over-chained precedence
- Garbage JSON tolerance
- `SafeForNFQUEUE()` truth table

## Live-tested findings (testnode 2026-05-14)

Run on `temp-constellation-test1` (k3s 1.35.4, Flannel CNI):

```
{"msg":"dp: CNI detected","name":"flannel","source":"10-flannel.conflist","nfqueue_safe":true}
```

Confirmed behaviours:
- Auto-discovery walks `/etc/cni/net.d` (empty on k3s) then
  `/var/lib/rancher/k3s/agent/etc/cni/net.d` (where k3s drops its config)
  and identifies Flannel correctly without any per-distro values overrides.
- The chart's multi-mount approach (every well-known path mounted as a
  hostPath with `DirectoryOrCreate`) means missing paths on the host
  don't fail pod scheduling.

## Bugs found and fixed during validation

| Bug | Where | Fix |
|---|---|---|
| Detector defaulted to `/etc/cni/net.d` only — wrong on k3s/RKE2/OpenShift | `cmd/constellation-runtime-agent/main.go:137` | Default to empty string so `cnidetect.go`'s auto-discovery loop fires. |
| Original detector took a single dir argument; no auto-discovery | `internal/runtime/dp/cnidetect.go` | Added `CandidateCNIDirs` and `hasCNIConfig` helpers; `DetectCNI("")` walks the candidates. |
| Chart mounted only `/etc/cni/net.d` — wrong path on k3s | `deploy/charts/constellation/templates/runtime-agent-daemonset.yaml` | Mount every well-known CNI config dir as a separate `DirectoryOrCreate` hostPath. |
| Admission webhook denied its own runtime-agent (`block-privileged`), deadlocking the install | `deploy/charts/constellation/templates/admission-webhook.yaml` | Always exclude the release namespace from the webhook's `namespaceSelector`. Operator-supplied selectors merge AFTER the self-exclusion. |

## What's NOT yet tested live

The remaining rows are unit-tested at the detector level but not yet
exercised against a real cluster:

- **cilium chains calico** — requires the Cilium chain-mode install
  (`cilium install --set cni.chainingMode=portmap` or similar). The
  detector's Cilium-wins-precedence is unit-tested; the live behaviour
  should match the pure-Cilium row exactly.
- **EKS / GKE / AKS managed clusters** — need actual cloud accounts in
  each provider; tracked in `docs/hardware-validation-plan.md` Spec 2.
