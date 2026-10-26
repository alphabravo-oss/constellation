# Network Enforcement Model (D-1 resolution / NET-INLINE-22)

> Records the historical **D-1** design resolution for **NET-INLINE-22**.
> The [current readiness plan](readiness-and-parity-plan.md) tracks qualification
> separately: Cilium uses CNI-native policy; inline WAF/DLP remains unavailable.

## The two backends

Constellation enforces network policy through **two** datapaths, selected by CNI
capability. They are complementary, not redundant.

### 1. CNI-native policy (PRIMARY — supported CNI profiles, including Cilium)

The netpolicy candidate lifecycle generates a real Kubernetes object per flavor —
`networking.k8s.io/v1 NetworkPolicy` (native), `cilium.io/v2 CiliumNetworkPolicy`
(cilium), and `projectcalico.org/v3 GlobalNetworkPolicy` (calico) — see
`internal/handler/netpolicy/network_policies.go` (all three rendered per
candidate) and `pkg/netpolicy` (`GenerateNative` / `GenerateCilium` /
`GenerateCalico`). The in-cluster `network-policy-applier` applies the flavor set
by `CONSTELLATION_NETWORK_POLICY_APPLIER_FLAVOR` (`cmd/constellation-netpolicy-applier`).

**This is enforced by the selected CNI's own dataplane.** On **Cilium/eBPF**, a
`CiliumNetworkPolicy` is enforced by Cilium (`egressDeny`/`ingressDeny`, `toFQDNs`,
L3/L4 + limited L7). Applied CNI policy is independent of the Constellation dp
process and can remain active across agent restarts. It is the primary path for
block-IP, isolation and segmentation. Each supported CNI/profile still needs
qualification; object generation alone does not prove the traffic verdict.
NeuVector also [documents Cilium support](https://open-docs.neuvector.com/basics/requirements/).
This architectural difference does not establish superior enforcement.

**On a Cilium cluster: set `netpolicy.flavor: cilium`.** The applier then emits
CiliumNetworkPolicy for every approved candidate and for the Phase-1 map actions
(block-IP already emits `CiliumNetworkPolicy` — see `internal/handler/network/enforcement.go`).

### 2. Inline dp NFQUEUE (SECONDARY — flannel-class / iptables CNIs only)

The runtime-agent's dp can sit **inline** on a pod's veth via NFQUEUE and issue a
real DROP/RESET verdict (`internal/runtime/dp/enforce.go`). This is what gives us
**L7/DPI/WAF inline enforcement** (OWASP CRS SQLi reset, DLP drop) that no CNI
NetworkPolicy can express — verified working (see the inline-enforce canary).

It is deliberately scoped to **iptables-class CNIs (flannel, kube-router, calico-iptables)**.
`internal/runtime/dp/cnidetect.go SafeForNFQUEUE()` returns **false for Cilium**
because Cilium's eBPF dataplane bypasses the iptables chains NFQUEUE hooks — an
NFQUEUE rule there simply never sees the packets. `cmd/constellation-runtime-agent/main.go`
gates inline on `SafeForNFQUEUE() || CONSTELLATION_DP_ENFORCE_ON_CILIUM`, so on
Cilium the inline path stays dormant by default and the agent runs tap/monitor only.
It uses `iptables --queue-bypass` so packets pass when no NFQUEUE listener is
available. That availability tradeoff and other failure cases require explicit
testing for the supported profile.

## Decision (D-1)

**CNI-native policy is the primary enforcement model on every cluster.** Inline dp
NFQUEUE is a **secondary** datapath whose job is the L7/DPI/WAF verdicts CNI policy
cannot express, and it runs only on iptables-class CNIs.

Therefore, on Cilium clusters:
- L3/L4 segmentation, block-IP, isolate → **CiliumNetworkPolicy** (applier `flavor: cilium`), subject to the qualified policy/profile scope.
- L7 WAF/DLP inline drop → **not available on Cilium** (NFQUEUE-blind). Requires either
  a future verdict hook, or a qualified iptables-class CNI profile. CNI-native
  L3/L4 policy does not substitute for payload inspection verdicts.

This design does not port NeuVector's tc/ovs veth port-pair intercept for Cilium.
CiliumNetworkPolicy supplies the primary L3/L4 path, with different failure and
policy semantics from inline interception. Comparative safety requires evidence
for the specific profiles being compared.

## Configuration matrix

| Cluster CNI | L3/L4 enforce | L7 WAF/DLP inline |
|---|---|---|
| Cilium (eBPF) | CiliumNetworkPolicy (`flavor: cilium`) | not available (NFQUEUE-blind) — run iptables CNI for L7 |
| flannel / kube-router | native NetworkPolicy **or** inline dp (`enforcement.network`) | inline dp (`enforcement.dpi` + labels) |
| Calico | GlobalNetworkPolicy (`flavor: calico`) or native, or inline (iptables mode) | inline dp (iptables mode) |

Enforcement gates (all default OFF, per-workload):
`enforcement.mode=protect` + `enforcement.network=true` (inline L3/L4) +
`enforcement.dpi=true` (inline L7) + pod labels
`dpi.constellation.alphabravo.io/{enforce,waf,dlp}=true`. CNI-native needs only an
approved policy candidate + the applier flavor for the cluster's CNI.
