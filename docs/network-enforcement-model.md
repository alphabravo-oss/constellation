# Network Enforcement Model (D-1 resolution / NET-INLINE-22)

> Resolves decision **D-1** from `NEUVECTOR-PARITY-PLAN-2026-08.md` and closes
> **NET-INLINE-22** ("no inline enforcement on Cilium/eBPF CNIs").

## The two backends

Constellation enforces network policy through **two** datapaths, selected by CNI
capability. They are complementary, not redundant.

### 1. CNI-native policy (PRIMARY — all clusters, including Cilium)

The netpolicy candidate lifecycle generates a real Kubernetes object per flavor —
`networking.k8s.io/v1 NetworkPolicy` (native), `cilium.io/v2 CiliumNetworkPolicy`
(cilium), and `projectcalico.org/v3 GlobalNetworkPolicy` (calico) — see
`internal/handler/netpolicy/network_policies.go` (all three rendered per
candidate) and `pkg/netpolicy` (`GenerateNative` / `GenerateCilium` /
`GenerateCalico`). The in-cluster `network-policy-applier` applies the flavor set
by `CONSTELLATION_NETWORK_POLICY_APPLIER_FLAVOR` (`cmd/constellation-netpolicy-applier`).

**This is enforced by the CNI's own dataplane**, so it works everywhere — crucially
on **Cilium/eBPF**, where a `CiliumNetworkPolicy` is enforced by Cilium's eBPF
dataplane (`egressDeny`/`ingressDeny`, `toFQDNs`, L3/L4 + limited L7). This is
enforcement Constellation has that NeuVector does **not** — NV cannot emit CNI-native
policy. It is fail-open-safe (a dp crash cannot blackhole), survives agent restarts,
and is the correct answer for the "block IP / isolate workload / deny conversation"
actions (Phase 1) and for learned default-deny segmentation.

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
It is **fail-OPEN** (`iptables --queue-bypass`), a deliberate safety divergence from
NeuVector's fail-closed veth surgery.

## Decision (D-1)

**CNI-native policy is the primary enforcement model on every cluster.** Inline dp
NFQUEUE is a **secondary** datapath whose job is the L7/DPI/WAF verdicts CNI policy
cannot express, and it runs only on iptables-class CNIs.

Therefore, on Cilium clusters:
- L3/L4 segmentation, block-IP, isolate → **CiliumNetworkPolicy** (applier `flavor: cilium`). ✅ real enforcement.
- L7 WAF/DLP inline drop → **not available on Cilium** (NFQUEUE-blind). Requires either
  a future TC-BPF verdict hook, or running an iptables-class CNI. This is the one
  documented Cilium limitation; it is L7-only, and CNI-native covers all L3/L4.

We do **not** port NeuVector's tc/ovs veth port-pair intercept for Cilium: it is
the most dangerous code in NV (fail-closed veth surgery), and CiliumNetworkPolicy
already gives Cilium clusters a real, safer L3/L4 enforcement path NV lacks.

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
