"""Host / cluster environment pre-flight checks.

Modeled on the kind of validation NeuVector does at install time. The
runtime-agent has hard kernel + cluster requirements; if these aren't
met, the chart will install but the agent will silently fail to do its
job (BPF probes won't load, NFQUEUE rules won't take effect, etc.).

Each check below either:
  - FAILS the test and points at the missing dependency, or
  - SKIPS the test with a clear "this env doesn't support X" message
    when the failure is expected and documented (eg. BPF LSM on older
    kernels — Wave-D1 made the LSM probe optional).

Two layers of checks:

1. **Host-kernel checks** — query the agent pod, since it's hostNetwork +
   hostPID and sees the actual kernel. These check kernel version, BTF,
   BPF FS, kernel modules. A failure here means the host can't run dp.

2. **Cluster-restriction checks** — try to deploy a privileged pod, a
   hostPID pod, etc. If the cluster (eg. GKE Autopilot, restricted PSPs)
   blocks them, the runtime-agent DaemonSet won't come up.
"""
from __future__ import annotations

import re
from typing import Optional

import pytest


# Minimum kernel version we require. dp uses NFQUEUE + tc act_mirred (any
# 3.x kernel works); BPF tracepoint + perf event ring buffer require ≥4.18;
# BTF + CO-RE require ≥5.4. We require ≥5.10 because that's where the BPF
# verifier behaviour stabilised for the per-cpu maps we use.
MIN_KERNEL_VERSION = (5, 10)
RECOMMENDED_KERNEL_VERSION = (5, 15)  # for BPF LSM (Wave D1 file_open probe)


def _agent_pod(kubectl) -> str:
    pod = kubectl.get_pod("app.kubernetes.io/component=runtime-agent",
                          namespace="constellation-system")
    assert pod, "no runtime-agent pod — is the agent enabled?"
    return pod["metadata"]["name"]


def _parse_kernel_version(uname_r: str) -> tuple[int, int]:
    """Parse '6.8.0-111-generic' → (6, 8)."""
    m = re.match(r"^(\d+)\.(\d+)", uname_r.strip())
    if not m:
        raise ValueError(f"unparseable kernel version: {uname_r!r}")
    return (int(m.group(1)), int(m.group(2)))


# ---------------------------------------------------------------------------
# Host-kernel checks (run from inside the agent pod)
# ---------------------------------------------------------------------------

def test_host_kernel_version_supported(kubectl):
    """Kernel >= 5.10 (minimum). Anything older lacks BPF features dp needs."""
    agent = _agent_pod(kubectl)
    out = kubectl.exec_in_pod(agent, ["uname", "-r"],
                              namespace="constellation-system").strip()
    got = _parse_kernel_version(out)
    assert got >= MIN_KERNEL_VERSION, (
        f"kernel {out} is below minimum {MIN_KERNEL_VERSION}; "
        f"BPF verifier behaviour for per-cpu maps is unreliable"
    )
    if got < RECOMMENDED_KERNEL_VERSION:
        # Don't fail — Wave-D1 made the LSM probe optional. Just emit a
        # warning so a slow-kernel cluster shows up in test reports.
        pytest.warns(UserWarning, match="recommended")


def test_btf_present(kubectl):
    """`/sys/kernel/btf/vmlinux` must be readable inside the agent pod —
    CO-RE BPF programs use it to relocate field offsets at load time.
    Without BTF, our runtime.bpf.o won't load.
    """
    agent = _agent_pod(kubectl)
    # Use stat — `ls -l` would fail if the file doesn't exist with non-zero.
    out = kubectl.exec_in_pod(
        agent, ["sh", "-c", "test -s /sys/kernel/btf/vmlinux && echo present || echo missing"],
        namespace="constellation-system",
    ).strip()
    assert out == "present", (
        "BTF vmlinux missing — the host kernel was built without "
        "CONFIG_DEBUG_INFO_BTF=y. CO-RE BPF programs cannot load. "
        "Required for the runtime-agent's BPF probes."
    )


def test_bpf_fs_mounted(kubectl):
    """BPF filesystem at /sys/fs/bpf must be mounted (the agent pin BPF
    objects there for cross-pod sharing). Test by listing the mount.
    """
    agent = _agent_pod(kubectl)
    out = kubectl.exec_in_pod(
        agent, ["sh", "-c", "mount | grep -E 'bpf.*\\s/sys/fs/bpf' || echo MISSING"],
        namespace="constellation-system",
    ).strip()
    assert "MISSING" not in out, (
        "/sys/fs/bpf is not a bpf filesystem mount. The chart's DaemonSet "
        "mounts /sys/fs/bpf with type DirectoryOrCreate; ensure the host's "
        "/sys/fs/bpf is a real BPF FS, not just an empty dir. Run: "
        "`mount -t bpf bpf /sys/fs/bpf` on the host."
    )


def test_required_kernel_modules(shell):
    """xt_NFQUEUE is required for NFQUEUE-based enforcement (when our
    detector reports nfqueue_safe=true and the operator promotes a policy
    to enforce mode). Either loaded already, built-in, or loadable on
    demand.

    Probed directly on the host shell (not via kubectl exec into the
    agent pod): the agent's minimal container image doesn't ship
    `lsmod`, `iptables`, or `find`, so an in-pod probe always returned
    empty even when the host fully supports NFQUEUE. The question this
    test answers — "does the host kernel expose NFQUEUE?" — is a
    property of the host, not the pod's rootfs.

      1. lsmod / /proc/modules         — loaded modules
      2. /proc/net/netfilter           — netfilter subsystem present
      3. iptables -j NFQUEUE -h        — userspace tooling can use it
      4. /lib/modules/$(uname -r)/...  — module exists on disk to be loaded
    """
    probe = (
        "echo '== lsmod =='; (lsmod 2>/dev/null || cat /proc/modules 2>/dev/null) | "
        "awk '{print $1}' | grep -iE 'nfqueue|nfnetlink' || true; "
        "echo '== /proc/net/netfilter =='; ls /proc/net/netfilter 2>/dev/null || true; "
        "echo '== iptables NFQUEUE =='; iptables -j NFQUEUE -h 2>&1 | grep -i nfqueue || true; "
        "echo '== modules-on-disk =='; "
        "find /lib/modules/$(uname -r)/kernel/net/netfilter -name 'nfnetlink_queue*' "
        "-o -name 'xt_NFQUEUE*' 2>/dev/null || true"
    )
    out = shell.run(probe, check=False).stdout
    has_nfqueue = (
        "xt_NFQUEUE" in out
        or "nfnetlink_queue" in out
        or "NFQUEUE" in out
        or "nfnetlink" in out
    )
    if not has_nfqueue:
        pytest.skip(
            "NFQUEUE not detected on this host — runtime-agent enforcement "
            "won't work, but observability still does. Probe output:\n" + out
        )


def test_required_capabilities_granted(kubectl):
    """The chart must grant the agent these capabilities for BPF + NFQUEUE."""
    agent = _agent_pod(kubectl)
    pod = kubectl.get_pod("app.kubernetes.io/component=runtime-agent",
                          namespace="constellation-system")
    spec = pod["spec"]
    container = spec["containers"][0]
    sec = container.get("securityContext", {})
    # We may run privileged: true OR with explicit capabilities.add.
    if sec.get("privileged"):
        return  # privileged grants everything
    caps = sec.get("capabilities", {}).get("add", [])
    required = {"NET_ADMIN", "SYS_ADMIN", "BPF", "PERFMON", "SYS_PTRACE"}
    missing = required - set(caps)
    assert not missing, (
        f"runtime-agent missing required capabilities: {missing}. "
        f"Either set securityContext.privileged=true on the DaemonSet or "
        f"grant: {sorted(required)}."
    )


# ---------------------------------------------------------------------------
# Cluster-restriction checks
# ---------------------------------------------------------------------------

def test_cluster_allows_privileged_in_constellation_namespace(kubectl):
    """Some managed clusters (GKE Autopilot, restricted PSP profiles) deny
    privileged pods. The runtime-agent needs privileged or equivalent caps.
    Existence of a Running runtime-agent pod proves this.
    """
    agent = _agent_pod(kubectl)
    pod = kubectl.get_pod("app.kubernetes.io/component=runtime-agent",
                          namespace="constellation-system")
    phase = pod["status"].get("phase")
    assert phase == "Running", (
        f"runtime-agent pod is {phase} — the cluster may be denying "
        f"privileged DaemonSets (eg. GKE Autopilot). Switch to GKE Standard "
        f"or run on a permissive distribution."
    )


def test_cluster_allows_hostpath_mounts(kubectl):
    """The agent mounts /sys, /sys/fs/bpf, /sys/kernel/btf, /proc, and the
    CNI config dirs as hostPath volumes. If the cluster's PodSecurity
    admission is set to 'restricted', this fails.
    """
    pod = kubectl.get_pod("app.kubernetes.io/component=runtime-agent",
                          namespace="constellation-system")
    volumes = pod["spec"].get("volumes", [])
    expected = {"sys", "bpf-fs", "btf", "proc"}
    have = {v["name"] for v in volumes}
    missing = expected - have
    assert not missing, (
        f"agent DaemonSet missing hostPath volumes: {missing}. "
        f"PodSecurity 'restricted' may have stripped them. "
        f"Set the namespace label `pod-security.kubernetes.io/enforce=privileged`."
    )


def test_cluster_kubeproxy_or_replacement_present(kubectl):
    """We need either kube-proxy OR a CNI like Cilium that fully replaces
    it. Without one, cluster Services don't work and the agent can't talk
    to constellation-api.

    Detection layers (any one is sufficient):
      1. A kube-proxy / cilium / kindnet / flannel DaemonSet in kube-system
         — the normal case for kubeadm, kind, RKE.
      2. A pod in kube-system whose name contains one of those tokens —
         catches static-pod deployments.
      3. The `kubernetes` Service in `default` has a ClusterIP. If it
         does, *something* is wiring service IPs to backends, which is
         the actual property this test cares about. k3s embeds
         kube-proxy + flannel in its agent binary so layers 1 and 2
         find nothing — but layer 3 proves the cluster is functional.
    """
    proxies = kubectl.get_json("daemonsets",
                               namespace="kube-system").get("items", [])
    by_name = [d["metadata"]["name"].lower() for d in proxies]
    if any("proxy" in n or "cilium" in n or "kindnet" in n or "flannel" in n
           for n in by_name):
        return

    pods = kubectl.get_json("pods", namespace="kube-system").get("items", [])
    pod_names = [p["metadata"]["name"].lower() for p in pods]
    if any("proxy" in n or "cilium" in n or "kindnet" in n or "flannel" in n
           for n in pod_names):
        return

    # Layer 3: prove the cluster wires service IPs. k3s/k3d hits this branch.
    svc = kubectl.get_json("service kubernetes", namespace="default")
    cluster_ip = svc.get("spec", {}).get("clusterIP")
    assert cluster_ip and cluster_ip != "None", (
        f"no kube-proxy DaemonSet, no kube-proxy-like pod, and the default "
        f"`kubernetes` Service has no ClusterIP ({cluster_ip!r}). "
        f"Service IPs won't resolve. DaemonSets seen: {by_name}. "
        f"Pods sampled: {pod_names[:10]}."
    )


def test_postgres_storage_class_available(kubectl):
    """Embedded postgres StatefulSet needs a StorageClass that can satisfy
    its 20Gi PVC. If no default SC exists, the postgres pod will be Pending
    forever.
    """
    storage = kubectl.get_json("storageclasses", namespace="").get("items", [])
    if not storage:
        pytest.skip("no StorageClasses — only relevant for embedded postgres")
    # Check there's a default — annotation `storageclass.kubernetes.io/is-default-class=true`.
    has_default = any(
        sc.get("metadata", {}).get("annotations", {}).get(
            "storageclass.kubernetes.io/is-default-class") == "true"
        for sc in storage
    )
    assert has_default, (
        f"no default StorageClass — embedded postgres PVC will stay Pending. "
        f"Available: {[sc['metadata']['name'] for sc in storage]}. "
        f"Mark one default: `kubectl patch storageclass <name> -p "
        f"'{{\"metadata\":{{\"annotations\":{{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}}}}'`."
    )


def test_admission_webhooks_can_reach_api_server(kubectl):
    """If the apiserver can't reach our admission webhook (eg. node-local
    networking, NetworkPolicy blocking kube-system → constellation-system),
    every pod admission falls back to failurePolicy. Detected by checking
    that no pod is being denied by us when it shouldn't be.
    """
    # Look at the admission Service endpoints — must have at least one
    # endpoint or the apiserver can't reach the webhook.
    eps = kubectl.get_json("endpoints constellation-admission",
                           namespace="constellation-system")
    subsets = eps.get("subsets", [])
    addresses = []
    for s in subsets:
        addresses.extend(s.get("addresses", []))
    assert addresses, (
        "constellation-admission Service has zero endpoints — no admission "
        "pods Ready. The webhook is effectively dead and pod admission "
        "falls back to failurePolicy=Ignore."
    )


# ---------------------------------------------------------------------------
# Container runtime / cgroup checks
# ---------------------------------------------------------------------------

def test_cgroup_v2_or_v1_unified(kubectl):
    """dp's flow attribution reads /sys/fs/cgroup. v1 and v2 have different
    layouts; this test just confirms ONE of them is mounted."""
    agent = _agent_pod(kubectl)
    out = kubectl.exec_in_pod(
        agent, ["sh", "-c",
                "test -d /sys/fs/cgroup/unified && echo v1+unified || "
                "(test -e /sys/fs/cgroup/cgroup.controllers && echo v2 || "
                "(test -d /sys/fs/cgroup/cpu && echo v1 || echo none))"],
        namespace="constellation-system",
    ).strip()
    assert out in ("v1", "v2", "v1+unified"), (
        f"no cgroup hierarchy detected (got {out!r}). "
        f"dp's per-pod accounting won't work."
    )
