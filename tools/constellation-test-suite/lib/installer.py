"""Cluster installers — provision a fresh k3s / k3d / kind cluster on the
target shell, and produce a Cluster object for tests to talk to.

Each installer is idempotent: re-running on a host that already has the
cluster reconnects to it rather than failing. This matters because
pytest-fixture caching can re-enter on a parametric run.
"""
from __future__ import annotations

import time

from .cluster import Cluster
from .remote import LocalShell, Remote


def ensure_prereqs(shell) -> None:
    """Install make, docker, kubectl, helm if missing. Idempotent."""
    # Quick check — `command -v` returns non-zero if missing.
    missing: list[str] = []
    for tool in ["docker", "kubectl", "helm", "make"]:
        r = shell.run(f"command -v {tool} >/dev/null 2>&1 && echo yes || echo no",
                      check=False)
        if "no" in r.stdout:
            missing.append(tool)
    if not missing:
        return

    # apt path (Ubuntu/Debian). For other distros this would need a switch.
    if "make" in missing or "docker" in missing:
        shell.run("apt-get update -q", timeout=300)
    if "make" in missing:
        shell.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -q make", timeout=300)
    if "docker" in missing:
        shell.run(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -q "
            "docker.io docker-buildx",
            timeout=600,
        )
        shell.run("systemctl enable --now docker", timeout=60)
    if "kubectl" in missing:
        shell.run(
            "curl -sLO 'https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl' "
            "&& install -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl",
            timeout=300,
        )
    if "helm" in missing:
        shell.run(
            "curl -sfL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash",
            timeout=300,
        )


def install_k3s(shell, *, name: str = "k3s-test") -> Cluster:
    """Install k3s on the given shell. Disables Traefik (chart manages
    its own ingress) and writes a world-readable kubeconfig.
    """
    ensure_prereqs(shell)
    # Re-use existing k3s install if present.
    r = shell.run("command -v k3s && systemctl is-active --quiet k3s "
                  "&& echo running || echo absent", check=False)
    if "running" not in r.stdout:
        shell.run(
            "curl -sfL https://get.k3s.io | "
            "INSTALL_K3S_EXEC='--disable=traefik --write-kubeconfig-mode=644' sh -",
            timeout=600,
        )
        # k3s leaves a dangling symlink at /root/.kube/config from previous installs;
        # remove it before linking to the fresh kubeconfig.
        shell.run("rm -f /root/.kube/config && mkdir -p /root/.kube && "
                  "ln -sf /etc/rancher/k3s/k3s.yaml /root/.kube/config")
    else:
        # Re-link kubeconfig in case a different shell uninstalled the previous link.
        shell.run("rm -f /root/.kube/config && mkdir -p /root/.kube && "
                  "ln -sf /etc/rancher/k3s/k3s.yaml /root/.kube/config")
    # Wait for node Ready.
    for _ in range(60):
        r = shell.run("kubectl get nodes 2>&1 || true", check=False)
        if " Ready " in r.stdout:
            break
        time.sleep(2)
    else:
        raise RuntimeError("k3s node never reached Ready")

    return Cluster(
        name=name,
        cluster_kind="k3s",
        shell=shell,
        kubectl_binary="kubectl",
        expected_cni="flannel",
        teardown_callback=lambda c: c.shell.run(
            "/usr/local/bin/k3s-uninstall.sh 2>&1 | tail -2; rm -f /root/.kube/config",
            check=False, timeout=120,
        ),
    )


def install_k3d(shell, *, name: str = "k3d-test", agents: int = 1) -> Cluster:
    """Install k3d (k3s-in-docker) and create a cluster.

    `agents` is the number of worker nodes. Default is single-server
    (agents=0) but multi-node is the more interesting test target since
    it exercises the agent's hostNetwork DaemonSet across nodes.
    """
    ensure_prereqs(shell)
    # Install k3d binary if missing.
    r = shell.run("command -v k3d || echo no", check=False)
    if "no" in r.stdout:
        shell.run(
            "curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash",
            timeout=300,
        )
    # Re-use cluster if present.
    r = shell.run(f"k3d cluster list -o json", check=False)
    if name in r.stdout:
        # Existing cluster — just re-attach kubeconfig.
        shell.run(f"rm -f /root/.kube/config && mkdir -p /root/.kube && "
                  f"k3d kubeconfig get {name} > /root/.kube/config", check=True)
    else:
        shell.run(
            f"k3d cluster create {name} --agents {agents} --wait --timeout 5m "
            f"--k3s-arg='--disable=traefik@server:0'",
            timeout=600,
        )
        shell.run(f"rm -f /root/.kube/config && mkdir -p /root/.kube && "
                  f"k3d kubeconfig get {name} > /root/.kube/config", check=True)
    # Wait for nodes.
    for _ in range(60):
        r = shell.run("kubectl get nodes 2>&1 || true", check=False)
        if r.stdout.count(" Ready ") >= (agents + 1):
            break
        time.sleep(2)
    else:
        raise RuntimeError("k3d nodes never reached Ready")

    return Cluster(
        name=name,
        cluster_kind="k3d",
        shell=shell,
        kubectl_binary="kubectl",
        expected_cni="flannel",   # k3d wraps k3s, same default CNI
        teardown_callback=lambda c: c.shell.run(
            f"k3d cluster delete {name} 2>&1 | tail -2",
            check=False, timeout=120,
        ),
    )


def install_kind(shell, *, name: str = "kind-test", cni: str = "kindnet") -> Cluster:
    """Install kind and create a cluster.

    cni == 'kindnet' (default) | 'calico' | 'cilium'. For non-default CNI
    we disable the bundled CNI on cluster create and install the
    requested one before declaring Ready.
    """
    ensure_prereqs(shell)
    r = shell.run("command -v kind || echo no", check=False)
    if "no" in r.stdout:
        shell.run(
            "curl -sLo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64 "
            "&& chmod +x /usr/local/bin/kind",
            timeout=120,
        )

    # Generate the cluster config.
    networking = ""
    if cni in ("calico", "cilium"):
        networking = "networking:\n  disableDefaultCNI: true\n"
        if cni == "cilium":
            networking += "  kubeProxyMode: none\n  podSubnet: 10.244.0.0/16\n"
        else:
            networking += "  podSubnet: 192.168.0.0/16\n"

    cfg = (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        f"name: {name}\n"
        f"{networking}"
        "nodes:\n"
        "  - role: control-plane\n"
        "    extraMounts:\n"
        "      - hostPath: /sys/fs/bpf\n"
        "        containerPath: /sys/fs/bpf\n"
        "      - hostPath: /sys/kernel/btf\n"
        "        containerPath: /sys/kernel/btf\n"
    )
    import base64
    encoded = base64.b64encode(cfg.encode()).decode()
    # Re-use existing cluster if present.
    existing = shell.run("kind get clusters 2>&1", check=False).stdout
    if name in existing.splitlines():
        # Already up — just re-export the kubeconfig.
        pass
    else:
        shell.run(
            f"echo {encoded} | base64 -d > /tmp/kind-{name}.yaml && "
            f"kind create cluster --config /tmp/kind-{name}.yaml --wait 30s",
            timeout=600,
        )
    shell.run(
        f"rm -f /root/.kube/config && mkdir -p /root/.kube && "
        f"kind export kubeconfig --name {name} --kubeconfig /root/.kube/config"
    )

    # Skip CNI install if we re-used an existing cluster (it's already wired).
    cluster_was_new = name not in existing.splitlines()
    if cni == "calico" and cluster_was_new:
        shell.run(
            "kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml",
            timeout=120,
        )
        time.sleep(5)
        shell.run(
            "kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/custom-resources.yaml",
            timeout=120,
        )
    elif cni == "cilium" and cluster_was_new:
        # cilium-cli should be on PATH; install if missing.
        r = shell.run("command -v cilium || echo no", check=False)
        if "no" in r.stdout:
            shell.run(
                "curl -sL https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz "
                "| tar xzf - -C /usr/local/bin/",
                timeout=300,
            )
        shell.run(
            f"cilium install --version 1.16.1 --set kubeProxyReplacement=true "
            f"--set k8sServiceHost={name}-control-plane --set k8sServicePort=6443 --wait",
            timeout=600,
        )

    # Wait for node Ready.
    for _ in range(120):
        r = shell.run("kubectl get nodes 2>&1 || true", check=False)
        if " Ready " in r.stdout:
            break
        time.sleep(2)
    else:
        raise RuntimeError(f"kind+{cni} node never reached Ready")

    expected_cni_map = {
        "kindnet": "kindnet",
        "calico": "calico",
        "cilium": "cilium",
    }
    return Cluster(
        name=name,
        cluster_kind="kind",
        shell=shell,
        kubectl_binary="kubectl",
        expected_cni=expected_cni_map[cni],
        metadata={"cni": cni},
        teardown_callback=lambda c: c.shell.run(
            f"kind delete cluster --name {name} 2>&1 | tail -2",
            check=False, timeout=120,
        ),
    )


def attach_external() -> Cluster:
    """Use whatever cluster $KUBECONFIG points at. No teardown."""
    shell = LocalShell()
    return Cluster(
        name="external",
        cluster_kind="external",
        shell=shell,
        kubectl_binary="kubectl",
        expected_cni=None,  # unknown; tests that need it can skip
        teardown_callback=None,
    )
