"""Cluster abstraction.

A `Cluster` represents a Kubernetes cluster the test suite can talk to.
Either:
  - external: KUBECONFIG points at a pre-existing cluster
  - managed:  the harness brought it up via an Installer (k3s/k3d/kind)
              and is responsible for tearing it down

All tests interact through `Kubectl(cluster.shell, binary=cluster.kubectl_binary)`
so they don't need to know which kind of cluster they're running against.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .remote import LocalShell, Remote


@dataclass
class Cluster:
    """A live Kubernetes cluster reachable via `shell` and a kubectl binary.

    cluster_kind: 'k3s' | 'k3d' | 'kind' | 'external'
    expected_cni: name string we expect the agent's CNI detector to report
                  (or None if we don't care / can't predict)
    """
    name: str
    cluster_kind: str
    shell: Remote | LocalShell
    kubectl_binary: str = "kubectl"
    expected_cni: Optional[str] = None
    teardown_callback: Optional[callable] = None  # set by installer
    metadata: dict = field(default_factory=dict)

    def teardown(self) -> None:
        if self.teardown_callback:
            self.teardown_callback(self)
