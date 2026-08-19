"""A4 CNI detection — assert the agent reports the CNI the cluster fixture
expected. Skip when the cluster type doesn't have a stable expectation
(external clusters)."""
from __future__ import annotations

import pytest


def _agent_pod_name(kubectl) -> str:
    pod = kubectl.get_pod("app.kubernetes.io/component=runtime-agent",
                          namespace="constellation-system")
    assert pod, "no runtime-agent pod found"
    return pod["metadata"]["name"]


def _find_cni_log_line(kubectl) -> str:
    """The agent logs `dp: CNI detected` once at startup. Locate it in
    the JSON-formatted log (msg key is "dp: CNI detected", not just
    "CNI detected" with quotes around it)."""
    agent = _agent_pod_name(kubectl)
    log = kubectl.logs(agent, namespace="constellation-system", all_logs=True)
    for line in log.splitlines():
        if "dp: CNI detected" in line:
            return line
    return ""


def test_detects_expected_cni(deployed, kubectl):
    if not deployed.expected_cni:
        pytest.skip("cluster fixture didn't set expected_cni")
    line = _find_cni_log_line(kubectl)
    assert line, "no CNI detection log line"
    expected = deployed.expected_cni
    assert f'"name":"{expected}"' in line, \
        f"expected CNI={expected}, got line: {line}"


def test_nfqueue_safety_matches_cni(deployed, kubectl):
    """Cilium → nfqueue_safe=false; everything else → true."""
    if not deployed.expected_cni:
        pytest.skip("cluster fixture didn't set expected_cni")
    line = _find_cni_log_line(kubectl)
    assert line, "no CNI detection log line"
    expect_safe = deployed.expected_cni != "cilium"
    needle = f'"nfqueue_safe":{str(expect_safe).lower()}'
    assert needle in line, \
        f"expected {needle} for CNI={deployed.expected_cni}, got: {line}"
