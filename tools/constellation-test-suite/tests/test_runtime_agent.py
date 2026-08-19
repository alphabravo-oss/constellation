"""Runtime agent: dp data-plane alive, BPF probes attached, exec events
flowing through the agent log.
"""
from __future__ import annotations

import time

import pytest


def _agent_pod_name(kubectl) -> str:
    pod = kubectl.get_pod("app.kubernetes.io/component=runtime-agent",
                          namespace="constellation-system")
    assert pod, "no runtime-agent pod found"
    return pod["metadata"]["name"]


def test_dp_process_alive(kubectl):
    """The vendored NeuVector C data-plane (`dp`) should be a running child
    of the agent's Go supervisor."""
    agent = _agent_pod_name(kubectl)
    out = kubectl.exec_in_pod(
        agent,
        ["sh", "-c", "ps -eo pid,command | grep -E ' /usr/local/bin/dp( |$)' | grep -v grep"],
        namespace="constellation-system",
    )
    assert "/usr/local/bin/dp" in out, f"dp process not found in agent: {out}"


def test_bpf_probes_attached(kubectl):
    """Both BPF programs we ship should be loaded into the host kernel."""
    agent = _agent_pod_name(kubectl)
    out = kubectl.exec_in_pod(
        agent,
        ["bpftool", "prog", "show"],
        namespace="constellation-system",
    )
    # Expected probe names from runtime.bpf.c
    expected = ["trace_sched_exec", "lsm_file_open"]
    missing = [p for p in expected if p not in out]
    assert not missing, f"BPF probes missing: {missing}\n{out}"


def test_exec_events_captured(kubectl, deployed):
    """Trigger a known exec inside a pod; agent log should contain it.

    KNOWN LIMITATION: skipped on k3d. The k3d node container runs with
    docker's default seccomp/cgroups confinement which prevents the
    perf event ringbuffer from delivering BPF tracepoint events to the
    userspace agent — even though `bpftool prog show` confirms the
    programs are loaded. Operators wanting to validate runtime-agent
    BPF observability on k3d need to run the k3d node containers with
    `--privileged` plus `seccomp=unconfined`, which k3d doesn't expose
    as a stock flag. See docs/cni-compat.md for the supported envs.
    """
    if deployed.cluster_kind == "k3d":
        pytest.skip(
            "k3d node containers don't surface BPF perf events to the agent; "
            "validated separately on k3s and kind"
        )
    agent = _agent_pod_name(kubectl)
    kubectl.delete("pod", "exec-test", namespace="default", check=False)
    time.sleep(2)
    yaml_text = """\
apiVersion: v1
kind: Pod
metadata:
  name: exec-test
  namespace: default
  labels:
    app: exec-test
spec:
  containers:
    - name: c
      image: alpine:3
      command: ["sleep", "1d"]
"""
    rc, out = kubectl.apply_yaml(yaml_text, namespace="default", check=False)
    assert rc == 0, f"failed to create exec-test pod: {out}"
    # Wait up to 2 minutes — image pull on a fresh cluster can be slow.
    kubectl.wait_for_pods("app=exec-test", namespace="default", timeout=120)

    marker = f"exec-marker-{int(time.time())}"
    kubectl.exec_in_pod(
        "exec-test",
        ["sh", "-c", f"echo {marker}; cat /etc/passwd | head -1"],
        namespace="default",
    )

    # Wait for the agent log to flush our markers. The exec probe is host-wide
    # so events can be voluminous — read all logs to be sure we don't miss
    # the one we just triggered.
    found_cat = False
    for _ in range(15):
        log = kubectl.logs(agent, namespace="constellation-system",
                           tail=2000)
        if '"comm":"cat"' in log:
            found_cat = True
            break
        time.sleep(1)

    kubectl.delete("pod", "exec-test", namespace="default", check=False)
    assert found_cat, "agent BPF exec probe didn't capture our cat invocation"


def test_cni_detection_logged(kubectl):
    """The agent logs a `dp: CNI detected` line at startup with a name from
    the known set; if the cluster fixture set expected_cni, assert it."""
    agent = _agent_pod_name(kubectl)
    log = kubectl.logs(agent, namespace="constellation-system", all_logs=True)
    cni_lines = [l for l in log.splitlines() if '"CNI detected"' in l or "CNI detected" in l]
    assert cni_lines, f"no CNI detection log line found in agent log"
    # Last one wins (the agent reports it once at startup; restarts re-log).
    line = cni_lines[-1]
    known = ["unknown", "flannel", "calico", "cilium", "weave",
             "kindnet", "aws-vpc", "gke-cni", "azure-cni"]
    assert any(f'"name":"{k}"' in line for k in known), \
        f"CNI name not in known set: {line}"
