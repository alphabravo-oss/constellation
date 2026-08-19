"""E1 perf sanity — short fortio runs (15s each) to confirm the agent
doesn't cause errors and adds plausible overhead.

This is a smoke version of the full E1 protocol in
docs/perf-baseline.md. The full protocol's 30-min profiles need a
different harness (live monitoring, multi-node scheduling); we just
catch regressions where the agent adds visible RTT or breaks fortio.
"""
from __future__ import annotations

import json
import time

FORTIO_NS = "perf-bench"

FORTIO_NS_YAML = f"""\
apiVersion: v1
kind: Namespace
metadata: {{ name: {FORTIO_NS} }}
---
apiVersion: apps/v1
kind: Deployment
metadata: {{ name: fortio-server, namespace: {FORTIO_NS} }}
spec:
  replicas: 1
  selector: {{ matchLabels: {{ app: fortio-server }} }}
  template:
    metadata: {{ labels: {{ app: fortio-server }} }}
    spec:
      containers:
        - name: fortio
          image: fortio/fortio:latest
          imagePullPolicy: IfNotPresent
          args: ["server", "-http-port", "8080"]
---
apiVersion: v1
kind: Service
metadata: {{ name: fortio-server, namespace: {FORTIO_NS} }}
spec:
  selector: {{ app: fortio-server }}
  ports:
    - {{ name: http, port: 8080, targetPort: 8080 }}
"""


def _ensure_fortio(kubectl) -> None:
    kubectl.apply_yaml(FORTIO_NS_YAML, namespace="", check=True)
    kubectl.wait_for_pods("app=fortio-server", namespace=FORTIO_NS, timeout=120)


def _run_fortio(kubectl, label: str, qps: int, duration: str) -> dict:
    """Spin a transient fortio load pod, return parsed JSON output."""
    kubectl.delete("pod", f"fortio-load-{label}", namespace=FORTIO_NS, check=False)
    time.sleep(1)
    # Use kubectl run with --restart=Never; capture stdout.
    cmd = (
        f"{kubectl.binary} -n {FORTIO_NS} run fortio-load-{label} "
        f"--rm -i --restart=Never "
        f"--image=fortio/fortio:latest --image-pull-policy=IfNotPresent "
        f"--command -- /usr/bin/fortio load -qps {qps} -t {duration} -c 8 "
        f"-keepalive -json - "
        f"http://fortio-server.{FORTIO_NS}.svc.cluster.local:8080/echo "
        f"2>/dev/null"
    )
    result = kubectl.shell.run(cmd, timeout=120)
    out = result.stdout
    # fortio emits multiple JSON things on stdout:
    #   1. Single-line log entries:  {"ts":...,"level":"info","msg":"Starting",...}
    #   2. A few non-JSON header lines ("Fortio 1.75.1 running...")
    #   3. The MULTI-LINE result object — starts on a line that's literally `{`
    #      and contains keys like "RunType", "RequestedQPS", "DurationHistogram".
    #   4. kubectl run --rm appends `pod "..." deleted`.
    # The result object is the only one whose first line is just '{' — use
    # that as the marker, then balance-count braces from there.
    lines = out.splitlines()
    start_line = -1
    for i, line in enumerate(lines):
        if line.strip() == "{":
            start_line = i
            break
    if start_line < 0:
        raise ValueError(
            f"no fortio result JSON in output (first 500 chars):\n{out[:500]}"
        )
    # Re-join from the marker line, then balance-count.
    blob = "\n".join(lines[start_line:])
    depth = 0
    in_str = False
    escape = False
    end = -1
    for i, ch in enumerate(blob):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        raise ValueError(f"unterminated fortio result JSON:\n{blob[:500]}")
    return json.loads(blob[:end])


def _percentile(d: dict, p: int) -> float:
    for x in d["DurationHistogram"]["Percentiles"]:
        if x["Percentile"] == p:
            return x["Value"] * 1000.0  # ms
    return 0.0


def test_perf_smoke_with_agent(kubectl):
    """1k qps for 15s with the agent on. Must complete with 0 non-200s and
    p99 < 50ms (loose bound — sanity check, not perf bar)."""
    _ensure_fortio(kubectl)
    d = _run_fortio(kubectl, "smoke", qps=1000, duration="15s")
    # fortio emits RequestedQPS as a STRING, not int — be lenient.
    assert int(d["RequestedQPS"]) == 1000
    rc = d.get("RetCodes", {})
    non_200 = {k: v for k, v in rc.items() if k != "200"}
    assert not non_200, f"non-200 responses during smoke: {non_200}"
    p99 = _percentile(d, 99)
    assert p99 < 50, f"p99 latency {p99:.2f}ms is suspiciously high"
    # Sanity: at least 90% of target QPS achieved (kind/k3s on a single
    # node can dip a bit under sustained load — 90% catches real regressions
    # without flaking on noise).
    actual = d["ActualQPS"]
    assert actual >= 900, f"actual qps {actual} far below target 1000"
