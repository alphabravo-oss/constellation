"""End-to-end check that the runtime-agent's host-facts collector
(Slice A of the NeuVector-style host inventory work) snapshots the
host and the API surfaces it.

Path:

    runtime-agent          -- POST /api/v1/host-facts:report (runtime-agent-token)
        ↓
    constellation-api      -- upsert host_facts row (one per cluster+node)
        ↓
    GET /api/v1/host-facts -- caller (user JWT) sees the latest snapshot

The agent posts every CONSTELLATION_HOSTSCAN_INTERVAL (chart default 5m).
For test runs we wait up to ~90s for the first POST (the agent fires
once on launch, no interval-wait needed for the first sample).
"""
from __future__ import annotations

import time

import pytest


def _wait_for_host_facts(api, timeout: float = 90.0, poll: float = 5.0):
    """Poll GET /api/v1/host-facts until at least one row appears."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = api.get_json("/api/v1/host-facts")
        items = last.get("items", [])
        if items:
            return items
        time.sleep(poll)
    pytest.fail(
        f"no host-facts after {timeout:.0f}s — agent never POST'd. "
        f"last response: {last!r}"
    )


def test_host_facts_arrive(api):
    """The agent should report a snapshot within ~90s of pod start."""
    items = _wait_for_host_facts(api)
    assert items, "host-facts list was empty"
    # Snapshot for the only node in this single-node test cluster.
    row = items[0]
    assert row["node"], "row missing 'node'"
    assert row.get("observed_at"), "row missing 'observed_at'"


def test_host_facts_kernel_and_os_populated(api):
    """The snapshot should carry kernel + OS info the collector reads
    from uname + /etc/os-release."""
    items = _wait_for_host_facts(api)
    row = items[0]
    # Lifted columns.
    assert row.get("kernel_release", "").count(".") >= 2, (
        f"kernel_release looks malformed: {row.get('kernel_release')!r}"
    )
    assert row.get("os_id"), f"os_id missing — collector didn't read os-release: {row!r}"
    assert row.get("arch") in ("x86_64", "aarch64", "arm64"), row.get("arch")


def test_host_facts_nfqueue_capable(api):
    """On the Ubuntu testnode (kernel 6.8) NFQUEUE is supported; the
    collector should report nfqueue_capable=true so the UI can show
    the node as enforcement-capable.

    This mirrors what test_host_environment.py::test_required_kernel_modules
    asserts at the shell level — same fact, now flowing through the
    agent's snapshot path."""
    items = _wait_for_host_facts(api)
    row = items[0]
    # nfqueue_capable may not be a column the api hydrated yet; fall
    # back to the embedded facts payload.
    nf = row.get("nfqueue_capable")
    if nf is None:
        facts = row.get("facts") or {}
        net = facts.get("net") or {}
        nf = net.get("iptables_nfqueue") or net.get("nfqueue_loaded")
    assert nf is True, (
        f"expected nfqueue capability on the Ubuntu testnode, got {nf!r}. "
        f"row: {row!r}"
    )


def test_host_facts_cni_detected(api):
    """The agent's CNI detector should resolve a name (flannel on k3s,
    kindnet on kind, etc.) and the snapshot should carry it."""
    items = _wait_for_host_facts(api)
    row = items[0]
    cni = row.get("cni_name", "")
    if not cni:
        facts = row.get("facts") or {}
        cni_obj = facts.get("cni") or {}
        cni = cni_obj.get("name", "")
    # k3s defaults to flannel; k3d uses flannel too. Accept any known
    # name rather than pin to one.
    assert cni in {"flannel", "calico", "cilium", "kindnet", "weave", "ovn-kubernetes"}, (
        f"unexpected or missing CNI in host-facts: {cni!r}"
    )


def _wait_for_host_processes(api, timeout: float = 90.0, poll: float = 5.0):
    """Poll GET /api/v1/host-processes until a snapshot appears."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = api.get_json("/api/v1/host-processes")
        items = last.get("items", [])
        if items:
            return items
        time.sleep(poll)
    pytest.fail(
        f"no host-processes after {timeout:.0f}s — agent never POST'd. "
        f"last response: {last!r}"
    )


def test_host_processes_arrive(api):
    """Slice B: the agent's /proc walk should land in the API within ~90s."""
    items = _wait_for_host_processes(api)
    row = items[0]
    assert row["node"], "row missing 'node'"
    assert row.get("observed_at"), "row missing 'observed_at'"
    assert row["process_count"] > 0, (
        f"process_count is 0 — the collector found no userspace pids: {row!r}"
    )


def test_host_processes_contains_pid1(api):
    """A running k3s node always has pid 1 (the init or k3s server)."""
    items = _wait_for_host_processes(api)
    row = items[0]
    payload = row.get("payload") or {}
    procs = payload.get("items") or []
    assert procs, "snapshot payload empty"
    pid1 = next((p for p in procs if p.get("pid") == 1), None)
    assert pid1 is not None, (
        f"pid 1 missing from snapshot — agent may be reading container's "
        f"/proc instead of host /proc. Sample of pids seen: "
        f"{[p.get('pid') for p in procs[:10]]}"
    )
    assert pid1.get("comm"), f"pid 1 has empty comm: {pid1!r}"


def test_host_processes_excludes_kernel_threads(api):
    """The default collector filters kthreads (empty cmdline) so the
    payload is bounded and useful for inventory."""
    items = _wait_for_host_processes(api)
    row = items[0]
    payload = row.get("payload") or {}
    procs = payload.get("items") or []
    empty_cmdline = [p for p in procs if not p.get("cmdline")]
    # Some userspace daemons re-exec via prctl and have empty cmdline;
    # tolerate a handful but if MOST processes have empty cmdline the
    # filter is broken.
    assert len(empty_cmdline) < len(procs) / 4, (
        f"too many processes with empty cmdline ({len(empty_cmdline)}/{len(procs)}) "
        f"— kernel-thread filter likely broken"
    )


def _wait_for_host_containers(api, timeout: float = 120.0, poll: float = 5.0):
    """Poll GET /api/v1/host-containers until a snapshot appears.
    Longer timeout than other slices because crictl ps is a synchronous
    socket call that the agent only fires once a minute."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = api.get_json("/api/v1/host-containers")
        items = last.get("items", [])
        if items:
            return items
        time.sleep(poll)
    pytest.fail(
        f"no host-containers after {timeout:.0f}s — agent never POST'd. "
        f"last response: {last!r}"
    )


def test_host_containers_arrive(api):
    """Slice C: crictl-derived container list lands in the API."""
    items = _wait_for_host_containers(api)
    row = items[0]
    assert row["node"], "row missing 'node'"
    assert row["container_count"] > 0, (
        f"container_count is 0 — crictl saw no containers, but a "
        f"running k3s cluster always has at least the kube-system pods. "
        f"row: {row!r}"
    )
    assert row.get("runtime") in {"containerd", "crio", "docker"}, (
        f"unexpected runtime {row.get('runtime')!r}"
    )


def test_host_containers_includes_constellation_pods(api):
    """The agent should see itself + its peer pods in the snapshot."""
    items = _wait_for_host_containers(api)
    row = items[0]
    payload = row.get("payload") or {}
    conts = payload.get("items") or []
    names = {c.get("pod_namespace", "") + "/" + c.get("pod_name", "") for c in conts}
    # The runtime-agent pod itself must be in the snapshot.
    have_agent = any("runtime-agent" in n for n in names)
    assert have_agent, (
        f"runtime-agent pod missing from container snapshot — crictl "
        f"may be hitting the wrong socket. Pod names seen: {sorted(names)[:10]}"
    )


def _wait_for_host_packages(api, timeout: float = 120.0, poll: float = 5.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = api.get_json("/api/v1/host-packages")
        items = last.get("items", [])
        if items:
            return items
        time.sleep(poll)
    pytest.fail(
        f"no host-packages after {timeout:.0f}s — agent never POST'd. "
        f"last response: {last!r}"
    )


def test_host_packages_arrive(api):
    """Slice D.1: agent enumerates dpkg/apk packages and POSTs them.
    On Ubuntu testnode this should resolve to source='dpkg' and a
    package count in the hundreds."""
    items = _wait_for_host_packages(api)
    row = items[0]
    assert row["node"], "row missing 'node'"
    assert row.get("source") in {"dpkg", "rpm", "apk"}, (
        f"unexpected package source: {row.get('source')!r}"
    )
    assert row["package_count"] > 50, (
        f"package_count={row['package_count']} suspiciously low for a real host"
    )


def test_host_packages_include_common_debian(api):
    """On the Ubuntu testnode we expect to see a few well-known packages."""
    items = _wait_for_host_packages(api)
    row = items[0]
    if row.get("source") != "dpkg":
        pytest.skip(f"non-dpkg host ({row.get('source')})")
    payload = row.get("payload") or {}
    names = {p["name"] for p in payload.get("items") or []}
    # bash is on every Debian-family host. systemd is on every modern Ubuntu.
    must_have = {"bash"}
    missing = must_have - names
    assert not missing, (
        f"expected packages missing from snapshot: {missing}. "
        f"package_count={row['package_count']}; sample={sorted(names)[:5]}"
    )


def _wait_for_host_cis(api, timeout: float = 90.0, poll: float = 5.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = api.get_json("/api/v1/host-cis")
        items = last.get("items", [])
        if items:
            return items
        time.sleep(poll)
    pytest.fail(
        f"no host-cis after {timeout:.0f}s — agent never POST'd. "
        f"last response: {last!r}"
    )


def test_host_cis_arrive(api):
    """Slice E: agent runs in-tree CIS checks and POSTs a report."""
    items = _wait_for_host_cis(api)
    row = items[0]
    assert row["node"], "row missing 'node'"
    # Counters are non-negative and sum to a positive total.
    total = row["passed"] + row["failed"] + row["warned"] + row["skipped"]
    assert total > 0, f"no CIS checks ran: {row!r}"
    assert row.get("profile"), f"profile missing: {row!r}"


def test_host_cis_has_known_checks(api):
    """The default check set must include at least one fail-path check
    (file modes), one sysctl check, and one ssh config check."""
    items = _wait_for_host_cis(api)
    row = items[0]
    payload = row.get("payload") or {}
    checks = payload.get("checks") or []
    ids = {c["id"] for c in checks}
    expected_subset = {"3.2.1", "3.3.1", "5.1.2", "5.1.3", "5.2.5", "5.2.10"}
    missing = expected_subset - ids
    assert not missing, (
        f"CIS check set missing expected IDs: {missing}. "
        f"Got: {sorted(ids)}"
    )


def _wait_for_host_vulnerabilities(api, timeout: float = 180.0, poll: float = 5.0):
    """Poll GET /api/v1/host-vulnerabilities until a vuln row appears.
    Long timeout because the scan fires asynchronously off the agent's
    host-packages POST and the bundledb query batch takes a few seconds
    against the full Ubuntu package list."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = api.get_json("/api/v1/host-vulnerabilities")
        items = last.get("items", [])
        if items:
            return last
        time.sleep(poll)
    return last  # don't fail here — let the assertion in the test decide


def test_host_vulnerabilities_endpoint(api):
    """The read endpoint must return the standard shape (items + summary)
    even when no vulns have been matched yet. Validates the API surface
    independent of bundle availability."""
    resp = api.get_json("/api/v1/host-vulnerabilities")
    assert "items" in resp, f"missing 'items' in response: {resp!r}"
    assert "summary" in resp, f"missing 'summary' in response: {resp!r}"
    summary = resp["summary"]
    for bucket in ("critical", "high", "medium", "low", "unknown"):
        assert bucket in summary, f"summary missing bucket {bucket!r}"


def test_vulndb_status_endpoint(api):
    """GET /api/v1/vulndb/status returns metadata about the currently loaded
    bundle. On the testnode the bbolt is mounted at
    /var/lib/constellation/vulndb.bbolt so we expect present=true and a
    bundle_version. If the bbolt is missing, present=false and no bundle field
    is also valid."""
    resp = api.get_json("/api/v1/vulndb/status")
    assert "path" in resp, f"missing 'path' in response: {resp!r}"
    assert "present" in resp, f"missing 'present' in response: {resp!r}"
    if resp.get("present"):
        # When present, basic bundle metadata should be readable.
        b = resp.get("bundle") or {}
        # Production bundles always carry these; if they're missing
        # the bbolt is broken / corrupt.
        assert b.get("schema_version"), f"bundle missing schema_version: {resp!r}"
        assert resp.get("size_bytes", 0) > 0, f"present but zero-size: {resp!r}"


def test_host_vulnerabilities_populated(api):
    """After the agent POSTs host-packages, scanner workers should populate
    unified host vulnerability findings. Skips if the bundle file isn't
    present on the cluster (env without DB)."""
    resp = _wait_for_host_vulnerabilities(api)
    items = resp.get("items", []) if resp else []
    if not items:
        pytest.skip(
            "no host-vulnerabilities populated — bundle may be missing "
            "at /var/lib/constellation/vulndb.bbolt on the cluster node. "
            f"summary: {resp.get('summary') if resp else 'none'}"
        )
    # Validate the row shape on any one returned.
    row = items[0]
    for field in ("node", "package_name", "vuln_id", "source"):
        assert row.get(field), f"row missing required field {field!r}: {row!r}"
    assert row["source"] == "vulndb", (
        f"source = {row['source']!r}, want 'vulndb' — wrong matcher wired?"
    )


def test_host_facts_btf_present(api):
    """On any modern Ubuntu kernel /sys/kernel/btf/vmlinux exists. The
    BPF probes won't load without it; this is the same test as
    test_host_environment.py::test_btf_present but exercising the
    agent's reporter, not a kubectl-exec probe."""
    items = _wait_for_host_facts(api)
    row = items[0]
    btf = row.get("btf_present")
    if btf is None:
        facts = row.get("facts") or {}
        btf = (facts.get("bpf") or {}).get("btf_present")
    assert btf is True, f"BTF should be present on this kernel — got {btf!r}: {row!r}"
