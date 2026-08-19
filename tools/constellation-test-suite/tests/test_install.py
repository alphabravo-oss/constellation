"""Verify the helm install left the cluster in the expected shape:
all 8 expected pods Running, schema migrated to head, and every
machine-identity Secret present."""
from __future__ import annotations


EXPECTED_COMPONENTS = [
    "api", "operator", "discoverer", "admission", "frontend",
    "postgres", "runtime-agent", "scanner",
]


def test_pods_all_running(kubectl):
    """Every expected component has at least one Running 1/1 pod."""
    pods = kubectl.list_pods(namespace="constellation-system")
    by_component: dict[str, list[dict]] = {}
    for p in pods:
        c = p.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component")
        by_component.setdefault(c, []).append(p)

    missing = [c for c in EXPECTED_COMPONENTS if not by_component.get(c)]
    assert not missing, f"missing components: {missing} (saw: {sorted(by_component)})"

    not_ready = []
    for component in EXPECTED_COMPONENTS:
        for pod in by_component[component]:
            phase = pod["status"].get("phase")
            ready = all(c.get("ready", False)
                        for c in pod["status"].get("containerStatuses", []))
            if phase != "Running" or not ready:
                not_ready.append((pod["metadata"]["name"], phase,
                                  pod["status"].get("containerStatuses", [])))
    assert not not_ready, f"pods not Ready: {not_ready}"


def test_required_secrets_present(kubectl):
    """The chart's bootstrap Hooks must have produced these Secrets."""
    required = [
        "constellation-admission-tls",      # admission webhook TLS
        "constellation-admin-credentials",  # bootstrap admin password
        "constellation-runtime-agent-token",
        "constellation-scanner-token",
        "constellation-postgres",
    ]
    secrets = kubectl.get_json("secrets", namespace="constellation-system")
    names = {s["metadata"]["name"] for s in secrets.get("items", [])}
    missing = [s for s in required if s not in names]
    assert not missing, f"missing Secrets: {missing} (saw: {sorted(names)})"


def test_schema_migrated_to_head(kubectl):
    """goose_db_version contains every migration we ship."""
    out = kubectl.exec_in_pod(
        "constellation-postgres-0",
        ["psql", "-U", "constellation", "-d", "constellation",
         "-tAc", "SELECT MAX(version_id) FROM goose_db_version WHERE is_applied"],
        namespace="constellation-system",
    )
    head = int(out.strip())
    # Wave D/NeuVector-parity scan evidence added migrations through 082.
    # Update this floor when
    # new migrations land; the assertion guards against partial migration runs.
    assert head >= 82, f"schema head={head}, want >=82"
