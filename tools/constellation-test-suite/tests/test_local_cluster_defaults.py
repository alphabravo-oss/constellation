"""Default local-cluster evidence should be enabled end-to-end.

This is the NeuVector-style baseline for a fresh in-cluster install:
discoverer reports platform/workload context, runtime-agent reports node and
package evidence, and scanner workers process typed targets for host, workload,
image, and platform inventory without any manual setup.
"""
from __future__ import annotations

import time

import pytest

from lib.api import wait_for_json


EXPECTED_HEALTH_COMPONENTS = {
    "operator",
    "scanner",
    "admission",
    "runtime-agent",
    "discoverer",
}

SCAN_TARGET_REQUIREMENTS = {
    ("host", "host"),
    ("workload", "runtime-agent"),
    ("image", "runtime-agent"),
    ("platform", "platform"),
}

VALID_JOB_STATUSES = {"pending", "running", "completed", "failed", "paused", "canceled"}
VALID_NODE_SCAN_STATUSES = {"targeted", "pending", "running", "completed", "failed"}


def _cluster_from_list(payload: dict, cluster_id: str) -> dict | None:
    for cluster in payload.get("clusters", []):
        if cluster.get("id") == cluster_id:
            return cluster
    return None


def _health_components_ready(payload: dict) -> bool:
    components = {
        item.get("name"): item
        for item in payload.get("components", [])
        if item.get("name") in EXPECTED_HEALTH_COMPONENTS
    }
    if set(components) != EXPECTED_HEALTH_COMPONENTS:
        return False
    return all(
        item.get("status") == "ready" and int(item.get("ready") or 0) >= 1
        for item in components.values()
    )


def _wait_for_db_rows(psql_json, sql: str, predicate, *, timeout: float = 180.0,
                      poll: float = 5.0):
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        last = psql_json(sql)
        if predicate(last):
            return last
        time.sleep(poll)
    pytest.fail(f"database rows did not satisfy predicate after {timeout:.0f}s: {last!r}")


def test_local_cluster_health_defaults(api, cluster_id):
    clusters = wait_for_json(
        api,
        "/api/v1/clusters",
        lambda payload: (
            (cluster := _cluster_from_list(payload, cluster_id)) is not None
            and cluster.get("sensor_health", {}).get("ready") == len(EXPECTED_HEALTH_COMPONENTS)
            and cluster.get("sensor_health", {}).get("total") == len(EXPECTED_HEALTH_COMPONENTS)
        ),
        timeout=180,
    )
    cluster = _cluster_from_list(clusters, cluster_id)
    assert cluster is not None
    assert cluster.get("state") in {"connected", "healthy"}
    assert cluster.get("distro") == "k3s"
    assert cluster.get("deployments", 0) > 0
    assert cluster["sensor_health"]["status"] == "healthy"

    health = wait_for_json(
        api,
        f"/api/v1/clusters/{cluster_id}/health",
        _health_components_ready,
        timeout=180,
    )
    assert health["summary"]["expected_sensors"] == len(EXPECTED_HEALTH_COMPONENTS)
    assert health["summary"]["connected_sensors"] == len(EXPECTED_HEALTH_COMPONENTS)
    assert health["summary"]["status"] == "healthy"


def test_local_platform_facts_and_node_inventory(api, cluster_id):
    platform = wait_for_json(
        api,
        f"/api/v1/clusters/{cluster_id}/platform-facts",
        lambda payload: (
            bool(payload.get("facts"))
            and bool(payload.get("scan_target"))
            and (payload.get("evidence") or {}).get("package_count", 0) > 0
        ),
        timeout=180,
    )
    facts = platform["facts"]
    assert facts["cluster_id"] == cluster_id
    assert facts["distro"] == "k3s"
    assert facts["kubernetes_git_version"].startswith("v")
    assert facts["node_count"] >= 1
    assert facts["kubelet_versions"]
    component_names = {component["name"] for component in facts.get("components", [])}
    assert "kubernetes" in component_names

    target = platform["scan_target"]
    assert target["ref"] == f"cluster:{cluster_id}"
    assert target["source_type"] == "platform"
    assert target["inventory_hash"].startswith("sha256:")
    assert platform["evidence"]["package_count"] > 0
    if platform.get("latest_job"):
        assert platform["latest_job"]["status"] in VALID_JOB_STATUSES

    nodes = wait_for_json(
        api,
        f"/api/v1/clusters/{cluster_id}/nodes",
        lambda payload: bool(payload.get("items")),
        timeout=180,
    )
    node = nodes["items"][0]
    assert node["cluster_id"] == cluster_id
    assert node["node"]
    assert node["os_id"]
    assert node["kernel_release"]
    assert node["arch"]
    assert node["cni_name"]
    assert node["cri_runtime"]
    assert node.get("btf_present") is True
    assert node.get("nfqueue_capable") is True
    assert node["package_count"] > 0
    assert node["container_count"] > 0
    assert node["process_count"] > 0
    assert node["cis_passed"] + node["cis_failed"] + node["cis_warned"] + node["cis_skipped"] > 0
    assert node["runtime_agent_status"] == "healthy"
    assert node["scan_target_id"]
    assert node["inventory_hash"].startswith("sha256:")
    assert node["scan_status"] in VALID_NODE_SCAN_STATUSES

    detail = api.get_json(f"/api/v1/clusters/{cluster_id}/nodes/{node['node']}")
    assert detail["node"]["node"] == node["node"]
    for key in ("facts", "packages", "containers", "processes", "cis"):
        assert detail.get(key), f"node detail missing {key}"


def test_local_scan_targets_jobs_and_workload_links(psql_json, cluster_id):
    target_rows = _wait_for_db_rows(
        psql_json,
        f"""
        SELECT st.type,
               st.source_type,
               COUNT(DISTINCT st.id)::int AS targets,
               COUNT(DISTINCT se.id)::int AS evidence_rows,
               COALESCE(SUM(se.package_count), 0)::int AS package_count,
               COUNT(DISTINCT sj.id)::int AS jobs
          FROM scan_targets st
          LEFT JOIN scan_evidence se
            ON se.org_id = st.org_id AND se.scan_target_id = st.id
          LEFT JOIN scan_jobs sj
            ON sj.org_id = st.org_id AND sj.target_id = st.id
         WHERE st.cluster_id = '{cluster_id}'
           AND st.type IN ('host', 'workload', 'image', 'platform')
         GROUP BY st.type, st.source_type
        """,
        lambda rows: SCAN_TARGET_REQUIREMENTS.issubset(
            {(row["type"], row["source_type"]) for row in rows}
        ) and all(
            row["targets"] > 0
            and row["evidence_rows"] > 0
            and row["package_count"] > 0
            and row["jobs"] > 0
            for row in rows
            if (row["type"], row["source_type"]) in SCAN_TARGET_REQUIREMENTS
        ),
        timeout=180,
    )
    by_key = {(row["type"], row["source_type"]): row for row in target_rows}
    assert SCAN_TARGET_REQUIREMENTS.issubset(by_key)

    link_rows = _wait_for_db_rows(
        psql_json,
        f"""
        SELECT COUNT(*)::int AS links
          FROM image_workload_links
         WHERE cluster_id = '{cluster_id}'
        """,
        lambda rows: rows and rows[0]["links"] > 0,
        timeout=120,
    )
    assert link_rows[0]["links"] > 0


def test_local_scan_jobs_api_covers_whole_stack(api, cluster_id):
    jobs_payload = wait_for_json(
        api,
        "/api/v1/scan-jobs",
        lambda payload: {"host", "workload", "image", "platform"}.issubset(
            {job.get("target_type") for job in payload.get("jobs", [])}
        ),
        params={"cluster_id": cluster_id},
        timeout=180,
    )
    jobs = jobs_payload["jobs"]
    seen_types = {job["target_type"] for job in jobs}
    assert {"host", "workload", "image", "platform"}.issubset(seen_types)

    for job in jobs:
        assert job["target_id"]
        assert job["target_ref"]
        assert job["target_type"] in {"host", "workload", "image", "platform"}
        assert job["source_type"]
        assert job["status"] in VALID_JOB_STATUSES
        assert job["requested_at"]

    metric_types = {metric["target_type"] for metric in jobs_payload.get("queue_metrics", [])}
    assert {"host", "workload", "image", "platform"}.issubset(metric_types)

    status = api.get_json("/api/v1/scan/status", params={"cluster_id": cluster_id})
    total = sum(int(status.get(key) or 0) for key in ("scheduled", "scanning", "scanned", "failed"))
    assert total >= len({"host", "workload", "image", "platform"})
