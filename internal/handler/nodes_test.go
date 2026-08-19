package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestNodesListAndGetAggregatesHostPosture(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"host_facts", "scan_targets", "scan_evidence"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id = $1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	clusterID := uuid.New()
	node := "node-aggregate-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	targetID := uuid.New()
	jobID := uuid.New()
	assetID := uuid.New()
	vulnID := "CVE-2099-" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	now := time.Now().UTC()

	_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID)
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, agent_version, last_heartbeat_at)
VALUES ($1, $2, $3, 'k3s', 'connected', 'test-agent', $4)`,
		clusterID, orgID, "node-aggregate-"+clusterID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_facts (
    org_id, cluster_id, node, os_id, os_version_id, kernel_release, arch,
    btf_present, cgroup_version, nfqueue_capable, cni_name, cri_runtime,
    facts, observed_at
) VALUES ($1, $2, $3, 'ubuntu', '24.04', '6.8.0-test', 'amd64',
          true, 2, true, 'flannel', 'containerd',
          '{"node":"fixture","os":{"id":"ubuntu"}}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_packages (org_id, cluster_id, node, package_count, source, distro, payload, observed_at)
VALUES ($1, $2, $3, 2, 'dpkg', 'ubuntu',
        '{"items":[{"name":"openssl","version":"3.0.13-0ubuntu3.5"}]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_containers (org_id, cluster_id, node, container_count, runtime, socket, payload, observed_at)
VALUES ($1, $2, $3, 3, 'containerd', '/run/containerd/containerd.sock',
        '{"items":[{"name":"api","image":"example/api:dev"}]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_processes (org_id, cluster_id, node, process_count, items_count, payload, observed_at)
VALUES ($1, $2, $3, 42, 10, '{"items":[{"pid":1,"comm":"systemd"}]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_cis (org_id, cluster_id, node, profile, passed, failed, warned, skipped, payload, observed_at)
VALUES ($1, $2, $3, 'linux-node', 12, 1, 2, 3, '{"checks":[{"id":"1.1","result":"fail"}]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (org_id, cluster_id, component, version, hostname, uptime_seconds, last_seen_at)
VALUES ($1, $2, 'runtime-agent', 'test-runtime-agent', $3, 120, $4)`,
		orgID, clusterID, node, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, cluster_id, type, ref, source_type, source_ref, inventory_hash, metadata)
VALUES ($1, $2, $3, 'host', $4, 'host', $4, 'sha256:test-node-inventory', '{}'::jsonb)`,
		targetID, orgID, clusterID, node); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, package_count, finding_count, finished_at)
VALUES ($1, $2, $3, 'completed', 2, 1, $4)`,
		jobID, orgID, targetID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, cluster_id, kind, name, labels, criticality)
VALUES ($1, $2, $3, 'host', $4, '{}'::jsonb, 'medium')`,
		assetID, orgID, clusterID, node); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (
    org_id, cluster_id, asset_id, kind, external_id, title, description,
    severity, risk_score, lifecycle, canonical_engine, detail_json,
    scan_target_id, target_type, target_ref, target_cluster_id, source_type,
    first_seen_at, last_seen_at
) VALUES ($1, $2, $3, 'vulnerability', $4, 'fixture vuln', 'fixture',
          'critical', 95, 'open', 'vulndb',
          '{"package":{"name":"openssl","version":"3.0.13-0ubuntu3.5"},"aliases":["GHSA-test"],"references":["https://example.test/cve"]}'::jsonb,
          $5, 'host', $6, $2, 'host', $7, $7)`,
		orgID, clusterID, assetID, vulnID, targetID, node, now); err != nil {
		t.Fatal(err)
	}

	h := NewNodes(d)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterID.String()+"/nodes", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	req = withRouteParam(req, "id", clusterID.String())
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []NodeSummary `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	var found *NodeSummary
	for i := range list.Items {
		if list.Items[i].Node == node {
			found = &list.Items[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("node not listed: %+v", list.Items)
	}
	if found.PackageCount != 2 || found.ContainerCount != 3 || found.ProcessCount != 42 {
		t.Fatalf("inventory counts = %+v", found)
	}
	if found.CriticalVulns != 1 || found.OpenVulns != 1 || found.CISFailed != 1 {
		t.Fatalf("risk summary = %+v", found)
	}
	if found.ScanStatus != "completed" || found.InventoryHash != "sha256:test-node-inventory" {
		t.Fatalf("scan status = %+v", found)
	}
	if found.RuntimeAgentStatus != "healthy" {
		t.Fatalf("runtime status = %q", found.RuntimeAgentStatus)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterID.String()+"/nodes/"+node, nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	req = withRouteParam(req, "id", clusterID.String())
	req = withRouteParam(req, "node", node)
	rec = httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status: %d body: %s", rec.Code, rec.Body.String())
	}
	var detail NodeDetail
	if err := json.NewDecoder(rec.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Node.Node != node || len(detail.Vulnerabilities) != 1 {
		t.Fatalf("detail = %+v", detail)
	}
	if len(detail.Facts) == 0 || len(detail.Packages) == 0 || len(detail.CIS) == 0 {
		t.Fatalf("detail payloads missing: facts=%s packages=%s cis=%s", detail.Facts, detail.Packages, detail.CIS)
	}
	if detail.Vulnerabilities[0].VulnID != vulnID || detail.Vulnerabilities[0].PackageName != "openssl" {
		t.Fatalf("vulnerabilities = %+v", detail.Vulnerabilities)
	}
}

func withRouteParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		rctx = chi.NewRouteContext()
	}
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
