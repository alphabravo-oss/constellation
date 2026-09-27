package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestNodesHostCVEsScopeAndPagination(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.host_facts') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Skipf("host inventory migrations unavailable: %v", err)
	}

	orgID, foreignOrgID := uuid.New(), uuid.New()
	sourceClusterID, targetClusterID, foreignClusterID := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id IN ($1, $2)`, orgID, foreignOrgID)
		_, _ = pool.Exec(ctx, `DELETE FROM assets WHERE org_id IN ($1, $2)`, orgID, foreignOrgID)
		_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE org_id IN ($1, $2)`, orgID, foreignOrgID)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, foreignOrgID)
	})
	for _, orgID := range []uuid.UUID{orgID, foreignOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "nodes-host-cves-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, cluster := range []struct{ id, orgID uuid.UUID }{
		{sourceClusterID, orgID}, {targetClusterID, orgID}, {foreignClusterID, foreignOrgID},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, $3)`, cluster.id, cluster.orgID, cluster.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	createAsset := func(orgID, clusterID uuid.UUID) uuid.UUID {
		assetID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO assets (id, org_id, cluster_id, kind, name) VALUES ($1, $2, $3, 'host', $4)`, assetID, orgID, clusterID, assetID.String()); err != nil {
			t.Fatal(err)
		}
		return assetID
	}
	sourceAssetID := createAsset(orgID, sourceClusterID)
	foreignAssetID := createAsset(foreignOrgID, foreignClusterID)
	insertFinding := func(orgID, clusterID, assetID uuid.UUID, targetClusterID *uuid.UUID, node, kind, lifecycle string) {
		if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, cluster_id, asset_id, target_cluster_id, target_type, target_ref,
                      kind, title, severity, lifecycle)
VALUES ($1, $2, $3, $4, 'host', $5, $6, $7, 'critical', $8)`, orgID, clusterID, assetID, targetClusterID, node, kind, node, lifecycle); err != nil {
			t.Fatal(err)
		}
	}
	insertFinding(orgID, sourceClusterID, sourceAssetID, &targetClusterID, "attributed-node", "vulnerability", "open")
	insertFinding(orgID, sourceClusterID, sourceAssetID, nil, "normal-node", "vulnerability", "open")
	insertFinding(orgID, sourceClusterID, sourceAssetID, nil, "normal-node", "vulnerability", "open")
	insertFinding(orgID, sourceClusterID, sourceAssetID, nil, "compliance-only", "compliance", "open")
	insertFinding(orgID, sourceClusterID, sourceAssetID, nil, "accepted-only", "vulnerability", "accepted")
	insertFinding(foreignOrgID, sourceClusterID, foreignAssetID, nil, "foreign-only", "vulnerability", "open")

	requestList := func(subjectOrgID, clusterID uuid.UUID, query string) (int, struct {
		Items []NodeSummary `json:"items"`
		Total int           `json:"total"`
	}) {
		t.Helper()
		url := fmt.Sprintf("/api/v1/clusters/%s/nodes?%s", clusterID, query)
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: subjectOrgID}))
		req = withRouteParam(req, "id", clusterID.String())
		rec := httptest.NewRecorder()
		NewNodes(d).List(rec, req)
		var body struct {
			Items []NodeSummary `json:"items"`
			Total int           `json:"total"`
		}
		if rec.Code == http.StatusOK {
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, body
	}

	firstStatus, first := requestList(orgID, sourceClusterID, "host_cves=open&limit=1&offset=0")
	secondStatus, second := requestList(orgID, sourceClusterID, "host_cves=open&limit=1&offset=1")
	if firstStatus != http.StatusOK || secondStatus != http.StatusOK || first.Total != 2 || second.Total != 2 || len(first.Items) != 1 || len(second.Items) != 1 {
		t.Fatalf("paged host nodes: first=%d %+v second=%d %+v", firstStatus, first, secondStatus, second)
	}
	if first.Items[0].Node != "attributed-node" || first.Items[0].OpenVulns != 1 || second.Items[0].Node != "normal-node" || second.Items[0].OpenVulns != 2 {
		t.Fatalf("host CVE pages differ from dashboard findings: %+v %+v", first.Items, second.Items)
	}
	_, beyond := requestList(orgID, sourceClusterID, "host_cves=open&limit=1&offset=2")
	if beyond.Total != 2 || len(beyond.Items) != 0 {
		t.Fatalf("end of pages = %+v", beyond)
	}
	_, attributed := requestList(orgID, targetClusterID, "limit=10")
	if attributed.Total != 1 || len(attributed.Items) != 1 || attributed.Items[0].Node != "attributed-node" {
		t.Fatalf("target-cluster attribution omitted: %+v", attributed)
	}
	_, targetFiltered := requestList(orgID, targetClusterID, "host_cves=open")
	if targetFiltered.Total != 0 || len(targetFiltered.Items) != 0 {
		t.Fatalf("dashboard filter included another source cluster: %+v", targetFiltered)
	}
	status, _ := requestList(foreignOrgID, sourceClusterID, "host_cves=open")
	if status != http.StatusNotFound {
		t.Fatalf("foreign org accessed cluster: %d", status)
	}
}
