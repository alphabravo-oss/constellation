package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHostIngestRejectsCrossTenantBundleWithoutWrites(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterB := uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "host-ingest-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'foreign')`, clusterB, orgB); err != nil {
		t.Fatal(err)
	}

	for _, endpoint := range []struct {
		name    string
		table   string
		report  http.HandlerFunc
		payload func(string) any
	}{
		{
			name: "packages", table: "host_packages", report: NewHostPackages(d).Report,
			payload: func(node string) any {
				return HostPackagesPayload{Node: node, Count: 1, Source: "dpkg", Distro: "ubuntu", Items: []HostPackageItem{{Name: "openssl", Version: "3.0"}}}
			},
		},
		{
			name: "processes", table: "host_processes", report: NewHostProcesses(d).Report,
			payload: func(node string) any {
				return HostProcessesPayload{Node: node, Count: 1, Items: []HostProcessItem{{PID: 1, Comm: "init"}}}
			},
		},
		{
			name: "containers", table: "host_containers", report: NewHostContainers(d).Report,
			payload: func(node string) any {
				return HostContainersPayload{Node: node, Count: 1, Items: []HostContainerItem{{ID: "container", Name: "app", Image: "example/app:1", State: "running"}}}
			},
		},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, mapping := range []struct {
				name      string
				bundleOrg uuid.UUID
			}{
				{name: "foreign bundle org", bundleOrg: orgB},
				{name: "foreign cluster org", bundleOrg: orgA},
			} {
				t.Run(mapping.name, func(t *testing.T) {
					rawToken, tokenID, err := IssueRuntimeAgentToken(ctx, pool, orgA, "host-ingest-scope-"+uuid.NewString(), time.Hour)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
						mapping.bundleOrg, clusterB, "host-ingest-scope-"+uuid.NewString(), tokenID); err != nil {
						t.Fatal(err)
					}
					node := "host-ingest-scope-" + uuid.NewString()
					body, err := json.Marshal(endpoint.payload(node))
					if err != nil {
						t.Fatal(err)
					}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/host-"+endpoint.name+":report", bytes.NewReader(body))
					req.Header.Set("Authorization", "Bearer "+rawToken)
					rec := httptest.NewRecorder()
					RuntimeAgentTokenMiddleware(pool)(endpoint.report).ServeHTTP(rec, req)
					if rec.Code != http.StatusForbidden {
						t.Fatalf("report status = %d, want 403: %s", rec.Code, rec.Body.String())
					}

					var count int
					if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE node = $1`, endpoint.table), node).Scan(&count); err != nil {
						t.Fatal(err)
					}
					if count != 0 {
						t.Fatalf("cross-tenant report persisted %d %s rows", count, endpoint.table)
					}
					if endpoint.name == "packages" {
						for _, check := range []struct {
							name  string
							query string
						}{
							{name: "scan targets", query: `SELECT COUNT(*) FROM scan_targets WHERE type = 'host' AND ref = $1`},
							{name: "scan evidence", query: `SELECT COUNT(*) FROM scan_evidence WHERE target_type = 'host' AND target_ref = $1`},
							{name: "scan jobs", query: `SELECT COUNT(*) FROM scan_jobs sj JOIN scan_targets st ON st.id = sj.target_id WHERE st.type = 'host' AND st.ref = $1`},
						} {
							if err := pool.QueryRow(ctx, check.query, node).Scan(&count); err != nil {
								t.Fatal(err)
							}
							if count != 0 {
								t.Fatalf("cross-tenant report persisted %d %s", count, check.name)
							}
						}
					}
				})
			}
		})
	}
}
