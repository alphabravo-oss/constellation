//go:build integration

package findings

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestConstellationScopeParity(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	org, cluster, system, app, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'scope')`, org, org.String())
	defer func() {
		_, _ = d.Pool().Exec(ctx, `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	}()
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'scope')`, cluster, org)
	// A customer in the installation namespace remains an application workload.
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$3,$4,'constellation-system','api','Deployment','{"app.kubernetes.io/name":"constellation","app.kubernetes.io/part-of":"constellation","app.kubernetes.io/managed-by":"Helm","helm.sh/chart":"constellation-0.2.0"}'),
 ($2,$3,$4,'constellation-system','customer','Deployment','{}')`, system, app, org, cluster)
	for _, link := range []struct {
		id           uuid.UUID
		name, digest string
	}{
		{system, "api", "sha256:system"}, {system, "api", "sha256:shared"},
		{app, "customer", "sha256:shared"}, {app, "customer", "sha256:app"},
	} {
		exec(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_digest)
 VALUES($1,$2,$3,'constellation-system/'||$4,'constellation-system',$4,'Deployment',$5,$5,$5)`, org, cluster, link.id, link.name, link.digest)
	}
	for _, ref := range []string{"sha256:system", "sha256:shared", "sha256:app", "sha256:unknown"} {
		exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,external_id,title,severity,lifecycle,target_type,target_ref)
 VALUES($1,$2,$3,'vulnerability','CVE-2099-1234','scope','high','open','image-workload',$4)`, org, cluster, asset, ref)
	}
	for _, name := range []string{"api", "customer"} {
		exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,title,severity,lifecycle,target_type,target_ref)
 VALUES($1,$2,$3,'runtime','scope','high','open','workload','constellation-system/'||$4)`, org, cluster, asset, name)
	}
	request := func(h http.HandlerFunc, scope string) *httptest.ResponseRecorder {
		q := url.Values{"cluster_id": {cluster.String()}, "workload_scope": {scope}}
		r := httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil)
		r = r.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	for _, tc := range []struct {
		scope            string
		total, instances int
	}{{"application", 4, 3}, {"constellation", 2, 1}, {"all", 6, 4}, {"", 6, 4}} {
		t.Run(tc.scope, func(t *testing.T) {
			w := request(NewFindings(d, nil, nil).List, tc.scope)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var page struct {
				Total       int            `json:"total"`
				Counts      map[string]int `json:"lifecycle_counts"`
				SystemTotal *int           `json:"system_total"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if tc.scope != "" && (page.SystemTotal == nil || *page.SystemTotal != 2) {
				t.Fatalf("system count: %+v", page)
			}
			if page.Total != tc.total || page.Counts["open"] != tc.total {
				t.Fatalf("page: %+v", page)
			}
			w = request(NewFindingsCSV(d).Stream, tc.scope)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			rows, err := csv.NewReader(w.Body).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != tc.total+1 {
				t.Fatalf("CSV rows=%d", len(rows))
			}
			w = request(NewFindings(d, nil, nil).ByCVE, tc.scope)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var rollup struct {
				CVEs []struct {
					Instances int `json:"instances"`
				} `json:"cves"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &rollup); err != nil {
				t.Fatal(err)
			}
			if len(rollup.CVEs) != 1 || rollup.CVEs[0].Instances != tc.instances {
				t.Fatalf("rollup=%s", w.Body.String())
			}
		})
	}
	if w := request(NewFindings(d, nil, nil).List, "bogus"); w.Code != 400 {
		t.Fatalf("invalid scope status=%d", w.Code)
	}
}
