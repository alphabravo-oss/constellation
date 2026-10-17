package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	findinghandler "github.com/alphabravocompany/constellation/internal/handler/findings"
)

func TestAssetAndFindingPlatformRoleAPIExportParity(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool, ctx := d.Pool(), t.Context()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "role-export-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$4,'main'),($2,$4,'sibling'),($3,$5,'foreign')`, cluster, sibling, foreignCluster, org, foreign); err != nil {
		t.Fatal(err)
	}
	insertOwner := func(o, c uuid.UUID, namespace, name, kind, labels string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		err := pool.QueryRow(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,$3,$4,$5,$6::jsonb) RETURNING id`, o, c, namespace, name, kind, labels).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	core := `{"app.kubernetes.io/part-of":"constellation"}`
	owner := insertOwner(org, cluster, "custom-install", "agent", "Deployment", core)
	insertOwner(org, sibling, "custom-install", "agent", "Deployment", `{}`)
	insertOwner(foreign, foreignCluster, "custom-install", "agent", "Deployment", core)
	insertOwner(org, cluster, "custom-install", "ambiguous", "Deployment", core)
	insertOwner(org, cluster, "custom-install", "ambiguous", "DaemonSet", `{}`)
	insertOwner(org, sibling, "custom-install", "borrowed", "Deployment", core)
	insertOwner(foreign, foreignCluster, "custom-install", "foreign-only", "Deployment", core)
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'custom-install','agent-abc','role-export-pod','custom-install/pod/agent-abc','Deployment','agent','custom-install/agent',$3)`, org, cluster, owner); err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		kind, name, targetType, targetRef, role string
		c                                       *uuid.UUID
		asset, id                               uuid.UUID
	}
	fixtures := []fixture{
		{kind: "deployment", name: "custom-install/agent", c: &cluster, role: "core"},
		{kind: "workload", name: "custom-install/pod/agent-abc", c: &cluster, role: "core"},
		{kind: "workload", name: "custom-install/pod/agent-unlinked", c: &cluster},
		{kind: "workload", name: "custom-install/agent", c: &sibling},
		{kind: "workload", name: "custom-install/ambiguous", c: &cluster},
		{kind: "workload", name: "custom-install/borrowed", c: &cluster},
		{kind: "workload", name: "custom-install/foreign-only", c: &cluster},
		{kind: "workload", name: "kube-system/agent", c: &foreignCluster},
		{kind: "workload", name: "kube-system/agent"},
		{kind: "workload", name: "custom-install/10.2.3.4", c: &cluster},
		{kind: "workload", name: "kube-system/a/b", c: &cluster},
		{kind: "image", name: "kube-system/agent", c: &cluster},
		{kind: "repository", name: "custom-install/agent", c: &cluster},
		{kind: "cloud-resource", name: "custom-install/agent", c: &cluster},
		{kind: "host", name: "kube-system/agent", c: &cluster},
		{kind: "workload", name: "custom-install/agent", targetType: "image-workload", targetRef: "custom-install/agent", c: &cluster, role: "core"},
		{kind: "image", name: "image-backed-runtime", targetType: "workload", targetRef: "custom-install/pod/agent-abc", c: &cluster, role: "core"},
	}
	assetsExpected, findingsExpected := map[string]string{}, map[string]string{}
	for i := range fixtures {
		f := &fixtures[i]
		f.asset, f.id = uuid.New(), uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name,labels) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, f.asset, org, f.c, f.kind, f.name, core); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,title,severity,lifecycle,target_type,target_ref) VALUES($1,$2,$3,$4,'runtime','role fixture','high','open',$5,$6)`, f.id, org, f.c, f.asset, f.targetType, f.targetRef); err != nil {
			t.Fatal(err)
		}
		ar := f.role
		if f.kind == "image" {
			ar = ""
		}
		assetsExpected[f.asset.String()] = ar
		fr := f.role
		if f.targetType == "image-workload" {
			fr = ""
		}
		findingsExpected[f.id.String()] = fr
	}
	request := func(h http.HandlerFunc, path, id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: org, UserID: uuid.New()}))
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != 200 {
			t.Fatalf("%s status%d %s", path, w.Code, w.Body.String())
		}
		return w
	}
	verifyCSV := func(w *httptest.ResponseRecorder, idColumn, roleColumn string, want map[string]string) {
		t.Helper()
		rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		ii, ri := -1, -1
		for i, v := range rows[0] {
			if v == idColumn {
				ii = i
			}
			if v == roleColumn {
				ri = i
			}
		}
		if ii < 0 || ri < 0 || len(rows) != len(want)+1 {
			t.Fatalf("CSV headers/count %v count%d want%d", rows[0], len(rows), len(want)+1)
		}
		for _, r := range rows[1:] {
			expected, ok := want[r[ii]]
			if !ok || r[ri] != expected {
				t.Fatalf("CSV role id%s got%q want%q", r[ii], r[ri], expected)
			}
		}
	}
	a := NewAssets(d)
	fh := findinghandler.NewFindings(d, nil, nil)
	verifyCSV(request(a.ExportCSV, "/?limit=100", ""), "ID", "Platform role", assetsExpected)
	verifyCSV(request(findinghandler.NewFindingsCSV(d).Stream, "/?limit=100", ""), "id", "platform_role", findingsExpected)
	// Decode maps to assert explicit empty roles rather than omitted fields.
	var assetsBody struct {
		Assets []map[string]any `json:"assets"`
		Total  int              `json:"total"`
	}
	if err := json.Unmarshal(request(a.List, "/?limit=100", "").Body.Bytes(), &assetsBody); err != nil {
		t.Fatal(err)
	}
	if assetsBody.Total != len(fixtures) {
		t.Fatal("asset cohort changed")
	}
	for _, row := range assetsBody.Assets {
		role, ok := row["platform_role"].(string)
		if !ok || role != assetsExpected[row["id"].(string)] {
			t.Fatalf("asset role %v", row)
		}
	}
	var findingBody struct {
		Findings []map[string]any `json:"findings"`
		Total    int              `json:"total"`
	}
	if err := json.Unmarshal(request(fh.List, "/?limit=100", "").Body.Bytes(), &findingBody); err != nil {
		t.Fatal(err)
	}
	if findingBody.Total != len(fixtures) {
		t.Fatal("finding cohort changed")
	}
	for _, row := range findingBody.Findings {
		role, ok := row["platform_role"].(string)
		if !ok || role != findingsExpected[row["id"].(string)] {
			t.Fatalf("finding role %v", row)
		}
	}
	for _, f := range fixtures {
		var assetBody struct {
			Asset map[string]any `json:"asset"`
		}
		if err := json.Unmarshal(request(a.Get, "/", f.asset.String()).Body.Bytes(), &assetBody); err != nil {
			t.Fatal(err)
		}
		if assetBody.Asset["platform_role"] != assetsExpected[f.asset.String()] {
			t.Fatal("asset detail/export role mismatch")
		}
		var found map[string]any
		if err := json.Unmarshal(request(fh.Get, "/", f.id.String()).Body.Bytes(), &found); err != nil {
			t.Fatal(err)
		}
		if found["platform_role"] != findingsExpected[f.id.String()] {
			t.Fatal("finding detail/export role mismatch")
		}
		// Image-kind assets without a scan still expose their original generic findings.
		verifyCSV(request(a.FindingsCSV, "/", f.asset.String()), "finding_id", "platform_role", map[string]string{f.id.String(): findingsExpected[f.id.String()]})
		var inventory struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		}
		if err := json.Unmarshal(request(a.Findings, "/", f.asset.String()).Body.Bytes(), &inventory); err != nil {
			t.Fatal(err)
		}
		if inventory.Total != 1 || len(inventory.Items) != 1 || inventory.Items[0]["platform_role"] != findingsExpected[f.id.String()] {
			t.Fatal("asset finding role/count differs from export")
		}
	}
}
