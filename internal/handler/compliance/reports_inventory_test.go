package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReportsFullEffectiveScopeAndExactWorkloadRoles(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := d.Pool()
	ctx := context.Background()
	org, foreignOrg, cluster, sibling, foreign, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, o := range []uuid.UUID{org, foreignOrg} {
		if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Actual organization')`, o, "report-"+o.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = p.Exec(ctx, `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = p.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name) VALUES($1,$2,$3,'node','report-node')`, asset, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO compliance_checks(org_id,cluster_id,framework,control_id,title,status,severity) SELECT $1,$2,'report-framework','c-'||lpad(i::text,4,'0'),'main-check-'||i,CASE WHEN i=520 THEN 'manual' WHEN i%2=0 THEN 'pass' ELSE 'fail' END,'high' FROM generate_series(1,520)i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO compliance_checks(org_id,cluster_id,framework,control_id,title,status,severity) VALUES($1,$2,'report-framework','sibling','sibling-hidden','fail','high'),($3,$4,'report-framework','foreign','foreign-hidden','fail','high')`, org, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO compliance_exemptions(org_id,cluster_id,framework,control_id,reason,expires_at) VALUES($1,$2,'report-framework','c-0001','reviewed exemption',NOW()+INTERVAL '1 day')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,title,severity,lifecycle,first_seen_at) VALUES($1,$2,$3,'runtime','old retained finding','critical','accepted','2020-01-01'),($1,$2,$3,'runtime','current finding','high','open',NOW()),($1,$2,$4,'runtime','sibling finding','critical','open',NOW()),($5,$2,$6,'runtime','foreign finding','critical','open',NOW())`, org, asset, cluster, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels,risk_score,finding_count) VALUES($1,$2,'orbit','api','Deployment','{"helm.sh/chart":"constellation-1"}',90,2),($1,$2,'generic','customer','Deployment','{}',80,1),($1,$3,'orbit','sibling-secret','Deployment','{"helm.sh/chart":"constellation-1"}',100,9),($4,$5,'orbit','foreign-secret','Deployment','{"helm.sh/chart":"constellation-1"}',100,9)`, org, cluster, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	request := func(handler http.HandlerFunc, path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	h := NewReports(d)
	w := request(h.ComplianceHTML, "/reports/compliance.html?framework=report-framework&cluster_id="+cluster.String())
	if w.Code != 200 || w.Header().Get("X-Report-Total") != "520" || w.Header().Get("X-Report-Truncated") != "false" || !strings.Contains(w.Body.String(), "main-check-520") || !strings.Contains(w.Body.String(), "50%") || !strings.Contains(w.Body.String(), "Exempted: 1") || strings.Contains(w.Body.String(), "sibling-hidden") || strings.Contains(w.Body.String(), "foreign-hidden") || strings.Contains(w.Body.String(), "Demo Org") {
		t.Fatalf("compliance source %d %s", w.Code, w.Body.String())
	}
	exec := request(h.ExecutiveHTML, "/reports/executive.html?cluster_id="+cluster.String())
	if exec.Code != 200 {
		t.Fatalf("exec%d %s", exec.Code, exec.Body.String())
	}
	for _, needle := range []string{"Actual organization", "All retained finding instances", "orbit/api", "core", "Unclassified", cluster.String(), "Organization-wide materialized metrics", "50%"} {
		if !strings.Contains(exec.Body.String(), needle) {
			t.Fatal("missing actual report evidence", needle)
		}
	}
	for _, needle := range []string{"sibling-secret", "foreign-secret", "last 30 days", "Demo Org"} {
		if strings.Contains(exec.Body.String(), needle) {
			t.Fatal("wrong report source", needle)
		}
	}
	for _, path := range []string{"/reports/executive.html?cluster_id=invalid", "/reports/compliance.html?framework=a&framework=b"} {
		if request(h.ExecutiveHTML, path).Code != 400 {
			t.Fatal("invalid selector accepted")
		}
	}
	if request(h.ExecutiveHTML, "/reports/executive.html?cluster_id="+foreign.String()).Code != 404 {
		t.Fatal("foreign report cluster accepted")
	}
	// Read failures never render a successful empty/partial report.
	role := pgx.Identifier{"report_read_test_" + uuid.New().String()}.Sanitize()
	if _, err := p.Exec(ctx, `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = p.Exec(ctx, `DROP OWNED BY `+role); _, _ = p.Exec(ctx, `DROP ROLE `+role) })
	for _, sql := range []string{`GRANT USAGE ON SCHEMA public TO ` + role, `GRANT SELECT ON orgs,clusters TO ` + role} {
		if _, err := p.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := p.Config().Copy()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["role"] = role[1 : len(role)-1]
	limited, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(limited.Close)
	restricted := NewReports(db.NewFromPool(limited))
	for _, handle := range []http.HandlerFunc{restricted.ComplianceHTML, restricted.ExecutiveHTML} {
		w := request(handle, "/reports/source.html?cluster_id="+cluster.String())
		if w.Code != 500 || strings.Contains(w.Body.String(), "<html") {
			t.Fatalf("false report success%d %s", w.Code, w.Body.String())
		}
	}
}

func TestComplianceArtifactActualMetadataIsImmutableAndLegacyUnknown(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := d.Pool()
	ctx := context.Background()
	org, foreignOrg, cluster, schedule := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, o := range []uuid.UUID{org, foreignOrg} {
		if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, o, "artifact-report-"+o.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = p.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg) })
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO compliance_schedules(id,org_id,cluster_id,name,framework,cron_expression,report_format) VALUES($1,$2,$3,'artifact schedule','cis-k8s-1.9','0 0 * * *','pdf')`, schedule, org, cluster); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "actual-fallback.html")
	if err := os.WriteFile(filename, []byte("<html>actual fallback</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	run, legacy, remote := uuid.New(), uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `INSERT INTO compliance_runs(id,org_id,cluster_id,schedule_id,framework,status,artifact_uri,artifact_format,artifact_media_type,artifact_filename) VALUES($1,$2,$3,$4,'cis-k8s-1.9','succeeded',$5,'html','text/html; charset=utf-8','recorded-fallback.html')`, run, org, cluster, schedule, "file://"+filename); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO compliance_runs(id,org_id,cluster_id,schedule_id,framework,status,artifact_uri) VALUES($1,$2,$3,$4,'cis-k8s-1.9','succeeded',$5),($6,$2,$3,$4,'cis-k8s-1.9','succeeded','s3://bucket/report.json')`, legacy, org, cluster, schedule, "file://"+filename, remote); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE compliance_schedules SET report_format='json' WHERE id=$1`, schedule); err != nil {
		t.Fatal(err)
	}
	h := NewComplianceSchedulesDB(d, nil)
	router := chi.NewRouter()
	router.Get("/compliance/runs/{id}/artifact", h.Artifact)
	router.Get("/compliance/schedules/{id}/runs", h.Runs)
	request := func(tenant uuid.UUID, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: tenant}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	w := request(org, "/compliance/runs/"+run.String()+"/artifact")
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(w.Header().Get("Content-Disposition"), "recorded-fallback.html") || w.Header().Get("X-Constellation-Artifact-Metadata") != "recorded" || w.Body.String() != "<html>actual fallback</html>" {
		t.Fatalf("actual artifact%d %+v %s", w.Code, w.Header(), w.Body.String())
	}
	w = request(org, "/compliance/runs/"+legacy.String()+"/artifact")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" || w.Header().Get("X-Constellation-Artifact-Metadata") != "legacy_unknown" || strings.Contains(w.Header().Get("Content-Disposition"), ".pdf") {
		t.Fatalf("legacy false metadata%d %+v", w.Code, w.Header())
	}
	if request(foreignOrg, "/compliance/runs/"+run.String()+"/artifact").Code != 404 {
		t.Fatal("foreign artifact leaked")
	}
	w = request(org, "/compliance/runs/"+remote.String()+"/artifact")
	var metadata map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &metadata)
	if w.Code != 200 || metadata["download_kind"] != "metadata" || metadata["artifact_metadata_known"] != false {
		t.Fatalf("remote false bytes %s", w.Body.String())
	}
	runs := request(org, "/compliance/schedules/"+schedule.String()+"/runs")
	var list struct {
		Runs []complianceRunRow `json:"runs"`
	}
	if err := json.Unmarshal(runs.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if runs.Code != 200 || len(list.Runs) != 3 {
		t.Fatalf("runs%d %s", runs.Code, runs.Body.String())
	}
	for _, r := range list.Runs {
		if r.ID == run && (r.ArtifactFormat != "html" || !r.ArtifactMetadataKnown || r.ArtifactFilename != "recorded-fallback.html") {
			t.Fatalf("run metadata %+v", r)
		}
		if r.ID == legacy && r.ArtifactMetadataKnown {
			t.Fatal("legacy backfill guessed")
		}
	}
	if _, err := p.Exec(ctx, `UPDATE compliance_runs SET artifact_format='json',artifact_media_type='application/json',artifact_filename='wrong.json' WHERE id=$1`, run); err == nil {
		t.Fatal("recorded artifact identity changed")
	}
	if _, err := p.Exec(ctx, `UPDATE compliance_runs SET artifact_format='html' WHERE id=$1`, legacy); err == nil {
		t.Fatal("partial artifact metadata accepted")
	}
}
