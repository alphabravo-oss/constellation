package policy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestDPIThreatSettingsScopeAtomicCleanupAndCAS(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	org, foreign, user, cluster, sibling, other := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, o := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'DPI scope')`, o, "dpi-"+o.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, table := range []string{"runtime_threats", "network_flow_rollups", "network_flows"} {
			_, _ = pool.Exec(context.Background(), "DELETE FROM "+table+" WHERE org_id=ANY($1::uuid[])", []uuid.UUID{org, foreign})
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=ANY($1::uuid[])`, []uuid.UUID{org, foreign})
	})
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'DPI author')`, user, org, user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ id, org uuid.UUID }{{cluster, org}, {sibling, org}, {other, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name,distro,state) VALUES($1,$2,$3,'k3s','connected')`, c.id, c.org, "dpi-"+c.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	h := NewPolicies(d, nil, nil)
	call := func(fn http.HandlerFunc, method string, c uuid.UUID, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/policies/dpi-threats?cluster_id="+c.String(), strings.NewReader(body))
		req = req.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org, UserID: user}))
		out := httptest.NewRecorder()
		fn(out, req)
		return out
	}
	if out := call(h.DPIThreatSettings, http.MethodGet, cluster, ""); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"weak_tls_enabled":false`) {
		t.Fatalf("default=%d %s", out.Code, out.Body.String())
	}
	for _, fn := range []http.HandlerFunc{h.DPIThreatSettings, h.UpdateDPIThreatSettings} {
		out := call(fn, http.MethodPatch, other, `{"weak_tls_enabled":true}`)
		if out.Code != http.StatusNotFound {
			t.Fatalf("foreign cluster status=%d", out.Code)
		}
	}
	for _, body := range []string{`{}`, `null`, `{"weak_tls_enabled":null}`, `{"weak_tls_enabled":"false"}`} {
		out := call(h.UpdateDPIThreatSettings, http.MethodPatch, cluster, body)
		if out.Code != http.StatusBadRequest {
			t.Fatalf("missing explicit boolean=%d body=%s", out.Code, body)
		}
	}
	// Cluster-row serialization also protects the absent/default setting.
	var wait sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			codes <- call(h.UpdateDPIThreatSettings, http.MethodPatch, cluster, `{"weak_tls_enabled":true,"expected_weak_tls_enabled":false}`).Code
		}()
	}
	wait.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("CAS absent/default outcomes=%v", counts)
	}
	for _, c := range []struct{ id, org uuid.UUID }{{cluster, org}, {sibling, org}, {other, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,reported_at) VALUES($1,$2,2011,5,NOW()),($1,$2,40001,5,NOW())`, c.org, c.id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,max_threat_id,max_severity) VALUES($1,$2,'default/api','external','tcp',date_trunc('hour',NOW()),NOW(),2011,5)`, c.org, c.id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,threat_id,severity) VALUES($1,$2,'default/api','external','tcp',2011,5)`, c.org, c.id); err != nil {
			t.Fatal(err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	fn := "dpi_cleanup_failure_" + suffix
	trigger := "dpi_cleanup_failure_" + suffix
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid THEN RAISE EXCEPTION 'injected cleanup failure'; END IF; RETURN NEW; END $$`, fn, org)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE UPDATE ON network_flow_rollups FOR EACH ROW EXECUTE FUNCTION %s()`, trigger, fn)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON network_flow_rollups`, trigger))
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
	})
	out := call(h.UpdateDPIThreatSettings, http.MethodPatch, cluster, `{"weak_tls_enabled":false,"expected_weak_tls_enabled":true}`)
	if out.Code != http.StatusInternalServerError {
		t.Fatalf("cleanup failure=%d %s", out.Code, out.Body.String())
	}
	var enabled bool
	var threats, rollups, raw int
	if err := pool.QueryRow(ctx, `SELECT weak_tls_enabled FROM dpi_threat_settings WHERE org_id=$1 AND cluster_id=$2`, org, cluster).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("setting did not roll back: enabled%t err%v", enabled, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_threats WHERE org_id=$1 AND cluster_id=$2 AND threat_id=2011`, org, cluster).Scan(&threats); err != nil || threats != 1 {
		t.Fatalf("threat removal did not roll back: count%d err%v", threats, err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER %s ON network_flow_rollups`, trigger)); err != nil {
		t.Fatal(err)
	}
	out = call(h.UpdateDPIThreatSettings, http.MethodPatch, cluster, `{"weak_tls_enabled":false,"expected_weak_tls_enabled":true}`)
	if out.Code != http.StatusOK {
		t.Fatalf("disable=%d %s", out.Code, out.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_threats WHERE org_id=$1 AND cluster_id=$2 AND threat_id=2011`, org, cluster).Scan(&threats); err != nil || threats != 0 {
		t.Fatalf("weak threats not removed: count%d err%v", threats, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_flow_rollups WHERE org_id=$1 AND cluster_id=$2 AND max_threat_id=2011`, org, cluster).Scan(&rollups); err != nil || rollups != 0 {
		t.Fatalf("rollup refs retained: count%d err%v", rollups, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_flows WHERE org_id=$1 AND cluster_id=$2 AND threat_id=2011`, org, cluster).Scan(&raw); err != nil || raw != 0 {
		t.Fatalf("raw refs retained: count%d err%v", raw, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_threats WHERE (org_id=$1 AND cluster_id=$2 AND threat_id=40001) OR (cluster_id=ANY($3::uuid[]) AND threat_id=2011)`, org, cluster, []uuid.UUID{sibling, other}).Scan(&threats); err != nil || threats != 3 {
		t.Fatalf("unrelated evidence altered: count%d err%v", threats, err)
	}
	// Legacy clients may omit the optional precondition, but must explicitly name the boolean.
	out = call(h.UpdateDPIThreatSettings, http.MethodPatch, cluster, `{"weak_tls_enabled":true}`)
	if out.Code != http.StatusOK {
		t.Fatalf("legacy explicit setting=%d", out.Code)
	}
	closed := openTestDB(t)
	closed.Close()
	out = call(NewPolicies(closed, nil, nil).DPIThreatSettings, http.MethodGet, cluster, "")
	if out.Code != http.StatusInternalServerError {
		t.Fatalf("failed read masked as default off: status%d", out.Code)
	}
}
