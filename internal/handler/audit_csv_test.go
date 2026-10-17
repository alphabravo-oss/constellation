package handler

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	auditlog "github.com/alphabravocompany/constellation/pkg/audit"
)

func auditCSVRequest(t *testing.T, f *auditListFixture, org uuid.UUID, params url.Values) (*httptest.ResponseRecorder, [][]string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events.csv?"+params.Encode(), nil)
	request = request.WithContext(WithSubject(t.Context(), Subject{OrgID: org}))
	response := httptest.NewRecorder()
	NewAudit(f.database).ExportCSV(response, request)
	if response.Code != 200 {
		return response, nil
	}
	rows, err := csv.NewReader(response.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return response, rows
}

func TestAuditCSVMatchingScopeAndPinnedCohort(t *testing.T) {
	f := newAuditCSVFixture(t)
	action := "audit.csv." + uuid.NewString()
	if _, err := f.database.Pool().Exec(t.Context(), `INSERT INTO audit_events(org_id,action,target_kind,target_id,prev_hash,chain_hash)
 SELECT $1,$2,'asset',$3,repeat('0',64),$2||g::text FROM generate_series(1,205) g`, f.orgA, action, f.assetA.String()); err != nil {
		t.Fatal(err)
	}
	f.log(f.orgA, action, "asset", f.assetSibling.String())
	f.log(f.orgB, action, "asset", f.assetA.String())
	params := url.Values{"cluster_id": {f.clusterA.String()}, "action": {action}, "offset": {"200"}, "limit": {"5"}}
	response, rows := auditCSVRequest(t, f, f.orgA, params)
	if response.Code != 200 || len(rows) != 206 || response.Header().Get("X-Export-Rows") != "205" || response.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("export=%d rows=%d headers=%v", response.Code, len(rows), response.Header())
	}
	page := f.list(f.orgA, url.Values{"cluster_id": {f.clusterA.String()}, "action": {action}, "offset": {"200"}, "limit": {"5"}})
	for i, event := range page.Events {
		if rows[201+i][0] != event.EventID {
			t.Fatal("CSV and JSON ordering/identity differ")
		}
	}
	for _, row := range rows[1:] {
		if row[3] != action || row[5] != f.assetA.String() {
			t.Fatal("export scope leaked")
		}
	}
	selected := strings.Join([]string{rows[1][0], rows[2][0]}, ",")
	f.log(f.orgA, action, "asset", f.assetA.String())
	response, rows = auditCSVRequest(t, f, f.orgA, url.Values{"event_ids": {selected}})
	if response.Code != 200 || len(rows) != 3 {
		t.Fatalf("pinned export drifted: %d/%d", response.Code, len(rows))
	}
	for _, row := range rows[1:] {
		if !strings.Contains(selected, row[0]) {
			t.Fatal("new record replaced a selected ID")
		}
	}
	response, rows = auditCSVRequest(t, f, f.orgB, url.Values{"event_ids": {selected}})
	if response.Code != 200 || len(rows) != 1 {
		t.Fatal("foreign pinned records exported")
	}
	for _, params := range []url.Values{{"framework": {"unknown"}, "control": {"none"}}, {"event_ids": {""}}} {
		response, rows = auditCSVRequest(t, f, f.orgA, params)
		if response.Code != 200 || len(rows) != 1 || response.Header().Get("X-Export-Truncated") != "false" {
			t.Fatal("empty cohort expanded")
		}
	}
	for _, params := range []url.Values{{"framework": {"nist"}}, {"offset": {"bad"}}, {"limit": {"0"}}, {"event_ids": {selected}, "action": {action}}, {"action": {action, "other"}}, {"cluster_id": {f.clusterA.String(), f.clusterSibling.String()}}} {
		response, _ = auditCSVRequest(t, f, f.orgA, params)
		if response.Code != 400 {
			t.Fatalf("invalid export accepted: %v/%d", params, response.Code)
		}
	}
	response, _ = auditCSVRequest(t, f, f.orgB, url.Values{"cluster_id": {f.clusterA.String()}})
	if response.Code != 404 {
		t.Fatal("foreign cluster accepted")
	}
}

func TestAuditCSVIntersectsControlAndAction(t *testing.T) {
	f := newAuditCSVFixture(t)
	mapped := f.log(f.orgA, "auth.login.local", "cluster", f.clusterA.String())
	f.log(f.orgA, "unmapped.csv.fixture", "cluster", f.clusterA.String())
	f.log(f.orgA, "auth.login.local", "cluster", f.clusterSibling.String())
	params := url.Values{"cluster_id": {f.clusterA.String()}, "framework": {string(auditlog.FrameworkNIST80053)}, "control": {"AC-2"}, "action": {"auth.login.local"}}
	response, rows := auditCSVRequest(t, f, f.orgA, params)
	if response.Code != 200 || len(rows) != 2 || rows[1][0] != strconv.FormatInt(mapped, 10) {
		t.Fatalf("mapped cohort differs: %d/%v", response.Code, rows)
	}
	params.Set("action", "unmapped.csv.fixture")
	response, rows = auditCSVRequest(t, f, f.orgA, params)
	if response.Code != 200 || len(rows) != 1 {
		t.Fatal("exact action bypassed control filter")
	}
}

func TestAuditCSVReportsLookaheadCap(t *testing.T) {
	f := newAuditCSVFixture(t)
	action := "audit.csv.cap." + uuid.NewString()
	if _, err := f.database.Pool().Exec(t.Context(), `INSERT INTO audit_events(org_id,action,target_kind,target_id,prev_hash,chain_hash)
 SELECT $1,$2,'cluster',$3,repeat('0',64),$2||g::text FROM generate_series(1,100001) g`, f.orgA, action, f.clusterA.String()); err != nil {
		t.Fatal(err)
	}
	response, rows := auditCSVRequest(t, f, f.orgA, url.Values{"action": {action}})
	if response.Code != 200 || len(rows) != auditExportLimit+1 || response.Header().Get("X-Export-Limit") != strconv.Itoa(auditExportLimit) || response.Header().Get("X-Export-Truncated") != "true" || response.Header().Get("X-Export-Total") != "" {
		t.Fatalf("cap contract %d rows=%d headers=%v", response.Code, len(rows), response.Header())
	}
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		if seen[row[0]] {
			t.Fatal("duplicate audit ID")
		}
		seen[row[0]] = true
	}
}

// CSV cap fixtures use synthetic hashes to seed a large read cohort quickly.
// Keep those rows in a private table so another package can verify the real
// global audit chain after these tests have run.
func newAuditCSVFixture(t *testing.T) *auditListFixture {
	t.Helper()
	f := newAuditListFixture(t)
	publicPool := f.database.Pool()
	schema := "audit_csv_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := publicPool.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = publicPool.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") })
	if _, err := publicPool.Exec(t.Context(), "CREATE TABLE "+quoted+".audit_events (LIKE public.audit_events INCLUDING ALL); CREATE SEQUENCE "+quoted+".audit_events_id_seq; ALTER TABLE "+quoted+".audit_events ALTER COLUMN id SET DEFAULT nextval('"+schema+".audit_events_id_seq')"); err != nil {
		t.Fatal(err)
	}
	config := publicPool.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.database = db.NewFromPool(pool)
	return f
}

func TestAuditCSVSyntheticRowsDoNotChangeGlobalChain(t *testing.T) {
	f := newAuditCSVFixture(t)
	pool := f.database.Pool()
	var beforeID, afterID int64
	var beforeHash, afterHash string
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(id),0), COALESCE((SELECT chain_hash FROM public.audit_events ORDER BY id DESC LIMIT 1),'') FROM public.audit_events`).Scan(&beforeID, &beforeHash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO audit_events(org_id,action,prev_hash,chain_hash) VALUES($1,'isolated.csv.fixture',repeat('0',64),'private-synthetic-hash')`, f.orgA); err != nil {
		t.Fatal(err)
	}
	response, rows := auditCSVRequest(t, f, f.orgA, url.Values{"action": {"isolated.csv.fixture"}})
	if response.Code != 200 || len(rows) != 2 {
		t.Fatalf("isolated rows unavailable: %d/%d", response.Code, len(rows))
	}
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(id),0), COALESCE((SELECT chain_hash FROM public.audit_events ORDER BY id DESC LIMIT 1),'') FROM public.audit_events`).Scan(&afterID, &afterHash); err != nil {
		t.Fatal(err)
	}
	if beforeID != afterID || beforeHash != afterHash {
		t.Fatal("synthetic CSV fixture changed the global audit chain")
	}
}
