package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"time"

	"testing"

	"github.com/alphabravocompany/constellation/internal/db"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestAuditListScopesOrgAndCluster(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	action := "audit.scope." + uuid.NewString()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "audit-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'local'), ($3, $4, 'foreign')`, clusterA, orgA, clusterB, orgB); err != nil {
		t.Fatal(err)
	}
	logger := audit.New(pool)
	for _, event := range []audit.Event{
		{OrgID: &orgA, Action: action, TargetKind: "cluster", TargetID: clusterA.String()},
		{OrgID: &orgB, Action: action, TargetKind: "cluster", TargetID: clusterB.String()},
	} {
		if _, _, err := logger.Log(ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	list := func(orgID uuid.UUID, clusterID *uuid.UUID) *httptest.ResponseRecorder {
		t.Helper()
		url := "/api/v1/audit/events?action=" + action
		if clusterID != nil {
			url += "&cluster_id=" + clusterID.String()
		}
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: orgID}))
		response := httptest.NewRecorder()
		NewAudit(database).List(response, request)
		return response
	}
	for _, response := range []*httptest.ResponseRecorder{list(orgA, nil), list(orgA, &clusterA), list(orgB, nil), list(orgB, &clusterB)} {
		if response.Code != http.StatusOK {
			t.Fatalf("audit list status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Events []auditDTO `json:"events"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Events) != 1 {
			t.Fatalf("audit list returned %d events, want 1: %s", len(result.Events), response.Body.String())
		}
	}
	if response := list(orgA, &clusterB); response.Code != http.StatusNotFound {
		t.Fatalf("foreign cluster filter status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAuditListClusterTargetsAndFilters(t *testing.T) {
	f := newAuditListFixture(t)
	familyAction := "audit.targets." + uuid.NewString()
	targets := []uuid.UUID{f.clusterA, f.assetA, f.sharedTarget, f.checkA, f.policyA, f.policyGlobal}
	var eligible []int64
	for _, target := range targets {
		eligible = append(eligible, f.log(f.orgA, familyAction, "legacy-kind", target.String()))
	}
	var siblingReceipt int64
	for _, target := range []string{"", uuid.NewString(), f.assetSibling.String(), f.assetForeign.String()} {
		id := f.log(f.orgA, familyAction, "legacy-kind", target)
		if target == f.assetSibling.String() {
			siblingReceipt = id
		}
	}
	f.log(f.orgB, familyAction, "legacy-kind", f.assetA.String())
	sort.Slice(eligible, func(i, j int) bool { return eligible[i] > eligible[j] })

	for offset := 0; offset < 8; offset += 2 {
		result := f.list(f.orgA, url.Values{"cluster_id": {f.clusterA.String()}, "action": {familyAction}, "limit": {"2"}, "offset": {strconv.Itoa(offset)}})
		end := min(offset+2, len(eligible))
		start := min(offset, len(eligible))
		assertAuditIDs(t, result.Events, eligible[start:end])
		if result.HasMore != (end < len(eligible)) {
			t.Fatalf("offset %d has_more=%t", offset, result.HasMore)
		}
	}
	// The same target ID occurs in both findings and deployments. Its receipt
	// appears once; inherited org policies are included for either owned cluster.
	sibling := f.list(f.orgA, url.Values{"cluster_id": {f.clusterSibling.String()}, "action": {familyAction}})
	assertAuditIDs(t, sibling.Events, []int64{siblingReceipt, eligible[0]})

	// Event drilldowns still intersect the active cluster scope.
	direct := f.list(f.orgA, url.Values{"cluster_id": {f.clusterA.String()}, "event_id": {strconv.FormatInt(eligible[0], 10)}})
	assertAuditIDs(t, direct.Events, eligible[:1])
	absent := f.list(f.orgA, url.Values{"cluster_id": {f.clusterA.String()}, "event_id": {strconv.FormatInt(siblingReceipt, 10)}})
	assertAuditIDs(t, absent.Events, nil)
	orgEvent := f.list(f.orgA, url.Values{"event_id": {strconv.FormatInt(siblingReceipt, 10)}})
	assertAuditIDs(t, orgEvent.Events, []int64{siblingReceipt})
	foreign := f.list(f.orgB, url.Values{"event_id": {strconv.FormatInt(siblingReceipt, 10)}})
	assertAuditIDs(t, foreign.Events, nil)

	// Preserve the conjunction of job and cluster filters without imposing a new
	// target-kind interpretation on ordinary target matches.
	job := f.log(f.orgA, "support_bundle_job.ready", "support_bundle_job", f.clusterA.String())
	jobPage := f.list(f.orgA, url.Values{"support_bundle_job_id": {f.clusterA.String()}})
	assertAuditIDs(t, jobPage.Events, []int64{job})
	jobPage = f.list(f.orgA, url.Values{"cluster_id": {f.clusterA.String()}, "support_bundle_job_id": {f.clusterA.String()}})
	assertAuditIDs(t, jobPage.Events, []int64{job})
	jobPage = f.list(f.orgA, url.Values{"cluster_id": {f.clusterSibling.String()}, "support_bundle_job_id": {f.clusterA.String()}})
	assertAuditIDs(t, jobPage.Events, nil)

	mapped := f.log(f.orgA, "auth.login.local", "cluster", f.clusterA.String())
	mappedSibling := f.log(f.orgA, "auth.login.local", "cluster", f.clusterSibling.String())
	params := url.Values{"cluster_id": {f.clusterA.String()}, "framework": {string(audit.FrameworkNIST80053)}, "control": {"AC-2"}, "with_controls": {"true"}}
	mappedPage := f.list(f.orgA, params)
	assertAuditIDs(t, mappedPage.Events, []int64{mapped})
	if len(mappedPage.Events[0].Controls) == 0 {
		t.Fatal("requested compliance decoration missing")
	}
	params.Del("cluster_id")
	mappedPage = f.list(f.orgA, params)
	assertAuditIDs(t, mappedPage.Events, []int64{mappedSibling, mapped})
	params.Set("cluster_id", f.clusterA.String())
	params.Set("control", "ZZ-99")
	assertAuditIDs(t, f.list(f.orgA, params).Events, nil)
	params.Set("action", familyAction)
	// Every visible filter applies, including a control with no mapping.
	assertAuditIDs(t, f.list(f.orgA, params).Events, nil)
	params.Set("control", "AC-2")
	assertAuditIDs(t, f.list(f.orgA, params).Events, nil)
	params.Set("action", "auth.login.local")
	assertAuditIDs(t, f.list(f.orgA, params).Events, []int64{mapped})
}

func TestAuditListClusterPaginationBeyondFirstPage(t *testing.T) {
	f := newAuditListFixture(t)
	var ids []int64
	for i := 0; i < 251; i++ {
		target := f.assetA
		if i%2 == 0 {
			target = f.clusterA
		}
		ids = append(ids, f.log(f.orgA, "audit.page.fixture", "cluster", target.String()))
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	var received []int64
	for offset := 0; offset < 300; offset += 100 {
		page := f.list(f.orgA, url.Values{"cluster_id": {f.clusterA.String()}, "limit": {"100"}, "offset": {strconv.Itoa(offset)}})
		end := min(offset+100, len(ids))
		assertAuditIDs(t, page.Events, ids[offset:end])
		if page.HasMore != (end < len(ids)) {
			t.Fatalf("offset %d has_more=%t", offset, page.HasMore)
		}
		for _, event := range page.Events {
			received = append(received, event.ID)
		}
	}
	if len(received) != 251 {
		t.Fatalf("got %d rows across pages", len(received))
	}
}

type auditListFixture struct {
	t                                                                                                                     *testing.T
	database                                                                                                              *db.DB
	orgA, orgB, clusterA, clusterSibling, assetA, assetSibling, assetForeign, sharedTarget, checkA, policyA, policyGlobal uuid.UUID
}

func newAuditListFixture(t *testing.T) *auditListFixture {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	f := &auditListFixture{t: t, database: database, orgA: uuid.New(), orgB: uuid.New(), clusterA: uuid.New(), clusterSibling: uuid.New(), assetA: uuid.New(), assetSibling: uuid.New(), assetForeign: uuid.New(), sharedTarget: uuid.New(), checkA: uuid.New(), policyA: uuid.New(), policyGlobal: uuid.New()}
	pool := database.Pool()
	ctx := t.Context()
	for _, org := range []uuid.UUID{f.orgA, f.orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,$2)`, org, "audit-list-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN ($1,$2)`, f.orgA, f.orgB)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, f.orgA, f.orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id,org_id,name) VALUES ($1,$3,'main'),($2,$3,'sibling')`, f.clusterA, f.clusterSibling, f.orgA); err != nil {
		t.Fatal(err)
	}
	for _, asset := range []struct{ id, org, cluster uuid.UUID }{{f.assetA, f.orgA, f.clusterA}, {f.assetSibling, f.orgA, f.clusterSibling}, {f.assetForeign, f.orgB, f.clusterA}} {
		if _, err := pool.Exec(ctx, `INSERT INTO assets (id,org_id,cluster_id,kind,name) VALUES ($1,$2,$3,'workload',$4)`, asset.id, asset.org, asset.cluster, "audit-list-"+asset.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings (id,org_id,cluster_id,asset_id,kind,title,severity,first_seen_at) VALUES ($1,$2,$3,$4,'runtime','audit fixture','low',$5),($1,$2,$3,$4,'runtime','audit duplicate ID','low',$6)`, f.sharedTarget, f.orgA, f.clusterA, f.assetA, time.Now().Add(-time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (id,org_id,cluster_id,namespace,name,kind) VALUES ($1,$2,$3,'default','audit-fixture','Deployment')`, f.sharedTarget, f.orgA, f.clusterA); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO compliance_checks (id,org_id,cluster_id,framework,control_id,title,status,severity) VALUES ($1,$2,$3,'fixture','fixture','audit fixture','fail','low')`, f.checkA, f.orgA, f.clusterA); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO policies (id,org_id,cluster_id,name,engine,category,spec_yaml) VALUES ($1,$3,$4,'audit-cluster','internal-dlp','runtime-dlp','{}'),($2,$3,NULL,'audit-global','internal-dlp','runtime-dlp','{}')`, f.policyA, f.policyGlobal, f.orgA, f.clusterA); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *auditListFixture) log(org uuid.UUID, action, kind, target string) int64 {
	f.t.Helper()
	id, _, err := audit.New(f.database.Pool()).Log(f.t.Context(), audit.Event{OrgID: &org, Action: action, TargetKind: kind, TargetID: target})
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

type auditListResponse struct {
	Events  []auditDTO `json:"events"`
	HasMore bool       `json:"has_more"`
}

func (f *auditListFixture) list(org uuid.UUID, params url.Values) auditListResponse {
	f.t.Helper()
	request := httptest.NewRequestWithContext(f.t.Context(), http.MethodGet, "/api/v1/audit/events?"+params.Encode(), nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: org}))
	response := httptest.NewRecorder()
	NewAudit(f.database).List(response, request)
	if response.Code != http.StatusOK {
		f.t.Fatalf("audit request failed: status=%d", response.Code)
	}
	var result auditListResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		f.t.Fatal(err)
	}
	return result
}
func assertAuditIDs(t *testing.T, events []auditDTO, want []int64) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("got %d audit events, want %d", len(events), len(want))
	}
	for i, event := range events {
		if event.ID != want[i] {
			t.Fatalf("audit row %d id=%d want=%d", i, event.ID, want[i])
		}
	}
}
