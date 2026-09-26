package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func TestGroupEdgesAuditAttemptFailurePreventsMutation(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterID, userID := uuid.New(), uuid.New(), uuid.New()
	defer func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) }()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Edge Audit')`, orgID, "edge-audit-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,'edge-audit')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	for _, group := range []struct{ name, member string }{{"source", "default/front"}, {"destination", "default/back"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,$3,'ground',$4::jsonb)`, orgID, clusterID, group.name, `["`+group.member+`"]`); err != nil {
			t.Fatal(err)
		}
	}
	h := NewGroupEdgesHTTP(database, NewRuntimePolicyStore(database, nil), nil)
	call := func(method, path string, body any, serve func(http.ResponseWriter, *http.Request)) int {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(payload))
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: userID}))
		response := httptest.NewRecorder()
		serve(response, request)
		return response.Code
	}
	base := "/api/v1/runtime-policies/group-edges"
	request := CreateEdgeRequest{ClusterID: clusterID, FromGroup: "source", ToGroup: "destination", Mode: "protect", Expand: true}
	var attempts []audit.Event
	h.auditWriter = func(_ context.Context, event audit.Event) error {
		attempts = append(attempts, event)
		return errors.New("audit unavailable")
	}
	if status := call(http.MethodPost, base, request, h.Create); status != http.StatusServiceUnavailable {
		t.Fatalf("create with audit failure status=%d", status)
	}
	var edges int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edges); err != nil || edges != 0 {
		t.Fatalf("edges after failed create attempt=%d err=%v", edges, err)
	}
	if len(attempts) != 1 || attempts[0].Action != "group_rule_edge.upsert_attempt" || attempts[0].TargetID == "" || attempts[0].After == nil {
		t.Fatalf("create attempt event=%+v", attempts)
	}
	h.auditWriter = func(_ context.Context, event audit.Event) error {
		if event.Action == "group_rule_edge.expand_attempt" {
			return errors.New("audit unavailable")
		}
		return nil
	}
	if status := call(http.MethodPost, base, request, h.Create); status != http.StatusServiceUnavailable {
		t.Fatalf("create expansion audit failure status=%d", status)
	}
	var edgeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edges); err != nil || edges != 0 {
		t.Fatalf("edges after failed expansion audit=%d err=%v", edges, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE groups SET members='["default/front-a","default/front-b"]'::jsonb WHERE org_id=$1 AND name='source'`, orgID); err != nil {
		t.Fatal(err)
	}
	constraint := "edge_http_atomic_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE runtime_policies DROP CONSTRAINT IF EXISTS `+constraint)
	})
	if _, err := pool.Exec(ctx, `ALTER TABLE runtime_policies ADD CONSTRAINT `+constraint+` CHECK (NOT (org_id='`+orgID.String()+`'::uuid AND workload='default/front-b')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	h.auditWriter = func(context.Context, audit.Event) error { return nil }
	if status := call(http.MethodPost, base, request, h.Create); status != http.StatusInternalServerError {
		t.Fatalf("create with policy insert failure status=%d", status)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edges); err != nil || edges != 0 {
		t.Fatalf("edges after policy insert failure=%d err=%v", edges, err)
	}
	var failedPolicies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1`, orgID).Scan(&failedPolicies); err != nil || failedPolicies != 0 {
		t.Fatalf("policies after policy insert failure=%d err=%v", failedPolicies, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE runtime_policies DROP CONSTRAINT `+constraint); err != nil {
		t.Fatal(err)
	}
	row, err := h.store.Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{FromGroup: "source", ToGroup: "destination", Mode: "protect"}, &userID)
	if err != nil {
		t.Fatal(err)
	}
	edgeID = row.ID
	h.auditWriter = func(_ context.Context, event audit.Event) error { return errors.New("audit unavailable") }
	if status := call(http.MethodPost, base+"/"+edgeID.String()+"/expand", nil, h.Expand); status != http.StatusServiceUnavailable {
		t.Fatalf("explicit expand audit failure status=%d", status)
	}
	var policies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&policies); err != nil || policies != 0 {
		t.Fatalf("policies after failed expand attempts=%d err=%v", policies, err)
	}
	if status := call(http.MethodDelete, base+"/"+edgeID.String(), nil, h.Delete); status != http.StatusServiceUnavailable {
		t.Fatalf("delete audit failure status=%d", status)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE id=$1`, edgeID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("edge after failed delete attempt=%d err=%v", edges, err)
	}
}
