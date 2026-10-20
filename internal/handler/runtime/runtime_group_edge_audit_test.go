//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func edgeAuditRequest(t *testing.T, f reviewedPolicyFixture, h *GroupEdgesHTTP, id uuid.UUID, operation string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path, method := "/runtime-policies/group-edges", http.MethodPost
	switch operation {
	case "expand":
		path += "/" + id.String() + "/expand"
	case "delete":
		method = http.MethodDelete
		path += "/" + id.String()
	}
	req := httptest.NewRequestWithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: f.org, UserID: f.actor}), method, path, bytes.NewReader(raw))
	req.Header.Set("X-Request-Id", "edge-audit-request")
	w := httptest.NewRecorder()
	switch operation {
	case "upsert":
		h.Create(w, req)
	case "expand":
		h.Expand(w, req)
	case "delete":
		h.Delete(w, req)
	}
	return w
}

func edgeAuditBody(f reviewedPolicyFixture, edge netpolicy.GroupEdge, expand bool) CreateEdgeRequest {
	return CreateEdgeRequest{ClusterID: f.cluster, FromGroup: edge.FromGroup, ToGroup: edge.ToGroup, Ports: edge.Ports, Mode: edge.Mode, Comment: edge.Comment, Expand: expand}
}

func edgeCompletionCount(t *testing.T, f reviewedPolicyFixture) int {
	t.Helper()
	var count int
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND target_kind='group_rule_edge' AND action IN('group_rule_edge.upsert','group_rule_edge.expand','group_rule_edge.delete')`, f.org).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestEdgeRequiredCompletionFailureRollsBackEveryHTTPMutation(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	row, _, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, edge, &f.actor)
	if err != nil {
		t.Fatal(err)
	}
	h := NewGroupEdgesHTTP(store.db, store.pol, store.pol.auditLog)
	before := edgePolicySnapshot(t, f)
	completed := edgeCompletionCount(t, f)
	cases := []struct {
		name, operation, reject string
		body                    CreateEdgeRequest
	}{
		{"plain create", "upsert", "group_rule_edge.upsert", edgeAuditBody(f, netpolicy.GroupEdge{FromGroup: "back", ToGroup: "front", Mode: "protect"}, false)},
		{"create expansion", "upsert", "group_rule_edge.expand", edgeAuditBody(f, netpolicy.GroupEdge{FromGroup: "back", ToGroup: "front", Mode: "protect"}, true)},
		{"edit with implicit expansion", "upsert", "group_rule_edge.expand", edgeAuditBody(f, netpolicy.GroupEdge{FromGroup: "front", ToGroup: "back", Mode: "protect", Ports: []netpolicy.PortSpec{{Protocol: "TCP", Port: 8443}}}, false)},
		{"explicit expansion", "expand", "group_rule_edge.expand", CreateEdgeRequest{}},
		{"delete", "delete", "group_rule_edge.delete", CreateEdgeRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.auditTxWriter = func(ctx context.Context, tx pgx.Tx, event audit.Event) error {
				if event.Action == tc.reject {
					return errors.New("injected completion unavailable")
				}
				_, _, err := store.pol.auditLog.LogInTx(ctx, tx, event)
				return err
			}
			w := edgeAuditRequest(t, f, h, row.ID, tc.operation, tc.body)
			if w.Code != 503 || strings.Contains(w.Body.String(), "injected") {
				t.Fatalf("completion failure%d %s", w.Code, w.Body.String())
			}
			if state := edgePolicySnapshot(t, f); state != before {
				t.Fatal("completion failure committed edge, policy or member state")
			}
			if edgeCompletionCount(t, f) != completed {
				t.Fatal("completion from rolled-back mutation escaped")
			}
			assertEdgeFailureReceipt(t, f, tc.operation)
		})
	}
}

func assertEdgeFailureReceipt(t *testing.T, f reviewedPolicyFixture, operation string) {
	t.Helper()
	var committed bool
	var request, reason string
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT (after->>'committed')::bool,after->>'reason',request_id FROM audit_events WHERE org_id=$1 AND action=$2 ORDER BY id DESC LIMIT 1`, f.org, "group_rule_edge."+operation+"_failed").Scan(&committed, &reason, &request); err != nil {
		t.Fatal(err)
	}
	if committed || reason != "audit_unavailable" || request != "edge-audit-request" {
		t.Fatalf("misleading failed receipt %v %s %s", committed, reason, request)
	}
}

func TestEdgeHTTPMissingCompletionWriterCannotFallBackToOptionalStoreAudit(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	h := NewGroupEdgesHTTP(store.db, store.pol, store.pol.auditLog)
	h.auditTxWriter = nil
	// Preserve independent writer injection: a successful attempt writer is not
	// evidence of a transactional completion writer or permission to bypass it.
	h.auditWriter = func(context.Context, audit.Event) error { return nil }
	before := edgePolicySnapshot(t, f)
	w := edgeAuditRequest(t, f, h, uuid.Nil, "upsert", edgeAuditBody(f, edge, true))
	if w.Code != 503 || edgePolicySnapshot(t, f) != before || edgeCompletionCount(t, f) != 0 {
		t.Fatalf("missing completion quietly succeeded%d %s", w.Code, w.Body.String())
	}
}

func rejectEdgeCompletion(t *testing.T, f reviewedPolicyFixture, action string) func() {
	t.Helper()
	function := pgx.Identifier{"reject_edge_" + uuid.NewString()}.Sanitize()
	trigger := pgx.Identifier{"reject_edge_" + uuid.NewString()}.Sanitize()
	pool := f.h.store.db.Pool()
	sql := fmt.Sprintf(`CREATE FUNCTION %s()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.action='%s' THEN RAISE EXCEPTION 'fixture final edge audit rejected'; END IF; RETURN NEW; END $$`, function, f.org, action)
	if _, err := pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TRIGGER `+trigger+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
		t.Fatal(err)
	}
	removed := false
	remove := func() {
		if removed {
			return
		}
		removed = true
		for _, query := range []string{`DROP TRIGGER IF EXISTS ` + trigger + ` ON audit_events`, `DROP FUNCTION IF EXISTS ` + function + `() `} {
			if _, err := pool.Exec(context.Background(), query); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(remove)
	return remove
}

func TestConfiguredEdgeAuditFailureKeepsAttemptsButNoCompletionOrMutation(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	h := NewGroupEdgesHTTP(store.db, store.pol, store.pol.auditLog)
	remove := rejectEdgeCompletion(t, f, "group_rule_edge.expand")
	before := edgePolicySnapshot(t, f)
	w := edgeAuditRequest(t, f, h, uuid.Nil, "upsert", edgeAuditBody(f, edge, true))
	if w.Code != 503 || strings.Contains(w.Body.String(), "fixture") || edgePolicySnapshot(t, f) != before {
		t.Fatalf("configured completion failure%d %s", w.Code, w.Body.String())
	}
	var attempts, failed, completions, policyEvents int
	if err := store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FILTER(WHERE action LIKE '%_attempt'),count(*) FILTER(WHERE action LIKE '%_failed'),count(*) FILTER(WHERE action IN('group_rule_edge.upsert','group_rule_edge.expand')),count(*) FILTER(WHERE target_kind='runtime_policy') FROM audit_events WHERE org_id=$1`, f.org).Scan(&attempts, &failed, &completions, &policyEvents); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || failed != 2 || completions != 0 || policyEvents != 0 {
		t.Fatalf("incorrect audit outcome attempts%d failed%d complete%d policies%d", attempts, failed, completions, policyEvents)
	}
	remove()
	w = edgeAuditRequest(t, f, h, uuid.Nil, "upsert", edgeAuditBody(f, edge, true))
	if w.Code != 201 || edgeCompletionCount(t, f) != 2 {
		t.Fatalf("recovery%d %s", w.Code, w.Body.String())
	}
}

func TestEdgeFailedReceiptFailureDoesNotTurnRollbackIntoSuccess(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	h := NewGroupEdgesHTTP(store.db, store.pol, store.pol.auditLog)
	h.auditWriter = func(ctx context.Context, event audit.Event) error {
		if strings.HasSuffix(event.Action, "_failed") {
			return errors.New("failed receipt unavailable")
		}
		_, _, err := store.pol.auditLog.Log(ctx, event)
		return err
	}
	h.auditTxWriter = func(context.Context, pgx.Tx, audit.Event) error { return errors.New("completion unavailable") }
	before := edgePolicySnapshot(t, f)
	if w := edgeAuditRequest(t, f, h, uuid.Nil, "upsert", edgeAuditBody(f, edge, false)); w.Code != 503 || edgePolicySnapshot(t, f) != before {
		t.Fatalf("failure audit changed result%d %s", w.Code, w.Body.String())
	}
}

func TestEdgeCompletionUsesLockedStateRatherThanHTTPPreRead(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	row, _, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, edge, &f.actor)
	if err != nil {
		t.Fatal(err)
	}
	h := NewGroupEdgesHTTP(store.db, store.pol, store.pol.auditLog)
	h.auditWriter = func(ctx context.Context, event audit.Event) error {
		if _, err := store.db.Pool().Exec(ctx, `UPDATE group_rule_edges SET comment='latest concurrent edge' WHERE id=$1`, row.ID); err != nil {
			return err
		}
		_, _, err := store.pol.auditLog.Log(ctx, event)
		return err
	}
	w := edgeAuditRequest(t, f, h, row.ID, "expand", nil)
	if w.Code != 200 {
		t.Fatalf("expand%d %s", w.Code, w.Body.String())
	}
	var comment, cluster, request string
	var actor *uuid.UUID
	if err := store.db.Pool().QueryRow(t.Context(), `SELECT before->>'comment',before->>'cluster_id',request_id,actor_id FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='group_rule_edge.expand' ORDER BY id DESC LIMIT 1`, f.org, row.ID.String()).Scan(&comment, &cluster, &request, &actor); err != nil {
		t.Fatal(err)
	}
	if comment != "latest concurrent edge" || cluster != f.cluster.String() || request != "edge-audit-request" || actor == nil || *actor != f.actor {
		t.Fatalf("stale or misattributed completion %s %s %s %v", comment, cluster, request, actor)
	}
}

func TestConcurrentFirstEdgeUpsertsAuditActualPreviousState(t *testing.T) {
	f, store, edge := auditedEdgeFixture(t)
	start := make(chan struct{})
	failures := make(chan error, 2)
	var writers sync.WaitGroup
	for _, mode := range []string{"monitor", "protect"} {
		writers.Go(func() {
			<-start
			candidate := edge
			candidate.Mode = mode
			candidate.Comment = mode
			_, _, err := store.UpsertAndExpand(t.Context(), f.org, f.cluster, candidate, &f.actor)
			failures <- err
		})
	}
	close(start)
	writers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.db.Pool().Query(t.Context(), `SELECT before,after FROM audit_events WHERE org_id=$1 AND action='group_rule_edge.upsert' ORDER BY id`, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var previous *GroupEdgeRow
	count := 0
	for rows.Next() {
		var before *GroupEdgeRow
		var after GroupEdgeRow
		if err := rows.Scan(&before, &after); err != nil {
			t.Fatal(err)
		}
		if count == 0 && before != nil {
			t.Fatal("first creation has fabricated previous edge")
		}
		if count > 0 && (before == nil || before.Mode != previous.Mode || before.Comment != previous.Comment || before.ID != previous.ID) {
			t.Fatal("second upsert did not audit first committed edge")
		}
		previous = &after
		count++
	}
	if err := rows.Err(); err != nil || count != 2 {
		t.Fatalf("upsert history%d %v", count, err)
	}
	var policies int
	wantMode, _ := edgePolicyPosture(previous.Mode)
	if err := store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND name=$2 AND mode=$3`, f.org, edgePolicyName(edge), string(wantMode)).Scan(&policies); err != nil || policies != 2 {
		t.Fatalf("concurrent edge posture out of sync%d %v", policies, err)
	}
}

func TestMembershipCompletionAuditFailureRollsBackEntireTransition(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, cluster, id, _, reconciler := membershipEdgeFixture(t, d)
	reconciler.edges.pol.auditLog = audit.New(d.Pool())
	f := reviewedPolicyFixture{h: &RuntimePoliciesHTTP{store: reconciler.edges.pol}, org: org, cluster: cluster}
	before := edgePolicySnapshot(t, f)
	remove := rejectEdgeCompletion(t, f, "group.membership.refresh")
	if _, changed, err := reconciler.reconcileMembership(t.Context(), org, id, membershipGuardWorkloads(cluster)); err == nil || changed {
		t.Fatalf("membership completion failed but claimed success%v %v", changed, err)
	}
	if edgePolicySnapshot(t, f) != before {
		t.Fatal("membership completion failure committed profile, policies or members")
	}
	remove()
	if _, changed, err := reconciler.reconcileMembership(t.Context(), org, id, membershipGuardWorkloads(cluster)); err != nil || !changed {
		t.Fatalf("membership retry%v %v", changed, err)
	}
	var actor *uuid.UUID
	var oldMembers, newMembers []string
	if err := d.Pool().QueryRow(t.Context(), `SELECT actor_id,before->'members',after->'members' FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='group.membership.refresh'`, org, id.String()).Scan(&actor, &oldMembers, &newMembers); err != nil {
		t.Fatal(err)
	}
	if actor != nil || len(oldMembers) != 1 || oldMembers[0] != "default/old" || len(newMembers) != 1 || newMembers[0] != "default/new" {
		t.Fatalf("incorrect background membership receipt %v %v %v", actor, oldMembers, newMembers)
	}
}

func TestEdgeFailedReceiptDoesNotInventRollbackAfterLostCommitReceipt(t *testing.T) {
	h := &GroupEdgesHTTP{}
	var received audit.Event
	h.auditWriter = func(_ context.Context, event audit.Event) error { received = event; return nil }
	sub := authctx.Subject{OrgID: uuid.New(), UserID: uuid.New()}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/group-edges", nil)
	req.Header.Set("X-Request-Id", "unknown-commit-request")
	h.mutationFailed(req, sub, "owned-edge-intent", edgeCommitFailure{cause: errors.New("connection closed awaiting commit")}, "group_rule_edge.upsert")
	outcome, ok := received.After.(map[string]any)
	if !ok || outcome["commit_status"] != "unknown" || outcome["reason"] != "commit_unconfirmed" {
		t.Fatalf("unconfirmed commit outcome fabricated %+v", received)
	}
	if _, claimed := outcome["committed"]; claimed {
		t.Fatal("lost commit acknowledgement falsely claimed rollback")
	}
	if received.Action != "group_rule_edge.upsert_failed" || received.OrgID == nil || *received.OrgID != sub.OrgID || received.ActorID == nil || *received.ActorID != sub.UserID || received.RequestID != "unknown-commit-request" {
		t.Fatalf("failure receipt lost its source %+v", received)
	}
}
