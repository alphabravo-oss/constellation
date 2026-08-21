package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
)

// RT-KILL-02: the :pending endpoint must return only the calling node's pending rows,
// org-scoped by the token — never another org's rows, another node's rows, or terminal
// rows; node='' rows are broadcast to every node.
func TestResponseActions_PendingNodeAndOrgScoped(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	orgA, orgB := uuid.New(), uuid.New()
	clusterID := uuid.New()
	wantWL := "ns/target-" + uuid.New().String()

	// org A / node-a / pending  -> WANT
	// org A / node='' / pending -> WANT (broadcast)
	// org A / node-b / pending  -> not this node
	// org A / node-a / done     -> terminal
	// org B / node-a / pending  -> other org
	seed := []struct {
		org   uuid.UUID
		node  string
		wl    string
		state string
	}{
		{orgA, "node-a", wantWL, "pending"},
		{orgA, "", "ns/broadcast", "pending"},
		{orgA, "node-b", "ns/other-node", "pending"},
		{orgA, "node-a", "ns/already-done", "done"},
		{orgB, "node-a", "ns/other-org", "pending"},
	}
	for _, s := range seed {
		if _, err := pool.Exec(ctx, `
INSERT INTO runtime_response_actions (org_id, cluster_id, node, type, workload_id, state)
VALUES ($1, $2, $3, 'kill_process', $4, $5)`,
			s.org, clusterID, s.node, s.wl, s.state); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_response_actions WHERE org_id = ANY($1)`,
			[]uuid.UUID{orgA, orgB})
	})

	h := NewResponseActions(d)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/runtime/response-actions:pending?cluster_id="+clusterID.String()+"&node=node-a", nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{OrgID: orgA}))
	w := httptest.NewRecorder()
	h.Pending(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var out struct {
		Actions []responseActionWire `json:"actions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]bool{}
	for _, a := range out.Actions {
		got[a.WorkloadID] = true
		if a.Type != "kill_process" {
			t.Fatalf("unexpected type %q", a.Type)
		}
	}
	if len(out.Actions) != 2 || !got[wantWL] || !got["ns/broadcast"] {
		t.Fatalf("expected node-a + broadcast rows only, got %+v", out.Actions)
	}
}

// RT-KILL-02: the :result sink flips a pending row to done|failed with result/error +
// completed_at, and only touches the token org's rows.
func TestResponseActions_ResultFlipsState(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	orgID := uuid.New()
	clusterID := uuid.New()

	var id uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO runtime_response_actions (org_id, cluster_id, node, type, workload_id, state)
VALUES ($1, $2, 'node-a', 'kill_process', 'ns/api', 'pending') RETURNING id`,
		orgID, clusterID).Scan(&id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_response_actions WHERE org_id=$1`, orgID)
	})

	body, _ := json.Marshal(responseActionResultWire{
		ID: id.String(), Type: "kill_process", Node: "node-a", Applied: true, Reason: "", At: time.Now().UTC(),
	})
	h := NewResponseActions(d)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/response-actions:result", bytes.NewReader(body))
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{OrgID: orgID}))
	w := httptest.NewRecorder()
	h.Result(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var state string
	var completed *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT state, completed_at FROM runtime_response_actions WHERE id=$1`, id).Scan(&state, &completed); err != nil {
		t.Fatal(err)
	}
	if state != "done" || completed == nil {
		t.Fatalf("expected done+completed_at, got state=%q completed=%v", state, completed)
	}

	// A different org's token must not flip this row. Re-seed a fresh pending row and try
	// to complete it with the wrong org.
	var id2 uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO runtime_response_actions (org_id, cluster_id, type, workload_id, state)
VALUES ($1, $2, 'kill_process', 'ns/api2', 'pending') RETURNING id`, orgID, clusterID).Scan(&id2); err != nil {
		t.Fatalf("seed2: %v", err)
	}
	body2, _ := json.Marshal(responseActionResultWire{ID: id2.String(), Applied: true, At: time.Now().UTC()})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/response-actions:result", bytes.NewReader(body2))
	req2 = req2.WithContext(handler.WithRuntimeAgentToken(req2.Context(), &handler.RuntimeAgentToken{OrgID: uuid.New()}))
	w2 := httptest.NewRecorder()
	h.Result(w2, req2)
	var state2 string
	if err := pool.QueryRow(ctx, `SELECT state FROM runtime_response_actions WHERE id=$1`, id2).Scan(&state2); err != nil {
		t.Fatal(err)
	}
	if state2 != "pending" {
		t.Fatalf("cross-org result must not flip row; state=%q", state2)
	}
}

// RT-KILL-02: a response rule's kill action (quarantineRuntime.Kill) enqueues a pending
// kill_process row scoped to the workload/org/cluster.
func TestQuarantineRuntime_KillEnqueues(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	orgID := uuid.New()
	clusterID := uuid.New()
	workload := "kill-ns/kill-" + uuid.New().String()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_response_actions WHERE org_id=$1`, orgID)
	})

	q := &quarantineRuntime{db: d, orgID: orgID, clusterID: clusterID}
	if err := q.Kill(ctx, workload, "shell-in-container"); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	var n int
	var typ, state string
	if err := pool.QueryRow(ctx, `
SELECT count(*), COALESCE(max(type),''), COALESCE(max(state),'')
  FROM runtime_response_actions
 WHERE org_id=$1 AND cluster_id=$2 AND workload_id=$3`,
		orgID, clusterID, workload).Scan(&n, &typ, &state); err != nil {
		t.Fatal(err)
	}
	if n != 1 || typ != "kill_process" || state != "pending" {
		t.Fatalf("expected 1 pending kill_process row, got n=%d type=%q state=%q", n, typ, state)
	}

	// Empty workload is a no-op (nothing to target).
	if err := q.Kill(ctx, "  ", "noop"); err != nil {
		t.Fatalf("Kill(empty): %v", err)
	}
}
