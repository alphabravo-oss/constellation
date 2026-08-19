package runtime

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// wireRuntimePolicyBundle / wireRuntimePolicy intentionally re-declare the exact
// JSON struct tags the runtime-agent's policy-sync worker decodes into
// (cmd/constellation-runtime-agent/runtime_policy_sync.go: runtimePolicyBundle /
// runtimePolicyWire). Decoding the handler's response into these structs is the
// contract test: if a server-side tag drifts, the agent silently loses the field
// and this test catches it.
type wireRuntimePolicy struct {
	ID         string           `json:"id"`
	DPPolicyID int64            `json:"dp_policy_id"`
	Workload   string           `json:"workload"`
	Mode       string           `json:"mode"`
	DefAction  uint8            `json:"def_action"`
	ApplyDir   int              `json:"apply_dir"`
	Rules      []*dp.PolicyRule `json:"rules"`
	Version    int64            `json:"version"`
}

type wireRuntimePolicyBundle struct {
	Policies []wireRuntimePolicy `json:"policies"`
}

// TestAgentPolicyBundle_WireShapeAndOrgScope verifies the H6 server leg: the
// /runtime/policies:bundle handler emits exactly the JSON the agent decodes,
// returns only non-disabled policies for the right cluster, and never leaks
// another org's policies. Integration test; skips with no test DB.
func TestAgentPolicyBundle_WireShapeAndOrgScope(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	// Required tables present?
	for _, table := range []string{"orgs", "clusters", "runtime_policies"} {
		var rc string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.'||$1)::text,'')`, table).Scan(&rc); err != nil || rc == "" {
			t.Skipf("skipping: %s not present (%v)", table, err)
		}
	}

	orgID := uuid.New()
	otherOrgID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Policy Bundle Test'),($3,$4,'Other Org')`,
		orgID, "policy-bundle-"+orgID.String(), otherOrgID, "policy-bundle-other-"+otherOrgID.String()); err != nil {
		t.Fatalf("orgs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1)`, []uuid.UUID{orgID, otherOrgID})
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1,$2,'policy-bundle-cluster','k3s','connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}

	store := NewRuntimePolicyStore(d, nil)

	enforceRules := []*dp.PolicyRule{
		{ID: 7, Ingress: false, SrcIP: net.ParseIP("10.42.0.5"), DstIP: net.ParseIP("0.0.0.0"),
			Port: 443, IPProto: 6, Action: dp.PolicyActionDeny, Fqdn: "evil.example.com"},
	}
	enforceJSON, _ := json.Marshal(enforceRules)
	enforce := &RuntimePolicy{
		OrgID: orgID, ClusterID: clusterID,
		Workload: "default/api", Namespace: "default", Name: "bundle-enforce",
		Mode: PolicyModeEnforce, DefAction: dp.PolicyActionAllow, ApplyDir: dp.ApplyDirBoth,
		Rules: enforceJSON,
	}
	enforceID, err := store.Insert(ctx, enforce, "test-req-enforce")
	if err != nil {
		t.Fatalf("insert enforce: %v", err)
	}

	// A disabled policy must be excluded from the bundle (ListForCluster filters it).
	disabled := &RuntimePolicy{
		OrgID: orgID, ClusterID: clusterID,
		Workload: "default/web", Namespace: "default", Name: "bundle-disabled",
		Mode: PolicyModeDisabled, DefAction: dp.PolicyActionAllow, ApplyDir: dp.ApplyDirBoth,
		Rules: json.RawMessage("[]"),
	}
	if _, err := store.Insert(ctx, disabled, "test-req-disabled"); err != nil {
		t.Fatalf("insert disabled: %v", err)
	}

	h := NewRuntimePoliciesHTTP(d, nil)

	// 1) Happy path: correct org token + cluster.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/policies:bundle?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(),
		&handler.RuntimeAgentToken{ID: uuid.New(), OrgID: orgID, Name: "agent-test"}))
	h.AgentPolicyBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bundle status=%d body=%s", rec.Code, rec.Body.String())
	}
	var bundle wireRuntimePolicyBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v body=%s", err, rec.Body.String())
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 non-disabled policy, got %d: %s", len(bundle.Policies), rec.Body.String())
	}
	got := bundle.Policies[0]
	if got.ID != enforceID.String() {
		t.Fatalf("policy id = %q want %q", got.ID, enforceID.String())
	}
	if got.Workload != "default/api" || got.Mode != "enforce" {
		t.Fatalf("workload/mode = %q/%q", got.Workload, got.Mode)
	}
	if got.DPPolicyID != enforce.DPPolicyID || got.DPPolicyID == 0 {
		t.Fatalf("dp_policy_id = %d want %d (non-zero)", got.DPPolicyID, enforce.DPPolicyID)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d want 1", got.Version)
	}
	if len(got.Rules) != 1 || got.Rules[0].Action != dp.PolicyActionDeny || got.Rules[0].Port != 443 ||
		got.Rules[0].Fqdn != "evil.example.com" {
		t.Fatalf("rules not round-tripped: %+v", got.Rules)
	}

	// Verify the raw JSON actually carries the snake_case keys the agent expects
	// (decoding alone tolerates missing keys as zero values).
	var raw struct {
		Policies []map[string]json.RawMessage `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	for _, k := range []string{"id", "dp_policy_id", "workload", "mode", "def_action", "apply_dir", "rules", "version"} {
		if _, ok := raw.Policies[0][k]; !ok {
			t.Fatalf("bundle JSON missing key %q; agent worker would silently lose it: %s", k, rec.Body.String())
		}
	}

	// 2) Cross-org isolation: a token for another org must not see this cluster.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/runtime/policies:bundle?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(),
		&handler.RuntimeAgentToken{ID: uuid.New(), OrgID: otherOrgID, Name: "other-agent"}))
	h.AgentPolicyBundle(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org bundle status=%d want 404 body=%s", rec.Code, rec.Body.String())
	}

	// 3) Missing token -> 401.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/runtime/policies:bundle?cluster_id="+clusterID.String(), nil)
	h.AgentPolicyBundle(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status=%d want 401", rec.Code)
	}
}
