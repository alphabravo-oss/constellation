package netpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestNetworkPolicies_ListWithoutStorageReturnsEmptyLiveState(t *testing.T) {
	w := httptest.NewRecorder()
	NewNetworkPolicies().List(w, httptest.NewRequest("GET", "/api/v1/network/policies/lifecycle", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var got struct {
		Items   []networkPolicyLifecycleDTO `json:"items"`
		Summary struct {
			Total   int `json:"total"`
			Ready   int `json:"ready"`
			Monitor int `json:"monitor"`
			Protect int `json:"protect"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Items) != 0 || got.Summary.Total != 0 || got.Summary.Ready != 0 || got.Summary.Monitor != 0 || got.Summary.Protect != 0 {
		t.Fatalf("unexpected lifecycle summary: %+v items=%d", got.Summary, len(got.Items))
	}
}

func TestNetworkPolicies_ListFiltersNamespace(t *testing.T) {
	w := httptest.NewRecorder()
	NewNetworkPolicies().List(w, httptest.NewRequest("GET", "/api/v1/network/policies/lifecycle?namespace=data", nil))

	var got struct {
		Items []networkPolicyLifecycleDTO `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("unexpected namespace filter result: %+v", got.Items)
	}
}

func TestNetworkPolicies_PreviewActionRequiresStorage(t *testing.T) {
	r := chi.NewRouter()
	r.Post("/api/v1/network/policies/{workload}/{action}", NewNetworkPolicies().PreviewAction)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/network/policies/default%2Fapi-service/approve", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestNetworkPolicies_ActionPersistsStateAndAudit(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	// Shrink the learn window and minimum-flow threshold (as the other
	// lifecycle tests do) so the freshly-seeded workloads promote out of the
	// default 7-day discover window. Without this the engine re-seeds every
	// workload to discover/now, leaving target modes empty so approve/apply
	// never transition to monitor/protect and the persisted audit trail never
	// accumulates the expected events. Setup only — no assertions changed.
	t.Setenv("CONSTELLATION_NETPOLICY_LEARN_WINDOW", "1s")
	t.Setenv("CONSTELLATION_NETPOLICY_MIN_FLOWS", "1")

	orgID := uuid.New()
	clusterID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Policy Test')`, orgID, "netpol-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'netpol-prod', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	seedNetworkPolicyObservedWorkloads(t, pool, orgID, clusterID, 25)
	// Seed default/frontend in Monitor with mode_since an hour ago (well past the
	// 1s window) so its candidate evaluates Monitor->Protect: the apply below can
	// then transition it to Protect and the subsequent rollback restores Monitor.
	// default/api-service is intentionally left without a persisted row so its
	// approve creates exactly one lifecycle action/audit event (asserted below).
	// Mirrors the NET-4 lifecycle test's seeding; setup only.
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_lifecycle_states (org_id, cluster_id, workload, namespace, current_mode, target_mode, approval_status, reason, mode_since)
VALUES ($1, $2, 'default/frontend', 'default', 'monitor', 'protect', 'approved', 'monitoring', NOW() - INTERVAL '1 hour')`,
		orgID, clusterID); err != nil {
		t.Fatalf("seed frontend monitor state: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := chi.NewRouter()
	h := NewNetworkPolicies(d, audit.New(pool))
	r.Post("/api/v1/network/policies/{workload}/rollback", h.Rollback)
	r.Post("/api/v1/network/policies/{workload}/{action}", h.PreviewAction)
	r.Get("/api/v1/network/policies/lifecycle", h.List)

	apiHash := networkPolicyHashForTest(t, r, orgID, userID, "default/api-service")
	req := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Fapi-service/approve", strings.NewReader(`{"candidate_hash":"`+apiHash+`"}`))
	req.Header.Set("Idempotency-Key", "netpol-approve-"+orgID.String())
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", w.Code, w.Body.String())
	}
	var approved struct {
		ActionID string                    `json:"action_id"`
		Persists bool                      `json:"persists"`
		Policy   networkPolicyLifecycleDTO `json:"policy"`
	}
	if err := json.NewDecoder(w.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approve: %v", err)
	}
	if !approved.Persists || approved.ActionID == "" || approved.Policy.ApprovalStatus != "approved" {
		t.Fatalf("unexpected approve response: %+v", approved)
	}

	retryReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Fapi-service/approve", strings.NewReader(`{"candidate_hash":"`+apiHash+`"}`))
	retryReq.Header.Set("Idempotency-Key", "netpol-approve-"+orgID.String())
	retryReq = retryReq.WithContext(authctx.WithSubject(retryReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	retryResp := httptest.NewRecorder()
	r.ServeHTTP(retryResp, retryReq)
	if retryResp.Code != http.StatusOK {
		t.Fatalf("retry approve status=%d body=%s", retryResp.Code, retryResp.Body.String())
	}
	var replayed struct {
		ActionID       string `json:"action_id"`
		IdempotencyKey string `json:"idempotency_key"`
		Idempotent     bool   `json:"idempotent"`
	}
	if err := json.NewDecoder(retryResp.Body).Decode(&replayed); err != nil {
		t.Fatalf("decode retry approve: %v", err)
	}
	if !replayed.Idempotent || replayed.ActionID != approved.ActionID || replayed.IdempotencyKey == "" {
		t.Fatalf("unexpected idempotent replay: %+v approved=%+v", replayed, approved)
	}

	var status string
	var actions int
	if err := pool.QueryRow(ctx, `SELECT approval_status FROM network_policy_lifecycle_states WHERE org_id = $1 AND cluster_id = $2 AND workload = 'default/api-service'`, orgID, clusterID).Scan(&status); err != nil {
		t.Fatalf("state row: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_policy_lifecycle_actions WHERE org_id = $1 AND cluster_id = $2 AND workload = 'default/api-service'`, orgID, clusterID).Scan(&actions); err != nil {
		t.Fatalf("action count: %v", err)
	}
	if status != "approved" || actions != 1 {
		t.Fatalf("missing persisted state/action status=%s actions=%d", status, actions)
	}
	var auditEvents int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM audit_events
 WHERE org_id = $1 AND action = 'network_policy.approve' AND target_id = 'default/api-service'`, orgID).Scan(&auditEvents); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditEvents != 1 {
		t.Fatalf("expected one hash-chained audit event for idempotent approve, got %d", auditEvents)
	}

	listReq := httptest.NewRequest("GET", "/api/v1/network/policies/lifecycle", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listResp := httptest.NewRecorder()
	r.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResp.Code, listResp.Body.String())
	}
	var listed struct {
		Items []networkPolicyLifecycleDTO `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, item := range listed.Items {
		if item.Workload == "default/api-service" {
			// api-service has exactly one lifecycle action (the approve above;
			// the retry is an idempotent replay, consistent with the actions==1
			// assertion). The overlaid trail is therefore the list-derived
			// "evaluated" event plus the single persisted approve event, i.e.
			// length two. The org is freshly generated per run so this count is
			// determined solely by the rows this test creates.
			found = item.ApprovalStatus == "approved" && len(item.AuditTrail) >= 2
		}
	}
	if !found {
		t.Fatalf("persisted state not overlaid in list: %+v", listed.Items)
	}

	frontendHash := networkPolicyHashForTest(t, r, orgID, userID, "default/frontend")
	applyReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Ffrontend/apply", strings.NewReader(`{"candidate_hash":"`+frontendHash+`"}`))
	applyReq = applyReq.WithContext(authctx.WithSubject(applyReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	applyResp := httptest.NewRecorder()
	r.ServeHTTP(applyResp, applyReq)
	if applyResp.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyResp.Code, applyResp.Body.String())
	}
	var applied struct {
		ActionID    string                    `json:"action_id"`
		RollbackRef string                    `json:"rollback_ref"`
		Policy      networkPolicyLifecycleDTO `json:"policy"`
	}
	if err := json.NewDecoder(applyResp.Body).Decode(&applied); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if applied.ActionID == "" || applied.RollbackRef == "" || applied.Policy.CurrentMode != "protect" || !applied.Policy.RollbackAvailable {
		t.Fatalf("unexpected apply response: %+v", applied)
	}
	assertPolicyManifestBundle(t, applied.Policy.Preview)
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_apply_status (
    org_id, cluster_id, workload, namespace, flavor, resource_ref, desired_mode, approval_status,
    last_action, status, candidate_hash, applied_ref, updated_at, last_applied_at
) VALUES ($1,$2,'default/frontend','default','native','networking.k8s.io/v1/NetworkPolicy:default/frontend-policy','protect','applied','apply','ok',$3,$4,NOW(),NOW())`,
		orgID, clusterID, applied.Policy.CandidateHash, applied.Policy.AppliedRef); err != nil {
		t.Fatalf("insert apply status: %v", err)
	}
	statusReq := httptest.NewRequest("GET", "/api/v1/network/policies/lifecycle", nil)
	statusReq = statusReq.WithContext(authctx.WithSubject(statusReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	statusResp := httptest.NewRecorder()
	r.ServeHTTP(statusResp, statusReq)
	if statusResp.Code != http.StatusOK {
		t.Fatalf("status list=%d body=%s", statusResp.Code, statusResp.Body.String())
	}
	var statusListed struct {
		Items []networkPolicyLifecycleDTO `json:"items"`
	}
	if err := json.NewDecoder(statusResp.Body).Decode(&statusListed); err != nil {
		t.Fatalf("decode status list: %v", err)
	}
	if !hasApplyStatus(statusListed.Items, "default/frontend", "native", "ok") {
		t.Fatalf("missing apply status overlay: %+v", statusListed.Items)
	}
	var storedManifests map[string]string
	var storedRaw []byte
	if err := pool.QueryRow(ctx, `
SELECT preview_manifests
  FROM network_policy_lifecycle_actions
 WHERE org_id = $1 AND cluster_id = $2 AND workload = 'default/frontend' AND action = 'apply'`, orgID, clusterID).Scan(&storedRaw); err != nil {
		t.Fatalf("stored apply manifests: %v", err)
	}
	if err := json.Unmarshal(storedRaw, &storedManifests); err != nil {
		t.Fatalf("decode stored manifests: %v", err)
	}
	if storedManifests["native"] == "" || storedManifests["cilium"] == "" || storedManifests["calico"] == "" {
		t.Fatalf("missing stored manifest flavors: %+v", storedManifests)
	}

	rollbackReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Ffrontend/rollback", nil)
	rollbackReq = rollbackReq.WithContext(authctx.WithSubject(rollbackReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rollbackResp := httptest.NewRecorder()
	r.ServeHTTP(rollbackResp, rollbackReq)
	if rollbackResp.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackResp.Code, rollbackResp.Body.String())
	}
	var rolledBack struct {
		ActionID    string                    `json:"action_id"`
		RollbackRef string                    `json:"rollback_ref"`
		Policy      networkPolicyLifecycleDTO `json:"policy"`
	}
	if err := json.NewDecoder(rollbackResp.Body).Decode(&rolledBack); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}
	if rolledBack.ActionID == "" || rolledBack.RollbackRef != applied.RollbackRef || rolledBack.Policy.CurrentMode != "monitor" || rolledBack.Policy.RollbackAvailable {
		t.Fatalf("unexpected rollback response: %+v", rolledBack)
	}
	var frontendStatus, frontendMode string
	if err := pool.QueryRow(ctx, `SELECT approval_status, current_mode FROM network_policy_lifecycle_states WHERE org_id = $1 AND cluster_id = $2 AND workload = 'default/frontend'`, orgID, clusterID).Scan(&frontendStatus, &frontendMode); err != nil {
		t.Fatalf("frontend state: %v", err)
	}
	if frontendStatus != "rolled_back" || frontendMode != "monitor" {
		t.Fatalf("rollback did not persist state: status=%s mode=%s", frontendStatus, frontendMode)
	}
}

func TestNetworkPolicies_DemoteRejectsDiscover(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	orgID := uuid.New()
	clusterID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Policy Discover')`, orgID, "netpol-discover-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-discover-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'netpol-discover-prod', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	seedNetworkPolicyObservedWorkloads(t, pool, orgID, clusterID, 5)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := chi.NewRouter()
	r.Post("/api/v1/network/policies/{workload}/{action}", NewNetworkPolicies(d).PreviewAction)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Fapi-service/demote", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestNetworkPolicies_ListDerivesLifecycleFromClusterFlows(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	orgID := uuid.New()
	clusterID := uuid.New()
	otherClusterID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Policy Observed')`, orgID, "netpol-observed-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-observed-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'observed-a', 'connected'), ($3, $2, 'observed-b', 'connected')`, clusterID, orgID, otherClusterID); err != nil {
		t.Fatalf("clusters: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES ($1, $2, 'default', 'frontend', 'Deployment', '{"app":"frontend"}'::jsonb, 70, '{}'::jsonb, 3),
       ($1, $2, 'default', 'api', 'Deployment', '{"app":"api"}'::jsonb, 90, '{}'::jsonb, 5),
       ($1, $3, 'default', 'frontend', 'Deployment', '{"app":"frontend"}'::jsonb, 10, '{}'::jsonb, 0),
       ($1, $3, 'default', 'api', 'Deployment', '{"app":"api"}'::jsonb, 10, '{}'::jsonb, 0)`, orgID, clusterID, otherClusterID); err != nil {
		t.Fatalf("deployments: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/frontend', 'default/api', 'tcp', 'grpc', 8443, 'allow', 1000, 10, NOW()),
       ($1, $2, 'default/api', 'external/payments.example', 'tcp', 'http', 443, 'alert', 500, 5, NOW()),
       ($1, $3, 'default/frontend', 'default/api', 'tcp', 'grpc', 8443, 'allow', 9000, 90, NOW())`, orgID, clusterID, otherClusterID); err != nil {
		t.Fatalf("flows: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := chi.NewRouter()
	h := NewNetworkPolicies(d)
	r.Get("/api/v1/network/policies/lifecycle", h.List)
	r.Post("/api/v1/network/policies/{workload}/{action}", h.PreviewAction)

	req := httptest.NewRequest("GET", "/api/v1/network/policies/lifecycle?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Items []networkPolicyLifecycleDTO `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("expected observed lifecycle items only, got %+v", got.Items)
	}
	foundAPI := false
	for _, item := range got.Items {
		if item.ClusterID != clusterID.String() || item.ClusterName != "observed-a" {
			t.Fatalf("wrong cluster scope in item: %+v", item)
		}
		if item.Workload == "default/api" {
			assertPolicyManifestBundle(t, item.Preview)
			if !containsString(item.Preview.L7Protocols, "grpc") {
				t.Fatalf("missing L7 protocol metadata in preview: %+v", item.Preview)
			}
			foundAPI = item.ApprovalStatus == "blocked" && item.Summary.OutOfPolicyAlerts > 0 &&
				strings.Contains(item.Preview.Manifests["native"], "kind: NetworkPolicy") &&
				strings.Contains(item.Preview.Manifests["cilium"], "kind: CiliumNetworkPolicy") &&
				strings.Contains(item.Preview.Manifests["calico"], "kind: GlobalNetworkPolicy") &&
				strings.Contains(item.Preview.YAML, "constellation.alphabravo.io/l7-protocols: grpc")
		}
	}
	if !foundAPI {
		t.Fatalf("missing flow-derived api policy with alert summary: %+v", got.Items)
	}

	frontendHash := ""
	for _, item := range got.Items {
		if item.Workload == "default/frontend" {
			frontendHash = item.CandidateHash
			if len(item.TuplePreview) == 0 {
				t.Fatalf("missing tuple evidence for frontend: %+v", item)
			}
			if !hasTuplePreview(item.TuplePreview, "egress", "default/api", true, "") {
				t.Fatalf("missing included frontend->api tuple evidence: %+v", item.TuplePreview)
			}
		}
		if item.Workload == "default/api" {
			if !hasTuplePreview(item.TuplePreview, "ingress", "default/frontend", true, "") {
				t.Fatalf("missing included api ingress tuple evidence: %+v", item.TuplePreview)
			}
			if !hasTuplePreview(item.TuplePreview, "egress", "external/payments.example", false, "alert") {
				t.Fatalf("missing held api external alert evidence: %+v", item.TuplePreview)
			}
			if strings.Contains(item.Preview.YAML, "payments.example") || strings.Contains(item.Preview.YAML, "toCIDR") {
				t.Fatalf("held alert tuple leaked into generated policy: %s", item.Preview.YAML)
			}
		}
	}
	if frontendHash == "" {
		t.Fatalf("missing frontend candidate hash: %+v", got.Items)
	}
	approveReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Ffrontend/approve?cluster_id="+clusterID.String(), strings.NewReader(`{"candidate_hash":"`+frontendHash+`"}`))
	approveReq = approveReq.WithContext(authctx.WithSubject(approveReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	approveResp := httptest.NewRecorder()
	r.ServeHTTP(approveResp, approveReq)
	if approveResp.Code != http.StatusOK {
		t.Fatalf("approve observed status=%d body=%s", approveResp.Code, approveResp.Body.String())
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/frontend', 'external/new.example', 'tcp', 'http', 443, 'allow', 100, 1, NOW())`, orgID, clusterID); err != nil {
		t.Fatalf("new flow: %v", err)
	}
	updatedHash := networkPolicyHashForTestPath(t, r, orgID, userID, "default/frontend", "/api/v1/network/policies/lifecycle?cluster_id="+clusterID.String())
	if updatedHash == frontendHash {
		t.Fatalf("candidate hash did not change after new flow")
	}
	applyReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Ffrontend/apply?cluster_id="+clusterID.String(), strings.NewReader(`{"candidate_hash":"`+updatedHash+`"}`))
	applyReq = applyReq.WithContext(authctx.WithSubject(applyReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	applyResp := httptest.NewRecorder()
	r.ServeHTTP(applyResp, applyReq)
	if applyResp.Code != http.StatusConflict || !strings.Contains(applyResp.Body.String(), "re-approval required") {
		t.Fatalf("expected stale candidate conflict, got %d body=%s", applyResp.Code, applyResp.Body.String())
	}
}

func hasTuplePreview(items []networkPolicyTuplePreviewDTO, direction, peer string, included bool, reasonFragment string) bool {
	for _, item := range items {
		if item.Direction != direction || item.Peer != peer || item.Included != included {
			continue
		}
		if reasonFragment == "" || strings.Contains(item.ExcludeReason, reasonFragment) {
			return true
		}
	}
	return false
}

func assertPolicyManifestBundle(t *testing.T, preview networkPolicyPreviewDTO) {
	t.Helper()
	if preview.Engine != "cilium" || preview.YAML == "" {
		t.Fatalf("missing default cilium preview: %+v", preview)
	}
	required := map[string]string{
		"native": "kind: NetworkPolicy",
		"cilium": "kind: CiliumNetworkPolicy",
		"calico": "kind: GlobalNetworkPolicy",
	}
	for flavor, marker := range required {
		if !strings.Contains(preview.Manifests[flavor], marker) {
			t.Fatalf("missing %s manifest marker %q in %+v", flavor, marker, preview.Manifests)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasApplyStatus(items []networkPolicyLifecycleDTO, workload, flavor, status string) bool {
	for _, item := range items {
		if item.Workload != workload {
			continue
		}
		for _, applyStatus := range item.ApplyStatuses {
			if applyStatus.Flavor == flavor && applyStatus.Status == status {
				return true
			}
		}
	}
	return false
}

func seedNetworkPolicyObservedWorkloads(t *testing.T, pool *pgxpool.Pool, orgID, clusterID uuid.UUID, flowCount int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES ($1, $2, 'default', 'frontend', 'Deployment', '{"app":"frontend"}'::jsonb, 10, '{}'::jsonb, 0),
       ($1, $2, 'default', 'api-service', 'Deployment', '{"app":"api-service"}'::jsonb, 10, '{}'::jsonb, 0)
ON CONFLICT DO NOTHING`, orgID, clusterID); err != nil {
		t.Fatalf("seed deployments: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/frontend', 'default/api-service', 'tcp', 'grpc', 8443, 'allow', 1000, 10, NOW())`,
		orgID, clusterID); err != nil {
		t.Fatalf("seed flow: %v", err)
	}
	if flowCount > 1 {
		if _, err := pool.Exec(context.Background(), `
UPDATE network_flows
   SET bytes = bytes * $3,
       packets = packets * $3
 WHERE org_id = $1 AND cluster_id = $2 AND src_workload = 'default/frontend' AND dst_workload = 'default/api-service'`,
			orgID, clusterID, flowCount); err != nil {
			t.Fatalf("scale seed flow: %v", err)
		}
		for i := 1; i < flowCount; i++ {
			if _, err := pool.Exec(context.Background(), `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/frontend', 'default/api-service', 'tcp', 'grpc', 8443, 'allow', 1000, 10, NOW() - ($3::int * INTERVAL '1 minute'))`,
				orgID, clusterID, i); err != nil {
				t.Fatalf("seed flow sample %d: %v", i, err)
			}
		}
	}
}

func TestNetworkPolicies_RollbackRequiresStorage(t *testing.T) {
	r := chi.NewRouter()
	r.Post("/api/v1/network/policies/{workload}/rollback", NewNetworkPolicies().Rollback)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/network/policies/default%2Ffrontend/rollback", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
}

func TestNetworkPolicies_ActionGuardsApplyAndDemote(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	orgID := uuid.New()
	clusterID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Policy Guards')`, orgID, "netpol-guards-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-guards-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'netpol-guards-prod', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	seedNetworkPolicyObservedWorkloads(t, pool, orgID, clusterID, 25)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := chi.NewRouter()
	r.Post("/api/v1/network/policies/{workload}/{action}", NewNetworkPolicies(d).PreviewAction)

	applyReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Fapi-service/apply", nil)
	applyReq = applyReq.WithContext(authctx.WithSubject(applyReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	applyResp := httptest.NewRecorder()
	r.ServeHTTP(applyResp, applyReq)
	if applyResp.Code != http.StatusConflict {
		t.Fatalf("expected apply conflict, got %d: %s", applyResp.Code, applyResp.Body.String())
	}

	demoteReq := httptest.NewRequest("POST", "/api/v1/network/policies/default%2Ffrontend/demote", nil)
	demoteReq = demoteReq.WithContext(authctx.WithSubject(demoteReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	demoteResp := httptest.NewRecorder()
	r.ServeHTTP(demoteResp, demoteReq)
	if demoteResp.Code != http.StatusBadRequest {
		t.Fatalf("expected demote reason rejection, got %d: %s", demoteResp.Code, demoteResp.Body.String())
	}
}

func networkPolicyHashForTest(t *testing.T, r http.Handler, orgID, userID uuid.UUID, workload string) string {
	t.Helper()
	return networkPolicyHashForTestPath(t, r, orgID, userID, workload, "/api/v1/network/policies/lifecycle")
}

func networkPolicyHashForTestPath(t *testing.T, r http.Handler, orgID, userID uuid.UUID, workload, path string) string {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("lifecycle status=%d body=%s", resp.Code, resp.Body.String())
	}
	var got struct {
		Items []networkPolicyLifecycleDTO `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode lifecycle: %v", err)
	}
	for _, item := range got.Items {
		if item.Workload == workload {
			if item.CandidateHash == "" {
				t.Fatalf("missing candidate hash for %s: %+v", workload, item)
			}
			return item.CandidateHash
		}
	}
	t.Fatalf("missing workload %s in lifecycle: %+v", workload, got.Items)
	return ""
}

func ensureNetworkPolicyLifecycleTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS network_policy_lifecycle_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL,
    current_mode TEXT NOT NULL,
    target_mode TEXT,
    approval_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    preview_yaml TEXT NOT NULL DEFAULT '',
    preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb,
    diff JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_available BOOLEAN NOT NULL DEFAULT FALSE,
    rollback_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
    audit_trail JSONB NOT NULL DEFAULT '[]'::jsonb,
    applied_ref TEXT,
    rollback_ref TEXT,
    candidate_hash TEXT,
    last_applied_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload)
);
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS candidate_hash TEXT;
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS mode_since TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE network_policy_lifecycle_states
    DROP CONSTRAINT IF EXISTS network_policy_lifecycle_states_org_id_workload_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_lifecycle_org_cluster_workload
    ON network_policy_lifecycle_states(org_id, cluster_id, workload);
CREATE TABLE IF NOT EXISTS network_policy_lifecycle_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL,
    action TEXT NOT NULL,
    previous_mode TEXT NOT NULL,
    next_mode TEXT NOT NULL,
    reason TEXT NOT NULL,
    preview_yaml TEXT NOT NULL DEFAULT '',
    preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb,
    preview_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
    diff JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_ref TEXT,
    idempotency_key TEXT,
    candidate_hash TEXT,
    actor_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS candidate_hash TEXT;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_actions_idempotency
    ON network_policy_lifecycle_actions(org_id, cluster_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS network_policy_rollback_refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL,
    rollback_ref TEXT NOT NULL,
    previous_mode TEXT NOT NULL,
    restore_mode TEXT NOT NULL,
    preview_yaml TEXT NOT NULL DEFAULT '',
    preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb,
    preview_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, rollback_ref)
);
ALTER TABLE network_policy_rollback_refs
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_rollback_refs
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE network_policy_rollback_refs
    DROP CONSTRAINT IF EXISTS network_policy_rollback_refs_org_id_rollback_ref_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_rollback_refs_org_cluster_ref
    ON network_policy_rollback_refs(org_id, cluster_id, rollback_ref);
CREATE TABLE IF NOT EXISTS network_policy_apply_status (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    flavor TEXT NOT NULL,
    resource_ref TEXT NOT NULL DEFAULT '',
    desired_mode TEXT NOT NULL DEFAULT '',
    approval_status TEXT NOT NULL DEFAULT '',
    last_action TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    candidate_hash TEXT,
    applied_ref TEXT,
    rollback_ref TEXT,
    last_applied_at TIMESTAMPTZ,
    last_deleted_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id, workload, flavor)
);
`)
	if err != nil {
		t.Fatalf("network policy lifecycle tables: %v", err)
	}
}

// NET-4: the elevation engine must be seeded from the PERSISTED per-workload mode +
// mode_since (not re-seeded Discover/first-observation each request). A workload
// persisted in Monitor whose mode_since predates the promote threshold and has no
// out-of-policy alerts is evaluated as ready for Protect; a workload with no
// persisted row still defaults to Discover.
func TestNetworkPolicies_EvaluatesPersistedMonitorTimeInMode(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	// Short window so the clean monitor period qualifies; min flows low enough for
	// the seeded traffic. Without the persisted-mode seeding the engine would
	// re-seed Discover/now and never reach the Monitor->Protect branch.
	t.Setenv("CONSTELLATION_NETPOLICY_LEARN_WINDOW", "1s")
	t.Setenv("CONSTELLATION_NETPOLICY_MIN_FLOWS", "1")

	orgID := uuid.New()
	clusterID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Policy NET-4')`, orgID, "netpol-net4-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-net4-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'netpol-net4-prod', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	seedNetworkPolicyObservedWorkloads(t, pool, orgID, clusterID, 25)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	// Persist default/frontend in Monitor with mode_since one hour ago (well past
	// the 1s window). default/api-service is left without a persisted row.
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_lifecycle_states (org_id, cluster_id, workload, namespace, current_mode, approval_status, reason, mode_since)
VALUES ($1, $2, 'default/frontend', 'default', 'monitor', 'approved', 'monitoring', NOW() - INTERVAL '1 hour')`,
		orgID, clusterID); err != nil {
		t.Fatalf("seed persisted monitor state: %v", err)
	}

	// Drive the catalog directly so we observe the elevation engine's Decision
	// (current/target) BEFORE applyPersistedState overlays the persisted row's
	// (empty) target. This is the layer NET-4 changes: the Decision must be fed
	// the persisted mode + mode_since, not a re-seeded Discover/now state.
	h := NewNetworkPolicies(d)
	cluster := &networkPolicyCluster{ID: clusterID.String(), Name: "netpol-net4-prod"}
	catReq := httptest.NewRequest("GET", "/api/v1/network/policies/lifecycle", nil)
	catReq = catReq.WithContext(authctx.WithSubject(catReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	items, err := h.observedPolicyLifecycleCatalog(catReq, orgID.String(), cluster, "")
	if err != nil {
		t.Fatalf("observedPolicyLifecycleCatalog: %v", err)
	}

	var frontend, apiService *networkPolicyLifecycleDTO
	for i := range items {
		switch items[i].Workload {
		case "default/frontend":
			frontend = &items[i]
		case "default/api-service":
			apiService = &items[i]
		}
	}
	if frontend == nil || apiService == nil {
		t.Fatalf("missing seeded workloads in lifecycle: %+v", items)
	}
	// Persisted Monitor + old mode_since + clean traffic => evaluate toward Protect.
	if frontend.CurrentMode != "monitor" || frontend.TargetMode != "protect" {
		t.Fatalf("persisted monitor workload should target protect, got current=%q target=%q reason=%q",
			frontend.CurrentMode, frontend.TargetMode, frontend.Reason)
	}
	// No persisted row => defaults to Discover.
	if apiService.CurrentMode != "discover" {
		t.Fatalf("unpersisted workload should default to discover, got %q", apiService.CurrentMode)
	}
}

// TestLifecycleForWorkload_ReturnsPersistedMonitorState exercises the read seam
// the deployments handler consumes (NetworkPolicies.LifecycleForWorkload). ARC-1
// moved the per-workload lifecycle computation out of the deployments handler
// into this package and the deployments integration test now stubs the seam, so
// the real DB-backed computation is covered here. A workload persisted in Monitor
// with mode_since older than the promote threshold and clean traffic must come
// back with current_mode=monitor, target_mode=protect, a non-empty candidate hash
// and a generated preview bundle, overlaid from the persisted lifecycle row.
func TestLifecycleForWorkload_ReturnsPersistedMonitorState(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	// Short learn window + low min flows so the persisted Monitor period qualifies
	// for Protect against the seeded traffic (mirrors the NET-4 test). Without the
	// persisted-mode seeding the engine would re-seed Discover/now and never reach
	// the Monitor->Protect branch.
	t.Setenv("CONSTELLATION_NETPOLICY_LEARN_WINDOW", "1s")
	t.Setenv("CONSTELLATION_NETPOLICY_MIN_FLOWS", "1")

	orgID := uuid.New()
	clusterID := uuid.New()
	userID := uuid.New()
	// Scope cleanup to this test's org at setup so a leftover row from a previous
	// aborted run cannot poison the assertions; the org is freshly generated per
	// run so this only removes this test's own data.
	cleanup := func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) }
	cleanup()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Policy Lifecycle Seam')`, orgID, "netpol-seam-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-seam-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'netpol-seam-prod', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	seedNetworkPolicyObservedWorkloads(t, pool, orgID, clusterID, 25)
	t.Cleanup(cleanup)

	// Persist default/frontend in Monitor with mode_since one hour ago (well past
	// the 1s window) and target_mode=protect so the persisted overlay agrees with
	// the elevation engine's Monitor->Protect decision.
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_lifecycle_states (org_id, cluster_id, workload, namespace, current_mode, target_mode, approval_status, reason, mode_since)
VALUES ($1, $2, 'default/frontend', 'default', 'monitor', 'protect', 'approved', 'monitoring', NOW() - INTERVAL '1 hour')`,
		orgID, clusterID); err != nil {
		t.Fatalf("seed persisted monitor state: %v", err)
	}

	h := NewNetworkPolicies(d)
	req := httptest.NewRequest("GET", "/api/v1/deployments/default%2Ffrontend", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))

	// Independently compute the expected candidate hash/preview off the observed
	// catalog so the assertion tracks the real computation rather than a literal.
	cluster := &networkPolicyCluster{ID: clusterID.String(), Name: "netpol-seam-prod"}
	catalog, err := h.observedPolicyLifecycleCatalog(req, orgID.String(), cluster, "")
	if err != nil {
		t.Fatalf("observedPolicyLifecycleCatalog: %v", err)
	}
	var wantHash, wantYAML string
	for i := range catalog {
		if catalog[i].Workload == "default/frontend" {
			wantHash = catalog[i].CandidateHash
			wantYAML = catalog[i].Preview.YAML
		}
	}
	if wantHash == "" || wantYAML == "" {
		t.Fatalf("expected catalog candidate for default/frontend: %+v", catalog)
	}

	got, err := h.LifecycleForWorkload(req, orgID, &clusterID, "default/frontend")
	if err != nil {
		t.Fatalf("LifecycleForWorkload: %v", err)
	}
	dto, ok := got.(*networkPolicyLifecycleDTO)
	if !ok || dto == nil {
		t.Fatalf("expected *networkPolicyLifecycleDTO, got %#v", got)
	}
	if dto.CurrentMode != "monitor" || dto.TargetMode != "protect" {
		t.Fatalf("persisted monitor workload should surface current=monitor target=protect, got current=%q target=%q reason=%q",
			dto.CurrentMode, dto.TargetMode, dto.Reason)
	}
	if dto.CandidateHash != wantHash {
		t.Fatalf("candidate hash mismatch: got %q want %q", dto.CandidateHash, wantHash)
	}
	if dto.Preview.YAML != wantYAML {
		t.Fatalf("preview YAML mismatch: got %q want %q", dto.Preview.YAML, wantYAML)
	}
	if dto.ClusterID != clusterID.String() || dto.ClusterName != "netpol-seam-prod" {
		t.Fatalf("cluster scope mismatch: id=%q name=%q", dto.ClusterID, dto.ClusterName)
	}
	if dto.ApprovalStatus != "approved" {
		t.Fatalf("expected persisted approval status overlaid, got %q", dto.ApprovalStatus)
	}
	assertPolicyManifestBundle(t, dto.Preview)

	// A workload with no persisted row and no observed flows yields no entry.
	missing, err := h.LifecycleForWorkload(req, orgID, &clusterID, "default/does-not-exist")
	if err != nil {
		t.Fatalf("LifecycleForWorkload missing: %v", err)
	}
	if missing != nil {
		t.Fatalf("expected nil for unknown workload, got %#v", missing)
	}
}
