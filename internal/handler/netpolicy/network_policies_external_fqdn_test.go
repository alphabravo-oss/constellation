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

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

// TestNetworkPolicies_BareExternalAnchorsCIDRAndFQDN is the read-path proof for
// H12 and the lifecycle FQDN finding. Ingest collapses non-well-known external
// peers to the bare "external" bucket (real IP in dst_addr, observed DNS name in
// fqdn). The lifecycle catalog must:
//
//   - treat bare "external" as external (clear DstWorkload, set DstIP) so an
//     egress allow renders a toCIDR — NOT an app=external podSelector that
//     matches no pod and breaks the real upstream under protect mode; and
//   - anchor an egress-to-external row carrying an observed FQDN to toFQDNs so
//     the enforced Cilium manifest survives the peer's IPs rotating.
//
// It mirrors the runtime path's TestFlowFromRow_FqdnEgressToFQDNs so the two
// generators stay consistent.
func TestNetworkPolicies_BareExternalAnchorsCIDRAndFQDN(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)

	orgID := uuid.New()
	clusterID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Bare External')`, orgID, "netpol-ext-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'NetPol Admin')`, userID, orgID, "netpol-ext-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'ext-a', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES ($1, $2, 'default', 'api', 'Deployment', '{"app":"api"}'::jsonb, 10, '{}'::jsonb, 0)`, orgID, clusterID); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	// Three egress edges from default/api to the COLLAPSED bare "external" bucket:
	//   1. with a real dst_addr + observed fqdn  -> toFQDNs (fqdn wins over IP)
	//   2. with a real dst_addr, no fqdn         -> toCIDR /32
	//   3. with an EMPTY dst_addr                -> held (missing CIDR), excluded
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, dst_addr, fqdn, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/api', 'external', '93.184.216.34', 'api.github.com', 'tcp', 'http', 443, 'allow', 100, 1, NOW()),
       ($1, $2, 'default/api', 'external', '198.51.100.7', '', 'tcp', '', 8080, 'allow', 100, 1, NOW()),
       ($1, $2, 'default/api', 'external', '', '', 'tcp', '', 9090, 'allow', 100, 1, NOW())`, orgID, clusterID); err != nil {
		t.Fatalf("flows: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	r := chi.NewRouter()
	h := NewNetworkPolicies(d)
	r.Get("/api/v1/network/policies/lifecycle", h.List)

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

	var api *networkPolicyLifecycleDTO
	for i := range got.Items {
		if got.Items[i].Workload == "default/api" {
			api = &got.Items[i]
		}
	}
	if api == nil {
		t.Fatalf("missing default/api lifecycle item: %+v", got.Items)
	}
	cilium := api.Preview.Manifests["cilium"]

	// FQDN egress -> toFQDNs matchName (takes precedence over the observed /32).
	if !strings.Contains(cilium, "toFQDNs") || !strings.Contains(cilium, "matchName: api.github.com") {
		t.Fatalf("expected toFQDNs matchName for fqdn-bearing egress:\n%s", cilium)
	}
	// IP-only external egress -> toCIDR /32.
	if !strings.Contains(cilium, "toCIDR") || !strings.Contains(cilium, "198.51.100.7/32") {
		t.Fatalf("expected toCIDR for bare-external egress with dst_addr:\n%s", cilium)
	}
	// The bug: bare "external" was rendered as an app=external podSelector. The
	// fixed manifest anchors to CIDR/FQDN and must contain no "external" selector.
	if strings.Contains(cilium, "external") {
		t.Fatalf("bare external still leaked an app=external selector:\n%s", cilium)
	}
	// The held row (no dst_addr) must be surfaced as excluded evidence, never
	// promoted into the generated policy.
	if !hasTuplePreview(api.TuplePreview, "egress", "external", false, "missing CIDR") {
		t.Fatalf("expected held bare-external tuple (missing CIDR): %+v", api.TuplePreview)
	}
}
