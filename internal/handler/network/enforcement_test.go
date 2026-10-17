package network

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"

	"github.com/alphabravocompany/constellation/internal/netpolicyapply"
)

// The generated manifests are only useful if the applier can parse them. Round-trip
// each through ParseManifest and assert the flavor/GVR/name the applier will act on.
func TestEnforcementManifestsParse(t *testing.T) {
	isoManifest, isoRef := isolateManifest("prod", "api", map[string]string{"app": "api"})
	res, _, err := netpolicyapply.ParseManifest(netpolicyapply.FlavorNative, isoManifest)
	if err != nil {
		t.Fatalf("isolate manifest failed to parse: %v", err)
	}
	if res.Kind != "NetworkPolicy" || res.Namespace != "prod" {
		t.Fatalf("isolate parsed wrong: kind=%s ns=%s", res.Kind, res.Namespace)
	}
	if !strings.HasSuffix(isoRef, res.Namespace+"/"+res.Name) {
		t.Fatalf("isolate ref %q disagrees with parsed name %q", isoRef, res.Name)
	}
	// default-deny = both policy types, no allow rules
	if !strings.Contains(isoManifest, "\"policyTypes\":[\"Ingress\",\"Egress\"]") {
		t.Fatalf("isolate manifest is not default-deny: %s", isoManifest)
	}

	blkManifest, blkRef := blockIPManifest("prod", "api", "8.8.8.8", "egress", map[string]string{"app": "api"})
	bres, _, err := netpolicyapply.ParseManifest(netpolicyapply.FlavorCilium, blkManifest)
	if err != nil {
		t.Fatalf("block manifest failed to parse: %v", err)
	}
	if bres.Kind != "CiliumNetworkPolicy" || bres.Namespace != "prod" {
		t.Fatalf("block parsed wrong: kind=%s ns=%s", bres.Kind, bres.Namespace)
	}
	if !strings.HasSuffix(blkRef, bres.Namespace+"/"+bres.Name) {
		t.Fatalf("block ref %q disagrees with parsed name %q", blkRef, bres.Name)
	}
	if !strings.Contains(blkManifest, "egressDeny") || !strings.Contains(blkManifest, "8.8.8.8/32") {
		t.Fatalf("block manifest missing egressDeny toCIDR: %s", blkManifest)
	}
	// egress-only must not emit an ingressDeny
	if strings.Contains(blkManifest, "ingressDeny") {
		t.Fatalf("egress-only block leaked an ingressDeny: %s", blkManifest)
	}
}

func TestK8sNameSanitize(t *testing.T) {
	if got := k8sName("Constellation-Isolate-My_App.v2"); got != "constellation-isolate-my-app-v2" {
		t.Fatalf("k8sName sanitize: got %q", got)
	}
	if got := k8sName("///"); got != "constellation-enforce" {
		t.Fatalf("k8sName empty fallback: got %q", got)
	}
	if got := ipSlug("10.0.0.5"); got != "10-0-0-5" {
		t.Fatalf("ipSlug: got %q", got)
	}
}

func TestEnforcementRejectsMissingWorkloadAndUnsupportedCNI(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	org, cluster, otherCluster, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,$2)`, org, "enforce-scope-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM network_enforcement_actions WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters (id,org_id,name) VALUES ($1,$3,'a'),($2,$3,'b')`, cluster, otherCluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO deployments (org_id,cluster_id,namespace,name,kind,labels) VALUES ($1,$2,'team','api','Deployment','{"app":"api"}'),($1,$3,'team','other','Deployment','{}')`, org, cluster, otherCluster); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO host_facts (org_id,cluster_id,node,cni_name,facts,observed_at) VALUES ($1,$2,'node','calico','{}',NOW())`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewNetwork(d)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"kind":"isolate","target":"team/missing","reason":"incident"}`, 404},
		{`{"kind":"isolate","target":"team/other","reason":"incident"}`, 404},
		{`{"kind":"block_ip","workload":"team/api","target":"203.0.113.4","reason":"incident"}`, 422},
		{`{"kind":"isolate","target":"team/api","reason":"incident"}`, 201},
	} {
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/network/enforcement?cluster_id="+cluster.String(), strings.NewReader(tc.body))
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org, UserID: user, Email: "operator@example.com"}))
		w := httptest.NewRecorder()
		h.EnforcementCreate(w, r)
		if w.Code != tc.status {
			t.Errorf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
		}
	}
	if _, err := d.Pool().Exec(ctx, `UPDATE host_facts SET cni_name='cilium' WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	for _, workload := range []string{"team/missing", "team/other", "team/api"} {
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/network/enforcement?cluster_id="+cluster.String(), strings.NewReader(fmt.Sprintf(`{"kind":"block_ip","workload":%q,"target":"203.0.113.4","direction":"egress","reason":"incident"}`, workload)))
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org, UserID: user, Email: "operator@example.com"}))
		w := httptest.NewRecorder()
		h.EnforcementCreate(w, r)
		want := http.StatusNotFound
		if workload == "team/api" {
			want = http.StatusCreated
		}
		if w.Code != want {
			t.Errorf("block %s status=%d body=%s", workload, w.Code, w.Body.String())
		}
	}
	var count int
	if err := d.Pool().QueryRow(ctx, `SELECT count(*) FROM network_enforcement_actions WHERE org_id=$1`, org).Scan(&count); err != nil || count != 2 {
		t.Errorf("queued actions=%d err=%v", count, err)
	}
}
