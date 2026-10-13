package netpolicy

import (
	"context"
	"github.com/google/uuid"
	"net/http/httptest"
	"testing"
)

func TestLifecycleTuplePeerRolesExactClusterOwnerAndUnknown(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := d.Pool()
	ctx := context.Background()
	org, foreignOrg, cluster, sibling, foreign, owner, foreignOwner := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, o := range []uuid.UUID{org, foreignOrg} {
		if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, o, "tuple-role-"+o.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = p.Exec(ctx, `DELETE FROM network_flows WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = p.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'orbit','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'payments','app','Deployment','{}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}'),
 (gen_random_uuid(),$2,$4,'sibling-only','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 ($5,$6,$7,'foreign-only','api','Deployment','{"helm.sh/chart":"constellation-1"}')`, owner, org, cluster, sibling, foreignOwner, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'orbit','api-pod','tuple-pod','orbit/pod/api-pod','Deployment','api','orbit/api',$3),($1,$2,'foreign-only','api-pod','tuple-foreign','foreign-only/pod/api-pod','Deployment','api','foreign-only/api',$4)`, org, cluster, owner, foreignOwner); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"orbit/api": "core", "orbit/pod/api-pod": "core", "ambiguous/api": "", "sibling-only/api": "", "foreign-only/pod/api-pod": "", "10.42.0.2": "", "external": ""}
	for peer := range cases {
		if _, err := p.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict) VALUES($1,$2,$3,'payments/app','tcp',443,'allow')`, org, cluster, peer); err != nil {
			t.Fatal(err)
		}
	}
	items, err := NewNetworkPolicies(d).observedPolicyLifecycleCatalog(httptest.NewRequest("GET", "/network/policies/lifecycle", nil), org.String(), &networkPolicyCluster{ID: cluster.String(), Name: "selected"}, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		if item.Workload != "payments/app" {
			continue
		}
		found = true
		seen := map[string]bool{}
		for _, tuple := range item.TuplePreview {
			want, ok := cases[tuple.Peer]
			if !ok || tuple.PeerPlatformRole != want {
				t.Fatalf("tuple role %+v want%q", tuple, want)
			}
			seen[tuple.Peer] = true
		}
		if len(seen) != len(cases) {
			t.Fatalf("missing tuples %+v", item.TuplePreview)
		}
	}
	if !found {
		t.Fatal("selected policy missing")
	}
	one := []networkPolicyTuplePreviewDTO{{Peer: "orbit/api", Protocol: "TCP", Port: 443, Included: true}}
	two := append([]networkPolicyTuplePreviewDTO{}, one...)
	two[0].PeerPlatformRole = "core"
	if tuplePreviewHashInput(one) != tuplePreviewHashInput(two) {
		t.Fatal("display role changed policy candidate identity")
	}
}
