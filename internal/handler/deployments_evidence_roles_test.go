package handler

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestDeploymentEmbeddedEvidencePlatformRoles(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreignOrg, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name)VALUES($1,$2,$2)`, id, "deployment-roles-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM events WHERE org_id IN($1,$2)`, org, foreignOrg); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM network_flows WHERE org_id IN($1,$2)`, org, foreignOrg); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreignOrg); err != nil {
		t.Fatal(err)
	}
	owner, other, foreignOwner, ambiguousOwner := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels)VALUES
 ($1,$2,$3,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($4,$2,$3,'custom-install','other','Deployment','{}'),
 ($5,$6,$7,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$8,'custom-install','api','Deployment','{}'),
 ($9,$2,$3,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}'),
 (gen_random_uuid(),$2,$3,'generic','api','Deployment','{"app.kubernetes.io/managed-by":"Helm"}')`, owner, org, cluster, other, foreignOwner, foreignOrg, foreignCluster, sibling, ambiguousOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id)VALUES
 ($1,$2,'custom-install','api-pod','1','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$4,'custom-install','api-pod','2','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','foreign-pod','3','custom-install/pod/foreign-pod','Deployment','api','custom-install/api',$5),
 ($1,$2,'custom-install','ambiguous-pod','4','custom-install/pod/ambiguous-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','ambiguous-pod','5','custom-install/pod/ambiguous-pod','Deployment','other','custom-install/other',$6),
 ($1,$2,'ambiguous','api-pod','6','ambiguous/pod/api-pod','Deployment','api','ambiguous/api',$7)`, org, cluster, owner, sibling, foreignOwner, other, ambiguousOwner); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ workload, namespace, role string }{
		{"custom-install/api", "custom-install", "core"}, {"custom-install/pod/api-pod", "custom-install", "core"},
		{"ambiguous/api", "ambiguous", ""}, {"ambiguous/pod/api-pod", "ambiguous", "core"}, {"custom-install/pod/ambiguous-pod", "custom-install", ""},
		{"custom-install/pod/foreign-pod", "custom-install", ""}, {"custom-install/pod/missing", "custom-install", ""}, {"generic/api", "generic", ""}, {"kube-system/10.42.0.2", "kube-system", ""},
	}
	eventIDs := map[uuid.UUID]string{}
	flowIDs := map[string]string{}
	workloads := []string{"custom-install/api"}
	for i, item := range cases {
		eventID, flowID := uuid.New(), uuid.New()
		eventIDs[eventID] = item.role
		flowIDs[flowID.String()] = item.role
		workloads = append(workloads, item.workload)
		if _, err := pool.Exec(ctx, `INSERT INTO events(id,org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict,at)VALUES($1,$2,$3,'node',$4,$5,'ebpf','process_exec','high','alert',NOW()-$6::interval)`, eventID, org, cluster, item.workload, item.namespace, strconv.Itoa(i)+" minutes"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(id,org_id,cluster_id,src_workload,dst_workload,protocol,at)VALUES($1,$2,$3,'custom-install/api',$4,'tcp',NOW()-$5::interval)`, flowID, org, cluster, item.workload, strconv.Itoa(i)+" minutes"); err != nil {
			t.Fatal(err)
		}
	}
	// Older evidence remains eligible: this detail source has no24h bound.
	oldEvent, oldFlow := uuid.New(), uuid.New()
	eventIDs[oldEvent] = "core"
	flowIDs[oldFlow.String()] = "core"
	if _, err := pool.Exec(ctx, `INSERT INTO events(id,org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict,at)VALUES($1,$2,$3,'node','custom-install/api','custom-install','ebpf','process_exec','high','alert',NOW()-INTERVAL '2 days')`, oldEvent, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows(id,org_id,cluster_id,src_workload,dst_workload,protocol,at)VALUES($1,$2,$3,'custom-install/api','custom-install/api','tcp',NOW()-INTERVAL '2 days')`, oldFlow, org, cluster); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct{ org, cluster uuid.UUID }{{org, sibling}, {foreignOrg, foreignCluster}, {foreignOrg, cluster}} {
		if _, err := pool.Exec(ctx, `INSERT INTO events(org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict)VALUES($1,$2,'node','custom-install/api','custom-install','ebpf','process_exec','high','alert')`, scope.org, scope.cluster); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol)VALUES($1,$2,'custom-install/api','custom-install/api','tcp')`, scope.org, scope.cluster); err != nil {
			t.Fatal(err)
		}
	}
	h := NewDeployments(d, nil)
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/deployment", nil)
	t.Run("actual event clusters and exact role association", func(t *testing.T) {
		events, err := h.deploymentRuntimeEvents(request, org, &cluster, workloads)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != len(eventIDs) {
			t.Fatalf("events%d want%d", len(events), len(eventIDs))
		}
		for _, item := range events {
			want, ok := eventIDs[item.ID]
			if !ok || item.ClusterID != cluster || item.PlatformRole != want {
				t.Fatalf("event %+v want%q", item, want)
			}
			body, _ := json.Marshal(item)
			var value map[string]any
			_ = json.Unmarshal(body, &value)
			if value["cluster_id"] != cluster.String() || value["platform_role"] != want {
				t.Fatalf("wire%s", body)
			}
		}
		other, err := h.deploymentRuntimeEvents(request, org, &sibling, workloads)
		if err != nil {
			t.Fatal(err)
		}
		if len(other) != 1 || other[0].PlatformRole != "" || other[0].ClusterID != sibling {
			t.Fatalf("sibling %+v", other)
		}
		unknown, err := h.deploymentRuntimeEvents(request, org, nil, workloads)
		if err != nil || len(unknown) != 0 {
			t.Fatalf("unknown cluster borrowed rows%v err%v", unknown, err)
		}
	})
	t.Run("both flow endpoint roles are exact and explicit when unknown", func(t *testing.T) {
		flows, err := h.deploymentNetworkFlows(request, org, &cluster, workloads)
		if err != nil {
			t.Fatal(err)
		}
		if len(flows) != len(flowIDs) {
			t.Fatalf("flows%d want%d", len(flows), len(flowIDs))
		}
		for _, item := range flows {
			want, ok := flowIDs[item.ID]
			if !ok || item.ClusterID != cluster || item.SrcPlatformRole != "core" || item.DstPlatformRole != want {
				t.Fatalf("flow %+v want%q", item, want)
			}
			body, _ := json.Marshal(item)
			var value map[string]any
			_ = json.Unmarshal(body, &value)
			if value["cluster_id"] != cluster.String() || value["src_platform_role"] != "core" || value["dst_platform_role"] != want {
				t.Fatalf("wire%s", body)
			}
		}
		other, err := h.deploymentNetworkFlows(request, org, &sibling, workloads)
		if err != nil {
			t.Fatal(err)
		}
		if len(other) != 1 || other[0].SrcPlatformRole != "" || other[0].DstPlatformRole != "" || other[0].ClusterID != sibling {
			t.Fatalf("sibling %+v", other)
		}
		unknown, err := h.deploymentNetworkFlows(request, org, nil, workloads)
		if err != nil || len(unknown) != 0 {
			t.Fatalf("unknown scope borrowed flows%v err%v", unknown, err)
		}
	})
	t.Run("latest50 source bound stays independent of role lookup", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `INSERT INTO events(org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict) SELECT $1,$2,'node','custom-install/pod/api-pod','custom-install','ebpf','process_exec','high','alert' FROM generate_series(1,60)`, org, cluster); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol) SELECT $1,$2,'custom-install/api','custom-install/pod/api-pod','tcp' FROM generate_series(1,60)`, org, cluster); err != nil {
			t.Fatal(err)
		}
		events, err := h.deploymentRuntimeEvents(request, org, &cluster, workloads)
		if err != nil || len(events) != 50 {
			t.Fatalf("cap events%d err%v", len(events), err)
		}
		for _, item := range events {
			if item.PlatformRole != "core" {
				t.Fatal(item)
			}
		}
		flows, err := h.deploymentNetworkFlows(request, org, &cluster, workloads)
		if err != nil || len(flows) != 50 {
			t.Fatalf("cap flows%d err%v", len(flows), err)
		}
		for _, item := range flows {
			if item.SrcPlatformRole != "core" || item.DstPlatformRole != "core" {
				t.Fatal(item)
			}
		}
	})
}
