//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestPcapActionResponsesExactPlatformRoles(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	t.Setenv("CONSTELLATION_DATA_DIR", t.TempDir())
	ctx, pool := context.Background(), database.Pool()
	org, cluster := uuid.New(), uuid.New()
	token := seedBoundRuntimeAgentScope(t, database, org, cluster)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM runtime_pcap_captures WHERE org_id=$1`, org) })
	sibling, foreignOrg, foreign := uuid.New(), uuid.New(), uuid.New()
	seedBoundRuntimeAgentScope(t, database, foreignOrg, foreign)
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'sibling')`, sibling, org); err != nil {
		t.Fatal(err)
	}
	owner, foreignOwner, ambiguousOwner := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'custom-install','api','Deployment','{"helm.sh/chart":"constellation-1.0"}'),
 (gen_random_uuid(),$2,$4,'custom-install','api','Deployment','{}'),
 ($5,$6,$7,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($8,$2,$3,'ambiguous','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}')`, owner, org, cluster, sibling, foreignOwner, foreignOrg, foreign, ambiguousOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES
 ($1,$2,'custom-install','api-pod','pod-a','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','foreign-pod','pod-b','custom-install/pod/foreign-pod','Deployment','api','custom-install/api',$4),
 ($1,$2,'ambiguous','api-pod','pod-c','ambiguous/pod/api-pod','Deployment','api','ambiguous/api',$5)`, org, cluster, owner, foreignOwner, ambiguousOwner); err != nil {
		t.Fatal(err)
	}
	h := NewPcapHTTP(database)
	call := func(method, path string, body []byte, agent bool, handle http.HandlerFunc) PcapCapture {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
		if agent {
			req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), token))
		} else {
			req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		}
		res := httptest.NewRecorder()
		handle(res, req)
		expected := http.StatusOK
		if path == "/runtime-pcap/start" {
			expected = http.StatusCreated
		}
		if res.Code != expected {
			t.Fatalf("%s status=%d %s", path, res.Code, res.Body.String())
		}
		var got PcapCapture
		if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(res.Body.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["platform_role"]; !ok {
			t.Fatalf("unevaluated action response %s", path)
		}
		return got
	}
	for _, item := range []struct {
		workload, namespace, role string
		cluster                   uuid.UUID
	}{
		{"custom-install/api", "", "core", cluster},
		{"custom-install/pod/api-pod", "", "core", cluster},
		{"api", "custom-install", "core", cluster},
		{"ambiguous/api", "", "", cluster},
		{"ambiguous/pod/api-pod", "", "core", cluster},
		{"custom-install/pod/foreign-pod", "", "", cluster},
		{"custom-install/missing", "", "", cluster},
		{"kube-system/10.42.0.2", "", "", cluster},
		{"custom-install/api", "", "", sibling},
	} {
		t.Run(item.workload+"/"+item.cluster.String(), func(t *testing.T) {
			body, _ := json.Marshal(StartCaptureRequest{ClusterID: item.cluster, Workload: item.workload, Namespace: item.namespace, DurationS: 30})
			got := call(http.MethodPost, "/runtime-pcap/start", body, false, h.Start)
			assert := func(row PcapCapture, state PcapCaptureStatus) {
				t.Helper()
				if row.ID != got.ID || row.ClusterID != item.cluster || row.Workload != item.workload || row.PlatformRole != item.role || row.Status != state {
					t.Fatalf("unexpected response %+v", row)
				}
			}
			assert(got, PcapStatusPending)
			if item.cluster == sibling {
				assert(call(http.MethodGet, "/runtime-pcap/"+got.ID.String(), nil, false, h.Get), PcapStatusPending)
				// Avoid leaving a pending row in the other cluster while exercising the
				// bound agent's exact claim queue.
				return
			}
			assert(call(http.MethodGet, "/runtime-pcap/claim?cluster_id="+cluster.String()+"&node=node-a", nil, true, h.Claim), PcapStatusRunning)
			assert(call(http.MethodPost, "/runtime-pcap/"+got.ID.String()+"/status", []byte(`{"status":"running","packet_count":12}`), true, h.UpdateStatus), PcapStatusRunning)
			uploaded := call(http.MethodPost, "/runtime-pcap/"+got.ID.String()+"/upload", []byte("fixture pcap bytes"), true, h.Upload)
			assert(uploaded, PcapStatusCompleted)
			if uploaded.FileSizeBytes != int64(len("fixture pcap bytes")) || uploaded.SHA256 == "" || uploaded.PacketCount != 12 {
				t.Fatalf("upload evidence %+v", uploaded)
			}
			assert(call(http.MethodGet, "/runtime-pcap/"+got.ID.String(), nil, false, h.Get), PcapStatusCompleted)
		})
	}
}

// Give a disposable connection enough privileges for capture actions but deny
// deployment metadata. This verifies actual lookup errors without altering any
// shared table or relying on a canceled HTTP request.
func TestPcapRoleLookupFailureDoesNotCommitActions(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	t.Setenv("CONSTELLATION_DATA_DIR", t.TempDir())
	ctx, pool := context.Background(), database.Pool()
	org, cluster := uuid.New(), uuid.New()
	token := seedBoundRuntimeAgentScope(t, database, org, cluster)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM runtime_pcap_captures WHERE org_id=$1`, org) })
	role := pgx.Identifier{"pcap_role_test_" + uuid.New().String()}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP OWNED BY `+role); _, _ = pool.Exec(ctx, `DROP ROLE `+role) })
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON runtime_pcap_captures TO ` + role,
		`GRANT SELECT ON cluster_init_bundles, clusters TO ` + role,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := pool.Config().Copy()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["role"] = role[1 : len(role)-1]
	restricted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	h := NewPcapHTTP(db.NewFromPool(restricted))
	body, _ := json.Marshal(StartCaptureRequest{ClusterID: cluster, Workload: "custom-install/api", DurationS: 30})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/runtime-pcap/start", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
	res := httptest.NewRecorder()
	h.Start(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("start %d %s", res.Code, res.Body.String())
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM runtime_pcap_captures WHERE org_id=$1`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed start committed count=%d err=%v", count, err)
	}
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO runtime_pcap_captures(org_id,cluster_id,workload,namespace,requested_by) VALUES($1,$2,'custom-install/api','custom-install',$3) RETURNING id`, org, cluster, uuid.New()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/runtime-pcap/claim?cluster_id="+cluster.String()+"&node=node-a", nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), token))
	res = httptest.NewRecorder()
	h.Claim(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("claim %d %s", res.Code, res.Body.String())
	}
	var status, claimed string
	if err := pool.QueryRow(ctx, `SELECT status,COALESCE(claimed_by_node,'') FROM runtime_pcap_captures WHERE id=$1`, id).Scan(&status, &claimed); err != nil || status != "pending" || claimed != "" {
		t.Fatalf("failed claim committed status=%s node=%s err=%v", status, claimed, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runtime_pcap_captures SET status='running' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"upload", "status"} {
		body := []byte("fixture pcap bytes")
		if endpoint == "status" {
			body = []byte(`{"status":"failed"}`)
		}
		req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/runtime-pcap/"+id.String()+"/"+endpoint, bytes.NewReader(body))
		req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), token))
		res = httptest.NewRecorder()
		if endpoint == "upload" {
			h.Upload(res, req)
		} else {
			h.UpdateStatus(res, req)
		}
		if res.Code != http.StatusInternalServerError {
			t.Fatalf("%s %d %s", endpoint, res.Code, res.Body.String())
		}
		if endpoint == "upload" {
			if _, err := os.Stat(pcapFilePath(id)); !os.IsNotExist(err) {
				t.Fatalf("failed metadata lookup wrote capture file: %v", err)
			}
		}
		if err := pool.QueryRow(ctx, `SELECT status FROM runtime_pcap_captures WHERE id=$1`, id).Scan(&status); err != nil || status != "running" {
			t.Fatalf("%s committed status=%s err=%v", endpoint, status, err)
		}
	}
}
