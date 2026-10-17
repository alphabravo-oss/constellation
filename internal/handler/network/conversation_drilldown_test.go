package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
)

func TestConversationExactDrilldownsBeforePagination(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	org, foreign, cluster, otherCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,$2)`, id, "pair-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreign) })
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters (id,org_id,name) VALUES ($1,$3,'first'),($2,$3,'second')`, cluster, otherCluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups (org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_bytes)
 SELECT $1,$2,'default/client','default/api-'||seq,'tcp',443,'allow',date_trunc('hour',NOW()),NOW(),1000+seq FROM generate_series(1,250) seq`, org, cluster); err != nil {
		t.Fatal(err)
	}
	for i, verdict := range []string{"deny", "denied", "block", "blocked", "allow"} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups (org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_bytes) VALUES ($1,$2,'default/client','default/api', 'tcp',$3,$4,date_trunc('hour',NOW()),NOW(),$5)`, org, cluster, 440+i, verdict, i+1); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		org, cluster uuid.UUID
		from, to     string
	}{
		{org, otherCluster, "default/client", "default/api"},
		{foreign, cluster, "default/client", "default/api"},
		{org, cluster, "default/client-extra", "default/api"},
		{org, cluster, "default/api", "default/client"},
		{org, cluster, "default/%_client", "default/literal"},
	} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups (org_id,cluster_id,src_workload,dst_workload,protocol,verdict,bucket,max_at,sum_bytes) VALUES ($1,$2,$3,$4,'tcp','block',date_trunc('hour',NOW()),NOW(),9999)`, row.org, row.cluster, row.from, row.to); err != nil {
			t.Fatal(err)
		}
	}
	live := livegraph.New(livegraph.Config{})
	live.Publish(livegraph.Flow{OrgID: org, ClusterID: cluster, SrcWorkload: "wrong/source", DstWorkload: "wrong/destination", Protocol: "tcp", Bytes: 99999, At: time.Now()})
	handler := NewNetworkConversations(database).WithLiveGraph(live)
	request := func(query string, wantStatus int) struct {
		Conversations []struct {
			From, To string
			Bytes    int64
		}
		Total   int
		HasMore bool `json:"has_more"`
		Source  string
	} {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/network/conversations?cluster_id="+cluster.String()+"&"+query, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		handler.List(w, req)
		if w.Code != wantStatus {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
		}
		var body struct {
			Conversations []struct {
				From, To string
				Bytes    int64
			}
			Total   int
			HasMore bool `json:"has_more"`
			Source  string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, query := range []string{"from=default%2Fclient&to=default%2Fapi&verdict_group=blocked", "from=default%2Fclient&to=default%2Fapi&verdict_group=blocked&limit=1"} {
		body := request(query, http.StatusOK)
		if body.Total != 1 || len(body.Conversations) != 1 || body.Conversations[0].Bytes != 10 || body.Source == "live" || body.HasMore {
			t.Fatalf("exact blocked pair: %+v", body)
		}
	}
	body := request("from=default%2Fclient&to=default%2Fapi-250&limit=1", http.StatusOK)
	if body.Total != 1 || len(body.Conversations) != 1 || body.Conversations[0].Bytes != 1250 {
		t.Fatalf("match beyond first page: %+v", body)
	}
	body = request("from="+url.QueryEscape("default/%_client")+"&to=default%2Fliteral", http.StatusOK)
	if body.Total != 1 || len(body.Conversations) != 1 || body.Conversations[0].From != "default/%_client" {
		t.Fatalf("literal endpoint: %+v", body)
	}
	body = request("from=missing&to=default%2Fapi", http.StatusOK)
	if body.Total != 0 || len(body.Conversations) != 0 {
		t.Fatalf("missing endpoint broadened: %+v", body)
	}
	body = request("from=default%2Fclient&to=default%2Fapi&verdict_group=blocked&verdict=block", http.StatusOK)
	if body.Total != 1 || len(body.Conversations) != 1 || body.Conversations[0].Bytes != 3 {
		t.Fatalf("intersected verdict: %+v", body)
	}
	for _, offset := range []int{0, 1, 2} {
		body = request(fmt.Sprintf("from=default%%2Fclient&limit=100&offset=%d", offset*100), http.StatusOK)
		want := 100
		if offset == 2 {
			want = 51
		}
		if body.Total != 251 || len(body.Conversations) != want || body.HasMore != (offset < 2) {
			t.Fatalf("filtered page%d: %+v", offset, body)
		}
	}
	request("verdict_group=anything", http.StatusBadRequest)
}
