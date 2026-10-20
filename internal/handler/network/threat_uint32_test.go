//go:build integration

package network

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestThreatUint32StreamsMapAndLegacyPreserveUncertainty(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	org, cluster := uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM network_flow_rollups WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=$1`, org)
	})
	for _, q := range []string{`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'unsigned')`, `INSERT INTO clusters(id,org_id,name) VALUES($2,$1,'unsigned')`, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,max_threat_id,threat_id_complete,has_dp,flow_count) VALUES($1,$2,'prod/api','prod/db','tcp',443,'allow',date_trunc('hour',now()),now(),4294967295,true,true,2),($1,$2,'prod/api','prod/db','tcp',444,'allow',date_trunc('hour',now()),now(),0,false,true,1)`} {
		args := []any{org, cluster}
		if !strings.Contains(q, "$2") {
			args = args[:1]
		}
		if _, err := d.Pool().Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	request := func(path string) *http.Request {
		return httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), "GET", path, nil)
	}
	h := NewNetworkConversations(d)
	path := "/?cluster_id=" + cluster.String() + "&from=prod%2Fapi&to=prod%2Fdb&sort=threat&order=asc"
	w := httptest.NewRecorder()
	h.EntriesInventory(w, request(path))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var page struct {
		Entries []conversationStream `json:"entries"`
		Summary map[string]int64     `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || page.Entries[0].ThreatID != 4294967295 || !page.Entries[0].ThreatIDComplete || page.Entries[1].ThreatIDComplete || page.Summary["threat_id_incomplete"] != 1 {
		t.Fatalf("page=%+v", page)
	}
	w = httptest.NewRecorder()
	h.EntriesCSV(w, request(path))
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(records) != 3 || !strings.Contains(w.Body.String(), "4294967295,true") || !strings.Contains(w.Body.String(), ",0,false,") {
		t.Fatalf("CSV %s err=%v", w.Body.String(), err)
	}
	w = httptest.NewRecorder()
	h.Detail(w, request(path))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"threat_id":4294967295`) || !strings.Contains(w.Body.String(), `"threat_id_complete":false`) {
		t.Fatalf("legacy=%s", w.Body.String())
	}
	flows, err := NewNetwork(d).flows(request(path), org, &cluster, 24, "", "", false, nil, 0, "", "", 0)
	if err != nil || len(flows) != 2 {
		t.Fatalf("map flows=%v err=%v", flows, err)
	}
	if !strings.Contains(threatNameForFlow(4294967295), "4294967295") {
		t.Fatal("high ID aliased threat name")
	}
}
