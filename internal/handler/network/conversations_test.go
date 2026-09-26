package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
)

func TestEndpointKind(t *testing.T) {
	cases := map[string]string{
		"default/api":             "workload",
		"cert-manager/webhook":    "workload",
		"cluster/10.42.0.1":       "host",     // CNI pod-network gateway (.1) — infra, not a workload
		"cluster/8.8.8.8":         "external", // public IP under cluster scope
		"host/node-1":             "host",
		"node/ip-10-0-0-5":        "host",
		"external/api.github.com": "external",
		"10.0.0.5":                "unmanaged", // bare private IP
		"1.1.1.1":                 "external",  // bare public IP
		"default/192.168.1.5":     "unmanaged", // ns-scoped but a private IP
	}
	for id, want := range cases {
		if got := endpointKind(id); got != want {
			t.Errorf("endpointKind(%q)=%q want %q", id, got, want)
		}
	}
}

func TestNetworkConversationsPlatformRolesForSQLAndLiveGraph(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, foreignOrgID, clusterID, otherClusterID, foreignClusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "conversation-role-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, foreignOrgID, "conversation-role-"+foreignOrgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, foreignOrgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $3, 'first'), ($2, $3, 'second'), ($4, $5, 'foreign')`, clusterID, otherClusterID, orgID, foreignClusterID, foreignOrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES
		($1, $2, 'operations', 'houston', 'Deployment', '{"app.kubernetes.io/part-of":"astronomer"}'::jsonb),
		($1, $3, 'operations', 'houston', 'Deployment', '{}'::jsonb),
		($4, $5, 'operations', 'houston', 'Deployment', '{"app.kubernetes.io/part-of":"astronomer"}'::jsonb)`, orgID, clusterID, otherClusterID, foreignOrgID, foreignClusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups (org_id, cluster_id, src_workload, dst_workload, protocol, bucket, max_at, sum_bytes) VALUES
		($1, $2, 'operations/houston', 'payments/api', 'tcp', date_trunc('hour', NOW()), NOW(), 300),
		($1, $2, 'payments/api', 'kube-system/coredns', 'tcp', date_trunc('hour', NOW()), NOW(), 200),
		($1, $3, 'operations/houston', 'payments/api', 'tcp', date_trunc('hour', NOW()), NOW(), 100),
		($1, $2, 'kube-system/10.42.0.2', 'payments/api', 'tcp', date_trunc('hour', NOW()), NOW(), 50),
		($4, $5, 'operations/houston', 'payments/api', 'tcp', date_trunc('hour', NOW()), NOW(), 900)`, orgID, clusterID, otherClusterID, foreignOrgID, foreignClusterID); err != nil {
		t.Fatal(err)
	}
	live := livegraph.New(livegraph.Config{})
	for _, flow := range []livegraph.Flow{
		{OrgID: orgID, ClusterID: clusterID, SrcWorkload: "operations/houston", DstWorkload: "payments/api", Protocol: "tcp", Bytes: 300, At: time.Now()},
		{OrgID: orgID, ClusterID: clusterID, SrcWorkload: "payments/api", DstWorkload: "kube-system/coredns", Protocol: "tcp", Bytes: 200, At: time.Now()},
		{OrgID: orgID, ClusterID: otherClusterID, SrcWorkload: "operations/houston", DstWorkload: "payments/api", Protocol: "tcp", Bytes: 100, At: time.Now()},
		{OrgID: orgID, ClusterID: clusterID, SrcWorkload: "kube-system/10.42.0.2", DstWorkload: "payments/api", Protocol: "tcp", Bytes: 50, At: time.Now()},
		{OrgID: foreignOrgID, ClusterID: foreignClusterID, SrcWorkload: "operations/houston", DstWorkload: "payments/api", Protocol: "tcp", Bytes: 900, At: time.Now()},
	} {
		live.Publish(flow)
	}
	get := func(useLive bool, cluster *uuid.UUID) []map[string]any {
		t.Helper()
		url := "/api/v1/network/conversations"
		if cluster != nil {
			url += "?cluster_id=" + cluster.String()
		}
		request := httptest.NewRequest(http.MethodGet, url, nil)
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
		response := httptest.NewRecorder()
		handler := NewNetworkConversations(database)
		if useLive {
			handler.WithLiveGraph(live)
		}
		handler.List(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
		var body struct {
			Conversations []map[string]any `json:"conversations"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Conversations
	}
	for _, useLive := range []bool{false, true} {
		first := get(useLive, &clusterID)
		if len(first) != 3 {
			t.Fatalf("live=%t first cluster: %#v", useLive, first)
		}
		for _, conversation := range first {
			switch conversation["from"] {
			case "operations/houston":
				if conversation["from_platform_role"] != "core" || conversation["to_platform_role"] != nil {
					t.Fatalf("live=%t custom source: %#v", useLive, conversation)
				}
			case "payments/api":
				if conversation["from_platform_role"] != nil || conversation["to_platform_role"] != "core" {
					t.Fatalf("live=%t fixed-namespace destination: %#v", useLive, conversation)
				}
			case "kube-system/10.42.0.2":
				if conversation["from_platform_role"] != nil || conversation["to_platform_role"] != nil {
					t.Fatalf("live=%t IP endpoint classified: %#v", useLive, conversation)
				}
			default:
				t.Fatalf("live=%t unexpected conversation: %#v", useLive, conversation)
			}
		}
		second := get(useLive, &otherClusterID)
		if len(second) != 1 || second[0]["from_platform_role"] != nil || second[0]["to_platform_role"] != nil {
			t.Fatalf("live=%t second cluster: %#v", useLive, second)
		}
		all := get(useLive, nil)
		if len(all) != 3 {
			t.Fatalf("live=%t org-wide conversations: %#v", useLive, all)
		}
		for _, conversation := range all {
			if conversation["from"] == "operations/houston" && conversation["from_platform_role"] != nil {
				t.Fatalf("live=%t ambiguous org-wide role: %#v", useLive, conversation)
			}
		}
	}
	for _, testCase := range []struct {
		name, from, to, cluster string
		entries                 int
		bytes                   int64
		fromRole, toRole        string
	}{
		{"scoped label", "operations/houston", "payments/api", clusterID.String(), 1, 300, "core", ""},
		{"other cluster", "operations/houston", "payments/api", otherClusterID.String(), 1, 100, "", ""},
		{"ambiguous org-wide", "operations/houston", "payments/api", "", 1, 400, "", ""},
		{"fixed namespace", "payments/api", "kube-system/coredns", clusterID.String(), 1, 200, "", "core"},
		{"IP endpoint", "kube-system/10.42.0.2", "payments/api", clusterID.String(), 1, 50, "", ""},
		{"foreign cluster", "operations/houston", "payments/api", foreignClusterID.String(), 0, 0, "", ""},
		{"absent flow", "operations/houston", "payments/absent", clusterID.String(), 0, 0, "", ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			url := "/api/v1/network/conversations/entries?from=" + testCase.from + "&to=" + testCase.to
			if testCase.cluster != "" {
				url += "&cluster_id=" + testCase.cluster
			}
			request := httptest.NewRequest(http.MethodGet, url, nil)
			request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
			response := httptest.NewRecorder()
			NewNetworkConversations(database).Detail(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
			var body struct {
				Entries          []conversationEntryDTO `json:"entries"`
				FromPlatformRole *string                `json:"from_platform_role"`
				ToPlatformRole   *string                `json:"to_platform_role"`
				Totals           struct {
					Bytes int64 `json:"bytes"`
				} `json:"totals"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			role := func(value *string) string {
				if value == nil {
					return ""
				}
				return *value
			}
			if len(body.Entries) != testCase.entries || body.Totals.Bytes != testCase.bytes ||
				role(body.FromPlatformRole) != testCase.fromRole || role(body.ToPlatformRole) != testCase.toRole ||
				(body.FromPlatformRole == nil) != (testCase.fromRole == "") ||
				(body.ToPlatformRole == nil) != (testCase.toRole == "") {
				t.Fatalf("unexpected detail: %s", response.Body.String())
			}
		})
	}
	for _, path := range []string{"/api/v1/network/conversations?cluster_id=invalid", "/api/v1/network/conversations/entries?from=operations/houston&to=payments/api&cluster_id=invalid"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
		response := httptest.NewRecorder()
		if path == "/api/v1/network/conversations?cluster_id=invalid" {
			NewNetworkConversations(database).List(response, request)
		} else {
			NewNetworkConversations(database).Detail(response, request)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d: %s", path, response.Code, response.Body.String())
		}
	}
}
