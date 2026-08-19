package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

func TestPostFileProfileWatches(t *testing.T) {
	token := "cra_test"
	var got fileProfileWatchReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/file-profile-watches:report" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	report := fileProfileWatchReport{
		ClusterID:         "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130",
		Node:              "node-a",
		ObservedAt:        time.Now().UTC(),
		BundleFingerprint: "abc123",
		Rules: []hostscan.FileProfileWatchRule{{
			ID:         "rule-1",
			WorkloadID: "default/api",
			Files: []hostscan.FileProfileWatchFile{{
				Path:          "/etc/passwd",
				ContainerID:   "abc123",
				ContainerName: "api",
				PodName:       "api-7d9c",
				PodNamespace:  "default",
			}},
			FilesCount:     1,
			SensitiveCount: 1,
		}},
	}
	if err := postFileProfileWatches(context.Background(), srv.Client(), srv.URL+"/api/v1/runtime/file-profile-watches:report", token, report); err != nil {
		t.Fatal(err)
	}
	if got.ClusterID != report.ClusterID || got.Node != "node-a" || got.Rules[0].Files[0].Path != "/etc/passwd" {
		t.Fatalf("report = %+v", got)
	}
}

func TestHostscanRulesFromWireIncludesPodWorkloads(t *testing.T) {
	got := hostscanRulesFromWire([]fileProfileRuleWire{{
		ID:             "rule-1",
		WorkloadID:     "default/api",
		PodWorkloadIDs: []string{"default/pod/api-7d9c"},
		Filter:         "/etc/passwd",
		Path:           "/etc/passwd",
	}})
	if len(got) != 1 || got[0].PodWorkloadIDs[0] != "default/pod/api-7d9c" {
		t.Fatalf("rules = %+v", got)
	}
}
