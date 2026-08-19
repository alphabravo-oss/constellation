package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFileProfileRuleSyncWorkerFetchAndCache(t *testing.T) {
	clusterID := "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130"
	token := "cra_test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/file-profile-rules:bundle" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.URL.Query().Get("cluster_id") != clusterID {
			t.Fatalf("cluster_id=%s", r.URL.Query().Get("cluster_id"))
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(fileProfileRuleBundleWire{
			ClusterID: clusterID,
			Rules: []fileProfileRuleWire{{
				ID:         "rule-1",
				WorkloadID: "default/api",
				PodWorkloadIDs: []string{
					"default/pod/api-7d9c",
				},
				Mode:         "monitor",
				Filter:       "/etc/passwd",
				Path:         "/etc/passwd",
				Behavior:     "monitor_change",
				Applications: []string{"cat"},
				Exceptions: []fileProfileExceptionWire{{
					ID:           "exception-1",
					Filter:       "/etc/passwd",
					Path:         "/etc/passwd",
					Applications: []string{"rpm"},
					UpdatedAt:    "2026-06-14T00:01:00Z",
				}},
				UpdatedAt: "2026-06-14T00:00:00Z",
			}},
		})
	}))
	defer srv.Close()

	worker := NewFileProfileRuleSyncWorker(FileProfileRuleSyncConfig{
		APIBaseURL: srv.URL,
		Token:      token,
		ClusterID:  clusterID,
	})
	worker.SyncOnce(context.Background())
	got := worker.Rules()
	if len(got) != 1 || got[0].ID != "rule-1" || got[0].Applications[0] != "cat" || got[0].PodWorkloadIDs[0] != "default/pod/api-7d9c" || got[0].Exceptions[0].ID != "exception-1" {
		t.Fatalf("rules = %+v", got)
	}
	if worker.updates.Load() != 1 || worker.errors.Load() != 0 {
		t.Fatalf("updates=%d errors=%d", worker.updates.Load(), worker.errors.Load())
	}
}

func TestFingerprintFileProfileRulesIncludesPodWorkloads(t *testing.T) {
	base := []fileProfileRuleWire{{
		ID:             "rule-1",
		WorkloadID:     "default/api",
		PodWorkloadIDs: []string{"default/pod/api-7d9c"},
		Mode:           "monitor",
		Filter:         "/etc/passwd",
		Path:           "/etc/passwd",
		Behavior:       "monitor_change",
		Applications:   []string{"cat"},
		UpdatedAt:      "2026-06-14T00:00:00Z",
	}}
	changed := []fileProfileRuleWire{{
		ID:             "rule-1",
		WorkloadID:     "default/api",
		PodWorkloadIDs: []string{"default/pod/api-9abc"},
		Mode:           "monitor",
		Filter:         "/etc/passwd",
		Path:           "/etc/passwd",
		Behavior:       "monitor_change",
		Applications:   []string{"cat"},
		UpdatedAt:      "2026-06-14T00:00:00Z",
	}}
	if fingerprintFileProfileRules(base) == fingerprintFileProfileRules(changed) {
		t.Fatal("fingerprint should change when pod workload IDs change")
	}
}

func TestFingerprintFileProfileRulesIncludesExceptions(t *testing.T) {
	base := []fileProfileRuleWire{{
		ID:         "rule-1",
		WorkloadID: "default/api",
		Mode:       "enforce",
		Filter:     "/etc/passwd",
		Path:       "/etc/passwd",
		Behavior:   "block_access",
		Exceptions: []fileProfileExceptionWire{{
			ID:           "exception-1",
			Filter:       "/etc/passwd",
			Path:         "/etc/passwd",
			Applications: []string{"rpm"},
			UpdatedAt:    "2026-06-14T00:00:00Z",
		}},
		UpdatedAt: "2026-06-14T00:00:00Z",
	}}
	changed := []fileProfileRuleWire{{
		ID:         "rule-1",
		WorkloadID: "default/api",
		Mode:       "enforce",
		Filter:     "/etc/passwd",
		Path:       "/etc/passwd",
		Behavior:   "block_access",
		Exceptions: []fileProfileExceptionWire{{
			ID:           "exception-1",
			Filter:       "/etc/passwd",
			Path:         "/etc/passwd",
			Applications: []string{"cat"},
			UpdatedAt:    "2026-06-14T00:00:00Z",
		}},
		UpdatedAt: "2026-06-14T00:00:00Z",
	}}
	if fingerprintFileProfileRules(base) == fingerprintFileProfileRules(changed) {
		t.Fatal("fingerprint should change when exceptions change")
	}
}
