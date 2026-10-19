package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/scanlease"
	"github.com/google/uuid"
)

func TestScanLeaseIdentityPropagatesToWorkerRequests(t *testing.T) {
	id := uuid.NewString()
	seen := map[string]int{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(scanlease.Header) != id {
			t.Errorf("%s lease header = %q", r.URL.Path, r.Header.Get(scanlease.Header))
		}
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth_kind":"anonymous","kind":"generic","endpoint":"example.test"}`))
	}))
	defer server.Close()
	worker := &worker{controlPlane: server.URL, token: "fixture", instanceID: "same-worker", logger: nopLogger{}}
	ctx := scanlease.WithContext(context.Background(), id)
	if err := worker.reportSuccess(ctx, scanResultPayload{JobID: "job"}); err != nil {
		t.Fatal(err)
	}
	if err := worker.reportFailure(ctx, "job", "failure"); err != nil {
		t.Fatal(err)
	}
	if err := worker.renewOnce(ctx, "job"); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.fetchRegistryCredentials(ctx, "registry", "job"); err != nil {
		t.Fatal(err)
	}
	worker.executeJob(context.Background(), &scanJob{ID: "empty-target", TargetType: "image", LeaseID: id})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 5 {
		t.Fatalf("requests = %v", seen)
	}
}
