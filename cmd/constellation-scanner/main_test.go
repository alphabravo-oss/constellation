package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetryableScanFailure(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want bool
	}{
		{name: "empty", err: "", want: false},
		{name: "unsupported", err: "unsupported_target_type:registry", want: false},
		{name: "missing evidence", err: "missing_package_evidence", want: false},
		{name: "stale evidence", err: "stale_package_evidence", want: false},
		{name: "registry timeout", err: "registry timeout", want: true},
		{name: "scanner error", err: "trivy failed", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryableScanFailure(tc.err); got != tc.want {
				t.Fatalf("retryableScanFailure(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRenewOnceSendsScannerInstance(t *testing.T) {
	var gotInstance string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotInstance = r.Header.Get("X-Constellation-Scanner-Instance")
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/api/v1/scan-jobs/job-1/renew") {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := &worker{
		controlPlane: srv.URL,
		token:        "cst_test",
		instanceID:   "scanner-pod-1",
	}
	if err := w.renewOnce(context.Background(), "job-1"); err != nil {
		t.Fatal(err)
	}
	if gotInstance != "scanner-pod-1" {
		t.Fatalf("instance header = %q", gotInstance)
	}
}

func TestParseTargetCapacities(t *testing.T) {
	got := parseTargetCapacities("image=2,host=8,platform=0,repository=3,unknown=9", 4)
	if got["image"] != 2 {
		t.Fatalf("image capacity = %d", got["image"])
	}
	if got["host"] != 4 {
		t.Fatalf("host capacity should clamp to max concurrent, got %d", got["host"])
	}
	if got["platform"] != 0 {
		t.Fatalf("platform capacity = %d", got["platform"])
	}
	if got["repository"] != 3 {
		t.Fatalf("repository capacity = %d", got["repository"])
	}
	if _, ok := got["unknown"]; ok {
		t.Fatalf("unknown target type should be ignored: %+v", got)
	}
	if parseTargetCapacities("", 4) != nil {
		t.Fatal("empty target capacity should leave scheduler unfiltered")
	}
}

func TestStatusSnapshotReportsCacheHealth(t *testing.T) {
	cacheDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cacheDir, "layer-cache.json"), []byte("cache-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &worker{
		instanceID:    "scanner-pod-1",
		maxConcurrent: 4,
		targetCapacity: map[string]int{
			"image": 2,
			"host":  4,
		},
		activeByType: map[string]int{"image": 1},
		engines:      map[string]bool{"syft": true},
		cacheDirs: map[string]string{
			"syft":    cacheDir,
			"missing": filepath.Join(cacheDir, "missing"),
			"empty":   "",
		},
	}

	snapshot := w.statusSnapshot()
	if snapshot["active_jobs"].(int) != 1 || snapshot["idle_capacity"].(int) != 3 {
		t.Fatalf("capacity snapshot = %+v", snapshot)
	}
	cacheHealth, ok := snapshot["cache_health"].(map[string]any)
	if !ok {
		t.Fatalf("cache_health missing or wrong type: %+v", snapshot["cache_health"])
	}
	syft, ok := cacheHealth["syft"].(map[string]any)
	if !ok {
		t.Fatalf("syft cache health missing: %+v", cacheHealth)
	}
	if syft["status"] != "ready" || syft["writable"] != true || syft["present"] != true {
		t.Fatalf("syft cache health = %+v", syft)
	}
	if syft["record_count"] != int64(1) || syft["record_size_bytes"] != int64(10) {
		t.Fatalf("syft cache usage = %+v", syft)
	}
	records, ok := syft["records"].([]map[string]any)
	if !ok || len(records) != 1 || records[0]["layer"] != "layer-cache.json" {
		t.Fatalf("syft cache records = %+v", syft["records"])
	}
	missing := cacheHealth["missing"].(map[string]any)
	if missing["status"] != "missing" || missing["writable"] != false {
		t.Fatalf("missing cache health = %+v", missing)
	}
	empty := cacheHealth["empty"].(map[string]any)
	if empty["status"] != "not-configured" || empty["configured"] != false {
		t.Fatalf("empty cache health = %+v", empty)
	}
}
