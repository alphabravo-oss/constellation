package scannercache

import (
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func gather(t *testing.T, reg *prometheus.Registry) map[string]map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]float64{}
	for _, family := range families {
		values := map[string]float64{}
		for _, metric := range family.Metric {
			if len(metric.Label) != 1 || metric.Label[0].GetName() != "cache" {
				t.Fatalf("unexpected labels: %v", metric.Label)
			}
			value := metric.GetGauge().GetValue()
			if metric.Counter != nil {
				value = metric.Counter.GetValue()
			}
			values[metric.Label[0].GetValue()] = value
		}
		out[strings.TrimPrefix(family.GetName(), "constellation_scanner_cache_")] = values
	}
	return out
}

func expire(c *Collector) { c.mu.Lock(); defer c.mu.Unlock(); c.attempted = time.Time{} }

func TestCollectorRealFilesystemReadOnlyAndPrivate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "evidence"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Paths: map[string]string{"grype": root, "unbounded-secret": root}, Engines: map[string]bool{"grype": true}}
	c := New(cfg)
	cfg.Paths["grype"] = "changed-after-construction"
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	values := gather(t, reg)
	if values["collection_success"]["grype"] != 1 || values["present"]["grype"] != 1 || values["capacity_known"]["grype"] != 1 || values["capacity_bytes"]["grype"] <= 0 {
		t.Fatalf("missing real capacity: %v", values)
	}
	if len(values["enabled"]) != 4 || len(values["collection_success"]) != 1 {
		t.Fatalf("unbounded labels or disabled cache collected: %v", values)
	}
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", "/metrics", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), root) || strings.Contains(rec.Body.String(), "unbounded-secret") {
		t.Fatalf("metrics leaked configuration or failed: %s", rec.Body.String())
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("collector wrote to cache: %v %v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "evidence"))
	if err != nil || string(data) != "preserve" {
		t.Fatalf("modified cache: %q %v", data, err)
	}
}

func TestCollectorCacheFailureInvalidationAndRecovery(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cache")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	c := New(Config{Paths: map[string]string{"trivy": path}, Engines: map[string]bool{"trivy": true}, TTL: time.Hour})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	initial := gather(t, reg)
	last := initial["last_success_timestamp_seconds"]["trivy"]
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if gather(t, reg)["collection_success"]["trivy"] != 1 {
		t.Fatal("TTL did not cache sample")
	}
	expire(c)
	failed := gather(t, reg)
	if failed["collection_success"]["trivy"] != 0 || failed["collection_errors_total"]["trivy"] != 1 || failed["last_success_timestamp_seconds"]["trivy"] != last {
		t.Fatalf("failure state: %v", failed)
	}
	if _, ok := failed["available_bytes"]["trivy"]; ok {
		t.Fatal("stale capacity survived failure")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if gather(t, reg)["collection_errors_total"]["trivy"] != 1 {
				t.Error("concurrent scrape bypassed backoff")
			}
		})
	}
	wg.Wait()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	expire(c)
	recovered := gather(t, reg)
	if recovered["collection_success"]["trivy"] != 1 || recovered["capacity_known"]["trivy"] != 1 || recovered["collection_errors_total"]["trivy"] != 1 {
		t.Fatalf("recovery: %v", recovered)
	}
}

func TestCollectorMissingDisabledAndUnconfigured(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "absent")
	c := New(Config{Paths: map[string]string{"grype": path, "syft": root}, Engines: map[string]bool{"grype": true, "trivy": true}})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	values := gather(t, reg)
	if values["collection_success"]["grype"] != 1 || values["present"]["grype"] != 0 || values["configured"]["trivy"] != 0 || values["enabled"]["syft"] != 0 {
		t.Fatalf("path states: %v", values)
	}
	if _, ok := values["capacity_bytes"]["grype"]; ok {
		t.Fatal("missing cache got invented capacity")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("collector created missing directory: %v", err)
	}
}

func TestFilesystemCountersRejectInvalidAndPreserveExhaustion(t *testing.T) {
	normal := syscall.Statfs_t{Blocks: 100, Bfree: 20, Bavail: 10, Bsize: 4096, Files: 100, Ffree: 5}
	got := capacity(normal)
	if !got.bytesKnown || got.capacity != 409600 || got.available != 40960 || !got.inodesKnown || got.freeInodes != 5 {
		t.Fatalf("capacity: %+v", got)
	}
	exhausted := normal
	exhausted.Bavail = 0
	exhausted.Ffree = 0
	got = capacity(exhausted)
	if !got.bytesKnown || got.available != 0 || !got.inodesKnown || got.freeInodes != 0 {
		t.Fatalf("exhaustion hidden: %+v", got)
	}
	for _, stat := range []syscall.Statfs_t{{Bsize: 0}, {Bsize: 4096}, {Bsize: -1}, {Bsize: 4096, Blocks: math.MaxUint64}, {Blocks: 2, Bfree: 3, Bsize: 1}, {Blocks: 3, Bfree: 1, Bavail: 2, Bsize: 1}} {
		if capacity(stat).bytesKnown {
			t.Fatalf("invalid bytes accepted: %+v", stat)
		}
	}
	for _, stat := range []syscall.Statfs_t{{}, {Files: math.MaxUint64}, {Files: 1, Ffree: 2}} {
		if capacity(stat).inodesKnown {
			t.Fatalf("unknown inodes accepted: %+v", stat)
		}
	}
}

func TestCollectorFailureIsolatedPerCache(t *testing.T) {
	root := t.TempDir()
	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	c := New(Config{Paths: map[string]string{"grype": loop, "trivy": root}, Engines: map[string]bool{"grype": true, "trivy": true}})
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	values := gather(t, reg)
	if values["collection_success"]["grype"] != 0 || values["last_success_timestamp_seconds"]["grype"] != 0 || values["collection_errors_total"]["grype"] != 1 || values["collection_success"]["trivy"] != 1 || values["capacity_known"]["trivy"] != 1 {
		t.Fatalf("cache failure isolation: %v", values)
	}
	if _, ok := values["present"]["grype"]; ok {
		t.Fatal("unavailable path reported as known missing")
	}
}
