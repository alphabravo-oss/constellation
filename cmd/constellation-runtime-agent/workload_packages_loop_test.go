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

func TestWorkloadPackageReportsFromInventoriesGroupsSidecars(t *testing.T) {
	now := time.Now().UTC()
	inventories := []hostscan.ContainerPackages{
		{
			Node:          "node-a",
			ObservedAt:    now,
			Runtime:       "containerd",
			WorkloadID:    "payments/pod/api",
			Namespace:     "payments",
			PodName:       "api",
			PodUID:        "pod-uid",
			ContainerID:   "c1",
			ContainerName: "api",
			Image:         "example.test/api:dev",
			Distro:        "ubuntu",
			DistroVersion: "24.04",
			Source:        "dpkg",
			Count:         1,
			Items:         []hostscan.Package{{Name: "openssl", Version: "3.0.13", Source: "dpkg"}},
		},
		{
			Node:          "node-a",
			ObservedAt:    now.Add(time.Second),
			Runtime:       "containerd",
			WorkloadID:    "payments/pod/api",
			Namespace:     "payments",
			PodName:       "api",
			PodUID:        "pod-uid",
			ContainerID:   "c2",
			ContainerName: "sidecar",
			Image:         "example.test/sidecar:dev",
			Distro:        "alpine",
			DistroVersion: "3.20",
			Source:        "apk",
			Count:         1,
			Items:         []hostscan.Package{{Name: "musl", Version: "1.2.5-r0", Source: "apk"}},
		},
	}

	reports := workloadPackageReportsFromInventories("cluster-a", inventories)
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	report := reports[0]
	if report.WorkloadID != "payments/pod/api" || report.ClusterID != "cluster-a" {
		t.Fatalf("report identity = %+v", report)
	}
	if report.Count != 2 || len(report.Containers) != 2 {
		t.Fatalf("report counts = %+v", report)
	}
	if !report.ObservedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("observed_at = %s, want latest", report.ObservedAt)
	}
}

func TestWorkloadIDForContainerFallsBackToNodeLocal(t *testing.T) {
	if got := workloadIDForContainer(hostscan.Container{PodNS: "default", PodName: "api"}); got != "default/pod/api" {
		t.Fatalf("workload id = %q", got)
	}
	if got := workloadIDForContainer(hostscan.Container{ID: "containerd://abcdef1234567890"}); got != "node-local/abcdef123456" {
		t.Fatalf("fallback workload id = %q", got)
	}
}

func TestPostWorkloadPackages(t *testing.T) {
	var got workloadPackagesReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postWorkloadPackages(context.Background(), srv.Client(), srv.URL, "token", workloadPackagesReport{
		Node:       "node-a",
		ObservedAt: time.Now(),
		WorkloadID: "default/pod/api",
		Count:      1,
		Containers: []workloadPackagesContainer{{
			ContainerID: "c1",
			Count:       1,
			Items:       []hostscan.Package{{Name: "openssl", Version: "3.0.13"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Node != "node-a" || got.WorkloadID != "default/pod/api" || got.Count != 1 {
		t.Fatalf("posted = %+v", got)
	}
}
