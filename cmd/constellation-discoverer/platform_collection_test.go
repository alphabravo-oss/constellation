package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Exercise real client-go pagination and the HTTP report boundary together.
func TestPlatformReportingRequiresEveryInventoryPage(t *testing.T) {
	paths := []string{"/api/v1/nodes", "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets"}
	cases := []struct{ name, failPath, failPage string }{{name: "complete"}}
	for _, path := range paths {
		for _, page := range []string{"", "next"} {
			cases = append(cases, struct{ name, failPath, failPage string }{path + "/" + page, path, page})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			var failEnabled atomic.Bool
			failEnabled.Store(true)
			reports := make(chan platformFactsReportBody, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if req.URL.Path == "/version" {
					fmt.Fprint(w, `{"major":"1","minor":"35","gitVersion":"v1.35.5"}`)
					return
				}
				if req.URL.Path == "/api/v1/platform-facts:report" {
					posts.Add(1)
					var report platformFactsReportBody
					if err := json.NewDecoder(req.Body).Decode(&report); err != nil {
						t.Error(err)
					}
					reports <- report
					w.WriteHeader(http.StatusAccepted)
					return
				}
				page := req.URL.Query().Get("continue")
				if failEnabled.Load() && req.URL.Path == tc.failPath && page == tc.failPage {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`)
					return
				}
				if req.URL.Query().Get("limit") == "" {
					t.Error("unbounded list request")
				}
				next := "next"
				if page == "next" {
					next = ""
				} else if page != "" {
					t.Errorf("unexpected page %q", page)
				}
				kind, apiVersion, item := "", "", map[string]any{}
				switch req.URL.Path {
				case "/api/v1/nodes":
					kind, apiVersion = "NodeList", "v1"
					version := "v1.34.0"
					if page == "next" {
						version = "v1.35.5"
					}
					item = map[string]any{"metadata": map[string]any{"name": "node-" + page}, "status": map[string]any{"nodeInfo": map[string]any{"kubeletVersion": version}}}
				case "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets":
					kind, apiVersion = "DeploymentList", "apps/v1"
					image := "coredns/coredns:1.13.0"
					if strings.HasSuffix(req.URL.Path, "daemonsets") {
						kind = "DaemonSetList"
						image = "quay.io/cilium/cilium:v1.17.0"
					}
					if page == "next" {
						image = strings.ReplaceAll(strings.ReplaceAll(image, "1.13.0", "1.14.3"), "v1.17.0", "v1.18.0")
					}
					item = map[string]any{"metadata": map[string]any{"name": "component-" + page, "namespace": "system"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []map[string]string{{"name": "component", "image": image}}}}}}
				default:
					t.Errorf("unexpected request %s", req.URL.Path)
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"kind": kind, "apiVersion": apiVersion, "metadata": map[string]any{"continue": next, "resourceVersion": "1"}, "items": []any{item}})
			}))
			defer server.Close()
			t.Setenv("CONSTELLATION_API_URL", server.URL)
			t.Setenv("CONSTELLATION_DISCOVERER_TOKEN", "test-token")
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			r := reconciler{cs: client}
			err = r.reportPlatformFacts(context.Background())
			if tc.failPath != "" {
				if err == nil || posts.Load() != 0 {
					t.Fatalf("partial report submitted: err=%v posts=%d", err, posts.Load())
				}
				failEnabled.Store(false)
				err = r.reportPlatformFacts(context.Background())
			}
			if err != nil || posts.Load() != 1 {
				t.Fatalf("complete report failed: err=%v posts=%d", err, posts.Load())
			}
			report := <-reports
			if report.NodeCount != 2 || report.KubeletVersions["v1.34.0"] != 1 || report.KubeletVersions["v1.35.5"] != 1 {
				t.Fatalf("node pages lost: %+v", report)
			}
			versions := map[string]bool{}
			for _, c := range report.Components {
				versions[c.Name+"@"+c.Version] = true
			}
			for _, want := range []string{"coredns@1.13.0", "coredns@1.14.3", "cilium@v1.17.0", "cilium@v1.18.0"} {
				if !versions[want] {
					t.Errorf("missing later-page evidence %s", want)
				}
			}
		})
	}
}
