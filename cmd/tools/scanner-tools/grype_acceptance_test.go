package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGrypeBinary checks the release-built executable, including Cobra's actual
// completion entry point. It also accepts a binary extracted from a scanner image.
func TestGrypeBinary(t *testing.T) {
	binary := os.Getenv("CONSTELLATION_TEST_GRYPE_BINARY")
	if binary == "" {
		t.Skip("set CONSTELLATION_TEST_GRYPE_BINARY to a release-built Grype executable")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("linked dependencies", func(t *testing.T) {
		info, err := buildinfo.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		if info.Path != "github.com/anchore/grype/cmd/grype" {
			t.Fatalf("unexpected executable: %s", info.Path)
		}
		foundClient := false
		for _, dep := range info.Deps {
			if dep.Path == "github.com/docker/docker" {
				t.Fatalf("retired Docker module is linked: %s", dep.Version)
			}
			foundClient = foundClient || dep.Path == "github.com/moby/moby/client"
		}
		if !foundClient {
			t.Fatal("maintained Moby client missing from executable")
		}
	})
	for _, tc := range []struct {
		name     string
		version  string
		explicit bool
		status   int
		body     string
		want     []string
	}{
		{"negotiate older daemon", "1.44", false, 200, `[{"RepoTags":["team/app:one","team/app:two","other/app:one"]},{"RepoTags":null}]`, []string{"team/app:one", "team/app:two", ":0"}},
		{"negotiate newer daemon", "1.52", false, 200, `[{"RepoTags":["team/app:one"]}]`, []string{"team/app:one", ":0"}},
		{"explicit API", "1.44", true, 200, `[{"RepoTags":["team/app:one"]}]`, []string{"team/app:one", ":0"}},
		{"empty daemon fallback", "1.44", true, 200, `[]`, []string{":0"}},
		{"unmatched prefix fallback", "1.44", true, 200, `[{"RepoTags":["other/app:one"]}]`, []string{":0"}},
		{"daemon failure fallback", "1.44", true, 500, `{"message":"fixture daemon failure"}`, []string{":0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pings, lists atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					pings.Add(1)
					w.Header().Set("API-Version", tc.version)
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.Method != http.MethodGet || r.URL.Path != "/v"+tc.version+"/images/json" {
					t.Errorf("unexpected daemon request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				lists.Add(1)
				var filters map[string]map[string]bool
				if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil || !reflect.DeepEqual(filters, map[string]map[string]bool{"dangling": {"false": true}}) {
					t.Errorf("incorrect image filter: %v (decode error: %v)", filters, err)
				}
				if all := r.URL.Query().Get("all"); all != "" && all != "0" && all != "false" {
					t.Errorf("completion requested all images: %s", all)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "__complete", "team/")
			apiVersion := ""
			if tc.explicit {
				apiVersion = tc.version
			}
			// An isolated environment avoids the developer's Docker credentials,
			// Grype configuration, and proxy settings affecting the fixture.
			cmd.Env = []string{
				"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH"),
				"DOCKER_HOST=tcp://" + strings.TrimPrefix(server.URL, "http://"),
				"DOCKER_API_VERSION=" + apiVersion,
				"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_AUTO_UPDATE=false",
			}
			cmd.Dir = t.TempDir()
			var stderr strings.Builder
			cmd.Stderr = &stderr
			stdout, err := cmd.Output()
			if err != nil {
				t.Fatalf("completion failed: %v\n%s", err, stderr.String())
			}
			if got := strings.Split(strings.TrimSpace(string(stdout)), "\n"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("completion=%q, want=%q; stderr=%s", got, tc.want, stderr.String())
			}
			if lists.Load() != 1 || (tc.explicit && pings.Load() != 0) || (!tc.explicit && pings.Load() == 0) {
				t.Fatalf("unexpected daemon calls: lists=%d pings=%d", lists.Load(), pings.Load())
			}
		})
	}
}
