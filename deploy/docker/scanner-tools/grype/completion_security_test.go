package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
)

func TestConstellationMobyCompletion(t *testing.T) {
	for _, version := range []string{"1.44", "1.52"} {
		t.Run("negotiated_"+version, func(t *testing.T) {
			var lists, pings atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_ping" {
					pings.Add(1)
					w.Header().Set("API-Version", version)
					w.WriteHeader(200)
					return
				}
				if r.Method != http.MethodGet || r.URL.Path != "/v"+version+"/images/json" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
					return
				}
				lists.Add(1)
				var filters map[string]map[string]bool
				if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil || !reflect.DeepEqual(filters, map[string]map[string]bool{"dangling": {"false": true}}) {
					t.Errorf("incorrect image filter: %v %v", filters, err)
				}
				if r.URL.Query().Get("all") == "1" {
					t.Error("completion requested all images")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"RepoTags":["team/app:one","team/app:two","other/app:one"]},{"RepoTags":null}]`))
			}))
			defer server.Close()
			t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
			t.Setenv("DOCKER_API_VERSION", "")
			t.Setenv("DOCKER_TLS_VERIFY", "")
			t.Setenv("DOCKER_CERT_PATH", "")
			got, err := listLocalDockerImages("team/")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, []string{"team/app:one", "team/app:two"}) {
				t.Fatalf("tags=%v", got)
			}
			if lists.Load() != 1 || pings.Load() == 0 {
				t.Fatalf("lists=%d pings=%d", lists.Load(), pings.Load())
			}
		})
	}
	t.Run("explicit API and daemon failure preserve shell fallback", func(t *testing.T) {
		var lists atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_ping" {
				t.Error("explicit API should not negotiate")
				w.WriteHeader(500)
				return
			}
			if r.URL.Path != "/v1.44/images/json" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			lists.Add(1)
			http.Error(w, "fixture daemon failure", 500)
		}))
		defer server.Close()
		t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
		t.Setenv("DOCKER_API_VERSION", "1.44")
		t.Setenv("DOCKER_TLS_VERIFY", "")
		t.Setenv("DOCKER_CERT_PATH", "")
		got, directive := dockerImageValidArgsFunction(nil, nil, "team/")
		if len(got) != 0 || directive != cobra.ShellCompDirectiveDefault || lists.Load() != 1 {
			t.Fatalf("fallback=%v directive=%d lists=%d", got, directive, lists.Load())
		}
	})
	t.Run("empty daemon preserves shell fallback", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		}))
		defer server.Close()
		t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
		t.Setenv("DOCKER_API_VERSION", "1.44")
		t.Setenv("DOCKER_TLS_VERIFY", "")
		t.Setenv("DOCKER_CERT_PATH", "")
		got, directive := dockerImageValidArgsFunction(nil, nil, "")
		if len(got) != 0 || directive != cobra.ShellCompDirectiveDefault {
			t.Fatalf("fallback=%v directive=%d", got, directive)
		}
	})
}
