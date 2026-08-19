package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestOpenShiftListImagesPopulatesTags proves that a v2 connector now enumerates
// every tag of each repository (via /v2/<repo>/tags/list) instead of leaving Tags
// empty — the gap that made scan_policy tag_selection="all" a no-op and scanned
// only repo:latest. Before the fix ListImages returned Image{Tags: nil}.
func TestOpenShiftListImagesPopulatesTags(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/_catalog":
			_, _ = w.Write([]byte(`{"repositories":["team/app","team/db"]}`))
		case "/v2/team/app/tags/list":
			_, _ = w.Write([]byte(`{"name":"team/app","tags":["1.0","2.0","latest"]}`))
		case "/v2/team/db/tags/list":
			_, _ = w.Write([]byte(`{"name":"team/db","tags":["stable"]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn := NewOpenShift(Config{Endpoint: srv.URL, Token: "t", HTTPClient: srv.Client()})
	images, err := conn.ListImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byRepo := map[string][]string{}
	for _, im := range images {
		byRepo[im.Repository] = im.Tags
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	if got := byRepo[host+"/team/app"]; !reflect.DeepEqual(got, []string{"1.0", "2.0", "latest"}) {
		t.Fatalf("team/app tags = %v, want [1.0 2.0 latest]", got)
	}
	if got := byRepo[host+"/team/db"]; !reflect.DeepEqual(got, []string{"stable"}) {
		t.Fatalf("team/db tags = %v, want [stable]", got)
	}
}

// TestListTagsViaV2Paginates covers Link-header pagination and the WWW-Authenticate
// challenge dance for the shared tags/list helper.
func TestListTagsViaV2Paginates(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"token":"reg-token"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer reg-token" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="reg",scope="repository:acme/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v2/acme/app/tags/list" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</v2/acme/app/tags/list?n=100&last=v1>; rel="next"`)
			_, _ = w.Write([]byte(`{"tags":["v1"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"tags":["v2","v3"]}`))
	}))
	defer srv.Close()

	repoRef := strings.TrimPrefix(srv.URL, "https://") + "/acme/app"
	tags, err := listTagsViaV2(context.Background(), srv.Client(), repoRef, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tags, []string{"v1", "v2", "v3"}) {
		t.Fatalf("tags = %v, want [v1 v2 v3]", tags)
	}
}
