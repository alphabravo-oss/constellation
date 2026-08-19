package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAllRegistries_IncludesIBMCloudAndOpenShift proves the two A8 connectors are
// wired into the registry type enum (registry.All).
func TestAllRegistries_IncludesIBMCloudAndOpenShift(t *testing.T) {
	conns := All(map[string]Config{
		"ibmcloud":  {Endpoint: "us.icr.io", Account: "acct", Password: "apikey"},
		"openshift": {Endpoint: "registry.apps.example.com", Token: "sha256~tok"},
	})
	names := map[string]bool{}
	for _, c := range conns {
		names[c.Name()] = true
	}
	if !names["ibmcloud"] {
		t.Fatalf("ibmcloud connector missing from All(); got %+v", names)
	}
	if !names["openshift"] {
		t.Fatalf("openshift connector missing from All(); got %+v", names)
	}
}

func TestIBMCloudNameAndConfigValidation(t *testing.T) {
	r := NewIBMCloud(Config{})
	if r.Name() != "ibmcloud" {
		t.Fatalf("Name() = %q, want ibmcloud", r.Name())
	}
	// Missing endpoint.
	if _, err := r.ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "Endpoint") {
		t.Fatalf("expected Endpoint error, got %v", err)
	}
	// Endpoint but no account.
	r = NewIBMCloud(Config{Endpoint: "us.icr.io", Password: "k"})
	if _, err := r.ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "Account") {
		t.Fatalf("expected Account error, got %v", err)
	}
	// Endpoint + account but no API key -> token exchange fails on missing password.
	r = NewIBMCloud(Config{Endpoint: "us.icr.io", Account: "a"})
	if _, err := r.ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("expected API-key error, got %v", err)
	}
}

func TestIBMCloudTokenURLDefault(t *testing.T) {
	if got := NewIBMCloud(Config{}).tokenURL(); got != defaultIBMTokenURL {
		t.Fatalf("default tokenURL = %q, want %q", got, defaultIBMTokenURL)
	}
	if got := NewIBMCloud(Config{TokenURL: "https://custom/token"}).tokenURL(); got != "https://custom/token" {
		t.Fatalf("override tokenURL = %q", got)
	}
}

// TestIBMCloudListImages_TokenExchangeAndCatalog exercises the full IAM
// token-exchange + /api/v1/images enumeration and RepoTags collapsing.
func TestIBMCloudListImages_TokenExchangeAndCatalog(t *testing.T) {
	var gotGrant, gotAccount, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			gotGrant = r.Form.Get("grant_type")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"iam-tok"}`))
		case "/api/v1/images":
			gotAccount = r.Header.Get("Account")
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"RepoTags":["us.icr.io/ns/app:1.0","us.icr.io/ns/app:1.1"]},
				{"RepoTags":["us.icr.io/ns/db:latest"]}
			]`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	r := NewIBMCloud(Config{
		Endpoint:   host,
		Account:    "acct-guid",
		Password:   "my-apikey",
		TokenURL:   srv.URL + "/token",
		HTTPClient: srv.Client(),
	})
	imgs, err := r.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if gotGrant != ibmAPIKeyGrant {
		t.Fatalf("grant_type = %q, want %q", gotGrant, ibmAPIKeyGrant)
	}
	if gotAccount != "acct-guid" {
		t.Fatalf("Account header = %q", gotAccount)
	}
	if gotAuth != "Bearer iam-tok" {
		t.Fatalf("Authorization = %q, want Bearer iam-tok", gotAuth)
	}
	if len(imgs) != 2 {
		t.Fatalf("images = %d, want 2 (%+v)", len(imgs), imgs)
	}
	byRepo := map[string][]string{}
	for _, im := range imgs {
		byRepo[im.Repository] = im.Tags
	}
	app, ok := byRepo["us.icr.io/ns/app"]
	if !ok || len(app) != 2 || app[0] != "1.0" || app[1] != "1.1" {
		t.Fatalf("app tags = %+v, want [1.0 1.1]", app)
	}
	if _, ok := byRepo["us.icr.io/ns/db"]; !ok {
		t.Fatalf("db repo missing: %+v", byRepo)
	}
}

func TestSplitRepoTag(t *testing.T) {
	for _, tc := range []struct{ in, repo, tag string }{
		{"us.icr.io/ns/app:1.0", "us.icr.io/ns/app", "1.0"},
		{"registry:5000/ns/app:2.0", "registry:5000/ns/app", "2.0"},
		{"registry:5000/ns/app", "registry:5000/ns/app", ""},
		{"quay.io/org/x", "quay.io/org/x", ""},
		{"", "", ""},
	} {
		repo, tag := splitRepoTag(tc.in)
		if repo != tc.repo || tag != tc.tag {
			t.Fatalf("%q -> (%q,%q), want (%q,%q)", tc.in, repo, tag, tc.repo, tc.tag)
		}
	}
}

func TestOpenShiftNameAndConfigValidation(t *testing.T) {
	r := NewOpenShift(Config{})
	if r.Name() != "openshift" {
		t.Fatalf("Name() = %q, want openshift", r.Name())
	}
	if _, err := r.ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "Endpoint") {
		t.Fatalf("expected Endpoint error, got %v", err)
	}
	// Endpoint but neither token nor basic creds.
	r = NewOpenShift(Config{Endpoint: "registry.example"})
	if _, err := r.ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "Token") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestOpenShiftAuthShapes(t *testing.T) {
	if !NewOpenShift(Config{Token: "t"}).authWithToken() {
		t.Fatalf("token config should authWithToken")
	}
	if NewOpenShift(Config{Username: "u", Password: "p"}).authWithToken() {
		t.Fatalf("basic-auth config should not authWithToken")
	}
}

// TestOpenShiftListImages_CatalogBearer proves the v2 /_catalog enumeration and
// bearer-token auth path.
func TestOpenShiftListImages_CatalogBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/_catalog":
			gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"repositories":["project/app","project/db"]}`))
		case "/v2/project/app/tags/list":
			_, _ = w.Write([]byte(`{"tags":["1.0"]}`))
		case "/v2/project/db/tags/list":
			_, _ = w.Write([]byte(`{"tags":["latest"]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	r := NewOpenShift(Config{Endpoint: host, Token: "sha256~tok", HTTPClient: srv.Client()})
	imgs, err := r.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if gotAuth != "Bearer sha256~tok" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if len(imgs) != 2 || imgs[0].Repository != host+"/project/app" {
		t.Fatalf("images = %+v", imgs)
	}
}

func TestOpenShiftListImages_BasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"repositories":[]}`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	r := NewOpenShift(Config{Endpoint: host, Username: "svc", Password: "pw", HTTPClient: srv.Client()})
	if _, err := r.ListImages(context.Background()); err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if !ok || user != "svc" || pass != "pw" {
		t.Fatalf("basic auth = (%q,%q,%v)", user, pass, ok)
	}
}
