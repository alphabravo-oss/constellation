package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGenericV2ListImages_Catalog proves the plain Docker Registry v2 connector enumerates
// repositories from /v2/_catalog and qualifies each with the registry host.
func TestGenericV2ListImages_Catalog(t *testing.T) {
	var authHdr string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/_catalog":
			authHdr = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"repositories":["team/app","team/api"]}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/v2/") {
				w.WriteHeader(http.StatusNotFound) // tag listing is best-effort
				return
			}
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	g := NewGenericV2(Config{Endpoint: srv.URL, Username: "u", Password: "p", HTTPClient: srv.Client()})
	imgs, err := g.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	want := []string{host + "/team/api", host + "/team/app"}
	if got := repoSet(imgs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("repos = %v, want %v", got, want)
	}
	if !strings.HasPrefix(authHdr, "Basic ") {
		t.Fatalf("expected HTTP Basic auth, got %q", authHdr)
	}
}

// TestNexusListImages_BearerCatalog proves the Nexus connector shares the v2 catalog walk
// and prefers a bearer Token over Basic auth when both are set.
func TestNexusListImages_BearerCatalog(t *testing.T) {
	var authHdr string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/_catalog":
			authHdr = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"repositories":["nx/base"]}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/v2/") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	n := NewNexus(Config{Endpoint: srv.URL, Username: "u", Password: "p", Token: "tok", HTTPClient: srv.Client()})
	if n.Name() != "nexus" {
		t.Fatalf("Name() = %q, want nexus", n.Name())
	}
	imgs, err := n.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	if got := repoSet(imgs); strings.Join(got, ",") != host+"/nx/base" {
		t.Fatalf("repos = %v", got)
	}
	if authHdr != "Bearer tok" {
		t.Fatalf("expected Bearer token auth, got %q", authHdr)
	}
}

// TestGenericV2AndNexus_RequireEndpoint proves both connectors reject an empty endpoint.
func TestGenericV2AndNexus_RequireEndpoint(t *testing.T) {
	if _, err := NewGenericV2(Config{}).ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "Endpoint") {
		t.Fatalf("generic-v2: expected Endpoint error, got %v", err)
	}
	if _, err := NewNexus(Config{}).ListImages(context.Background()); err == nil || !strings.Contains(err.Error(), "Endpoint") {
		t.Fatalf("nexus: expected Endpoint error, got %v", err)
	}
}

// TestAllRegistries_IncludesNexusAndGenericV2 proves the two v2 connectors are reachable
// through registry.All.
func TestAllRegistries_IncludesNexusAndGenericV2(t *testing.T) {
	conns := All(map[string]Config{
		"nexus":      {Endpoint: "nexus.example:8082"},
		"generic-v2": {Endpoint: "registry.example:5000"},
	})
	names := map[string]bool{}
	for _, c := range conns {
		names[c.Name()] = true
	}
	if !names["nexus"] || !names["generic-v2"] {
		t.Fatalf("missing connectors from All(); got %+v", names)
	}
}
