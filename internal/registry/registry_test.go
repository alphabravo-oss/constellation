package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	for _, tc := range []struct {
		in, host, repo, tag string
		wantErr             bool
	}{
		{"ghcr.io/foo/bar:v1", "ghcr.io", "foo/bar", "v1", false},
		{"docker.io/library/alpine:3.18", "docker.io", "library/alpine", "3.18", false},
		{"public.ecr.aws/x/y", "public.ecr.aws", "x/y", "latest", false},
		{"alpine:3.18", "", "", "", true}, // no host
		{"ghcr.io/foo/bar@sha256:deadbeef", "", "", "", true},
	} {
		h, r, ta, err := parseRef(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected err", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if h != tc.host || r != tc.repo || ta != tc.tag {
			t.Fatalf("%s: got (%q,%q,%q) want (%q,%q,%q)", tc.in, h, r, ta, tc.host, tc.repo, tc.tag)
		}
	}
}

func TestAllRegistries_FiltersToConfigured(t *testing.T) {
	conns := All(map[string]Config{
		"ghcr":       {Token: "t", Username: "alphabravo"},
		"docker-hub": {Username: "alphabravo"},
		// no ecr → connector absent
	})
	if len(conns) != 2 {
		t.Fatalf("expected 2 connectors, got %d", len(conns))
	}
	names := map[string]bool{}
	for _, c := range conns {
		names[c.Name()] = true
	}
	if !names["ghcr"] || !names["docker-hub"] {
		t.Fatalf("expected ghcr+docker-hub, got %+v", names)
	}
	if names["ecr"] {
		t.Fatalf("ecr should be absent when no config supplied")
	}
}

// TestConfigHTTPClient_WiredClientUsed proves the B1 live-config consumer wiring: when a
// Config carries an HTTPClient (built by the server from the live syscfg Provider), the
// connector routes its outbound traffic through it rather than a private default. This is
// what makes a PATCH to egress_proxy / tls_verify / ca_bundle observable at runtime.
func TestConfigHTTPClient_WiredClientUsed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	// A transport that rewrites every outbound request to the test server — stands in for
	// the egress proxy the live Provider would configure. If the connector ignored the
	// wired client, the request would go to api.github.com and never hit the server.
	wired := &http.Client{Transport: rewriteTransport{target: srv.URL}}

	// httpClient() must return the wired client verbatim.
	if got := (Config{HTTPClient: wired}).httpClient(0); got != wired {
		t.Fatalf("Config.httpClient did not return the wired client")
	}

	g := NewGHCR(Config{Token: "t", Username: "alphabravo", HTTPClient: wired})
	if _, err := g.ListImages(context.Background()); err != nil {
		t.Fatalf("ListImages via wired client: %v", err)
	}
	if hits == 0 {
		t.Fatalf("connector did not route through the wired (live-config) HTTP client")
	}

	// Without a wired client, httpClient() falls back to a private default (non-nil).
	if got := (Config{}).httpClient(0); got == nil || got == wired {
		t.Fatalf("default httpClient should be a non-nil private client")
	}
}

type rewriteTransport struct{ target string }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := http.NewRequest(req.Method, rt.target, req.Body)
	if err != nil {
		return nil, err
	}
	u.Header = req.Header
	return http.DefaultTransport.RoundTrip(u.WithContext(req.Context()))
}

func TestAllRegistries_IncludesAllConfiguredProviders(t *testing.T) {
	conns := All(map[string]Config{
		"docker-hub":        {Username: "owner"},
		"ghcr":              {Username: "owner", Token: "token"},
		"ecr":               {Region: "us-east-1"},
		"artifact-registry": {Endpoint: "projects/p/locations/us/repositories/r", Token: "token"},
		"acr":               {Endpoint: "example.azurecr.io", Token: "token"},
		"quay":              {Endpoint: "quay.io", Token: "token"},
		"harbor":            {Endpoint: "https://harbor.example", Username: "u", Password: "p"},
		"gitlab":            {Endpoint: "https://gitlab.example", Token: "token"},
		"jfrog":             {Endpoint: "https://jfrog.example", Username: "u", Password: "p"},
	})
	want := map[string]bool{
		"docker-hub":        false,
		"ghcr":              false,
		"ecr":               false,
		"artifact-registry": false,
		"acr":               false,
		"quay":              false,
		"harbor":            false,
		"gitlab":            false,
		"jfrog":             false,
	}
	if len(conns) != len(want) {
		t.Fatalf("connectors = %d, want %d", len(conns), len(want))
	}
	for _, conn := range conns {
		name := conn.Name()
		if _, ok := want[name]; !ok {
			t.Fatalf("unexpected connector %q", name)
		}
		want[name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("missing connector %q", name)
		}
	}
}

func TestInspectManifestReferenceSingleManifest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/acme/api/manifests/sha256:manifest" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Docker-Content-Digest", "sha256:manifest")
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write([]byte(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:config", "size": 7023},
			"layers": [
				{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:layer1", "size": 100},
				{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:layer2", "size": 250}
			]
		}`))
	}))
	defer srv.Close()

	ref := strings.TrimPrefix(srv.URL, "https://") + "/acme/api@sha256:manifest"
	meta, err := inspectManifestViaV2(context.Background(), srv.Client(), ref, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if meta.ManifestDigest != "sha256:manifest" || meta.Config == nil || meta.Config.Digest != "sha256:config" {
		t.Fatalf("manifest metadata = %+v", meta)
	}
	if len(meta.Layers) != 2 || meta.Layers[0].Digest != "sha256:layer1" || meta.TotalSizeBytes != 350 {
		t.Fatalf("layers = %+v total=%d", meta.Layers, meta.TotalSizeBytes)
	}
}

func TestInspectManifestReferenceSelectsPlatformFromIndex(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/acme/api/manifests/sha256:index":
			w.Header().Set("Docker-Content-Digest", "sha256:index")
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_, _ = w.Write([]byte(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.oci.image.index.v1+json",
				"manifests": [
					{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:arm64", "size": 10, "platform": {"os": "linux", "architecture": "arm64"}},
					{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:amd64", "size": 11, "platform": {"os": "linux", "architecture": "amd64"}}
				]
			}`))
		case "/v2/acme/api/manifests/sha256:amd64":
			w.Header().Set("Docker-Content-Digest", "sha256:amd64")
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write([]byte(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:config-amd64", "size": 42},
				"layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:amd64-layer", "size": 1000}]
			}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	ref := strings.TrimPrefix(srv.URL, "https://") + "/acme/api@sha256:index"
	meta, err := inspectManifestViaV2(context.Background(), srv.Client(), ref, "", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if meta.IndexDigest != "sha256:index" || meta.ManifestDigest != "sha256:amd64" || meta.SelectedPlatform != "linux/amd64" {
		t.Fatalf("selected metadata = %+v", meta)
	}
	if len(meta.Architectures) != 2 || len(meta.Layers) != 1 || meta.Layers[0].Digest != "sha256:amd64-layer" {
		t.Fatalf("architectures/layers = %+v / %+v", meta.Architectures, meta.Layers)
	}
}

func TestInspectManifestReferenceRequiresPlatformForMultiArchIndex(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:index")
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		_, _ = w.Write([]byte(`{
			"schemaVersion": 2,
			"mediaType": "application/vnd.oci.image.index.v1+json",
			"manifests": [
				{"digest": "sha256:arm64", "platform": {"os": "linux", "architecture": "arm64"}},
				{"digest": "sha256:amd64", "platform": {"os": "linux", "architecture": "amd64"}}
			]
		}`))
	}))
	defer srv.Close()

	ref := strings.TrimPrefix(srv.URL, "https://") + "/acme/api@sha256:index"
	_, err := inspectManifestViaV2(context.Background(), srv.Client(), ref, "", "")
	if err == nil || !strings.Contains(err.Error(), "platform required") {
		t.Fatalf("err = %v, want platform required", err)
	}
}

func TestInspectManifestReferenceUsesBearerChallenge(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"token":"registry-token"}`))
		case "/v2/acme/api/manifests/sha256:manifest":
			if r.Header.Get("Authorization") != "Bearer registry-token" {
				w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.test",scope="repository:acme/api:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Docker-Content-Digest", "sha256:manifest")
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:config", "size": 7},
				"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:layer", "size": 9}]
			}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	ref := strings.TrimPrefix(srv.URL, "https://") + "/acme/api@sha256:manifest"
	meta, err := inspectManifestViaV2(context.Background(), srv.Client(), ref, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Layers) != 1 || meta.Layers[0].Digest != "sha256:layer" {
		t.Fatalf("layers = %+v", meta.Layers)
	}
}
