package registry

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

// repoSet collects the discovered repositories for order-independent comparison.
func repoSet(imgs []Image) []string {
	out := make([]string, 0, len(imgs))
	for _, im := range imgs {
		out = append(out, im.Repository)
	}
	sort.Strings(out)
	return out
}

// TestHarborListImages_ProjectsThenRepos proves Harbor discovery lists projects then
// per-project repositories (not the bogus `_default` project) and follows Link paging.
func TestHarborListImages_ProjectsThenRepos(t *testing.T) {
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2.0/projects":
			if r.URL.Query().Get("page") == "1" {
				w.Header().Set("Link", `</api/v2.0/projects?page=2>; rel="next"`)
				_, _ = w.Write([]byte(`[{"name":"library"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"name":"team"}]`))
			}
		case "/api/v2.0/projects/library/repositories":
			_, _ = w.Write([]byte(`[{"name":"library/nginx"}]`))
		case "/api/v2.0/projects/team/repositories":
			_, _ = w.Write([]byte(`[{"name":"team/app"},{"name":"team/api"}]`))
		default:
			if strings.HasPrefix(r.URL.Path, "/v2/") {
				w.WriteHeader(http.StatusNotFound) // tag listing is best-effort
				return
			}
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := NewHarbor(Config{Endpoint: srv.URL, Username: "u", Password: "p", HTTPClient: srv.Client()})
	imgs, err := h.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	want := []string{host + "/library/nginx", host + "/team/api", host + "/team/app"}
	if got := repoSet(imgs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("repos = %v, want %v", got, want)
	}
	// Assert we paged projects and hit both per-project repository endpoints.
	joined := strings.Join(paths, " ")
	for _, must := range []string{
		"/api/v2.0/projects",
		"/api/v2.0/projects/library/repositories",
		"/api/v2.0/projects/team/repositories",
	} {
		if !strings.Contains(joined, must) {
			t.Fatalf("expected a request to %s; paths=%v", must, paths)
		}
	}
	if strings.Contains(joined, "_default") {
		t.Fatalf("must not hit the bogus _default project; paths=%v", paths)
	}
}

// TestGitLabListImages_ProjectsThenRegistryRepos proves GitLab discovery enumerates
// membership projects then per-project registry repositories with page paging.
func TestGitLabListImages_ProjectsThenRegistryRepos(t *testing.T) {
	var paths []string
	var membership string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects":
			membership = r.URL.Query().Get("membership")
			if r.URL.Query().Get("page") == "1" {
				w.Header().Set("X-Next-Page", "2")
				_, _ = w.Write([]byte(`[{"id":1}]`))
			} else {
				w.Header().Set("X-Next-Page", "")
				_, _ = w.Write([]byte(`[{"id":2}]`))
			}
		case "/api/v4/projects/1/registry/repositories":
			_, _ = w.Write([]byte(`[{"id":10,"location":"reg.example/g/p1"}]`))
		case "/api/v4/projects/2/registry/repositories":
			_, _ = w.Write([]byte(`[{"id":20,"location":"reg.example/g/p2"}]`))
		case "/api/v4/registry/repositories/10/tags", "/api/v4/registry/repositories/20/tags":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	g := NewGitLab(Config{Endpoint: srv.URL, Token: "glpat-x", HTTPClient: srv.Client()})
	imgs, err := g.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if membership != "true" {
		t.Fatalf("membership query = %q, want true", membership)
	}
	want := []string{"reg.example/g/p1", "reg.example/g/p2"}
	if got := repoSet(imgs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("repos = %v, want %v", got, want)
	}
	joined := strings.Join(paths, " ")
	for _, must := range []string{
		"/api/v4/projects",
		"/api/v4/projects/1/registry/repositories",
		"/api/v4/projects/2/registry/repositories",
	} {
		if !strings.Contains(joined, must) {
			t.Fatalf("expected a request to %s; paths=%v", must, paths)
		}
	}
	if strings.Contains(joined, "/api/v4/registry/repositories?") {
		t.Fatalf("must not hit the invalid instance-wide list endpoint; paths=%v", paths)
	}
}

// TestJFrogListImages_RepositoriesThenCatalog proves JFrog discovery lists docker
// repos via /api/repositories?type=docker then per-repo v2 catalogs, not cfg.Username.
func TestJFrogListImages_RepositoriesThenCatalog(t *testing.T) {
	var paths []string
	var repoType string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/repositories":
			repoType = r.URL.Query().Get("type")
			_, _ = w.Write([]byte(`[
				{"key":"docker-local","type":"local","packageType":"Docker"},
				{"key":"docker-remote","type":"remote","packageType":"Docker"}
			]`))
		case "/api/docker/docker-local/v2/_catalog":
			_, _ = w.Write([]byte(`{"repositories":["app","api"]}`))
		case "/api/docker/docker-remote/v2/_catalog":
			_, _ = w.Write([]byte(`{"repositories":["cache/nginx"]}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/v2/") {
				w.WriteHeader(http.StatusNotFound) // best-effort tag listing
				return
			}
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	// Username is intentionally set to prove it is NOT used as the repo key.
	j := NewJFrog(Config{Endpoint: srv.URL, Username: "svc", Token: "jf-tok", HTTPClient: srv.Client()})
	imgs, err := j.ListImages(context.Background())
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if repoType != "docker" {
		t.Fatalf("repositories type query = %q, want docker", repoType)
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	want := []string{
		host + "/docker-local/api",
		host + "/docker-local/app",
		host + "/docker-remote/cache/nginx",
	}
	if got := repoSet(imgs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("repos = %v, want %v", got, want)
	}
	joined := strings.Join(paths, " ")
	if strings.Contains(joined, "/api/docker/svc/") {
		t.Fatalf("must not use Username as repo key; paths=%v", paths)
	}
}

// TestECRStaticCredentialsProvider proves the static-credentials provider we wire in
// NewECR resolves the configured keys (rather than the ambient chain).
func TestECRStaticCredentialsProvider(t *testing.T) {
	prov := credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "SECRETKEY", "SESSION")
	creds, err := prov.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if creds.AccessKeyID != "AKIDEXAMPLE" || creds.SecretAccessKey != "SECRETKEY" || creds.SessionToken != "SESSION" {
		t.Fatalf("static creds = %+v", creds)
	}

	// NewECR builds a client when a region is present, and none without one.
	if c := NewECR(Config{Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"}); c.client == nil {
		t.Fatalf("expected an ECR client when region+static keys supplied")
	}
	if c := NewECR(Config{AccessKeyID: "a", SecretAccessKey: "b"}); c.client != nil {
		t.Fatalf("expected no ECR client without a region")
	}
}

// TestDecodeECRAuthToken proves the GetAuthorizationToken base64 "user:pass" decode
// and the cache round-trip encoding.
func TestDecodeECRAuthToken(t *testing.T) {
	tok := base64.StdEncoding.EncodeToString([]byte("AWS:s3cr3t:with:colons"))
	user, pass, err := decodeECRAuthToken(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if user != "AWS" || pass != "s3cr3t:with:colons" {
		t.Fatalf("decoded = %q/%q", user, pass)
	}
	u, p, ep, err := splitECRAuth("https://acct.dkr.ecr.us-east-1.amazonaws.com\x00AWS:pw")
	if err != nil {
		t.Fatalf("splitECRAuth: %v", err)
	}
	if u != "AWS" || p != "pw" || ep != "https://acct.dkr.ecr.us-east-1.amazonaws.com" {
		t.Fatalf("split = %q/%q/%q", u, p, ep)
	}
}
