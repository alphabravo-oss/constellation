package gitops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectorReady(t *testing.T) {
	base := ConnectorConfig{Branch: "main", FilePath: "c.yaml", PAT: "x"}
	gh := base
	gh.Provider = ProviderGitHub
	gh.GitHubOwner, gh.GitHubRepo = "o", "r"
	if !gh.ready() {
		t.Fatal("github should be ready")
	}
	ghBad := gh
	ghBad.GitHubRepo = ""
	if ghBad.ready() {
		t.Fatal("github missing repo should not be ready")
	}
	az := base
	az.Provider = ProviderAzureDevops
	az.AzureOrg, az.AzureProject, az.AzureRepo = "o", "p", "r"
	if !az.ready() {
		t.Fatal("azure should be ready")
	}
	noPAT := gh
	noPAT.PAT = ""
	if noPAT.ready() {
		t.Fatal("missing PAT should not be ready")
	}
}

func TestPushConfigDisabled(t *testing.T) {
	err := PushConfig(context.Background(), ConnectorConfig{Provider: ProviderGitHub}, []byte("x"), "m")
	if err != ErrConnectorDisabled {
		t.Fatalf("want ErrConnectorDisabled, got %v", err)
	}
}

// TestPushGitHubCreate exercises the create path (GET 404 -> PUT 201) against a stub.
func TestPushGitHubCreate(t *testing.T) {
	var gotPut bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound) // file absent
		case http.MethodPut:
			gotPut = true
			if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
				t.Errorf("bad auth header %q", auth)
			}
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()

	// Point the connector at the stub by overriding the content URL via a RoundTripper
	// that rewrites api.github.com to the test server.
	cfg := ConnectorConfig{
		Provider: ProviderGitHub, GitHubOwner: "o", GitHubRepo: "r",
		Branch: "main", FilePath: "c.yaml", PAT: "tok",
		CommitterName: "bot", CommitterEmail: "b@x",
		Client: &http.Client{Transport: rewriteTransport{target: srv.URL}},
	}
	if err := PushConfig(context.Background(), cfg, []byte("hello: world\n"), "msg"); err != nil {
		t.Fatalf("push: %v", err)
	}
	if !gotPut {
		t.Fatal("expected a PUT to create the file")
	}
}

// TestPushGitHubNoopWhenIdentical verifies the blob-SHA short-circuit: when the remote
// file already has the identical content, no PUT is issued.
func TestPushGitHubNoopWhenIdentical(t *testing.T) {
	content := []byte("same: content\n")
	sha := gitBlobSHA1(content)
	var putCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sha":"` + sha + `"}`))
			return
		}
		putCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := ConnectorConfig{
		Provider: ProviderGitHub, GitHubOwner: "o", GitHubRepo: "r",
		Branch: "main", FilePath: "c.yaml", PAT: "tok",
		Client: &http.Client{Transport: rewriteTransport{target: srv.URL}},
	}
	if err := PushConfig(context.Background(), cfg, content, "msg"); err != nil {
		t.Fatalf("push: %v", err)
	}
	if putCount != 0 {
		t.Fatalf("expected no PUT for identical content, got %d", putCount)
	}
}

// rewriteTransport redirects any request to the test server, preserving path+query.
type rewriteTransport struct{ target string }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := rt.target + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	out.Header = req.Header
	return http.DefaultTransport.RoundTrip(out)
}

func TestAzureRefBranch(t *testing.T) {
	r := azureRef{Name: "refs/heads/main"}
	if r.branch() != "main" {
		t.Fatalf("branch=%q", r.branch())
	}
	if (azureRef{Name: "main"}).branch() != "main" {
		t.Fatal("bare name should return itself")
	}
	if !strings.Contains(azureURL(ConnectorConfig{AzureOrg: "o", AzureProject: "p", AzureRepo: "r"}, "pushes"), "dev.azure.com/o/p/_apis/git/repositories/r/pushes") {
		t.Fatal("azure url malformed")
	}
}
