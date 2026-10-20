package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGHCRPrivateTagsAndDigestUseScopedToken(t *testing.T) {
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		body := ""
		h := make(http.Header)
		switch r.URL.Host + r.URL.Path {
		case "api.github.com/users/owner/packages":
			if r.Header.Get("Authorization") != "Bearer api-secret" {
				t.Fatal("missing API credential")
			}
			body = `[{"name":"private/app"}]`
		case "ghcr.io/token":
			user, pass, ok := r.BasicAuth()
			if !ok || user != "owner" || pass != "api-secret" {
				t.Fatal("missing exchange credentials")
			}
			if r.URL.Query().Get("scope") != "repository:owner/private/app:pull" {
				t.Fatal("wrong token scope")
			}
			body = `{"token":"scoped-registry-token"}`
		case "ghcr.io/v2/owner/private/app/tags/list":
			if r.Header.Get("Authorization") != "Bearer scoped-registry-token" {
				t.Fatal("API credential used as registry token")
			}
			body = `{"tags":["reviewed"]}`
		case "ghcr.io/v2/owner/private/app/manifests/reviewed":
			if r.Header.Get("Authorization") != "Bearer scoped-registry-token" {
				t.Fatal("digest lookup lacks scoped token")
			}
			h.Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
		default:
			t.Fatalf("unexpected endpoint %s", r.URL.Host+r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	g := NewGHCR(Config{Username: "owner", Token: "api-secret", HTTPClient: client})
	images, err := g.ListImages(t.Context())
	if err != nil || len(images) != 1 || len(images[0].Tags) != 1 || images[0].Tags[0] != "reviewed" {
		t.Fatalf("private tags: %v %v", images, err)
	}
	ref, err := g.ResolveDigest(t.Context(), images[0].Repository+":reviewed")
	if err != nil || !strings.Contains(ref, "@sha256:") {
		t.Fatalf("digest: %s %v", ref, err)
	}
	if _, err := g.ResolveDigest(t.Context(), "other.example/owner/app:reviewed"); err == nil {
		t.Fatal("foreign registry accepted")
	}
}

func TestGHCRTagFailureDoesNotInventLatest(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
				code := 200
				body := `{"token":"scoped"}`
				if r.URL.Host == "api.github.com" {
					body = `[{"name":"app"}]`
				}
				if strings.Contains(r.URL.Path, "tags/list") {
					code = status
					body = `{"tags":[]}`
				}
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			images, err := NewGHCR(Config{Username: "owner", Token: "secret", HTTPClient: client}).ListImages(t.Context())
			if len(images) != 0 {
				t.Fatal("invented image for absent tags")
			}
			if status == 403 && err == nil {
				t.Fatal("tag authorization failure hidden")
			}
			if status == 200 && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGHCRTokenExchangeDoesNotFollowRedirect(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "ghcr.io" {
			t.Fatal("credential sent outside GHCR")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.example/token"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	_, err := NewGHCR(Config{Username: "owner", Token: "secret-sentinel", HTTPClient: client}).pullToken(t.Context(), "ghcr.io/owner/app")
	if err == nil || calls != 1 {
		t.Fatalf("redirect was not rejected: calls=%d err=%v", calls, err)
	}
	if strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("token leaked")
	}
}

func TestGHCRMultiPackageLookupIsBoundedAndKeepsTagsAssociated(t *testing.T) {
	var active, peak atomic.Int32
	var ready sync.Once
	gate := make(chan struct{})
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.URL.Host == "api.github.com" {
			rows := []string{}
			for i := 0; i < 12; i++ {
				rows = append(rows, fmt.Sprintf(`{"name":"app%d"}`, i))
			}
			body = "[" + strings.Join(rows, ",") + "]"
		} else {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			if n >= 4 {
				ready.Do(func() { close(gate) })
			}
			select {
			case <-gate:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			if r.URL.Path == "/token" {
				body = `{"token":"scoped"}`
			} else {
				parts := strings.Split(r.URL.Path, "/")
				body = fmt.Sprintf(`{"tags":[%q]}`, parts[3]+"-tag")
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	images, err := NewGHCR(Config{Username: "owner", Token: "secret", HTTPClient: client}).ListImages(ctx)
	if err != nil || len(images) != 12 {
		t.Fatalf("discovery: count=%d error=%v", len(images), err)
	}
	if peak.Load() != 4 {
		t.Fatalf("unbounded or serial requests: %d", peak.Load())
	}
	for i, im := range images {
		if len(im.Tags) != 1 || im.Tags[0] != fmt.Sprintf("app%d-tag", i) {
			t.Fatalf("tags crossed repository boundary: %#v", im)
		}
	}
}
