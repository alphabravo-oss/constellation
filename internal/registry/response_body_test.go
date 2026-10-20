package registry

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type registryPageTransport func(*http.Request) (*http.Response, error)

func (f registryPageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type registryErrorBody struct {
	body              string
	readErr, closeErr error
	read              bool
	closed            int
}

func (b *registryErrorBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(p, b.body), b.readErr
}
func (b *registryErrorBody) Close() error { b.closed++; return b.closeErr }

func registryFailureClient(kind, operation string, failure error, bodies *[]*registryErrorBody) *http.Client {
	return &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		body := &registryErrorBody{body: "[]"}
		header := make(http.Header)
		switch {
		case operation == "second-page-read" && len(*bodies) == 0:
			if kind == "harbor" {
				body.body = `[{"name":"library"}]`
				header.Set("Link", `</projects?page=2>; rel="next"`)
			} else {
				body.body = `[{"id":1}]`
				header.Set("X-Next-Page", "2")
			}
		case operation == "close":
			body.closeErr = failure
		default:
			body.readErr = failure
		}
		*bodies = append(*bodies, body)
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: r}, nil
	})}
}

func listRegistryTestImages(t *testing.T, kind string, client *http.Client) ([]Image, error) {
	t.Helper()
	cfg := Config{Endpoint: "https://registry.example", Username: "user", Password: "password", Token: "token", HTTPClient: client}
	return listRegistryTestImagesWithConfig(t, kind, cfg)
}

func listRegistryTestImagesWithConfig(t *testing.T, kind string, cfg Config) ([]Image, error) {
	t.Helper()
	if kind == "harbor" {
		return NewHarbor(cfg).ListImages(t.Context())
	}
	return NewGitLab(cfg).ListImages(t.Context())
}

func assertRegistryBodiesClosed(t *testing.T, bodies []*registryErrorBody) {
	t.Helper()
	for _, body := range bodies {
		if body.closed != 1 {
			t.Fatal("response body not closed exactly once")
		}
	}
}

func TestRegistryPageFailuresNeverReturnSuccessfulInventory(t *testing.T) {
	failure := errors.New("owned test transport failure")
	for _, kind := range []string{"harbor", "gitlab"} {
		for _, operation := range []string{"read", "close", "second-page-read"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				var bodies []*registryErrorBody
				client := registryFailureClient(kind, operation, failure, &bodies)
				images, err := listRegistryTestImages(t, kind, client)
				if err == nil || !errors.Is(err, failure) || images != nil {
					t.Fatal("failed response returned a successful/partial inventory")
				}
				want := 1
				if operation == "second-page-read" {
					want = 2
				}
				if len(bodies) != want {
					t.Fatal("request continued beyond a failed page")
				}
				assertRegistryBodiesClosed(t, bodies)
			})
		}
	}
}

func TestRegistryPageRejectsValidJSONWithUnexpectedEOF(t *testing.T) {
	body := &registryErrorBody{body: "[]", readErr: io.ErrUnexpectedEOF}
	result, err := readRegistryPage(&http.Response{Body: body}, 1024)
	if !errors.Is(err, io.ErrUnexpectedEOF) || result != nil || body.closed != 1 {
		t.Fatal("complete-looking JSON masked failed HTTP body read")
	}
}

func TestRegistryPageEnforcesByteLimitAndCloses(t *testing.T) {
	body := io.NopCloser(strings.NewReader("[]      "))
	result, err := readRegistryPage(&http.Response{Body: body}, 4)
	if err == nil || result != nil {
		t.Fatal("oversized page accepted")
	}
}

func TestRegistryInvalidListURLReturnsErrorWithoutTransport(t *testing.T) {
	client := &http.Client{Transport: registryPageTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid endpoint reached transport")
		return nil, errors.New("unexpected transport")
	})}
	username, password, query := "owned-user-sentinel", "owned-password-sentinel", "owned-query-sentinel"
	endpoint := "https://" + username + ":" + password + "@registry.example/\n?credential=" + query
	cfg := Config{Endpoint: endpoint, Username: "user", Password: "password", Token: "token", HTTPClient: client}
	for _, kind := range []string{"harbor", "gitlab"} {
		_, err := listRegistryTestImagesWithConfig(t, kind, cfg)
		if err == nil {
			t.Fatal("invalid list URL accepted")
		}
		for _, sensitive := range []string{username, password, query, "registry.example", "credential="} {
			if strings.Contains(err.Error(), sensitive) {
				t.Fatal("request construction error revealed configured endpoint details")
			}
		}
	}
}
