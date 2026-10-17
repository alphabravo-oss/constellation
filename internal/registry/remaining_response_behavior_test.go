package registry

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGitLabTagResponseFailureRemainsBestEffort(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			body := faultResponseBody(`[{"name":"must-not-use"}]`, fault, 4<<20)
			client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
			})}
			tags := NewGitLab(Config{Token: "owned-token", HTTPClient: client}).repoTags(t.Context(), "https://registry.example", 1)
			if len(tags) != 0 || body.closed != 1 {
				t.Fatal("failed tag response did not retain the no-tag fallback")
			}
		})
	}
}

func checkJFrogRepoFallback(t *testing.T, fault string) {
	t.Helper()
	body := faultResponseBody(`{"repositories":["must-not-use"]}`, fault, 4<<20)
	healthyRead := false
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		status := http.StatusOK
		var responseBody io.ReadCloser
		switch r.URL.Path {
		case "/api/repositories":
			responseBody = io.NopCloser(strings.NewReader(`[{"key":"broken"},{"key":"healthy"}]`))
		case "/api/docker/broken/v2/_catalog":
			responseBody = body
		case "/api/docker/healthy/v2/_catalog":
			healthyRead = true
			responseBody = io.NopCloser(strings.NewReader(`{"repositories":["app"]}`))
		default:
			status = http.StatusNotFound // Existing best-effort tag lookup.
			responseBody = io.NopCloser(strings.NewReader(""))
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: responseBody, Request: r}, nil
	})}
	images, err := NewJFrog(Config{Endpoint: "https://registry.example", Token: "owned-token", HTTPClient: client}).ListImages(t.Context())
	if err != nil || !healthyRead || body.closed != 1 || len(images) != 1 || images[0].Repository != "registry.example/healthy/app" {
		t.Fatal("one failed JFrog repository prevented the healthy-repository fallback or borrowed failed rows")
	}
}

func TestJFrogFailedRepositoryStillAllowsHealthyRepositories(t *testing.T) {
	for _, fault := range []string{"read", "close", "overflow"} {
		t.Run(fault, func(t *testing.T) { checkJFrogRepoFallback(t, fault) })
	}
}

func assertCategoricalEndpointError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("malformed endpoint accepted")
	}
	for _, value := range []string{"owned-user-sentinel", "owned-password-sentinel", "owned-query-sentinel", "registry.example", "credential="} {
		if strings.Contains(err.Error(), value) {
			t.Fatal("endpoint construction error revealed configured endpoint details")
		}
	}
}

func rejectingRegistryTransport(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: registryPageTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("malformed endpoint reached transport")
		return nil, io.ErrUnexpectedEOF
	})}
}

func malformedRegistryEndpoint() string {
	return "owned-user-sentinel:owned-password-sentinel@registry.example/\n?credential=owned-query-sentinel"
}

func TestAdditionalRegistryInvalidEndpointsNeverPanicOrLeak(t *testing.T) {
	for _, test := range primaryReadCases() {
		if test.name == "docker-hub" || test.name == "ibmcloud" {
			continue // Escaped username; IBM needs a successful separate token request first.
		}
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{Endpoint: malformedRegistryEndpoint(), Username: "owned-user", Password: "owned-password", Token: "owned-token", HTTPClient: rejectingRegistryTransport(t)}
			if test.name == "ghcr" {
				cfg.Username = cfg.Endpoint
			}
			_, err := test.build(cfg).ListImages(t.Context())
			assertCategoricalEndpointError(t, err)
		})
	}
}

func TestAuthMalformedEndpointErrorsNeverLeak(t *testing.T) {
	client := rejectingRegistryTransport(t)
	endpoint := "https://" + malformedRegistryEndpoint()
	_, _, err := exchangeGCPAssertion(t.Context(), client, endpoint, "owned-assertion")
	assertCategoricalEndpointError(t, err)
	_, err = acrExchangeRefreshToken(t.Context(), client, malformedRegistryEndpoint(), "owned-tenant", "owned-token")
	assertCategoricalEndpointError(t, err)
	_, _, err = acrExchangeAccessToken(t.Context(), client, malformedRegistryEndpoint(), "owned-refresh", "owned-scope")
	assertCategoricalEndpointError(t, err)
	_, err = NewIBMCloud(Config{TokenURL: endpoint, Password: "owned-key", HTTPClient: client}).acquireToken(t.Context())
	assertCategoricalEndpointError(t, err)
}

func checkFailedCloudTokenNotCached(t *testing.T, kind, fault string) {
	t.Helper()
	calls := 0
	var bodies []*trackedResponseBody
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body := faultResponseBody(`{"access_token":"must-not-cache","expires_in":3600}`, fault, 1<<20)
		bodies = append(bodies, body)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
	})}
	cfg := Config{ClientID: "owned-client-" + fault, ClientSecret: "owned-secret", TenantID: "owned-tenant"}
	if kind == "gcp" {
		cfg.ServiceAccountJSON, _ = testSAKey(t, "owned-"+fault+"@example.invalid", "https://token.example/"+fault)
	}
	for range 2 {
		var token string
		var err error
		if kind == "gcp" {
			token, err = cfg.gcpAccessToken(t.Context(), client)
		} else {
			token, err = cfg.acrAccessToken(t.Context(), client, "registry.example")
		}
		if token != "" || err == nil {
			t.Fatal("failed response returned or cached a token")
		}
	}
	if calls != 2 || len(bodies) != 2 || bodies[0].closed != 1 || bodies[1].closed != 1 {
		t.Fatal("failed token was cached or response body was not closed exactly once")
	}
}

func TestFailedCloudTokenResponsesNeverPopulateCache(t *testing.T) {
	for _, kind := range []string{"gcp", "azure"} {
		for _, fault := range []string{"read", "close", "overflow"} {
			t.Run(kind+"/"+fault, func(t *testing.T) { checkFailedCloudTokenNotCached(t, kind, fault) })
		}
	}
}
