package registry

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var errResponseTransportFailure = errors.New("owned response transport failure")

type trackedResponseBody struct {
	reader   io.Reader
	readErr  error
	closeErr error
	closed   int
}

func (b *trackedResponseBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if errors.Is(err, io.EOF) && b.readErr != nil {
		return n, b.readErr
	}
	return n, err
}

func (b *trackedResponseBody) Close() error {
	b.closed++
	return b.closeErr
}

func faultResponseBody(payload, fault string, limit int) *trackedResponseBody {
	body := &trackedResponseBody{reader: strings.NewReader(payload)}
	switch fault {
	case "read":
		body.readErr = errResponseTransportFailure
	case "close":
		body.closeErr = errResponseTransportFailure
	case "overflow":
		body.reader = strings.NewReader(payload + strings.Repeat(" ", limit+1))
	}
	return body
}

type primaryReadCase struct {
	name    string
	payload string
	limit   int
	build   func(Config) Connector
}

func primaryReadCases() []primaryReadCase {
	return []primaryReadCase{
		{"artifact-registry", `{"dockerImages":[]}`, 4 << 20, func(c Config) Connector { return NewArtifactRegistry(c) }},
		{"acr", `{"repositories":[]}`, 4 << 20, func(c Config) Connector { return NewACR(c) }},
		{"quay", `{"repositories":[]}`, 4 << 20, func(c Config) Connector { return NewQuay(c) }},
		{"jfrog", `[]`, 4 << 20, func(c Config) Connector { return NewJFrog(c) }},
		{"generic-v2", `{"repositories":[]}`, 8 << 20, func(c Config) Connector { return NewGenericV2(c) }},
		{"nexus", `{"repositories":[]}`, 8 << 20, func(c Config) Connector { return NewNexus(c) }},
		{"ghcr", `[]`, 4 << 20, func(c Config) Connector { return NewGHCR(c) }},
		{"openshift", `{"repositories":[]}`, 8 << 20, func(c Config) Connector { return NewOpenShift(c) }},
		{"ibmcloud", `[]`, 8 << 20, func(c Config) Connector { return NewIBMCloud(c) }},
		{"docker-hub", `{"results":[],"next":""}`, 4 << 20, func(c Config) Connector { return NewDockerHub(c) }},
	}
}

func assertResponseFailed(t *testing.T, err error, body *trackedResponseBody, fault string) {
	t.Helper()
	if err == nil {
		t.Fatal("failed or oversized response was accepted")
	}
	if fault != "overflow" && !errors.Is(err, errResponseTransportFailure) {
		t.Fatal("response failure cause was not preserved")
	}
	if body.closed != 1 {
		t.Fatalf("response closed %d times, want exactly once", body.closed)
	}
}

func checkPrimaryReadFailure(t *testing.T, test primaryReadCase, fault string) {
	t.Helper()
	body := faultResponseBody(test.payload, fault, test.limit)
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var responseBody io.ReadCloser = body
		if test.name == "ibmcloud" && r.URL.Path == "/identity/token" {
			responseBody = io.NopCloser(strings.NewReader(`{"access_token":"owned-token"}`))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: responseBody, Request: r}, nil
	})}
	cfg := Config{Endpoint: "registry.example", Username: "owned-user", Password: "owned-password", Token: "owned-token", Account: "owned-account", HTTPClient: client}
	images, err := test.build(cfg).ListImages(t.Context())
	assertResponseFailed(t, err, body, fault)
	if len(images) != 0 {
		t.Fatal("failed response returned inventory rows")
	}
	want := 1
	if test.name == "ibmcloud" {
		want = 2
	}
	if calls != want {
		t.Fatal("enumeration continued after the failed response")
	}
}

func TestRemainingPrimaryRegistryResponsesPropagateFailure(t *testing.T) {
	for _, test := range primaryReadCases() {
		for _, fault := range []string{"read", "close", "overflow"} {
			t.Run(test.name+"/"+fault, func(t *testing.T) { checkPrimaryReadFailure(t, test, fault) })
		}
	}
}

type authReadCase struct {
	name string
	call func(*testing.T, *http.Client) (string, error)
}

func authReadCases() []authReadCase {
	return []authReadCase{
		{"gcp", func(t *testing.T, c *http.Client) (string, error) {
			token, _, err := exchangeGCPAssertion(t.Context(), c, "https://token.example", "owned-assertion")
			return token, err
		}},
		{"azure-client", func(t *testing.T, c *http.Client) (string, error) {
			token, _, err := azureClientCredentialsToken(t.Context(), c, "owned-tenant", "owned-client", "owned-secret", "owned-scope")
			return token, err
		}},
		{"azure-imds", func(t *testing.T, c *http.Client) (string, error) {
			token, _, err := azureIMDSToken(t.Context(), c, "owned-resource", "owned-client")
			return token, err
		}},
		{"acr-refresh", func(t *testing.T, c *http.Client) (string, error) {
			return acrExchangeRefreshToken(t.Context(), c, "registry.example", "owned-tenant", "owned-token")
		}},
		{"acr-access", func(t *testing.T, c *http.Client) (string, error) {
			token, _, err := acrExchangeAccessToken(t.Context(), c, "registry.example", "owned-refresh", "owned-scope")
			return token, err
		}},
		{"ibm", func(t *testing.T, c *http.Client) (string, error) {
			return NewIBMCloud(Config{Password: "owned-key", HTTPClient: c}).acquireToken(t.Context())
		}},
	}
}

func checkAuthReadFailure(t *testing.T, test authReadCase, fault string) {
	t.Helper()
	body := faultResponseBody(`{"access_token":"owned-token","refresh_token":"owned-refresh","expires_in":3600}`, fault, 1<<20)
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
	})}
	token, err := test.call(t, client)
	assertResponseFailed(t, err, body, fault)
	if token != "" || calls != 1 {
		t.Fatal("failed authentication response returned a token or retried")
	}
}

func TestRegistryAuthResponsesPropagateFailure(t *testing.T) {
	for _, test := range authReadCases() {
		for _, fault := range []string{"read", "close", "overflow"} {
			t.Run(test.name+"/"+fault, func(t *testing.T) { checkAuthReadFailure(t, test, fault) })
		}
	}
}
