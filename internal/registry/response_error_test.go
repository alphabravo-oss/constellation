package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const responseSecretCanary = "938475621938475621938475621"

type redactionFixture struct {
	fault   string
	payload string
	failure error
	bodies  []*trackedResponseBody
}

func (f *redactionFixture) response(r *http.Request) (*http.Response, error) {
	if f.fault == "transport" {
		return nil, &url.Error{Op: "Post", URL: "https://owned-user:" + responseSecretCanary + "@registry.invalid?token=" + responseSecretCanary, Err: f.failure}
	}
	status := http.StatusOK
	payload := f.payload
	if f.fault == "status" {
		status = http.StatusUnauthorized
		payload = responseSecretCanary
	}
	body := &trackedResponseBody{reader: strings.NewReader(payload)}
	if f.fault == "read" {
		body.readErr = f.failure
	}
	if f.fault == "close" {
		body.closeErr = f.failure
	}
	f.bodies = append(f.bodies, body)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: r}, nil
}

func (f *redactionFixture) client() *http.Client {
	return &http.Client{Transport: registryPageTransport(f.response)}
}

func assertCategoricalResponseError(t *testing.T, err error, f *redactionFixture) {
	t.Helper()
	if err == nil || strings.Contains(err.Error(), responseSecretCanary) || strings.Contains(err.Error(), "registry.invalid") {
		t.Fatal("untrusted response diagnostics escaped categorical error")
	}
	var safe *providerResponseError
	if !errors.As(err, &safe) || safe.stage == "" {
		t.Fatal("error lost its provider stage")
	}
	wantStatus := http.StatusOK
	if f.fault == "transport" {
		wantStatus = 0
	}
	if f.fault == "status" {
		wantStatus = http.StatusUnauthorized
	}
	if safe.status != wantStatus {
		t.Fatal("error lost actual HTTP status")
	}
	if f.fault == "read" || f.fault == "close" || f.fault == "transport" {
		if !errors.Is(err, f.failure) {
			t.Fatal("underlying failure no longer available through errors.Is")
		}
	}
	if f.fault == "json" {
		var typed *json.UnmarshalTypeError
		if !errors.As(err, &typed) {
			t.Fatal("typed JSON cause no longer available through errors.As")
		}
	}
	for _, body := range f.bodies {
		if body.closed != 1 {
			t.Fatal("response body not closed exactly once")
		}
	}
}

func checkCloudResponseRedaction(t *testing.T, c authReadCase, fault string) {
	t.Helper()
	payload := `{"access_token":"owned-token","refresh_token":"owned-refresh"}`
	if fault == "json" {
		payload = fmt.Sprintf(`{"access_token":%s,"refresh_token":%s}`, responseSecretCanary, responseSecretCanary)
	}
	fixture := &redactionFixture{fault: fault, payload: payload, failure: errors.New("owned response cause " + responseSecretCanary)}
	token, err := c.call(t, fixture.client())
	assertCategoricalResponseError(t, err, fixture)
	if token != "" {
		t.Fatal("failed response returned a token")
	}
}

func TestCloudAuthResponseErrorsDoNotRevealRemoteValues(t *testing.T) {
	for _, c := range authReadCases() {
		for _, fault := range []string{"status", "transport", "read", "close", "json"} {
			t.Run(c.name+"/"+fault, func(t *testing.T) { checkCloudResponseRedaction(t, c, fault) })
		}
	}
}

func cloudListConfig(client *http.Client) Config {
	return Config{Endpoint: "owned.registry.example", Token: "owned-token", Password: "owned-key", Account: "owned-account", HTTPClient: client}
}

func checkCloudListRedaction(t *testing.T, c primaryReadCase, fault string) {
	t.Helper()
	payload := c.payload
	if fault == "json" {
		switch c.name {
		case "artifact-registry":
			payload = `{"dockerImages":` + responseSecretCanary + `}`
		case "acr":
			payload = `{"repositories":` + responseSecretCanary + `}`
		case "ibmcloud":
			payload = `[{"RepoTags":` + responseSecretCanary + `}]`
		}
	}
	fixture := &redactionFixture{fault: fault, payload: payload, failure: errors.New("owned response cause " + responseSecretCanary)}
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		if c.name == "ibmcloud" && r.URL.Path == "/identity/token" {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"owned-token"}`)), Request: r}, nil
		}
		return fixture.response(r)
	})}
	rows, err := c.build(cloudListConfig(client)).ListImages(t.Context())
	assertCategoricalResponseError(t, err, fixture)
	if len(rows) != 0 {
		t.Fatal("failed response returned inventory rows")
	}
}

func TestCloudRegistryListErrorsDoNotRevealRemoteValues(t *testing.T) {
	for _, c := range primaryReadCases() {
		if c.name != "artifact-registry" && c.name != "acr" && c.name != "ibmcloud" {
			continue
		}
		for _, fault := range []string{"status", "transport", "read", "close", "json"} {
			t.Run(c.name+"/"+fault, func(t *testing.T) { checkCloudListRedaction(t, c, fault) })
		}
	}
}

func TestCloudTokenJSONErrorPreservesCauseWithoutEchoingNumber(t *testing.T) {
	payload := `{"access_token":"owned-token","expires_in":` + responseSecretCanary + `}`
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
	})}
	token, _, err := readOAuthToken(client, mustRedactionRequest(t), "gcp")
	if token != "" || err == nil || strings.Contains(err.Error(), responseSecretCanary) {
		t.Fatal("typed token response exposed a numeric secret canary")
	}
	var safe *providerResponseError
	var underlying *json.UnmarshalTypeError
	if !errors.As(err, &safe) || safe.status != http.StatusCreated || !errors.As(err, &underlying) {
		t.Fatal("token decode lost its status or typed cause")
	}
	if !strings.Contains(underlying.Error(), responseSecretCanary) {
		t.Fatal("fixture did not exercise an actually secret-bearing JSON error")
	}
}

func mustRedactionRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://token.invalid", nil)
	if err != nil {
		t.Fatal("build owned test request")
	}
	return r
}
