package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func ownedCredentialScope(t *testing.T) string {
	t.Helper()
	return t.Name() + "/" + uuid.NewString()
}

func credentialResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func replaceGCPPrivateKey(t *testing.T, raw, replacement string) string {
	t.Helper()
	var key map[string]string
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		t.Fatal("owned service-account fixture did not decode")
	}
	key["private_key"] = replacement
	body, err := json.Marshal(key)
	if err != nil {
		t.Fatal("owned service-account fixture did not encode")
	}
	return string(body)
}

func checkGCPCredentialBoundary(t *testing.T, change string) {
	t.Helper()
	email := ownedCredentialScope(t) + "@example.invalid"
	raw, _ := testSAKey(t, email, "https://token.example/owned")
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return credentialResponse(r, http.StatusOK, fmt.Sprintf(`{"access_token":"owned-token-%d","expires_in":3600}`, calls)), nil
	})}
	cfg := Config{CredentialCacheScope: ownedCredentialScope(t), ServiceAccountJSON: raw}
	first, err := cfg.gcpAccessToken(t.Context(), client)
	if err != nil || first == "" || calls != 1 {
		t.Fatal("initial service-account mint failed")
	}
	changed := cfg
	switch change {
	case "invalid-key":
		changed.ServiceAccountJSON = replaceGCPPrivateKey(t, raw, "invalid-owned-PEM")
	case "rotated-key":
		changed.ServiceAccountJSON, _ = testSAKey(t, email, "https://token.example/owned")
	case "sibling-scope":
		changed.CredentialCacheScope = ownedCredentialScope(t)
	case "missing-scope":
		changed.CredentialCacheScope = ""
	}
	second, err := changed.gcpAccessToken(t.Context(), client)
	if change == "invalid-key" {
		if err == nil || second != "" || calls != 1 {
			t.Fatal("invalid key borrowed a previously authenticated token")
		}
		return
	}
	if err != nil || second == "" || second == first || calls != 2 {
		t.Fatal("changed credential/scope borrowed a cached token instead of minting")
	}
}

func TestGCPCacheRequiresActualCredentialAndOwner(t *testing.T) {
	for _, change := range []string{"invalid-key", "rotated-key", "sibling-scope", "missing-scope"} {
		t.Run(change, func(t *testing.T) { checkGCPCredentialBoundary(t, change) })
	}
}

func TestGCPMissingScopeRemainsFunctionalWithoutCaching(t *testing.T) {
	raw, _ := testSAKey(t, ownedCredentialScope(t)+"@example.invalid", "https://token.example/owned")
	calls := 0
	client := &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return credentialResponse(r, http.StatusOK, `{"access_token":"owned-token","expires_in":3600}`), nil
	})}
	cfg := Config{ServiceAccountJSON: raw}
	for range 2 {
		if token, err := cfg.gcpAccessToken(t.Context(), client); err != nil || token == "" {
			t.Fatal("unscoped credential stopped authenticating")
		}
	}
	if calls != 2 {
		t.Fatal("unscoped service-account credential used the global cache")
	}
}

type azureCredentialFixture struct {
	calls        int
	principal    string
	failIMDS     bool
	staticSecret string
}

func (f *azureCredentialFixture) client(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: registryPageTransport(func(r *http.Request) (*http.Response, error) {
		f.calls++
		if r.URL.Path == "/metadata/identity/oauth2/token" {
			if f.failIMDS {
				return credentialResponse(r, http.StatusUnauthorized, `{}`), nil
			}
			return credentialResponse(r, http.StatusOK, `{"access_token":"`+f.principal+`","expires_in":3600}`), nil
		}
		return f.oauthResponse(t, r), nil
	})}
}

func (f *azureCredentialFixture) oauthResponse(t *testing.T, r *http.Request) *http.Response {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		t.Fatal("owned auth request could not be read")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal("owned auth request did not encode a form")
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		expected := f.staticSecret
		if expected == "" {
			expected = "owned-current-secret"
		}
		if form.Get("client_secret") != expected {
			return credentialResponse(r, http.StatusUnauthorized, `{}`)
		}
		return credentialResponse(r, http.StatusOK, `{"access_token":"owned-aad","expires_in":3600}`)
	case r.URL.Path == "/oauth2/exchange":
		return credentialResponse(r, http.StatusOK, `{"refresh_token":"owned-refresh"}`)
	case r.URL.Path == "/oauth2/token":
		return credentialResponse(r, http.StatusOK, fmt.Sprintf(`{"access_token":"owned-acr-%d","expires_in":3600}`, f.calls))
	default:
		t.Fatal("unexpected auth endpoint")
		return credentialResponse(r, http.StatusNotFound, `{}`)
	}
}

func azureScopedConfig(t *testing.T, managed bool) Config {
	t.Helper()
	cfg := Config{CredentialCacheScope: ownedCredentialScope(t), TenantID: "owned-tenant", ClientID: "owned-client", ClientSecret: "owned-current-secret"}
	if managed {
		cfg.AuthKind = "azure-managed-id"
		cfg.ClientSecret = ""
	}
	return cfg
}

func checkACRStaticCredentialBoundary(t *testing.T, change string) {
	t.Helper()
	isolateTokenCache(t)
	fixture := &azureCredentialFixture{}
	client := fixture.client(t)
	cfg := azureScopedConfig(t, false)
	first, err := cfg.acrAccessToken(t.Context(), client, "owned.azurecr.io")
	if err != nil || first == "" || fixture.calls != 3 {
		t.Fatal("initial ACR mint failed")
	}
	changed := cfg
	switch change {
	case "wrong-secret":
		changed.ClientSecret = "owned-wrong-secret"
	case "rotated-secret":
		changed.ClientSecret = "owned-rotated-secret"
		fixture.staticSecret = changed.ClientSecret
	case "sibling-scope":
		changed.CredentialCacheScope = ownedCredentialScope(t)
	case "missing-scope":
		changed.CredentialCacheScope = ""
	}
	second, err := changed.acrAccessToken(t.Context(), client, "owned.azurecr.io")
	if change == "wrong-secret" {
		if err == nil || second != "" || fixture.calls != 4 {
			t.Fatal("wrong AAD secret borrowed a cached ACR credential")
		}
		return
	}
	if err != nil || second == first || fixture.calls != 6 {
		t.Fatal("different or unavailable owner scope borrowed an ACR credential")
	}
}

func TestACRStaticCacheRequiresActualCredentialAndOwner(t *testing.T) {
	for _, change := range []string{"wrong-secret", "rotated-secret", "sibling-scope", "missing-scope"} {
		t.Run(change, func(t *testing.T) { checkACRStaticCredentialBoundary(t, change) })
	}
}

func TestACRStaticSameCredentialStillCaches(t *testing.T) {
	isolateTokenCache(t)
	fixture := &azureCredentialFixture{}
	client := fixture.client(t)
	cfg := azureScopedConfig(t, false)
	for range 2 {
		if token, err := cfg.acrAccessToken(t.Context(), client, "owned.azurecr.io"); err != nil || token == "" {
			t.Fatal("valid scoped ACR credential failed")
		}
	}
	if fixture.calls != 3 {
		t.Fatal("same scoped ACR credential did not reuse cached mint")
	}
}

func checkACRManagedCredentialBoundary(t *testing.T, change string) {
	t.Helper()
	isolateTokenCache(t)
	fixture := &azureCredentialFixture{principal: "owned-principal-one"}
	client := fixture.client(t)
	cfg := azureScopedConfig(t, true)
	first, err := cfg.acrAccessToken(t.Context(), client, "owned.azurecr.io")
	if err != nil || first == "" || fixture.calls != 3 {
		t.Fatal("initial managed identity mint failed")
	}
	wantCalls := 6
	switch change {
	case "same-principal":
		wantCalls = 4
	case "rotated-principal":
		fixture.principal = "owned-principal-two"
	case "failed-resolution":
		fixture.failIMDS = true
		wantCalls = 4
	case "sibling-scope":
		cfg.CredentialCacheScope = ownedCredentialScope(t)
	case "missing-scope":
		cfg.CredentialCacheScope = ""
	}
	second, err := cfg.acrAccessToken(t.Context(), client, "owned.azurecr.io")
	if change == "failed-resolution" {
		if err == nil || second != "" || fixture.calls != wantCalls {
			t.Fatal("failed current-principal acquisition borrowed a cached managed token")
		}
		return
	}
	if err != nil || second == "" || fixture.calls != wantCalls {
		t.Fatal("managed cache skipped principal acquisition or failed its valid scoped flow")
	}
	if (second == first) != (change == "same-principal") {
		t.Fatal("managed token cache did not bind the effective principal and owner")
	}
}

func TestACRManagedCacheResolvesEffectiveIdentityBeforeLookup(t *testing.T) {
	for _, change := range []string{"same-principal", "rotated-principal", "failed-resolution", "sibling-scope", "missing-scope"} {
		t.Run(change, func(t *testing.T) { checkACRManagedCredentialBoundary(t, change) })
	}
}
