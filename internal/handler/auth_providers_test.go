package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/auth"
)

func TestAuthProviders(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    *Auth
		want string
	}{
		{"none", &Auth{}, `{"oidc":false,"saml":false}`},
		{"environment", &Auth{oidc: &auth.OIDCClient{}}, `{"oidc":true,"saml":false}`},
		{"live", &Auth{providers: auth.NewStaticProviderSet(&auth.OIDCClient{}, &auth.SAMLProvider{}, nil, nil)}, `{"oidc":true,"saml":true}`},
		{"disabled overrides environment", &Auth{oidc: &auth.OIDCClient{}, saml: &auth.SAMLProvider{}, ldap: &auth.LDAPProvider{}, providers: auth.NewProviderSet(nil)}, `{"oidc":false,"saml":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.a.Providers(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))
			if w.Code != http.StatusOK || w.Body.String() != tc.want+"\n" {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("provider availability must not be cached by proxies")
			}
			if tc.name == "disabled overrides environment" {
				if tc.a.providerLDAP() != nil {
					t.Fatal("disabled LDAP fell back to environment provider")
				}
				w = httptest.NewRecorder()
				tc.a.OIDCStart(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/start", nil))
				if w.Code != http.StatusNotImplemented {
					t.Fatalf("disabled OIDC start status=%d", w.Code)
				}
			}
		})
	}
}
