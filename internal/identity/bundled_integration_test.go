//go:build integration

package identity

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestBundledProviderDisableAndReenable(t *testing.T) {
	t.Parallel()
	s, admin, _ := testLocalService(t)
	s.bundled = &OIDCConfig{IssuerURL: "https://identity.example.test", ClientID: "product-client", ClientSecret: "create-only-secret", Audience: "product-client", RedirectURL: "https://product.example.test/api/v1/auth/oidc/callback", RolesClaim: "alphabravo_roles", RoleMapping: map[string]string{"analyst": "Analyst"}}
	s.bundled.defaults()
	update := func(oidc *OIDCConfig) {
		t.Helper()
		current, err := s.store.readSettings(t.Context(), s.enc)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(settingsRecord{Local: current.Local, OIDC: oidc, Revision: current.Revision})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("PUT", "/settings/identity", bytes.NewReader(body))
		req = req.WithContext(authctx.WithSubject(t.Context(), admin))
		out := httptest.NewRecorder()
		s.UpdateSettings(out, req)
		if out.Code != 200 {
			t.Fatalf("update %d %s", out.Code, out.Body.String())
		}
	}
	update(s.bundled)
	update(nil)
	out := httptest.NewRecorder()
	s.Settings(out, httptest.NewRequest("GET", "/settings/identity", nil))
	if strings.Contains(out.Body.String(), s.bundled.ClientSecret) {
		t.Fatal("bundled credential leaked to settings")
	}
	var settings struct {
		Bundled *OIDCConfig `json:"bundled_oidc"`
		OIDC    *OIDCConfig `json:"oidc"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.OIDC != nil || settings.Bundled == nil {
		t.Fatalf("disabled SSO lost bundled option: %s", out.Body.String())
	}
	update(settings.Bundled)
	restored, err := s.store.readSettings(t.Context(), s.enc)
	if err != nil {
		t.Fatal(err)
	}
	if restored.OIDC.ClientSecret != s.bundled.ClientSecret {
		t.Fatal("create-only bundled secret was lost across disable/re-enable")
	}
	external := *settings.Bundled
	external.IssuerURL = "https://customer.example.test"
	update(&external)
	saved, err := s.store.readSettings(t.Context(), s.enc)
	if err != nil {
		t.Fatal(err)
	}
	if saved.OIDC.ClientSecret != "" {
		t.Fatal("bundled credential crossed the external-provider trust boundary")
	}
}
