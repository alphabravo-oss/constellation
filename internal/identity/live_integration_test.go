//go:build integration

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// This tier deliberately uses a deployed OIDC provider. The regular integration
// target skips it; the live proof runner supplies its temporary credentials.
func TestLiveOIDCVerification(t *testing.T) {
	issuer := os.Getenv("IDENTITY_PROOF_ISSUER")
	if issuer == "" {
		t.Skip("live OIDC issuer not configured")
	}
	client := os.Getenv("IDENTITY_PROOF_CLIENT_ID")
	rp, err := NewRP(t.Context(), OIDCConfig{IssuerURL: issuer, ClientID: client, Audience: client, RedirectURL: os.Getenv("IDENTITY_PROOF_REDIRECT"), RolesClaim: os.Getenv("IDENTITY_PROOF_ROLES_CLAIM"), RoleMapping: map[string]string{"platform-admins": "GlobalAdmin"}})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"password"}, "client_id": {client}, "client_secret": {os.Getenv("IDENTITY_PROOF_CLIENT_SECRET")}, "username": {os.Getenv("IDENTITY_PROOF_USERNAME")}, "password": {os.Getenv("IDENTITY_PROOF_PASSWORD")}, "scope": {"openid email profile"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rp.meta.Token, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := rp.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var tokens struct {
		Access string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || tokens.Access == "" {
		t.Fatalf("real token endpoint status %d", res.StatusCode)
	}
	p, err := rp.Access.Verify(tokens.Access)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles) != 1 || p.Roles[0] != "GlobalAdmin" {
		t.Fatalf("mapped roles %v", p.Roles)
	}
	before := rp.Keys.Fetches.Load()
	for range 10000 {
		if _, err := rp.Access.Verify(tokens.Access); err != nil {
			t.Fatal(err)
		}
	}
	if rp.Keys.Fetches.Load() != before {
		t.Fatal("JWKS fetched on known token requests")
	}
	// A real failed HTTP refresh must preserve keys, including for an unseen token.
	rp.Keys.MinGap = 0
	original := rp.Keys.URL
	rp.Keys.URL = issuer + "/unavailable-jwks-proof"
	if err := rp.Keys.Refresh(context.Background()); err == nil {
		t.Fatal("expected failed refresh")
	}
	rp.Access.mu.Lock()
	clear(rp.Access.memo)
	rp.Access.mu.Unlock()
	if _, err := rp.Access.Verify(tokens.Access); err != nil {
		t.Fatalf("last-good signing keys lost: %v", err)
	}
	rp.Keys.URL = original
	wrongAudience := newVerifier(rp.Keys, rp.cfg, "foreign-audience", false)
	if _, err := wrongAudience.Verify(tokens.Access); err == nil {
		t.Fatal("foreign audience accepted")
	}
	wrongIssuer := rp.cfg
	wrongIssuer.IssuerURL = "https://foreign-issuer.invalid"
	if _, err := newVerifier(rp.Keys, wrongIssuer, client, false).Verify(tokens.Access); err == nil {
		t.Fatal("foreign issuer accepted")
	}
	// Missing, invalid and oversized tokens never become identities.
	for _, raw := range []string{"", tokens.Access + "tampered", strings.Repeat("x", 16385)} {
		if _, err := rp.Access.Verify(raw); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
	t.Logf("real provider: roles=%v; 10000 memo hits; failed JWKS HTTP refresh retained keys; audience/issuer/tamper rejected; token remaining=%s", p.Roles, time.Until(p.Expires).Round(time.Second))
}
