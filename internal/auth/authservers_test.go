package auth

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"

	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

// newTestSealer builds a real AES-GCM cipher (no DB) so the seal/open helpers can be exercised
// end-to-end.
func newTestSealer(t *testing.T) Sealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := regsecrets.New(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	return c
}

// TestSealConfigSecrets_RoundTrip asserts all three secret fields seal at rest (prefixed, not
// plaintext), open back to the original, are idempotent (no double-seal), and that non-secret
// fields are untouched. This is the core of the H2 fix.
func TestSealConfigSecrets_RoundTrip(t *testing.T) {
	sealer := newTestSealer(t)
	cfg := ServerConfig{
		URL:          "ldap://x",            // non-secret, must be untouched
		BindPassword: "bind-pw",             // SECRET
		SPKeyPEM:     "-----BEGIN KEY-----", // SECRET
		ClientSecret: "client-sec",          // SECRET
	}
	sealed, err := sealConfigSecrets(cfg, sealer)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for name, v := range map[string]string{
		"bind_password": sealed.BindPassword, "sp_key_pem": sealed.SPKeyPEM, "client_secret": sealed.ClientSecret,
	} {
		if !strings.HasPrefix(v, secretEncPrefix) {
			t.Fatalf("%s not sealed: %q", name, v)
		}
	}
	if sealed.BindPassword == "bind-pw" || sealed.ClientSecret == "client-sec" || sealed.SPKeyPEM == "-----BEGIN KEY-----" {
		t.Fatal("a secret field remained cleartext after seal")
	}
	if sealed.URL != "ldap://x" {
		t.Fatalf("non-secret URL was altered: %q", sealed.URL)
	}

	// Idempotent: sealing an already-sealed config is a no-op (the UpdateAuthServer merge path).
	twice, err := sealConfigSecrets(sealed, sealer)
	if err != nil {
		t.Fatalf("seal twice: %v", err)
	}
	if twice.BindPassword != sealed.BindPassword || twice.ClientSecret != sealed.ClientSecret || twice.SPKeyPEM != sealed.SPKeyPEM {
		t.Fatal("double-seal changed an already-sealed value")
	}

	// Open recovers the original plaintext.
	opened, err := openConfigSecrets(sealed, sealer)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.BindPassword != "bind-pw" || opened.ClientSecret != "client-sec" || opened.SPKeyPEM != "-----BEGIN KEY-----" {
		t.Fatalf("open did not recover plaintext: %+v", opened)
	}
}

// TestOpenConfigSecrets_LegacyPlaintext confirms a pre-seal (plaintext) row opens unchanged, so
// existing rows keep working until their next write re-seals them (graceful migration).
func TestOpenConfigSecrets_LegacyPlaintext(t *testing.T) {
	cfg := ServerConfig{BindPassword: "legacy-plain"}
	opened, err := openConfigSecrets(cfg, newTestSealer(t))
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	if opened.BindPassword != "legacy-plain" {
		t.Fatalf("legacy plaintext mangled: %q", opened.BindPassword)
	}
}

// TestSealConfigSecrets_NilSealer confirms the no-KEK fallback stores plaintext (pre-H2 behavior)
// rather than failing.
func TestSealConfigSecrets_NilSealer(t *testing.T) {
	cfg := ServerConfig{BindPassword: "p"}
	out, err := sealConfigSecrets(cfg, nil)
	if err != nil || out.BindPassword != "p" {
		t.Fatalf("nil sealer should be a no-op: out=%q err=%v", out.BindPassword, err)
	}
}

func TestAuthServer_Validate(t *testing.T) {
	cases := []struct {
		name    string
		srv     AuthServer
		wantErr bool
	}{
		{"ldap ok", AuthServer{Type: ServerTypeLDAP, Name: "a", Config: ServerConfig{URL: "ldap://x", BaseDN: "dc=x", UserFilter: "(uid=%s)"}}, false},
		{"ldap missing %s", AuthServer{Type: ServerTypeLDAP, Name: "a", Config: ServerConfig{URL: "ldap://x", BaseDN: "dc=x", UserFilter: "(uid=foo)"}}, true},
		{"ldap missing url", AuthServer{Type: ServerTypeLDAP, Name: "a", Config: ServerConfig{BaseDN: "dc=x", UserFilter: "(uid=%s)"}}, true},
		{"saml ok", AuthServer{Type: ServerTypeSAML, Name: "a", Config: ServerConfig{IdPMetadataXML: "<x/>", ACSURL: "https://acs"}}, false},
		{"saml missing acs", AuthServer{Type: ServerTypeSAML, Name: "a", Config: ServerConfig{IdPMetadataXML: "<x/>"}}, true},
		{"oidc ok", AuthServer{Type: ServerTypeOIDC, Name: "a", Config: ServerConfig{IssuerURL: "https://i", ClientID: "c"}}, false},
		{"oidc missing client", AuthServer{Type: ServerTypeOIDC, Name: "a", Config: ServerConfig{IssuerURL: "https://i"}}, true},
		{"unknown type", AuthServer{Type: "kerberos", Name: "a"}, true},
		{"no name", AuthServer{Type: ServerTypeOIDC, Config: ServerConfig{IssuerURL: "https://i", ClientID: "c"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.srv.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthServer_RedactAndSecretPreserve(t *testing.T) {
	srv := AuthServer{
		Type: ServerTypeLDAP, Name: "a",
		Config: ServerConfig{URL: "ldap://x", BaseDN: "dc=x", UserFilter: "(uid=%s)", BindPassword: "hunter2"},
	}
	red := srv.Redacted()
	if red.Config.BindPassword == "hunter2" {
		t.Fatal("Redacted() leaked the bind password")
	}
	if red.Config.BindPassword != redactedMarker {
		t.Fatalf("Redacted() bind_password = %q, want marker", red.Config.BindPassword)
	}
	// An empty secret stays empty (so the UI can distinguish set/unset).
	unset := AuthServer{Type: ServerTypeOIDC, Config: ServerConfig{ClientSecret: ""}}
	if unset.Redacted().Config.ClientSecret != "" {
		t.Fatal("Redacted() must leave an unset secret empty")
	}

	// A redacted-echo update preserves the stored secret rather than wiping it.
	upd := srv
	upd.Config.BindPassword = redactedMarker
	upd.mergeSecrets(srv)
	if upd.Config.BindPassword != "hunter2" {
		t.Fatalf("mergeSecrets did not preserve secret on redacted echo: %q", upd.Config.BindPassword)
	}
	// A real new value overwrites.
	upd2 := srv
	upd2.Config.BindPassword = "rotated"
	upd2.mergeSecrets(srv)
	if upd2.Config.BindPassword != "rotated" {
		t.Fatalf("mergeSecrets clobbered an intentional rotation: %q", upd2.Config.BindPassword)
	}
}

// TestBuildProviders_AuthOrder confirms the lowest-auth_order ENABLED provider of each type wins,
// disabled rows are skipped, and a bad row is skipped (not fatal) leaving the others built.
func TestBuildProviders_AuthOrder(t *testing.T) {
	org := uuid.New()
	srvs := []AuthServer{
		{OrgID: org, Type: ServerTypeLDAP, Name: "high", Enabled: true, AuthOrder: 100,
			Config: ServerConfig{URL: "ldap://high", BaseDN: "dc=x", UserFilter: "(uid=%s)"}},
		{OrgID: org, Type: ServerTypeLDAP, Name: "low", Enabled: true, AuthOrder: 10,
			Config: ServerConfig{URL: "ldap://low", BaseDN: "dc=x", UserFilter: "(uid=%s)"}},
		{OrgID: org, Type: ServerTypeLDAP, Name: "lowest-disabled", Enabled: false, AuthOrder: 1,
			Config: ServerConfig{URL: "ldap://disabled", BaseDN: "dc=x", UserFilter: "(uid=%s)"}},
	}
	_, _, ldap, errs := BuildProviders(context.Background(), srvs, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected build errors: %v", errs)
	}
	if ldap == nil {
		t.Fatal("no LDAP provider built")
	}
	if ldap.URL() != "ldap://low" {
		t.Fatalf("active LDAP = %q, want ldap://low (auth_order 10, lowest ENABLED)", ldap.URL())
	}
}

// TestProviderSet_NilSafe confirms a nil *ProviderSet and an empty set return nil providers so
// callers degrade to "provider disabled" exactly as before B4.
func TestProviderSet_NilSafe(t *testing.T) {
	var ps *ProviderSet
	if ps.OIDC() != nil || ps.SAML() != nil || ps.LDAP() != nil || ps.Revision() != 0 {
		t.Fatal("nil *ProviderSet must be safe and return nil providers")
	}
	empty := NewProviderSet(nil)
	if empty.OIDC() != nil || empty.SAML() != nil || empty.LDAP() != nil {
		t.Fatal("empty ProviderSet must return nil providers")
	}
}
