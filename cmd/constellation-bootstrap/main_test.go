package main

import (
	"testing"

	"github.com/google/uuid"
)

// TestParseAuthProviders proves the declarative-provider YAML (B4) maps onto a valid
// auth.AuthServer — including that secret-bearing fields pass through and role_mapping is
// honoured — so the bootstrap seed produces exactly what the API CRUD would.
func TestParseAuthProviders(t *testing.T) {
	raw := []byte(`
- type: oidc
  name: corp-okta
  enabled: true
  auth_order: 100
  config:
    issuer_url: https://okta.example.com
    client_id: abc
    client_secret: shh
    redirect_url: https://constellation.example.com/auth/oidc/callback
    scopes: [openid, email, profile]
  role_mapping:
    rules:
      "group:platform-admins": GlobalAdmin
    default: Viewer
- type: ldap
  name: corp-ldap
  enabled: true
  config:
    url: ldaps://ldap.example.com:636
    base_dn: ou=people,dc=example,dc=com
    user_filter: (uid=%s)
    bind_password: bindpw
`)
	specs, err := parseAuthProviders(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 providers, got %d", len(specs))
	}

	oidc := specs[0].toAuthServer(uuid.New())
	if oidc.Type != "oidc" || oidc.Config.IssuerURL != "https://okta.example.com" || oidc.Config.ClientSecret != "shh" {
		t.Fatalf("oidc mapping wrong: %+v", oidc)
	}
	if oidc.RoleMapping.Rules["group:platform-admins"] != "GlobalAdmin" || oidc.RoleMapping.Default != "Viewer" {
		t.Fatalf("oidc role mapping wrong: %+v", oidc.RoleMapping)
	}
	if err := oidc.Validate(); err != nil {
		t.Fatalf("oidc should validate: %v", err)
	}

	ldap := specs[1].toAuthServer(uuid.New())
	if ldap.Config.BindPassword != "bindpw" || ldap.Config.UserFilter != "(uid=%s)" {
		t.Fatalf("ldap mapping wrong: %+v", ldap.Config)
	}
	if err := ldap.Validate(); err != nil {
		t.Fatalf("ldap should validate: %v", err)
	}

	// Empty / absent file is a no-op, not an error.
	if specs, err := parseAuthProviders([]byte("  \n")); err != nil || specs != nil {
		t.Fatalf("empty input: got specs=%v err=%v, want nil,nil", specs, err)
	}
}
