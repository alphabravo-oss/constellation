package handler

import "testing"

func TestValidOIDCMetadata(t *testing.T) {
	issuer := "https://idp.example.com/tenant"
	valid := oidcDiscoveryMetadata{
		Issuer:                issuer,
		AuthorizationEndpoint: "https://login.example.com/authorize",
		TokenEndpoint:         "https://login.example.com/token",
		JWKSURI:               "https://keys.example.com/jwks",
	}
	if !validOIDCMetadata(issuer, valid) {
		t.Fatal("valid cross-host metadata rejected")
	}
	for _, tc := range []struct {
		name string
		edit func(*oidcDiscoveryMetadata)
	}{
		{"issuer mismatch", func(metadata *oidcDiscoveryMetadata) { metadata.Issuer = "https://other.example.com" }},
		{"missing token", func(metadata *oidcDiscoveryMetadata) { metadata.TokenEndpoint = "" }},
		{"plaintext token", func(metadata *oidcDiscoveryMetadata) { metadata.TokenEndpoint = "http://login.example.com/token" }},
		{"private keys", func(metadata *oidcDiscoveryMetadata) { metadata.JWKSURI = "https://127.0.0.1/jwks" }},
		{"credentials in URL", func(metadata *oidcDiscoveryMetadata) {
			metadata.AuthorizationEndpoint = "https://user:pass@login.example.com/authorize"
		}},
		{"URL fragment", func(metadata *oidcDiscoveryMetadata) { metadata.TokenEndpoint += "#secret" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := valid
			tc.edit(&metadata)
			if validOIDCMetadata(issuer, metadata) {
				t.Fatalf("unsafe metadata accepted: %+v", metadata)
			}
		})
	}
}
