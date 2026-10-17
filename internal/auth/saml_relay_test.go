package auth

import (
	"net/url"
	"testing"
)

func TestSAMLRelayStateRemainsOneOpaqueQueryValue(t *testing.T) {
	for _, relay := range []string{"browser-nonce_123", "x&extra=value&SAMLRequest=other", "/clusters?name=a+b&next=%2F#fragment", "space and unicode α", ""} {
		t.Run(relay, func(t *testing.T) {
			provider, err := NewSAMLProvider(SAMLConfig{
				IdPMetadataXML: []byte(idpRedirectMetadata),
				ACSURL:         "https://sp.example.com/api/v1/auth/saml/acs",
			})
			if err != nil {
				t.Fatal(err)
			}
			redirect, err := provider.StartLogin(relay)
			if err != nil {
				t.Fatal(err)
			}
			target, err := url.Parse(redirect)
			if err != nil {
				t.Fatal(err)
			}
			query, err := url.ParseQuery(target.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			wantKeys := 2
			if relay == "" {
				wantKeys = 1
			}
			if target.Scheme != "https" || target.Host != "idp.example.com" || target.Path != "/sso/redirect" || target.Fragment != "" {
				t.Fatal("relay state changed the configured IdP destination")
			}
			if len(query) != wantKeys || len(query["SAMLRequest"]) != 1 || query.Get("SAMLRequest") == "" || query.Get("RelayState") != relay {
				t.Fatal("relay state altered query fields or failed its opaque round trip")
			}
		})
	}
}
