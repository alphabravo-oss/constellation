package auth

import (
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

// idpRedirectMetadata is a minimal IdP EntityDescriptor exposing an HTTP-Redirect SSO endpoint —
// just enough for StartLogin to build an AuthnRequest and a redirect URL.
const idpRedirectMetadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/sso">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso/redirect"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

// TestSAML_SPInitiatedRequestIDRoundTrip is the item-6 self-check: a login-start produces a
// request ID that the ACS InResponseTo validator accepts, an unknown InResponseTo is rejected,
// and an empty InResponseTo (IdP-initiated) is still allowed.
func TestSAML_SPInitiatedRequestIDRoundTrip(t *testing.T) {
	p, err := NewSAMLProvider(SAMLConfig{
		IdPMetadataXML: []byte(idpRedirectMetadata),
		ACSURL:         "https://sp.example.com/api/v1/auth/saml/acs",
		EntityID:       "https://sp.example.com",
	})
	if err != nil {
		t.Fatalf("NewSAMLProvider: %v", err)
	}

	redirect, err := p.StartLogin("relay-123")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if !strings.HasPrefix(redirect, "https://idp.example.com/sso/redirect") || u.Query().Get("SAMLRequest") == "" {
		t.Fatalf("redirect not an IdP SSO URL with SAMLRequest: %q", redirect)
	}
	if len(p.pending) != 1 {
		t.Fatalf("want exactly one pending request ID, got %d", len(p.pending))
	}

	var reqID string
	for id := range p.pending {
		reqID = id
	}

	// Accepts the minted request ID.
	if err := p.validateInResponseTo(saml.Response{InResponseTo: reqID}, nil); err != nil {
		t.Fatalf("validator rejected the minted request ID: %v", err)
	}
	// One-shot: after consuming, the same ID is no longer valid.
	if err := p.validateInResponseTo(saml.Response{InResponseTo: reqID}, nil); err == nil {
		t.Fatalf("validator accepted a replayed (already-consumed) request ID")
	}
	// Rejects an unknown InResponseTo (SP-initiated response with no matching request).
	if err := p.validateInResponseTo(saml.Response{InResponseTo: "id-unknown"}, nil); err == nil {
		t.Fatalf("validator accepted an unknown InResponseTo")
	}
	// Allows IdP-initiated (empty InResponseTo) while AllowIDPInitiated stays true.
	if err := p.validateInResponseTo(saml.Response{}, nil); err != nil {
		t.Fatalf("validator rejected an IdP-initiated (empty InResponseTo) response: %v", err)
	}
}
