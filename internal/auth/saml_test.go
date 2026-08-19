package auth

import "testing"

// cannedAssertion is a minimal but realistic SAML 2.0 <Assertion> as an Okta-style IdP would
// emit it: a NameID subject, an email attribute, and a multi-valued "groups" attribute.
const cannedAssertion = `<?xml version="1.0"?>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1" IssueInstant="2026-06-17T00:00:00Z">
  <saml:Issuer>https://idp.example.com/sso</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>alice@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="groups">
      <saml:AttributeValue>okta-secadmins</saml:AttributeValue>
      <saml:AttributeValue>everyone</saml:AttributeValue>
      <saml:AttributeValue>okta-auditors</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`

func testSAMLProvider(t *testing.T) *SAMLProvider {
	t.Helper()
	return &SAMLProvider{cfg: SAMLConfig{
		GroupAttribute: "groups",
		EmailAttribute: "email",
		RoleMapping: RoleMapping{
			Rules: map[string]string{
				"okta-secadmins": "SecurityAdmin",
				"okta-auditors":  "Auditor",
			},
		},
	}}
}

func TestSAML_AssertionParseAndRoleMap(t *testing.T) {
	p := testSAMLProvider(t)
	id, err := p.ParseAssertionXML([]byte(cannedAssertion))
	if err != nil {
		t.Fatalf("ParseAssertionXML: %v", err)
	}
	if id.Subject != "alice@example.com" {
		t.Fatalf("subject: %q", id.Subject)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("email: %q", id.Email)
	}
	if id.Issuer != "https://idp.example.com/sso" {
		t.Fatalf("issuer: %q", id.Issuer)
	}
	if len(id.Groups) != 3 {
		t.Fatalf("groups: %v", id.Groups)
	}
	// "everyone" has no rule and is dropped; the two mapped groups become two roles, in order.
	want := []string{"SecurityAdmin", "Auditor"}
	if len(id.Roles) != len(want) {
		t.Fatalf("roles: %v", id.Roles)
	}
	for i := range want {
		if id.Roles[i] != want[i] {
			t.Fatalf("roles[%d] = %q, want %q (%v)", i, id.Roles[i], want[i], id.Roles)
		}
	}
}

func TestSAML_EmailFallsBackToSubject(t *testing.T) {
	p := &SAMLProvider{cfg: SAMLConfig{GroupAttribute: "groups"}} // no EmailAttribute
	id, err := p.ParseAssertionXML([]byte(cannedAssertion))
	if err != nil {
		t.Fatalf("ParseAssertionXML: %v", err)
	}
	if id.Email != id.Subject {
		t.Fatalf("email %q should fall back to subject %q", id.Email, id.Subject)
	}
}

func TestSAML_DefaultRoleWhenNoGroupMatches(t *testing.T) {
	p := &SAMLProvider{cfg: SAMLConfig{
		GroupAttribute: "groups",
		RoleMapping:    RoleMapping{Rules: map[string]string{"nobody": "x"}, Default: "Auditor"},
	}}
	id, err := p.ParseAssertionXML([]byte(cannedAssertion))
	if err != nil {
		t.Fatalf("ParseAssertionXML: %v", err)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "Auditor" {
		t.Fatalf("expected default Auditor, got %v", id.Roles)
	}
}
