package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// cannedSAMLAssertion is an Okta-style <Assertion>: NameID subject + email + multi-valued groups.
// %s is a per-run-unique subject/email so the resulting (issuer, subject) link is hermetic.
const cannedSAMLAssertion = `<?xml version="1.0"?>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a1" IssueInstant="2026-06-17T00:00:00Z">
  <saml:Issuer>https://idp.example.com/sso</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
    <saml:Attribute Name="groups">
      <saml:AttributeValue>okta-secadmins</saml:AttributeValue>
      <saml:AttributeValue>everyone</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`

func TestAuth_SAMLACSIssuesMappedSession(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	orgID := uuid.New()
	userID := uuid.New()
	issuer := "https://idp.example.com/sso"
	subject := "alice-" + uuid.NewString() + "@example.com"
	assertion := fmt.Sprintf(cannedSAMLAssertion, subject, subject)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'SAML Org')`,
		orgID, "saml-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, oidc_issuer, oidc_subject)
VALUES ($1, $2, $3, 'Alice', $4, $5)`,
		userID, orgID, subject, issuer, subject); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'SecurityAdmin', $2)`,
		userID, orgID); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	signer := testAuthSigner(t)
	// A non-nil provider so SAMLACS is enabled; the parse seam below drives the canned assertion
	// through the (signature-free) mapping core.
	samlP := authpkg.NewSAMLProviderForMapping(authpkg.SAMLConfig{
		GroupAttribute: "groups",
		EmailAttribute: "email",
		RoleMapping:    authpkg.RoleMapping{Rules: map[string]string{"okta-secadmins": "SecurityAdmin"}},
	})
	h := NewAuth(d, signer, nil, samlP, nil, audit.New(pool))
	h.setSAMLParseFunc(func(_ *http.Request) (*authpkg.AssertionIdentity, error) {
		return samlP.ParseAssertionXML([]byte(assertion))
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", nil)
	rec := httptest.NewRecorder()
	h.SAMLACS(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	tok := decodeToken(t, rec)
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.UserID != userID || claims.OrgID != orgID {
		t.Fatalf("claims = user %s org %s, want %s / %s", claims.UserID, claims.OrgID, userID, orgID)
	}
	assertHasRole(t, claims.Roles, "SecurityAdmin")
}

// TestAuth_SAMLACSJITProvisioning exercises the ENT-1 JIT path: a SAML login for an identity with
// no pre-provisioned user. When the org has jit_provisioning = TRUE the login auto-creates the user
// and seeds role_assignments from the IdP-asserted, mapped roles; when it is FALSE the original
// provision-by-admin 403 is preserved (no user, no session).
func TestAuth_SAMLACSJITProvisioning(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	issuer := "https://idp.example.com/sso"

	newHandler := func(orgID uuid.UUID, subject string) (*Auth, *authpkg.Signer) {
		t.Helper()
		signer := testAuthSigner(t)
		samlP := authpkg.NewSAMLProviderForMapping(authpkg.SAMLConfig{
			GroupAttribute: "groups",
			EmailAttribute: "email",
			RoleMapping:    authpkg.RoleMapping{Rules: map[string]string{"okta-secadmins": "SecurityAdmin"}},
		})
		assertion := fmt.Sprintf(cannedSAMLAssertion, subject, subject)
		h := NewAuth(d, signer, nil, samlP, nil, audit.New(pool))
		h.setSAMLParseFunc(func(_ *http.Request) (*authpkg.AssertionIdentity, error) {
			return samlP.ParseAssertionXML([]byte(assertion))
		})
		return h, signer
	}

	// JIT disabled: no linked user -> 403, and no user is created.
	t.Run("disabled keeps 403", func(t *testing.T) {
		orgID := uuid.New()
		subject := "carol-" + uuid.NewString() + "@example.com"
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
		if _, err := pool.Exec(ctx,
			`INSERT INTO orgs (id, name, display_name, jit_provisioning) VALUES ($1, $2, 'No JIT Org', FALSE)`,
			orgID, "nojit-org-"+orgID.String()); err != nil {
			t.Fatalf("insert org: %v", err)
		}
		h, _ := newHandler(orgID, subject)
		rec := httptest.NewRecorder()
		h.SAMLACS(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d (want 403), body=%s", rec.Code, rec.Body.String())
		}
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`, issuer, subject,
		).Scan(&n); err != nil {
			t.Fatalf("count users: %v", err)
		}
		if n != 0 {
			t.Fatalf("JIT-disabled login provisioned %d user(s)", n)
		}
	})

	// JIT enabled: no linked user -> auto-provision + mapped roles -> session with those roles.
	t.Run("enabled provisions session with mapped roles", func(t *testing.T) {
		orgID := uuid.New()
		subject := "dave-" + uuid.NewString() + "@example.com"
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
		if _, err := pool.Exec(ctx,
			`INSERT INTO orgs (id, name, display_name, jit_provisioning) VALUES ($1, $2, 'JIT Org', TRUE)`,
			orgID, "jit-org-"+orgID.String()); err != nil {
			t.Fatalf("insert org: %v", err)
		}
		h, signer := newHandler(orgID, subject)
		rec := httptest.NewRecorder()
		h.SAMLACS(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (want 200), body=%s", rec.Code, rec.Body.String())
		}
		claims, err := signer.Verify(decodeToken(t, rec))
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}
		if claims.OrgID != orgID {
			t.Fatalf("org = %s, want %s", claims.OrgID, orgID)
		}
		assertHasRole(t, claims.Roles, "SecurityAdmin")

		// H10 regression: the JWT must carry the user's post-provision session_epoch. JIT
		// provisioning seeds roles and bumps session_epoch (0 -> 1) in reconcileJITRoles' own
		// tx; if issueLinkedSession signs with the stale pre-bump epoch the middleware rejects
		// the token (claims.Epoch < session_epoch) and the very first SSO login is unusable.
		var storedEpoch int64
		if err := pool.QueryRow(ctx, `
SELECT session_epoch FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`,
			issuer, subject,
		).Scan(&storedEpoch); err != nil {
			t.Fatalf("load session_epoch: %v", err)
		}
		if claims.Epoch != storedEpoch {
			t.Fatalf("token epoch = %d, stored session_epoch = %d (token dead-on-arrival)", claims.Epoch, storedEpoch)
		}
		if storedEpoch == 0 {
			t.Fatalf("expected role-seeding to bump session_epoch above 0, got %d", storedEpoch)
		}

		// The user and its seeded role_assignment must be persisted.
		var role string
		if err := pool.QueryRow(ctx, `
SELECT ra.role FROM role_assignments ra
  JOIN users u ON u.id = ra.user_id
 WHERE u.oidc_issuer = $1 AND u.oidc_subject = $2`,
			issuer, subject,
		).Scan(&role); err != nil {
			t.Fatalf("load seeded role: %v", err)
		}
		if role != "SecurityAdmin" {
			t.Fatalf("seeded role = %q, want SecurityAdmin", role)
		}
	})
}

func TestAuth_LDAPEntryDrivesMappedSession(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	ldapP := authpkg.NewLDAPProviderForMapping(authpkg.LDAPConfig{
		URL:            "ldap://dir.example.com",
		GroupAttribute: "memberOf",
		EmailAttribute: "mail",
		RoleMapping:    authpkg.RoleMapping{Rules: map[string]string{"auditors": "Auditor"}},
	})
	// Unique DN per run so the (oidc_issuer, oidc_subject) link is hermetic across reruns.
	dn := "uid=bob-" + uuid.NewString() + ",ou=people,dc=example,dc=com"
	entry := ldap.NewEntry(dn, map[string][]string{
		"mail":     {"bob@example.com"},
		"memberOf": {"cn=Auditors,ou=groups,dc=example,dc=com"},
	})
	id := ldapP.IdentityFromEntry(entry)
	assertHasRole(t, id.Roles, "Auditor")

	orgID := uuid.New()
	userID := uuid.New()
	issuer := "ldap:" + ldapP.URL()
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'LDAP Org')`,
		orgID, "ldap-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, oidc_issuer, oidc_subject)
VALUES ($1, $2, $3, 'Bob', $4, $5)`,
		userID, orgID, id.Email, issuer, id.DN); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'Auditor', $2)`,
		userID, orgID); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	signer := testAuthSigner(t)
	h := NewAuth(d, signer, nil, nil, ldapP, audit.New(pool))
	// Drive the shared linked-session tail with the canned entry's identity (the network bind in
	// Authenticate is out of scope for a hermetic handler test).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/ldap/login", nil)
	h.issueLinkedSession(rec, req, issuer, id.DN, id.Email, id.Roles, id.ScopedRoles, "auth.login.ldap")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	claims, err := signer.Verify(decodeToken(t, rec))
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.UserID != userID || claims.OrgID != orgID {
		t.Fatalf("claims = user %s org %s, want %s / %s", claims.UserID, claims.OrgID, userID, orgID)
	}
	assertHasRole(t, claims.Roles, "Auditor")
}

// TestAuth_SAMLACSRejectsUnsignedAssertion exercises the REAL ACS path — NewAuth wires
// SAMLProvider.ParseResponse (the crewjam/saml signature-validating consumer), with NO test seam
// override — and confirms an unsigned SAMLResponse is rejected. This is the security regression
// guard for the unexported test seam: production code can never bypass XML-DSig validation, so an
// IdP-less, unsigned assertion must fail (401), never mint a session.
func TestAuth_SAMLACSRejectsUnsignedAssertion(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	const acsURL = "https://sp.example.com/api/v1/auth/saml/acs"
	idpMeta := testIdPMetadataXML(t)

	// Real provider: parses IdP metadata + ACS URL. NewAuth sets a.samlParse = samlP.ParseResponse,
	// the signature-validating path. We do NOT call setSAMLParseFunc, so the live path is exercised.
	samlP, err := authpkg.NewSAMLProvider(authpkg.SAMLConfig{
		IdPMetadataXML: idpMeta,
		ACSURL:         acsURL,
		EntityID:       "https://sp.example.com/saml/metadata",
		GroupAttribute: "groups",
		EmailAttribute: "email",
	})
	if err != nil {
		t.Fatalf("NewSAMLProvider: %v", err)
	}
	h := NewAuth(d, testAuthSigner(t), nil, samlP, nil, audit.New(d.Pool()))

	// An unsigned <Response>/<Assertion> as a forger would submit: well-formed, but no XML-DSig.
	unsigned := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-06-17T00:00:00Z" Destination="%s">
  <saml:Issuer>https://idp.example.com/sso</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-06-17T00:00:00Z">
    <saml:Issuer>https://idp.example.com/sso</saml:Issuer>
    <saml:Subject><saml:NameID>attacker@example.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>attacker@example.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>okta-secadmins</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`, acsURL)

	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(unsigned))}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.SAMLACS(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned assertion: status = %d (want 401), body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("unsigned assertion minted a session: %s", rec.Body.String())
	}
}

// testIdPMetadataXML returns a standard SAML 2.0 IdP EntityDescriptor carrying a freshly generated
// (and thus unrelated-to-the-unsigned-response) signing cert, so NewSAMLProvider can build a real
// signature-validating ServiceProvider. The keypair is discarded: the point is that the IdP's
// trusted cert never signed the forged assertion, so validation must fail.
func testIdPMetadataXML(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	// Sanity: ensure we built valid PEM-able DER (not asserted, just exercises encoders).
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/sso">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, b64))
}

func decodeToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Token == "" {
		t.Fatalf("empty token, body=%s", rec.Body.String())
	}
	return out.Token
}

func assertHasRole(t *testing.T, roles []string, want string) {
	t.Helper()
	for _, r := range roles {
		if r == want {
			return
		}
	}
	t.Fatalf("roles %v missing %q", roles, want)
}
