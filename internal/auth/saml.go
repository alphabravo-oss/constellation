package auth

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// samlRequestTTL bounds how long a minted SP-initiated AuthnRequest ID stays valid for
// InResponseTo matching on the ACS callback. Short enough to bound the pending set, long enough
// to cover an interactive IdP login.
const samlRequestTTL = 10 * time.Minute

// SAMLConfig is the per-org SAML SP configuration.
//
// Signature/XML handling is delegated to crewjam/saml (we do NOT hand-roll XML-DSig). This
// struct carries only what a deployment configures per organization: the IdP's metadata
// (entity descriptor XML) and the SP's own keypair + ACS/entity URLs, plus the
// attribute->role mapping that reuses the RBAC role-assignment path.
type SAMLConfig struct {
	// IdPMetadataXML is the IdP's SAML 2.0 EntityDescriptor (contains the IdP signing cert
	// and SSO endpoints). Required.
	IdPMetadataXML []byte
	// EntityID is this SP's entity ID (defaults to ACSURL's origin if empty).
	EntityID string
	// ACSURL is the SP's Assertion Consumer Service URL (the callback the IdP POSTs to).
	ACSURL string
	// SPCertPEM / SPKeyPEM are the SP's keypair, used to sign AuthnRequests and to decrypt
	// encrypted assertions. Optional for IdPs that don't require signed requests.
	SPCertPEM []byte
	SPKeyPEM  []byte

	// GroupAttribute is the SAML attribute Name (or FriendlyName) whose values carry the
	// user's group/role membership (e.g. "groups", "Role", or an Okta app-group attribute).
	GroupAttribute string
	// EmailAttribute is the attribute holding the user's email. If empty the Subject NameID
	// is used as the email/identifier.
	EmailAttribute string
	// RoleMapping turns GroupAttribute values into Constellation roles.
	RoleMapping RoleMapping
}

// SAMLProvider wraps a crewjam/saml ServiceProvider configured for one org.
type SAMLProvider struct {
	cfg SAMLConfig
	sp  saml.ServiceProvider

	// mu guards pending, the set of outstanding SP-initiated AuthnRequest IDs (id -> expiry) that
	// StartLogin minted and the ACS validates InResponseTo against. In-memory with per-entry TTL:
	// bounded by (login rate x samlRequestTTL) — there is no hard cap, which is fine on a single
	// node behind the /auth/* per-IP rate limit; it is NOT shared across replicas, and a provider
	// rebuild (hot IdP-config reload) drops in-flight requests, so those logins simply restart.
	mu      sync.Mutex
	pending map[string]time.Time
}

// NewSAMLProvider builds the SP from the configured IdP metadata + SP keypair. It performs all
// signature-trust setup (IdP cert from metadata) up front; ParseResponse then validates the
// assertion signature against it.
func NewSAMLProvider(cfg SAMLConfig) (*SAMLProvider, error) {
	if len(cfg.IdPMetadataXML) == 0 {
		return nil, errors.New("saml: IdP metadata required")
	}
	if cfg.ACSURL == "" {
		return nil, errors.New("saml: ACSURL required")
	}
	acs, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: bad ACSURL: %w", err)
	}
	idpMeta, err := samlsp.ParseMetadata(cfg.IdPMetadataXML)
	if err != nil {
		return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
	}

	p := &SAMLProvider{cfg: cfg, pending: map[string]time.Time{}}
	sp := saml.ServiceProvider{
		AcsURL:      *acs,
		MetadataURL: *acs,
		EntityID:    cfg.EntityID,
		IDPMetadata: idpMeta,
		// SP-initiated login is now supported: StartLogin mints an AuthnRequest, stores its ID
		// (see p.pending), and validateInResponseTo enforces that any response carrying an
		// InResponseTo matches an outstanding, unexpired request. We keep AllowIDPInitiated=true so
		// IdP-initiated (unsolicited, empty-InResponseTo) responses still validate — crewjam's own
		// InResponseTo check is a no-op whenever that flag is set, so the SP-initiated contract is
		// enforced by our ValidateRequestID hook instead. Signature/audience/conditions checks are
		// unaffected (still enforced by crewjam against IDPMetadata).
		AllowIDPInitiated: true,
		ValidateRequestID: p.validateInResponseTo,
	}
	if len(cfg.SPCertPEM) > 0 && len(cfg.SPKeyPEM) > 0 {
		keypair, err := tls.X509KeyPair(cfg.SPCertPEM, cfg.SPKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("saml: SP keypair: %w", err)
		}
		leaf, err := x509.ParseCertificate(keypair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("saml: SP cert: %w", err)
		}
		key, ok := keypair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("saml: SP key must be RSA")
		}
		sp.Certificate = leaf
		sp.Key = key
	}
	p.sp = sp
	return p, nil
}

// StartLogin begins an SP-initiated login: it builds a SAML AuthnRequest for the IdP's
// HTTP-Redirect SSO endpoint, records the request ID (with TTL) so the ACS can match the
// response's InResponseTo, and returns the IdP URL the caller should 302 the browser to.
// relayState is echoed back by the IdP on the ACS POST (opaque return-path/CSRF token).
func (p *SAMLProvider) StartLogin(relayState string) (string, error) {
	if p.pending == nil {
		return "", errors.New("saml: provider not configured for login")
	}
	loc := p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if loc == "" {
		return "", errors.New("saml: IdP has no HTTP-Redirect SSO endpoint")
	}
	req, err := p.sp.MakeAuthenticationRequest(loc, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("saml: build AuthnRequest: %w", err)
	}
	p.storePending(req.ID)
	u, err := req.Redirect(relayState, &p.sp)
	if err != nil {
		return "", fmt.Errorf("saml: redirect URL: %w", err)
	}
	return u.String(), nil
}

// storePending records an outstanding AuthnRequest ID, pruning expired entries first so the map
// stays bounded by the login rate over samlRequestTTL.
func (p *SAMLProvider) storePending(id string) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, exp := range p.pending {
		if now.After(exp) {
			delete(p.pending, k)
		}
	}
	p.pending[id] = now.Add(samlRequestTTL)
}

// consumePending reports whether id is an outstanding, unexpired request and removes it (one-shot:
// an AuthnRequest ID is valid for exactly one response, blunting replay of a captured assertion).
func (p *SAMLProvider) consumePending(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	exp, ok := p.pending[id]
	if !ok {
		return false
	}
	delete(p.pending, id)
	return time.Now().Before(exp)
}

// validateInResponseTo is wired as the ServiceProvider's ValidateRequestID hook. A response with
// an empty InResponseTo is IdP-initiated and allowed (AllowIDPInitiated stays true); a non-empty
// InResponseTo is an SP-initiated response and MUST match an outstanding, unexpired request ID we
// minted in StartLogin. crewjam's built-in check is skipped under AllowIDPInitiated, so this hook
// is what enforces the SP-initiated contract.
func (p *SAMLProvider) validateInResponseTo(response saml.Response, _ []string) error {
	if response.InResponseTo == "" {
		return nil
	}
	if !p.consumePending(response.InResponseTo) {
		return fmt.Errorf("saml: InResponseTo %q matches no pending SP-initiated request", response.InResponseTo)
	}
	return nil
}

// NewSAMLProviderForMapping builds a provider that can run only the attribute->role mapping
// (ParseAssertionXML / IdentityFromAssertion) without IdP metadata. It exists so tests in other
// packages can drive a canned assertion through the mapping; it MUST NOT be used for production
// logins, which require NewSAMLProvider + ParseResponse for signature validation.
func NewSAMLProviderForMapping(cfg SAMLConfig) *SAMLProvider { return &SAMLProvider{cfg: cfg} }

// AssertionIdentity is the result of a successful SAML login: the IdP-asserted identity plus
// the Constellation roles it maps to. It mirrors the OIDC IDTokenClaims shape closely enough
// that the handler can issue an identical session.
type AssertionIdentity struct {
	// Issuer is the IdP entity ID (assertion Issuer).
	Issuer string
	// Subject is the NameID (stable user identifier, used like OIDC "sub").
	Subject string
	// Email is the user's email (EmailAttribute value, or Subject if unset).
	Email string
	// Groups are the raw values of GroupAttribute (before role mapping).
	Groups []string
	// Roles are the mapped Constellation roles (org scope). Retained for the existing
	// session-issuing path, which writes org-scope role_assignments.
	Roles []string
	// ScopedRoles are the full scope-aware grants (A2): the org-scope roles PLUS any
	// cluster/namespace grants from the provider's ScopedRules. The scoped grants beyond the
	// IsOrg() subset are threaded here for the cluster/namespace-aware assignment writer.
	ScopedRoles []ScopedRole
}

// IdentityFromAssertion extracts the subject, email and group->role mapping from an already
// signature-validated assertion. Splitting this from signature validation keeps the
// security-critical XML handling inside crewjam/saml while making the attribute/group mapping
// trivially unit-testable against canned assertions (per the G4 DoD).
func (p *SAMLProvider) IdentityFromAssertion(a *saml.Assertion) (*AssertionIdentity, error) {
	if a == nil {
		return nil, errors.New("saml: nil assertion")
	}
	id := &AssertionIdentity{Issuer: a.Issuer.Value}
	if a.Subject != nil && a.Subject.NameID != nil {
		id.Subject = a.Subject.NameID.Value
	}
	id.Groups = attributeValues(a, p.cfg.GroupAttribute)
	if p.cfg.EmailAttribute != "" {
		if vals := attributeValues(a, p.cfg.EmailAttribute); len(vals) > 0 {
			id.Email = vals[0]
		}
	}
	if id.Email == "" {
		id.Email = id.Subject
	}
	if id.Subject == "" {
		return nil, errors.New("saml: assertion has no NameID subject")
	}
	id.Roles = p.cfg.RoleMapping.MapRoles(id.Groups)
	id.ScopedRoles = p.cfg.RoleMapping.MapScopedRoles(id.Groups)
	return id, nil
}

// ParseResponse is the production ACS path: it validates the IdP's POSTed SAMLResponse
// (signature, conditions, audience) via crewjam/saml against the configured IdP metadata, then
// runs the same attribute/group->role mapping. The handler's ACS endpoint calls this; the
// resulting identity is issued an identical session to an OIDC login.
func (p *SAMLProvider) ParseResponse(r *http.Request) (*AssertionIdentity, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("saml: parse form: %w", err)
	}
	assertion, err := p.sp.ParseResponse(r, nil)
	if err != nil {
		return nil, fmt.Errorf("saml: parse response: %w", err)
	}
	return p.IdentityFromAssertion(assertion)
}

// ParseAssertionXML is a test/offline seam: it unmarshals a raw <Assertion> XML document into
// the crewjam/saml type WITHOUT signature validation, then runs the mapping. Production logins
// MUST go through ParseResponse (which validates the signature); this exists so the assertion->
// role mapping can be unit-tested against canned IdP output with no live IdP.
func (p *SAMLProvider) ParseAssertionXML(assertionXML []byte) (*AssertionIdentity, error) {
	var a saml.Assertion
	if err := xml.Unmarshal(assertionXML, &a); err != nil {
		return nil, fmt.Errorf("saml: unmarshal assertion: %w", err)
	}
	return p.IdentityFromAssertion(&a)
}

// attributeValues returns all values of the attribute whose Name or FriendlyName matches.
func attributeValues(a *saml.Assertion, name string) []string {
	if name == "" {
		return nil
	}
	var out []string
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			if attr.Name != name && attr.FriendlyName != name {
				continue
			}
			for _, v := range attr.Values {
				if v.Value != "" {
					out = append(out, v.Value)
				}
			}
		}
	}
	return out
}
