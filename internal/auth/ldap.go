package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig is the per-org LDAP/AD configuration. Mirrors NeuVector's bind+search model
// (share/auth/ldap.go): a service account binds, the user is located by filter, then either
// the user entry's membership attribute or a group search yields the groups that map to roles.
type LDAPConfig struct {
	// URL is the LDAP server, e.g. ldaps://ad.example.com:636 or ldap://dc:389.
	URL string
	// BindDN / BindPassword are the read-only service account used to search for users.
	BindDN       string
	BindPassword string
	// BaseDN is the search base for users, e.g. "ou=people,dc=example,dc=com".
	BaseDN string
	// UserFilter locates the user by their login name; %s is replaced with the (escaped)
	// username, e.g. "(uid=%s)" or "(sAMAccountName=%s)".
	UserFilter string
	// GroupAttribute is the user-entry attribute carrying group DNs/names (e.g. "memberOf").
	// If set, groups are read directly from the user entry (the common AD case) and no
	// second search is needed.
	GroupAttribute string
	// EmailAttribute holds the user's email (e.g. "mail"). Optional.
	EmailAttribute string
	// RoleMapping turns group CNs into Constellation roles.
	RoleMapping RoleMapping
}

// LDAPProvider authenticates users against an LDAP/AD directory.
type LDAPProvider struct {
	cfg LDAPConfig
}

// NewLDAPProvider validates config and returns a provider. Connections are opened per-login
// (Authenticate), matching NeuVector — no long-lived pooled bind.
func NewLDAPProvider(cfg LDAPConfig) (*LDAPProvider, error) {
	if cfg.URL == "" {
		return nil, errors.New("ldap: URL required")
	}
	if cfg.BaseDN == "" || cfg.UserFilter == "" {
		return nil, errors.New("ldap: BaseDN and UserFilter required")
	}
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, errors.New("ldap: UserFilter must contain %s username placeholder")
	}
	return &LDAPProvider{cfg: cfg}, nil
}

// NewLDAPProviderForMapping builds a provider that can run only the entry->role mapping
// (IdentityFromEntry) without a live directory. It exists so tests in other packages can drive a
// canned entry through the mapping; production logins use NewLDAPProvider + Authenticate.
func NewLDAPProviderForMapping(cfg LDAPConfig) *LDAPProvider { return &LDAPProvider{cfg: cfg} }

// IdentityFromEntry is the exported, network-free mapping core (see identityFromEntry).
func (p *LDAPProvider) IdentityFromEntry(e *ldap.Entry) *LDAPIdentity { return p.identityFromEntry(e) }

// URL returns the configured directory URL (used to namespace the LDAP linked-identity issuer).
func (p *LDAPProvider) URL() string { return p.cfg.URL }

// LDAPIdentity is the result of a successful LDAP login.
type LDAPIdentity struct {
	// DN is the user's distinguished name (stable identifier, used like OIDC "sub").
	DN string
	// Email from EmailAttribute, or the DN if unset.
	Email string
	// Groups are the raw group CNs (before role mapping).
	Groups []string
	// Roles are the mapped Constellation roles (org scope).
	Roles []string
	// ScopedRoles are the full scope-aware grants (A2): org-scope roles plus any
	// cluster/namespace grants from the provider's ScopedRules.
	ScopedRoles []ScopedRole
}

// Authenticate binds the service account, finds the user, verifies the user's password by
// re-binding as them, then reads groups and maps roles. Returns an error on any bind/search
// failure or no/ambiguous match.
func (p *LDAPProvider) Authenticate(username, password string) (*LDAPIdentity, error) {
	if password == "" {
		// An empty password against many servers is an "unauthenticated bind" that
		// succeeds — refuse it outright.
		return nil, errors.New("ldap: empty password rejected")
	}
	conn, err := ldap.DialURL(p.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	defer conn.Close()

	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap: service bind: %w", err)
		}
	}

	filter := fmt.Sprintf(p.cfg.UserFilter, ldap.EscapeFilter(username))
	attrs := []string{"dn"}
	if p.cfg.GroupAttribute != "" {
		attrs = append(attrs, p.cfg.GroupAttribute)
	}
	if p.cfg.EmailAttribute != "" {
		attrs = append(attrs, p.cfg.EmailAttribute)
	}
	res, err := conn.Search(ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, filter, attrs, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap: user search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("ldap: expected 1 user, got %d", len(res.Entries))
	}
	userDN := res.Entries[0].DN

	// Verify the password by binding as the user.
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: user bind: %w", err)
	}
	return p.identityFromEntry(res.Entries[0]), nil
}

// ResolveUserDN binds the service account and locates the user's DN by UserFilter WITHOUT
// verifying their password. It exists so the brute-force lockout (A2) can resolve the SAME
// directory identity the password bind will authenticate — keyed off the stable DN — before
// attempting the bind, regardless of whether the login name is an email, uid, or sAMAccountName.
// Returns ("", false) on any dial/bind/search miss (the caller then simply skips lockout
// accounting for that attempt; no oracle is leaked).
func (p *LDAPProvider) ResolveUserDN(username string) (string, bool) {
	conn, err := ldap.DialURL(p.cfg.URL)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			return "", false
		}
	}
	filter := fmt.Sprintf(p.cfg.UserFilter, ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, filter, []string{"dn"}, nil,
	))
	if err != nil || len(res.Entries) != 1 {
		return "", false
	}
	return res.Entries[0].DN, true
}

// identityFromEntry is the pure, network-free core: turn an LDAP user entry into roles. It is
// what the G4 unit test exercises against canned entries (no live directory).
func (p *LDAPProvider) identityFromEntry(e *ldap.Entry) *LDAPIdentity {
	id := &LDAPIdentity{DN: e.DN}
	if p.cfg.EmailAttribute != "" {
		id.Email = e.GetAttributeValue(p.cfg.EmailAttribute)
	}
	if id.Email == "" {
		id.Email = e.DN
	}
	if p.cfg.GroupAttribute != "" {
		for _, raw := range e.GetAttributeValues(p.cfg.GroupAttribute) {
			id.Groups = append(id.Groups, groupCN(raw))
		}
	}
	id.Roles = p.cfg.RoleMapping.MapRoles(id.Groups)
	id.ScopedRoles = p.cfg.RoleMapping.MapScopedRoles(id.Groups)
	return id
}

// groupCN extracts the CN from a group DN ("cn=Auditors,ou=groups,dc=x" -> "Auditors"). If the
// value is a bare name (not a DN), it is returned unchanged. This is what lets RoleMapping rules
// be written against human-readable group names rather than full DNs.
func groupCN(v string) string {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if cn, ok := strings.CutPrefix(strings.ToLower(part), "cn="); ok {
			// Return the original-case CN value (slice the original part after "cn=").
			return strings.TrimSpace(part[len(part)-len(cn):])
		}
	}
	return strings.TrimSpace(v)
}
