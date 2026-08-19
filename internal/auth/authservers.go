package auth

// B4 — DB-backed auth-provider (IdP) configuration + a hot-reloadable provider set.
//
// Historically LDAP/SAML/OIDC were single-instance providers wired at process start from
// env/Helm. This file turns them into runtime-mutable rows (the auth_servers table) and a
// ProviderSet the login handler reads the LIVE providers through. A background poller (wired
// in internal/server, mirroring runSessionKeyReloader / syscfg.Provider) rebuilds the set
// from the DB on a revision bump so a CRUD change takes effect WITHOUT a restart.
//
// Env/Helm providers become BOOTSTRAP DEFAULTS: the server seeds a row of each configured
// type on first boot if absent, after which the DB row owns the provider.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Server types.
const (
	ServerTypeLDAP = "ldap"
	ServerTypeSAML = "saml"
	ServerTypeOIDC = "oidc"
)

// redactedMarker is returned by Redacted() in place of a stored secret so a GET caller can
// tell a secret is set without leaking its bytes (mirrors syscfg.Redacted).
const redactedMarker = "***REDACTED***"

// AuthServer is one configured identity provider row. Config is the provider-specific blob
// (carrying secrets); RoleMapping is the group/attribute -> Constellation role map the SSO/JIT
// provisioning resolves at login. AuthOrder sorts providers (lower first) so the active provider
// of each type is deterministic.
type AuthServer struct {
	ID          uuid.UUID    `json:"id"`
	OrgID       uuid.UUID    `json:"org_id"`
	Type        string       `json:"type"`
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	AuthOrder   int          `json:"auth_order"`
	Config      ServerConfig `json:"config"`
	RoleMapping RoleMapping  `json:"role_mapping"`
	Revision    int64        `json:"revision"`
}

// ServerConfig is the union of the per-type provider configuration. Only the fields relevant to
// Type are meaningful; the others are zero. Secret-bearing fields are redacted by Redacted().
type ServerConfig struct {
	// --- LDAP ---
	URL            string `json:"url,omitempty"`
	BindDN         string `json:"bind_dn,omitempty"`
	BindPassword   string `json:"bind_password,omitempty"` // SECRET
	BaseDN         string `json:"base_dn,omitempty"`
	UserFilter     string `json:"user_filter,omitempty"`
	GroupAttribute string `json:"group_attribute,omitempty"`
	EmailAttribute string `json:"email_attribute,omitempty"`

	// --- SAML ---
	IdPMetadataXML string `json:"idp_metadata_xml,omitempty"`
	EntityID       string `json:"entity_id,omitempty"`
	ACSURL         string `json:"acs_url,omitempty"`
	SPCertPEM      string `json:"sp_cert_pem,omitempty"`
	SPKeyPEM       string `json:"sp_key_pem,omitempty"` // SECRET

	// --- OIDC ---
	IssuerURL    string   `json:"issuer_url,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"` // SECRET
	RedirectURL  string   `json:"redirect_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// Validate enforces the per-type required fields so a malformed row can never become a live
// provider (the build step would otherwise fail silently and drop the provider).
func (s AuthServer) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("auth server: name required")
	}
	switch s.Type {
	case ServerTypeLDAP:
		if strings.TrimSpace(s.Config.URL) == "" {
			return errors.New("auth server (ldap): url required")
		}
		if strings.TrimSpace(s.Config.BaseDN) == "" || strings.TrimSpace(s.Config.UserFilter) == "" {
			return errors.New("auth server (ldap): base_dn and user_filter required")
		}
		if !strings.Contains(s.Config.UserFilter, "%s") {
			return errors.New("auth server (ldap): user_filter must contain %s username placeholder")
		}
	case ServerTypeSAML:
		if strings.TrimSpace(s.Config.IdPMetadataXML) == "" {
			return errors.New("auth server (saml): idp_metadata_xml required")
		}
		if strings.TrimSpace(s.Config.ACSURL) == "" {
			return errors.New("auth server (saml): acs_url required")
		}
	case ServerTypeOIDC:
		if strings.TrimSpace(s.Config.IssuerURL) == "" {
			return errors.New("auth server (oidc): issuer_url required")
		}
		if strings.TrimSpace(s.Config.ClientID) == "" {
			return errors.New("auth server (oidc): client_id required")
		}
	default:
		return fmt.Errorf("auth server: unknown type %q", s.Type)
	}
	return nil
}

// Redacted returns a copy with secret-bearing config fields masked, for GET responses + audit.
// An empty secret stays empty (so the UI can tell "set" from "unset"); a set secret becomes the
// marker.
func (s AuthServer) Redacted() AuthServer {
	out := s
	redact := func(v *string) {
		if strings.TrimSpace(*v) != "" {
			*v = redactedMarker
		}
	}
	redact(&out.Config.BindPassword)
	redact(&out.Config.SPKeyPEM)
	redact(&out.Config.ClientSecret)
	return out
}

// mergeSecrets copies each secret field from prev into s when s's value is empty or the
// redaction marker (a GET->edit->PUT round-trip of the redacted body), so an update never wipes
// a stored secret the caller didn't intend to change.
func (s *AuthServer) mergeSecrets(prev AuthServer) {
	keep := func(cur *string, old string) {
		if strings.TrimSpace(*cur) == "" || *cur == redactedMarker {
			*cur = old
		}
	}
	keep(&s.Config.BindPassword, prev.Config.BindPassword)
	keep(&s.Config.SPKeyPEM, prev.Config.SPKeyPEM)
	keep(&s.Config.ClientSecret, prev.Config.ClientSecret)
}

// secretEncPrefix tags a stored secret value that has been sealed at rest (so openConfigSecrets
// can distinguish a sealed value from a legacy plaintext one and migrate gracefully). The bytes
// after the prefix are base64(nonce||ciphertext||tag) from the install-KEK cipher.
const secretEncPrefix = "cstl-enc:v1:"

// secretFieldPtrs returns the addresses of the three secret-bearing config fields so seal/open
// can iterate them uniformly. The order is irrelevant (each is independent).
func (c *ServerConfig) secretFieldPtrs() []*string {
	return []*string{&c.BindPassword, &c.SPKeyPEM, &c.ClientSecret}
}

// sealConfigSecrets returns a copy of cfg whose secret-bearing fields (BindPassword, SPKeyPEM,
// ClientSecret) are sealed at rest under sealer. It is idempotent: an empty value or one already
// carrying secretEncPrefix is left untouched (so an UpdateAuthServer round-trip that preserved a
// previously-sealed secret via mergeSecrets does not double-seal it). A nil sealer is a no-op, so a
// deployment without an install KEK keeps the historical plaintext behavior rather than failing.
func sealConfigSecrets(cfg ServerConfig, sealer Sealer) (ServerConfig, error) {
	if sealer == nil {
		return cfg, nil
	}
	for _, p := range cfg.secretFieldPtrs() {
		v := *p
		if v == "" || strings.HasPrefix(v, secretEncPrefix) {
			continue
		}
		sealed, err := sealer.Seal([]byte(v))
		if err != nil {
			return cfg, fmt.Errorf("auth servers: seal secret: %w", err)
		}
		*p = secretEncPrefix + base64.StdEncoding.EncodeToString(sealed)
	}
	return cfg, nil
}

// openConfigSecrets returns a copy of cfg whose sealed secret-bearing fields are decrypted to
// plaintext, ready to build a live provider. A value WITHOUT secretEncPrefix is treated as legacy
// plaintext and returned unchanged (graceful migration: pre-seal rows keep working until their next
// write re-seals them). A sealed value with a nil sealer, undecodable base64, or a failed Open is an
// error so a misconfigured KEK fails the provider build loudly instead of authenticating with garbage.
func openConfigSecrets(cfg ServerConfig, sealer Sealer) (ServerConfig, error) {
	for _, p := range cfg.secretFieldPtrs() {
		v := *p
		if !strings.HasPrefix(v, secretEncPrefix) {
			continue
		}
		if sealer == nil {
			return cfg, errors.New("auth servers: sealed secret but no cipher configured")
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, secretEncPrefix))
		if err != nil {
			return cfg, fmt.Errorf("auth servers: decode sealed secret: %w", err)
		}
		pt, err := sealer.Open(raw)
		if err != nil {
			return cfg, fmt.Errorf("auth servers: open sealed secret: %w", err)
		}
		*p = string(pt)
	}
	return cfg, nil
}

// ---------------------------------- store -----------------------------------

// store is the minimal pgx surface this package needs; *pgxpool.Pool satisfies it.
type store interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ListAuthServers returns the org's auth servers ordered by (auth_order, created_at).
func ListAuthServers(ctx context.Context, s store, orgID uuid.UUID) ([]AuthServer, error) {
	rows, err := s.Query(ctx, `
SELECT id, org_id, type, name, enabled, auth_order, config, role_mapping, revision
  FROM auth_servers WHERE org_id = $1 ORDER BY auth_order, created_at`, orgID)
	if err != nil {
		return nil, fmt.Errorf("auth servers: list: %w", err)
	}
	defer rows.Close()
	var out []AuthServer
	for rows.Next() {
		srv, err := scanAuthServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}

// GetAuthServer returns a single row by id (scoped to org). Returns pgx.ErrNoRows when absent.
func GetAuthServer(ctx context.Context, s store, orgID, id uuid.UUID) (AuthServer, error) {
	row := s.QueryRow(ctx, `
SELECT id, org_id, type, name, enabled, auth_order, config, role_mapping, revision
  FROM auth_servers WHERE org_id = $1 AND id = $2`, orgID, id)
	return scanAuthServer(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAuthServer(row scanner) (AuthServer, error) {
	var s AuthServer
	var cfgRaw, rmRaw []byte
	if err := row.Scan(&s.ID, &s.OrgID, &s.Type, &s.Name, &s.Enabled, &s.AuthOrder, &cfgRaw, &rmRaw, &s.Revision); err != nil {
		return AuthServer{}, err
	}
	if len(cfgRaw) > 0 {
		if err := json.Unmarshal(cfgRaw, &s.Config); err != nil {
			return AuthServer{}, fmt.Errorf("auth servers: decode config: %w", err)
		}
	}
	if len(rmRaw) > 0 {
		if err := json.Unmarshal(rmRaw, &s.RoleMapping); err != nil {
			return AuthServer{}, fmt.Errorf("auth servers: decode role_mapping: %w", err)
		}
	}
	return s, nil
}

// CreateAuthServer inserts a validated row and returns it (with id + revision). A unique
// (org_id, name) collision surfaces as ErrNameConflict.
func CreateAuthServer(ctx context.Context, s store, srv AuthServer, sealer Sealer, updatedBy *uuid.UUID) (AuthServer, error) {
	if err := srv.Validate(); err != nil {
		return AuthServer{}, err
	}
	sealedCfg, err := sealConfigSecrets(srv.Config, sealer)
	if err != nil {
		return AuthServer{}, err
	}
	cfg, _ := json.Marshal(sealedCfg)
	rm, _ := json.Marshal(srv.RoleMapping)
	var id uuid.UUID
	var rev int64
	err = s.QueryRow(ctx, `
INSERT INTO auth_servers (org_id, type, name, enabled, auth_order, config, role_mapping, updated_by)
VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8)
RETURNING id, revision`,
		srv.OrgID, srv.Type, strings.TrimSpace(srv.Name), srv.Enabled, srv.AuthOrder, cfg, rm, updatedBy).Scan(&id, &rev)
	if err != nil {
		if isUniqueViolation(err) {
			return AuthServer{}, ErrNameConflict
		}
		return AuthServer{}, fmt.Errorf("auth servers: create: %w", err)
	}
	srv.ID, srv.Revision = id, rev
	return srv, nil
}

// UpdateAuthServer overwrites a row's mutable fields (scoped to org), bumping revision. Secrets
// left empty/redacted are preserved from the existing row. Returns pgx.ErrNoRows when absent.
func UpdateAuthServer(ctx context.Context, s store, srv AuthServer, sealer Sealer, updatedBy *uuid.UUID) (AuthServer, error) {
	prev, err := GetAuthServer(ctx, s, srv.OrgID, srv.ID)
	if err != nil {
		return AuthServer{}, err
	}
	// Type is immutable on update (it determines which provider is built); keep the stored type.
	srv.Type = prev.Type
	// mergeSecrets copies prev's stored (already-sealed) secret value for any field the caller left
	// empty/redacted; sealConfigSecrets is idempotent over those, only sealing a freshly-supplied
	// plaintext rotation.
	srv.mergeSecrets(prev)
	if err := srv.Validate(); err != nil {
		return AuthServer{}, err
	}
	sealedCfg, err := sealConfigSecrets(srv.Config, sealer)
	if err != nil {
		return AuthServer{}, err
	}
	cfg, _ := json.Marshal(sealedCfg)
	rm, _ := json.Marshal(srv.RoleMapping)
	var rev int64
	err = s.QueryRow(ctx, `
UPDATE auth_servers
   SET name=$3, enabled=$4, auth_order=$5, config=$6::jsonb, role_mapping=$7::jsonb,
       revision=revision+1, updated_at=now(), updated_by=$8
 WHERE org_id=$1 AND id=$2
RETURNING revision`,
		srv.OrgID, srv.ID, strings.TrimSpace(srv.Name), srv.Enabled, srv.AuthOrder, cfg, rm, updatedBy).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthServer{}, pgx.ErrNoRows
	}
	if err != nil {
		if isUniqueViolation(err) {
			return AuthServer{}, ErrNameConflict
		}
		return AuthServer{}, fmt.Errorf("auth servers: update: %w", err)
	}
	srv.Revision = rev
	return srv, nil
}

// DeleteAuthServer removes a row (scoped to org). Returns pgx.ErrNoRows when nothing was deleted.
func DeleteAuthServer(ctx context.Context, s store, orgID, id uuid.UUID) error {
	ct, err := s.Exec(ctx, `DELETE FROM auth_servers WHERE org_id=$1 AND id=$2`, orgID, id)
	if err != nil {
		return fmt.Errorf("auth servers: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// SeedAuthServer inserts a bootstrap (env/Helm-derived) provider row if no row of that type
// exists yet for the org. Idempotent: once any row of the type is present this is a no-op, so the
// DB then owns the provider. Returns true when a row was inserted.
func SeedAuthServer(ctx context.Context, s store, srv AuthServer, sealer Sealer) (bool, error) {
	if err := srv.Validate(); err != nil {
		return false, err
	}
	sealedCfg, err := sealConfigSecrets(srv.Config, sealer)
	if err != nil {
		return false, err
	}
	cfg, _ := json.Marshal(sealedCfg)
	rm, _ := json.Marshal(srv.RoleMapping)
	ct, err := s.Exec(ctx, `
INSERT INTO auth_servers (org_id, type, name, enabled, auth_order, config, role_mapping)
SELECT $1,$2,$3,$4,$5,$6::jsonb,$7::jsonb
 WHERE NOT EXISTS (SELECT 1 FROM auth_servers WHERE org_id=$1 AND type=$2)`,
		srv.OrgID, srv.Type, strings.TrimSpace(srv.Name), srv.Enabled, srv.AuthOrder, cfg, rm)
	if err != nil {
		return false, fmt.Errorf("auth servers: seed: %w", err)
	}
	return ct.RowsAffected() > 0, nil
}

// MaxRevision returns the org's highest auth_servers revision (0 when no rows). The poller
// compares it to detect any CRUD change cheaply without re-reading every row each tick.
func MaxRevision(ctx context.Context, s store, orgID uuid.UUID) (int64, error) {
	var rev int64
	err := s.QueryRow(ctx,
		`SELECT COALESCE(MAX(revision),0) FROM auth_servers WHERE org_id=$1`, orgID).Scan(&rev)
	if err != nil {
		return 0, err
	}
	return rev, nil
}

// ErrNameConflict is returned when a create/update would violate the unique (org_id, name).
var ErrNameConflict = errors.New("auth server: a server with that name already exists")

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "auth_servers_org_id_name_key")
}

// -------------------------- built provider instances -------------------------

// BuildProviders turns enabled rows into live provider instances, honoring auth_order. The first
// enabled provider of each type (lowest auth_order, ties by created_at via the query) wins, matching
// the historical single-instance-per-type wiring. A row that fails to build is skipped (logged by
// the caller via the returned errs) so one bad provider never disables the others.
//
// Returns the active OIDC/SAML/LDAP providers (any may be nil) plus the build errors.
func BuildProviders(ctx context.Context, srvs []AuthServer, sealer Sealer) (*OIDCClient, *SAMLProvider, *LDAPProvider, []error) {
	// Stable order by (auth_order, name) so the active pick is deterministic in tests.
	ordered := append([]AuthServer(nil), srvs...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].AuthOrder != ordered[j].AuthOrder {
			return ordered[i].AuthOrder < ordered[j].AuthOrder
		}
		return ordered[i].Name < ordered[j].Name
	})

	var oidc *OIDCClient
	var saml *SAMLProvider
	var ldap *LDAPProvider
	var errs []error
	for _, srv := range ordered {
		if !srv.Enabled {
			continue
		}
		// Decrypt the row's at-rest secret fields before building the live provider. A bad/unsealable
		// secret is treated like any other build failure: skip this provider, keep the others.
		openedCfg, oerr := openConfigSecrets(srv.Config, sealer)
		if oerr != nil {
			errs = append(errs, fmt.Errorf("%s %q: %w", srv.Type, srv.Name, oerr))
			continue
		}
		srv.Config = openedCfg
		switch srv.Type {
		case ServerTypeLDAP:
			if ldap != nil {
				continue
			}
			p, err := NewLDAPProvider(srv.toLDAPConfig())
			if err != nil {
				errs = append(errs, fmt.Errorf("ldap %q: %w", srv.Name, err))
				continue
			}
			ldap = p
		case ServerTypeSAML:
			if saml != nil {
				continue
			}
			p, err := NewSAMLProvider(srv.toSAMLConfig())
			if err != nil {
				errs = append(errs, fmt.Errorf("saml %q: %w", srv.Name, err))
				continue
			}
			saml = p
		case ServerTypeOIDC:
			if oidc != nil {
				continue
			}
			p, err := NewOIDCClient(ctx, srv.toOIDCConfig())
			if err != nil {
				errs = append(errs, fmt.Errorf("oidc %q: %w", srv.Name, err))
				continue
			}
			oidc = p
		}
	}
	return oidc, saml, ldap, errs
}

func (s AuthServer) toLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:            s.Config.URL,
		BindDN:         s.Config.BindDN,
		BindPassword:   s.Config.BindPassword,
		BaseDN:         s.Config.BaseDN,
		UserFilter:     s.Config.UserFilter,
		GroupAttribute: s.Config.GroupAttribute,
		EmailAttribute: s.Config.EmailAttribute,
		RoleMapping:    s.RoleMapping,
	}
}

func (s AuthServer) toSAMLConfig() SAMLConfig {
	return SAMLConfig{
		IdPMetadataXML: []byte(s.Config.IdPMetadataXML),
		EntityID:       s.Config.EntityID,
		ACSURL:         s.Config.ACSURL,
		SPCertPEM:      []byte(s.Config.SPCertPEM),
		SPKeyPEM:       []byte(s.Config.SPKeyPEM),
		GroupAttribute: s.Config.GroupAttribute,
		EmailAttribute: s.Config.EmailAttribute,
		RoleMapping:    s.RoleMapping,
	}
}

func (s AuthServer) toOIDCConfig() OIDCConfig {
	return OIDCConfig{
		IssuerURL:    s.Config.IssuerURL,
		ClientID:     s.Config.ClientID,
		ClientSecret: s.Config.ClientSecret,
		RedirectURL:  s.Config.RedirectURL,
		Scopes:       s.Config.Scopes,
		RoleMapping:  s.RoleMapping,
	}
}

// --------------------------- hot-reloadable set -----------------------------

// ProviderSet is the in-process, atomically-swappable set of active auth providers the login
// handler reads through. Reload() rebuilds it from the DB rows; the login handler's accessors
// (OIDC/SAML/LDAP) read the current snapshot lock-free. A nil *ProviderSet is safe: its accessors
// return nil (no provider), so callers degrade to "provider disabled" exactly as before B4.
type ProviderSet struct {
	cur atomic.Pointer[providerSnapshot]
	// sealer decrypts the at-rest IdP secret fields when Reload rebuilds the live providers. It is
	// the same install-KEK cipher Create/Update/Seed seal with; nil means no cipher (plaintext rows).
	sealer Sealer
}

type providerSnapshot struct {
	oidc *OIDCClient
	saml *SAMLProvider
	ldap *LDAPProvider
	rev  int64
}

// NewProviderSet returns an empty set (all providers nil). Reload populates it, decrypting at-rest
// secrets with sealer (nil = plaintext rows / no install KEK).
func NewProviderSet(sealer Sealer) *ProviderSet {
	ps := &ProviderSet{sealer: sealer}
	ps.cur.Store(&providerSnapshot{})
	return ps
}

// NewStaticProviderSet wraps already-built providers (used to preserve the env-wired providers as
// the initial snapshot before the first DB reload, and in tests). sealer is retained for the
// subsequent DB Reload that rebuilds the set from sealed rows.
func NewStaticProviderSet(oidc *OIDCClient, saml *SAMLProvider, ldap *LDAPProvider, sealer Sealer) *ProviderSet {
	ps := &ProviderSet{sealer: sealer}
	ps.cur.Store(&providerSnapshot{oidc: oidc, saml: saml, ldap: ldap})
	return ps
}

// OIDC returns the active OIDC client (nil if none/disabled). Safe on a nil *ProviderSet.
func (ps *ProviderSet) OIDC() *OIDCClient {
	if ps == nil {
		return nil
	}
	return ps.cur.Load().oidc
}

// SAML returns the active SAML provider (nil if none/disabled). Safe on a nil *ProviderSet.
func (ps *ProviderSet) SAML() *SAMLProvider {
	if ps == nil {
		return nil
	}
	return ps.cur.Load().saml
}

// LDAP returns the active LDAP provider (nil if none/disabled). Safe on a nil *ProviderSet.
func (ps *ProviderSet) LDAP() *LDAPProvider {
	if ps == nil {
		return nil
	}
	return ps.cur.Load().ldap
}

// Revision returns the DB revision the current snapshot was built from (0 if never reloaded).
func (ps *ProviderSet) Revision() int64 {
	if ps == nil {
		return 0
	}
	return ps.cur.Load().rev
}

// Reload rebuilds the snapshot from the org's enabled auth_servers rows and atomically swaps it
// in, so the login handler picks up the change WITHOUT a restart. It returns the build errors (a
// bad row is skipped, not fatal). Callers poll MaxRevision and only call Reload when it advances.
func (ps *ProviderSet) Reload(ctx context.Context, s store, orgID uuid.UUID) []error {
	srvs, err := ListAuthServers(ctx, s, orgID)
	if err != nil {
		return []error{err}
	}
	// A2: attach each server's cluster/namespace-scoped group->role grants (sso_role_mappings,
	// migration 125) onto its RoleMapping so the built provider's MapScopedRoles resolves them at
	// login. Best-effort per server: a load failure leaves that provider org-scope-only (its prior
	// behaviour) rather than dropping the provider.
	for i := range srvs {
		if scoped, serr := LoadScopedRoleMappings(ctx, s, srvs[i].ID); serr == nil {
			srvs[i].RoleMapping = srvs[i].RoleMapping.WithScopedRules(scoped)
		}
	}
	rev, _ := MaxRevision(ctx, s, orgID)
	oidc, saml, ldap, errs := BuildProviders(ctx, srvs, ps.sealer)
	ps.cur.Store(&providerSnapshot{oidc: oidc, saml: saml, ldap: ldap, rev: rev})
	return errs
}
