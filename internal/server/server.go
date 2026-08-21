// Package server wires the control-plane HTTP API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/astronomer"
	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/compliance"
	"github.com/alphabravocompany/constellation/internal/handler/findings"
	"github.com/alphabravocompany/constellation/internal/handler/k8saudit"
	"github.com/alphabravocompany/constellation/internal/handler/netpolicy"
	"github.com/alphabravocompany/constellation/internal/handler/network"
	"github.com/alphabravocompany/constellation/internal/handler/policy"
	"github.com/alphabravocompany/constellation/internal/handler/runtime"
	"github.com/alphabravocompany/constellation/internal/handler/scanning"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/observability"
	"github.com/alphabravocompany/constellation/pkg/rbac"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
	"github.com/alphabravocompany/constellation/pkg/version"
)

// Config is the constellation-api configuration.
type Config struct {
	ListenAddr  string
	DatabaseURL string
	JWTKeys     [][]byte // active key in [0]; older keys still accepted
	JWTIssuer   string
	JWTAudience string
	JWTTTL      time.Duration
	// SessionIdleTimeout is the inactivity window (A7). A JWT session whose
	// last authenticated request is older than this is rejected even though the
	// JWT itself is unexpired (it sits inside the absolute JWTTTL). Zero disables
	// idle expiry, leaving only the absolute TTL.
	SessionIdleTimeout time.Duration
	// PATMaxLifetime caps how far in the future a minted PAT's expires_at may be,
	// and forbids unbounded (never-expiring) PATs (A7). Zero disables the cap
	// (back-compat: any expiry, including none, is accepted).
	PATMaxLifetime       time.Duration
	OIDC                 *auth.OIDCConfig // nil to disable OIDC login
	SAML                 *auth.SAMLConfig // nil to disable SAML login
	LDAP                 *auth.LDAPConfig // nil to disable LDAP login
	CORSOrigins          []string
	AstronomerJWKSURL    string // empty to disable Astronomer adapter
	AstronomerIssuer     string // optional iss claim required for Astronomer JWTs
	AstronomerAudience   string // optional aud claim required for Astronomer JWTs
	VulnDBReadyRequired  bool
	VulnDBReadyMaxAge    time.Duration
	VulnDBRescanInterval time.Duration

	RepositoryScanRetentionEnabled   bool
	RepositoryScanRetentionMaxAge    time.Duration
	RepositoryScanRetentionInterval  time.Duration
	RepositoryScanRetentionBatchSize int
	RepositoryScanRetentionDryRun    bool
}

// Server holds the HTTP server + its dependencies.
type Server struct {
	cfg      Config
	tel      *observability.Telemetry
	db       *db.DB
	auditLog *audit.Logger
	signer   *auth.Signer
	// fedSigner signs/verifies federation join tokens + per-cluster sync tickets (D1). It
	// is loaded from the dedicated fed_signing_keys table (auto-generated on first boot)
	// so federation trust is isolated from user-session signing. nil only if the key load
	// failed (the fed trust surface then reports 501).
	fedSigner *auth.FedSigner
	// fedCA is the federation CA (D2) that mints a per-joint client certificate at join and
	// anchors mTLS verification on /sync. Loaded (or first-boot generated) from fed_ca with
	// its private key encrypted under the install KEK. nil when no KEK/cipher is available;
	// the fed surface then stays on the D1 bearer-only path.
	fedCA *auth.FedCA
	// dbBackedSessionKeys is true when the session signer was loaded from the
	// session_signing_keys table (no operator JWT_KEYS). Only then does Run start
	// the A5 rotation poller that hot-reloads the signer after --rotate-jwt-key.
	dbBackedSessionKeys bool
	oidc                *auth.OIDCClient
	saml                *auth.SAMLProvider
	ldap                *auth.LDAPProvider
	dispatcher          *notify.Dispatcher
	router              chi.Router
	astronomerJWT       *astronomer.Validator
	astronomerMap       *astronomer.Mapper
	// live is the optional in-memory conversation-graph cache + SSE fan-out
	// (plan B5). nil unless CONSTELLATION_LIVEGRAPH is enabled; when nil every
	// consumer degrades to the durable Postgres path (default behavior).
	live *livegraph.Store
	// customRoles resolves org-defined RBAC roles for the authz gate (G5).
	customRoles *handler.CustomRoles
	// syscfg is the B1 runtime-mutable system-config accessor. The GET/PATCH handler
	// writes through it and the consumers (shared outbound HTTP client + syslog/SIEM
	// sender) read the live config from it; a background reloader polls each org's
	// revision so a PATCH propagates to every replica without a restart.
	syscfg *syscfg.Provider
	// authProviders is the B4 DB-backed, hot-reloadable auth-provider (IdP) set the login
	// handler reads the live LDAP/SAML/OIDC providers through. It is seeded from the env-wired
	// providers on first boot, then owned by the auth_servers rows; a background reloader polls
	// the max revision so a CRUD change rebuilds the live verifier set without a restart.
	authProviders *auth.ProviderSet
	// bootstrapOrgID is the org whose auth_servers rows drive the process-wide provider set
	// (the auth endpoints are anonymous, so the provider set is single-instance per process,
	// matching the historical env-wired model). Defaults to the first org at boot.
	bootstrapOrgID uuid.UUID
	// sealer is the install-KEK cipher (H2) the auth-server CRUD handler seals IdP secret fields
	// with before persisting them to auth_servers.config. nil when no KEK is available.
	sealer auth.Sealer
}

// New constructs the server. Caller must Run() and Shutdown().
func New(ctx context.Context, cfg Config, tel *observability.Telemetry, database *db.DB) (*Server, error) {
	// A5: session JWTs are signed RS256 by default. When no JWT_KEYS env secret is
	// provided we load (or first-boot generate + persist) a shared RSA keypair from the
	// session_signing_keys table so every replica signs with the same key and a rotation
	// keeps prior tokens valid until they expire. An explicit JWTKeys (env-provided HS256
	// secret or PEM key) still wins, preserving the operator-supplied-key path.
	keys := cfg.JWTKeys
	dbBackedSessionKeys := false
	if len(keys) == 0 {
		loaded, err := auth.LoadSessionKeysPEM(ctx, database.Pool())
		if err != nil {
			return nil, err
		}
		keys = loaded
		dbBackedSessionKeys = true
	}
	signer, err := auth.NewSigner(cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTL, keys...)
	if err != nil {
		return nil, err
	}
	// D1: load (or first-boot generate) the dedicated federation signing keypair so the
	// master can mint signed join tokens / per-cluster sync tickets without any operator
	// secret, and every replica shares one fed identity. Best-effort: a load failure
	// disables the fed trust surface (501) rather than failing startup.
	var fedSigner *auth.FedSigner
	if fedKeys, ferr := auth.LoadFedSigningKeysPEM(ctx, database.Pool()); ferr != nil {
		tel.Logger.Warn("federation signing key load failed; fed trust handshake disabled", slog.String("err", ferr.Error()))
	} else if fs, ferr := auth.NewFedSigner(fedKeys...); ferr != nil {
		tel.Logger.Warn("federation signer build failed; fed trust handshake disabled", slog.String("err", ferr.Error()))
	} else {
		fedSigner = fs
	}
	// D2: load (or first-boot generate) the federation CA so a master mints a per-joint
	// client certificate at join and verifies it on every /sync poll (mutual auth). The CA
	// private key is sealed under the install KEK (the registry-secrets cipher). Best-effort:
	// a cipher/CA failure leaves fedCA nil — the fed surface then stays on the D1 bearer-only
	// path rather than failing startup.
	var fedCA *auth.FedCA
	// sealer is the install-KEK cipher used to seal at-rest secrets: the fed-CA key, registry creds,
	// and (H2) the IdP secret fields in auth_servers.config. nil when no KEK is available, in which
	// case those paths fall back to their pre-seal behavior rather than failing startup.
	var sealer auth.Sealer
	if cipher, cerr := regsecrets.Default(ctx, database.Pool(), tel.Logger); cerr != nil {
		tel.Logger.Warn("install KEK cipher unavailable; per-joint mTLS + IdP secret sealing disabled", slog.String("err", cerr.Error()))
	} else {
		sealer = cipher
		if ca, lerr := auth.LoadFedCA(ctx, database.Pool(), cipher); lerr != nil {
			tel.Logger.Warn("federation CA load failed; per-joint mTLS disabled", slog.String("err", lerr.Error()))
		} else {
			fedCA = ca
		}
	}
	var oidcClient *auth.OIDCClient
	if cfg.OIDC != nil {
		c, err := auth.NewOIDCClient(ctx, *cfg.OIDC)
		if err != nil {
			tel.Logger.Warn("OIDC discovery failed; OIDC login disabled", slog.String("err", err.Error()))
		} else {
			oidcClient = c
		}
	}
	// Per-deployment SAML/LDAP, mirroring OIDC: build the provider once, warn-and-disable on
	// misconfig rather than failing startup.
	var samlProvider *auth.SAMLProvider
	if cfg.SAML != nil {
		p, err := auth.NewSAMLProvider(*cfg.SAML)
		if err != nil {
			tel.Logger.Warn("SAML setup failed; SAML login disabled", slog.String("err", err.Error()))
		} else {
			samlProvider = p
		}
	}
	var ldapProvider *auth.LDAPProvider
	if cfg.LDAP != nil {
		p, err := auth.NewLDAPProvider(*cfg.LDAP)
		if err != nil {
			tel.Logger.Warn("LDAP setup failed; LDAP login disabled", slog.String("err", err.Error()))
		} else {
			ldapProvider = p
		}
	}
	// B4: the auth-provider set starts as the env-wired providers (so behavior is unchanged
	// before the first DB reload), then a first-boot seed writes them into auth_servers and the
	// background reloader makes the DB rows the source of truth — runtime IdP CRUD takes effect
	// without a restart.
	authProviders := auth.NewStaticProviderSet(oidcClient, samlProvider, ldapProvider, sealer)
	// B1: the system-config accessor is built here so the dispatcher's syslog/SIEM
	// mirror reads the LIVE target (consumer b) through the same Provider the HTTP
	// handler writes to.
	sysCfgProvider := syscfg.NewProvider(database.Pool())
	dispatcher := notify.NewDispatcher(database.Pool(), notify.DispatcherConfig{
		Logger:       tel.Logger,
		SyslogTarget: sysCfgProvider.SyslogSender,
		SMTPServer:   sysCfgProvider.SMTPSender,
	})
	dispatcher.Start(ctx)
	var astronomerJWT *astronomer.Validator
	var astronomerMap *astronomer.Mapper
	if strings.TrimSpace(cfg.AstronomerJWKSURL) != "" {
		opts := []astronomer.ValidatorOption{}
		if cfg.AstronomerIssuer != "" {
			opts = append(opts, astronomer.WithIssuer(cfg.AstronomerIssuer))
		}
		if cfg.AstronomerAudience != "" {
			opts = append(opts, astronomer.WithAudience(cfg.AstronomerAudience))
		}
		astronomerJWT = astronomer.NewValidator(cfg.AstronomerJWKSURL, opts...)
		astronomerMap = astronomer.NewMapper(database.Pool())
	}
	// Plan B5: opt-in in-memory conversation graph + StreamFlows SSE. Off by
	// default so the durable Postgres path stays the only behavior unless a
	// deployment sets CONSTELLATION_LIVEGRAPH=1 (TTL overridable for tuning).
	var liveStore *livegraph.Store
	if livegraphEnabled() {
		liveStore = livegraph.New(livegraph.Config{TTL: livegraphTTL()})
		tel.Logger.Info("livegraph enabled (in-memory conversation graph + StreamFlows SSE)")
	}
	s := &Server{
		cfg:                 cfg,
		tel:                 tel,
		db:                  database,
		auditLog:            audit.New(database.Pool()),
		signer:              signer,
		fedSigner:           fedSigner,
		fedCA:               fedCA,
		dbBackedSessionKeys: dbBackedSessionKeys,
		oidc:                oidcClient,
		saml:                samlProvider,
		ldap:                ldapProvider,
		dispatcher:          dispatcher,
		astronomerJWT:       astronomerJWT,
		astronomerMap:       astronomerMap,
		live:                liveStore,
		customRoles:         handler.NewCustomRoles(database.Pool()),
		syscfg:              sysCfgProvider,
		authProviders:       authProviders,
		sealer:              sealer,
	}
	// B1: seed each existing org's system_config from env BOOTSTRAP DEFAULTS on first
	// boot (idempotent — a row already present wins), then the DB row is source of
	// truth. Best-effort: a seed error is logged, not fatal, since the accessor falls
	// back to Default() and a later PATCH still creates the row.
	if err := seedSystemConfig(ctx, database.Pool(), s.syscfg, tel); err != nil {
		tel.Logger.Warn("system config seed failed", slog.String("err", err.Error()))
	}
	// B4: pick the bootstrap org, seed the env-wired IdPs into auth_servers on first boot
	// (idempotent — a row of a type already present wins), then load the live provider set
	// from the DB so the rows are the source of truth. Best-effort: a failure leaves the
	// env-wired static set in place.
	if id, ok := firstOrgID(ctx, database.Pool()); ok {
		s.bootstrapOrgID = id
		seedAuthServers(ctx, database.Pool(), id, cfg, sealer, tel)
		if errs := s.authProviders.Reload(ctx, database.Pool(), id); len(errs) > 0 {
			for _, e := range errs {
				tel.Logger.Warn("auth provider build (seed reload)", slog.String("err", e.Error()))
			}
		}
	}
	s.router = s.buildRouter()
	return s, nil
}

// firstOrgID returns the lowest-created org's id (the bootstrap org whose auth_servers rows drive
// the process-wide provider set). Returns false when no org exists yet.
func firstOrgID(ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, bool) {
	var id uuid.UUID
	err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at, id LIMIT 1`).Scan(&id)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// seedAuthServers writes the env/Helm-wired LDAP/SAML/OIDC providers into auth_servers as
// bootstrap rows for org if no row of that type exists yet (so the DB then owns them). Best-effort:
// a seed error is logged, not fatal — the static provider set stays in effect until a row exists.
func seedAuthServers(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, cfg Config, sealer auth.Sealer, tel *observability.Telemetry) {
	var seeds []auth.AuthServer
	if cfg.OIDC != nil {
		seeds = append(seeds, auth.AuthServer{
			OrgID: orgID, Type: auth.ServerTypeOIDC, Name: "oidc (bootstrap)", Enabled: true, AuthOrder: 100,
			Config: auth.ServerConfig{
				IssuerURL:    cfg.OIDC.IssuerURL,
				ClientID:     cfg.OIDC.ClientID,
				ClientSecret: cfg.OIDC.ClientSecret,
				RedirectURL:  cfg.OIDC.RedirectURL,
				Scopes:       cfg.OIDC.Scopes,
			},
		})
	}
	if cfg.SAML != nil {
		seeds = append(seeds, auth.AuthServer{
			OrgID: orgID, Type: auth.ServerTypeSAML, Name: "saml (bootstrap)", Enabled: true, AuthOrder: 100,
			Config: auth.ServerConfig{
				IdPMetadataXML: string(cfg.SAML.IdPMetadataXML),
				EntityID:       cfg.SAML.EntityID,
				ACSURL:         cfg.SAML.ACSURL,
				SPCertPEM:      string(cfg.SAML.SPCertPEM),
				SPKeyPEM:       string(cfg.SAML.SPKeyPEM),
				GroupAttribute: cfg.SAML.GroupAttribute,
				EmailAttribute: cfg.SAML.EmailAttribute,
			},
			RoleMapping: cfg.SAML.RoleMapping,
		})
	}
	if cfg.LDAP != nil {
		seeds = append(seeds, auth.AuthServer{
			OrgID: orgID, Type: auth.ServerTypeLDAP, Name: "ldap (bootstrap)", Enabled: true, AuthOrder: 100,
			Config: auth.ServerConfig{
				URL:            cfg.LDAP.URL,
				BindDN:         cfg.LDAP.BindDN,
				BindPassword:   cfg.LDAP.BindPassword,
				BaseDN:         cfg.LDAP.BaseDN,
				UserFilter:     cfg.LDAP.UserFilter,
				GroupAttribute: cfg.LDAP.GroupAttribute,
				EmailAttribute: cfg.LDAP.EmailAttribute,
			},
			RoleMapping: cfg.LDAP.RoleMapping,
		})
	}
	for _, srv := range seeds {
		if _, err := auth.SeedAuthServer(ctx, pool, srv, sealer); err != nil {
			tel.Logger.Warn("auth server seed failed",
				slog.String("type", srv.Type), slog.String("err", err.Error()))
		}
	}
}

// seedSystemConfig seeds env-derived bootstrap defaults into every existing org's
// system_config row if absent, and warms the Provider cache for each. New orgs created
// later get Default() via the accessor's load-or-default path until their first PATCH.
func seedSystemConfig(ctx context.Context, pool *pgxpool.Pool, p *syscfg.Provider, tel *observability.Telemetry) error {
	defaults := syscfg.DefaultsFromEnv()
	rows, err := pool.Query(ctx, `SELECT id FROM orgs`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		cfg, rev, err := syscfg.Seed(ctx, pool, id, defaults)
		if err != nil {
			tel.Logger.Warn("system config seed (org) failed",
				slog.String("org", id.String()), slog.String("err", err.Error()))
			continue
		}
		p.UpdateAfterPatch(id, cfg, rev)
	}
	return nil
}

// livegraphEnabled reports whether the plan-B5 in-memory conversation graph +
// StreamFlows SSE is turned on. Off unless CONSTELLATION_LIVEGRAPH is a truthy
// value (1/true/yes/on).
func livegraphEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_LIVEGRAPH"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// livegraphTTL is the hot-graph retention window; defaults to 1h and is
// overridable via CONSTELLATION_LIVEGRAPH_TTL (a Go duration, e.g. "30m").
func livegraphTTL() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("CONSTELLATION_LIVEGRAPH_TTL"))); err == nil && d > 0 {
		return d
	}
	return time.Hour
}

// fedJoinConfig reads the (non-hardcoded) federation join knobs from env. These are
// the D1 home for the join-token TTL, per-cluster secret TTL, and the optional
// pre-shared fixed join token for GitOps joins. They live in env/syscfg (B1) rather
// than being baked into the handler so the values can be tuned per deployment and the
// fixed token is never a compile-time constant.
//
//   - CONSTELLATION_FED_JOIN_TOKEN_TTL  (Go duration, default 30m): minted join token life.
//   - CONSTELLATION_FED_SECRET_TTL      (Go duration, default 0 = no expiry): per-cluster
//     sync ticket life; revocation is otherwise via epoch bump on kick/leave.
//   - CONSTELLATION_FED_JOIN_TOKEN      (string, empty disables): pre-shared GitOps token.
func (s *Server) fedJoinConfig() handler.FedJoinConfig {
	joinTTL := 30 * time.Minute
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("CONSTELLATION_FED_JOIN_TOKEN_TTL"))); err == nil && d > 0 {
		joinTTL = d
	}
	var secretTTL time.Duration
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("CONSTELLATION_FED_SECRET_TTL"))); err == nil && d > 0 {
		secretTTL = d
	}
	return handler.FedJoinConfig{
		JoinTokenTTL: joinTTL,
		SecretTTL:    secretTTL,
		FixedToken:   strings.TrimSpace(os.Getenv("CONSTELLATION_FED_JOIN_TOKEN")),
	}
}

// fedMTLSCA returns the federation CA to wire into Join + the /sync middleware, gated on
// the D2 per-joint mTLS toggle (CONSTELLATION_FED_MTLS). It is OFF by default because the
// controller's TLS is terminated externally (ingress) in a default deployment, so
// r.TLS.PeerCertificates would be empty and enforcing the client cert would reject every
// poll. An operator enables it once the fed path terminates mTLS at the controller (TLS
// passthrough / in-process mTLS): joins then issue a per-joint client cert and /sync
// requires it. When OFF this returns nil, leaving the D1 bearer-only behaviour intact.
//
// This is the syscfg/B1 home for fed peer/CA config — nothing about the trust material is
// hardcoded; the toggle (and the CA itself) come from config and the DB.
func (s *Server) fedMTLSCA() *auth.FedCA {
	if !fedMTLSEnabled() {
		return nil
	}
	return s.fedCA
}

// fedMTLSEnabled reports whether D2 per-joint mTLS enforcement is turned on.
func fedMTLSEnabled() bool {
	return envBool("CONSTELLATION_FED_MTLS", false)
}

// fedMTLSClientCertHeader is the (optional) trusted-terminator header carrying the verified
// per-joint client certificate when the controller's TLS is terminated by an ingress rather
// than in-process (the documented two-cluster topology). Empty (default) restricts the /sync
// client-cert check to a directly-terminated mTLS handshake (r.TLS). When set — e.g.
// ingress-nginx's `ssl-client-cert` — the ingress MUST perform the real mTLS handshake AND
// strip any client-supplied copy of this header, otherwise a caller could spoof it. This is
// the syscfg/B1 home for the fed mTLS terminator config; nothing is hardcoded.
func fedMTLSClientCertHeader() string {
	return strings.TrimSpace(os.Getenv("CONSTELLATION_FED_MTLS_CLIENT_CERT_HEADER"))
}

// authorizeSubject reports whether subj holds verb in its own org scope, honoring org-defined
// custom roles (the same gate requireVerb applies). The D3 proxy uses it to decide whether a
// caller is a federation admin (may forward mutating verbs) or a read-only non-admin.
func (s *Server) authorizeSubject(ctx context.Context, subj authctx.Subject, verb rbac.Verb) bool {
	if !subj.HasTokenScope(verb) {
		return false
	}
	var custom map[string][]rbac.Verb
	if s.customRoles != nil {
		custom = s.customRoles.VerbsForOrg(ctx, subj.OrgID)
	}
	return rbac.AuthorizeWithCustom(subj.Assignments, verb, rbac.Resource{OrgID: subj.OrgID}, custom) == nil
}

// fedProxyReadAllowlist reads the optional override for the D3 non-admin cross-cluster read
// allowlist from env (B1 home for fed proxy config). CONSTELLATION_FED_PROXY_READ_PATHS is a
// comma-separated list of first path segments a non-admin may GET through the proxy; empty
// leaves the handler's built-in default. Nothing is hardcoded into policy here.
func (s *Server) fedProxyReadAllowlist() []string {
	raw := strings.TrimSpace(os.Getenv("CONSTELLATION_FED_PROXY_READ_PATHS"))
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// corsAllowedOrigins sanitizes the configured CORS allow-list for use with
// AllowCredentials:true. The CORS spec forbids reflecting credentials to a wildcard
// origin, so any "*" (or empty/whitespace) entry is dropped rather than silently
// widening access to every site. An empty result means the configured list carried
// only wildcard/blank entries; callers MUST NOT hand an empty slice straight to
// go-chi/cors (which reads it as "allow all") — buildRouter pairs an empty result
// with a deny-all AllowOriginFunc so cross-origin browser requests are refused
// (same-origin only), never wildcarded.
func corsAllowedOrigins(origins []string) []string {
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "" || o == "*" {
			continue
		}
		out = append(out, o)
	}
	return out
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	// SECURITY: honor X-Forwarded-For / X-Real-IP ONLY when the direct peer is a
	// trusted proxy. Bare chimw.RealIP rewrites RemoteAddr from those headers for
	// every client, letting an attacker spoof its source IP and mint a fresh
	// per-IP auth rate-limit bucket per request (credential-spray bypass).
	r.Use(s.trustedProxyRealIP())
	r.Use(chimw.Recoverer)
	r.Use(s.slogMiddleware)
	r.Use(s.tel.HTTPMiddleware)
	// A8 CORS/CSRF hardening:
	//   - We authenticate exclusively via a bearer token in the Authorization header
	//     (see authMiddleware — it reads only `Authorization: Bearer …`, never a cookie).
	//     The browser does not attach the Authorization header automatically, so a
	//     cross-site form/img/script cannot forge an authenticated mutation: this API
	//     is structurally CSRF-immune. A CSRF-token middleware would only be required if
	//     a cookie-authenticated mutation path is ever introduced — if you add one, add
	//     double-submit / SameSite=strict CSRF protection alongside it.
	//   - AllowCredentials is true, so per the Fetch spec the wildcard origin "*" is
	//     forbidden (a wildcard with credentials would let any site read responses).
	//     corsAllowedOrigins drops any "*"/empty entry defensively; if that leaves the
	//     list empty we install a deny-all AllowOriginFunc below, so no cross-origin
	//     browser request is permitted (same-origin only) rather than go-chi's
	//     empty-list "allow all" default.
	corsOpts := cors.Options{
		AllowedOrigins:   corsAllowedOrigins(s.cfg.CORSOrigins),
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-Id", "Idempotency-Key"},
		AllowCredentials: true,
		MaxAge:           300,
	}
	// go-chi/cors treats an empty AllowedOrigins (with no AllowOriginFunc) as
	// "allow all", reflecting a wildcard Access-Control-Allow-Origin — the exact
	// opposite of the same-origin-only intent when every configured entry was a
	// "*"/blank that corsAllowedOrigins dropped. Install a deny-all origin func so
	// an empty allow-list rejects every cross-origin request instead.
	if len(corsOpts.AllowedOrigins) == 0 {
		corsOpts.AllowOriginFunc = func(*http.Request, string) bool { return false }
	}
	r.Use(cors.Handler(corsOpts))

	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)
	r.Get("/version", s.handleVersion) // root-level convenience mirror of /api/v1/version
	r.Get("/metrics", s.tel.MetricsHandler().ServeHTTP)
	// Runtime profiling, mounted on the same listener as /metrics and OFF by
	// default. net/http/pprof is unauthenticated and exposes heap/goroutine/CPU
	// profiles, so it must only be enabled in a trusted environment.
	if os.Getenv("CONSTELLATION_ENABLE_PPROF") == "true" {
		r.HandleFunc("/debug/pprof/*", pprof.Index)
		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	r.Get("/openapi.json", handler.OpenAPISpec)

	r.Route("/api/v1", func(r chi.Router) {
		// A3: a lenient global per-token request ceiling on /api/v1/* — an abuse circuit
		// breaker, not a fairness throttle. Keyed by the bearer token (JWT or PAT) so one
		// credential cannot saturate the API; keyless requests fall back to the client IP.
		// The limit is deliberately high (well above any interactive UI burst).
		r.Use(httprate.Limit(
			apiTokenRateLimit, time.Minute,
			httprate.WithKeyFuncs(apiRateLimitKey),
			httprate.WithLimitHandler(rateLimited),
		))

		// Process Baseline lifecycle handler (Wave L4 / WS-F2). Constructed once at
		// /api/v1 scope so its in-memory state map is shared across the user-JWT route
		// group (List/Get/SetMode) and the runtime-agent ingest group, where
		// baselines.BaselineMode feeds the events-ingest drift classifier.
		baselines := runtime.NewBaselines(s.db, s.auditLog)

		// Anonymous endpoints. A3: a strict per-IP rate limit on the unauthenticated
		// /auth/* surface (login/OIDC/SAML/LDAP) blunts credential-stuffing /
		// password-spray from a single source — complementing the per-account lockout
		// (A2), which a botnet rotating accounts would otherwise sidestep. RealIP (set in
		// buildRouter) feeds httprate the real client address behind the proxy.
		auth := handler.NewAuth(s.db, s.signer, s.oidc, s.saml, s.ldap, s.auditLog).WithProviderSet(s.authProviders)
		r.Group(func(r chi.Router) {
			r.Use(httprate.Limit(
				authIPRateLimit, time.Minute,
				httprate.WithKeyByIP(),
				httprate.WithLimitHandler(rateLimited),
			))
			r.Post("/auth/login", auth.Login)
			r.Get("/auth/oidc/start", auth.OIDCStart)
			r.Get("/auth/oidc/callback", auth.OIDCCallback)
			r.Get("/auth/saml/login", auth.SAMLLogin)
			r.Post("/auth/saml/acs", auth.SAMLACS)
			r.Post("/auth/ldap/login", auth.LDAPLogin)
			// D1: federation join/exchange. Anonymous like /auth/login — the request is
			// authenticated by the join token it carries (a signed, master-minted token or
			// the pre-shared fixed token), and returns a per-cluster sync secret. Shares the
			// strict per-IP rate limit so a stolen-but-expired join token can't be brute-forced.
			anonFed := handler.NewFederation(s.db, s.auditLog).WithFedTrust(s.fedSigner, s.fedJoinConfig()).WithFedCA(s.fedMTLSCA())
			r.Post("/federation/join", anonFed.Join)
			// One-command cluster join (Rancher /v3/import equivalent): the URL token
			// IS the runtime-agent join credential, so it's anonymous + IP-rate-limited.
			// Serves a self-contained agent manifest pointed at this control-plane's FQDN.
			clusterImport := handler.NewClusterImport(s.db)
			r.Get("/import/{filename}", clusterImport.Manifest)
		})

		// Authenticated endpoints
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Post("/auth/logout", auth.Logout)
			r.Post("/auth/change-password", auth.ChangePassword)
			r.Get("/auth/me", auth.Me)

			findingsH := findings.NewFindings(s.db, s.auditLog, s.dispatcher)
			r.Get("/findings", s.requireVerb(rbac.VerbReadFindings, findingsH.List))
			r.Get("/findings/by-cve", s.requireVerb(rbac.VerbReadFindings, findingsH.ByCVE))
			eventsExport := runtime.NewEventsExport(s.db.Pool())
			r.Get("/events:export", s.requireVerb(rbac.VerbReadFindings, eventsExport.Export))
			r.Get("/findings/{id}", s.requireVerb(rbac.VerbReadFindings, findingsH.Get))
			r.Post("/findings/{id}/triage", s.requireVerb(rbac.VerbTriageFindings, findingsH.Triage))
			r.Post("/findings/{id}/suppress", s.requireVerb(rbac.VerbSuppressFindings, findingsH.Suppress))
			r.Post("/findings/{id}/accept-risk", s.requireVerb(rbac.VerbAcceptRisk, findingsH.AcceptRisk))
			r.Post("/findings/{id}/reachability", s.requireVerb(rbac.VerbTriageFindings, findingsH.Reachability))

			comments := findings.NewComments(s.db, s.auditLog)
			r.Get("/findings/{id}/comments", s.requireVerb(rbac.VerbReadFindings, comments.List))
			r.Post("/findings/{id}/comments", s.requireVerb(rbac.VerbTriageFindings, comments.Create))

			csv := findings.NewFindingsCSV(s.db)
			r.Get("/findings.csv", s.requireVerb(rbac.VerbReadFindings, csv.Stream))

			deps := handler.NewDeployments(s.db, s.auditLog).
				WithNetworkPolicyLookup(netpolicy.NewNetworkPolicies(s.db).LifecycleForWorkload)
			r.Get("/deployments", s.requireVerb(rbac.VerbReadFindings, deps.List))
			r.Get("/deployments/{id}", s.requireVerb(rbac.VerbReadFindings, deps.Get))
			r.Get("/violations", s.requireVerb(rbac.VerbReadFindings, deps.Violations))

			networkMap := network.NewNetwork(s.db)
			r.Get("/network/map", s.requireVerb(rbac.VerbReadFindings, networkMap.Map))
			r.Get("/network/exposure", s.requireVerb(rbac.VerbReadFindings, networkMap.Exposure))
			r.Get("/network/peers", s.requireVerb(rbac.VerbReadFindings, networkMap.Peers))
			r.Get("/network/sessions", s.requireVerb(rbac.VerbReadFindings, networkMap.Sessions))
			r.Get("/network/sessions/summary", s.requireVerb(rbac.VerbReadFindings, networkMap.SessionsSummary))
			r.Delete("/network/sessions/{id}", s.requireVerb(rbac.VerbManagePolicies, networkMap.KillSession))
			r.Get("/clusters/{id}/network-rules", s.requireVerb(rbac.VerbReadFindings, networkMap.NetworkRules))
			r.Post("/clusters/{id}/network-rules", s.requireVerb(rbac.VerbManagePolicies, networkMap.UpsertNetworkRule))
			r.Put("/clusters/{id}/network-rules", s.requireVerb(rbac.VerbManagePolicies, networkMap.UpsertNetworkRule))
			r.Delete("/clusters/{id}/network-rules", s.requireVerb(rbac.VerbManagePolicies, networkMap.DeleteNetworkRule))
			r.Post("/clusters/{id}/network-rules:move-top", s.requireVerb(rbac.VerbManagePolicies, networkMap.MoveNetworkRuleToTop))

			// Wave 5: user-facing list of DPI threats. Same auth as findings.
			runtimeThreats := runtime.NewRuntimeThreats(s.db)
			r.Get("/runtime-threats", s.requireVerb(rbac.VerbReadFindings, runtimeThreats.List))
			// Wave 5b: per-id drilldown — returns the captured packet bytes
			// (base64-encoded) plus a parsed L7 preview (HTTP/DNS/TLS).
			r.Get("/runtime-threats/{id}", s.requireVerb(rbac.VerbReadFindings, runtimeThreats.Get))

			// B1: unified incident timeline — merges DPI threats + runtime
			// events + network violations + audit into one time-ordered stream.
			// Read-only aggregation over existing tables (same auth as findings).
			securityTimeline := handler.NewSecurityTimeline(s.db)
			r.Get("/security/timeline", s.requireVerb(rbac.VerbReadFindings, securityTimeline.List))
			// B8: score what-if. Recomputes the projected risk score if a set of
			// findings were resolved. Read-only projection; never mutates state.
			scorePredict := handler.NewScorePredict(s.db)
			r.Post("/security/score/predict", s.requireVerb(rbac.VerbReadFindings, scorePredict.Predict))

			// C1: Kubernetes control-plane audit events (exec/secret/RBAC/
			// privileged-create). Same read-findings gate as the threats list.
			k8sAudit := k8saudit.NewIngest(s.db)
			r.Get("/k8s-audit", s.requireVerb(k8sAudit.VerbList(), k8sAudit.List))

			// Wave B1: runtime_policies CRUD. Promote/demote/disable are
			// dedicated routes (separate from PUT) so the UI confirmation
			// dialogs can hit distinct endpoints.
			rtPolicies := runtime.NewRuntimePoliciesHTTP(s.db, s.auditLog)
			r.Get("/runtime-policies", s.requireVerb(rbac.VerbReadFindings, rtPolicies.List))
			r.Get("/runtime-policies/{id}", s.requireVerb(rbac.VerbReadFindings, rtPolicies.Get))
			r.Post("/runtime-policies", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.Create))
			r.Put("/runtime-policies/{id}", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.Update))
			r.Post("/runtime-policies/{id}/promote", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.Promote))
			r.Post("/runtime-policies/{id}/demote", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.Demote))
			r.Post("/runtime-policies/{id}/disable", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.Disable))
			r.Delete("/runtime-policies/{id}", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.Delete))
			// Wave B2/B3: match-stats (saved) + simulate (candidate). Read
			// verb on both — neither mutates state.
			r.Get("/runtime-policies/{id}/match-stats", s.requireVerb(rbac.VerbReadFindings, rtPolicies.MatchStats))
			r.Post("/runtime-policies/{id}/simulate", s.requireVerb(rbac.VerbReadFindings, rtPolicies.Simulate))
			// Wave B4: threat-aware auto-generation. :generate is a preview
			// (read-findings); :apply-generated inserts a new row in
			// monitor mode (manage-policies).
			r.Post("/runtime-policies:generate", s.requireVerb(rbac.VerbReadFindings, rtPolicies.Generate))
			r.Post("/runtime-policies:apply-generated", s.requireVerb(rbac.VerbManagePolicies, rtPolicies.ApplyGenerated))
			// Wave D1: export an existing policy as NetworkPolicy YAML
			// (native / cilium / calico). Critical for Cilium clusters
			// where dp's NFQUEUE path is bypassed — operator exports
			// CiliumNetworkPolicy and applies it via kubectl.
			r.Get("/runtime-policies/{id}/export", s.requireVerb(rbac.VerbReadFindings, rtPolicies.Export))

			// Wave C4: DLP regex rules. Same mode vocabulary as runtime_policies
			// (monitor / enforce / disabled) and same audit-action mapping.
			rtDLP := runtime.NewRuntimeDLPHTTP(s.db, s.auditLog)
			r.Get("/runtime-dlp-rules", s.requireVerb(rbac.VerbReadFindings, rtDLP.List))
			r.Get("/runtime-dlp-rules:export", s.requireVerb(rbac.VerbReadFindings, rtDLP.Export))
			r.Post("/runtime-dlp-rules:import", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Import))
			r.Get("/runtime-dlp-rules/{id}", s.requireVerb(rbac.VerbReadFindings, rtDLP.Get))
			r.Post("/runtime-dlp-rules", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Create))
			r.Put("/runtime-dlp-rules/{id}", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Update))
			r.Post("/runtime-dlp-rules/{id}/promote", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Promote))
			r.Post("/runtime-dlp-rules/{id}/demote", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Demote))
			r.Post("/runtime-dlp-rules/{id}/disable", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Disable))
			r.Delete("/runtime-dlp-rules/{id}", s.requireVerb(rbac.VerbManagePolicies, rtDLP.Delete))

			// Wave D4: custom DPI signatures. Same backing table as DLP
			// rules but filtered/stamped to category='signature'. Distinct
			// HTTP surface so the UI can keep them as separate concepts.
			rtSigs := runtime.NewRuntimeSignaturesHTTP(s.db, s.auditLog)
			r.Get("/runtime-signatures", s.requireVerb(rbac.VerbReadFindings, rtSigs.List))
			r.Get("/runtime-signatures/{id}", s.requireVerb(rbac.VerbReadFindings, rtSigs.Get))
			r.Post("/runtime-signatures", s.requireVerb(rbac.VerbManagePolicies, rtSigs.Create))
			r.Put("/runtime-signatures/{id}", s.requireVerb(rbac.VerbManagePolicies, rtSigs.Update))
			r.Post("/runtime-signatures/{id}/promote", s.requireVerb(rbac.VerbManagePolicies, rtSigs.Promote))
			r.Post("/runtime-signatures/{id}/demote", s.requireVerb(rbac.VerbManagePolicies, rtSigs.Demote))
			r.Post("/runtime-signatures/{id}/disable", s.requireVerb(rbac.VerbManagePolicies, rtSigs.Disable))
			r.Delete("/runtime-signatures/{id}", s.requireVerb(rbac.VerbManagePolicies, rtSigs.Delete))

			// Wave C3: PCAP capture orchestration. Start/list/get/download
			// + delete are user-facing; the agent-facing claim/upload/status
			// endpoints are added in the runtime-agent-token block below.
			pcap := runtime.NewPcapHTTP(s.db)
			r.Post("/runtime-pcap/start", s.requireVerb(rbac.VerbManagePolicies, pcap.Start))
			r.Get("/runtime-pcap", s.requireVerb(rbac.VerbReadFindings, pcap.List))
			r.Get("/runtime-pcap/{id}", s.requireVerb(rbac.VerbReadFindings, pcap.Get))
			r.Get("/runtime-pcap/{id}/download", s.requireVerb(rbac.VerbReadFindings, pcap.Download))
			r.Delete("/runtime-pcap/{id}", s.requireVerb(rbac.VerbManagePolicies, pcap.Delete))
			networkPolicies := netpolicy.NewNetworkPolicies(s.db, s.auditLog)
			r.Get("/network/policies/lifecycle", s.requireVerb(rbac.VerbReadFindings, networkPolicies.List))
			// B6: cross-namespace network boundary enforcement (NBE) toggle.
			nbeSettings := netpolicy.NewNBEHTTP(s.db)
			r.Get("/network/policies/nbe", s.requireVerb(rbac.VerbReadFindings, nbeSettings.List))
			r.Put("/network/policies/nbe", s.requireVerb(rbac.VerbManagePolicies, nbeSettings.Put))
			r.Post("/network/policies/{workload}/rollback", s.requireVerb(rbac.VerbManagePolicies, networkPolicies.Rollback))
			r.Post("/network/policies/{workload}/{action}", s.requireVerb(rbac.VerbManagePolicies, networkPolicies.PreviewAction))

			clusters := handler.NewClusters(s.db, s.auditLog)
			nodes := handler.NewNodes(s.db)
			platformFacts := handler.NewPlatformFacts(s.db)
			r.Get("/clusters", s.requireVerb(rbac.VerbReadFindings, clusters.List))
			r.Get("/clusters/{id}", s.requireVerb(rbac.VerbReadFindings, clusters.GetOne))
			r.Get("/clusters/{id}/health", s.requireVerb(rbac.VerbReadFindings, clusters.Health))
			r.Get("/clusters/{id}/platform-facts", s.requireVerb(rbac.VerbReadFindings, platformFacts.Get))
			r.Post("/clusters/{id}/platform-scan", s.requireVerb(rbac.VerbManagePolicies, platformFacts.Scan))
			r.Get("/clusters/{id}/nodes", s.requireVerb(rbac.VerbReadFindings, nodes.List))
			r.Get("/clusters/{id}/nodes/{node}", s.requireVerb(rbac.VerbReadFindings, nodes.Get))
			r.Get("/clusters/{id}/containers", s.requireVerb(rbac.VerbReadFindings, nodes.Containers))
			r.Post("/clusters/{id}/cross-scan", s.requireVerb(rbac.VerbManagePolicies, clusters.CrossScan))

			// Wave N1: cluster init-bundles (StackRox-style pre-minted onboarding kits).
			// All routes guarded by manage-org since they mint/rotate/revoke long-lived
			// service-principal credentials + TLS material.
			initBundles := handler.NewClusterInitBundles(s.db, s.auditLog)
			r.Post("/cluster-init-bundles", s.requireVerb(rbac.VerbManageOrg, initBundles.Create))
			r.Get("/cluster-init-bundles", s.requireVerb(rbac.VerbManageOrg, initBundles.List))
			r.Get("/cluster-init-bundles/{id}", s.requireVerb(rbac.VerbManageOrg, initBundles.Get))
			r.Post("/cluster-init-bundles/{id}/rotate", s.requireVerb(rbac.VerbManageOrg, initBundles.Rotate))
			r.Delete("/cluster-init-bundles/{id}", s.requireVerb(rbac.VerbManageOrg, initBundles.Delete))

			coverage := compliance.NewCoverage()
			r.Get("/coverage", s.requireVerb(rbac.VerbReadFindings, coverage.List))

			enterprise := handler.NewEnterprise(s.db)
			r.Get("/runtime/overview", s.requireVerb(rbac.VerbReadFindings, enterprise.RuntimeOverview))

			// Process Baseline lifecycle (Wave L4). Backed by pkg/runtime/baseline; profiles
			// synthesized from observed deployments so the kanban renders against live data.
			// `baselines` is constructed at /api/v1 scope above and shared with the ingest path.
			r.Get("/runtime/baselines", s.requireVerb(rbac.VerbReadFindings, baselines.List))
			r.Get("/runtime/baselines/{workload_id}", s.requireVerb(rbac.VerbReadFindings, baselines.Get))
			r.Post("/runtime/baselines/{workload_id}/mode", s.requireVerb(rbac.VerbManageRuntimeRules, baselines.SetMode))
			r.Get("/runtime/baselines/{workload_id}/rules", s.requireVerb(rbac.VerbReadFindings, baselines.ListRules))
			r.Post("/runtime/baselines/{workload_id}/rules", s.requireVerb(rbac.VerbManageRuntimeRules, baselines.CreateRule))
			r.Put("/runtime/baselines/{workload_id}/rules/{rule_id}", s.requireVerb(rbac.VerbManageRuntimeRules, baselines.UpdateRule))
			r.Delete("/runtime/baselines/{workload_id}/rules/{rule_id}", s.requireVerb(rbac.VerbManageRuntimeRules, baselines.DeleteRule))
			fileProfiles := runtime.NewFileProfiles(s.db, s.auditLog)
			r.Get("/runtime/file-profiles", s.requireVerb(rbac.VerbReadFindings, fileProfiles.List))
			r.Get("/runtime/file-profiles/{workload_id}", s.requireVerb(rbac.VerbReadFindings, fileProfiles.Get))
			r.Get("/runtime/file-profiles/{workload_id}/export", s.requireVerb(rbac.VerbReadFindings, fileProfiles.Export))
			r.Post("/runtime/file-profiles/{workload_id}/mode", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.SetMode))
			r.Post("/runtime/file-profiles/{workload_id}:import", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.Import))
			r.Post("/runtime/file-profiles/{workload_id}/rules", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.CreateRule))
			r.Put("/runtime/file-profiles/{workload_id}/rules/{rule_id}", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.UpdateRule))
			r.Delete("/runtime/file-profiles/{workload_id}/rules/{rule_id}", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.DeleteRule))
			r.Post("/runtime/file-profiles/{workload_id}/exceptions", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.CreateException))
			r.Put("/runtime/file-profiles/{workload_id}/exceptions/{exception_id}", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.UpdateException))
			r.Delete("/runtime/file-profiles/{workload_id}/exceptions/{exception_id}", s.requireVerb(rbac.VerbManageRuntimeRules, fileProfiles.DeleteException))
			r.Get("/integrations", s.requireVerb(rbac.VerbReadFindings, enterprise.Integrations))
			r.Get("/migration/sources", s.requireVerb(rbac.VerbReadFindings, enterprise.MigrationSources))
			r.Post("/migration/preview", s.requireVerb(rbac.VerbManagePolicies, enterprise.MigrationPreview))
			r.Get("/onboarding", s.requireVerb(rbac.VerbReadFindings, enterprise.Onboarding))

			responseRules := policy.NewResponseRules(s.db, s.auditLog)
			r.Get("/response-rules", s.requireVerb(rbac.VerbReadFindings, responseRules.List))
			r.Post("/response-rules/{id}/preview", s.requireVerb(rbac.VerbManageRuntimeRules, responseRules.Preview))
			r.Patch("/response-rules/{id}", s.requireVerb(rbac.VerbManageRuntimeRules, responseRules.Update))

			// Wave D: NeuVector-style condition catalog. Distinct from /response-rules
			// above which mutates a hardcoded catalog via override rows.
			rrv2 := policy.NewResponseRulesV2(s.db, s.auditLog)
			r.Get("/response-rules-v2", s.requireVerb(rbac.VerbReadFindings, rrv2.List))
			r.Post("/response-rules-v2", s.requireVerb(rbac.VerbManageRuntimeRules, rrv2.Create))
			r.Patch("/response-rules-v2:reorder", s.requireVerb(rbac.VerbManageRuntimeRules, rrv2.Reorder))
			r.Put("/response-rules-v2/{id}", s.requireVerb(rbac.VerbManageRuntimeRules, rrv2.Update))
			r.Delete("/response-rules-v2/{id}", s.requireVerb(rbac.VerbManageRuntimeRules, rrv2.Delete))

			// E1: declarative response-rule engine (NeuVector CLUSResponseRule parity).
			// Generic field/op conditions + priority ordering, gated by the dedicated
			// manage-response-rules verb. The agent pulls enabled rules via the :sync
			// bundle registered in the runtime-agent-token block below.
			ruleDefs := policy.NewResponseRuleDefs(s.db, s.auditLog).WithDispatcher(s.dispatcher)
			r.Get("/response-rule-defs", s.requireVerb(rbac.VerbManageResponseRules, ruleDefs.List))
			r.Get("/response-rule-defs/{id}", s.requireVerb(rbac.VerbManageResponseRules, ruleDefs.Get))
			r.Post("/response-rule-defs", s.requireVerb(rbac.VerbManageResponseRules, ruleDefs.Create))
			r.Put("/response-rule-defs/{id}", s.requireVerb(rbac.VerbManageResponseRules, ruleDefs.Update))
			r.Delete("/response-rule-defs/{id}", s.requireVerb(rbac.VerbManageResponseRules, ruleDefs.Delete))

			vp := findings.NewVulnProfiles(s.db, s.auditLog)
			r.Get("/vuln-profiles", s.requireVerb(rbac.VerbReadFindings, vp.List))
			r.Get("/vuln-profiles:export", s.requireVerb(rbac.VerbReadFindings, vp.Export))
			r.Post("/vuln-profiles:import", s.requireVerb(rbac.VerbManagePolicies, vp.Import))
			r.Post("/vuln-profiles", s.requireVerb(rbac.VerbManagePolicies, vp.Create))
			r.Put("/vuln-profiles/{id}", s.requireVerb(rbac.VerbManagePolicies, vp.Update))
			r.Delete("/vuln-profiles/{id}", s.requireVerb(rbac.VerbManagePolicies, vp.Delete))

			groupsHandler := handler.NewGroups(s.db, s.auditLog)
			r.Get("/groups", s.requireVerb(rbac.VerbReadFindings, groupsHandler.List))
			r.Get("/groups:export", s.requireVerb(rbac.VerbReadFindings, groupsHandler.Export))
			r.Post("/groups:import", s.requireVerb(rbac.VerbManagePolicies, groupsHandler.Import))
			r.Post("/groups:promote", s.requireVerb(rbac.VerbManagePolicies, groupsHandler.Promote))
			r.Post("/groups", s.requireVerb(rbac.VerbManagePolicies, groupsHandler.Create))
			r.Put("/groups/{id}", s.requireVerb(rbac.VerbManagePolicies, groupsHandler.Update))
			r.Delete("/groups/{id}", s.requireVerb(rbac.VerbManagePolicies, groupsHandler.Delete))

			fed := handler.NewFederation(s.db, s.auditLog).WithFedTrust(s.fedSigner, s.fedJoinConfig())
			r.Get("/federation/state", s.requireVerb(rbac.VerbReadFindings, fed.State))
			r.Post("/federation/state", s.requireVerb(rbac.VerbManageOrg, fed.Transition))
			r.Get("/federation/members", s.requireVerb(rbac.VerbReadFindings, fed.ListMembers))
			r.Post("/federation/members", s.requireVerb(rbac.VerbManageOrg, fed.AddMember))
			r.Delete("/federation/members/{id}", s.requireVerb(rbac.VerbManageOrg, fed.KickMember))
			// D1: master mints a short-lived signed join token for a joining cluster.
			r.Post("/federation/join-tokens", s.requireVerb(rbac.VerbManageOrg, fed.MintJoinToken))
			// NOTE: GET /federation/sync is NO LONGER in the user-JWT block — it moved to a
			// dedicated fed-credential group below so a generic read-findings JWT can no
			// longer pull the federated rule log (D1). The exchange endpoint
			// POST /federation/join is anonymous (authenticated by the join token itself).

			// D3: cross-cluster admin reverse-proxy. ANY /federation/clusters/{id}/* forwards to
			// the joint resolved from its membership endpoint, attaching the master's fed
			// credential (D1 ticket + D2 client cert when mTLS is enabled). Per-method RBAC: GET
			// is open to any reader (the handler then enforces a read-only allowlist for
			// non-admins), while mutating verbs require VerbManageOrg so only a fed admin can
			// drive a joint's write API. The handler's SSRF guard forbids any non-registered host.
			fedProxy := handler.NewFedProxy(s.db, s.auditLog).
				WithFedCredentials(s.fedSigner, s.fedMTLSCA()).
				WithReadAllowlist(s.fedProxyReadAllowlist()).
				WithAuthorizer(s.authorizeSubject)
			r.Get("/federation/clusters/{id}/*", s.requireVerb(rbac.VerbReadFindings, fedProxy.Forward))
			r.Post("/federation/clusters/{id}/*", s.requireVerb(rbac.VerbManageOrg, fedProxy.Forward))
			r.Put("/federation/clusters/{id}/*", s.requireVerb(rbac.VerbManageOrg, fedProxy.Forward))
			r.Patch("/federation/clusters/{id}/*", s.requireVerb(rbac.VerbManageOrg, fedProxy.Forward))
			r.Delete("/federation/clusters/{id}/*", s.requireVerb(rbac.VerbManageOrg, fedProxy.Forward))

			// WS-G G1 / P0-01: the /waf/groups AND /dlp/sensors CRUD surfaces were
			// removed — neither had an agent bundle, sync worker, or DP consumer, so
			// their rows never enforced. The enforced DPI/DLP rulesets are
			// /runtime-signatures and the code-seeded runtime_dlp_rules.

			netConv := network.NewNetworkConversations(s.db).WithLiveGraph(s.live)
			r.Get("/network/conversations", s.requireVerb(rbac.VerbReadFindings, netConv.List))
			r.Get("/network/conversations/entries", s.requireVerb(rbac.VerbReadFindings, netConv.Detail))
			// Plan B5: StreamFlows SSE fallback, only when the hot graph is on.
			if s.live != nil {
				streamFlows := network.NewStreamFlows(s.live)
				r.Get("/network/flows:stream", s.requireVerb(rbac.VerbReadFindings, streamFlows.Stream))
			}

			vulnExceptions := findings.NewVulnerabilityExceptions(s.db)
			r.Get("/vulnerability-exceptions", s.requireVerb(rbac.VerbReadFindings, vulnExceptions.List))

			systemHealth := handler.NewSystemHealth(s.db)
			r.Get("/system-health", s.requireVerb(rbac.VerbReadFindings, systemHealth.List))
			r.Get("/system-health/overview", s.requireVerb(rbac.VerbReadFindings, systemHealth.Overview))
			r.Get("/system-health/clusters/{cluster_id}", s.requireVerb(rbac.VerbReadFindings, systemHealth.Cluster))
			components := handler.NewComponentsInventory(s.db)
			r.Get("/components", s.requireVerb(rbac.VerbReadFindings, components.List))
			r.Get("/components/{id}", s.requireVerb(rbac.VerbReadFindings, components.Get))
			r.Get("/components/{id}/diagnostics", s.requireVerb(rbac.VerbManageOrg, components.Diagnostics))
			// /api/v1/version is read-only; gated by read-findings so any
			// authenticated user (or PAT) can introspect the API build.
			r.Get("/version", s.requireVerb(rbac.VerbReadFindings, s.handleAPIVersion))

			accessControl := handler.NewAccessControl(s.db, s.auditLog)
			r.Get("/custom-roles", s.requireVerb(rbac.VerbManageUsers, s.customRoles.List))
			r.Post("/custom-roles", s.requireVerb(rbac.VerbManageUsers, s.customRoles.Create))
			r.Put("/custom-roles/{id}", s.requireVerb(rbac.VerbManageUsers, s.customRoles.Update))
			r.Delete("/custom-roles/{id}", s.requireVerb(rbac.VerbManageUsers, s.customRoles.Delete))
			r.Get("/access-control", s.requireVerb(rbac.VerbManageUsers, accessControl.Overview))
			r.Post("/access-control/role-bindings", s.requireVerb(rbac.VerbManageUsers, accessControl.CreateRoleBinding))
			r.Delete("/access-control/role-bindings/{id}", s.requireVerb(rbac.VerbManageUsers, accessControl.DeleteRoleBinding))
			r.Post("/access-control/service-accounts", s.requireVerb(rbac.VerbManageUsers, accessControl.CreateServiceAccount))
			r.Post("/access-control/local-users", s.requireVerb(rbac.VerbManageUsers, accessControl.CreateLocalUser))

			// A1/A4: user-management mutations that drive the credential-revocation cascade.
			// Disable/Delete bump session_epoch + revoke PATs + tear down role_assignments
			// atomically; ForcePasswordReset gates the user (JWT and PAT) until they reset.
			users := handler.NewUsers(s.db, s.auditLog)
			r.Post("/users/{id}/disable", s.requireVerb(rbac.VerbManageUsers, users.Disable))
			r.Delete("/users/{id}", s.requireVerb(rbac.VerbManageUsers, users.Delete))
			r.Post("/users/{id}/force-password-reset", s.requireVerb(rbac.VerbManageUsers, users.ForcePasswordReset))

			dashboard := handler.NewDashboard(s.db)
			r.Get("/dashboard/summary", s.requireVerb(rbac.VerbReadFindings, dashboard.Summary))
			r.Get("/dashboard/events-timeline", s.requireVerb(rbac.VerbReadFindings, dashboard.EventsTimeline))

			// B1: runtime-mutable system config (egress proxy, TLS verify + CA bundle,
			// syslog/SIEM target, scanner autoscale). GET redacts secrets; PATCH applies
			// a validated partial update and hot-reloads the in-process accessor. Both
			// routes are gated by VerbManageSystemConfig.
			sysConfig := handler.NewSystemConfig(s.db, s.auditLog, s.syscfg)
			r.Get("/system/config", s.requireVerb(rbac.VerbManageSystemConfig, sysConfig.Get))
			r.Patch("/system/config", s.requireVerb(rbac.VerbManageSystemConfig, sysConfig.Patch))
			// Force an immediate scanner DB refresh across connected scanners.
			r.Post("/scanner/refresh", s.requireVerb(rbac.VerbManageSystemConfig, sysConfig.RefreshScanner))

			// B4: DB-backed auth-provider (IdP) CRUD. GET redacts provider secrets; a mutation
			// hot-reloads the live verifier set the login endpoints read through. All routes are
			// gated by VerbManageAuthServers.
			authServers := handler.NewAuthServers(s.db, s.auditLog, s.authProviders, s.sealer)
			r.Get("/auth-servers", s.requireVerb(rbac.VerbManageAuthServers, authServers.List))
			r.Post("/auth-servers", s.requireVerb(rbac.VerbManageAuthServers, authServers.Create))
			r.Get("/auth-servers/{id}", s.requireVerb(rbac.VerbManageAuthServers, authServers.Get))
			r.Put("/auth-servers/{id}", s.requireVerb(rbac.VerbManageAuthServers, authServers.Update))
			r.Delete("/auth-servers/{id}", s.requireVerb(rbac.VerbManageAuthServers, authServers.Delete))

			// P0-10: per-(cluster, namespace) group->role grants (sso_role_mappings) — the WRITE
			// side that finally gives the scoped-role resolver data in a real deployment. A mutation
			// bumps the parent auth server's revision so the ProviderSet poller re-attaches the
			// scoped rules on every replica. Gated by the same VerbManageAuthServers.
			r.Get("/auth-servers/{id}/scoped-mappings", s.requireVerb(rbac.VerbManageAuthServers, authServers.ListScopedMappings))
			r.Post("/auth-servers/{id}/scoped-mappings", s.requireVerb(rbac.VerbManageAuthServers, authServers.CreateScopedMapping))
			r.Delete("/auth-servers/{id}/scoped-mappings/{mid}", s.requireVerb(rbac.VerbManageAuthServers, authServers.DeleteScopedMapping))

			// A1: admin-configurable password policy + session/idle timeout. GET returns the
			// org's policy (built-in default when unconfigured); PUT replaces it (optimistic
			// concurrency by revision). Supersedes the hardcoded auth.DefaultPasswordProfile.
			authPolicy := handler.NewAuthSecurityPolicy(s.db, s.auditLog)
			r.Get("/auth/security-policy", s.requireVerb(rbac.VerbManageSystemConfig, authPolicy.Get))
			r.Put("/auth/security-policy", s.requireVerb(rbac.VerbManageSystemConfig, authPolicy.Put))

			settings := handler.NewSettings(s.db, s.auditLog)
			r.Get("/settings/org", s.requireVerb(rbac.VerbReadFindings, settings.GetOrg))
			r.Patch("/settings/org", s.requireVerb(rbac.VerbManageOrg, settings.PatchOrg))
			r.Get("/settings/user", s.requireVerb(rbac.VerbReadFindings, settings.GetUser))
			r.Patch("/settings/user", s.requireVerb(rbac.VerbReadFindings, settings.PatchUser))

			receivers := handler.NewReceivers(s.db, s.auditLog, s.dispatcher)
			r.Get("/integrations/receivers", s.requireVerb(rbac.VerbReadFindings, receivers.List))
			r.Post("/integrations/receivers", s.requireVerb(rbac.VerbManagePolicies, receivers.Create))
			r.Patch("/integrations/receivers/{id}", s.requireVerb(rbac.VerbManagePolicies, receivers.Patch))
			r.Delete("/integrations/receivers/{id}", s.requireVerb(rbac.VerbManagePolicies, receivers.Delete))
			// Wave N3: operator controls + test-fire button + delivery history.
			r.Post("/integrations/receivers/{id}/test-fire", s.requireVerb(rbac.VerbManagePolicies, receivers.TestFire))
			r.Post("/integrations/receivers/{id}/pause", s.requireVerb(rbac.VerbManagePolicies, receivers.Pause))
			r.Post("/integrations/receivers/{id}/unpause", s.requireVerb(rbac.VerbManagePolicies, receivers.Unpause))
			r.Post("/integrations/receivers/{id}/rotate-secret", s.requireVerb(rbac.VerbManagePolicies, receivers.RotateSecret))
			r.Get("/integrations/receivers/{id}/deliveries", s.requireVerb(rbac.VerbReadFindings, receivers.ListDeliveries))
			r.Get("/routing.yaml", s.requireVerb(rbac.VerbReadFindings, receivers.GetRoutingYAML))
			r.Post("/routing.yaml", s.requireVerb(rbac.VerbManagePolicies, receivers.PutRoutingYAML))

			forensics := runtime.NewForensics(s.db)
			r.Get("/forensics/{snapshot_id}", s.requireVerb(rbac.VerbReadFindings, forensics.Get))

			integrationDeliveries := handler.NewIntegrationDeliveries(s.db)
			r.Get("/integration-deliveries", s.requireVerb(rbac.VerbReadFindings, integrationDeliveries.Overview))
			r.Post("/integration-deliveries/test", s.requireVerb(rbac.VerbReadFindings, integrationDeliveries.TestPreview))

			connectorCoverage := compliance.NewConnectorCoverage(s.db)
			r.Get("/connector-coverage", s.requireVerb(rbac.VerbReadFindings, connectorCoverage.Overview))
			r.Post("/connector-coverage/test", s.requireVerb(rbac.VerbReadFindings, connectorCoverage.Test))
			r.Post("/connector-coverage/configs", s.requireVerb(rbac.VerbManagePolicies, connectorCoverage.SaveConfig))
			r.Post("/connector-coverage/configs/{id}/test", s.requireVerb(rbac.VerbManagePolicies, connectorCoverage.TestSavedConfig))

			search := handler.NewSearch(s.db)
			r.Get("/search", s.requireVerb(rbac.VerbReadFindings, search.Q))

			sboms := findings.NewSBOM(s.db)
			r.Get("/sbom/spdx/{asset_id}", s.requireVerb(rbac.VerbReadFindings, sboms.SPDX))
			r.Get("/sbom/cyclonedx/{asset_id}", s.requireVerb(rbac.VerbReadFindings, sboms.CycloneDX))
			r.Get("/sbom/mbom/{asset_id}", s.requireVerb(rbac.VerbReadFindings, sboms.MBOM))

			compl := compliance.NewCompliance(s.db, s.auditLog).WithResponseAlerts(
				runtime.NewResponseDispatch(s.db, s.dispatcher),
				policy.NewResponseRuleDefs(s.db, s.auditLog).WithDispatcher(s.dispatcher).Evaluate,
				s.dispatcher,
			)
			r.Get("/compliance/frameworks", s.requireVerb(rbac.VerbReadFindings, compl.Frameworks))
			r.Get("/compliance/checks", s.requireVerb(rbac.VerbReadFindings, compl.Checks))
			r.Get("/compliance/summary", s.requireVerb(rbac.VerbReadFindings, compl.Summary))
			r.Get("/compliance/evidence", s.requireVerb(rbac.VerbReadFindings, compl.Evidence))
			r.Get("/compliance/nodes", s.requireVerb(rbac.VerbReadFindings, compl.NodeEvidence))
			r.Get("/compliance/workloads", s.requireVerb(rbac.VerbReadFindings, compl.WorkloadEvidence))
			r.Get("/compliance/kubernetes", s.requireVerb(rbac.VerbReadFindings, compl.KubernetesEvidence))
			r.Get("/compliance/cloud", s.requireVerb(rbac.VerbReadFindings, compl.CloudEvidence))
			r.Get("/compliance/exemptions", s.requireVerb(rbac.VerbReadFindings, compl.ListExemptions))
			r.Post("/compliance/exemptions", s.requireVerb(rbac.VerbManagePolicies, compl.CreateExemption))
			r.Post("/compliance/exemptions/{id}/revoke", s.requireVerb(rbac.VerbManagePolicies, compl.RevokeExemption))
			r.Post("/compliance/ingest", s.requireVerb(rbac.VerbManagePolicies, compl.Ingest))

			// Wave N8: production-grade scheduled compliance runs backed by the
			// compliance_schedules + compliance_runs tables (migration 039). The
			// constellation-compliance-scheduler daemon polls next_run_at, signs
			// the rendered artifact with cosign, and delivers to email / S3 /
			// webhook / file targets.
			complianceSchedulesDB := compliance.NewComplianceSchedulesDB(s.db, s.auditLog)
			r.Get("/compliance/schedules", s.requireVerb(rbac.VerbReadFindings, complianceSchedulesDB.List))
			r.Post("/compliance/schedules", s.requireVerb(rbac.VerbManagePolicies, complianceSchedulesDB.Create))
			r.Get("/compliance/schedules/{id}", s.requireVerb(rbac.VerbReadFindings, complianceSchedulesDB.Get))
			r.Patch("/compliance/schedules/{id}", s.requireVerb(rbac.VerbManagePolicies, complianceSchedulesDB.Patch))
			r.Delete("/compliance/schedules/{id}", s.requireVerb(rbac.VerbManagePolicies, complianceSchedulesDB.Delete))
			r.Post("/compliance/schedules/{id}/run-now", s.requireVerb(rbac.VerbManagePolicies, complianceSchedulesDB.RunNow))
			r.Get("/compliance/schedules/{id}/runs", s.requireVerb(rbac.VerbReadFindings, complianceSchedulesDB.Runs))
			r.Get("/compliance/runs/{id}/artifact", s.requireVerb(rbac.VerbReadFindings, complianceSchedulesDB.Artifact))

			cf := compliance.NewCustomFrameworks(s.db, s.auditLog)
			r.Get("/compliance/primitives", s.requireVerb(rbac.VerbReadFindings, cf.Primitives))
			r.Get("/compliance/custom-frameworks", s.requireVerb(rbac.VerbReadFindings, cf.List))
			r.Post("/compliance/custom-frameworks", s.requireVerb(rbac.VerbManagePolicies, cf.Create))
			r.Delete("/compliance/custom-frameworks/{id}", s.requireVerb(rbac.VerbManagePolicies, cf.Delete))

			// User-supplied CEL compliance checks (P0-03). The k8s-compliance collector
			// loads these per-org and evaluates them over collected objects.
			cc := compliance.NewCustomChecks(s.db, s.auditLog)
			r.Get("/compliance/custom-checks", s.requireVerb(rbac.VerbReadFindings, cc.List))
			r.Post("/compliance/custom-checks", s.requireVerb(rbac.VerbManagePolicies, cc.Create))
			r.Delete("/compliance/custom-checks/{id}", s.requireVerb(rbac.VerbManagePolicies, cc.Delete))

			reports := compliance.NewReports(s.db)
			r.Get("/reports/compliance.html", s.requireVerb(rbac.VerbReadFindings, reports.ComplianceHTML))
			r.Get("/reports/compliance.pdf", s.requireVerb(rbac.VerbReadFindings, reports.CompliancePDF))
			r.Get("/reports/executive.html", s.requireVerb(rbac.VerbReadFindings, reports.ExecutiveHTML))
			r.Get("/reports/executive.pdf", s.requireVerb(rbac.VerbReadFindings, reports.ExecutivePDF))

			analytics := handler.NewAnalytics(s.db)
			r.Get("/analytics/trend", s.requireVerb(rbac.VerbReadFindings, analytics.Trend))
			r.Get("/analytics/mttr", s.requireVerb(rbac.VerbReadFindings, analytics.MTTR))
			r.Get("/analytics/backups", s.requireVerb(rbac.VerbReadFindings, analytics.Backups))

			assets := handler.NewAssets(s.db)
			assetVuln := handler.NewAssetVuln(s.db)
			imageAcceptances := handler.NewImageAcceptances(s.db, s.auditLog)
			r.Get("/assets", s.requireVerb(rbac.VerbReadFindings, assets.List))
			r.Get("/assets/{id}", s.requireVerb(rbac.VerbReadFindings, assets.Get))
			r.Get("/assets/{id}/vulnerabilities", s.requireVerb(rbac.VerbReadFindings, assetVuln.Get))
			r.Get("/assets/{id}/image-acceptances", s.requireVerb(rbac.VerbReadFindings, imageAcceptances.List))
			r.Post("/assets/{id}/image-acceptances", s.requireVerb(rbac.VerbAcceptRisk, imageAcceptances.Create))
			r.Post("/assets/{id}/image-acceptances/{acceptanceID}/revoke", s.requireVerb(rbac.VerbAcceptRisk, imageAcceptances.Revoke))

			policies := policy.NewPolicies(s.db, s.auditLog, s.dispatcher)
			r.Get("/policies", s.requireVerb(rbac.VerbReadFindings, policies.List))
			r.Get("/policies/admission-profiles", s.requireVerb(rbac.VerbReadFindings, policies.AdmissionProfiles))
			r.Get("/policies/admission-profiles/{profile}/export", s.requireVerb(rbac.VerbReadFindings, policies.ExportAdmissionProfile))
			r.Post("/policies/admission-profiles:import", s.requireVerb(rbac.VerbManagePolicies, policies.ImportAdmissionProfile))
			r.Post("/policies", s.requireVerb(rbac.VerbManagePolicies, policies.Create))
			r.Patch("/policies/{id}", s.requireVerb(rbac.VerbManagePolicies, policies.Update))
			r.Delete("/policies/{id}", s.requireVerb(rbac.VerbManagePolicies, policies.Delete))
			r.Post("/policies:bulk", s.requireVerb(rbac.VerbManagePolicies, policies.Bulk))
			r.Post("/policies/simulate", s.requireVerb(rbac.VerbReadFindings, policies.Simulate))
			r.Post("/policies/assess", s.requireVerb(rbac.VerbReadFindings, policies.Assess))
			r.Get("/policies/admission/state", s.requireVerb(rbac.VerbReadFindings, policies.AdmissionState))
			r.Patch("/policies/admission/state", s.requireVerb(rbac.VerbManagePolicies, policies.UpdateAdmissionState))
			r.Get("/policies/admission/rules", s.requireVerb(rbac.VerbReadFindings, policies.AdmissionRules))
			r.Get("/policies/service-mode-defaults", s.requireVerb(rbac.VerbReadFindings, policies.ServiceModeDefaults))
			r.Patch("/policies/service-mode-defaults", s.requireVerb(rbac.VerbManagePolicies, policies.UpdateServiceModeDefaults))
			r.Get("/policies/dpi-threats", s.requireVerb(rbac.VerbReadFindings, policies.DPIThreatSettings))
			r.Patch("/policies/dpi-threats", s.requireVerb(rbac.VerbManagePolicies, policies.UpdateDPIThreatSettings))
			r.Get("/policies/admission/options", s.requireVerb(rbac.VerbReadFindings, policies.AdmissionOptions))
			r.Post("/policies/admission/rules", s.requireVerb(rbac.VerbManagePolicies, policies.CreateAdmissionRule))

			policyFields := policy.NewPolicyFields()
			r.Get("/policy/fields", s.requireVerb(rbac.VerbReadFindings, policyFields.List))

			// Empty path resolves to CONSTELLATION_VULNDB_PATH or the chart
			// default — the same store the scanner matches against. CVE detail
			// metadata is served from it when cve_records has no row.
			cve := findings.NewCVE(s.db, "")
			r.Get("/cve/search", s.requireVerb(rbac.VerbReadFindings, cve.Search))
			r.Get("/cve/stats", s.requireVerb(rbac.VerbReadFindings, cve.Stats))
			r.Get("/cve/bundle/status", s.requireVerb(rbac.VerbReadFindings, cve.BundleStatus))
			r.Get("/cve/{id}/affected", s.requireVerb(rbac.VerbReadFindings, cve.Affected))
			r.Get("/cve/{id}", s.requireVerb(rbac.VerbReadFindings, cve.Get))

			auditHandler := handler.NewAudit(s.db)
			r.Get("/audit/events", s.requireVerb(rbac.VerbReadAudit, auditHandler.List))
			r.Post("/audit/verify", s.requireVerb(rbac.VerbReadAudit, auditHandler.Verify))
			// E2: compliance evidence path. ControlMappings is the static
			// table (no PII / org data) so we put it under VerbReadAudit
			// rather than minting a new verb; anyone with audit-read
			// already sees enough to derive it.
			r.Get("/compliance/control-mappings", s.requireVerb(rbac.VerbReadAudit, auditHandler.ControlMappings))

			// E4: quarantine. Read mirrors findings/threats (VerbReadFindings).
			// Mutations need VerbManageQuarantine (granted ClusterAdmin+).
			quar := runtime.NewQuarantine(s.db, s.auditLog)
			r.Get("/quarantine", s.requireVerb(rbac.VerbReadFindings, quar.List))
			r.Get("/quarantine/{id}", s.requireVerb(rbac.VerbReadFindings, quar.Get))
			r.Post("/quarantine", s.requireVerb(rbac.VerbManageQuarantine, quar.Create))
			r.Post("/quarantine/{id}/lift", s.requireVerb(rbac.VerbManageQuarantine, quar.Lift))

			// Runtime events read path. The write path (POST /events:bulk) is in a separate
			// group below — runtime-agent token auth there, not user JWT — so a compromised
			// agent token can't read findings, etc.
			eventsRead := runtime.NewEventsIngest(s.db, s.auditLog, baselines.BaselineMode)
			r.Get("/events", s.requireVerb(rbac.VerbReadFindings, eventsRead.List))

			// Host-facts read path. Write path is in the runtime-agent token
			// group below (POST /host-facts:report). One row per (cluster, node);
			// list returns the latest snapshot for the caller's org.
			hostFactsRead := handler.NewHostFacts(s.db)
			r.Get("/host-facts", s.requireVerb(rbac.VerbReadFindings, hostFactsRead.List))
			r.Get("/host-facts/{node}", s.requireVerb(rbac.VerbReadFindings, hostFactsRead.Get))

			// Host process snapshots (Slice B). Same read/write split.
			hostProcsRead := handler.NewHostProcesses(s.db)
			r.Get("/host-processes", s.requireVerb(rbac.VerbReadFindings, hostProcsRead.List))
			r.Get("/host-processes/{node}", s.requireVerb(rbac.VerbReadFindings, hostProcsRead.Get))

			// Host container inventory (Slice C). crictl-derived list of
			// containers per node, snapshotted every minute or so.
			hostContsRead := handler.NewHostContainers(s.db)
			r.Get("/host-containers", s.requireVerb(rbac.VerbReadFindings, hostContsRead.List))
			r.Get("/host-containers/{node}", s.requireVerb(rbac.VerbReadFindings, hostContsRead.Get))

			// Host package inventory (Slice D.1). CVE matching is in
			// the runtime-agent-token write group below — it fires
			// asynchronously off the Report path.
			hostPkgsRead := handler.NewHostPackages(s.db)
			r.Get("/host-packages", s.requireVerb(rbac.VerbReadFindings, hostPkgsRead.List))
			r.Get("/host-packages/{node}", s.requireVerb(rbac.VerbReadFindings, hostPkgsRead.Get))

			serverlessPkgs := scanning.NewServerlessPackages(s.db)
			r.Post("/serverless-packages:report", s.requireVerb(rbac.VerbManagePolicies, serverlessPkgs.Report))
			repositoryPkgs := handler.NewRepositoryPackages(s.db)
			r.Post("/repository-packages:report", s.requireVerb(rbac.VerbManagePolicies, repositoryPkgs.Report))
			repositoryInventory := handler.NewRepositoryInventory(s.db)
			r.Get("/repository-scans", s.requireVerb(rbac.VerbReadFindings, repositoryInventory.List))
			r.Get("/repository-scans/{id}", s.requireVerb(rbac.VerbReadFindings, repositoryInventory.Get))
			scanAttestations := scanning.NewScanAttestationsWithAudit(s.db, s.auditLog)
			r.Get("/repository-scan-attestation-trust-policies", s.requireVerb(rbac.VerbReadFindings, scanAttestations.ListTrustPolicies))
			r.Post("/repository-scan-attestation-trust-policies", s.requireVerb(rbac.VerbManagePolicies, scanAttestations.CreateTrustPolicy))
			r.Patch("/repository-scan-attestation-trust-policies/{id}", s.requireVerb(rbac.VerbManagePolicies, scanAttestations.PatchTrustPolicy))
			r.Delete("/repository-scan-attestation-trust-policies/{id}", s.requireVerb(rbac.VerbManagePolicies, scanAttestations.DeleteTrustPolicy))
			r.Post("/repository-scan-attestation-trust-policies/{id}:verify-pending", s.requireVerb(rbac.VerbManagePolicies, scanAttestations.VerifyPendingForPolicy))
			r.Post("/repository-scan-attestations:report", s.requireVerb(rbac.VerbManagePolicies, scanAttestations.Report))
			r.Post("/repository-scan-attestations/{id}:verify", s.requireVerb(rbac.VerbManagePolicies, scanAttestations.Verify))
			r.Get("/repository-scan-attestations/{id}", s.requireVerb(rbac.VerbReadFindings, scanAttestations.Get))
			r.Get("/repository-scan-attestations/{id}/verifications", s.requireVerb(rbac.VerbReadFindings, scanAttestations.ListVerifications))
			r.Get("/repository-scan-attestations/{id}/export", s.requireVerb(rbac.VerbReadFindings, scanAttestations.Export))
			r.Get("/repository-scans/{id}/attestations", s.requireVerb(rbac.VerbReadFindings, scanAttestations.ListForRepositoryScan))
			r.Get("/image-scan-results/{id}/attestations", s.requireVerb(rbac.VerbReadFindings, scanAttestations.ListForImageScanResult))
			serverlessInventory := scanning.NewServerlessInventory(s.db)
			r.Get("/serverless-functions", s.requireVerb(rbac.VerbReadFindings, serverlessInventory.List))
			r.Get("/serverless-functions/{id}", s.requireVerb(rbac.VerbReadFindings, serverlessInventory.Get))

			// Host vulnerabilities. Read-only view backed by unified findings
			// where target_type='host'.
			hostVulnsRead := handler.NewHostVulnerabilities(s.db)
			r.Get("/host-vulnerabilities", s.requireVerb(rbac.VerbReadFindings, hostVulnsRead.List))
			r.Get("/host-vulnerabilities/{node}", s.requireVerb(rbac.VerbReadFindings, hostVulnsRead.Get))

			// Host CIS benchmark reports (Slice E).
			hostCISRead := compliance.NewHostCIS(s.db)
			r.Get("/host-cis", s.requireVerb(rbac.VerbReadFindings, hostCISRead.List))
			r.Get("/host-cis/{node}", s.requireVerb(rbac.VerbReadFindings, hostCISRead.Get))

			// AI surface (Abbot). Disabled unless org.ai_enabled is true; the handler
			// itself returns 503 with "ai disabled" so frontend can degrade gracefully.
			ai := handler.NewAI(s.db, s.auditLog)
			r.Post("/ai/query", s.requireVerb(rbac.VerbInvokeAI, ai.Query))

			// Container-registry CRUD + auto-discover (Wave N2). Walker daemon
			// is cmd/constellation-registry-walker; the same SyncOnce backs both
			// /sync-now (user-triggered) and the timer-driven loop.
			registries := handler.NewRegistries(s.db, s.auditLog)
			r.Get("/registries", s.requireVerb(rbac.VerbReadFindings, registries.List))
			r.Post("/registries", s.requireVerb(rbac.VerbManageRegistries, registries.Create))
			r.Get("/registries/{id}", s.requireVerb(rbac.VerbReadFindings, registries.Get))
			r.Patch("/registries/{id}", s.requireVerb(rbac.VerbManageRegistries, registries.Patch))
			r.Delete("/registries/{id}", s.requireVerb(rbac.VerbManageRegistries, registries.Delete))
			r.Post("/registries/{id}/test", s.requireVerb(rbac.VerbManageRegistries, registries.Test))
			r.Post("/registries/{id}/sync-now", s.requireVerb(rbac.VerbManageRegistries, registries.SyncNow))
			r.Get("/registries/{id}/images", s.requireVerb(rbac.VerbReadFindings, registries.Images))

			// User-facing scan-job endpoints.
			jobs := scanning.NewScanJobs(s.db, s.auditLog)
			scannerCache := scanning.NewScannerCache(s.db)
			imageScanResults := handler.NewImageScanResults(s.db)
			// Enqueueing a scan job makes the platform pull + scan an arbitrary
			// external image, so it is a write/control action — gate it with
			// VerbManagePolicies, consistent with the /scan/workload|host|platform
			// trigger routes below. A read-only auditor must not be able to drive it.
			r.Post("/scan-jobs", s.requireVerb(rbac.VerbManagePolicies, jobs.Enqueue))
			r.Get("/scan-jobs", s.requireVerb(rbac.VerbReadFindings, jobs.List))
			r.Get("/scan-targets/{id}/impacted-workloads", s.requireVerb(rbac.VerbReadFindings, jobs.ImpactedWorkloads))
			r.Get("/scan/status", s.requireVerb(rbac.VerbReadFindings, jobs.Status))
			r.Post("/scan/workload/{id}", s.requireVerb(rbac.VerbManagePolicies, jobs.TriggerWorkload))
			r.Get("/scan/workload/{id}", s.requireVerb(rbac.VerbReadFindings, jobs.WorkloadReport))
			r.Post("/scan/host/{id}", s.requireVerb(rbac.VerbManagePolicies, jobs.TriggerHost))
			r.Get("/scan/host/{id}", s.requireVerb(rbac.VerbReadFindings, jobs.HostReport))
			r.Post("/scan/platform/platform", s.requireVerb(rbac.VerbManagePolicies, jobs.TriggerPlatform))
			r.Get("/scan/platform/platform", s.requireVerb(rbac.VerbReadFindings, jobs.PlatformReport))
			r.Get("/scan/platform", s.requireVerb(rbac.VerbReadFindings, jobs.PlatformSummary))
			r.Get("/scan/scanner", s.requireVerb(rbac.VerbReadFindings, scannerCache.List))
			r.Get("/scan/cache_stat/{scanner_id}", s.requireVerb(rbac.VerbReadFindings, scannerCache.CompatStat))
			r.Get("/scan/cache_data/{scanner_id}", s.requireVerb(rbac.VerbReadFindings, scannerCache.CompatData))
			r.Get("/scanner-cache/{scanner_id}/stat", s.requireVerb(rbac.VerbReadFindings, scannerCache.Stat))
			r.Get("/scanner-cache/{scanner_id}/data", s.requireVerb(rbac.VerbReadFindings, scannerCache.Data))
			r.Get("/image-scan-results", s.requireVerb(rbac.VerbReadFindings, imageScanResults.List))
			r.Get("/image-scan-results/{id}", s.requireVerb(rbac.VerbReadFindings, imageScanResults.Get))
			r.Get("/image-scan-results/{id}/packages", s.requireVerb(rbac.VerbReadFindings, imageScanResults.Packages))
			r.Get("/image-scan-results/{id}/layers", s.requireVerb(rbac.VerbReadFindings, imageScanResults.Layers))
			r.Get("/image-scan-results/{id}/secrets", s.requireVerb(rbac.VerbReadFindings, imageScanResults.Secrets))
			r.Get("/image-scan-results/{id}/file-risks", s.requireVerb(rbac.VerbReadFindings, imageScanResults.FileRisks))
			r.Get("/image-scan-results/{id}/config-checks", s.requireVerb(rbac.VerbReadFindings, imageScanResults.ConfigChecks))
			r.Get("/image-scan-results/{id}/signature", s.requireVerb(rbac.VerbReadFindings, imageScanResults.Signature))
			r.Get("/image-scan-results/{id}/sbom/spdx", s.requireVerb(rbac.VerbReadFindings, imageScanResults.SPDX))
			r.Get("/image-scan-results/{id}/sbom/cyclonedx", s.requireVerb(rbac.VerbReadFindings, imageScanResults.CycloneDX))
			r.Get("/image-scan-results/{id}/affected-workloads", s.requireVerb(rbac.VerbReadFindings, imageScanResults.AffectedWorkloads))
			r.Post("/scan-jobs/{id}/pause", s.requireVerb(rbac.VerbManagePolicies, jobs.Pause))
			r.Post("/scan-jobs/{id}/resume", s.requireVerb(rbac.VerbManagePolicies, jobs.Resume))
			r.Post("/scan-jobs/{id}/retry", s.requireVerb(rbac.VerbManagePolicies, jobs.Retry))
			r.Post("/scan-jobs/{id}/cancel", s.requireVerb(rbac.VerbManagePolicies, jobs.Cancel))

			// Wave N5: Backup / Restore. All under manage-org because backups contain the
			// full org's operator state (policies, receivers, etc.) and a restore mutates
			// every namespace's policy posture.
			backups := handler.NewBackups(s.db, s.auditLog)
			r.Post("/backups", s.requireVerb(rbac.VerbManageOrg, backups.Create))
			r.Get("/backups", s.requireVerb(rbac.VerbManageOrg, backups.List))
			r.Get("/backups/{id}", s.requireVerb(rbac.VerbManageOrg, backups.Get))
			r.Get("/backups/{id}/download", s.requireVerb(rbac.VerbManageOrg, backups.Download))
			r.Post("/backups/verify", s.requireVerb(rbac.VerbManageOrg, backups.Verify))
			r.Post("/backups/restore", s.requireVerb(rbac.VerbManageOrg, backups.Restore))
			r.Get("/backups/schedule", s.requireVerb(rbac.VerbManageOrg, backups.GetSchedule))
			r.Post("/backups/schedule", s.requireVerb(rbac.VerbManageOrg, backups.PutSchedule))

			// Task B3: config-as-code export/import. Gated by manage-org because the
			// config document carries the full org config (re-sealed registry credentials,
			// policies, receivers, ...). The identity tables it can also carry (users,
			// custom_roles, role_bindings) are subject to a SECOND in-handler check: the
			// import only writes them when the caller ALSO holds manage-users, mirroring the
			// verb that gates the direct /users, /custom-roles, and /access-control routes —
			// so a manage-org-only principal can't escalate via an imported role binding.
			// Import takes an explicit ?mode=merge|replace flag.
			configIO := handler.NewConfigIO(s.db, s.auditLog, s.customRoles)
			r.Get("/config/export", s.requireVerb(rbac.VerbManageOrg, configIO.Export))
			r.Post("/config/import", s.requireVerb(rbac.VerbManageOrg, configIO.Import))

			// Task B5: Git connector for config-as-code. Same manage-org gate as export —
			// the connector holds a PAT and controls where the full org config is published.
			gitConn := handler.NewGitConnector(s.db, s.auditLog)
			r.Get("/config/git-connector", s.requireVerb(rbac.VerbManageOrg, gitConn.Get))
			r.Put("/config/git-connector", s.requireVerb(rbac.VerbManageOrg, gitConn.Put))
			r.Post("/config/git-connector/push", s.requireVerb(rbac.VerbManageOrg, gitConn.Push))

			// Wave N4: API-token (PAT) management. List/get are gated by manage-users
			// since tokens are credentials; create/rotate/revoke are also manage-users.
			// The raw token value is returned ONLY on create/rotate, and only once.
			apiTokens := handler.NewAPITokens(s.db, s.auditLog).WithMaxLifetime(s.cfg.PATMaxLifetime)
			r.Get("/api-tokens", s.requireVerb(rbac.VerbManageUsers, apiTokens.List))
			r.Post("/api-tokens", s.requireVerb(rbac.VerbManageUsers, apiTokens.Create))
			r.Get("/api-tokens/{id}", s.requireVerb(rbac.VerbManageUsers, apiTokens.Get))
			r.Post("/api-tokens/{id}/rotate", s.requireVerb(rbac.VerbManageUsers, apiTokens.Rotate))
			r.Delete("/api-tokens/{id}", s.requireVerb(rbac.VerbManageUsers, apiTokens.Revoke))
			// Scope catalog drives the UI scope-picker. read-findings is the gate so any
			// authenticated user can render the picker without needing manage-users.
			r.Get("/rbac/verbs", s.requireVerb(rbac.VerbReadFindings, apiTokens.VerbCatalog))
		})

		// Scanner-worker endpoints (scanner-token auth, not user JWT).
		r.Group(func(r chi.Router) {
			r.Use(handler.ScannerTokenMiddleware(s.db.Pool()))
			// E1: the declarative response-rule evaluator fires EventScan rules on a completed
			// scan (NeuVector EventCVEReport parity), executing their ordered actions and
			// webhooks (via the dispatcher). Mirrors the runtime-ingest wiring below.
			scanRuleDefs := policy.NewResponseRuleDefs(s.db, s.auditLog).WithDispatcher(s.dispatcher)
			jobs := scanning.NewScanJobs(s.db, s.auditLog).WithResponseRuleEngine(scanRuleDefs.Evaluate)
			evidence := handler.NewScanEvidence(s.db)
			r.Post("/scan-jobs/claim", jobs.Claim)
			r.Post("/scan-jobs/{id}/renew", jobs.RenewLease)
			r.Post("/scan-jobs/{id}/complete", jobs.Complete)
			r.Post("/scan-jobs/{id}/fail", jobs.Fail)
			r.Get("/scan-evidence/{id}", evidence.Get)
			// Runtime config the scanner polls (UI-settable via system_config): how
			// often to refresh Trivy/Grype DBs, and whether it's air-gapped.
			r.Get("/scanner/config", func(w http.ResponseWriter, r *http.Request) {
				subj, ok := authctx.SubjectFrom(r.Context())
				if !ok {
					writeError(w, http.StatusUnauthorized, "no subject")
					return
				}
				cfg := s.syscfg.Get(r.Context(), subj.OrgID)
				writeJSON(w, http.StatusOK, map[string]any{
					"db_refresh_minutes": cfg.ScannerDBRefreshMinutes,
					"offline_db":         cfg.ScannerOfflineDB,
					"refresh_now":        cfg.ScannerDBRefreshNow,
				})
			})
		})

		// Runtime-agent ingest (runtime-agent-token auth, not user JWT). Holds the single
		// runtime-ingest rbac verb so a compromised agent cannot read findings.
		r.Group(func(r chi.Router) {
			r.Use(handler.RuntimeAgentTokenMiddleware(s.db.Pool()))
			// E1 evaluator: the declarative response-rule engine fires on matching runtime
			// events and executes its ordered actions (webhooks via the dispatcher). Wired
			// here so the headline E1 acceptance ("a rule fires on a matching runtime event")
			// is met server-side on the live ingest path.
			e1RuleDefs := policy.NewResponseRuleDefs(s.db, s.auditLog).WithDispatcher(s.dispatcher)
			eventsIngest := runtime.NewEventsIngest(s.db, s.auditLog, baselines.BaselineMode).
				WithDispatcher(s.dispatcher).
				WithResponseEngine(runtime.NewResponseDispatch(s.db, s.dispatcher)).
				WithResponseRuleEngine(e1RuleDefs.Evaluate)
			r.Post("/events:bulk", eventsIngest.Bulk)

			fileProfiles := runtime.NewFileProfiles(s.db, s.auditLog)
			r.Get("/runtime/file-profile-rules:bundle", fileProfiles.AgentRulesBundle)
			r.Post("/runtime/file-profile-watches:report", fileProfiles.ReportWatchInventory)

			// Process baseline bundle for the agent-side process enforcer (kill-on-exec).
			r.Get("/runtime/process-baselines:bundle", baselines.AgentBaselineBundle)

			// DLP/signature rules bundle for the agent's dlp sync poller (the
			// user-RBAC /runtime-dlp-rules List 401s a bearer-token agent).
			r.Get("/runtime/dlp-rules:bundle", runtime.NewRuntimeDLPHTTP(s.db, s.auditLog).AgentBundle)

			// H6: per-workload dp policy bundle for the agent's policy-sync worker
			// (cmd/constellation-runtime-agent/runtime_policy_sync.go). Same
			// runtime-agent-token auth + org/cluster scoping as the other bundles;
			// without this the worker 404s and dp runs with an empty rule table.
			r.Get("/runtime/policies:bundle", runtime.NewRuntimePoliciesHTTP(s.db, s.auditLog).AgentPolicyBundle)

			// E1: enabled declarative response rules for the agent's stream evaluator,
			// priority-ordered. Same :sync pull shape + runtime-agent-token auth as the
			// other agent bundles (the user-RBAC /response-rule-defs 401s a bearer agent).
			r.Get("/runtime/response-rules:sync", policy.NewResponseRuleDefs(s.db, s.auditLog).AgentSyncBundle)

			// Wave M1: bucketed L4 flows -> network_flows (separate write path
			// from /events:bulk because the destination tables differ; same
			// runtime-agent-token authn).
			flowsIngest := netpolicy.NewNetworkFlowsIngest(s.db).WithLiveGraph(s.live)
			r.Post("/network-flows:bulk", flowsIngest.Bulk)

			// Wave 5: DPI signature hits from the NeuVector dp data-plane.
			// One row per DPMsgThreatLog the agent decoded; same auth path
			// as the other runtime-agent ingest endpoints. The matching
			// user-facing read endpoint lives in the JWT block below.
			//
			// P0-5: fan high-severity threats out to audit + notify + the
			// response engines the same way /events:bulk does, so a detected
			// SYN flood / SQLi / Heartbleed pages an operator in real time
			// instead of waiting for a poll. Flood dedup is in-memory.
			threatsIngest := runtime.NewRuntimeThreats(s.db).
				WithAlerting(s.auditLog, s.dispatcher,
					runtime.NewResponseDispatch(s.db, s.dispatcher), e1RuleDefs.Evaluate)
			r.Post("/runtime-threats:bulk", threatsIngest.Bulk)

			// Live-session snapshot ingest (NV RESTSession). The agent uploads its dp
			// ctrl_list_session table; the ingest replaces the node's rows.
			r.Post("/network-sessions:bulk", network.NewNetwork(s.db).IngestSessions)

			// C1: Kubernetes API audit-webhook receiver. The apiserver POSTs
			// batches of audit.k8s.io/v1 Events here (same cluster/runtime-agent
			// token as the other agent-ingest routes, supplied as the webhook
			// kubeconfig's bearer token). High-signal control-plane events (exec
			// into a pod, secret reads, RBAC mutations, privileged pod creates)
			// fan out to audit + notify + the response engines exactly like
			// /events:bulk. See internal/handler/k8saudit for the apiserver
			// audit-policy/webhook config this endpoint expects.
			k8sAuditIngest := k8saudit.NewIngest(s.db).
				WithAlerting(s.auditLog, s.dispatcher,
					runtime.NewResponseDispatch(s.db, s.dispatcher), e1RuleDefs.Evaluate)
			r.Post("/k8s-audit:bulk", k8sAuditIngest.Bulk)

			// Wave C3: agent-facing pcap claim/upload/status endpoints.
			// Same runtime-agent token as events + flows + threats.
			pcap := runtime.NewPcapHTTP(s.db)
			r.Get("/runtime-pcap/claim", pcap.Claim)
			r.Post("/runtime-pcap/{id}/upload", pcap.Upload)
			r.Post("/runtime-pcap/{id}/status", pcap.UpdateStatus)

			// Host-facts ingest. The agent posts one snapshot per
			// CONSTELLATION_HOSTSCAN_INTERVAL; upsert by (cluster, node).
			hostFacts := handler.NewHostFacts(s.db)
			r.Post("/host-facts:report", hostFacts.Report)

			// Host process snapshots (Slice B). Same upsert shape.
			hostProcs := handler.NewHostProcesses(s.db)
			r.Post("/host-processes:report", hostProcs.Report)

			// Host container inventory (Slice C).
			hostConts := handler.NewHostContainers(s.db)
			r.Post("/host-containers:report", hostConts.Report)

			// Host package inventory. Reports are stored as scanner evidence
			// and queued as host scan targets; scanner workers do the matching.
			hostPkgs := handler.NewHostPackages(s.db)
			r.Post("/host-packages:report", hostPkgs.Report)

			// Running workload package evidence. The runtime-agent reads
			// packages from container root filesystems and queues workload
			// scan targets for scanner workers.
			workloadPkgs := scanning.NewWorkloadPackages(s.db)
			r.Post("/workload-packages:report", workloadPkgs.Report)

			// Host CIS benchmark reports (Slice E).
			hostCIS := compliance.NewHostCIS(s.db).WithResponseAlerts(
				runtime.NewResponseDispatch(s.db, s.dispatcher),
				policy.NewResponseRuleDefs(s.db, s.auditLog).WithDispatcher(s.dispatcher).Evaluate,
				s.dispatcher,
			)
			r.Post("/host-cis:report", hostCIS.Report)
		})

		// D1: federation sync (per-cluster fed credential auth, NOT user JWT). A joint
		// presents the signed per-cluster sync ticket it received at join; the middleware
		// validates the signature + the fed_credentials row (live, not revoked, epoch
		// current). A generic read-findings JWT can never produce a valid ticket, so it is
		// rejected here — /sync is no longer reachable with an ordinary read principal.
		r.Group(func(r chi.Router) {
			r.Use(handler.FedSyncTokenMiddleware(s.db.Pool(), s.fedSigner, s.fedMTLSCA(), fedMTLSClientCertHeader()))
			syncFed := handler.NewFederation(s.db, s.auditLog).WithFedTrust(s.fedSigner, s.fedJoinConfig())
			r.Get("/federation/sync", syncFed.Sync)
		})

		// Wave N6: heartbeat ingest. Accepts either a scanner-token OR a
		// runtime-agent-token (the operator + discoverer also use one of these
		// two, so we don't need a third token kind). Chained middleware tries
		// runtime-agent first, falls back to scanner-token, then 401s.
		r.Group(func(r chi.Router) {
			r.Use(handler.AnyServiceTokenMiddleware(s.db.Pool()))
			hb := handler.NewHeartbeats(s.db, s.auditLog)
			platformFacts := handler.NewPlatformFacts(s.db)
			r.Post("/heartbeats", hb.Ingest)
			r.Post("/platform-facts:report", platformFacts.Report)
		})

		// Astronomer-mounted routes (validated against Astronomer JWKS rather than our JWT).
		if s.cfg.AstronomerJWKSURL != "" {
			r.Group(func(r chi.Router) {
				r.Use(s.astronomerJWTMiddleware)
				r.Get("/security/findings", s.requireVerb(rbac.VerbReadFindings,
					findings.NewFindings(s.db, s.auditLog, nil).List))
				// (Other /security/* mounts are added as Astronomer's UI shells expand them.)
			})
		}
	})

	return r
}

// Handler returns the underlying chi router (used by tests).
func (s *Server) Handler() http.Handler { return s.router }

// Run starts the HTTP listener. Blocks until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.tel.Logger.Info("listening", slog.String("addr", s.cfg.ListenAddr))
		errCh <- srv.ListenAndServe()
	}()

	// D5: the HTTP server above runs on every replica (so each pod serves the
	// API + readiness), but the singleton background loops must run on exactly
	// one replica. With leader election disabled (default) we start them inline
	// — identical to the historical single-replica behavior. With it enabled we
	// start them only while this replica holds the lease.
	s.startBackgroundWork(ctx)

	// A5: hot-reload the session signing keys so a `--rotate-jwt-key` rotation
	// propagates to this already-running replica without a restart. Only runs on
	// the DB-backed RS256 path (an operator-supplied JWT_KEYS is static).
	if s.dbBackedSessionKeys {
		go s.runSessionKeyReloader(ctx)
	}

	// B1: hot-reload the system config so a PATCH on any replica reaches this
	// already-running replica's in-process accessor (and thus its consumers) without
	// a restart. Polls each cached org's revision every 30s, mirroring the session-key
	// reloader above.
	if s.syscfg != nil {
		go s.syscfg.Run(ctx, 30*time.Second, func(n int) {
			s.tel.Logger.Info("system config reloaded after PATCH", slog.Int("orgs", n))
		})
	}

	// B4: hot-reload the auth-provider (IdP) set so a CRUD change on any replica reaches this
	// running replica's login handler without a restart. Polls the bootstrap org's max
	// auth_servers revision every 30s, mirroring the session-key + system-config reloaders.
	if s.authProviders != nil && s.bootstrapOrgID != uuid.Nil {
		go s.runAuthProviderReloader(ctx)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if s.dispatcher != nil {
			s.dispatcher.Stop()
		}
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if s.dispatcher != nil {
			s.dispatcher.Stop()
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// runSessionKeyReloader periodically reloads the session signing keys from
// session_signing_keys and hot-swaps the in-process Signer when they change, so an
// out-of-band `constellation-api --rotate-jwt-key` rotation reaches this running
// replica without a restart. The new active key signs new tokens; the retained
// previous key keeps already-issued tokens verifiable until they expire — closing
// the cross-replica verification gap during rotation. Best-effort: a transient DB or
// parse error logs and retries on the next tick, leaving the current keys in place.
func (s *Server) runSessionKeyReloader(ctx context.Context) {
	const interval = 30 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastActive string
	if keys, err := auth.LoadSessionKeysPEM(ctx, s.db.Pool()); err == nil && len(keys) > 0 {
		lastActive = string(keys[0])
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			keys, err := auth.LoadSessionKeysPEM(ctx, s.db.Pool())
			if err != nil {
				s.tel.Logger.Warn("session key reload: load failed", slog.String("err", err.Error()))
				continue
			}
			if len(keys) == 0 || string(keys[0]) == lastActive {
				continue // unchanged
			}
			if err := s.signer.ReloadKeys(keys...); err != nil {
				s.tel.Logger.Warn("session key reload: swap failed", slog.String("err", err.Error()))
				continue
			}
			lastActive = string(keys[0])
			s.tel.Logger.Info("session signing key reloaded after rotation")
		}
	}
}

// runAuthProviderReloader periodically rebuilds the auth-provider (IdP) set from the bootstrap
// org's auth_servers rows and atomically swaps it in, so a CRUD change reaches this running
// replica's login handler without a restart. It polls the org's max revision and only rebuilds
// when it advances (cheap: one aggregate query per tick). Best-effort: a transient DB or build
// error logs and retries on the next tick, leaving the current providers in place. Mirrors
// runSessionKeyReloader / syscfg.Provider.Run.
func (s *Server) runAuthProviderReloader(ctx context.Context) {
	const interval = 30 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	last := s.authProviders.Revision()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rev, err := auth.MaxRevision(ctx, s.db.Pool(), s.bootstrapOrgID)
			if err != nil {
				s.tel.Logger.Warn("auth provider reload: revision check failed", slog.String("err", err.Error()))
				continue
			}
			if rev == last {
				continue // unchanged
			}
			if errs := s.authProviders.Reload(ctx, s.db.Pool(), s.bootstrapOrgID); len(errs) > 0 {
				for _, e := range errs {
					s.tel.Logger.Warn("auth provider reload: build", slog.String("err", e.Error()))
				}
			}
			last = rev
			s.tel.Logger.Info("auth providers reloaded after CRUD change", slog.Int64("revision", rev))
		}
	}
}

// ---------------- middleware ----------------

func (s *Server) slogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.tel.Logger.Info("http",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("request_id", chimw.GetReqID(r.Context())),
			slog.Duration("dur", time.Since(start)),
		)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		// PAT (Personal Access / API token) auth path. Tokens are minted via
		// /api/v1/api-tokens; the raw value is `cst_<base64url(32)>` and we store
		// sha256(raw). When the bearer matches an api_tokens row, the subject's
		// effective verbs are the intersection of the token's scopes ∩ the underlying
		// user (or service-account) role grants.
		if strings.HasPrefix(tok, "cst_") {
			subj, ok := handler.AuthenticateAPIToken(r.Context(), s.db.Pool(), tok, s.cfg.PATMaxLifetime, loadRoleAssignmentsAdapter(s.db))
			if !ok {
				writeError(w, http.StatusUnauthorized, "invalid api token")
				return
			}
			ctx := authctx.WithSubject(r.Context(), subj)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		claims, err := s.signer.Verify(tok)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		// A1: DB-backed session revocation. Re-read the user's disabled flag and
		// current session_epoch on every request (per-request, not cached) so a
		// disabled account or a bumped epoch (logout / delete / password-change /
		// role-change) invalidates an already-issued JWT on its next call —
		// consistently across API replicas. A missing row also rejects (deleted user).
		// must_change_password (A4) is read here too so the forced-reset gate below
		// can block everything except the password-change endpoint.
		var (
			disabled     bool
			sessionEpoch int64
			mustChange   bool
		)
		err = s.db.Pool().QueryRow(r.Context(),
			`SELECT disabled, session_epoch, must_change_password FROM users WHERE id = $1`, claims.UserID,
		).Scan(&disabled, &sessionEpoch, &mustChange)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "user not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load user")
			return
		}
		if disabled {
			writeError(w, http.StatusUnauthorized, "user disabled")
			return
		}
		if claims.Epoch < sessionEpoch {
			writeError(w, http.StatusUnauthorized, "session revoked")
			return
		}
		// A3: concurrent-session cap. A login records its JWT's session id in
		// user_sessions and evicts the oldest beyond the cap; a JWT whose session row is
		// gone has been evicted (logged in on too many devices) and is rejected here.
		// Legacy/test tokens minted without session tracking carry a session id too, so
		// we only enforce this when at least one session row exists for the user — an
		// empty set means tracking was never recorded (or was cleared on logout, which
		// also bumped the epoch and was already caught above).
		if sid := claims.SessionID(); sid != uuid.Nil {
			var (
				exists, anySession bool
				lastSeen           *time.Time
			)
			if qerr := s.db.Pool().QueryRow(r.Context(), `
SELECT EXISTS (SELECT 1 FROM user_sessions WHERE session_id = $1),
       EXISTS (SELECT 1 FROM user_sessions WHERE user_id = $2),
       (SELECT last_seen_at FROM user_sessions WHERE session_id = $1)`,
				sid, claims.UserID).Scan(&exists, &anySession, &lastSeen); qerr == nil {
				if anySession && !exists {
					writeError(w, http.StatusUnauthorized, "session evicted")
					return
				}
				// A7: idle/inactivity timeout. A tracked session whose last
				// authenticated request is older than the idle window is expired
				// even though the JWT is still inside its absolute TTL. We then
				// stamp last_seen_at = now() so an active session keeps sliding.
				// Untracked legacy/test tokens (no session row) skip this entirely.
				// A1: a per-org SecurityPolicy may override the deploy-time idle window
				// (falls back to the SESSION_IDLE_TIMEOUT env default when unconfigured).
				idle := s.cfg.SessionIdleTimeout
				if pol, _, perr := auth.LoadSecurityPolicy(r.Context(), s.db.Pool(), claims.OrgID); perr == nil {
					idle = pol.IdleTimeout(s.cfg.SessionIdleTimeout)
				}
				if exists && idle > 0 && lastSeen != nil {
					if time.Since(*lastSeen) > idle {
						// Hard-stop the idle session so a later request can't revive it.
						// Deleting the row alone is NOT enough: once it's gone, anySession
						// can be false and the same still-within-TTL JWT would be treated
						// as an untracked token and slip past on replay. Bumping the user's
						// session_epoch makes the epoch check above reject every later
						// replay of this (and any sibling) token. Best-effort: a bookkeeping
						// failure still 401s this request.
						_, _ = s.db.Pool().Exec(r.Context(),
							`DELETE FROM user_sessions WHERE session_id = $1`, sid)
						_, _ = s.db.Pool().Exec(r.Context(),
							`UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1`, claims.UserID)
						// RSP-AUDIT-05: an idle-timeout session rejection is a security-relevant
						// auth event; record it so inactivity expiries are visible in /audit/events
						// and the SIEM alongside failed logins.
						oid := claims.OrgID
						uid := claims.UserID
						_, _, _ = s.auditLog.Log(r.Context(), audit.Event{
							OrgID: &oid, ActorID: &uid, ActorIP: remoteHostIP(r.RemoteAddr),
							Action: "auth.session.idle_timeout", TargetKind: "user", TargetID: uid.String(),
						})
						writeError(w, http.StatusUnauthorized, "session idle timeout")
						return
					}
					if _, uerr := s.db.Pool().Exec(r.Context(),
						`UPDATE user_sessions SET last_seen_at = now() WHERE session_id = $1`, sid); uerr != nil {
						s.tel.Logger.Warn("update session last_seen_at", slog.String("err", uerr.Error()))
					}
				}
			}
		}
		// A4: forced password reset. While must_change_password is set, the only thing the
		// user may do is change their password (and logout). Everything else 403s until the
		// flag clears (ChangePassword clears it).
		if mustChange && !isPasswordChangePath(r) {
			writeError(w, http.StatusForbidden, "password change required")
			return
		}
		// Resolve role assignments from DB.
		assignments, err := loadRoleAssignments(r.Context(), s.db, claims.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load role assignments")
			return
		}
		ctx := authctx.WithSubject(r.Context(), authctx.Subject{
			UserID:      claims.UserID,
			OrgID:       claims.OrgID,
			Email:       claims.Email,
			Assignments: assignments,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loadRoleAssignmentsAdapter exposes loadRoleAssignments to handler.AuthenticateAPIToken
// without leaking the *db.DB type across packages. It returns a closure the handler can
// call with just a context + userID.
func loadRoleAssignmentsAdapter(database *db.DB) func(context.Context, uuid.UUID) ([]rbac.RoleAssignment, error) {
	return func(ctx context.Context, uid uuid.UUID) ([]rbac.RoleAssignment, error) {
		return loadRoleAssignments(ctx, database, uid)
	}
}

// astronomerJWTMiddleware validates an Astronomer-issued JWT via JWKS and maps the Astronomer
// identity to a Constellation subject via the astronomer_identity_map table.
func (s *Server) astronomerJWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.astronomerJWT == nil || s.astronomerMap == nil {
			writeError(w, http.StatusServiceUnavailable, "astronomer adapter disabled")
			return
		}
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := s.astronomerJWT.Verify(r.Context(), tok)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid astronomer token")
			return
		}
		astronomerUserID, err := astronomer.SubjectID(claims)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "astronomer token missing subject")
			return
		}
		userID, orgID, err := s.astronomerMap.Resolve(r.Context(), astronomerUserID)
		if errors.Is(err, astronomer.ErrUnmapped) {
			writeError(w, http.StatusForbidden, "astronomer identity not mapped")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "resolve astronomer identity")
			return
		}

		var email string
		var disabled bool
		err = s.db.Pool().QueryRow(r.Context(),
			`SELECT email, disabled FROM users WHERE id = $1 AND org_id = $2`,
			userID, orgID,
		).Scan(&email, &disabled)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusForbidden, "mapped constellation user not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load mapped constellation user")
			return
		}
		if disabled {
			writeError(w, http.StatusForbidden, "mapped constellation user disabled")
			return
		}
		assignments, err := loadRoleAssignments(r.Context(), s.db, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load role assignments")
			return
		}
		ctx := authctx.WithSubject(r.Context(), authctx.Subject{
			UserID:      userID,
			OrgID:       orgID,
			Email:       email,
			Assignments: assignments,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireVerb(verb rbac.Verb, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subj, ok := authctx.SubjectFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "no subject")
			return
		}
		// API-token (PAT) sessions narrow the effective verb set to the token's scopes.
		// This gate is in addition to (not a replacement for) the rbac.Authorize check
		// below — we want the intersection of role-granted and token-granted verbs.
		if !subj.HasTokenScope(verb) {
			writeError(w, http.StatusForbidden, "forbidden: token lacks scope "+string(verb))
			return
		}
		// P0-09: derive the cluster scope from the route so cluster-scoped assignments actually
		// authorize. On a /clusters/{id}/* route the resource is that cluster, so an org-scoped
		// grant still covers it (org ⊇ cluster) while a cluster-scoped grant covers ONLY its own
		// cluster and a mismatched or org-wide route is denied. Non-cluster routes stay org-scoped.
		res := rbac.Resource{OrgID: subj.OrgID}
		if cid := clusterScopeFromRequest(r); cid != nil {
			res.ClusterID = cid
		}
		var custom map[string][]rbac.Verb
		if s.customRoles != nil {
			custom = s.customRoles.VerbsForOrg(r.Context(), subj.OrgID)
		}
		if err := rbac.AuthorizeWithCustom(subj.Assignments, verb, res, custom); err != nil {
			writeError(w, http.StatusForbidden, "forbidden: "+string(verb))
			return
		}
		h(w, r)
	}
}

// clusterScopeFromRequest returns the cluster the request targets, or nil for org-wide routes.
// A route is cluster-scoped iff its chi pattern carries the /clusters/{id} segment (both the
// direct /clusters/{id}/* subtree and the /federation/clusters/{id}/* proxy), where {id} is a
// cluster id. requireVerb uses this to build a cluster-scoped rbac.Resource so cluster-scoped
// role assignments authorize on their own cluster only.
func clusterScopeFromRequest(r *http.Request) *uuid.UUID {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return nil
	}
	return clusterScopeFromPattern(rctx.RoutePattern(), chi.URLParam(r, "id"))
}

// clusterScopeFromPattern is the pure core of clusterScopeFromRequest, split out for testing:
// it returns the parsed cluster id when pattern addresses the /clusters/{id} subtree and idParam
// is a valid UUID, else nil.
func clusterScopeFromPattern(pattern, idParam string) *uuid.UUID {
	if !strings.Contains(pattern, "/clusters/{id}") || idParam == "" {
		return nil
	}
	cid, err := uuid.Parse(idParam)
	if err != nil {
		return nil
	}
	return &cid
}

// ---------------- handlers (root) ----------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleVersion exposes the API binary's build triplet at /version (root-level,
// unauthenticated). Wave N6: lets external tooling and liveness probes pull
// the SHA without juggling tokens.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"component":    "api",
		"version":      version.Version,
		"commit":       version.Commit,
		"commit_short": version.ShortCommit(),
		"build_time":   version.BuildTimeParsed().Format(time.RFC3339),
		"started_at":   version.Started().UTC().Format(time.RFC3339),
		"uptime_s":     int64(version.Uptime().Seconds()),
	})
}

// handleAPIVersion is the auth-gated /api/v1/version mirror.
func (s *Server) handleAPIVersion(w http.ResponseWriter, r *http.Request) {
	s.handleVersion(w, r)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Health(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "db unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ---------------- helpers ----------------

// A3 rate-limit knobs. Per-minute ceilings; like the A2 lockout consts these are
// package-level for now and move into per-org system_config (B1) later.
const (
	// authIPRateLimit caps unauthenticated /auth/* requests per client IP per minute.
	authIPRateLimit = 10
	// apiTokenRateLimit is the lenient per-credential ceiling on /api/v1/* per minute —
	// an abuse breaker, set far above any legitimate interactive burst.
	apiTokenRateLimit = 600
)

// apiRateLimitKey keys the /api/v1/* rate limiter by bearer token when present (so the
// ceiling is per-credential, not per-IP — many users behind one NAT are not penalized),
// falling back to the client IP for keyless requests.
func apiRateLimitKey(r *http.Request) (string, error) {
	if tok := bearerToken(r); tok != "" {
		return "tok:" + tok, nil
	}
	return httprate.KeyByIP(r)
}

// rateLimited is the 429 handler shared by both limiters; it emits the API's standard
// JSON error envelope instead of httprate's default plain-text body.
func rateLimited(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

// trustedProxyRealIP returns middleware that applies chi's RealIP rewrite (which
// derives RemoteAddr from X-Forwarded-For / X-Real-IP / True-Client-IP) ONLY for
// requests whose direct TCP peer falls inside a trusted-proxy CIDR. For every
// other peer RemoteAddr is left as the real socket address. This closes the
// credential-spray bypass: without the gate, any client could spoof a forwarded
// header to mint a fresh per-IP auth rate-limit bucket on each request.
//
// Trusted CIDRs come from CONSTELLATION_TRUSTED_PROXIES (comma-separated CIDRs or
// bare IPs). When unset, we default to loopback + RFC1918/RFC4193 private ranges
// so the common single-proxy ingress (proxy on a private/pod IP) keeps working
// with no configuration, while a directly internet-exposed server ignores
// forwarded headers from public clients.
func (s *Server) trustedProxyRealIP() func(http.Handler) http.Handler {
	trusted := parseTrustedProxies(os.Getenv("CONSTELLATION_TRUSTED_PROXIES"))
	realIP := chimw.RealIP
	return func(next http.Handler) http.Handler {
		honored := realIP(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ipInNets(remoteHostIP(r.RemoteAddr), trusted) {
				honored.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// remoteHostIP extracts the IP from a "host:port" RemoteAddr (or a bare host).
func remoteHostIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parses a comma-separated CONSTELLATION_TRUSTED_PROXIES
// value into CIDRs. Bare IPs are treated as single-host CIDRs. An unset/blank
// value yields the private+loopback defaults; a value that is set but parses to
// zero valid entries trusts nothing (fail-safe: forwarded headers are ignored).
func parseTrustedProxies(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultTrustedProxyNets()
	}
	var out []*net.IPNet
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if !strings.Contains(tok, "/") {
			if ip := net.ParseIP(tok); ip != nil {
				if ip.To4() != nil {
					tok += "/32"
				} else {
					tok += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(tok); err == nil {
			out = append(out, n)
		} else {
			slog.Default().Warn("ignoring invalid CONSTELLATION_TRUSTED_PROXIES entry",
				slog.String("entry", tok), slog.String("err", err.Error()))
		}
	}
	return out
}

// defaultTrustedProxyNets is the trusted set used when CONSTELLATION_TRUSTED_PROXIES
// is unset: loopback + RFC1918 + RFC4193 private ranges. These cover the typical
// in-cluster ingress/proxy without trusting public-internet sources.
func defaultTrustedProxyNets() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// isPasswordChangePath reports whether the request targets an endpoint a
// must-change-password user is still allowed to reach (A4): the password-change endpoint
// itself and logout. Everything else is blocked until the flag clears.
func isPasswordChangePath(r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/auth/change-password", "/api/v1/auth/logout":
		return true
	}
	return false
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// loadRoleAssignments queries role_assignments for the user. The inline pgx query below is
// the source of truth; the schema lives in db/migrations.
func loadRoleAssignments(ctx context.Context, database *db.DB, userID uuid.UUID) ([]rbac.RoleAssignment, error) {
	// P0-11: an assignment mirrored from an expiring role binding stops authorizing once its
	// expires_at passes. This is the single per-request loader, so filtering here enforces
	// expiry everywhere without a background reaper.
	rows, err := database.Pool().Query(ctx, `
SELECT role, scope_org_id, scope_cluster_id, scope_project_id, scope_namespace
  FROM role_assignments
 WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now())`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rbac.RoleAssignment
	for rows.Next() {
		var role, namespace string
		var org uuid.UUID
		var cluster, project *uuid.UUID
		// P0-10: scope_namespace narrows a grant to one namespace on scope_cluster_id. Loading it
		// here (the single per-request authz loader) is what stops a materialized namespace grant
		// from authorizing the whole cluster — Authorize gates it against the resource's namespace.
		if err := rows.Scan(&role, &org, &cluster, &project, &namespace); err != nil {
			return nil, err
		}
		out = append(out, rbac.RoleAssignment{
			Role:  role,
			Scope: rbac.Scope{OrgID: org, ClusterID: cluster, ProjectID: project, Namespace: namespace},
		})
	}
	return out, rows.Err()
}
