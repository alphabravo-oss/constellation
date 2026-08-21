package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// Auth bundles the auth-related routes.
type Auth struct {
	db       *db.DB
	signer   *auth.Signer
	oidc     *auth.OIDCClient
	saml     *auth.SAMLProvider
	ldap     *auth.LDAPProvider
	auditLog *audit.Logger

	// providers, when non-nil, is the B4 DB-backed, hot-reloadable provider set. The login
	// endpoints read the LIVE provider through providerOIDC/providerSAML/providerLDAP, which
	// prefer the set's current snapshot and fall back to the static fields when the set is nil
	// (env-only deployments / tests). This is what lets a runtime IdP CRUD change take effect
	// WITHOUT a restart.
	providers *auth.ProviderSet

	// samlParse resolves a validated SAML identity from the ACS request. Defaults to the
	// provider's signature-validating ParseResponse; overridable in tests to drive a canned
	// assertion (no live IdP / no signature).
	samlParse func(*http.Request) (*auth.AssertionIdentity, error)
	// samlParseOverridden is set by setSAMLParseFunc (the test-only seam). When true the
	// live provider-set's ParseResponse is NOT substituted, so the canned-assertion test path
	// keeps working even after a provider-set reload.
	samlParseOverridden bool
}

func NewAuth(database *db.DB, signer *auth.Signer, oidc *auth.OIDCClient, samlP *auth.SAMLProvider, ldapP *auth.LDAPProvider, auditLog *audit.Logger) *Auth {
	a := &Auth{db: database, signer: signer, oidc: oidc, saml: samlP, ldap: ldapP, auditLog: auditLog}
	if samlP != nil {
		a.samlParse = samlP.ParseResponse
	}
	return a
}

// WithProviderSet attaches the B4 hot-reloadable provider set so the login endpoints resolve
// the LIVE provider built from the auth_servers rows (rebuilt on a CRUD change without a restart).
// Returns the receiver for chaining at wire-up. When the set has a SAML provider, samlParse is
// (re)bound dynamically per-request through providerSAMLParse, so a reload swaps the validator too.
func (a *Auth) WithProviderSet(ps *auth.ProviderSet) *Auth {
	a.providers = ps
	return a
}

// providerOIDC returns the live OIDC client: the provider-set snapshot if attached, else the
// static env-wired one.
func (a *Auth) providerOIDC() *auth.OIDCClient {
	if a.providers != nil {
		if p := a.providers.OIDC(); p != nil {
			return p
		}
	}
	return a.oidc
}

// providerSAML returns the live SAML provider (set snapshot, else static).
func (a *Auth) providerSAML() *auth.SAMLProvider {
	if a.providers != nil {
		if p := a.providers.SAML(); p != nil {
			return p
		}
	}
	return a.saml
}

// providerLDAP returns the live LDAP provider (set snapshot, else static).
func (a *Auth) providerLDAP() *auth.LDAPProvider {
	if a.providers != nil {
		if p := a.providers.LDAP(); p != nil {
			return p
		}
	}
	return a.ldap
}

// providerSAMLParse returns the SAML ACS identity resolver to use for this request. A test-set
// samlParse override always wins (so the canned-assertion seam keeps working); otherwise it binds
// to the LIVE provider's signature-validating ParseResponse so a reload swaps the validator.
func (a *Auth) providerSAMLParse() func(*http.Request) (*auth.AssertionIdentity, error) {
	if !a.samlParseOverridden {
		if p := a.providerSAML(); p != nil {
			return p.ParseResponse
		}
	}
	return a.samlParse
}

// setSAMLParseFunc overrides the SAML ACS identity resolver. UNEXPORTED on purpose: this is a
// test-only seam (callable only from within the handler package's own tests) so production code
// in any other package can never swap out the provider's signature-validating ParseResponse —
// the live ACS path (NewAuth) always wires ParseResponse, which validates XML-DSig via
// crewjam/saml. Do NOT export this.
func (a *Auth) setSAMLParseFunc(f func(*http.Request) (*auth.AssertionIdentity, error)) {
	a.samlParse = f
	a.samlParseOverridden = true
}

// ldapLoginRequest is the body for POST /auth/ldap/login.
type ldapLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type loginPrincipal struct {
	UserID            uuid.UUID
	OrgID             uuid.UUID
	PasswordHash      *string
	SessionEpoch      int64
	PasswordChangedAt *time.Time
}

// Brute-force lockout knobs (A2). Kept as package consts for now; the plan moves
// these into per-org system_config (B1) later — they are intentionally in one place
// so that migration is a mechanical lift, not a hunt.
const (
	// maxFailedLogins is the number of consecutive failures that trips the lockout.
	maxFailedLogins = 5
	// loginLockoutWindow is how long an account stays locked after the most recent failure
	// once the threshold is crossed. The failure count itself does not decay with time; it
	// is cleared only by a successful authentication (see recordLoginSuccess).
	loginLockoutWindow = 15 * time.Minute
)

// maxConcurrentSessions caps the number of simultaneously-live JWT sessions per user (A3).
// A login past the cap evicts the user's oldest session(s). Overridable via
// MAX_CONCURRENT_SESSIONS (default 5) so shared automation logins can't crowd out a human
// user's session on a busy dev instance; moves into per-org system_config (B1) later.
var maxConcurrentSessions = envIntDefault("MAX_CONCURRENT_SESSIONS", 5)

func envIntDefault(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// errLoginLocked is the sentinel returned by the lockout pre-check. The HTTP layer maps
// it (and every other auth failure) to the same generic 401 so a caller cannot use the
// response to distinguish "locked" from "wrong password" from "no such user".
var errLoginLocked = errors.New("account temporarily locked")

// decoyPasswordHash is a fixed Argon2id hash of an unguessable value, computed once at
// startup. The local-login path runs VerifyPassword against it whenever the user is unknown
// or has no local password (password_hash IS NULL), so the unknown-user / SSO-only / wrong-
// password branches all spend comparable Argon2id time before returning the SAME generic 401.
// This removes the timing- and message-based user-enumeration oracles (A2): an attacker can no
// longer distinguish "no such account" from "account exists but bad password" from "SSO-only
// account". The decoy value is irrelevant (it is never a valid login secret); only its cost
// matters, so it is hashed with the production Argon2id parameters.
var decoyPasswordHash = func() string {
	h, err := auth.HashPassword("constellation-decoy-" + uuid.NewString())
	if err != nil {
		// Argon2id hashing has no failure mode here beyond a salt-RNG error; a malformed
		// decoy still consumes time on VerifyPassword's format check, which is acceptable.
		return "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	return h
}()

// Login authenticates against a local Argon2id-hashed user.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	principal, err := a.resolveLoginPrincipal(r.Context(), req.Email)
	if err != nil {
		// Unknown user: burn comparable Argon2id time against a decoy hash and return the
		// SAME generic 401 as a wrong password, so neither the message nor the latency
		// reveals whether the account exists (A2: no user-enumeration oracle). The audit row
		// (RSP-AUDIT-05) is server-side only, so it doesn't reintroduce an enumeration oracle.
		_ = auth.VerifyPassword(decoyPasswordHash, req.Password)
		a.auditLoginFailure(r.Context(), r, nil, nil, req.Email, "unknown_user")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	// A2: brute-force lockout pre-check. If the account is inside the lockout window we
	// reject before touching the password — and with the same generic message used for a
	// wrong password / unknown user, so the response leaks no valid/locked/invalid oracle.
	if lerr := a.loginLocked(r.Context(), principal.OrgID, principal.UserID); lerr != nil {
		// A2: burn comparable Argon2id time against the decoy before returning, so a locked
		// account does not respond measurably faster than the unknown-user / wrong-password
		// branches (which each run one VerifyPassword). Otherwise the latency gap is a
		// user-enumeration / lockout oracle.
		_ = auth.VerifyPassword(decoyPasswordHash, req.Password)
		a.auditLoginFailure(r.Context(), r, &principal.OrgID, &principal.UserID, req.Email, "account_locked")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if principal.PasswordHash == nil {
		// SSO-only / no local password. Burn decoy Argon2id time and return the SAME generic
		// 401 as a wrong password (A2: do not reveal that the account exists but is SSO-only).
		_ = auth.VerifyPassword(decoyPasswordHash, req.Password)
		a.auditLoginFailure(r.Context(), r, &principal.OrgID, &principal.UserID, req.Email, "no_local_password")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err := auth.VerifyPassword(*principal.PasswordHash, req.Password); err != nil {
		// A2: count the failure (and trip the lockout once the threshold is crossed).
		locked := a.recordLoginFailure(r.Context(), principal.OrgID, principal.UserID)
		a.auditLoginFailure(r.Context(), r, &principal.OrgID, &principal.UserID, req.Email, "bad_password")
		if locked {
			a.auditLoginLocked(r.Context(), r, &principal.OrgID, &principal.UserID, req.Email)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	// A2: success clears the counter + any lockout.
	a.recordLoginSuccess(r.Context(), principal.UserID)
	// A4b: enforce password max-age. The password was correct but it's past MaxAge (matching
	// NeuVector's EnablePwdExpiration / BlockedForPwdExpired), so flag the account for forced
	// reset and let login PROCEED. The auth middleware then blocks everything except the
	// password-change endpoint until the user resets (ChangePassword clears the flag and
	// refreshes password_changed_at, resetting the age). We must not hard-fail here: the
	// change-password endpoint itself needs a session, so a 401/403 would trap the user with
	// no way to recover. NULL password_changed_at (pre-policy users) is never expired, so an
	// upgrade doesn't mass-flag every existing account.
	if profile := auth.LoadPasswordProfile(r.Context(), a.db.Pool(), principal.OrgID); profile.MaxAge > 0 &&
		principal.PasswordChangedAt != nil &&
		time.Since(*principal.PasswordChangedAt) > profile.MaxAge {
		if _, uerr := a.db.Pool().Exec(r.Context(),
			`UPDATE users SET must_change_password = TRUE WHERE id = $1`, principal.UserID); uerr != nil {
			slog.WarnContext(r.Context(), "flag expired password", slog.String("err", uerr.Error()))
		}
		_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
			OrgID:      &principal.OrgID,
			ActorID:    &principal.UserID,
			Action:     "auth.login.password_expired",
			TargetKind: "user",
			TargetID:   principal.UserID.String(),
		})
		// fall through — issue the session; the middleware forces the reset.
	}
	roles, _ := loadRoleNames(r.Context(), a.db, principal.UserID)
	tok, expiresAt, err := a.issueSession(r.Context(), principal.UserID, principal.OrgID, req.Email, roles, principal.SessionEpoch)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue token"})
		return
	}
	_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &principal.OrgID,
		ActorID:    &principal.UserID,
		Action:     "auth.login.local",
		TargetKind: "user",
		TargetID:   principal.UserID.String(),
	})
	writeJSON(w, http.StatusOK, loginResponse{Token: tok, ExpiresAt: expiresAt})
}

func (a *Auth) resolveLoginPrincipal(ctx context.Context, email string) (loginPrincipal, error) {
	rows, err := a.db.Pool().Query(ctx, `
SELECT id, org_id, password_hash, session_epoch, password_changed_at
  FROM users
 WHERE lower(email) = lower($1)
   AND disabled = FALSE
 ORDER BY created_at, id
 LIMIT 2`,
		email,
	)
	if err != nil {
		return loginPrincipal{}, err
	}
	defer rows.Close()

	var matches []loginPrincipal
	for rows.Next() {
		var out loginPrincipal
		if err := rows.Scan(&out.UserID, &out.OrgID, &out.PasswordHash, &out.SessionEpoch, &out.PasswordChangedAt); err != nil {
			return loginPrincipal{}, err
		}
		matches = append(matches, out)
	}
	if err := rows.Err(); err != nil {
		return loginPrincipal{}, err
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return loginPrincipal{}, pgx.ErrNoRows
}

// loginLocked reports whether the user is currently inside the brute-force lockout
// window (A2). It returns errLoginLocked when block_login_since is set and still within
// loginLockoutWindow. A DB error is returned as-is and treated as a hard failure by the
// caller (fail closed). Missing row => not locked (no oracle is leaked either way).
func (a *Auth) loginLocked(ctx context.Context, orgID, userID uuid.UUID) error {
	var blockSince *time.Time
	err := a.db.Pool().QueryRow(ctx,
		`SELECT block_login_since FROM users WHERE id = $1`, userID,
	).Scan(&blockSince)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	// A1: a per-org SecurityPolicy may override the deploy-time lockout window.
	window := loginLockoutWindow
	if pol, _, perr := auth.LoadSecurityPolicy(ctx, a.db.Pool(), orgID); perr == nil {
		window = pol.EffectiveLockoutWindow(loginLockoutWindow)
	}
	if blockSince != nil && time.Since(*blockSince) < window {
		return errLoginLocked
	}
	return nil
}

// recordLoginFailure increments failed_login_count and, once the threshold is crossed,
// stamps block_login_since to start the lockout window (A2). It returns whether the account
// is now in a locked state so the caller can emit an auth.login.locked audit event
// (RSP-AUDIT-05). Best-effort: a failure to record the failure must not change the auth
// outcome (the request is already a 401), and reports not-locked on error.
func (a *Auth) recordLoginFailure(ctx context.Context, orgID, userID uuid.UUID) (locked bool) {
	// A1: a per-org SecurityPolicy may override the deploy-time failure threshold.
	threshold := maxFailedLogins
	if pol, _, perr := auth.LoadSecurityPolicy(ctx, a.db.Pool(), orgID); perr == nil {
		threshold = pol.EffectiveLockoutThreshold(maxFailedLogins)
	}
	err := a.db.Pool().QueryRow(ctx, `
UPDATE users
   SET failed_login_count = failed_login_count + 1,
       block_login_since = CASE
           WHEN failed_login_count + 1 >= $2 THEN now()
           ELSE block_login_since
       END
 WHERE id = $1
 RETURNING (failed_login_count >= $2 AND block_login_since IS NOT NULL)`, userID, threshold).Scan(&locked)
	if err != nil {
		slog.WarnContext(ctx, "record login failure", slog.String("err", err.Error()))
		return false
	}
	return locked
}

// loginUsername picks the most human-readable identifier for an external-IdP login audit
// row: the asserted email when present, else the IdP subject (DN / NameID / sub).
func loginUsername(email, subject string) string {
	if strings.TrimSpace(email) != "" {
		return email
	}
	return subject
}

// actorIPFromRequest extracts the client IP from the request's RemoteAddr (which the server
// rewrites from X-Forwarded-For/-Real-IP only for trusted proxies). Used to stamp auth
// audit events with the source IP.
func actorIPFromRequest(r *http.Request) net.IP {
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	return actorIP
}

// auditLoginFailure emits an auth.login.failed audit row (RSP-AUDIT-05) with the source IP,
// the attempted username, and a machine-readable reason so brute-force is visible to
// /audit/events and the SIEM. orgID/userID are nil for an unknown/unlinked identity. This
// is server-side only — the HTTP response stays a generic 401 (no user enumeration).
func (a *Auth) auditLoginFailure(ctx context.Context, r *http.Request, orgID, userID *uuid.UUID, username, reason string) {
	targetID := ""
	if userID != nil {
		targetID = userID.String()
	}
	_, _, _ = a.auditLog.Log(ctx, audit.Event{
		OrgID:      orgID,
		ActorID:    userID,
		ActorIP:    actorIPFromRequest(r),
		Action:     "auth.login.failed",
		TargetKind: "user",
		TargetID:   targetID,
		After:      map[string]any{"username": username, "reason": reason},
	})
}

// auditLoginLocked emits an auth.login.locked audit row when a failed login trips the
// brute-force lockout (RSP-AUDIT-05).
func (a *Auth) auditLoginLocked(ctx context.Context, r *http.Request, orgID, userID *uuid.UUID, username string) {
	targetID := ""
	if userID != nil {
		targetID = userID.String()
	}
	_, _, _ = a.auditLog.Log(ctx, audit.Event{
		OrgID:      orgID,
		ActorID:    userID,
		ActorIP:    actorIPFromRequest(r),
		Action:     "auth.login.locked",
		TargetKind: "user",
		TargetID:   targetID,
		After:      map[string]any{"username": username},
	})
}

// recordLoginSuccess clears the failed-login counter and any lockout (A2). Best-effort.
func (a *Auth) recordLoginSuccess(ctx context.Context, userID uuid.UUID) {
	if _, err := a.db.Pool().Exec(ctx,
		`UPDATE users SET failed_login_count = 0, block_login_since = NULL WHERE id = $1`,
		userID,
	); err != nil {
		slog.WarnContext(ctx, "reset login failure counter", slog.String("err", err.Error()))
	}
}

// bumpSessionEpoch increments users.session_epoch (A1), invalidating every
// previously-issued session JWT for the user on its next request. Used by logout and
// (via BumpSessionEpoch) by disable/delete/password-change/role-change cascades.
func bumpSessionEpoch(ctx context.Context, pool sessionEpochExecer, userID uuid.UUID) error {
	_, err := pool.Exec(ctx, `UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1`, userID)
	return err
}

// sessionEpochExecer is the minimal Exec surface shared by *pgxpool.Pool and pgx.Tx so
// the epoch bump + cascade can run either standalone or inside a caller's transaction.
type sessionEpochExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RevokeUserSessions bumps the user's session epoch and cascades credential revocation
// (A1 step 5/6): it revokes every API token attached to the user and removes the user's
// role_assignments. Call inside the same transaction that disables or deletes the user so
// the JWT invalidation, PAT revocation, and role teardown are atomic. Exported so the
// user-management handlers (disable / delete / password-change / role-change) can reuse it.
func RevokeUserSessions(ctx context.Context, tx sessionEpochExecer, userID uuid.UUID) error {
	if err := bumpSessionEpoch(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = now(), status = 'revoked'
		  WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM role_assignments WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM user_sessions WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return nil
}

// issueSession mints a session JWT for the user and records it for the A3
// concurrent-session cap: the new session id is inserted into user_sessions and any
// sessions beyond maxConcurrentSessions (oldest first) are evicted. The auth middleware
// rejects a JWT whose session row has been evicted, so logging in on an (N+1)th device
// silently logs out the oldest device — bounded fan-out, not a full epoch bump. Session
// tracking is best-effort: a bookkeeping failure must not block an otherwise-valid login
// (the JWT still works; the cap is simply not tightened for that login).
func (a *Auth) issueSession(ctx context.Context, userID, orgID uuid.UUID, email string, roles []string, epoch int64) (string, time.Time, error) {
	// A1: a per-org SecurityPolicy may override the deploy-time JWT TTL at login time. Load it
	// (falling back to the signer's env default when the org has no policy row) and mint the
	// session with that absolute lifetime so the returned expires_at matches the JWT's exp.
	ttl := a.signer.TTL()
	if pol, _, perr := auth.LoadSecurityPolicy(ctx, a.db.Pool(), orgID); perr == nil {
		ttl = pol.SessionTTL(ttl)
	}
	expiresAt := time.Now().Add(ttl)
	tok, sessionID, err := a.signer.IssueWithTTL(ttl, userID, orgID, email, roles, epoch)
	if err != nil {
		return "", time.Time{}, err
	}
	// A3: record the new session and evict the oldest beyond the cap in ONE transaction, so the
	// invariant "at most maxConcurrentSessions rows per user" cannot be transiently violated by a
	// partial write (the original code ran the INSERT and DELETE as two independent Execs, so a
	// failure between them could leave the user over the cap). Eviction keeps the most recent
	// maxConcurrentSessions by created_at; session_id is a deterministic tiebreaker for the
	// (rare) sub-millisecond-simultaneous case so the same row is chosen regardless of plan.
	// Session tracking remains best-effort: a bookkeeping failure rolls back and does not block
	// the otherwise-valid login (the JWT still works; the cap is simply not tightened this time).
	tx, err := a.db.Pool().Begin(ctx)
	if err != nil {
		slog.WarnContext(ctx, "record session: begin", slog.String("err", err.Error()))
		return tok, expiresAt, nil
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO user_sessions (session_id, user_id) VALUES ($1, $2)`, sessionID, userID); err != nil {
		slog.WarnContext(ctx, "record session", slog.String("err", err.Error()))
		return tok, expiresAt, nil
	}
	if _, err := tx.Exec(ctx, `
DELETE FROM user_sessions
 WHERE user_id = $1
   AND session_id NOT IN (
       SELECT session_id FROM user_sessions
        WHERE user_id = $1
        ORDER BY created_at DESC, session_id
        LIMIT $2
   )`, userID, maxConcurrentSessions); err != nil {
		slog.WarnContext(ctx, "evict sessions", slog.String("err", err.Error()))
		return tok, expiresAt, nil
	}
	if err := tx.Commit(ctx); err != nil {
		slog.WarnContext(ctx, "record session: commit", slog.String("err", err.Error()))
	}
	return tok, expiresAt, nil
}

// changePasswordRequest is the body for POST /auth/change-password.
type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword is the self-service password-change endpoint (A4). It verifies the
// caller's current password, enforces the password policy on the new one, rejects reuse
// of the last HistoryDepth passwords, stores the new hash, records the old hash in
// password_history, clears must_change_password, and bumps session_epoch so every other
// live JWT for the user is invalidated. The whole change is one transaction.
func (a *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok || subj.UserID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	// A1: enforce the caller's per-org password policy (falls back to the built-in default when
	// the org has no policy row), superseding the hardcoded DefaultPasswordProfile.
	profile := auth.LoadPasswordProfile(r.Context(), a.db.Pool(), subj.OrgID)

	var currentHash *string
	if err := a.db.Pool().QueryRow(r.Context(),
		`SELECT password_hash FROM users WHERE id = $1`, subj.UserID,
	).Scan(&currentHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load user"})
		return
	}
	if currentHash == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "local login not enabled for user"})
		return
	}
	if err := auth.VerifyPassword(*currentHash, req.CurrentPassword); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password incorrect"})
		return
	}
	// A4: policy + reuse enforcement.
	if err := auth.ValidatePassword(profile, req.NewPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password does not meet policy"})
		return
	}
	reused, err := a.passwordReused(r.Context(), subj.UserID, *currentHash, req.NewPassword, profile.HistoryDepth)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "check password history"})
		return
	}
	if reused {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password was used recently; choose a new one"})
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash password"})
		return
	}
	if err := a.commitPasswordChange(r.Context(), subj.UserID, *currentHash, newHash, profile.HistoryDepth); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "change password"})
		return
	}
	_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
		OrgID: &subj.OrgID, ActorID: &subj.UserID,
		Action: "auth.password.change", TargetKind: "user", TargetID: subj.UserID.String(),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// passwordReused reports whether candidate matches the user's current password hash or
// any of the last `depth` hashes in password_history. depth <= 0 disables the check.
func (a *Auth) passwordReused(ctx context.Context, userID uuid.UUID, currentHash, candidate string, depth int) (bool, error) {
	if depth <= 0 {
		return false, nil
	}
	// The current password also counts as "recently used".
	if auth.VerifyPassword(currentHash, candidate) == nil {
		return true, nil
	}
	rows, err := a.db.Pool().Query(ctx, `
SELECT password_hash FROM password_history
 WHERE user_id = $1
 ORDER BY created_at DESC
 LIMIT $2`, userID, depth)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return false, err
		}
		if auth.VerifyPassword(h, candidate) == nil {
			return true, nil
		}
	}
	return false, rows.Err()
}

// commitPasswordChange atomically: appends the old hash to password_history, prunes it to
// the most recent `depth` entries, writes the new hash + password_changed_at, clears
// must_change_password, and bumps session_epoch (A1) to invalidate the user's other live
// JWTs.
func (a *Auth) commitPasswordChange(ctx context.Context, userID uuid.UUID, oldHash, newHash string, depth int) error {
	tx, err := a.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)`, userID, oldHash); err != nil {
		return err
	}
	if depth > 0 {
		if _, err := tx.Exec(ctx, `
DELETE FROM password_history
 WHERE user_id = $1
   AND id NOT IN (
       SELECT id FROM password_history
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2
   )`, userID, depth); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
UPDATE users
   SET password_hash = $2,
       password_changed_at = now(),
       must_change_password = FALSE,
       session_epoch = session_epoch + 1
 WHERE id = $1`, userID, newHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// OIDCStart redirects (via JSON) to the IdP. Frontend follows the URL.
func (a *Auth) OIDCStart(w http.ResponseWriter, r *http.Request) {
	oidc := a.providerOIDC()
	if oidc == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "oidc disabled"})
		return
	}
	url, state, verifier, nonce, err := oidc.StartURL()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// State + verifier + nonce go into short-lived HttpOnly cookies; the callback validates
	// them. state defends the redirect (CSRF); nonce binds the returned id_token to this login.
	http.SetCookie(w, &http.Cookie{Name: "oidc_state", Value: state, Path: "/", HttpOnly: true, Secure: true, MaxAge: 600, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "oidc_verifier", Value: verifier, Path: "/", HttpOnly: true, Secure: true, MaxAge: 600, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "oidc_nonce", Value: nonce, Path: "/", HttpOnly: true, Secure: true, MaxAge: 600, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]string{"authorize_url": url})
}

// OIDCCallback handles the IdP redirect, exchanges the code, and issues a Constellation JWT.
func (a *Auth) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	oidc := a.providerOIDC()
	if oidc == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "oidc disabled"})
		return
	}
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	stateCookie, _ := r.Cookie("oidc_state")
	verifierCookie, _ := r.Cookie("oidc_verifier")
	nonceCookie, _ := r.Cookie("oidc_nonce")
	if stateCookie == nil || verifierCookie == nil || nonceCookie == nil || stateCookie.Value != state {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state mismatch"})
		return
	}
	claims, _, err := oidc.Exchange(r.Context(), code, verifierCookie.Value, nonceCookie.Value)
	if err != nil {
		// RSP-AUDIT-05: a failed OIDC code exchange / id_token validation is a failed login
		// attempt on the OIDC path — audit it (identity unknown pre-validation, so no username).
		a.auditLoginFailure(r.Context(), r, nil, nil, "", "oidc_exchange_failed")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	// Route OIDC through the shared linked-session tail (like SAML/LDAP) so its id_token groups are
	// mapped to roles via the provider's RoleMapping and reconciled by the JIT path — previously the
	// configured OIDC group->role map was silently dropped and only DB role_assignments applied.
	roles := oidc.MapRoles(claims.Groups)
	a.issueLinkedSession(w, r, claims.Issuer, claims.Subject, claims.Email, roles, oidc.MapScopedRoles(claims.Groups), "auth.login.oidc")
}

// SAMLLogin starts an SP-initiated SAML login: it mints an AuthnRequest (recording its ID so the
// ACS can match InResponseTo) and redirects the browser to the IdP's SSO endpoint. Mirrors
// OIDCStart but uses a 302 since the SAML redirect binding is a plain browser redirect.
func (a *Auth) SAMLLogin(w http.ResponseWriter, r *http.Request) {
	saml := a.providerSAML()
	if saml == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "saml disabled"})
		return
	}
	redirectURL, err := saml.StartLogin(r.URL.Query().Get("relay_state"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// SAMLACS is the SAML 2.0 Assertion Consumer Service: the IdP POSTs a signed SAMLResponse here.
// It validates the assertion, maps groups->roles, links the IdP identity to a provisioned user
// via the shared oidc_issuer/oidc_subject columns (SAML Issuer + NameID), and issues an
// identical session to OIDCCallback.
func (a *Auth) SAMLACS(w http.ResponseWriter, r *http.Request) {
	parse := a.providerSAMLParse()
	if a.providerSAML() == nil || parse == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "saml disabled"})
		return
	}
	id, err := parse(r)
	if err != nil {
		// RSP-AUDIT-05: a rejected/invalid SAML assertion is a failed login attempt on the SAML
		// path — audit it (identity unresolved pre-validation, so no username).
		a.auditLoginFailure(r.Context(), r, nil, nil, "", "saml_validation_failed")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	a.issueLinkedSession(w, r, id.Issuer, id.Subject, id.Email, id.Roles, id.ScopedRoles, "auth.login.saml")
}

// LDAPLogin authenticates a username/password against the configured LDAP/AD directory, maps the
// user's groups to roles, links the DN to a provisioned user via the shared oidc_issuer/
// oidc_subject columns (issuer "ldap:<URL>", subject = DN), and issues an identical session.
func (a *Auth) LDAPLogin(w http.ResponseWriter, r *http.Request) {
	ldap := a.providerLDAP()
	if ldap == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "ldap disabled"})
		return
	}
	var req ldapLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	issuer := ldapIssuer(ldap.URL())
	// A2: lockout pre-check for the LDAP path. The lockout MUST key off the same directory
	// identity the password bind authenticates — not the email guess. We resolve the user's
	// DN via a service-account search (no password) and look the linked constellation user up
	// by (issuer, oidc_subject = DN); this is stable whether the login name is an email, uid,
	// or sAMAccountName, and whatever its casing. We fall back to the email-keyed lookup only
	// when the DN search misses (e.g. directory transiently unreachable), so legacy
	// username==email deployments still trip. Unknown/unlinked identities skip the counter
	// (no oracle). A subsequent good bind during the window is still rejected below.
	lockUserID, lockKnown := a.lockoutUserForLDAP(r.Context(), issuer, req.Username)
	var lockUserPtr *uuid.UUID
	if lockKnown {
		lockUserPtr = &lockUserID
		if lerr := a.loginLocked(r.Context(), uuid.Nil, lockUserID); lerr != nil {
			a.auditLoginFailure(r.Context(), r, nil, lockUserPtr, req.Username, "account_locked")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
	}
	id, err := ldap.Authenticate(req.Username, req.Password)
	if err != nil {
		// A2: count the directory-auth failure against the linked user, when known.
		var locked bool
		if lockKnown {
			locked = a.recordLoginFailure(r.Context(), uuid.Nil, lockUserID)
		}
		a.auditLoginFailure(r.Context(), r, nil, lockUserPtr, req.Username, "bad_password")
		if locked {
			a.auditLoginLocked(r.Context(), r, nil, lockUserPtr, req.Username)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	a.issueLinkedSession(w, r, issuer, id.DN, id.Email, id.Roles, id.ScopedRoles, "auth.login.ldap")
}

// lockoutUserForLDAP resolves the constellation user the LDAP password bind will authenticate,
// for brute-force accounting (A2) only — never for authorization. It first resolves the user's
// DN via a service-account search and matches on (oidc_issuer, oidc_subject = DN), which is the
// SAME identity the bind authenticates regardless of email-vs-username form or casing. If the DN
// search misses it falls back to the legacy email-keyed match so username==email deployments
// still trip. A miss just means failures for that identity aren't counted (no oracle leaked).
func (a *Auth) lockoutUserForLDAP(ctx context.Context, issuer, username string) (uuid.UUID, bool) {
	ldap := a.providerLDAP()
	if ldap == nil {
		return uuid.Nil, false
	}
	if dn, ok := ldap.ResolveUserDN(username); ok {
		if uid, ok := a.linkedUserBySubject(ctx, issuer, dn); ok {
			return uid, true
		}
	}
	return a.linkedUserByEmail(ctx, issuer, username)
}

// linkedUserBySubject resolves the user linked to (oidc_issuer, oidc_subject). Used by the LDAP
// lockout to key accounting on the stable directory DN.
func (a *Auth) linkedUserBySubject(ctx context.Context, issuer, subject string) (uuid.UUID, bool) {
	var userID uuid.UUID
	err := a.db.Pool().QueryRow(ctx,
		`SELECT id FROM users
		  WHERE oidc_issuer = $1 AND oidc_subject = $2 AND disabled = FALSE
		  ORDER BY created_at, id LIMIT 1`,
		issuer, subject,
	).Scan(&userID)
	if err != nil {
		return uuid.Nil, false
	}
	return userID, true
}

// linkedUserByEmail is the legacy fallback: resolve by stored email == login username. Only
// reached when the DN search misses; used solely for lockout accounting.
func (a *Auth) linkedUserByEmail(ctx context.Context, issuer, username string) (uuid.UUID, bool) {
	var userID uuid.UUID
	err := a.db.Pool().QueryRow(ctx,
		`SELECT id FROM users
		  WHERE oidc_issuer = $1 AND lower(email) = lower($2) AND disabled = FALSE
		  ORDER BY created_at, id LIMIT 1`,
		issuer, username,
	).Scan(&userID)
	if err != nil {
		return uuid.Nil, false
	}
	return userID, true
}

// ldapIssuer namespaces an LDAP linked identity so its DN-as-subject can coexist with OIDC
// subjects in the shared (oidc_issuer, oidc_subject) unique key.
func ldapIssuer(url string) string { return "ldap:" + url }

// issueLinkedSession is the shared tail of every external-IdP login (OIDC/SAML/LDAP): look up the
// user pre-provisioned for (issuer, subject) and issue the same session. When no user is linked but
// the deployment's org has jit_provisioning enabled, the user is auto-provisioned and its
// role_assignments are seeded from the IdP-asserted roles (idpRoles). On every JIT login the
// assignments are reconciled to the current asserted set (add/remove). Asserted role names that do
// not resolve to a known RBAC role are ignored. When JIT is disabled and no user is linked, the
// 403 provision-by-admin path is preserved.
func (a *Auth) issueLinkedSession(w http.ResponseWriter, r *http.Request, issuer, subject, email string, idpRoles []string, scopedRoles []auth.ScopedRole, action string) {
	var userID, orgID uuid.UUID
	var sessionEpoch int64
	err := a.db.Pool().QueryRow(r.Context(),
		`SELECT id, org_id, session_epoch FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2 AND disabled = FALSE`,
		issuer, subject,
	).Scan(&userID, &orgID, &sessionEpoch)
	switch {
	case err == nil:
		// A2: even though the directory bind already succeeded, honor an active lockout so
		// a flood of bad passwords (recorded in LDAPLogin) blocks a subsequent good one.
		if lerr := a.loginLocked(r.Context(), orgID, userID); lerr != nil {
			a.auditLoginFailure(r.Context(), r, &orgID, &userID, loginUsername(email, subject), "account_locked")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		// User already linked. Reconcile its assignments to the IdP-asserted set only when JIT is
		// enabled for its org; otherwise leave admin-managed roles untouched. reconcileJITRoles may
		// bump session_epoch in its own tx, so adopt the epoch it returns (H10).
		if a.orgJITEnabled(r.Context(), orgID) {
			ep, rerr := reconcileJITRoles(r.Context(), a.db, userID, orgID, idpRoles, scopedRoles)
			if rerr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reconcile roles"})
				return
			}
			sessionEpoch = ep
		}
	case errors.Is(err, pgx.ErrNoRows):
		// No linked user: only JIT-provision if an org has opted in. ponytail: single-org
		// deployment model (one IdP per server, migration 060), so the JIT target is the org with
		// jit_provisioning = TRUE — no per-IdP org binding exists to disambiguate further.
		jitOrg, ok := a.jitProvisioningOrg(r.Context())
		if !ok {
			a.auditLoginFailure(r.Context(), r, nil, nil, loginUsername(email, subject), "not_provisioned")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "no user linked to identity; ask admin to provision"})
			return
		}
		orgID = jitOrg
		userID, err = provisionJITUser(r.Context(), a.db, orgID, issuer, subject, email)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "provision user"})
			return
		}
		// A freshly provisioned user starts at epoch 0; seeding roles bumps it to 1 inside
		// reconcileJITRoles' own tx. Adopt the returned epoch so the JWT we sign matches the
		// stored value (H10 — without this the very first SSO login is dead-on-arrival).
		ep, rerr := reconcileJITRoles(r.Context(), a.db, userID, orgID, idpRoles, scopedRoles)
		if rerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reconcile roles"})
			return
		}
		sessionEpoch = ep
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup user"})
		return
	}
	// A2: a fully successful external-IdP login clears any failed-login lockout.
	a.recordLoginSuccess(r.Context(), userID)
	roles, _ := loadRoleNames(r.Context(), a.db, userID)
	tok, expiresAt, err := a.issueSession(r.Context(), userID, orgID, email, roles, sessionEpoch)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue token"})
		return
	}
	_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
		OrgID: &orgID, ActorID: &userID,
		Action: action, TargetKind: "user", TargetID: userID.String(),
	})
	writeJSON(w, http.StatusOK, loginResponse{Token: tok, ExpiresAt: expiresAt})
}

// Logout bumps the user's session_epoch (A1), which invalidates the JWT used to call it
// (and every other live session for that user) on its next request — the DB-backed
// revocation primitive, consistent across API replicas. Previously this was a no-op, so a
// "logged out" token kept working until its 1h TTL.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	uid := subj.UserID
	oid := subj.OrgID
	if uid != uuid.Nil {
		if err := bumpSessionEpoch(r.Context(), a.db.Pool(), uid); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout"})
			return
		}
		// Drop the user's session rows too (A3): the epoch bump already invalidates every
		// live JWT, so leaving stale user_sessions rows would only skew the concurrent cap.
		if _, err := a.db.Pool().Exec(r.Context(), `DELETE FROM user_sessions WHERE user_id = $1`, uid); err != nil {
			slog.WarnContext(r.Context(), "clear sessions on logout", slog.String("err", err.Error()))
		}
	}
	_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "auth.logout", TargetKind: "user", TargetID: uid.String(),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Me returns the authenticated user's profile + capabilities.
func (a *Auth) Me(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	roles := make([]string, 0, len(subj.Assignments))
	for _, a := range subj.Assignments {
		roles = append(roles, a.Role)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": subj.UserID,
		"org_id":  subj.OrgID,
		"email":   subj.Email,
		"roles":   roles,
	})
}

// ---- shared helpers ----

func loadRoleNames(ctx context.Context, database *db.DB, userID uuid.UUID) ([]string, error) {
	rows, err := database.Pool().Query(ctx, `SELECT role FROM role_assignments WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

// orgJITEnabled reports whether the given org has SSO JIT provisioning turned on.
func (a *Auth) orgJITEnabled(ctx context.Context, orgID uuid.UUID) bool {
	var enabled bool
	if err := a.db.Pool().QueryRow(ctx,
		`SELECT jit_provisioning FROM orgs WHERE id = $1`, orgID,
	).Scan(&enabled); err != nil {
		return false
	}
	return enabled
}

// jitProvisioningOrg returns the org an unlinked external-IdP identity should be provisioned into.
// In the single-org deployment model this is the (single) org with jit_provisioning = TRUE; ok is
// false when none has opted in, which preserves the provision-by-admin 403.
func (a *Auth) jitProvisioningOrg(ctx context.Context) (uuid.UUID, bool) {
	var orgID uuid.UUID
	err := a.db.Pool().QueryRow(ctx,
		`SELECT id FROM orgs WHERE jit_provisioning = TRUE ORDER BY created_at, id LIMIT 1`,
	).Scan(&orgID)
	if err != nil {
		return uuid.Nil, false
	}
	return orgID, true
}

// provisionJITUser creates a user linked to (issuer, subject) in the given org and returns its id.
func provisionJITUser(ctx context.Context, database *db.DB, orgID uuid.UUID, issuer, subject, email string) (uuid.UUID, error) {
	displayName := email
	if displayName == "" {
		displayName = subject
	}
	var userID uuid.UUID
	err := database.Pool().QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, oidc_issuer, oidc_subject)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`,
		orgID, email, displayName, issuer, subject,
	).Scan(&userID)
	return userID, err
}

// reconcileJITRoles makes the user's org-scoped role_assignments match the IdP-asserted set: it
// adds assignments for newly-asserted roles and removes ones no longer asserted. Only role names
// that resolve to a known RBAC role are considered; unknown names are ignored.
//
// A2: it also MATERIALIZES the identity's cluster- AND namespace-scoped SSO grants (scopedRoles)
// into scope_cluster_id/scope_namespace-bearing role_assignments rows. This is additive and
// idempotent: a scoped grant that already exists is skipped (dedup on the (role, cluster, namespace)
// triple), and existing cluster/project assignments are never removed — an admin's hand-created
// cluster grants stay untouched (there is no source marker to tell a JIT-materialized row apart from
// an admin one, so the safe reconcile is add-only for scoped grants; only the ORG-scope set is
// add/remove-reconciled). A namespace-bearing grant lands as a row with scope_namespace set (P0-10,
// migration 133 adds the column) so it grants EXACTLY that namespace on that cluster rather than the
// whole cluster; a grant with a namespace but no cluster has no anchor to materialise against and is
// skipped (the CRUD writer rejects it, so it only arises for malformed legacy data).
//
// It returns the user's session_epoch as it stands after the reconcile (post-bump when the
// assignment set moved). Callers MUST issue the session with this returned epoch — the bump
// happens in this function's own transaction, so the epoch the caller read before calling is
// stale, and a JWT minted with that stale epoch is rejected by the auth middleware as revoked
// (H10: first JIT/SSO login dead-on-arrival).
func reconcileJITRoles(ctx context.Context, database *db.DB, userID, orgID uuid.UUID, idpRoles []string, scopedRoles []auth.ScopedRole) (int64, error) {
	want := map[string]struct{}{}
	for _, role := range idpRoles {
		if rbac.IsRole(role) {
			want[role] = struct{}{}
		}
	}
	// A1: the assignment reconcile and the session_epoch bump must commit atomically so a
	// crash can never leave privileges changed while prior JWTs keep their stale (possibly
	// higher) envelope until TTL. Run the whole reconcile in one transaction.
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT role FROM role_assignments
		  WHERE user_id = $1 AND scope_org_id = $2
		    AND scope_cluster_id IS NULL AND scope_project_id IS NULL`,
		userID, orgID)
	if err != nil {
		return 0, err
	}
	have := map[string]struct{}{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			rows.Close()
			return 0, err
		}
		have[role] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	changed := false
	for role := range want {
		if _, ok := have[role]; ok {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, $2, $3)`,
			userID, role, orgID); err != nil {
			return 0, err
		}
		changed = true
	}
	for role := range have {
		if _, ok := want[role]; ok {
			continue
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM role_assignments
			  WHERE user_id = $1 AND role = $2 AND scope_org_id = $3
			    AND scope_cluster_id IS NULL AND scope_project_id IS NULL`,
			userID, role, orgID); err != nil {
			return 0, err
		}
		changed = true
	}
	// A2: materialize the identity's cluster-scoped grants (add-only, deduped). Load the user's
	// existing cluster-scoped assignments once, keyed by (role, cluster), so a re-login does not
	// duplicate rows.
	haveScoped := map[string]struct{}{}
	srows, err := tx.Query(ctx,
		`SELECT role, scope_cluster_id, scope_namespace FROM role_assignments
		  WHERE user_id = $1 AND scope_org_id = $2
		    AND scope_cluster_id IS NOT NULL AND scope_project_id IS NULL`,
		userID, orgID)
	if err != nil {
		return 0, err
	}
	for srows.Next() {
		var role, ns string
		var cluster uuid.UUID
		if err := srows.Scan(&role, &cluster, &ns); err != nil {
			srows.Close()
			return 0, err
		}
		haveScoped[role+"|"+cluster.String()+"|"+ns] = struct{}{}
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return 0, err
	}
	for _, sr := range scopedRoles {
		// Org-scope grants are handled by the org-scope reconcile above; a namespace grant with no
		// cluster has no anchor to materialise against, and unknown role names are ignored. A
		// namespace-bearing grant WITH a cluster lands as a scope_namespace row (P0-10).
		if sr.Scope.IsOrg() || sr.Scope.ClusterID == "" || !rbac.IsRole(sr.Role) {
			continue
		}
		clusterID, perr := uuid.Parse(sr.Scope.ClusterID)
		if perr != nil {
			continue
		}
		key := sr.Role + "|" + clusterID.String() + "|" + sr.Scope.Namespace
		if _, ok := haveScoped[key]; ok {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO role_assignments (user_id, role, scope_org_id, scope_cluster_id, scope_namespace) VALUES ($1, $2, $3, $4, $5)`,
			userID, sr.Role, orgID, clusterID, sr.Scope.Namespace); err != nil {
			return 0, err
		}
		haveScoped[key] = struct{}{}
		changed = true
	}
	// A1: a role change must invalidate prior JWTs (their embedded role set / privilege
	// envelope is now stale). Bump the epoch only when the assignment set actually moved.
	if changed {
		if err := bumpSessionEpoch(ctx, tx, userID); err != nil {
			return 0, err
		}
	}
	// Read the post-reconcile epoch inside the same tx so the caller signs the JWT with the
	// value the auth middleware will compare against (H10). Returns the bumped value when
	// changed, the unchanged value otherwise.
	var epoch int64
	if err := tx.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id = $1`, userID).Scan(&epoch); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return epoch, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// SafeFilter sanitizes a filter param so it can be safely echoed in error responses.
func SafeFilter(f string) string { return strings.ReplaceAll(f, "\n", "") }
