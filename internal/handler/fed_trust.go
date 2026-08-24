package handler

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/federation"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// ── D1: federation trust handshake ───────────────────────────────────────────
//
// Replaces the single static CONSTELLATION_FED_MASTER_TOKEN with a real issuance
// flow: the master mints a short-lived SIGNED join token; a joint exchanges it for a
// PER-CLUSTER secret (a signed sync ticket, stored hashed like api_tokens); every
// /sync poll re-validates that ticket; kick/leave bumps a per-cluster epoch to revoke
// the joint (mirrors A1's users.session_epoch). A pre-shared FIXED join token supports
// GitOps joins. None of the trust material is hardcoded — the signing key lives in
// fed_signing_keys (auto-generated first boot) and the TTLs / fixed token come from
// env/syscfg via FedJoinConfig.

// FedJoinConfig carries the (non-hardcoded) federation join knobs. They are populated
// in internal/server from env (the syscfg/B1 home for fed peer endpoints / CA), so this
// handler never embeds a default token or URL.
type FedJoinConfig struct {
	// JoinTokenTTL bounds a master-minted join token's lifetime.
	JoinTokenTTL time.Duration
	// SecretTTL bounds a per-cluster sync ticket's lifetime; 0 mints a non-expiring
	// ticket (revocation is then solely via epoch bump / explicit revoke).
	SecretTTL time.Duration
	// FixedToken is an optional pre-shared join token for GitOps joins (env/syscfg).
	// Empty disables the fixed-token path, leaving only signed, minted join tokens.
	FixedToken string
}

// WithFedTrust wires the federation signing key + join config so the trust-handshake
// endpoints (MintJoinToken / Join) and FedSyncTokenMiddleware are operative. A nil
// signer leaves them disabled (501), preserving a deployment that has not enabled the
// fed surface.
func (h *Federation) WithFedTrust(signer *auth.FedSigner, cfg FedJoinConfig) *Federation {
	h.fedSigner = signer
	h.joinCfg = cfg
	return h
}

// WithFedCA wires the federation CA (D2) so Join also mints a per-joint client certificate
// and binds its fingerprint to the per-cluster credential. A nil CA leaves the D1
// bearer-only path intact (no client cert is issued and the /sync middleware skips the
// cert check) — preserving deployments without a KEK-backed CA.
func (h *Federation) WithFedCA(ca *auth.FedCA) *Federation {
	h.fedCA = ca
	return h
}

// MintJoinToken (POST /federation/join-tokens) mints a short-lived signed join token an
// operator hands to a joining cluster. Master-only: a standalone/joint org has no
// authority to admit members. Gated by VerbManageOrg (the same verb as the other
// federation membership mutations).
func (h *Federation) MintJoinToken(w http.ResponseWriter, r *http.Request) {
	if h.fedSigner == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "federation signing not configured"})
		return
	}
	subj, _ := SubjectFrom(r.Context())

	var state string
	err := h.db.Pool().QueryRow(r.Context(),
		`SELECT state FROM federation_state WHERE org_id=$1`, subj.OrgID).Scan(&state)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if state != string(federation.StateMaster) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "federation: only a master can mint join tokens"})
		return
	}

	ttl := h.joinCfg.JoinTokenTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	// Optional caller override, capped at the configured ceiling so a request cannot mint
	// a longer-lived join token than policy allows.
	var body struct {
		TTLSeconds int64 `json:"ttl_seconds,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.TTLSeconds > 0 {
		if req := time.Duration(body.TTLSeconds) * time.Second; req < ttl {
			ttl = req
		}
	}

	token, jti, err := h.fedSigner.IssueJoinTokenWithJTI(subj.OrgID, ttl)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// D1-2: persist the jti so the token is single-use — the first successful Join
	// consumes it, and any replay within the TTL window finds it already consumed and
	// is rejected. Without this a captured join token is a replayable bearer that can
	// mint per-cluster secrets for arbitrary cluster ids.
	if id, perr := uuid.Parse(jti); perr == nil {
		if _, derr := h.db.Pool().Exec(r.Context(),
			`INSERT INTO fed_join_tokens (jti, org_id, expires_at) VALUES ($1,$2,$3)`,
			id, subj.OrgID, time.Now().Add(ttl)); derr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": derr.Error()})
			return
		}
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "federation.join_token.mint", TargetKind: "federation"})
	writeJSON(w, http.StatusCreated, map[string]any{
		"join_token": token,
		"expires_at": time.Now().Add(ttl).UTC(),
	})
}

type fedJoinRequest struct {
	JoinToken   string `json:"join_token"`
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name"`
	Endpoint    string `json:"endpoint,omitempty"`
}

// Join (POST /federation/join) is the unauthenticated exchange endpoint: a joining
// cluster presents a join token (a signed, master-minted token OR the pre-shared fixed
// token) plus its cluster id/name, and receives a PER-CLUSTER secret it then uses to
// poll /sync. The secret is a signed sync ticket; only its sha256 is persisted (like
// api_tokens), so the master never stores a replayable credential. Idempotent on
// (org, cluster_id): a re-join rotates the secret and bumps the epoch, invalidating the
// previous ticket.
func (h *Federation) Join(w http.ResponseWriter, r *http.Request) {
	if h.fedSigner == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "federation signing not configured"})
		return
	}
	var req fedJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	req.ClusterID = strings.TrimSpace(req.ClusterID)
	req.ClusterName = strings.TrimSpace(req.ClusterName)
	if req.ClusterID == "" || req.ClusterName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster_id and cluster_name are required"})
		return
	}

	ja, ok := h.authenticateJoinToken(req.JoinToken)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired join token"})
		return
	}
	orgID := ja.orgID

	// D2-3: when the join issues per-joint mTLS key material, refuse to hand out the
	// private key over a connection that is not TLS-protected, so it never crosses the
	// wire in cleartext. Behind an ingress terminator the request reaches the app as
	// plain HTTP with X-Forwarded-Proto=https; an in-process TLS listener sets r.TLS.
	if h.fedCA != nil && !fedJoinOverTLS(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "federation: mTLS join requires a TLS-terminated connection"})
		return
	}

	// D1-2: a master-minted join token is single-use. Consume its jti BEFORE minting the
	// credential; a replay finds it already consumed and is rejected. The fixed/GitOps
	// token is reusable by design and is not tracked here. mintedAt is the persisted mint
	// time (used below for the durable-kick re-admission test at microsecond precision,
	// avoiding the second-granularity truncation of the JWT iat).
	var mintedAt *time.Time
	if ja.signed && ja.jti != "" {
		consumed, known, createdAt, cerr := h.consumeJoinToken(r.Context(), ja.jti)
		if cerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": cerr.Error()})
			return
		}
		if known && !consumed {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "federation: join token already used"})
			return
		}
		mintedAt = createdAt
	}

	// D1-1: a kicked cluster cannot silently re-admit itself by replaying a join
	// credential. KickMember tombstones the member with kicked_at; re-admission requires
	// a FRESH signed join token minted AFTER the kick. A pre-shared/fixed GitOps token —
	// or a stale minted token the kicked joint still holds — is refused, so a kick is
	// durable until an operator deliberately re-issues a join token. This check runs
	// BEFORE any credential mutation so a refused re-join never clears revoked_at /
	// bumps the epoch.
	var (
		memberStatus string
		kickedAt     *time.Time
	)
	_ = h.db.Pool().QueryRow(r.Context(),
		`SELECT status, kicked_at FROM fed_members WHERE org_id=$1 AND cluster_id=$2`,
		orgID, req.ClusterID).Scan(&memberStatus, &kickedAt)
	if memberStatus == federation.MemberStatusKicked {
		// Prefer the persisted mint time (microsecond precision); fall back to the JWT
		// issued-at for a signed token that is not tracked in fed_join_tokens.
		freshAt := ja.issuedAt
		if mintedAt != nil {
			freshAt = *mintedAt
		}
		readmit := ja.signed && kickedAt != nil && !freshAt.IsZero() && freshAt.After(*kickedAt)
		if !readmit {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "federation: cluster has been kicked; re-admission requires a join token minted after the kick"})
			return
		}
	}

	// Bump the epoch on (re)join so a re-issued ticket supersedes any prior one for this
	// cluster, then mint the per-cluster sync ticket carrying that epoch.
	var epoch int64
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO fed_credentials (org_id, cluster_id, secret_hash, epoch, expires_at)
VALUES ($1, $2, '', 0, $3)
ON CONFLICT (org_id, cluster_id) DO UPDATE
   SET epoch = fed_credentials.epoch + 1, revoked_at = NULL, expires_at = EXCLUDED.expires_at
RETURNING epoch`, orgID, req.ClusterID, fedSecretExpiry(h.joinCfg.SecretTTL)).Scan(&epoch); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ticket, err := h.fedSigner.IssueSyncTicket(orgID, req.ClusterID, epoch, h.joinCfg.SecretTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// D2: when the federation CA is configured, mint a per-joint CLIENT certificate (CN =
	// cluster_id) and bind its fingerprint to this credential. The /sync middleware then
	// requires a verified client cert with this fingerprint, so the bearer ticket alone (no
	// matching client key) cannot authenticate. The cert TTL tracks the secret TTL so the
	// cert and ticket expire together. fedCA==nil leaves cert_fingerprint empty (D1 path).
	var clientCertPEM, clientKeyPEM []byte
	var fingerprint string
	if h.fedCA != nil {
		certPEM, keyPEM, cerr := h.fedCA.IssueClientCert(req.ClusterID, h.joinCfg.SecretTTL)
		if cerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": cerr.Error()})
			return
		}
		fp, ferr := fedCertFingerprintPEM(certPEM)
		if ferr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": ferr.Error()})
			return
		}
		clientCertPEM, clientKeyPEM, fingerprint = certPEM, keyPEM, fp
	}

	if _, err := h.db.Pool().Exec(r.Context(),
		`UPDATE fed_credentials SET secret_hash=$3, cert_fingerprint=$4 WHERE org_id=$1 AND cluster_id=$2`,
		orgID, req.ClusterID, hashFedSecret(ticket), fingerprint); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Register/refresh the member as pending (its first /sync flips it to active). Mirrors
	// AddMember, but driven by the joint's self-reported identity at exchange time.
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO fed_members (org_id, cluster_id, name, role, endpoint, status, revision)
VALUES ($1,$2,$3,'joint',$4,'pending',0)
ON CONFLICT (org_id, cluster_id) DO UPDATE
   SET name=EXCLUDED.name, endpoint=EXCLUDED.endpoint,
       status=CASE WHEN fed_members.status='kicked' THEN 'pending' ELSE fed_members.status END,
       kicked_at=CASE WHEN fed_members.status='kicked' THEN NULL ELSE fed_members.kicked_at END`,
		orgID, req.ClusterID, req.ClusterName, req.Endpoint); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &orgID,
		Action: "federation.join", TargetKind: "fed-member", TargetID: req.ClusterID,
		After: map[string]any{"epoch": epoch}})

	var expiresAt any
	if h.joinCfg.SecretTTL > 0 {
		expiresAt = time.Now().Add(h.joinCfg.SecretTTL).UTC()
	}
	resp := map[string]any{
		"cluster_id": req.ClusterID,
		"secret":     ticket,
		"expires_at": expiresAt,
	}
	// D2: hand the joint its per-joint client cert + key and the master CA so its poll
	// client presents the cert (mutual auth) and pins the master. The private key crosses
	// the wire once here (over the join TLS connection, exactly like the bearer secret) and
	// is persisted encrypted at rest on the joint side (fed_joint_secret.client_key_enc).
	if h.fedCA != nil {
		resp["client_cert"] = string(clientCertPEM)
		resp["client_key"] = string(clientKeyPEM)
		resp["ca_cert"] = string(h.fedCA.CertPEM())
	}
	writeJSON(w, http.StatusOK, resp)
}

// fedClientCertBound reports whether leaf is the per-joint client certificate bound to this
// credential: a certificate that (1) is present, (2) chains to the fed CA with client-auth
// EKU, (3) has the expected sha256 fingerprint, and (4) carries the cluster id as its
// CommonName. When leaf came from r.TLS.PeerCertificates, its presence proves the caller
// completed the TLS handshake with the matching PRIVATE key (crypto/tls verifies the client
// CertificateVerify), so a leaked bearer + the public cert alone cannot satisfy it.
func fedClientCertBound(leaf *x509.Certificate, ca *auth.FedCA, wantFingerprint, clusterID string) bool {
	if leaf == nil {
		return false
	}
	if err := ca.VerifyClientCert(leaf); err != nil {
		return false
	}
	if !subtleConstantEq(auth.FedCertFingerprint(leaf), wantFingerprint) {
		return false
	}
	// Bind the cert to the authenticated cluster identity so one joint's cert cannot
	// authenticate another joint's ticket.
	return leaf.Subject.CommonName == clusterID
}

// fedClientCert extracts the presented client certificate. It prefers the cert from a
// directly-terminated mTLS handshake (r.TLS.PeerCertificates) so possession of the private
// key is proven by crypto/tls. When the controller's TLS is terminated by a trusted ingress
// (the documented two-cluster topology) the app sees plain HTTP, so — ONLY when an operator
// has configured a trusted forwarded-cert header name — it falls back to the certificate the
// terminator attests in that header. The terminator MUST perform the real mTLS handshake and
// MUST strip any inbound copy of the header; otherwise a caller could spoof it. The header is
// empty (disabled) by default, so the default behaviour is unchanged.
func fedClientCert(r *http.Request, header string) *x509.Certificate {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	return fedForwardedClientCert(r, header)
}

// fedForwardedClientCert parses the client certificate the trusted terminator placed in the
// configured header (ingress-nginx's ssl-client-cert is URL-encoded PEM). Returns nil when the
// header is unconfigured, absent, or unparseable.
func fedForwardedClientCert(r *http.Request, header string) *x509.Certificate {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	v := r.Header.Get(header)
	if v == "" {
		return nil
	}
	if dec, err := neturl.QueryUnescape(v); err == nil {
		v = dec
	}
	block, _ := pem.Decode([]byte(v))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// fedJoinOverTLS reports whether the join request is TLS-protected: either a directly
// terminated TLS connection (r.TLS) or a trusted terminator attesting https via
// X-Forwarded-Proto. Used to fail closed before handing out per-joint mTLS key material.
func fedJoinOverTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// fedCertFingerprintPEM parses a PEM-encoded certificate and returns its sha256(DER)
// fingerprint, the value bound in fed_credentials.cert_fingerprint and matched on /sync.
func fedCertFingerprintPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("federation: client certificate PEM invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return auth.FedCertFingerprint(cert), nil
}

// joinAuth is the authenticated result of a join-token exchange: the master org the token
// scopes to, whether it was a master-minted SIGNED token (vs the reusable fixed/GitOps
// token), and — for signed tokens — its jti and issued-at, used for single-use consumption
// (D1-2) and durable-kick re-admission (D1-1).
type joinAuth struct {
	orgID    uuid.UUID
	signed   bool
	jti      string
	issuedAt time.Time
}

// authenticateJoinToken accepts either a valid signed join token (returning the master
// org it scopes to) or the pre-shared fixed token (GitOps). The fixed token is compared
// in constant time and only authorizes the master org it is configured against — which,
// on a master controller, is the single federation_state master org.
func (h *Federation) authenticateJoinToken(raw string) (joinAuth, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return joinAuth{}, false
	}
	// Signed, minted join token: self-describing (carries its org), signature-verified.
	if claims, err := h.fedSigner.VerifyJoinToken(raw); err == nil {
		a := joinAuth{orgID: claims.OrgID, signed: true, jti: claims.ID}
		if claims.IssuedAt != nil {
			a.issuedAt = claims.IssuedAt.Time
		}
		return a, true
	}
	// Fixed/pre-shared token: resolve the single master org from federation_state.
	// The token itself carries no org claim, so accepting it when multiple master
	// orgs exist would bind the join to an arbitrary tenant.
	if fixed := strings.TrimSpace(h.joinCfg.FixedToken); fixed != "" && subtleConstantEq(raw, fixed) {
		if orgID, ok := h.fixedTokenMasterOrg(); ok {
			return joinAuth{orgID: orgID}, true
		}
	}
	return joinAuth{}, false
}

func (h *Federation) fixedTokenMasterOrg() (uuid.UUID, bool) {
	rows, err := h.db.Pool().Query(context.Background(),
		`SELECT org_id FROM federation_state WHERE state=$1 ORDER BY updated_at, org_id LIMIT 2`,
		string(federation.StateMaster))
	if err != nil {
		return uuid.Nil, false
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return uuid.Nil, false
		}
		out = append(out, id)
	}
	if rows.Err() != nil || len(out) != 1 {
		return uuid.Nil, false
	}
	return out[0], true
}

// consumeJoinToken atomically marks a minted join token's jti consumed. It returns
// (consumed, known): consumed is true when THIS call claimed a previously-unconsumed jti;
// known reports whether the jti exists in fed_join_tokens at all. A jti that is known but
// not consumed by this call was already consumed (a replay) — the caller rejects it. An
// UNKNOWN jti is untracked (e.g. a token issued out-of-band in tests); production join
// tokens are always tracked by MintJoinToken, so an untracked token is left to the caller.
func (h *Federation) consumeJoinToken(ctx context.Context, jtiStr string) (consumed, known bool, createdAt *time.Time, err error) {
	jti, perr := uuid.Parse(jtiStr)
	if perr != nil {
		return false, false, nil, nil // malformed jti: treat as untracked
	}
	err = h.db.Pool().QueryRow(ctx, `
WITH upd AS (
    UPDATE fed_join_tokens SET consumed_at = NOW()
     WHERE jti = $1 AND consumed_at IS NULL
    RETURNING jti
)
SELECT EXISTS(SELECT 1 FROM fed_join_tokens WHERE jti = $1) AS known,
       EXISTS(SELECT 1 FROM upd) AS consumed,
       (SELECT created_at FROM fed_join_tokens WHERE jti = $1) AS created_at`,
		jti).Scan(&known, &consumed, &createdAt)
	return consumed, known, createdAt, err
}

// fedSyncPrincipalKey is the context key for the authenticated joint identity.
type fedSyncPrincipalKey struct{}

// FedSyncPrincipal is the per-cluster identity FedSyncTokenMiddleware attaches once a
// joint's sync ticket validates.
type FedSyncPrincipal struct {
	OrgID     uuid.UUID
	ClusterID string
}

// FedSyncPrincipalFrom returns the authenticated joint identity, if any.
func FedSyncPrincipalFrom(ctx context.Context) (FedSyncPrincipal, bool) {
	p, ok := ctx.Value(fedSyncPrincipalKey{}).(FedSyncPrincipal)
	return p, ok
}

// WithFedSyncPrincipal attaches a joint identity (exported for tests that drive Sync
// without the full middleware).
func WithFedSyncPrincipal(ctx context.Context, p FedSyncPrincipal) context.Context {
	return context.WithValue(ctx, fedSyncPrincipalKey{}, p)
}

// FedSyncTokenMiddleware authenticates GET /federation/sync with a per-cluster signed
// sync ticket instead of a user JWT. It (1) verifies the ticket's signature/claims
// against the dedicated fed signing key, (2) matches it to a live fed_credentials row
// (not revoked, not expired, sha256 matches the currently-issued secret), (3) enforces
// the epoch (ticket.epoch >= row.epoch) so a kick/leave epoch bump revokes the joint on
// its next poll, and (4) — D2 — when the credential carries a bound per-joint client
// certificate, requires the request to present that exact client cert (verified against
// the fed CA). On success it attaches a Subject (org-scoped, fed-only verb) plus the joint
// identity, so the Sync handler stays org-scoped and a generic read-findings JWT — which
// can never produce a valid fed ticket — is rejected here.
//
// ca is the federation CA (D2). nil leaves the D1 bearer-only behaviour; non-nil ENFORCES a
// bound client cert: a credential with no bound cert is rejected outright, and one with a
// bound cert must present that exact cert, so a leaked bearer WITHOUT the matching client key
// is rejected. clientCertHeader is the (optional) trusted-terminator forwarded-cert header
// (see fedClientCert); empty restricts the client cert to a directly-terminated mTLS handshake.
func FedSyncTokenMiddleware(pool *pgxpool.Pool, signer *auth.FedSigner, ca *auth.FedCA, clientCertHeader string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if signer == nil {
				jsonError(w, http.StatusNotImplemented, "federation signing not configured")
				return
			}
			raw := extractBearer(r)
			if raw == "" {
				jsonError(w, http.StatusUnauthorized, "federation sync ticket required")
				return
			}
			claims, err := signer.VerifySyncTicket(raw)
			if err != nil {
				jsonError(w, http.StatusUnauthorized, "invalid federation sync ticket")
				return
			}
			var (
				epoch       int64
				revokedAt   *time.Time
				expiresAt   *time.Time
				hash        string
				fingerprint string
			)
			err = pool.QueryRow(r.Context(), `
SELECT epoch, revoked_at, expires_at, secret_hash, cert_fingerprint
  FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`,
				claims.OrgID, claims.ClusterID).Scan(&epoch, &revokedAt, &expiresAt, &hash, &fingerprint)
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, http.StatusUnauthorized, "federation credential not found")
				return
			}
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "load federation credential")
				return
			}
			if revokedAt != nil {
				jsonError(w, http.StatusForbidden, "federation credential revoked")
				return
			}
			if expiresAt != nil && time.Now().After(*expiresAt) {
				jsonError(w, http.StatusUnauthorized, "federation credential expired")
				return
			}
			// Epoch gate (A1 parity): a ticket minted before a kick/leave epoch bump is stale.
			if claims.Epoch < epoch {
				jsonError(w, http.StatusForbidden, "federation credential revoked")
				return
			}
			// The presented ticket must be the currently-issued secret (a re-join rotated it).
			if hash != "" && !subtleConstantEq(hash, hashFedSecret(raw)) {
				jsonError(w, http.StatusUnauthorized, "stale federation sync ticket")
				return
			}
			// D2 per-joint mTLS: when the CA is wired, enforcement is mandatory. A credential
			// with NO bound client cert (empty cert_fingerprint) is rejected rather than
			// silently downgraded to bearer-only — otherwise a credential minted while the CA
			// was off would stay permanently bearer-only even under enforced mTLS. A credential
			// WITH a bound cert must present that exact cert, verified against the fed CA: this
			// is what makes a leaked bearer alone insufficient — without the matching client
			// key the joint cannot complete the TLS handshake that proves possession.
			if ca != nil {
				if fingerprint == "" {
					jsonError(w, http.StatusForbidden, "federation credential not bound to a client certificate")
					return
				}
				if !fedClientCertBound(fedClientCert(r, clientCertHeader), ca, fingerprint, claims.ClusterID) {
					jsonError(w, http.StatusForbidden, "federation client certificate required")
					return
				}
			}
			_, _ = pool.Exec(r.Context(),
				`UPDATE fed_credentials SET last_used_at=NOW() WHERE org_id=$1 AND cluster_id=$2`,
				claims.OrgID, claims.ClusterID)

			ctx := authctx.WithSubject(r.Context(), authctx.Subject{
				OrgID:       claims.OrgID,
				TokenScopes: []rbac.Verb{rbac.VerbFederationSync},
			})
			ctx = WithFedSyncPrincipal(ctx, FedSyncPrincipal{OrgID: claims.OrgID, ClusterID: claims.ClusterID})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RevokeFedCredential bumps the per-cluster epoch so the joint's already-issued sync
// ticket is rejected on its next poll. Called by KickMember (and the leave path). A
// missing credential row is a no-op — a member kicked before it ever exchanged a join
// token simply has nothing to revoke.
func RevokeFedCredential(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, clusterID string) error {
	_, err := pool.Exec(ctx, `
UPDATE fed_credentials SET epoch = epoch + 1, revoked_at = NOW()
 WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	return err
}

// hashFedSecret returns the hex sha256 of a per-cluster secret, the value persisted in
// fed_credentials.secret_hash (mirrors api_tokens / runtime_agent_tokens hashing).
func hashFedSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// fedSecretExpiry maps a TTL onto a nullable expires_at for the fed_credentials row.
func fedSecretExpiry(ttl time.Duration) *time.Time {
	if ttl <= 0 {
		return nil
	}
	t := time.Now().Add(ttl)
	return &t
}

// subtleConstantEq compares two strings in constant time (length-independent).
func subtleConstantEq(a, b string) bool {
	ab := sha256.Sum256([]byte(a))
	bb := sha256.Sum256([]byte(b))
	var diff byte
	for i := range ab {
		diff |= ab[i] ^ bb[i]
	}
	return diff == 0
}
