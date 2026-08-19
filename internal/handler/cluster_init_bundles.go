// Cluster init-bundle endpoints (Wave N1).
//
// Mirrors StackRox's init-bundle workflow: an admin pre-mints a single sealed YAML
// containing everything a remote cluster needs to register with the control plane:
//
//   - scanner_token + runtime_agent_token (fresh rows in their tables, tied to a clusters row)
//   - admission webhook TLS material (CA, server cert + key) for <cluster>.cluster.constellation.internal
//   - audit HMAC secret (per-cluster, for tamper-resistant log forwarding)
//   - control-plane URL + cluster_id + org_id + expires_at metadata
//
// The raw YAML is stored encrypted (AES-256-GCM, per-install KEK) and shown to the admin
// exactly once at mint time. Subsequent GETs return the decrypted YAML but flip
// downloaded_at and audit-log the read; rotates invalidate the existing bundle's tokens
// and mint a replacement; revokes set revoked_at on the bundle row AND on its underlying
// scanner_token / runtime_agent_token rows so a leaked bundle can be killed instantly.
//
// Endpoints (all RBAC: manage-org):
//
//	POST   /api/v1/cluster-init-bundles            — mint
//	GET    /api/v1/cluster-init-bundles            — list
//	GET    /api/v1/cluster-init-bundles/{id}       — read (decrypts; one-time download flag)
//	POST   /api/v1/cluster-init-bundles/{id}/rotate— mint replacement, revoke prior tokens
//	DELETE /api/v1/cluster-init-bundles/{id}       — revoke
package handler

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// ClusterInitBundles handler.
type ClusterInitBundles struct {
	db    *db.DB
	audit *audit.Logger
	kek   []byte // 32 bytes; resolved once at construction time
}

// NewClusterInitBundles returns a handler whose KEK is derived from the env var
// CONSTELLATION_KEK (hex-encoded, must yield 32 bytes after decode) — or, if unset,
// is generated process-local on first use and persisted to /tmp/constellation.kek so
// dev restarts can still decrypt bundles minted earlier in the session.
func NewClusterInitBundles(d *db.DB, a *audit.Logger) *ClusterInitBundles {
	// A KEK resolve failure (crypto-RNG hiccup) must not crash server startup or any
	// request path. We construct with a nil KEK; the request handlers below detect that
	// via kekReady and return 503 only for init-bundle routes.
	kek, _ := resolveKEK()
	return &ClusterInitBundles{db: d, audit: a, kek: kek}
}

// kekReady writes a 503 and returns false when this handler has no usable KEK (the
// process-wide resolveKEK hit a crypto-RNG failure at startup). Guards every route that
// seals or unseals bundle contents so a KEK gen failure degrades these endpoints instead
// of taking the API down.
func (h *ClusterInitBundles) kekReady(w http.ResponseWriter) bool {
	if len(h.kek) != 32 {
		jsonError(w, http.StatusServiceUnavailable, "init-bundle key unavailable; check control-plane KEK configuration")
		return false
	}
	return true
}

// kekResolved is the per-process cached KEK so repeat constructions don't reread/regen.
var (
	kekResolvedOnce sync.Once
	kekResolvedVal  []byte
	kekResolvedErr  error
)

// resolveKEK loads or generates the per-install Key Encryption Key. Order:
//  1. $CONSTELLATION_KEK (hex; must decode to 32 bytes).
//  2. Read /tmp/constellation.kek if present.
//  3. Generate a fresh 32-byte KEK and persist to /tmp/constellation.kek (0600).
//
// We log the fingerprint (sha256[:16]) at construction so operators can detect when a
// KEK rotation has happened by accident (previously-minted bundles will fail to decrypt).
//
// On a crypto-RNG failure (step 3) it returns a nil KEK + the error rather than
// panicking: the constructor caches the nil, and the request handlers return 503 for
// init-bundle routes (D3) instead of crashing the whole API process.
func resolveKEK() ([]byte, error) {
	kekResolvedOnce.Do(func() {
		if v := strings.TrimSpace(os.Getenv("CONSTELLATION_KEK")); v != "" {
			if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
				kekResolvedVal = b
				slog.Info("cluster-init-bundles: KEK loaded from env",
					slog.String("fingerprint", kekFingerprint(b)))
				return
			}
			slog.Warn("cluster-init-bundles: CONSTELLATION_KEK set but invalid (not 32 hex bytes); falling back")
		}
		const cache = "/tmp/constellation.kek"
		if b, err := os.ReadFile(cache); err == nil {
			// File contents are hex-encoded.
			trimmed := strings.TrimSpace(string(b))
			if dec, err := hex.DecodeString(trimmed); err == nil && len(dec) == 32 {
				kekResolvedVal = dec
				slog.Info("cluster-init-bundles: KEK loaded from cache",
					slog.String("fingerprint", kekFingerprint(dec)))
				return
			}
		}
		// Generate fresh.
		fresh := make([]byte, 32)
		if _, err := rand.Read(fresh); err != nil {
			// Crypto-RNG hiccup: record the error, leave kekResolvedVal nil.
			// Callers degrade to 503 instead of taking the process down.
			kekResolvedErr = fmt.Errorf("cluster-init-bundles: KEK gen: %w", err)
			slog.Error("cluster-init-bundles: KEK generation failed; init-bundle routes will return 503",
				slog.String("err", err.Error()))
			return
		}
		kekResolvedVal = fresh
		if err := os.WriteFile(cache, []byte(hex.EncodeToString(kekResolvedVal)), 0o600); err != nil {
			slog.Warn("cluster-init-bundles: KEK cache write failed", slog.String("err", err.Error()))
		}
		slog.Warn("cluster-init-bundles: KEK auto-generated (set CONSTELLATION_KEK in prod)",
			slog.String("fingerprint", kekFingerprint(kekResolvedVal)))
	})
	return kekResolvedVal, kekResolvedErr
}

func kekFingerprint(k []byte) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:8])
}

// ---------------- DTOs ----------------

// CreateBundleRequest is the JSON body for POST /cluster-init-bundles.
type CreateBundleRequest struct {
	Name   string `json:"name"`
	Distro string `json:"distro,omitempty"`
	Region string `json:"region,omitempty"`
	// TTL string parses as time.Duration ("24h", "720h", "7d" handled below).
	TTL string `json:"ttl,omitempty"`
}

// BundleSummary is the list/detail response shape (no contents).
type BundleSummary struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	ClusterID   uuid.UUID  `json:"cluster_id"`
	Name        string     `json:"name"`
	Distro      string     `json:"distro"`
	Region      string     `json:"region,omitempty"`
	Status      string     `json:"status"` // active | expired | revoked
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	DownloadedAt *time.Time `json:"downloaded_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

// MintResponse is the response to POST and rotate: includes the rendered YAML once.
type MintResponse struct {
	BundleSummary
	YAML       string `json:"yaml"`
	ServerURL  string `json:"server_url"`
	// ImportURL is the one-command join URL (kubectl apply -f). The URL's token IS
	// the runtime-agent credential, so treat it like a secret.
	ImportURL  string `json:"import_url"`
}

// ClusterInitBundleManifest is the structure rendered into the YAML payload.
// Top-level apiVersion/kind keep the file recognisable by `kubectl apply -f -` parsers
// (we don't apply it; it's just for shape consistency with K8s tooling).
type ClusterInitBundleManifest struct {
	APIVersion string                    `yaml:"apiVersion"`
	Kind       string                    `yaml:"kind"`
	Metadata   ClusterInitBundleMetadata `yaml:"metadata"`
	Spec       ClusterInitBundleSpec     `yaml:"spec"`
}

type ClusterInitBundleMetadata struct {
	Name      string    `yaml:"name"`
	ClusterID string    `yaml:"cluster_id"`
	OrgID     string    `yaml:"org_id"`
	ExpiresAt time.Time `yaml:"expires_at"`
}

type ClusterInitBundleSpec struct {
	ControlPlaneURL     string `yaml:"control_plane_url"`
	ScannerToken        string `yaml:"scanner_token"`
	RuntimeAgentToken   string `yaml:"runtime_agent_token"`
	AdmissionCACert     string `yaml:"admission_ca_cert"`
	AdmissionServerCert string `yaml:"admission_server_cert"`
	AdmissionServerKey  string `yaml:"admission_server_key"`
	AuditHMACSecret     string `yaml:"audit_hmac_secret"`
}

// ---------------- HTTP handlers ----------------

// Create mints a brand-new bundle. Upserts the clusters row on (org_id, name).
func (h *ClusterInitBundles) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if !h.kekReady(w) {
		return
	}
	var req CreateBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.Distro == "" {
		req.Distro = "kubernetes"
	}
	ttl, err := parseTTL(req.TTL)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp, err := h.mint(r.Context(), subj, mintArgs{
		Name:      req.Name,
		Distro:    req.Distro,
		Region:    req.Region,
		TTL:       ttl,
		ServerURL: deriveServerURL(r),
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// List returns all (active, expired, revoked) bundles for the caller's org.
func (h *ClusterInitBundles) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT b.id, b.org_id, b.cluster_id, b.name, b.distro, COALESCE(b.region,''),
       b.expires_at, b.revoked_at, b.downloaded_at, b.created_at, b.created_by
  FROM cluster_init_bundles b
 WHERE b.org_id = $1
 ORDER BY b.created_at DESC
 LIMIT 500`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []BundleSummary{}
	for rows.Next() {
		var s BundleSummary
		var region string
		if err := rows.Scan(&s.ID, &s.OrgID, &s.ClusterID, &s.Name, &s.Distro, &region,
			&s.ExpiresAt, &s.RevokedAt, &s.DownloadedAt, &s.CreatedAt, &s.CreatedBy); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.Region = region
		s.Status = statusOf(s.ExpiresAt, s.RevokedAt)
		out = append(out, s)
	}
	writeJSON(w, 200, map[string]any{"bundles": out})
}

// Get returns the full bundle including the decrypted YAML. Flips downloaded_at on first
// successful read so the UI can surface a "this has already been retrieved" warning.
func (h *ClusterInitBundles) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if !h.kekReady(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var s BundleSummary
	var region string
	var ciphertext []byte
	var kekFP string
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT id, org_id, cluster_id, name, distro, COALESCE(region,''),
       expires_at, revoked_at, downloaded_at, created_at, created_by,
       contents_encrypted, kek_fingerprint
  FROM cluster_init_bundles
 WHERE id = $1 AND org_id = $2`, id, subj.OrgID).Scan(
		&s.ID, &s.OrgID, &s.ClusterID, &s.Name, &s.Distro, &region,
		&s.ExpiresAt, &s.RevokedAt, &s.DownloadedAt, &s.CreatedAt, &s.CreatedBy,
		&ciphertext, &kekFP)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Region = region
	s.Status = statusOf(s.ExpiresAt, s.RevokedAt)
	if kekFP != kekFingerprint(h.kek) {
		jsonError(w, http.StatusFailedDependency, "KEK fingerprint mismatch; bundle was minted under a different control-plane key")
		return
	}
	plaintext, err := decrypt(h.kek, ciphertext)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Errorf("decrypt: %w", err).Error())
		return
	}
	// Mark downloaded if first time.
	if s.DownloadedAt == nil {
		now := time.Now().UTC()
		_, _ = h.db.Pool().Exec(r.Context(),
			`UPDATE cluster_init_bundles SET downloaded_at = $1 WHERE id = $2 AND downloaded_at IS NULL`,
			now, id)
		s.DownloadedAt = &now
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "cluster-init-bundle.read",
		TargetKind: "cluster-init-bundle",
		TargetID:   id.String(),
		After:      map[string]any{"first_download": s.DownloadedAt.Equal(time.Now().UTC().Truncate(time.Second))},
	})
	writeJSON(w, 200, MintResponse{BundleSummary: s, YAML: string(plaintext), ServerURL: deriveServerURL(r)})
}

// Rotate revokes the current bundle (and its tokens) and mints a replacement under the
// same (org, name). The new bundle gets fresh TLS material and fresh tokens.
func (h *ClusterInitBundles) Rotate(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if !h.kekReady(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Resolve the existing row for its (name, distro, region) so the replacement
	// matches the cluster identity.
	var (
		name, distro, region string
		expiresAt            time.Time
	)
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT name, distro, COALESCE(region,''), expires_at
  FROM cluster_init_bundles
 WHERE id = $1 AND org_id = $2`, id, subj.OrgID).Scan(&name, &distro, &region, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Revoke the old (best-effort; mint will continue even if no rows changed).
	if err := h.revoke(r.Context(), subj, id, "rotate"); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Mint replacement with the same TTL relative to now as the original had at creation.
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = 720 * time.Hour
	}
	resp, err := h.mint(r.Context(), subj, mintArgs{
		Name:      name,
		Distro:    distro,
		Region:    region,
		TTL:       ttl,
		ServerURL: deriveServerURL(r),
		Reason:    "rotate",
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// Delete revokes the bundle and cascades the revocation to its scanner_token +
// runtime_agent_token rows so a leaked bundle is immediately useless even though the
// underlying tokens still exist (for audit-trail continuity).
func (h *ClusterInitBundles) Delete(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.revoke(r.Context(), subj, id, "revoke"); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"status": "revoked"})
}

// ---------------- internals ----------------

type mintArgs struct {
	Name      string
	Distro    string
	Region    string
	TTL       time.Duration
	ServerURL string
	Reason    string // "create" | "rotate"
}

// mint executes the full create-or-rotate transaction:
//   - upserts a clusters row on (org_id, name)
//   - generates TLS material (CA + server cert)
//   - mints fresh scanner_token + runtime_agent_token rows
//   - renders the YAML
//   - encrypts the YAML and persists the cluster_init_bundles row
//
// Returns the rendered YAML + the persisted row. The YAML is the ONLY copy of the
// raw tokens (the DB stores only token_hash); the caller is expected to surface it once.
func (h *ClusterInitBundles) mint(ctx context.Context, subj Subject, args mintArgs) (*MintResponse, error) {
	if args.TTL <= 0 {
		args.TTL = 720 * time.Hour
	}
	expiresAt := time.Now().UTC().Add(args.TTL)

	// Upsert clusters row.
	var clusterID uuid.UUID
	err := h.db.Pool().QueryRow(ctx, `
INSERT INTO clusters (org_id, name, distro, region, state)
VALUES ($1, $2, $3, NULLIF($4,''), 'pending')
ON CONFLICT (org_id, name)
  DO UPDATE SET distro = EXCLUDED.distro,
                region = COALESCE(EXCLUDED.region, clusters.region),
                updated_at = NOW()
RETURNING id`, subj.OrgID, args.Name, args.Distro, args.Region).Scan(&clusterID)
	if err != nil {
		return nil, fmt.Errorf("upsert cluster: %w", err)
	}

	// TLS material.
	caCertPEM, serverCertPEM, serverKeyPEM, err := generateBundleTLS(args.Name)
	if err != nil {
		return nil, fmt.Errorf("tls gen: %w", err)
	}

	// Mint tokens. Each lives in its own row tied to org_id (the global identifier today);
	// we surface the IDs back so the bundle row keeps pointers for cascaded revocation.
	tokenName := args.Name + ":bundle:" + time.Now().UTC().Format("20060102-150405")
	scannerRaw, scannerID, err := IssueScannerToken(ctx, h.db.Pool(), subj.OrgID, tokenName, args.TTL)
	if err != nil {
		return nil, err
	}
	agentRaw, agentID, err := IssueRuntimeAgentToken(ctx, h.db.Pool(), subj.OrgID, tokenName, args.TTL)
	if err != nil {
		return nil, err
	}

	// Audit HMAC secret (32 random bytes hex).
	hmacRaw := make([]byte, 32)
	if _, err := rand.Read(hmacRaw); err != nil {
		return nil, err
	}

	manifest := ClusterInitBundleManifest{
		APIVersion: "constellation.alphabravo.io/v1alpha1",
		Kind:       "ClusterInitBundle",
		Metadata: ClusterInitBundleMetadata{
			Name:      args.Name,
			ClusterID: clusterID.String(),
			OrgID:     subj.OrgID.String(),
			ExpiresAt: expiresAt,
		},
		Spec: ClusterInitBundleSpec{
			ControlPlaneURL:     args.ServerURL,
			ScannerToken:        scannerRaw,
			RuntimeAgentToken:   agentRaw,
			AdmissionCACert:     caCertPEM,
			AdmissionServerCert: serverCertPEM,
			AdmissionServerKey:  serverKeyPEM,
			AuditHMACSecret:     hex.EncodeToString(hmacRaw),
		},
	}
	yml, err := yaml.Marshal(&manifest)
	if err != nil {
		return nil, fmt.Errorf("yaml marshal: %w", err)
	}
	ciphertext, err := encrypt(h.kek, yml)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	bundleID := uuid.New()
	if _, err := h.db.Pool().Exec(ctx, `
INSERT INTO cluster_init_bundles
  (id, org_id, cluster_id, name, distro, region, expires_at, created_by,
   scanner_token_id, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), $7, $8, $9, $10, $11, $12)`,
		bundleID, subj.OrgID, clusterID, args.Name, args.Distro, args.Region, expiresAt, subj.UserID,
		scannerID, agentID, kekFingerprint(h.kek), ciphertext,
	); err != nil {
		return nil, fmt.Errorf("insert bundle: %w", err)
	}

	action := "cluster-init-bundle.create"
	if args.Reason == "rotate" {
		action = "cluster-init-bundle.rotate"
	}
	_, _, _ = h.audit.Log(ctx, audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     action,
		TargetKind: "cluster-init-bundle",
		TargetID:   bundleID.String(),
		After: map[string]any{
			"cluster_id":              clusterID.String(),
			"name":                    args.Name,
			"distro":                  args.Distro,
			"region":                  args.Region,
			"expires_at":              expiresAt,
			"scanner_token_id":        scannerID.String(),
			"runtime_agent_token_id":  agentID.String(),
		},
	})

	return &MintResponse{
		BundleSummary: BundleSummary{
			ID:        bundleID,
			OrgID:     subj.OrgID,
			ClusterID: clusterID,
			Name:      args.Name,
			Distro:    args.Distro,
			Region:    args.Region,
			Status:    "active",
			ExpiresAt: expiresAt,
			CreatedAt: time.Now().UTC(),
			CreatedBy: &subj.UserID,
		},
		YAML:      string(yml),
		ServerURL: args.ServerURL,
		// One-command join URL: the raw agent token IS the credential (Rancher model).
		ImportURL: args.ServerURL + "/api/v1/import/" + agentRaw + ".yaml",
	}, nil
}

// revoke marks the bundle row revoked AND cascades to its scanner / runtime tokens.
// Idempotent: a no-op on already-revoked rows except for the audit event.
func (h *ClusterInitBundles) revoke(ctx context.Context, subj Subject, id uuid.UUID, reason string) error {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var (
		scannerID, agentID *uuid.UUID
	)
	err = tx.QueryRow(ctx, `
UPDATE cluster_init_bundles
   SET revoked_at = COALESCE(revoked_at, NOW())
 WHERE id = $1 AND org_id = $2
RETURNING scanner_token_id, runtime_agent_token_id`, id, subj.OrgID).Scan(&scannerID, &agentID)
	if err != nil {
		return err
	}
	if scannerID != nil {
		_, _ = tx.Exec(ctx, `UPDATE scanner_tokens SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1`, *scannerID)
	}
	if agentID != nil {
		_, _ = tx.Exec(ctx, `UPDATE runtime_agent_tokens SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1`, *agentID)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	_, _, _ = h.audit.Log(ctx, audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "cluster-init-bundle.revoke",
		TargetKind: "cluster-init-bundle",
		TargetID:   id.String(),
		After:      map[string]any{"reason": reason},
	})
	return nil
}

// ---------------- helpers ----------------

func statusOf(expiresAt time.Time, revokedAt *time.Time) string {
	switch {
	case revokedAt != nil:
		return "revoked"
	case time.Now().UTC().After(expiresAt):
		return "expired"
	default:
		return "active"
	}
}

// parseTTL accepts Go-style durations plus a "Nd" extension ("7d", "30d", "90d").
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 720 * time.Hour, nil
	}
	if strings.HasSuffix(s, "d") {
		n := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(n, "%d", &days); err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid ttl %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	return d, nil
}

// deriveServerURL prefers the X-Forwarded-{Proto,Host} pair (set by ingresses) so the
// rendered control_plane_url is reachable from outside the cluster; falls back to the
// Host header on r if the proxy headers are absent.
func deriveServerURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// ---------------- TLS bundle generation ----------------

// generateBundleTLS mints a self-signed CA + a server certificate for the synthetic
// hostname <cluster>.cluster.constellation.internal that the admission webhook + future
// control-plane mTLS will present. Mirrors deploy/charts/constellation/templates/
// tls-bootstrap-job.yaml semantically (in-Go rather than via openssl) so the bundle is
// portable and rotation is online.
func generateBundleTLS(clusterName string) (caPEM, serverCertPEM, serverKeyPEM string, err error) {
	// CA key + cert.
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", "", "", fmt.Errorf("ca key: %w", err)
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "constellation-admission-ca-" + clusterName},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("ca cert: %w", err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		return "", "", "", err
	}

	// Server key + cert.
	srvKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", "", "", fmt.Errorf("srv key: %w", err)
	}
	srvSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	dns := []string{
		clusterName + ".cluster.constellation.internal",
		"constellation-admission",
		"constellation-admission.constellation-system",
		"constellation-admission.constellation-system.svc",
		"constellation-admission.constellation-system.svc.cluster.local",
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject:      pkix.Name{CommonName: dns[0]},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caParsed, &srvKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("srv cert: %w", err)
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return "", "", "", err
	}

	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	serverCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}))
	serverKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER}))
	return
}

// ---------------- AES-256-GCM helpers ----------------

// encrypt produces nonce(12) || ciphertext(plaintext||tag). The KEK is the 32-byte key.
func encrypt(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

// decrypt is the inverse of encrypt.
func decrypt(kek, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}
