package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/scanlease"
)

// RegistryCredentialsDTO is the decrypted-credential envelope returned to a
// scanner worker. Only ever served over scanner-token auth and scoped to the
// token's org and active job lease; never exposed on any user-facing route.
type RegistryCredentialsDTO struct {
	RegistryID string `json:"registry_id"`
	Kind       string `json:"kind"`
	AuthKind   string `json:"auth_kind"`
	// Endpoint is the configured registry endpoint (host or URL). The worker
	// uses it, alongside the image ref, to scope the credentials to the right
	// registry authority.
	Endpoint string `json:"endpoint,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

// RegistryCredentials serves decrypted per-registry credentials to scanner
// workers over scanner-token auth.
type RegistryCredentials struct {
	db    *db.DB
	audit *audit.Logger
}

// NewRegistryCredentials constructs the handler.
func NewRegistryCredentials(d *db.DB, a *audit.Logger) *RegistryCredentials {
	return &RegistryCredentials{db: d, audit: a}
}

// Get unseals the registry attached to a job currently leased to this worker.
// Every successful credential release requires a redacted audit receipt.
func (h *RegistryCredentials) Get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tok, ok := ScannerTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "scanner token required")
		return
	}

	raw := strings.TrimSpace(r.URL.Query().Get("registry_id"))
	if raw == "" {
		jsonError(w, http.StatusBadRequest, "registry_id required")
		return
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid registry_id")
		return
	}

	jobID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("job_id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "valid job_id required")
		return
	}
	leaseID, leaseErr := scanlease.FromRequest(r)
	if leaseErr != nil {
		jsonError(w, http.StatusBadRequest, leaseErr.Error())
		return
	}
	workerID := ScannerWorkerIDFromRequest(tok, r)
	var kind, endpoint, authKind string
	var sealed []byte
	// Check every ownership edge as well as the unexpired lease. An unrelated,
	// expired or foreign job returns the same response as a missing registry.
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT reg.kind, reg.endpoint, reg.auth_kind, reg.auth_secret
  FROM registries reg
  JOIN scan_targets st ON st.registry_id = reg.id AND st.org_id = reg.org_id
  JOIN scan_jobs sj ON sj.target_id = st.id AND sj.org_id = st.org_id
 WHERE reg.id = $1 AND reg.org_id = $2 AND sj.id = $3
   AND st.type = 'image' AND sj.status = 'running'
   AND sj.worker_id = $4 AND sj.lease_expires_at > clock_timestamp()
 AND sj.lease_id IS NOT DISTINCT FROM $5::uuid`,
		id, tok.OrgID, jobID, workerID, leaseID).Scan(&kind, &endpoint, &authKind, &sealed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "registry not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "credential lookup failed")
		return
	}

	creds, err := openCredentials(r.Context(), h.db.Pool(), sealed)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "credential decryption failed")
		return
	}

	if h.audit == nil {
		jsonError(w, http.StatusServiceUnavailable, "credential audit unavailable")
		return
	}
	_, _, err = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &tok.OrgID,
		Action:     "registry.credentials-issued",
		TargetKind: "registry",
		TargetID:   id.String(),
		After: map[string]any{
			"scanner":          tok.Name,
			"scanner_token_id": tok.ID.String(),
			"job_id":           jobID.String(),
			"worker_id":        workerID,
			"auth_kind":        authKind,
			"has_credentials":  creds["username"] != "" || creds["password"] != "" || creds["token"] != "",
		},
	})
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "credential audit unavailable")
		return
	}

	writeJSON(w, http.StatusOK, RegistryCredentialsDTO{
		RegistryID: id.String(),
		Kind:       kind,
		AuthKind:   authKind,
		Endpoint:   endpoint,
		Username:   creds["username"],
		Password:   creds["password"],
		Token:      creds["token"],
	})
}
