// Package handler — per-registry credential delivery to scanner workers
// (gap REG-PRIVAUTH-11).
//
// A scan job carries a registry_id (scan_targets.registry_id, surfaced on the
// claimed JobView). Before REG-PRIVAUTH-11 the scanner never fetched the
// per-registry credentials, so every private-registry pull ran unauthenticated.
// This endpoint unseals registries.auth_secret for the job's registry — scoped
// to the scanner token's org and written to the append-only audit chain — and
// hands the decrypted username/password/token back to the worker for the
// duration of one scan. This mirrors NeuVector, which passes decrypted registry
// credentials to the scanner per ScanImage request
// (neuvector/controller/scan/image.go ScanImage → ScanImageRequest.Username/
// Password).
//
// ─────────────────────────────────────────────────────────────────────────────
// ROUTE TO WIRE (do NOT wired here — add by hand in internal/server/server.go,
// inside the EXISTING scanner-token group that already applies
// handler.ScannerTokenMiddleware, next to the "/scanner/config" route ~line
// 1328). No new middleware is needed — the group's ScannerTokenMiddleware is
// the auth. Exact line to add:
//
//	r.Get("/scanner/registry-credentials", handler.NewRegistryCredentials(s.db, s.auditLog).Get)
//
// Full route: method GET, path /api/v1/scanner/registry-credentials
//
//	(base "/api/v1" is applied by the enclosing router), query param
//	registry_id=<uuid>, auth = scanner-token (group middleware).
//
// ─────────────────────────────────────────────────────────────────────────────
package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// RegistryCredentialsDTO is the decrypted-credential envelope returned to a
// scanner worker. Only ever served over scanner-token auth and scoped to the
// token's org; never exposed on any user-facing route.
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

// Get unseals registries.auth_secret for ?registry_id=<uuid>, scoped to the
// scanner token's org, and returns the decrypted credentials. Every call is
// written to the audit chain.
func (h *RegistryCredentials) Get(w http.ResponseWriter, r *http.Request) {
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

	// org-scoped: a scanner token can only read credentials for registries in
	// its own org. A registry belonging to another org returns 404, identical
	// to a registry that does not exist — no cross-org existence oracle.
	kind, endpoint, authKind, sealed, _, err := loadRegistryRow(r.Context(), h.db.Pool(), tok.OrgID, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "registry not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	creds, err := openCredentials(r.Context(), h.db.Pool(), sealed)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "decrypt credentials: "+err.Error())
		return
	}

	// AUDITED: record that a scanner fetched decrypted credentials for this
	// registry. Actor is the scanner token (a service credential, not a user),
	// so ActorID stays nil and the scanner identity lives in the After payload.
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &tok.OrgID,
		Action:     "registry.credentials-issued",
		TargetKind: "registry",
		TargetID:   id.String(),
		After: map[string]any{
			"scanner":          tok.Name,
			"scanner_token_id": tok.ID.String(),
			"auth_kind":        authKind,
			"has_credentials":  creds["username"] != "" || creds["password"] != "" || creds["token"] != "",
		},
	})

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
