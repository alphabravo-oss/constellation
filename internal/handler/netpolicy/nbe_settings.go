// B6: cross-namespace network boundary enforcement (NBE) settings API +
// store, backed by netpolicy_nbe_settings (migration 128).
//
// Per-namespace toggle that flags, and under protect denies, cross-namespace
// flows. Default OFF (a namespace with no row is 'off'); a freshly-set row
// defaults to 'observe' and must be explicitly promoted to 'protect'. Pure
// decision logic (EvaluateNBE) lives in pkg/netpolicy/nbe.go.
//
// Routes (registered in internal/server/server.go near the network-policy
// lifecycle routes):
//
//	GET /api/v1/network/policies/nbe?cluster_id=...   — list enabled namespaces
//	PUT /api/v1/network/policies/nbe?cluster_id=...    — set one namespace's mode
package netpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// NBESettings is one netpolicy_nbe_settings row in wire form.
type NBESettings struct {
	Namespace string           `json:"namespace"`
	Mode      netpolicy.NBEMode `json:"mode"`
	UpdatedAt string           `json:"updated_at,omitempty"`
}

// NBEStore reads/writes the per-namespace NBE toggle.
type NBEStore struct {
	db *db.DB
}

// NewNBEStore constructs the store.
func NewNBEStore(d *db.DB) *NBEStore { return &NBEStore{db: d} }

// ModeFor returns the NBE mode for one namespace, defaulting to NBEOff when no
// row exists (the feature is opt-in).
func (s *NBEStore) ModeFor(ctx context.Context, orgID, clusterID uuid.UUID, namespace string) (netpolicy.NBEMode, error) {
	if s == nil || s.db == nil {
		return netpolicy.NBEOff, nil
	}
	var mode string
	err := s.db.Pool().QueryRow(ctx,
		`SELECT mode FROM netpolicy_nbe_settings
		  WHERE org_id = $1 AND cluster_id = $2 AND namespace = $3`,
		orgID, clusterID, namespace).Scan(&mode)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return netpolicy.NBEOff, nil
		}
		return netpolicy.NBEOff, err
	}
	return netpolicy.NBEMode(mode), nil
}

// ModesForCluster loads every namespace with a non-default NBE row for the
// cluster as a map, so a caller (eg. the flow-ingest loop) can resolve modes
// with a single query and treat absent namespaces as NBEOff. Rows explicitly
// set to 'off' are included so an operator can pin a namespace off.
func (s *NBEStore) ModesForCluster(ctx context.Context, orgID, clusterID uuid.UUID) (map[string]netpolicy.NBEMode, error) {
	out := map[string]netpolicy.NBEMode{}
	if s == nil || s.db == nil {
		return out, nil
	}
	rows, err := s.db.Pool().Query(ctx,
		`SELECT namespace, mode FROM netpolicy_nbe_settings
		  WHERE org_id = $1 AND cluster_id = $2`, orgID, clusterID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var ns, mode string
		if err := rows.Scan(&ns, &mode); err != nil {
			return out, err
		}
		out[ns] = netpolicy.NBEMode(mode)
	}
	return out, rows.Err()
}

// List returns all NBE rows for a cluster.
func (s *NBEStore) List(ctx context.Context, orgID, clusterID uuid.UUID) ([]NBESettings, error) {
	out := []NBESettings{}
	if s == nil || s.db == nil {
		return out, nil
	}
	rows, err := s.db.Pool().Query(ctx,
		`SELECT namespace, mode, updated_at FROM netpolicy_nbe_settings
		  WHERE org_id = $1 AND cluster_id = $2 ORDER BY namespace`, orgID, clusterID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var it NBESettings
		var mode string
		var ts time.Time
		if err := rows.Scan(&it.Namespace, &mode, &ts); err != nil {
			return out, err
		}
		it.Mode = netpolicy.NBEMode(mode)
		if !ts.IsZero() {
			it.UpdatedAt = ts.UTC().Format(time.RFC3339)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Put upserts one namespace's NBE mode. An empty mode defaults to 'observe'
// (flag-only) — a new toggle is never created straight into 'protect'.
func (s *NBEStore) Put(ctx context.Context, orgID, clusterID uuid.UUID, namespace string, mode netpolicy.NBEMode, by *uuid.UUID) error {
	if s == nil || s.db == nil {
		return errors.New("storage unavailable")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return errors.New("namespace is required")
	}
	if mode == "" {
		mode = netpolicy.NBEObserve
	}
	if !mode.Valid() {
		return errors.New("invalid mode")
	}
	_, err := s.db.Pool().Exec(ctx, `
INSERT INTO netpolicy_nbe_settings (org_id, cluster_id, namespace, mode, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,NOW())
ON CONFLICT (org_id, cluster_id, namespace) DO UPDATE
   SET mode = EXCLUDED.mode, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		orgID, clusterID, namespace, string(mode), by)
	return err
}

// ---------------------------------- HTTP ------------------------------------

// NBEHTTP wires the NBE settings store to HTTP.
type NBEHTTP struct {
	store *NBEStore
}

// NewNBEHTTP constructs the HTTP handler.
func NewNBEHTTP(d *db.DB) *NBEHTTP { return &NBEHTTP{store: NewNBEStore(d)} }

func nbeCluster(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(strings.TrimSpace(r.URL.Query().Get("cluster_id")))
}

// List handles GET /api/v1/network/policies/nbe?cluster_id=...
func (h *NBEHTTP) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := nbeCluster(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	items, err := h.store.List(r.Context(), sub.OrgID, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// Put handles PUT /api/v1/network/policies/nbe?cluster_id=...
func (h *NBEHTTP) Put(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "auth required")
		return
	}
	clusterID, err := nbeCluster(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "cluster_id is required")
		return
	}
	var req NBESettings
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := h.store.Put(r.Context(), sub.OrgID, clusterID, req.Namespace, req.Mode, &sub.UserID); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode, err := h.store.ModeFor(r.Context(), sub.OrgID, clusterID, strings.TrimSpace(req.Namespace))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NBESettings{Namespace: strings.TrimSpace(req.Namespace), Mode: mode})
}
