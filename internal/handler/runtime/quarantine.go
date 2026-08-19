// Wave E4: quarantine handler — manual add/list/lift for the
// admission-webhook deny list. Auto-quarantine writes (driven by runtime
// alerts) go through internal/handler/runtime_threats_ingest.go directly
// to keep the ingest path independent of the user-facing handler.
package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	auditlog "github.com/alphabravocompany/constellation/pkg/audit"
	pkgquar "github.com/alphabravocompany/constellation/pkg/quarantine"
)

type Quarantine struct {
	db    *db.DB
	audit *auditlog.Logger
}

func NewQuarantine(database *db.DB, audit *auditlog.Logger) *Quarantine {
	return &Quarantine{db: database, audit: audit}
}

type quarantineDTO struct {
	ID           uuid.UUID  `json:"id"`
	OrgID        uuid.UUID  `json:"org_id"`
	ClusterID    uuid.UUID  `json:"cluster_id"`
	Scope        string     `json:"scope"`
	MatchKey     string     `json:"match_key"`
	Reason       string     `json:"reason"`
	Origin       string     `json:"origin"`
	SourceKind   string     `json:"source_kind,omitempty"`
	SourceID     *uuid.UUID `json:"source_id,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	LiftedAt     *time.Time `json:"lifted_at,omitempty"`
	LiftedBy     *uuid.UUID `json:"lifted_by,omitempty"`
	LiftedReason string     `json:"lifted_reason,omitempty"`
}

// Create — POST /api/v1/quarantine
//
// Body:
//
//	{
//	  "cluster_id": "<uuid>",
//	  "scope":      "workload" | "image" | "namespace",
//	  "match_key":  "<scope-specific string>",
//	  "reason":     "<human-readable reason>",
//	  "expires_in_hours": 24    // optional; null/0 = no expiry
//	}
func (h *Quarantine) Create(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var req struct {
		ClusterID      uuid.UUID `json:"cluster_id"`
		Scope          string    `json:"scope"`
		MatchKey       string    `json:"match_key"`
		Reason         string    `json:"reason"`
		ExpiresInHours *int      `json:"expires_in_hours,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.ClusterID == uuid.Nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster_id is required"})
		return
	}
	switch pkgquar.Scope(req.Scope) {
	case pkgquar.ScopeWorkload, pkgquar.ScopeImage, pkgquar.ScopeNamespace:
	default:
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "scope must be one of: workload, image, namespace",
		})
		return
	}
	req.MatchKey = strings.TrimSpace(req.MatchKey)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.MatchKey == "" || req.Reason == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "match_key and reason are required",
		})
		return
	}
	var expiresAt *time.Time
	if req.ExpiresInHours != nil && *req.ExpiresInHours > 0 {
		t := time.Now().UTC().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		expiresAt = &t
	}

	row := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO quarantine_entries
    (org_id, cluster_id, scope, match_key, reason, origin, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, 'manual', $6, $7)
RETURNING id, created_at`,
		subj.OrgID, req.ClusterID, req.Scope, req.MatchKey, req.Reason,
		subj.UserID, expiresAt)

	var id uuid.UUID
	var createdAt time.Time
	if err := row.Scan(&id, &createdAt); err != nil {
		// Unique-index violation → collapse into the existing entry.
		if strings.Contains(err.Error(), "uniq_quarantine_active_target") {
			httpx.WriteJSON(w, http.StatusConflict, map[string]string{
				"error": "an active quarantine entry already exists for this scope+match_key",
			})
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Audit trail. action "quarantine.add" is mapped in pkg/audit/compliance.go.
	if h.audit != nil {
		userID := subj.UserID
		_, _, _ = h.audit.Log(r.Context(), auditlog.Event{
			OrgID:      &subj.OrgID,
			ActorID:    &userID,
			Action:     "quarantine.add",
			TargetKind: "quarantine_entries",
			TargetID:   id.String(),
			After: map[string]any{
				"cluster_id":       req.ClusterID,
				"scope":            req.Scope,
				"match_key":        req.MatchKey,
				"reason":           req.Reason,
				"expires_in_hours": req.ExpiresInHours,
			},
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, quarantineDTO{
		ID: id, OrgID: subj.OrgID, ClusterID: req.ClusterID,
		Scope: req.Scope, MatchKey: req.MatchKey, Reason: req.Reason,
		Origin: "manual", CreatedAt: createdAt, ExpiresAt: expiresAt,
	})
}

// List — GET /api/v1/quarantine?cluster_id=&scope=&include_lifted=
func (h *Quarantine) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	includeLifted := r.URL.Query().Get("include_lifted") == "1"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, org_id, cluster_id, scope, match_key, reason, origin,
       COALESCE(source_kind, ''), source_id, created_by, created_at,
       expires_at, lifted_at, lifted_by, COALESCE(lifted_reason, '')
  FROM quarantine_entries
 WHERE org_id = $1
   AND ($2::text = '' OR cluster_id::text = $2)
   AND ($3::text = '' OR scope = $3)
   AND ($4::boolean OR lifted_at IS NULL)
   AND ($4::boolean OR expires_at IS NULL OR expires_at > NOW())
 ORDER BY created_at DESC
 LIMIT $5`, subj.OrgID, clusterID, scope, includeLifted, limit)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := make([]quarantineDTO, 0, limit)
	for rows.Next() {
		var d quarantineDTO
		if err := rows.Scan(&d.ID, &d.OrgID, &d.ClusterID, &d.Scope, &d.MatchKey,
			&d.Reason, &d.Origin, &d.SourceKind, &d.SourceID, &d.CreatedBy,
			&d.CreatedAt, &d.ExpiresAt, &d.LiftedAt, &d.LiftedBy, &d.LiftedReason); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// Lift — POST /api/v1/quarantine/{id}/lift
//
// Body: {"reason": "<why we're lifting>"}
//
// Soft-delete (sets lifted_at + lifted_by + lifted_reason). Hard delete
// is intentionally never exposed — the audit chain references this row.
func (h *Quarantine) Lift(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "reason is required"})
		return
	}

	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE quarantine_entries
   SET lifted_at = NOW(), lifted_by = $3, lifted_reason = $4
 WHERE id = $1 AND org_id = $2 AND lifted_at IS NULL`,
		id, subj.OrgID, subj.UserID, req.Reason)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{
			"error": "quarantine entry not found or already lifted",
		})
		return
	}
	if h.audit != nil {
		userID := subj.UserID
		_, _, _ = h.audit.Log(r.Context(), auditlog.Event{
			OrgID:      &subj.OrgID,
			ActorID:    &userID,
			Action:     "quarantine.lift",
			TargetKind: "quarantine_entries",
			TargetID:   id.String(),
			After:      map[string]any{"reason": req.Reason},
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "lifted"})
}

// Get — GET /api/v1/quarantine/{id}
func (h *Quarantine) Get(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var d quarantineDTO
	row := h.db.Pool().QueryRow(r.Context(), `
SELECT id, org_id, cluster_id, scope, match_key, reason, origin,
       COALESCE(source_kind, ''), source_id, created_by, created_at,
       expires_at, lifted_at, lifted_by, COALESCE(lifted_reason, '')
  FROM quarantine_entries
 WHERE id = $1 AND org_id = $2`, id, subj.OrgID)
	if err := row.Scan(&d.ID, &d.OrgID, &d.ClusterID, &d.Scope, &d.MatchKey,
		&d.Reason, &d.Origin, &d.SourceKind, &d.SourceID, &d.CreatedBy,
		&d.CreatedAt, &d.ExpiresAt, &d.LiftedAt, &d.LiftedBy, &d.LiftedReason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}
