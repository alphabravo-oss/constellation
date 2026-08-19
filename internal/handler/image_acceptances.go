package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type ImageAcceptances struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewImageAcceptances(database *db.DB, auditLog *audit.Logger) *ImageAcceptances {
	return &ImageAcceptances{db: database, auditLog: auditLog}
}

type imageAcceptanceDTO struct {
	ID            uuid.UUID `json:"id"`
	ImageDigest   string    `json:"image_digest"`
	Rationale     string    `json:"rationale"`
	ApproverID    uuid.UUID `json:"approver_id"`
	AcceptedUntil string    `json:"accepted_until"`
	CreatedAt     string    `json:"created_at"`
	RevokedAt     string    `json:"revoked_at,omitempty"`
	Status        string    `json:"status"`
}

type createImageAcceptanceBody struct {
	Rationale     string `json:"rationale"`
	AcceptedUntil string `json:"accepted_until"`
}

func (h *ImageAcceptances) List(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad asset id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	items, err := h.listForAsset(r, subj.OrgID, assetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image_acceptances": items})
}

func (h *ImageAcceptances) Create(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad asset id"})
		return
	}
	var body createImageAcceptanceBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	body.Rationale = strings.TrimSpace(body.Rationale)
	if len(body.Rationale) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rationale must be at least 12 characters"})
		return
	}
	acceptedUntil, err := time.Parse(time.RFC3339, body.AcceptedUntil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "accepted_until must be RFC3339"})
		return
	}
	if acceptedUntil.Before(time.Now().UTC()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "accepted_until must be in the future"})
		return
	}
	if acceptedUntil.After(time.Now().UTC().Add(30 * 24 * time.Hour)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "accepted_until cannot exceed 30 days"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	imageDigest, err := h.imageDigest(r, subj.OrgID, assetID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "image not found"})
		return
	}
	var id uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO image_acceptances (org_id, image_digest, rationale, approver_id, accepted_until)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`, subj.OrgID, imageDigest, body.Rationale, subj.UserID, acceptedUntil).Scan(&id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if h.auditLog != nil {
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
			OrgID: &subj.OrgID, ActorID: &subj.UserID,
			Action: "image.accept-risk", TargetKind: "image", TargetID: imageDigest,
			After: map[string]any{
				"asset_id":       assetID.String(),
				"acceptance_id":  id.String(),
				"accepted_until": acceptedUntil.UTC().Format(time.RFC3339),
				"rationale":      body.Rationale,
			},
		})
	}
	items, _ := h.listForAsset(r, subj.OrgID, assetID)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "image_acceptances": items})
}

func (h *ImageAcceptances) Revoke(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad asset id"})
		return
	}
	acceptanceID, err := uuid.Parse(chi.URLParam(r, "acceptanceID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad acceptance id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	imageDigest, err := h.imageDigest(r, subj.OrgID, assetID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "image not found"})
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE image_acceptances
   SET revoked_at = NOW()
 WHERE id = $1 AND org_id = $2 AND image_digest = $3 AND revoked_at IS NULL`,
		acceptanceID, subj.OrgID, imageDigest)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "acceptance not found"})
		return
	}
	if h.auditLog != nil {
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
			OrgID: &subj.OrgID, ActorID: &subj.UserID,
			Action: "image.accept-risk.revoke", TargetKind: "image", TargetID: imageDigest,
			After: map[string]any{"asset_id": assetID.String(), "acceptance_id": acceptanceID.String()},
		})
	}
	items, _ := h.listForAsset(r, subj.OrgID, assetID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "image_acceptances": items})
}

func (h *ImageAcceptances) imageDigest(r *http.Request, orgID uuid.UUID, assetID uuid.UUID) (string, error) {
	var digest string
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT i.digest
  FROM images i
  JOIN assets a ON a.id = i.asset_id
 WHERE i.asset_id = $1 AND a.org_id = $2`, assetID, orgID).Scan(&digest)
	return digest, err
}

func (h *ImageAcceptances) listForAsset(r *http.Request, orgID uuid.UUID, assetID uuid.UUID) ([]imageAcceptanceDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT ia.id, ia.image_digest, ia.rationale, ia.approver_id, ia.accepted_until, ia.created_at, ia.revoked_at
  FROM image_acceptances ia
  JOIN images i ON i.digest = ia.image_digest
  JOIN assets a ON a.id = i.asset_id
 WHERE i.asset_id = $1 AND ia.org_id = $2 AND a.org_id = $2
 ORDER BY ia.created_at DESC`, assetID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []imageAcceptanceDTO{}
	now := time.Now().UTC()
	for rows.Next() {
		var item imageAcceptanceDTO
		var acceptedUntil, createdAt time.Time
		var revokedAt *time.Time
		if err := rows.Scan(&item.ID, &item.ImageDigest, &item.Rationale, &item.ApproverID, &acceptedUntil, &createdAt, &revokedAt); err != nil {
			return nil, err
		}
		item.AcceptedUntil = acceptedUntil.UTC().Format(time.RFC3339)
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		item.Status = "active"
		if revokedAt != nil {
			item.RevokedAt = revokedAt.UTC().Format(time.RFC3339)
			item.Status = "revoked"
		} else if acceptedUntil.Before(now) {
			item.Status = "expired"
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
