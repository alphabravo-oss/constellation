package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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

type imageAcceptanceScope struct {
	ExpectedImageDigest string `json:"expected_image_digest"`
	ClusterID           string `json:"cluster_id"`
}

type createImageAcceptanceBody struct {
	imageAcceptanceScope
	Rationale     string `json:"rationale"`
	AcceptedUntil string `json:"accepted_until"`
}

func (h *ImageAcceptances) List(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad asset id")
		return
	}
	subj, _ := SubjectFrom(r.Context())
	items, err := h.listForAsset(r, subj.OrgID, assetID)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image_acceptances": items})
}

func (h *ImageAcceptances) Create(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad asset id")
		return
	}
	var body createImageAcceptanceBody
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad request")
		return
	}
	body.Rationale = strings.TrimSpace(body.Rationale)
	if len(body.Rationale) < 12 {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "rationale must be at least 12 characters")
		return
	}
	acceptedUntil, err := time.Parse(time.RFC3339, body.AcceptedUntil)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "accepted_until must be RFC3339")
		return
	}
	if acceptedUntil.Before(time.Now().UTC()) {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "accepted_until must be in the future")
		return
	}
	if acceptedUntil.After(time.Now().UTC().Add(30 * 24 * time.Hour)) {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "accepted_until cannot exceed 30 days")
		return
	}
	subj, _ := SubjectFrom(r.Context())
	tx, imageDigest, clusterID, ok := h.lockReviewedImage(w, r, subj.OrgID, assetID, body.imageAcceptanceScope)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	var id uuid.UUID
	if err := tx.QueryRow(r.Context(), `
INSERT INTO image_acceptances (org_id, image_digest, rationale, approver_id, accepted_until)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`, subj.OrgID, imageDigest, body.Rationale, subj.UserID, acceptedUntil).Scan(&id); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "image_acceptances_active_expiry_key" {
			apiutil.WriteStatus(r.Context(), w, http.StatusConflict, "active image acceptance already exists for this expiry")
			return
		}
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "create image acceptance failed")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "image acceptance commit failed")
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
	items, _ := h.listForDigest(r, subj.OrgID, imageDigest)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "asset_id": assetID, "cluster_id": clusterID, "image_digest": imageDigest, "image_acceptances": items})
}

func (h *ImageAcceptances) Revoke(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad asset id")
		return
	}
	acceptanceID, err := uuid.Parse(chi.URLParam(r, "acceptanceID"))
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad acceptance id")
		return
	}
	var body imageAcceptanceScope
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad request")
		return
	}
	subj, _ := SubjectFrom(r.Context())
	tx, imageDigest, clusterID, ok := h.lockReviewedImage(w, r, subj.OrgID, assetID, body)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `
UPDATE image_acceptances
   SET revoked_at = NOW()
 WHERE id = $1 AND org_id = $2 AND image_digest = $3 AND revoked_at IS NULL`,
		acceptanceID, subj.OrgID, imageDigest)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		apiutil.WriteStatus(r.Context(), w, http.StatusNotFound, "acceptance not found")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "image acceptance commit failed")
		return
	}
	if h.auditLog != nil {
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
			OrgID: &subj.OrgID, ActorID: &subj.UserID,
			Action: "image.accept-risk.revoke", TargetKind: "image", TargetID: imageDigest,
			After: map[string]any{"asset_id": assetID.String(), "acceptance_id": acceptanceID.String()},
		})
	}
	items, _ := h.listForDigest(r, subj.OrgID, imageDigest)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "asset_id": assetID, "cluster_id": clusterID, "image_digest": imageDigest, "image_acceptances": items})
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
	digest, err := h.imageDigest(r, orgID, assetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return []imageAcceptanceDTO{}, nil
	}
	if err != nil {
		return nil, err
	}
	return h.listForDigest(r, orgID, digest)
}

func (h *ImageAcceptances) listForDigest(r *http.Request, orgID uuid.UUID, digest string) ([]imageAcceptanceDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, image_digest, rationale, approver_id, accepted_until, created_at, revoked_at
FROM image_acceptances WHERE image_digest=$1 AND org_id=$2 ORDER BY created_at DESC`, digest, orgID)
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

// lockReviewedImage keeps the reviewed asset/image identity stable through the
// acceptance write. Legacy clients may omit preconditions; console forms send both.
func (h *ImageAcceptances) lockReviewedImage(w http.ResponseWriter, r *http.Request, orgID, assetID uuid.UUID, expected imageAcceptanceScope) (pgx.Tx, string, *uuid.UUID, bool) {
	expected.ExpectedImageDigest = strings.TrimSpace(expected.ExpectedImageDigest)
	expected.ClusterID = strings.TrimSpace(expected.ClusterID)
	var wantedCluster uuid.UUID
	if expected.ExpectedImageDigest != "" || expected.ClusterID != "" {
		var err error
		wantedCluster, err = uuid.Parse(expected.ClusterID)
		if err != nil || expected.ExpectedImageDigest == "" {
			apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "expected_image_digest and valid cluster_id must be provided together")
			return nil, "", nil, false
		}
	}
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "image scope unavailable")
		return nil, "", nil, false
	}
	var digest string
	var clusterID *uuid.UUID
	err = tx.QueryRow(r.Context(), `SELECT i.digest, a.cluster_id FROM images i JOIN assets a ON a.id=i.asset_id WHERE i.asset_id=$1 AND a.org_id=$2 FOR SHARE OF i,a`, assetID, orgID).Scan(&digest, &clusterID)
	if err != nil {
		_ = tx.Rollback(r.Context())
		status, message := http.StatusInternalServerError, "image scope unavailable"
		if errors.Is(err, pgx.ErrNoRows) {
			status, message = http.StatusNotFound, "image not found"
		}
		apiutil.WriteStatus(r.Context(), w, status, message)
		return nil, "", nil, false
	}
	if expected.ExpectedImageDigest != "" && (digest != expected.ExpectedImageDigest || clusterID == nil || *clusterID != wantedCluster) {
		_ = tx.Rollback(r.Context())
		apiutil.WriteStatus(r.Context(), w, http.StatusConflict, "reviewed image digest or cluster changed; reload before submitting")
		return nil, "", nil, false
	}
	return tx, digest, clusterID, true
}
