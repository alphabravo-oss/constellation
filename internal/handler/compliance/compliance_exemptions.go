package compliance

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type complianceExemptionDTO struct {
	ID         uuid.UUID  `json:"id"`
	ClusterID  *uuid.UUID `json:"cluster_id,omitempty"`
	Framework  string     `json:"framework"`
	ControlID  string     `json:"control_id"`
	Reason     string     `json:"reason"`
	ApprovedBy *uuid.UUID `json:"approved_by,omitempty"`
	ExpiresAt  string     `json:"expires_at"`
	CreatedAt  string     `json:"created_at"`
	RevokedAt  string     `json:"revoked_at,omitempty"`
	Status     string     `json:"status"`
}

type createComplianceExemptionBody struct {
	ClusterID string `json:"cluster_id"`
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

// ListExemptions returns compliance exemptions for the authenticated org. If a
// cluster_id filter is present, org-wide exemptions are included because they
// apply to every cluster in the org.
func (c *Compliance) ListExemptions(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	framework := strings.TrimSpace(r.URL.Query().Get("framework"))
	controlID := strings.TrimSpace(r.URL.Query().Get("control_id"))
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	items, err := c.listExemptions(r, subj.OrgID, framework, controlID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"exemptions": items})
}

func (c *Compliance) CreateExemption(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var body createComplianceExemptionBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	body.Framework = strings.TrimSpace(body.Framework)
	body.ControlID = strings.TrimSpace(body.ControlID)
	body.Reason = strings.TrimSpace(body.Reason)
	body.ClusterID = strings.TrimSpace(body.ClusterID)
	if body.Framework == "" || body.ControlID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "framework and control_id are required"})
		return
	}
	if len(body.Reason) < 12 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "reason must be at least 12 characters"})
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_at must be RFC3339"})
		return
	}
	if !expiresAt.After(time.Now().UTC()) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_at must be in the future"})
		return
	}
	var clusterID *uuid.UUID
	var clusterArg any
	if body.ClusterID != "" {
		parsed, err := uuid.Parse(body.ClusterID)
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster_id must be a UUID"})
			return
		}
		clusterID = &parsed
		clusterArg = parsed
	}
	var id uuid.UUID
	if err := c.db.Pool().QueryRow(r.Context(), `
INSERT INTO compliance_exemptions (org_id, cluster_id, framework, control_id, reason, approved_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id`,
		subj.OrgID, clusterArg, body.Framework, body.ControlID, body.Reason, subj.UserID, expiresAt.UTC(),
	).Scan(&id); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if c.audit != nil {
		_, _, _ = c.audit.Log(r.Context(), audit.Event{
			OrgID: &subj.OrgID, ActorID: &subj.UserID,
			Action:     "compliance.exemption.create",
			TargetKind: "compliance-exemption",
			TargetID:   id.String(),
			After: map[string]any{
				"cluster_id": clusterIDString(clusterID),
				"framework":  body.Framework,
				"control_id": body.ControlID,
				"expires_at": expiresAt.UTC().Format(time.RFC3339),
				"reason":     body.Reason,
			},
		})
	}
	items, _ := c.listExemptions(r, subj.OrgID, body.Framework, body.ControlID, clusterArg)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "exemptions": items})
}

func (c *Compliance) RevokeExemption(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad exemption id"})
		return
	}
	tag, err := c.db.Pool().Exec(r.Context(), `
UPDATE compliance_exemptions
   SET revoked_at = NOW(), updated_at = NOW()
 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "exemption not found"})
		return
	}
	if c.audit != nil {
		_, _, _ = c.audit.Log(r.Context(), audit.Event{
			OrgID: &subj.OrgID, ActorID: &subj.UserID,
			Action:     "compliance.exemption.revoke",
			TargetKind: "compliance-exemption",
			TargetID:   id.String(),
			After:      map[string]any{"exemption_id": id.String()},
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": id})
}

func (c *Compliance) listExemptions(r *http.Request, orgID uuid.UUID, framework, controlID string, clusterArg any) ([]complianceExemptionDTO, error) {
	rows, err := c.db.Pool().Query(r.Context(), `
SELECT id, cluster_id, framework, control_id, reason, approved_by, expires_at, created_at, revoked_at
  FROM compliance_exemptions
 WHERE org_id = $1
   AND ($2::text = '' OR framework = $2)
   AND ($3::text = '' OR control_id = $3)
   AND ($4::uuid IS NULL OR cluster_id = $4 OR cluster_id IS NULL)
 ORDER BY (revoked_at IS NOT NULL), (expires_at <= NOW()), created_at DESC
 LIMIT 500`, orgID, framework, controlID, clusterArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []complianceExemptionDTO{}
	now := time.Now().UTC()
	for rows.Next() {
		var item complianceExemptionDTO
		var expiresAt, createdAt time.Time
		var revokedAt *time.Time
		if err := rows.Scan(&item.ID, &item.ClusterID, &item.Framework, &item.ControlID, &item.Reason, &item.ApprovedBy, &expiresAt, &createdAt, &revokedAt); err != nil {
			return nil, err
		}
		item.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		item.Status = "active"
		if revokedAt != nil {
			item.RevokedAt = revokedAt.UTC().Format(time.RFC3339)
			item.Status = "revoked"
		} else if !expiresAt.After(now) {
			item.Status = "expired"
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func clusterIDString(clusterID *uuid.UUID) string {
	if clusterID == nil {
		return ""
	}
	return clusterID.String()
}
