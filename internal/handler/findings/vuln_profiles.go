package findings

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
)

type VulnProfiles struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewVulnProfiles(d *db.DB, a *audit.Logger) *VulnProfiles {
	return &VulnProfiles{db: d, auditLog: a}
}

type vulnProfileDTO struct {
	ID          uuid.UUID               `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Active      bool                    `json:"active"`
	Entries     []vulnprofile.Entry     `json:"entries"`
	DomainScope vulnprofile.DomainScope `json:"domain_scope"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

type vulnProfileBody struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Active      bool                    `json:"active"`
	Entries     []vulnprofile.Entry     `json:"entries"`
	DomainScope vulnprofile.DomainScope `json:"domain_scope"`
}

func (h *VulnProfiles) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, name, description, active, entries, domain_scope, created_at, updated_at
  FROM vuln_profiles
 WHERE org_id=$1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY name`, subj.OrgID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []vulnProfileDTO{}
	for rows.Next() {
		var d vulnProfileDTO
		var entries, domain []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.Description, &d.Active, &entries, &domain, &d.CreatedAt, &d.UpdatedAt); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal(entries, &d.Entries)
		_ = json.Unmarshal(domain, &d.DomainScope)
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

func (h *VulnProfiles) Create(w http.ResponseWriter, r *http.Request) {
	var body vulnProfileBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	p := &vulnprofile.Profile{Name: strings.TrimSpace(body.Name), Description: body.Description,
		Active: body.Active, Entries: body.Entries, DomainScope: body.DomainScope}
	if err := p.Validate(); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	entries, _ := json.Marshal(body.Entries)
	domain, _ := json.Marshal(body.DomainScope)
	var id uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO vuln_profiles (org_id, cluster_id, name, description, active, entries, domain_scope, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		subj.OrgID, clusterArg, p.Name, p.Description, p.Active, entries, domain, subj.UserID).Scan(&id); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "vuln_profile.create", TargetKind: "vuln-profile", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *VulnProfiles) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var body vulnProfileBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	p := &vulnprofile.Profile{Name: body.Name, Entries: body.Entries}
	if err := p.Validate(); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	entries, _ := json.Marshal(body.Entries)
	domain, _ := json.Marshal(body.DomainScope)
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE vuln_profiles SET name=$1, description=$2, active=$3, entries=$4, domain_scope=$5, updated_at=NOW()
 WHERE id=$6 AND org_id=$7`,
		body.Name, body.Description, body.Active, entries, domain, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "vuln_profile.update", TargetKind: "vuln-profile", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (h *VulnProfiles) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	if _, err := h.db.Pool().Exec(r.Context(), `DELETE FROM vuln_profiles WHERE id=$1 AND org_id=$2`, id, subj.OrgID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "vuln_profile.delete", TargetKind: "vuln-profile", TargetID: id.String()})
	httpx.WriteJSON(w, http.StatusNoContent, nil)
}
