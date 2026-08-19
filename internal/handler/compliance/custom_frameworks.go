// Custom-framework endpoints. Mirrors compliance.go but for org-specific frameworks
// composed from pkg/compliance.CoreMappings internal IDs.
package compliance

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

type CustomFrameworks struct {
	db    *db.DB
	audit *audit.Logger
}

func NewCustomFrameworks(d *db.DB, a *audit.Logger) *CustomFrameworks {
	return &CustomFrameworks{db: d, audit: a}
}

type customFrameworkBody struct {
	Name        string   `json:"name"`
	Category    string   `json:"category,omitempty"`
	Description string   `json:"description,omitempty"`
	ControlIDs  []string `json:"control_ids"`
}

// Primitives returns the canonical list of internal checks customers compose into custom
// frameworks. Each maps to one or more upstream framework controls; see pkg/compliance.
func (c *CustomFrameworks) Primitives(w http.ResponseWriter, _ *http.Request) {
	out := make([]map[string]any, 0, len(compliancepkg.CoreMappings))
	for _, m := range compliancepkg.CoreMappings {
		controls := []map[string]string{}
		for fw, id := range m.Controls {
			controls = append(controls, map[string]string{"framework": fw, "control_id": id})
		}
		out = append(out, map[string]any{
			"id":       m.InternalID,
			"title":    m.Title,
			"severity": m.Severity,
			"maps_to":  controls,
		})
	}
	httpx.WriteJSON(w, 200, map[string]any{"primitives": out})
}

// List returns org-defined custom frameworks.
func (c *CustomFrameworks) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	rows, err := c.db.Pool().Query(r.Context(), `
SELECT id, name, category, COALESCE(description,''), control_ids, created_at
  FROM custom_frameworks WHERE org_id = $1 ORDER BY created_at DESC`, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			id                  uuid.UUID
			name, cat, desc, at string
			controls            []string
		)
		if err := rows.Scan(&id, &name, &cat, &desc, &controls, &at); err == nil {
			out = append(out, map[string]any{
				"id": id, "name": name, "category": cat, "description": desc,
				"control_ids": controls, "created_at": at,
			})
		}
	}
	httpx.WriteJSON(w, 200, map[string]any{"frameworks": out})
}

// Create stores a new custom framework. Returns the persisted row.
func (c *CustomFrameworks) Create(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var body customFrameworkBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	if len(body.ControlIDs) == 0 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "control_ids required"})
		return
	}
	if body.Category == "" {
		body.Category = "custom"
	}

	id := uuid.New()
	uid := subj.UserID
	oid := subj.OrgID
	if _, err := c.db.Pool().Exec(r.Context(), `
INSERT INTO custom_frameworks (id, org_id, name, category, description, control_ids, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, subj.OrgID, body.Name, body.Category, body.Description, body.ControlIDs, subj.UserID,
	); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_, _, _ = c.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "compliance.custom_framework.create", TargetKind: "custom-framework", TargetID: id.String(),
		After: body,
	})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": body.Name, "category": body.Category, "control_ids": body.ControlIDs,
	})
}

// Delete removes a custom framework. Audit-logged.
func (c *CustomFrameworks) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	if _, err := c.db.Pool().Exec(r.Context(),
		`DELETE FROM custom_frameworks WHERE id = $1 AND org_id = $2`, id, subj.OrgID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = c.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "compliance.custom_framework.delete", TargetKind: "custom-framework", TargetID: id.String(),
	})
	httpx.WriteJSON(w, 200, map[string]string{"status": "deleted"})
}
