// Custom compliance check endpoints. Parity with NeuVector's per-group custom check CRUD
// (neuvector/controller/rest/bench.go handlerCustomCheckConfig/Show/List). A check is a CEL
// expression the k8s-compliance collector evaluates over collected Kubernetes objects; results
// land in compliance_checks under the "Custom" framework.
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
	"github.com/alphabravocompany/constellation/internal/k8scompliance"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type CustomChecks struct {
	db    *db.DB
	audit *audit.Logger
}

func NewCustomChecks(d *db.DB, a *audit.Logger) *CustomChecks {
	return &CustomChecks{db: d, audit: a}
}

// validTargetKinds are the collected object kinds a custom check may run against; they mirror
// the objects k8scompliance.Collect gathers.
var validTargetKinds = map[string]bool{
	"Namespace":   true,
	"ClusterRole": true,
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
}

var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

type customCheckBody struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
	TargetKind  string `json:"target_kind"`
	Expression  string `json:"expression"`
	Remediation string `json:"remediation,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

// List returns the org's custom compliance checks.
func (c *CustomChecks) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	rows, err := c.db.Pool().Query(r.Context(), `
SELECT id, name, description, severity, target_kind, expression, remediation, enabled, created_at
  FROM custom_compliance_checks WHERE org_id = $1 ORDER BY created_at DESC`, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			id                                                  uuid.UUID
			name, desc, sev, kind, expr, remediation, createdAt string
			enabled                                             bool
		)
		if err := rows.Scan(&id, &name, &desc, &sev, &kind, &expr, &remediation, &enabled, &createdAt); err == nil {
			out = append(out, map[string]any{
				"id": id, "name": name, "description": desc, "severity": sev,
				"target_kind": kind, "expression": expr, "remediation": remediation,
				"enabled": enabled, "created_at": createdAt,
			})
		}
	}
	httpx.WriteJSON(w, 200, map[string]any{"checks": out})
}

// Create stores a new custom compliance check after validating the CEL expression.
func (c *CustomChecks) Create(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var body customCheckBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.TargetKind = strings.TrimSpace(body.TargetKind)
	body.Expression = strings.TrimSpace(body.Expression)
	if body.Name == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	if !validTargetKinds[body.TargetKind] {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "target_kind must be one of Namespace, ClusterRole, Deployment, StatefulSet, DaemonSet"})
		return
	}
	if body.Expression == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "expression required"})
		return
	}
	if err := k8scompliance.ValidateExpression(body.Expression); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CEL expression: " + err.Error()})
		return
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	if !validSeverities[body.Severity] {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "severity must be one of info, low, medium, high, critical"})
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	id := uuid.New()
	uid := subj.UserID
	oid := subj.OrgID
	if _, err := c.db.Pool().Exec(r.Context(), `
INSERT INTO custom_compliance_checks (id, org_id, name, description, severity, target_kind, expression, remediation, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		id, subj.OrgID, body.Name, body.Description, body.Severity, body.TargetKind, body.Expression, body.Remediation, enabled, subj.UserID,
	); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_, _, _ = c.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "compliance.custom_check.create", TargetKind: "custom-compliance-check", TargetID: id.String(),
		After: body,
	})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": body.Name, "severity": body.Severity, "target_kind": body.TargetKind,
		"expression": body.Expression, "enabled": enabled,
	})
}

// Delete removes a custom compliance check. Audit-logged.
func (c *CustomChecks) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	if _, err := c.db.Pool().Exec(r.Context(),
		`DELETE FROM custom_compliance_checks WHERE id = $1 AND org_id = $2`, id, subj.OrgID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = c.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "compliance.custom_check.delete", TargetKind: "custom-compliance-check", TargetID: id.String(),
	})
	httpx.WriteJSON(w, 200, map[string]string{"status": "deleted"})
}
